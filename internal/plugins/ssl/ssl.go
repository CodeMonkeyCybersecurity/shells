package ssl

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

type sslScanner struct {
	cfg    config.SSLConfig
	logger interface {
		Info(msg string, keysAndValues ...interface{})
		Error(msg string, keysAndValues ...interface{})
		Debug(msg string, keysAndValues ...interface{})
	}
}

func NewScanner(cfg config.SSLConfig, logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}) core.Scanner {
	return &sslScanner{
		cfg:    cfg,
		logger: logger,
	}
}

func (s *sslScanner) Name() string {
	return "ssl"
}

func (s *sslScanner) Type() types.ScanType {
	return types.ScanTypeSSL
}

func (s *sslScanner) Validate(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	if !strings.Contains(target, ":") {
		target = target + ":443"
	}

	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid target format: %w", err)
	}

	if net.ParseIP(host) == nil {
		if _, err := net.LookupHost(host); err != nil {
			return fmt.Errorf("cannot resolve host: %w", err)
		}
	}

	return nil
}

func (s *sslScanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	if !strings.Contains(target, ":") {
		port := options["port"]
		if port == "" {
			port = "443"
		}
		target = target + ":" + port
	}

	s.logger.Info("Starting SSL/TLS scan", "target", target)

	findings := []types.Finding{}

	host, port, _ := net.SplitHostPort(target)

	tlsConfigs := s.getTLSConfigs()
	supportedVersions := []string{}
	var conn *tls.Conn
	var state tls.ConnectionState

	for version, config := range tlsConfigs {
		dialer := &net.Dialer{
			Timeout: s.cfg.Timeout,
		}

		tcpConn, err := dialer.DialContext(ctx, "tcp", target)
		if err != nil {
			continue
		}

		tlsConn := tls.Client(tcpConn, config)
		tlsConn.SetDeadline(time.Now().Add(s.cfg.Timeout))

		err = tlsConn.HandshakeContext(ctx)
		tcpConn.Close()

		if err == nil {
			supportedVersions = append(supportedVersions, version)
			if conn == nil {
				conn = tlsConn
				state = tlsConn.ConnectionState()
			}
		}
	}

	if conn == nil {
		return findings, fmt.Errorf("failed to establish TLS connection to %s", target)
	}
	defer conn.Close()

	findings = append(findings, s.checkProtocolVersions(host, port, supportedVersions)...)

	findings = append(findings, s.checkCertificates(host, port, state.PeerCertificates)...)

	findings = append(findings, s.checkCipherSuites(host, port, state)...)

	if s.cfg.CheckRevocation {
		findings = append(findings, s.checkRevocation(host, port, state.PeerCertificates)...)
	}

	return findings, nil
}

func (s *sslScanner) getTLSConfigs() map[string]*tls.Config {
	return map[string]*tls.Config{
		"SSLv3": {
			MinVersion:         tls.VersionSSL30,
			MaxVersion:         tls.VersionSSL30,
			InsecureSkipVerify: true,
		},
		"TLS 1.0": {
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS10,
			InsecureSkipVerify: true,
		},
		"TLS 1.1": {
			MinVersion:         tls.VersionTLS11,
			MaxVersion:         tls.VersionTLS11,
			InsecureSkipVerify: true,
		},
		"TLS 1.2": {
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		},
		"TLS 1.3": {
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		},
	}
}

func (s *sslScanner) checkProtocolVersions(host, port string, supported []string) []types.Finding {
	findings := []types.Finding{}

	weakProtocols := map[string]types.Severity{
		"SSLv3":   types.SeverityCritical,
		"TLS 1.0": types.SeverityHigh,
		"TLS 1.1": types.SeverityMedium,
	}

	for _, version := range supported {
		if severity, isWeak := weakProtocols[version]; isWeak {
			finding := types.Finding{
				Tool:     "ssl",
				Type:     "weak_protocol",
				Severity: severity,
				Title:    fmt.Sprintf("Weak SSL/TLS Protocol: %s", version),
				Description: fmt.Sprintf(
					"The server at %s:%s supports %s, which has known vulnerabilities.",
					host, port, version,
				),
				Evidence: fmt.Sprintf("Protocol %s is enabled on %s:%s", version, host, port),
				Solution: s.getProtocolRecommendation(version),
				Metadata: map[string]interface{}{
					"host":     host,
					"port":     port,
					"protocol": version,
				},
			}
			findings = append(findings, finding)
		}
	}

	bestProtocol := ""
	for _, v := range supported {
		if v == "TLS 1.3" || v == "TLS 1.2" {
			bestProtocol = v
			break
		}
	}

	if bestProtocol != "" {
		finding := types.Finding{
			Tool:     "ssl",
			Type:     "ssl_info",
			Severity: types.SeverityInfo,
			Title:    "SSL/TLS Configuration",
			Description: fmt.Sprintf(
				"Server supports protocols: %s. Best available: %s",
				strings.Join(supported, ", "), bestProtocol,
			),
			Metadata: map[string]interface{}{
				"host":               host,
				"port":               port,
				"supported_versions": supported,
				"best_version":       bestProtocol,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

func (s *sslScanner) checkCertificates(host, port string, certs []*x509.Certificate) []types.Finding {
	findings := []types.Finding{}

	if len(certs) == 0 {
		return findings
	}

	cert := certs[0]
	now := time.Now()

	if now.After(cert.NotAfter) {
		finding := types.Finding{
			Tool:     "ssl",
			Type:     "expired_certificate",
			Severity: types.SeverityCritical,
			Title:    "SSL Certificate Expired",
			Description: fmt.Sprintf(
				"The SSL certificate for %s:%s expired on %s",
				host, port, cert.NotAfter.Format("2006-01-02"),
			),
			Evidence: fmt.Sprintf("Certificate expired %v ago", now.Sub(cert.NotAfter)),
			Solution: "Replace the expired certificate immediately.",
			Metadata: map[string]interface{}{
				"host":      host,
				"port":      port,
				"not_after": cert.NotAfter,
				"days_ago":  int(now.Sub(cert.NotAfter).Hours() / 24),
				"subject":   cert.Subject.String(),
				"issuer":    cert.Issuer.String(),
			},
		}
		findings = append(findings, finding)
	} else if now.Add(30 * 24 * time.Hour).After(cert.NotAfter) {
		finding := types.Finding{
			Tool:     "ssl",
			Type:     "certificate_expiring_soon",
			Severity: types.SeverityMedium,
			Title:    "SSL Certificate Expiring Soon",
			Description: fmt.Sprintf(
				"The SSL certificate for %s:%s will expire on %s",
				host, port, cert.NotAfter.Format("2006-01-02"),
			),
			Evidence: fmt.Sprintf("Certificate expires in %v", cert.NotAfter.Sub(now)),
			Solution: "Plan to renew the certificate before expiration.",
			Metadata: map[string]interface{}{
				"host":           host,
				"port":           port,
				"not_after":      cert.NotAfter,
				"days_remaining": int(cert.NotAfter.Sub(now).Hours() / 24),
				"subject":        cert.Subject.String(),
				"issuer":         cert.Issuer.String(),
			},
		}
		findings = append(findings, finding)
	}

	if now.Before(cert.NotBefore) {
		finding := types.Finding{
			Tool:     "ssl",
			Type:     "certificate_not_yet_valid",
			Severity: types.SeverityCritical,
			Title:    "SSL Certificate Not Yet Valid",
			Description: fmt.Sprintf(
				"The SSL certificate for %s:%s is not valid until %s",
				host, port, cert.NotBefore.Format("2006-01-02"),
			),
			Evidence: fmt.Sprintf("Certificate will be valid in %v", cert.NotBefore.Sub(now)),
			Solution: "Use a certificate that is currently valid.",
			Metadata: map[string]interface{}{
				"host":       host,
				"port":       port,
				"not_before": cert.NotBefore,
				"subject":    cert.Subject.String(),
				"issuer":     cert.Issuer.String(),
			},
		}
		findings = append(findings, finding)
	}

	if !s.verifyHostname(cert, host) {
		finding := types.Finding{
			Tool:     "ssl",
			Type:     "hostname_mismatch",
			Severity: types.SeverityHigh,
			Title:    "SSL Certificate Hostname Mismatch",
			Description: fmt.Sprintf(
				"The SSL certificate does not match the hostname %s",
				host,
			),
			Evidence: fmt.Sprintf("Certificate is for: %s", strings.Join(cert.DNSNames, ", ")),
			Solution: "Use a certificate that includes the correct hostname.",
			Metadata: map[string]interface{}{
				"host":      host,
				"port":      port,
				"dns_names": cert.DNSNames,
				"subject":   cert.Subject.String(),
			},
		}
		findings = append(findings, finding)
	}

	if cert.PublicKeyAlgorithm == x509.RSA {
		if keySize := cert.PublicKey.(*rsa.PublicKey).N.BitLen(); keySize < 2048 {
			finding := types.Finding{
				Tool:     "ssl",
				Type:     "weak_key",
				Severity: types.SeverityHigh,
				Title:    "Weak RSA Key Size",
				Description: fmt.Sprintf(
					"The SSL certificate uses a %d-bit RSA key, which is considered weak",
					keySize,
				),
				Evidence: fmt.Sprintf("RSA key size: %d bits", keySize),
				Solution: "Use at least 2048-bit RSA keys or consider using ECDSA.",
				Metadata: map[string]interface{}{
					"host":     host,
					"port":     port,
					"key_size": keySize,
					"subject":  cert.Subject.String(),
				},
			}
			findings = append(findings, finding)
		}
	}

	if cert.SignatureAlgorithm == x509.SHA1WithRSA || cert.SignatureAlgorithm == x509.DSAWithSHA1 || cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {
		finding := types.Finding{
			Tool:     "ssl",
			Type:     "weak_signature",
			Severity: types.SeverityMedium,
			Title:    "Weak Certificate Signature Algorithm",
			Description: fmt.Sprintf(
				"The SSL certificate uses SHA-1 for signing, which is deprecated",
			),
			Evidence: fmt.Sprintf("Signature algorithm: %s", cert.SignatureAlgorithm),
			Solution: "Use SHA-256 or stronger signature algorithms.",
			Metadata: map[string]interface{}{
				"host":                host,
				"port":                port,
				"signature_algorithm": cert.SignatureAlgorithm.String(),
				"subject":             cert.Subject.String(),
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

func (s *sslScanner) checkCipherSuites(host, port string, state tls.ConnectionState) []types.Finding {
	findings := []types.Finding{}

	weakCiphers := map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:             "RC4 cipher (weak)",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:        "3DES cipher (weak)",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:         "No forward secrecy",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:         "No forward secrecy",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:     "RC4 cipher (weak)",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:       "RC4 cipher (weak)",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:  "3DES cipher (weak)",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: "CBC mode (vulnerable to BEAST)",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: "CBC mode (vulnerable to BEAST)",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:   "CBC mode (vulnerable to BEAST)",
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:   "CBC mode (vulnerable to BEAST)",
	}

	cipherName := tls.CipherSuiteName(state.CipherSuite)

	if weakness, isWeak := weakCiphers[state.CipherSuite]; isWeak {
		finding := types.Finding{
			Tool:     "ssl",
			Type:     "weak_cipher",
			Severity: types.SeverityMedium,
			Title:    "Weak Cipher Suite in Use",
			Description: fmt.Sprintf(
				"The connection uses %s: %s",
				cipherName, weakness,
			),
			Evidence: fmt.Sprintf("Negotiated cipher: %s (0x%04X)", cipherName, state.CipherSuite),
			Solution: "Configure the server to prefer strong cipher suites with forward secrecy.",
			Metadata: map[string]interface{}{
				"host":         host,
				"port":         port,
				"cipher_suite": cipherName,
				"cipher_id":    fmt.Sprintf("0x%04X", state.CipherSuite),
				"weakness":     weakness,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

func (s *sslScanner) checkRevocation(host, port string, certs []*x509.Certificate) []types.Finding {
	findings := []types.Finding{}

	for i, cert := range certs {
		if len(cert.CRLDistributionPoints) == 0 && len(cert.OCSPServer) == 0 {
			finding := types.Finding{
				Tool:     "ssl",
				Type:     "no_revocation_mechanism",
				Severity: types.SeverityLow,
				Title:    "No Certificate Revocation Mechanism",
				Description: fmt.Sprintf(
					"Certificate %d in chain has no CRL or OCSP endpoints",
					i,
				),
				Evidence: "No CRLDistributionPoints or OCSPServer fields found",
				Solution: "Configure certificates with proper revocation mechanisms.",
				Metadata: map[string]interface{}{
					"host":              host,
					"port":              port,
					"certificate_index": i,
					"subject":           cert.Subject.String(),
				},
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

func (s *sslScanner) verifyHostname(cert *x509.Certificate, hostname string) bool {
	err := cert.VerifyHostname(hostname)
	return err == nil
}

func (s *sslScanner) getProtocolRecommendation(protocol string) string {
	recommendations := map[string]string{
		"SSLv3":   "SSLv3 has critical vulnerabilities (POODLE). Disable immediately and use TLS 1.2 or higher.",
		"TLS 1.0": "TLS 1.0 has known weaknesses. Migrate to TLS 1.2 or TLS 1.3.",
		"TLS 1.1": "TLS 1.1 is deprecated. Upgrade to TLS 1.2 or TLS 1.3.",
	}

	if rec, ok := recommendations[protocol]; ok {
		return rec
	}

	return "Use TLS 1.2 or TLS 1.3 for optimal security."
}
