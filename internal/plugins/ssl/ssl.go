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
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/google/uuid"
)

type sslScanner struct {
	cfg    config.SSLConfig
	logger *logger.Logger
}

func NewScanner(cfg config.SSLConfig, log interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}) core.Scanner {
	start := time.Now()

	// Initialize enhanced logger for SSL scanner
	enhancedLogger, err := logger.New(config.LoggerConfig{Level: "debug", Format: "json"})
	if err != nil {
		// Fallback to basic logger if initialization fails
		enhancedLogger, _ = logger.New(config.LoggerConfig{Level: "info", Format: "json"})
	}
	enhancedLogger = enhancedLogger.WithComponent("ssl-scanner")

	ctx := context.Background()
	ctx, span := enhancedLogger.StartOperation(ctx, "ssl.NewScanner")
	defer func() {
		enhancedLogger.FinishOperation(ctx, span, "ssl.NewScanner", start, nil)
	}()

	enhancedLogger.WithContext(ctx).Infow("Initializing SSL/TLS scanner",
		"scanner_type", "ssl",
		"component", "ssl_tls_scanner",
		"timeout", cfg.Timeout.String(),
		"check_revocation", cfg.CheckRevocation,
	)

	// Log SSL scanner configuration
	enhancedLogger.WithContext(ctx).Debugw("SSL scanner configuration",
		"timeout_seconds", cfg.Timeout.Seconds(),
		"check_revocation", cfg.CheckRevocation,
		"capabilities", []string{"protocol_analysis", "certificate_validation", "cipher_suite_analysis", "revocation_checking"},
	)

	scanner := &sslScanner{
		cfg:    cfg,
		logger: enhancedLogger,
	}

	enhancedLogger.WithContext(ctx).Infow("SSL scanner initialized successfully",
		"scanner_type", "ssl",
		"total_init_duration_ms", time.Since(start).Milliseconds(),
		"security_checks", []string{"weak_protocols", "certificate_validation", "cipher_suites", "key_strength", "signature_algorithms"},
	)

	return scanner
}

func (s *sslScanner) Name() string {
	return "ssl"
}

func (s *sslScanner) Type() types.ScanType {
	return types.ScanTypeSSL
}

func (s *sslScanner) Validate(target string) error {
	start := time.Now()
	ctx := context.Background()
	ctx, span := s.logger.StartOperation(ctx, "ssl.Validate",
		"target", target,
	)
	var err error
	defer func() {
		s.logger.FinishOperation(ctx, span, "ssl.Validate", start, err)
	}()

	s.logger.WithContext(ctx).Debugw("Validating SSL target",
		"target", target,
		"target_length", len(target),
	)

	if target == "" {
		err = fmt.Errorf("target cannot be empty")
		s.logger.LogError(ctx, err, "ssl.Validate.empty",
			"validation_type", "empty_target",
		)
		return err
	}

	originalTarget := target
	if !strings.Contains(target, ":") {
		target = target + ":443"
		s.logger.WithContext(ctx).Debugw("Added default port",
			"original_target", originalTarget,
			"target_with_port", target,
			"default_port", "443",
		)
	}

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		s.logger.LogError(ctx, err, "ssl.Validate.split_host_port",
			"target", target,
			"validation_type", "host_port_parsing",
		)
		err = fmt.Errorf("invalid target format: %w", err)
		return err
	}

	s.logger.WithContext(ctx).Debugw("Target parsed successfully",
		"host", host,
		"port", port,
		"is_ip", net.ParseIP(host) != nil,
	)

	// Validate host resolution
	if net.ParseIP(host) == nil {
		// It's a hostname, not an IP
		resolveStart := time.Now()
		addrs, err := net.LookupHost(host)
		resolveDuration := time.Since(resolveStart)

		if err != nil {
			s.logger.LogError(ctx, err, "ssl.Validate.resolve",
				"host", host,
				"validation_type", "hostname_resolution",
				"resolve_duration_ms", resolveDuration.Milliseconds(),
			)
			err = fmt.Errorf("cannot resolve host: %w", err)
			return err
		}

		s.logger.WithContext(ctx).Debugw("Hostname resolution successful",
			"host", host,
			"resolved_addresses", addrs,
			"address_count", len(addrs),
			"resolve_duration_ms", resolveDuration.Milliseconds(),
		)
	} else {
		s.logger.WithContext(ctx).Debugw("Target is IP address",
			"host", host,
			"ip_version", getIPVersion(net.ParseIP(host)),
		)
	}

	s.logger.WithContext(ctx).Infow("SSL target validation successful",
		"target", target,
		"host", host,
		"port", port,
		"validation_duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

func (s *sslScanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	start := time.Now()
	scanID := uuid.New().String()

	ctx, span := s.logger.StartOperation(ctx, "ssl.Scan",
		"target", target,
		"scan_id", scanID,
	)
	var err error
	defer func() {
		s.logger.FinishOperation(ctx, span, "ssl.Scan", start, err)
	}()

	// Handle port specification
	originalTarget := target
	if !strings.Contains(target, ":") {
		port := options["port"]
		if port == "" {
			port = "443"
			s.logger.WithContext(ctx).Debugw("Using default SSL port",
				"scan_id", scanID,
				"port", port,
				"reason", "no port specified",
			)
		} else {
			s.logger.WithContext(ctx).Debugw("Using specified port",
				"scan_id", scanID,
				"port", port,
				"source", "options",
			)
		}
		target = target + ":" + port
	}

	s.logger.WithContext(ctx).Infow("Starting SSL/TLS scan",
		"scan_id", scanID,
		"target", target,
		"original_target", originalTarget,
		"timeout_seconds", s.cfg.Timeout.Seconds(),
		"check_revocation", s.cfg.CheckRevocation,
	)

	findings := []types.Finding{}
	host, port, _ := net.SplitHostPort(target)

	s.logger.WithContext(ctx).Debugw("Target parsed for SSL scan",
		"scan_id", scanID,
		"host", host,
		"port", port,
	)

	// Test TLS protocol versions
	protocolTestStart := time.Now()
	tlsConfigs := s.getTLSConfigs()
	supportedVersions := []string{}
	var conn *tls.Conn
	var state tls.ConnectionState
	protocolTestResults := make(map[string]interface{})

	s.logger.WithContext(ctx).Infow("Testing TLS protocol versions",
		"scan_id", scanID,
		"protocols_to_test", len(tlsConfigs),
		"target", target,
	)

	for version, config := range tlsConfigs {
		versionTestStart := time.Now()

		s.logger.WithContext(ctx).Debugw("Testing TLS version",
			"scan_id", scanID,
			"version", version,
			"target", target,
		)

		dialer := &net.Dialer{
			Timeout: s.cfg.Timeout,
		}

		tcpConn, err := dialer.DialContext(ctx, "tcp", target)
		if err != nil {
			protocolTestResults[version] = map[string]interface{}{
				"supported":        false,
				"error":            err.Error(),
				"test_duration_ms": time.Since(versionTestStart).Milliseconds(),
			}

			s.logger.WithContext(ctx).Debugw("TLS version connection failed",
				"scan_id", scanID,
				"version", version,
				"error", err.Error(),
				"test_duration_ms", time.Since(versionTestStart).Milliseconds(),
			)
			continue
		}

		tlsConn := tls.Client(tcpConn, config)
		tlsConn.SetDeadline(time.Now().Add(s.cfg.Timeout))

		err = tlsConn.HandshakeContext(ctx)
		tcpConn.Close()

		if err == nil {
			supportedVersions = append(supportedVersions, version)
			protocolTestResults[version] = map[string]interface{}{
				"supported":        true,
				"test_duration_ms": time.Since(versionTestStart).Milliseconds(),
			}

			s.logger.WithContext(ctx).Infow("TLS version supported",
				"scan_id", scanID,
				"version", version,
				"test_duration_ms", time.Since(versionTestStart).Milliseconds(),
			)

			if conn == nil {
				conn = tlsConn
				state = tlsConn.ConnectionState()

				s.logger.WithContext(ctx).Debugw("Using connection for detailed analysis",
					"scan_id", scanID,
					"version", version,
					"cipher_suite", tls.CipherSuiteName(state.CipherSuite),
				)
			}
		} else {
			protocolTestResults[version] = map[string]interface{}{
				"supported":        false,
				"error":            err.Error(),
				"test_duration_ms": time.Since(versionTestStart).Milliseconds(),
			}

			s.logger.WithContext(ctx).Debugw("TLS version handshake failed",
				"scan_id", scanID,
				"version", version,
				"error", err.Error(),
				"test_duration_ms", time.Since(versionTestStart).Milliseconds(),
			)
		}
	}

	protocolTestDuration := time.Since(protocolTestStart)
	s.logger.WithContext(ctx).Infow("TLS protocol testing completed",
		"scan_id", scanID,
		"protocol_test_duration_ms", protocolTestDuration.Milliseconds(),
		"supported_versions", supportedVersions,
		"total_versions_tested", len(tlsConfigs),
		"supported_count", len(supportedVersions),
	)

	if conn == nil {
		err = fmt.Errorf("failed to establish TLS connection to %s", target)
		s.logger.LogError(ctx, err, "ssl.Scan.no_connection",
			"scan_id", scanID,
			"target", target,
			"protocols_tested", len(tlsConfigs),
		)
		return findings, err
	}
	defer conn.Close()

	s.logger.WithContext(ctx).Infow("SSL connection established, running security checks",
		"scan_id", scanID,
		"target", target,
		"connection_state_version", state.Version,
		"negotiated_cipher", tls.CipherSuiteName(state.CipherSuite),
		"peer_certificates", len(state.PeerCertificates),
	)

	// Run protocol version checks
	protocolStart := time.Now()
	protocolFindings := s.checkProtocolVersions(ctx, scanID, host, port, supportedVersions)
	findings = append(findings, protocolFindings...)

	s.logger.WithContext(ctx).Debugw("Protocol version checks completed",
		"scan_id", scanID,
		"check_duration_ms", time.Since(protocolStart).Milliseconds(),
		"findings_count", len(protocolFindings),
	)

	// Run certificate checks
	certStart := time.Now()
	certFindings := s.checkCertificates(ctx, scanID, host, port, state.PeerCertificates)
	findings = append(findings, certFindings...)

	s.logger.WithContext(ctx).Debugw("Certificate checks completed",
		"scan_id", scanID,
		"check_duration_ms", time.Since(certStart).Milliseconds(),
		"findings_count", len(certFindings),
		"certificates_analyzed", len(state.PeerCertificates),
	)

	// Run cipher suite checks
	cipherStart := time.Now()
	cipherFindings := s.checkCipherSuites(ctx, scanID, host, port, state)
	findings = append(findings, cipherFindings...)

	s.logger.WithContext(ctx).Debugw("Cipher suite checks completed",
		"scan_id", scanID,
		"check_duration_ms", time.Since(cipherStart).Milliseconds(),
		"findings_count", len(cipherFindings),
		"cipher_suite", tls.CipherSuiteName(state.CipherSuite),
	)

	// Run revocation checks if enabled
	if s.cfg.CheckRevocation {
		revocationStart := time.Now()
		revocationFindings := s.checkRevocation(ctx, scanID, host, port, state.PeerCertificates)
		findings = append(findings, revocationFindings...)

		s.logger.WithContext(ctx).Debugw("Revocation checks completed",
			"scan_id", scanID,
			"check_duration_ms", time.Since(revocationStart).Milliseconds(),
			"findings_count", len(revocationFindings),
		)
	} else {
		s.logger.WithContext(ctx).Debugw("Revocation checks skipped",
			"scan_id", scanID,
			"reason", "check_revocation disabled",
		)
	}

	// Log scan completion with comprehensive metrics
	totalDuration := time.Since(start)
	severityBreakdown := make(map[types.Severity]int)
	for _, finding := range findings {
		severityBreakdown[finding.Severity]++
	}

	s.logger.WithContext(ctx).Infow("SSL scan completed successfully",
		"scan_id", scanID,
		"target", target,
		"total_duration_ms", totalDuration.Milliseconds(),
		"total_findings", len(findings),
		"severity_breakdown", severityBreakdown,
		"supported_protocols", supportedVersions,
		"protocol_test_results", protocolTestResults,
		"checks_performed", []string{"protocol_versions", "certificates", "cipher_suites", "revocation"},
	)

	// Add scan metadata to all findings
	for i := range findings {
		if findings[i].Metadata == nil {
			findings[i].Metadata = make(map[string]interface{})
		}
		findings[i].Metadata["scan_id"] = scanID
		findings[i].Metadata["scan_duration_ms"] = totalDuration.Milliseconds()
		findings[i].Metadata["supported_protocols"] = supportedVersions
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

func (s *sslScanner) checkProtocolVersions(ctx context.Context, scanID, host, port string, supported []string) []types.Finding {
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

func (s *sslScanner) checkCertificates(ctx context.Context, scanID, host, port string, certs []*x509.Certificate) []types.Finding {
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

func (s *sslScanner) checkCipherSuites(ctx context.Context, scanID, host, port string, state tls.ConnectionState) []types.Finding {
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

func (s *sslScanner) checkRevocation(ctx context.Context, scanID, host, port string, certs []*x509.Certificate) []types.Finding {
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

// Helper functions for enhanced logging

func getIPVersion(ip net.IP) string {
	if ip.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}
