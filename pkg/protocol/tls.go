// pkg/protocol/tls.go
package protocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// TLSScanner performs comprehensive TLS/SSL testing
type TLSScanner struct {
	config Config
	logger Logger
}

// NewTLSScanner creates a new TLS scanner
func NewTLSScanner(config Config, logger Logger) *TLSScanner {
	return &TLSScanner{
		config: config,
		logger: logger,
	}
}

// TestProtocols tests supported TLS protocols
func (t *TLSScanner) TestProtocols(ctx context.Context, host, port string) []types.Finding {
	findings := []types.Finding{}

	protocols := []struct {
		name    string
		version uint16
		secure  bool
	}{
		{"SSL 2.0", tls.VersionSSL30 - 1, false}, // SSL 2.0
		{"SSL 3.0", tls.VersionSSL30, false},
		{"TLS 1.0", tls.VersionTLS10, false},
		{"TLS 1.1", tls.VersionTLS11, false},
		{"TLS 1.2", tls.VersionTLS12, true},
		{"TLS 1.3", tls.VersionTLS13, true},
	}

	supportedProtocols := []string{}
	insecureProtocols := []string{}

	for _, proto := range protocols {
		if t.testProtocol(ctx, host, port, proto.version) {
			supportedProtocols = append(supportedProtocols, proto.name)
			if !proto.secure {
				insecureProtocols = append(insecureProtocols, proto.name)
			}
		}
	}

	// Create findings for insecure protocols
	if len(insecureProtocols) > 0 {
		findings = append(findings, types.Finding{
			Type:        "TLS_INSECURE_PROTOCOL",
			Severity:    types.SeverityHigh,
			Title:       fmt.Sprintf("Insecure TLS protocols supported: %s", strings.Join(insecureProtocols, ", ")),
			Description: "The server supports outdated and insecure TLS protocol versions that are vulnerable to various attacks",
			Tool:        "protocol-tls",
			Metadata: map[string]interface{}{
				"insecure_protocols": insecureProtocols,
				"all_protocols":      supportedProtocols,
				"confidence":         "HIGH",
				"target":             fmt.Sprintf("%s:%s", host, port),
			},
			Solution: "Disable support for SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1. Only support TLS 1.2 and TLS 1.3.",
			References: []string{
				"https://tools.ietf.org/html/rfc8996",
				"https://www.ssllabs.com/ssltest/",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	// Info finding for supported protocols
	findings = append(findings, types.Finding{
		Type:        "TLS_PROTOCOLS_INFO",
		Severity:    types.SeverityInfo,
		Title:       "Supported TLS protocols",
		Description: fmt.Sprintf("The server supports the following protocols: %s", strings.Join(supportedProtocols, ", ")),
		Tool:        "protocol-tls",
		Metadata: map[string]interface{}{
			"protocols":  supportedProtocols,
			"confidence": "HIGH",
			"target":     fmt.Sprintf("%s:%s", host, port),
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	return findings
}

// TestCipherSuites tests supported cipher suites
func (t *TLSScanner) TestCipherSuites(ctx context.Context, host, port string) []types.Finding {
	findings := []types.Finding{}

	// Categories of cipher suites
	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	}

	// Test each cipher suite
	supportedWeak := []string{}
	supportedStrong := []string{}

	for _, suite := range tls.CipherSuites() {
		if t.testCipherSuite(ctx, host, port, suite.ID) {
			if isWeakCipher(suite.ID, weakCiphers) {
				supportedWeak = append(supportedWeak, suite.Name)
			} else {
				supportedStrong = append(supportedStrong, suite.Name)
			}
		}
	}

	// Create findings
	if len(supportedWeak) > 0 {
		findings = append(findings, types.Finding{
			Type:        "TLS_WEAK_CIPHER",
			Severity:    types.SeverityMedium,
			Title:       fmt.Sprintf("Weak cipher suites supported: %d found", len(supportedWeak)),
			Description: "The server supports cipher suites with known weaknesses",
			Tool:        "protocol-tls",
			Metadata: map[string]interface{}{
				"weak_ciphers": supportedWeak,
				"confidence":   "HIGH",
				"target":       fmt.Sprintf("%s:%s", host, port),
			},
			Solution: "Disable weak cipher suites and only use strong, modern ciphers with forward secrecy",
			References: []string{
				"https://wiki.mozilla.org/Security/Server_Side_TLS",
				"https://ciphersuite.info/",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	// Check for forward secrecy
	hasForwardSecrecy := false
	for _, cipher := range supportedStrong {
		if strings.Contains(cipher, "ECDHE") || strings.Contains(cipher, "DHE") {
			hasForwardSecrecy = true
			break
		}
	}

	if !hasForwardSecrecy && len(supportedStrong) > 0 {
		findings = append(findings, types.Finding{
			Type:        "TLS_NO_FORWARD_SECRECY",
			Severity:    types.SeverityMedium,
			Title:       "No cipher suites with forward secrecy",
			Description: "The server does not support any cipher suites that provide forward secrecy",
			Tool:        "protocol-tls",
			Metadata: map[string]interface{}{
				"ciphers":    supportedStrong,
				"confidence": "HIGH",
				"target":     fmt.Sprintf("%s:%s", host, port),
			},
			Solution:  "Enable ECDHE or DHE cipher suites to provide forward secrecy",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	return findings
}

// TestCertificateChain tests the certificate chain
func (t *TLSScanner) TestCertificateChain(ctx context.Context, host, port string) []types.Finding {
	findings := []types.Finding{}

	// Connect and get certificates
	conn, err := t.tlsConnect(ctx, host, port, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return findings
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return findings
	}

	cert := state.PeerCertificates[0]

	// Check certificate validity
	now := time.Now()
	if now.Before(cert.NotBefore) {
		findings = append(findings, types.Finding{
			Type:        "TLS_CERT_NOT_YET_VALID",
			Severity:    types.SeverityHigh,
			Title:       "Certificate not yet valid",
			Description: fmt.Sprintf("Certificate is not valid until %s", cert.NotBefore),
			Tool:        "protocol-tls",
			Metadata: map[string]interface{}{
				"not_before": cert.NotBefore,
				"current":    now,
				"confidence": "HIGH",
				"target":     fmt.Sprintf("%s:%s", host, port),
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	if now.After(cert.NotAfter) {
		findings = append(findings, types.Finding{
			Type:        "TLS_CERT_EXPIRED",
			Severity:    types.SeverityHigh,
			Title:       "Certificate has expired",
			Description: fmt.Sprintf("Certificate expired on %s", cert.NotAfter),
			Tool:        "protocol-tls",
			Metadata: map[string]interface{}{
				"not_after":  cert.NotAfter,
				"current":    now,
				"confidence": "HIGH",
				"target":     fmt.Sprintf("%s:%s", host, port),
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	} else {
		// Check if expiring soon (30 days)
		daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
		if daysUntilExpiry < 30 {
			findings = append(findings, types.Finding{
				Type:        "TLS_CERT_EXPIRING_SOON",
				Severity:    types.SeverityMedium,
				Title:       fmt.Sprintf("Certificate expiring in %d days", daysUntilExpiry),
				Description: "Certificate is expiring soon and should be renewed",
				Tool:        "protocol-tls",
				Metadata: map[string]interface{}{
					"days_remaining": daysUntilExpiry,
					"expires":        cert.NotAfter,
					"confidence":     "HIGH",
					"target":         fmt.Sprintf("%s:%s", host, port),
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			})
		}
	}

	// Check hostname verification
	if err := cert.VerifyHostname(host); err != nil {
		findings = append(findings, types.Finding{
			Type:        "TLS_HOSTNAME_MISMATCH",
			Severity:    types.SeverityHigh,
			Title:       "Certificate hostname mismatch",
			Description: fmt.Sprintf("Certificate is not valid for hostname %s", host),
			Tool:        "protocol-tls",
			Metadata: map[string]interface{}{
				"requested_host": host,
				"cert_hosts":     cert.DNSNames,
				"subject":        cert.Subject.String(),
				"confidence":     "HIGH",
				"target":         fmt.Sprintf("%s:%s", host, port),
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	// Check weak signature algorithms
	if isWeakSignatureAlgorithm(cert.SignatureAlgorithm) {
		findings = append(findings, types.Finding{
			Type:        "TLS_WEAK_SIGNATURE",
			Severity:    types.SeverityMedium,
			Title:       fmt.Sprintf("Weak signature algorithm: %s", cert.SignatureAlgorithm),
			Description: "Certificate uses a weak signature algorithm",
			Tool:        "protocol-tls",
			Metadata: map[string]interface{}{
				"algorithm":  cert.SignatureAlgorithm.String(),
				"confidence": "HIGH",
				"target":     fmt.Sprintf("%s:%s", host, port),
			},
			Solution:  "Use SHA256 or stronger signature algorithms",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	// Check key size
	keySize := getPublicKeySize(cert)
	if keySize > 0 && keySize < 2048 {
		findings = append(findings, types.Finding{
			Type:        "TLS_WEAK_KEY",
			Severity:    types.SeverityHigh,
			Title:       fmt.Sprintf("Weak key size: %d bits", keySize),
			Description: "Certificate uses a key size that is considered weak",
			Tool:        "protocol-tls",
			Metadata: map[string]interface{}{
				"key_size":   keySize,
				"confidence": "HIGH",
				"target":     fmt.Sprintf("%s:%s", host, port),
			},
			Solution:  "Use at least 2048-bit RSA keys or 256-bit ECC keys",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	return findings
}

// TestVulnerabilities tests for known TLS vulnerabilities
func (t *TLSScanner) TestVulnerabilities(ctx context.Context, host, port string) []types.Finding {
	findings := []types.Finding{}

	// Test for Heartbleed
	if t.testHeartbleed(ctx, host, port) {
		findings = append(findings, types.Finding{
			Type:        "TLS_HEARTBLEED",
			Severity:    types.SeverityCritical,
			Title:       "Server vulnerable to Heartbleed (CVE-2014-0160)",
			Description: "The server is vulnerable to the Heartbleed bug, which allows remote attackers to read memory",
			Tool:        "protocol-tls",
			Metadata: map[string]interface{}{
				"cve":        "CVE-2014-0160",
				"confidence": "HIGH",
				"target":     fmt.Sprintf("%s:%s", host, port),
			},
			Solution: "Update OpenSSL to a patched version",
			References: []string{
				"https://heartbleed.com/",
				"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	// Test for POODLE
	if t.testPOODLE(ctx, host, port) {
		findings = append(findings, types.Finding{
			Type:        "TLS_POODLE",
			Severity:    types.SeverityHigh,
			Title:       "Server vulnerable to POODLE (CVE-2014-3566)",
			Description: "The server is vulnerable to the POODLE attack due to SSL 3.0 support",
			Tool:        "protocol-tls",
			Metadata: map[string]interface{}{
				"cve":        "CVE-2014-3566",
				"confidence": "HIGH",
				"target":     fmt.Sprintf("%s:%s", host, port),
			},
			Solution: "Disable SSL 3.0 support",
			References: []string{
				"https://www.openssl.org/~bodo/ssl-poodle.pdf",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	// Test for CRIME
	if t.testCRIME(ctx, host, port) {
		findings = append(findings, types.Finding{
			Type:        "TLS_CRIME",
			Severity:    types.SeverityMedium,
			Title:       "Server vulnerable to CRIME attack",
			Description: "The server has TLS compression enabled, making it vulnerable to CRIME",
			Tool:        "protocol-tls",
			Metadata: map[string]interface{}{
				"confidence": "HIGH",
				"target":     fmt.Sprintf("%s:%s", host, port),
			},
			Solution:  "Disable TLS compression",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	// Test for BEAST
	if t.testBEAST(ctx, host, port) {
		findings = append(findings, types.Finding{
			Type:        "TLS_BEAST",
			Severity:    types.SeverityMedium,
			Title:       "Server vulnerable to BEAST attack",
			Description: "The server uses CBC ciphers with TLS 1.0, making it vulnerable to BEAST",
			Tool:        "protocol-tls",
			Metadata: map[string]interface{}{
				"confidence": "HIGH",
				"target":     fmt.Sprintf("%s:%s", host, port),
			},
			Solution:  "Prefer RC4 ciphers for TLS 1.0 or disable TLS 1.0",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	// Test for renegotiation
	if t.testInsecureRenegotiation(ctx, host, port) {
		findings = append(findings, types.Finding{
			Type:        "TLS_INSECURE_RENEGOTIATION",
			Severity:    types.SeverityMedium,
			Title:       "Server allows insecure renegotiation",
			Description: "The server allows client-initiated renegotiation which can lead to DoS",
			Tool:        "protocol-tls",
			Metadata: map[string]interface{}{
				"confidence": "HIGH",
				"target":     fmt.Sprintf("%s:%s", host, port),
			},
			Solution:  "Disable client-initiated renegotiation",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	return findings
}

// Helper methods

func (t *TLSScanner) testProtocol(ctx context.Context, host, port string, version uint16) bool {
	config := &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true,
	}

	conn, err := t.tlsConnect(ctx, host, port, config)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (t *TLSScanner) testCipherSuite(ctx context.Context, host, port string, cipher uint16) bool {
	config := &tls.Config{
		CipherSuites:       []uint16{cipher},
		InsecureSkipVerify: true,
	}

	conn, err := t.tlsConnect(ctx, host, port, config)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (t *TLSScanner) tlsConnect(ctx context.Context, host, port string, config *tls.Config) (*tls.Conn, error) {
	dialer := &net.Dialer{
		Timeout: t.config.Timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func isWeakCipher(cipher uint16, weakList []uint16) bool {
	for _, weak := range weakList {
		if cipher == weak {
			return true
		}
	}
	return false
}

func isWeakSignatureAlgorithm(algo x509.SignatureAlgorithm) bool {
	weak := []x509.SignatureAlgorithm{
		x509.MD5WithRSA,
		x509.SHA1WithRSA,
		x509.DSAWithSHA1,
		x509.ECDSAWithSHA1,
	}

	for _, w := range weak {
		if algo == w {
			return true
		}
	}
	return false
}

func getPublicKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	default:
		return 0
	}
}

// Vulnerability test stubs (would need full implementations)

func (t *TLSScanner) testHeartbleed(ctx context.Context, host, port string) bool {
	// Simplified test - real implementation would send heartbeat request
	return false
}

func (t *TLSScanner) testPOODLE(ctx context.Context, host, port string) bool {
	// Test if SSL 3.0 is supported
	return t.testProtocol(ctx, host, port, tls.VersionSSL30)
}

func (t *TLSScanner) testCRIME(ctx context.Context, host, port string) bool {
	// Test for TLS compression - simplified
	// Real implementation would check for compression in handshake
	return false
}

func (t *TLSScanner) testBEAST(ctx context.Context, host, port string) bool {
	// Test if TLS 1.0 with CBC ciphers is supported
	if !t.testProtocol(ctx, host, port, tls.VersionTLS10) {
		return false
	}

	// Check for CBC ciphers
	cbcCiphers := []uint16{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	}

	for _, cipher := range cbcCiphers {
		if t.testCipherSuite(ctx, host, port, cipher) {
			return true
		}
	}

	return false
}

func (t *TLSScanner) testInsecureRenegotiation(ctx context.Context, host, port string) bool {
	// Simplified test - real implementation would attempt renegotiation
	return false
}
