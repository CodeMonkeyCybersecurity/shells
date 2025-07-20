// pkg/protocol/smtp.go
package protocol

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// SMTPScanner performs SMTP security testing
type SMTPScanner struct {
	config Config
	logger Logger
}

// NewSMTPScanner creates a new SMTP scanner
func NewSMTPScanner(config Config, logger Logger) *SMTPScanner {
	return &SMTPScanner{
		config: config,
		logger: logger,
	}
}

// TestUserEnumeration tests for SMTP user enumeration
func (s *SMTPScanner) TestUserEnumeration(ctx context.Context, target string) []types.Finding {
	findings := []types.Finding{}

	host, port, err := parseTarget(target)
	if err != nil {
		return findings
	}

	// Default SMTP port
	if port == "443" {
		port = "25"
	}

	// Test VRFY command
	vrfyVuln := s.testVRFY(ctx, host, port)
	if vrfyVuln {
		findings = append(findings, types.Finding{
			Type:        "SMTP_USER_ENUM_VRFY",
			Severity:    types.SeverityMedium,
			Title:       "SMTP user enumeration via VRFY",
			Description: "The SMTP server allows user enumeration through the VRFY command",
			Tool:        "protocol-smtp",
			Metadata: map[string]interface{}{
				"command":    "VRFY",
				"port":       port,
				"confidence": "HIGH",
				"target":     fmt.Sprintf("%s:%s", host, port),
			},
			Solution: "Disable VRFY command or configure it to always return the same response",
			References: []string{
				"https://tools.ietf.org/html/rfc5321#section-3.5.1",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	// Test EXPN command
	expnVuln := s.testEXPN(ctx, host, port)
	if expnVuln {
		findings = append(findings, types.Finding{
			Type:        "SMTP_USER_ENUM_EXPN",
			Severity:    "MEDIUM",
			Title:       "SMTP user enumeration via EXPN",
			Description: "The SMTP server allows user enumeration through the EXPN command",
			Metadata: map[string]interface{}{
				"command": "EXPN",
				"port":    port,
			},
			Solution: "Disable EXPN command or configure it to always return the same response",
			References: []string{
				"https://tools.ietf.org/html/rfc5321#section-3.5.2",
			},
			CreatedAt: time.Now(),
		})
	}

	// Test RCPT TO enumeration
	rcptVuln := s.testRCPTEnum(ctx, host, port)
	if rcptVuln {
		findings = append(findings, types.Finding{
			Type:        "SMTP_USER_ENUM_RCPT",
			Severity:    "LOW",
			Title:       "Possible SMTP user enumeration via RCPT TO",
			Description: "The SMTP server may allow user enumeration through different RCPT TO responses",
			Metadata: map[string]interface{}{
				"command": "RCPT TO",
				"port":    port,
			},
			Solution:  "Configure SMTP server to return consistent responses for invalid recipients",
			CreatedAt: time.Now(),
		})
	}

	return findings
}

// TestOpenRelay tests for open relay configuration
func (s *SMTPScanner) TestOpenRelay(ctx context.Context, target string) []types.Finding {
	findings := []types.Finding{}

	host, port, err := parseTarget(target)
	if err != nil {
		return findings
	}

	if port == "443" {
		port = "25"
	}

	// Test relay combinations
	relayTests := []struct {
		from string
		to   string
		desc string
	}{
		{
			from: "test@external.com",
			to:   "relay@external.com",
			desc: "External to external relay",
		},
		{
			from: "",
			to:   "test@external.com",
			desc: "Null sender relay",
		},
		{
			from: "test@[127.0.0.1]",
			to:   "test@external.com",
			desc: "IP literal relay",
		},
	}

	vulnerableRelays := []string{}

	for _, test := range relayTests {
		if s.testRelay(ctx, host, port, test.from, test.to) {
			vulnerableRelays = append(vulnerableRelays, test.desc)
		}
	}

	if len(vulnerableRelays) > 0 {
		findings = append(findings, types.Finding{
			Type:        "SMTP_OPEN_RELAY",
			Severity:    "CRITICAL",
			Title:       "SMTP open relay detected",
			Description: "The SMTP server is configured as an open relay, allowing anyone to send email through it",
			Metadata: map[string]interface{}{
				"vulnerable_relay_types": vulnerableRelays,
			},
			Solution: "Configure SMTP server to only relay mail for authenticated users or specific domains",
			References: []string{
				"https://www.rfc-editor.org/rfc/rfc5321",
				"https://www.spamhaus.org/faq/section/SMTP%20Open%20Relays",
			},
			CreatedAt: time.Now(),
		})
	}

	return findings
}

// TestSTARTTLS tests STARTTLS implementation
func (s *SMTPScanner) TestSTARTTLS(ctx context.Context, target string) []types.Finding {
	findings := []types.Finding{}

	host, port, err := parseTarget(target)
	if err != nil {
		return findings
	}

	if port == "443" {
		port = "25"
	}

	// Check if STARTTLS is supported
	supported, enforced := s.testSTARTTLSSupport(ctx, host, port)

	if !supported {
		findings = append(findings, types.Finding{
			Type:        "SMTP_NO_STARTTLS",
			Severity:    "HIGH",
			Title:       "SMTP server does not support STARTTLS",
			Description: "The SMTP server does not support STARTTLS, transmitting all data in plaintext",
			Solution:    "Enable STARTTLS support to encrypt SMTP communications",
			References: []string{
				"https://tools.ietf.org/html/rfc3207",
			},
			CreatedAt: time.Now(),
		})
	} else if !enforced {
		findings = append(findings, types.Finding{
			Type:        "SMTP_STARTTLS_NOT_ENFORCED",
			Severity:    "MEDIUM",
			Title:       "SMTP server does not enforce STARTTLS",
			Description: "The SMTP server supports but does not require STARTTLS, allowing plaintext connections",
			Solution:    "Configure SMTP server to require STARTTLS for all connections",
			CreatedAt:   time.Now(),
		})
	}

	// If STARTTLS is supported, test the TLS configuration
	if supported {
		tlsVulns := s.testSTARTTLSSecurity(ctx, host, port)
		findings = append(findings, tlsVulns...)
	}

	return findings
}

// TestAuthentication tests SMTP authentication methods
func (s *SMTPScanner) TestAuthentication(ctx context.Context, target string) []types.Finding {
	findings := []types.Finding{}

	host, port, err := parseTarget(target)
	if err != nil {
		return findings
	}

	if port == "443" {
		port = "25"
	}

	// Get supported auth methods
	authMethods := s.getSupportedAuth(ctx, host, port)

	// Check for insecure methods
	insecureMethods := []string{}
	for _, method := range authMethods {
		if isInsecureAuthMethod(method) {
			insecureMethods = append(insecureMethods, method)
		}
	}

	if len(insecureMethods) > 0 {
		findings = append(findings, types.Finding{
			Type:        "SMTP_INSECURE_AUTH",
			Severity:    "MEDIUM",
			Title:       fmt.Sprintf("Insecure authentication methods: %s", strings.Join(insecureMethods, ", ")),
			Description: "The SMTP server supports authentication methods that transmit credentials insecurely",
			Metadata: map[string]interface{}{
				"insecure_methods": insecureMethods,
				"all_methods":      authMethods,
			},
			Solution:  "Disable PLAIN and LOGIN authentication methods over non-TLS connections",
			CreatedAt: time.Now(),
		})
	}

	// Test for anonymous authentication
	if s.testAnonymousAuth(ctx, host, port) {
		findings = append(findings, types.Finding{
			Type:        "SMTP_ANONYMOUS_AUTH",
			Severity:    "HIGH",
			Title:       "SMTP server allows anonymous authentication",
			Description: "The SMTP server accepts anonymous authentication, potentially allowing unauthorized access",
			Solution:    "Disable anonymous authentication",
			CreatedAt:   time.Now(),
		})
	}

	return findings
}

// Helper methods

func (s *SMTPScanner) testVRFY(ctx context.Context, host, port string) bool {
	conn, err := s.connectSMTP(ctx, host, port)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Send VRFY commands
	validUser := s.sendCommand(conn, "VRFY postmaster")
	invalidUser := s.sendCommand(conn, "VRFY definitely-not-a-real-user-12345")

	// If responses are different, enumeration is possible
	return validUser != invalidUser
}

func (s *SMTPScanner) testEXPN(ctx context.Context, host, port string) bool {
	conn, err := s.connectSMTP(ctx, host, port)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Send EXPN command
	response := s.sendCommand(conn, "EXPN postmaster")

	// If command is not rejected, it's enabled
	return !strings.HasPrefix(response, "5")
}

func (s *SMTPScanner) testRCPTEnum(ctx context.Context, host, port string) bool {
	conn, err := s.connectSMTP(ctx, host, port)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Start mail transaction
	s.sendCommand(conn, "MAIL FROM:<test@test.com>")

	// Test different recipients
	validResp := s.sendCommand(conn, "RCPT TO:<postmaster@localhost>")
	invalidResp := s.sendCommand(conn, "RCPT TO:<definitely-not-real-12345@localhost>")

	// Reset
	s.sendCommand(conn, "RSET")

	// Check if responses differ significantly
	return validResp != invalidResp &&
		strings.HasPrefix(validResp, "2") &&
		strings.HasPrefix(invalidResp, "5")
}

func (s *SMTPScanner) testRelay(ctx context.Context, host, port, from, to string) bool {
	conn, err := s.connectSMTP(ctx, host, port)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Try to relay mail
	if from != "" {
		s.sendCommand(conn, fmt.Sprintf("MAIL FROM:<%s>", from))
	} else {
		s.sendCommand(conn, "MAIL FROM:<>")
	}

	response := s.sendCommand(conn, fmt.Sprintf("RCPT TO:<%s>", to))

	// Reset
	s.sendCommand(conn, "RSET")

	// If accepted (2xx response), relay is possible
	return strings.HasPrefix(response, "2")
}

func (s *SMTPScanner) testSTARTTLSSupport(ctx context.Context, host, port string) (supported, enforced bool) {
	// Test with STARTTLS
	conn1, err := s.connectSMTP(ctx, host, port)
	if err != nil {
		return false, false
	}
	defer conn1.Close()

	response := s.sendCommand(conn1, "STARTTLS")
	supported = strings.HasPrefix(response, "2")

	// Test without STARTTLS to see if plaintext is allowed
	conn2, err := s.connectSMTP(ctx, host, port)
	if err != nil {
		return supported, true
	}
	defer conn2.Close()

	// Try to send mail without STARTTLS
	s.sendCommand(conn2, "MAIL FROM:<test@test.com>")
	response = s.sendCommand(conn2, "RCPT TO:<test@test.com>")

	// If rejected, STARTTLS is enforced
	enforced = !strings.HasPrefix(response, "2")

	return supported, enforced
}

func (s *SMTPScanner) testSTARTTLSSecurity(ctx context.Context, host, port string) []types.Finding {
	findings := []types.Finding{}

	// Connect and initiate STARTTLS
	conn, err := s.connectSMTP(ctx, host, port)
	if err != nil {
		return findings
	}
	defer conn.Close()

	response := s.sendCommand(conn, "STARTTLS")
	if !strings.HasPrefix(response, "2") {
		return findings
	}

	// Upgrade to TLS
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return findings
	}

	// Check TLS version
	state := tlsConn.ConnectionState()
	if state.Version < tls.VersionTLS12 {
		findings = append(findings, types.Finding{
			Type:        "SMTP_WEAK_TLS",
			Severity:    types.SeverityMedium,
			Title:       "SMTP STARTTLS uses weak TLS version",
			Description: fmt.Sprintf("STARTTLS negotiated TLS %s which is considered weak", getTLSVersionString(state.Version)),
			Tool:        "protocol-smtp",
			Metadata: map[string]interface{}{
				"confidence": "HIGH",
				"target":     fmt.Sprintf("%s:%s", host, port),
			},
			Solution:  "Configure SMTP server to use TLS 1.2 or higher",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	return findings
}

func (s *SMTPScanner) getSupportedAuth(ctx context.Context, host, port string) []string {
	conn, err := s.connectSMTP(ctx, host, port)
	if err != nil {
		return []string{}
	}
	defer conn.Close()

	// Send EHLO to get capabilities
	response := s.sendCommand(conn, "EHLO scanner.local")

	// Parse AUTH line
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "250-AUTH ") || strings.HasPrefix(line, "250 AUTH ") {
			authLine := strings.TrimPrefix(line, "250-AUTH ")
			authLine = strings.TrimPrefix(authLine, "250 AUTH ")
			return strings.Split(authLine, " ")
		}
	}

	return []string{}
}

func (s *SMTPScanner) testAnonymousAuth(ctx context.Context, host, port string) bool {
	conn, err := s.connectSMTP(ctx, host, port)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Try AUTH ANONYMOUS
	response := s.sendCommand(conn, "AUTH ANONYMOUS")
	return strings.HasPrefix(response, "2")
}

func (s *SMTPScanner) connectSMTP(ctx context.Context, host, port string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: s.config.Timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}

	// Read banner
	reader := bufio.NewReader(conn)
	_, err = reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Send EHLO
	fmt.Fprintf(conn, "EHLO scanner.local\r\n")

	// Read response
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}

		// Check if this is the last line
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	return conn, nil
}

func (s *SMTPScanner) sendCommand(conn net.Conn, command string) string {
	fmt.Fprintf(conn, "%s\r\n", command)

	reader := bufio.NewReader(conn)
	response := ""

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		response += line

		// Check if this is the last line
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	return response
}

func isInsecureAuthMethod(method string) bool {
	insecure := []string{"PLAIN", "LOGIN"}
	for _, m := range insecure {
		if method == m {
			return true
		}
	}
	return false
}

func getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "Unknown"
	}
}
