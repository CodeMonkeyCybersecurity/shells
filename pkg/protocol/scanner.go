// pkg/protocol/scanner.go
package protocol

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
	"github.com/google/uuid"
)

// Scanner implements protocol-specific security testing
type Scanner struct {
	config   Config
	logger   Logger
	tlsTest  *TLSScanner
	smtpTest *SMTPScanner
	ldapTest *LDAPScanner
}

// Config holds protocol scanner configuration
type Config struct {
	Timeout         time.Duration
	TLSMinVersion   uint16
	CheckCiphers    bool
	CheckVulns      bool
	SMTPCommands    []string
	LDAPSearchBase  string
	MaxWorkers      int
	FollowRedirects bool
}

// Logger interface
type Logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
}

// NewScanner creates a new protocol scanner
func NewScanner(config Config, logger Logger) *Scanner {
	return &Scanner{
		config:   config,
		logger:   logger,
		tlsTest:  NewTLSScanner(config, logger),
		smtpTest: NewSMTPScanner(config, logger),
		ldapTest: NewLDAPScanner(config, logger),
	}
}

// ScanTLS performs comprehensive SSL/TLS testing
func (s *Scanner) ScanTLS(ctx context.Context, target string) ([]types.Finding, error) {
	s.logger.Info("Starting TLS security scan", "target", target)

	host, port, err := parseTarget(target)
	if err != nil {
		return nil, err
	}

	findings := []types.Finding{}

	// Test supported protocols
	protocolFindings := s.tlsTest.TestProtocols(ctx, host, port)
	findings = append(findings, protocolFindings...)

	// Test cipher suites
	if s.config.CheckCiphers {
		cipherFindings := s.tlsTest.TestCipherSuites(ctx, host, port)
		findings = append(findings, cipherFindings...)
	}

	// Test certificate chain
	certFindings := s.tlsTest.TestCertificateChain(ctx, host, port)
	findings = append(findings, certFindings...)

	// Test known vulnerabilities
	if s.config.CheckVulns {
		vulnFindings := s.tlsTest.TestVulnerabilities(ctx, host, port)
		findings = append(findings, vulnFindings...)
	}

	// Add summary
	summary := s.createTLSSummary(findings, target)
	findings = append([]types.Finding{summary}, findings...)

	return findings, nil
}

// ScanSMTP performs SMTP security testing
func (s *Scanner) ScanSMTP(ctx context.Context, target string) ([]types.Finding, error) {
	s.logger.Info("Starting SMTP security scan", "target", target)

	findings := []types.Finding{}

	// Test user enumeration
	enumFindings := s.smtpTest.TestUserEnumeration(ctx, target)
	findings = append(findings, enumFindings...)

	// Test relay configuration
	relayFindings := s.smtpTest.TestOpenRelay(ctx, target)
	findings = append(findings, relayFindings...)

	// Test STARTTLS
	tlsFindings := s.smtpTest.TestSTARTTLS(ctx, target)
	findings = append(findings, tlsFindings...)

	// Test authentication methods
	authFindings := s.smtpTest.TestAuthentication(ctx, target)
	findings = append(findings, authFindings...)

	return findings, nil
}

// ScanLDAP performs LDAP security testing
func (s *Scanner) ScanLDAP(ctx context.Context, target string) ([]types.Finding, error) {
	s.logger.Info("Starting LDAP security scan", "target", target)

	findings := []types.Finding{}

	// Test anonymous bind
	anonFindings := s.ldapTest.TestAnonymousBind(ctx, target)
	findings = append(findings, anonFindings...)

	// Test null bind
	nullFindings := s.ldapTest.TestNullBind(ctx, target)
	findings = append(findings, nullFindings...)

	// Test information disclosure
	infoFindings := s.ldapTest.TestInformationDisclosure(ctx, target)
	findings = append(findings, infoFindings...)

	// Test LDAP injection points
	injectionFindings := s.ldapTest.TestInjection(ctx, target)
	findings = append(findings, injectionFindings...)

	return findings, nil
}

// Helper functions

func parseTarget(target string) (string, string, error) {
	// Handle different target formats
	if !strings.Contains(target, ":") {
		return target, "443", nil
	}

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", "", fmt.Errorf("invalid target format: %w", err)
	}

	return host, port, nil
}

func (s *Scanner) createTLSSummary(findings []types.Finding, target string) types.Finding {
	issues := map[string]int{
		"high":   0,
		"medium": 0,
		"low":    0,
		"info":   0,
	}

	for _, f := range findings {
		issues[string(f.Severity)]++
	}

	severity := types.SeverityInfo
	if issues["high"] > 0 {
		severity = types.SeverityHigh
	} else if issues["medium"] > 0 {
		severity = types.SeverityMedium
	} else if issues["low"] > 0 {
		severity = types.SeverityLow
	}

	now := time.Now()
	return types.Finding{
		ID:          uuid.New().String(),
		Tool:        "protocol-scanner",
		Type:        "TLS_SCAN_SUMMARY",
		Severity:    severity,
		Title:       fmt.Sprintf("TLS Security Assessment: %d issues found", len(findings)),
		Description: fmt.Sprintf("TLS scan found %d high, %d medium, %d low severity issues", issues["high"], issues["medium"], issues["low"]),
		Metadata: map[string]interface{}{
			"target":        target,
			"confidence":    "HIGH",
			"high_issues":   issues["high"],
			"medium_issues": issues["medium"],
			"low_issues":    issues["low"],
			"total_tests":   len(findings),
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}
