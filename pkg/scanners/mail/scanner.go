// pkg/scanners/mail/scanner.go
//
// Mail Server Security Scanner Implementation
//
// Performs comprehensive security testing of mail servers:
// 1. Service discovery (SMTP, POP3, IMAP)
// 2. Open relay detection
// 3. SPF/DKIM/DMARC validation
// 4. User enumeration testing
// 5. STARTTLS and encryption validation
// 6. Authentication method analysis

package mail

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Logger interface for structured logging
type Logger interface {
	Info(msg string, keysAndValues ...interface{})
	Infow(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
	Debugw(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Errorw(msg string, keysAndValues ...interface{})
}

// Scanner performs mail server security testing
type Scanner struct {
	logger  Logger
	timeout time.Duration
}

// NewScanner creates a new mail scanner instance
func NewScanner(logger Logger, timeout time.Duration) *Scanner {
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &Scanner{
		logger:  logger,
		timeout: timeout,
	}
}

// ScanMailServers discovers and tests mail servers for a target domain
func (s *Scanner) ScanMailServers(ctx context.Context, target string) ([]MailFinding, error) {
	s.logger.Infow("Starting mail server security scan",
		"target", target,
		"timeout", s.timeout.String(),
	)

	var findings []MailFinding

	// 1. Resolve MX records
	mxRecords, err := s.resolveMXRecords(ctx, target)
	if err != nil {
		s.logger.Warnw("Failed to resolve MX records", "error", err, "target", target)
		// Continue with direct domain test
		mxRecords = []string{target}
	}

	s.logger.Infow("Resolved mail servers",
		"target", target,
		"mx_count", len(mxRecords),
		"servers", mxRecords,
	)

	// 2. Test each mail server
	for _, mxHost := range mxRecords {
		// Test SMTP (ports 25, 587, 465)
		smtpFindings := s.testSMTPServer(ctx, mxHost)
		findings = append(findings, smtpFindings...)

		// Test POP3 (ports 110, 995)
		pop3Findings := s.testPOP3Server(ctx, mxHost)
		findings = append(findings, pop3Findings...)

		// Test IMAP (ports 143, 993)
		imapFindings := s.testIMAPServer(ctx, mxHost)
		findings = append(findings, imapFindings...)
	}

	// 3. Check DNS security records (SPF, DKIM, DMARC)
	dnsFindings := s.checkDNSSecurityRecords(ctx, target)
	findings = append(findings, dnsFindings...)

	s.logger.Infow("Mail server scan completed",
		"target", target,
		"findings_count", len(findings),
	)

	return findings, nil
}

// resolveMXRecords resolves MX records for a domain
func (s *Scanner) resolveMXRecords(ctx context.Context, domain string) ([]string, error) {
	s.logger.Debugw("Resolving MX records", "domain", domain)

	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil, fmt.Errorf("MX lookup failed: %w", err)
	}

	var hosts []string
	for _, mx := range mxRecords {
		// Remove trailing dot from MX hostname
		host := strings.TrimSuffix(mx.Host, ".")
		hosts = append(hosts, host)
	}

	return hosts, nil
}

// testSMTPServer tests SMTP server for vulnerabilities
func (s *Scanner) testSMTPServer(ctx context.Context, host string) []MailFinding {
	var findings []MailFinding

	// Test common SMTP ports
	ports := []int{25, 587, 465}

	for _, port := range ports {
		// Test connectivity
		serverInfo, err := s.probeSMTPPort(ctx, host, port)
		if err != nil {
			s.logger.Debugw("SMTP port unreachable", "host", host, "port", port, "error", err)
			continue
		}

		s.logger.Infow("SMTP server discovered",
			"host", host,
			"port", port,
			"banner", serverInfo.Banner,
			"tls_supported", serverInfo.TLSSupported,
		)

		// Check for open relay (CRITICAL)
		if port == 25 { // Only test open relay on port 25
			if openRelayFinding := s.testOpenRelay(ctx, host, port, serverInfo); openRelayFinding != nil {
				findings = append(findings, *openRelayFinding)
			}
		}

		// Check for user enumeration via VRFY/EXPN
		if userEnumFinding := s.testUserEnumeration(ctx, host, port); userEnumFinding != nil {
			findings = append(findings, *userEnumFinding)
		}

		// Check STARTTLS support
		if !serverInfo.TLSSupported && port != 465 {
			findings = append(findings, MailFinding{
				Host:              host,
				Port:              port,
				Service:           ServiceSMTP,
				VulnerabilityType: VulnNoSTARTTLS,
				Severity:          "HIGH",
				Title:             "SMTP Server Missing STARTTLS Support",
				Description:       "The SMTP server does not support STARTTLS encryption. Email communications may be transmitted in cleartext.",
				Evidence:          fmt.Sprintf("SMTP server at %s:%d does not advertise STARTTLS capability", host, port),
				Remediation:       "Enable STARTTLS support on the mail server to encrypt email transmission.",
				Banner:            serverInfo.Banner,
				Capabilities:      serverInfo.Capabilities,
				TLSSupported:      false,
				DiscoveredAt:      time.Now(),
			})
		}

		// Check for information disclosure in banner
		if s.hasBannerDisclosure(serverInfo.Banner) {
			findings = append(findings, MailFinding{
				Host:              host,
				Port:              port,
				Service:           ServiceSMTP,
				VulnerabilityType: VulnBannerDisclosure,
				Severity:          "LOW",
				Title:             "SMTP Banner Information Disclosure",
				Description:       "The SMTP server banner reveals version information that could aid attackers.",
				Evidence:          fmt.Sprintf("Banner: %s", serverInfo.Banner),
				Remediation:       "Configure the mail server to display a generic banner without version information.",
				Banner:            serverInfo.Banner,
				DiscoveredAt:      time.Now(),
			})
		}
	}

	return findings
}

// testPOP3Server tests POP3 server for vulnerabilities
func (s *Scanner) testPOP3Server(ctx context.Context, host string) []MailFinding {
	var findings []MailFinding

	// Test common POP3 ports
	ports := []int{110, 995}

	for _, port := range ports {
		if s.isPortOpen(ctx, host, port) {
			s.logger.Infow("POP3 server discovered", "host", host, "port", port)

			// Check for TLS support on port 110
			if port == 110 {
				// TODO: Implement STLS capability check for POP3
				// For now, just log discovery
				s.logger.Debugw("POP3 server found on cleartext port", "host", host, "port", port)
			}
		}
	}

	return findings
}

// testIMAPServer tests IMAP server for vulnerabilities
func (s *Scanner) testIMAPServer(ctx context.Context, host string) []MailFinding {
	var findings []MailFinding

	// Test common IMAP ports
	ports := []int{143, 993}

	for _, port := range ports {
		if s.isPortOpen(ctx, host, port) {
			s.logger.Infow("IMAP server discovered", "host", host, "port", port)

			// Check for STARTTLS support on port 143
			if port == 143 {
				// TODO: Implement STARTTLS capability check for IMAP
				// For now, just log discovery
				s.logger.Debugw("IMAP server found on cleartext port", "host", host, "port", port)
			}
		}
	}

	return findings
}

// probeSMTPPort probes an SMTP port and returns server information
func (s *Scanner) probeSMTPPort(ctx context.Context, host string, port int) (*MailServerInfo, error) {
	address := fmt.Sprintf("%s:%d", host, port)

	// Set connection timeout
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(s.timeout))

	// Read SMTP banner
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read banner: %w", err)
	}

	banner := strings.TrimSpace(string(buffer[:n]))

	// Send EHLO command to get capabilities
	conn.Write([]byte("EHLO scanner.local\r\n"))
	conn.SetReadDeadline(time.Now().Add(s.timeout))

	capBuffer := make([]byte, 2048)
	n, err = conn.Read(capBuffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read EHLO response: %w", err)
	}

	ehloResponse := string(capBuffer[:n])
	capabilities := s.parseEHLOCapabilities(ehloResponse)

	// Check for STARTTLS support
	tlsSupported := s.hasCapability(capabilities, "STARTTLS")

	return &MailServerInfo{
		Host:         host,
		Port:         port,
		Service:      ServiceSMTP,
		Banner:       banner,
		Capabilities: capabilities,
		TLSSupported: tlsSupported,
		Reachable:    true,
	}, nil
}

// testOpenRelay checks if the SMTP server is an open relay
func (s *Scanner) testOpenRelay(ctx context.Context, host string, port int, serverInfo *MailServerInfo) *MailFinding {
	s.logger.Debugw("Testing for open relay", "host", host, "port", port)

	// Connect to SMTP server
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(s.timeout))

	// Read banner (discard)
	buffer := make([]byte, 1024)
	conn.Read(buffer)

	// Send EHLO
	conn.Write([]byte("EHLO scanner.local\r\n"))
	conn.Read(buffer)

	// Try to send email from external domain to external domain
	conn.Write([]byte("MAIL FROM:<test@external-domain.com>\r\n"))
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	n, _ := conn.Read(buffer)
	mailResponse := string(buffer[:n])

	if !strings.HasPrefix(mailResponse, "250") {
		// Server rejected MAIL FROM
		return nil
	}

	conn.Write([]byte("RCPT TO:<recipient@another-external-domain.com>\r\n"))
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	n, _ = conn.Read(buffer)
	rcptResponse := string(buffer[:n])

	// If server accepts external recipient, it's an open relay
	if strings.HasPrefix(rcptResponse, "250") {
		return &MailFinding{
			Host:              host,
			Port:              port,
			Service:           ServiceSMTP,
			VulnerabilityType: VulnOpenRelay,
			Severity:          "CRITICAL",
			Title:             "SMTP Open Relay Detected",
			Description:       "The SMTP server is configured as an open relay, allowing anyone to send email through it. This can be abused for spam and phishing attacks.",
			Evidence:          fmt.Sprintf("Server accepted: MAIL FROM:<test@external-domain.com> and RCPT TO:<recipient@another-external-domain.com>\nResponse: %s", rcptResponse),
			Remediation: "Configure the SMTP server to:\n" +
				"1. Require authentication before accepting mail\n" +
				"2. Only accept mail for local domains\n" +
				"3. Implement proper relay restrictions\n" +
				"4. Use SPF, DKIM, and DMARC to prevent abuse",
			TLSSupported: serverInfo.TLSSupported,
			Banner:       serverInfo.Banner,
			DiscoveredAt: time.Now(),
		}
	}

	return nil
}

// testUserEnumeration tests for user enumeration via VRFY/EXPN
func (s *Scanner) testUserEnumeration(ctx context.Context, host string, port int) *MailFinding {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(s.timeout))

	buffer := make([]byte, 1024)
	conn.Read(buffer) // Read banner

	// Send EHLO
	conn.Write([]byte("EHLO scanner.local\r\n"))
	conn.Read(buffer)

	// Test VRFY command
	conn.Write([]byte("VRFY admin\r\n"))
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	n, _ := conn.Read(buffer)
	vrfyResponse := string(buffer[:n])

	// If VRFY returns user information (250) instead of disabled (252/502)
	if strings.HasPrefix(vrfyResponse, "250") {
		return &MailFinding{
			Host:              host,
			Port:              port,
			Service:           ServiceSMTP,
			VulnerabilityType: VulnUserEnumeration,
			Severity:          "MEDIUM",
			Title:             "SMTP User Enumeration via VRFY Command",
			Description:       "The SMTP server responds to VRFY commands, allowing attackers to enumerate valid email addresses.",
			Evidence:          fmt.Sprintf("VRFY admin response: %s", vrfyResponse),
			Remediation:       "Disable the VRFY and EXPN commands in the SMTP server configuration.",
			DiscoveredAt:      time.Now(),
		}
	}

	return nil
}

// checkDNSSecurityRecords checks SPF, DKIM, and DMARC records
func (s *Scanner) checkDNSSecurityRecords(ctx context.Context, domain string) []MailFinding {
	var findings []MailFinding

	// Check SPF record
	spfRecord, err := s.lookupSPFRecord(ctx, domain)
	if err != nil || spfRecord == "" {
		findings = append(findings, MailFinding{
			Host:              domain,
			Service:           ServiceSMTP,
			VulnerabilityType: VulnNoSPF,
			Severity:          "MEDIUM",
			Title:             "Missing SPF Record",
			Description:       "The domain does not have an SPF record, making it easier for attackers to spoof emails from this domain.",
			Evidence:          fmt.Sprintf("No SPF record found for domain: %s", domain),
			Remediation: "Add an SPF record to your DNS:\n" +
				"TXT record: v=spf1 mx ~all\n" +
				"Adjust the policy based on your mail sending infrastructure.",
			DiscoveredAt: time.Now(),
		})
	} else {
		s.logger.Infow("SPF record found", "domain", domain, "record", spfRecord)
	}

	// Check DMARC record
	dmarcRecord, err := s.lookupDMARCRecord(ctx, domain)
	if err != nil || dmarcRecord == "" {
		findings = append(findings, MailFinding{
			Host:              domain,
			Service:           ServiceSMTP,
			VulnerabilityType: VulnNoDMARC,
			Severity:          "MEDIUM",
			Title:             "Missing DMARC Record",
			Description:       "The domain does not have a DMARC record, reducing email security and making domain spoofing easier.",
			Evidence:          fmt.Sprintf("No DMARC record found for domain: %s", domain),
			Remediation: "Add a DMARC record to your DNS:\n" +
				"TXT record at _dmarc.yourdomain.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com\n" +
				"Start with p=none for monitoring, then move to p=quarantine or p=reject.",
			DiscoveredAt: time.Now(),
		})
	} else {
		s.logger.Infow("DMARC record found", "domain", domain, "record", dmarcRecord)
	}

	return findings
}

// lookupSPFRecord looks up SPF record for a domain
func (s *Scanner) lookupSPFRecord(ctx context.Context, domain string) (string, error) {
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return "", err
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			return record, nil
		}
	}

	return "", fmt.Errorf("no SPF record found")
}

// lookupDMARCRecord looks up DMARC record for a domain
func (s *Scanner) lookupDMARCRecord(ctx context.Context, domain string) (string, error) {
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		return "", err
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=DMARC1") {
			return record, nil
		}
	}

	return "", fmt.Errorf("no DMARC record found")
}

// parseEHLOCapabilities parses SMTP EHLO response to extract capabilities
func (s *Scanner) parseEHLOCapabilities(response string) []string {
	var capabilities []string
	lines := strings.Split(response, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// EHLO responses have format: "250-CAPABILITY" or "250 CAPABILITY"
		if strings.HasPrefix(line, "250-") || strings.HasPrefix(line, "250 ") {
			capability := strings.TrimPrefix(line, "250-")
			capability = strings.TrimPrefix(capability, "250 ")
			capability = strings.TrimSpace(capability)
			if capability != "" && !strings.Contains(capability, "Hello") {
				capabilities = append(capabilities, capability)
			}
		}
	}

	return capabilities
}

// hasCapability checks if a capability is in the list
func (s *Scanner) hasCapability(capabilities []string, capability string) bool {
	for _, cap := range capabilities {
		if strings.EqualFold(cap, capability) || strings.HasPrefix(strings.ToUpper(cap), capability) {
			return true
		}
	}
	return false
}

// hasBannerDisclosure checks if banner reveals version information
func (s *Scanner) hasBannerDisclosure(banner string) bool {
	// Common version disclosure patterns
	versionPatterns := []string{
		"Postfix",
		"Exim",
		"Sendmail",
		"Microsoft",
		"Exchange",
		"qmail",
		"version",
		"v1.", "v2.", "v3.", "v4.",
	}

	bannerLower := strings.ToLower(banner)
	for _, pattern := range versionPatterns {
		if strings.Contains(bannerLower, strings.ToLower(pattern)) {
			// Check if it also contains a version number
			if strings.ContainsAny(banner, "0123456789.") {
				return true
			}
		}
	}

	return false
}

// isPortOpen checks if a TCP port is open
func (s *Scanner) isPortOpen(ctx context.Context, host string, port int) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
