// pkg/discovery/mail_analyzer.go
package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// MailServerAnalyzer performs comprehensive mail server analysis
type MailServerAnalyzer struct {
	logger            *logger.Logger
	serviceClassifier *ServiceClassifier
	timeout           time.Duration
}

// MailServerInfo contains comprehensive mail server information
type MailServerInfo struct {
	Domain          string
	Organization    string
	MailServers     []MailServer
	WebmailURLs     []string
	AdminPanelURLs  []string
	RelatedDomains  []string
	SPFRecord       string
	DMARCRecord     string
	DKIMSelectors   []string
	AuthMethods     []MailAuthMethod
	Technologies    []string
	Vulnerabilities []string
	Metadata        map[string]interface{}
}

// MailServer represents a mail server with its services
type MailServer struct {
	Hostname string
	IP       string
	Services []MailService
	Priority int // MX priority
}

// MailService represents a mail service (SMTP, IMAP, etc.)
type MailService struct {
	Type        string // smtp, imap, pop3
	Port        int
	TLS         bool
	AuthMethods []string
	Banner      string
	Version     string
}

// MailAuthMethod represents an authentication method
type MailAuthMethod struct {
	Service     string   // smtp, imap, pop3, webmail
	Methods     []string // PLAIN, LOGIN, CRAM-MD5, etc.
	Endpoint    string
	RequiresTLS bool
}

// NewMailServerAnalyzer creates a new mail server analyzer
func NewMailServerAnalyzer(log *logger.Logger) *MailServerAnalyzer {
	if log == nil {
		cfg := config.LoggerConfig{Level: "error", Format: "json"}
		log, _ = logger.New(cfg)
	}

	return &MailServerAnalyzer{
		logger:            log.WithComponent("mail-analyzer"),
		serviceClassifier: NewServiceClassifier(log),
		timeout:           30 * time.Second,
	}
}

// AnalyzeMailServer performs comprehensive mail server analysis
func (ma *MailServerAnalyzer) AnalyzeMailServer(ctx context.Context, target string) (*MailServerInfo, error) {
	info := &MailServerInfo{
		Domain:         target,
		MailServers:    []MailServer{},
		WebmailURLs:    []string{},
		AdminPanelURLs: []string{},
		RelatedDomains: []string{},
		DKIMSelectors:  []string{},
		AuthMethods:    []MailAuthMethod{},
		Technologies:   []string{},
		Metadata:       make(map[string]interface{}),
	}

	// First, classify the target to get context
	targetContext, err := ma.serviceClassifier.ClassifyTarget(ctx, target)
	if err != nil {
		ma.logger.Errorw("Failed to classify target", "error", err)
	} else {
		// Use classification data
		info.Organization = targetContext.Organization
		info.RelatedDomains = targetContext.RelatedDomains
		info.Technologies = targetContext.Technologies
	}

	// Extract hostname
	hostname := ma.extractHostname(target)

	// Discover mail servers
	ma.discoverMailServers(ctx, hostname, info)

	// Analyze mail services
	ma.analyzeMailServices(ctx, info)

	// Discover webmail interfaces
	ma.discoverWebmail(ctx, hostname, info)

	// Discover admin panels
	ma.discoverAdminPanels(ctx, hostname, info)

	// Extract organization from certificates
	ma.extractOrgFromCerts(ctx, hostname, info)

	// Analyze DNS records
	ma.analyzeDNSRecords(ctx, hostname, info)

	// Test authentication methods
	ma.testAuthMethods(ctx, info)

	return info, nil
}

// discoverMailServers discovers all mail servers for the domain
func (ma *MailServerAnalyzer) discoverMailServers(ctx context.Context, domain string, info *MailServerInfo) {
	// Get MX records
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		// If no MX records, the domain itself might be the mail server
		ma.logger.Debugw("No MX records found, checking domain itself", "domain", domain)

		// Check if the domain has mail services
		if ips, err := net.LookupIP(domain); err == nil && len(ips) > 0 {
			mailServer := MailServer{
				Hostname: domain,
				IP:       ips[0].String(),
				Priority: 0,
				Services: []MailService{},
			}
			info.MailServers = append(info.MailServers, mailServer)
		}
		return
	}

	// Process MX records
	for _, mx := range mxRecords {
		hostname := strings.TrimSuffix(mx.Host, ".")

		// Resolve IP
		ips, err := net.LookupIP(hostname)
		if err != nil || len(ips) == 0 {
			continue
		}

		mailServer := MailServer{
			Hostname: hostname,
			IP:       ips[0].String(),
			Priority: int(mx.Pref),
			Services: []MailService{},
		}

		info.MailServers = append(info.MailServers, mailServer)

		// Add to related domains if different
		if !strings.HasSuffix(hostname, domain) {
			info.RelatedDomains = appendUnique(info.RelatedDomains, extractBaseDomain(hostname))
		}
	}

	ma.logger.Infow("Discovered mail servers",
		"domain", domain,
		"count", len(info.MailServers),
	)
}

// analyzeMailServices analyzes services on each mail server
func (ma *MailServerAnalyzer) analyzeMailServices(ctx context.Context, info *MailServerInfo) {
	for i := range info.MailServers {
		server := &info.MailServers[i]

		// Check SMTP services
		if authMethod := ma.checkSMTPService(server, 25, false); len(authMethod.Methods) > 0 {
			info.AuthMethods = append(info.AuthMethods, authMethod)
		}
		if authMethod := ma.checkSMTPService(server, 465, true); len(authMethod.Methods) > 0 {
			info.AuthMethods = append(info.AuthMethods, authMethod)
		}
		if authMethod := ma.checkSMTPService(server, 587, false); len(authMethod.Methods) > 0 {
			info.AuthMethods = append(info.AuthMethods, authMethod)
		}

		// Check IMAP services
		if authMethod := ma.checkIMAPService(server, 143, false); len(authMethod.Methods) > 0 {
			info.AuthMethods = append(info.AuthMethods, authMethod)
		}
		if authMethod := ma.checkIMAPService(server, 993, true); len(authMethod.Methods) > 0 {
			info.AuthMethods = append(info.AuthMethods, authMethod)
		}

		// Check POP3 services
		if authMethod := ma.checkPOP3Service(server, 110, false); len(authMethod.Methods) > 0 {
			info.AuthMethods = append(info.AuthMethods, authMethod)
		}
		if authMethod := ma.checkPOP3Service(server, 995, true); len(authMethod.Methods) > 0 {
			info.AuthMethods = append(info.AuthMethods, authMethod)
		}
	}
}

// checkSMTPService checks SMTP service on a specific port
func (ma *MailServerAnalyzer) checkSMTPService(server *MailServer, port int, useTLS bool) MailAuthMethod {
	authMethod := MailAuthMethod{
		Service:     fmt.Sprintf("SMTP:%d", port),
		Methods:     []string{},
		Endpoint:    fmt.Sprintf("%s:%d", server.Hostname, port),
		RequiresTLS: useTLS,
	}

	address := fmt.Sprintf("%s:%d", server.Hostname, port)

	var client *smtp.Client
	var err error

	if useTLS {
		// Direct TLS connection
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         server.Hostname,
		}

		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, tlsConfig)
		if err != nil {
			return authMethod
		}
		defer conn.Close()

		client, err = smtp.NewClient(conn, server.Hostname)
		if err != nil {
			return authMethod
		}
	} else {
		// Plain connection
		client, err = smtp.Dial(address)
		if err != nil {
			return authMethod
		}
	}
	defer client.Close()

	service := MailService{
		Type: "smtp",
		Port: port,
		TLS:  useTLS,
	}

	// Get banner
	if banner, err := client.Text.ReadLine(); err == nil {
		service.Banner = banner

		// Extract version from banner
		if version := extractSMTPVersion(banner); version != "" {
			service.Version = version
		}
	}

	// Send EHLO to get capabilities
	if err := client.Hello(server.Hostname); err == nil {
		// Get auth methods
		if ext, authStr := client.Extension("AUTH"); ext {
			authMethods := strings.Fields(authStr)
			service.AuthMethods = authMethods
			authMethod.Methods = authMethods
		}

		// Check for STARTTLS
		if !useTLS {
			if ok, _ := client.Extension("STARTTLS"); ok {
				service.AuthMethods = append(service.AuthMethods, "STARTTLS")
				authMethod.Methods = append(authMethod.Methods, "STARTTLS")
			}
		}
	}

	server.Services = append(server.Services, service)

	ma.logger.Debugw("SMTP service discovered",
		"server", server.Hostname,
		"port", port,
		"tls", useTLS,
		"auth_methods", service.AuthMethods,
	)

	return authMethod
}

// checkIMAPService checks IMAP service
func (ma *MailServerAnalyzer) checkIMAPService(server *MailServer, port int, useTLS bool) MailAuthMethod {
	authMethod := MailAuthMethod{
		Service:     fmt.Sprintf("IMAP:%d", port),
		Methods:     []string{},
		Endpoint:    fmt.Sprintf("%s:%d", server.Hostname, port),
		RequiresTLS: useTLS,
	}

	// Use net.JoinHostPort for proper IPv6 support
	address := net.JoinHostPort(server.Hostname, strconv.Itoa(port))

	var conn net.Conn
	var err error

	if useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         server.Hostname,
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, tlsConfig)
	} else {
		conn, err = net.DialTimeout("tcp", address, 5*time.Second)
	}

	if err != nil {
		return authMethod
	}
	defer conn.Close()

	service := MailService{
		Type: "imap",
		Port: port,
		TLS:  useTLS,
	}

	// Read banner
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	banner := make([]byte, 1024)
	if n, err := conn.Read(banner); err == nil && n > 0 {
		service.Banner = strings.TrimSpace(string(banner[:n]))

		// Extract version
		if strings.Contains(service.Banner, "IMAP") {
			service.Version = "IMAP4"
		}
	}

	// Send CAPABILITY command
	conn.Write([]byte("A001 CAPABILITY\r\n"))
	response := make([]byte, 4096)
	if n, err := conn.Read(response); err == nil && n > 0 {
		respStr := string(response[:n])

		// Extract auth methods
		if strings.Contains(respStr, "AUTH=") {
			authMethods := extractIMAPAuthMethods(respStr)
			service.AuthMethods = authMethods
			authMethod.Methods = authMethods
		}
	}

	server.Services = append(server.Services, service)

	ma.logger.Debugw("IMAP service discovered",
		"server", server.Hostname,
		"port", port,
		"tls", useTLS,
	)

	return authMethod
}

// checkPOP3Service checks POP3 service
func (ma *MailServerAnalyzer) checkPOP3Service(server *MailServer, port int, useTLS bool) MailAuthMethod {
	authMethod := MailAuthMethod{
		Service:     fmt.Sprintf("POP3:%d", port),
		Methods:     []string{},
		Endpoint:    fmt.Sprintf("%s:%d", server.Hostname, port),
		RequiresTLS: useTLS,
	}

	// Similar to IMAP but simpler
	// Use net.JoinHostPort for proper IPv6 support
	address := net.JoinHostPort(server.Hostname, strconv.Itoa(port))

	var conn net.Conn
	var err error

	if useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         server.Hostname,
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, tlsConfig)
	} else {
		conn, err = net.DialTimeout("tcp", address, 5*time.Second)
	}

	if err != nil {
		return authMethod
	}
	defer conn.Close()

	service := MailService{
		Type: "pop3",
		Port: port,
		TLS:  useTLS,
	}

	// Read banner
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	banner := make([]byte, 1024)
	if n, err := conn.Read(banner); err == nil && n > 0 {
		service.Banner = strings.TrimSpace(string(banner[:n]))
		service.AuthMethods = []string{"USER/PASS"}
		authMethod.Methods = []string{"USER/PASS"}

		if strings.Contains(service.Banner, "POP3") {
			service.Version = "POP3"
		}
	}

	server.Services = append(server.Services, service)

	return authMethod
}

// discoverWebmail discovers webmail interfaces
func (ma *MailServerAnalyzer) discoverWebmail(ctx context.Context, hostname string, info *MailServerInfo) {
	// Common webmail paths
	webmailPaths := []struct {
		path string
		name string
	}{
		{"/webmail", "Generic Webmail"},
		{"/roundcube", "Roundcube"},
		{"/squirrelmail", "SquirrelMail"},
		{"/horde", "Horde"},
		{"/zimbra", "Zimbra"},
		{"/owa", "Outlook Web App"},
		{"/exchange", "Exchange"},
		{"/sogo", "SOGo"},
		{"/rainloop", "RainLoop"},
		{"/afterlogic", "AfterLogic"},
		{"/mail", "Generic Mail"},
		{"/email", "Generic Email"},
	}

	// Check both HTTP and HTTPS
	protocols := []string{"https", "http"}

	for _, proto := range protocols {
		for _, wp := range webmailPaths {
			url := fmt.Sprintf("%s://%s%s", proto, hostname, wp.path)

			client := &http.Client{
				Timeout: 5 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			resp, err := client.Head(url)
			if err != nil {
				continue
			}
			httpclient.CloseBody(resp)

			// Check if accessible
			if resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 401 {
				info.WebmailURLs = append(info.WebmailURLs, url)

				// Add technology
				info.Technologies = appendUnique(info.Technologies, wp.name)

				// Add auth method
				info.AuthMethods = append(info.AuthMethods, MailAuthMethod{
					Service:  "Webmail",
					Methods:  []string{wp.name + " Login"},
					Endpoint: url,
				})

				ma.logger.Infow("Webmail interface found",
					"url", url,
					"type", wp.name,
					"status", resp.StatusCode,
				)
			}
		}
	}
}

// discoverAdminPanels discovers mail admin panels
func (ma *MailServerAnalyzer) discoverAdminPanels(ctx context.Context, hostname string, info *MailServerInfo) {
	// Common admin panel paths
	adminPaths := []struct {
		path string
		name string
	}{
		{"/admin", "Generic Admin"},
		{"/administrator", "Administrator"},
		{"/mailman", "Mailman"},
		{"/postfixadmin", "PostfixAdmin"},
		{"/mailcow", "Mailcow"},
		{"/vimbadmin", "ViMbAdmin"},
		{"/poweradmin", "PowerAdmin"},
		{"/ispconfig", "ISPConfig"},
		{"/cpanel", "cPanel"},
		{"/plesk", "Plesk"},
		{"/directadmin", "DirectAdmin"},
	}

	// Check both HTTP and HTTPS
	protocols := []string{"https", "http"}

	for _, proto := range protocols {
		for _, ap := range adminPaths {
			url := fmt.Sprintf("%s://%s%s", proto, hostname, ap.path)

			client := &http.Client{
				Timeout: 5 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			resp, err := client.Head(url)
			if err != nil {
				continue
			}
			httpclient.CloseBody(resp)

			// Check if accessible
			if resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 401 {
				info.AdminPanelURLs = append(info.AdminPanelURLs, url)

				// Add technology
				info.Technologies = appendUnique(info.Technologies, ap.name)

				// Add auth method
				info.AuthMethods = append(info.AuthMethods, MailAuthMethod{
					Service:  "Admin Panel",
					Methods:  []string{ap.name + " Login"},
					Endpoint: url,
				})

				ma.logger.Infow("Admin panel found",
					"url", url,
					"type", ap.name,
					"status", resp.StatusCode,
				)
			}
		}
	}
}

// extractOrgFromCerts extracts organization from SSL certificates
func (ma *MailServerAnalyzer) extractOrgFromCerts(ctx context.Context, hostname string, info *MailServerInfo) {
	// Check HTTPS certificate
	conn, err := tls.Dial("tcp", hostname+":443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err == nil {
		defer conn.Close()

		certs := conn.ConnectionState().PeerCertificates
		for _, cert := range certs {
			// Extract organization
			if cert.Subject.Organization != nil && len(cert.Subject.Organization) > 0 {
				info.Organization = cert.Subject.Organization[0]
			}

			// Extract domains from SANs
			for _, san := range cert.DNSNames {
				if !strings.HasPrefix(san, "*.") {
					baseDomain := extractBaseDomain(san)
					if baseDomain != "" && baseDomain != hostname {
						info.RelatedDomains = appendUnique(info.RelatedDomains, baseDomain)
					}
				}
			}
		}
	}
}

// analyzeDNSRecords analyzes DNS records for mail configuration
func (ma *MailServerAnalyzer) analyzeDNSRecords(ctx context.Context, domain string, info *MailServerInfo) {
	// SPF record
	txtRecords, err := net.LookupTXT(domain)
	if err == nil {
		for _, txt := range txtRecords {
			if strings.HasPrefix(txt, "v=spf1") {
				info.SPFRecord = txt

				// Extract domains from SPF
				ma.extractDomainsFromSPF(txt, info)
			}
		}
	}

	// DMARC record
	dmarcDomain := "_dmarc." + domain
	dmarcRecords, err := net.LookupTXT(dmarcDomain)
	if err == nil && len(dmarcRecords) > 0 {
		info.DMARCRecord = dmarcRecords[0]
	}

	// Common DKIM selectors
	dkimSelectors := []string{
		"default", "selector1", "selector2", "google", "k1", "k2",
		"mail", "email", "dkim", "s1", "s2", "key1", "key2",
	}

	for _, selector := range dkimSelectors {
		dkimDomain := selector + "._domainkey." + domain
		if records, err := net.LookupTXT(dkimDomain); err == nil && len(records) > 0 {
			info.DKIMSelectors = append(info.DKIMSelectors, selector)
		}
	}
}

// testAuthMethods tests discovered authentication methods
func (ma *MailServerAnalyzer) testAuthMethods(ctx context.Context, info *MailServerInfo) {
	// This would test each auth method to verify it works
	// For now, we just log what we found
	ma.logger.Infow("Authentication methods discovered",
		"domain", info.Domain,
		"total_methods", len(info.AuthMethods),
		"webmail_interfaces", len(info.WebmailURLs),
		"admin_panels", len(info.AdminPanelURLs),
	)
}

// Helper functions

func (ma *MailServerAnalyzer) extractHostname(target string) string {
	// Remove protocol
	host := strings.TrimPrefix(target, "https://")
	host = strings.TrimPrefix(host, "http://")

	// Remove path
	if idx := strings.Index(host, "/"); idx > 0 {
		host = host[:idx]
	}

	// Remove port
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}

	return host
}

func (ma *MailServerAnalyzer) extractDomainsFromSPF(spf string, info *MailServerInfo) {
	parts := strings.Fields(spf)
	for _, part := range parts {
		if strings.HasPrefix(part, "include:") {
			domain := strings.TrimPrefix(part, "include:")
			info.RelatedDomains = appendUnique(info.RelatedDomains, domain)
		}
		if strings.HasPrefix(part, "mx:") {
			domain := strings.TrimPrefix(part, "mx:")
			if domain != "" && domain != info.Domain {
				info.RelatedDomains = appendUnique(info.RelatedDomains, domain)
			}
		}
		if strings.HasPrefix(part, "a:") {
			domain := strings.TrimPrefix(part, "a:")
			if domain != "" && domain != info.Domain {
				info.RelatedDomains = appendUnique(info.RelatedDomains, domain)
			}
		}
	}
}

func extractBaseDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return hostname
}

func extractSMTPVersion(banner string) string {
	// Extract version from SMTP banner
	// Examples: "220 mail.example.com ESMTP Postfix", "220 Microsoft ESMTP MAIL Service"
	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "postfix") {
		return "Postfix"
	} else if strings.Contains(bannerLower, "exim") {
		return "Exim"
	} else if strings.Contains(bannerLower, "sendmail") {
		return "Sendmail"
	} else if strings.Contains(bannerLower, "microsoft") {
		return "Microsoft Exchange"
	} else if strings.Contains(bannerLower, "zimbra") {
		return "Zimbra"
	}

	return ""
}

func extractIMAPAuthMethods(capability string) []string {
	methods := []string{}

	// Common IMAP auth methods
	authTypes := []string{"PLAIN", "LOGIN", "CRAM-MD5", "DIGEST-MD5", "NTLM", "GSSAPI", "XOAUTH2"}

	for _, auth := range authTypes {
		if strings.Contains(capability, "AUTH="+auth) {
			methods = append(methods, auth)
		}
	}

	return methods
}
