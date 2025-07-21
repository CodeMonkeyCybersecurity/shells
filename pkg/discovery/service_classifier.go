// pkg/discovery/service_classifier.go
package discovery

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// ServiceType represents the type of service
type ServiceType string

const (
	ServiceTypeMailServer     ServiceType = "mail_server"
	ServiceTypeWebApplication ServiceType = "web_application"
	ServiceTypeAPI            ServiceType = "api"
	ServiceTypeDatabase       ServiceType = "database"
	ServiceTypeFileServer     ServiceType = "file_server"
	ServiceTypeVPN            ServiceType = "vpn"
	ServiceTypeLoadBalancer   ServiceType = "load_balancer"
	ServiceTypeCDN            ServiceType = "cdn"
	ServiceTypeGitRepository  ServiceType = "git_repository"
	ServiceTypeContainer      ServiceType = "container"
	ServiceTypeUnknown        ServiceType = "unknown"
)

// TargetContext contains detailed information about the target
type TargetContext struct {
	Target            string
	PrimaryService    ServiceType
	Services          []ServiceInfo
	Ports             []PortInfo
	Technologies      []string
	Subdomains        []string
	RelatedDomains    []string
	Organization      string
	IsMailServer      bool
	IsWebApp          bool
	IsAPI             bool
	HasAuthentication bool
	AuthMethods       []string
	Metadata          map[string]interface{}
}

// ServiceInfo contains information about a discovered service
type ServiceInfo struct {
	Type       ServiceType
	Port       int
	Protocol   string
	Version    string
	Banner     string
	Confidence float64
}

// PortInfo contains information about an open port
type PortInfo struct {
	Port     int
	Protocol string
	Service  string
	State    string
	Banner   string
}

// ServiceClassifier classifies targets based on their services
type ServiceClassifier struct {
	logger      *logger.Logger
	portScanner *PortScanner
	httpClient  *http.Client
	dnsResolver *net.Resolver
	timeout     time.Duration
}

// NewServiceClassifier creates a new service classifier
func NewServiceClassifier(log *logger.Logger) *ServiceClassifier {
	if log == nil {
		cfg := config.LoggerConfig{Level: "error", Format: "json"}
		log, _ = logger.New(cfg)
	}

	return &ServiceClassifier{
		logger:      log.WithComponent("service-classifier"),
		portScanner: NewPortScanner(log),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		dnsResolver: &net.Resolver{},
		timeout:     30 * time.Second,
	}
}

// ClassifyTarget performs comprehensive target classification
func (sc *ServiceClassifier) ClassifyTarget(ctx context.Context, target string) (*TargetContext, error) {
	tc := &TargetContext{
		Target:         target,
		Services:       []ServiceInfo{},
		Ports:          []PortInfo{},
		Technologies:   []string{},
		Subdomains:     []string{},
		RelatedDomains: []string{},
		AuthMethods:    []string{},
		Metadata:       make(map[string]interface{}),
	}

	// Extract hostname
	hostname := sc.extractHostname(target)

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Port scanning
	wg.Add(1)
	go func() {
		defer wg.Done()
		sc.scanPorts(ctx, hostname, tc, &mu)
	}()

	// DNS analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		sc.analyzeDNS(ctx, hostname, tc, &mu)
	}()

	// HTTP analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		sc.analyzeHTTP(ctx, target, tc, &mu)
	}()

	wg.Wait()

	// Analyze collected data to determine service types
	sc.analyzeServices(tc)
	sc.detectAuthMethods(tc)
	sc.extractOrganization(tc)

	return tc, nil
}

// scanPorts performs port scanning to identify services
func (sc *ServiceClassifier) scanPorts(ctx context.Context, host string, tc *TargetContext, mu *sync.Mutex) {
	// Common service ports to check
	servicePorts := map[int]string{
		// Mail services
		25:  "smtp",
		465: "smtps",
		587: "submission",
		143: "imap",
		993: "imaps",
		110: "pop3",
		995: "pop3s",

		// Web services
		80:   "http",
		443:  "https",
		8080: "http-alt",
		8443: "https-alt",

		// Database services
		3306:  "mysql",
		5432:  "postgresql",
		27017: "mongodb",
		6379:  "redis",

		// Other services
		22:   "ssh",
		21:   "ftp",
		445:  "smb",
		3389: "rdp",
		5900: "vnc",

		// Admin/API ports
		8000: "admin",
		9000: "api",
		3000: "webapp",
		4000: "webapp",
		5000: "webapp",
	}

	var openPorts []PortInfo
	var wg sync.WaitGroup
	portChan := make(chan PortInfo, len(servicePorts))

	// Scan ports in parallel
	for port, service := range servicePorts {
		wg.Add(1)
		go func(p int, s string) {
			defer wg.Done()

			if sc.isPortOpen(host, p) {
				info := PortInfo{
					Port:     p,
					Protocol: "tcp",
					Service:  s,
					State:    "open",
				}

				// Try to grab banner
				if banner := sc.grabBanner(host, p); banner != "" {
					info.Banner = banner
				}

				portChan <- info
			}
		}(port, service)
	}

	wg.Wait()
	close(portChan)

	// Collect results
	for port := range portChan {
		openPorts = append(openPorts, port)
	}

	mu.Lock()
	tc.Ports = openPorts
	mu.Unlock()

	sc.logger.Infow("Port scan completed",
		"host", host,
		"open_ports", len(openPorts),
	)
}

// analyzeDNS performs DNS analysis
func (sc *ServiceClassifier) analyzeDNS(ctx context.Context, domain string, tc *TargetContext, mu *sync.Mutex) {
	// MX records (mail servers)
	mxRecords, err := net.LookupMX(domain)
	if err == nil && len(mxRecords) > 0 {
		mu.Lock()
		tc.IsMailServer = true
		for _, mx := range mxRecords {
			tc.RelatedDomains = appendUnique(tc.RelatedDomains, strings.TrimSuffix(mx.Host, "."))
		}
		mu.Unlock()
	}

	// TXT records (SPF, DKIM, etc.)
	txtRecords, err := net.LookupTXT(domain)
	if err == nil {
		for _, txt := range txtRecords {
			// SPF records
			if strings.HasPrefix(txt, "v=spf1") {
				mu.Lock()
				tc.Metadata["spf"] = txt
				// Extract domains from SPF
				sc.extractSPFDomains(txt, tc)
				mu.Unlock()
			}

			// DMARC records
			if strings.Contains(txt, "v=DMARC1") {
				mu.Lock()
				tc.Metadata["dmarc"] = txt
				mu.Unlock()
			}
		}
	}

	// Check common subdomains
	subdomains := []string{
		"www", "mail", "smtp", "imap", "pop", "pop3", "webmail",
		"admin", "api", "app", "portal", "secure", "vpn",
		"dev", "test", "staging", "uat", "demo",
		"ftp", "sftp", "ssh", "remote", "vpn",
		"ns1", "ns2", "mx", "mx1", "mx2",
	}

	for _, sub := range subdomains {
		fqdn := sub + "." + domain
		if _, err := net.LookupHost(fqdn); err == nil {
			mu.Lock()
			tc.Subdomains = appendUnique(tc.Subdomains, fqdn)
			mu.Unlock()
		}
	}
}

// analyzeHTTP performs HTTP analysis
func (sc *ServiceClassifier) analyzeHTTP(ctx context.Context, target string, tc *TargetContext, mu *sync.Mutex) {
	// Ensure target has protocol
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	resp, err := sc.httpClient.Get(target)
	if err != nil {
		// Try HTTP if HTTPS failed
		if strings.HasPrefix(target, "https://") {
			target = strings.Replace(target, "https://", "http://", 1)
			resp, err = sc.httpClient.Get(target)
		}
		if err != nil {
			return
		}
	}
	defer resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	// Analyze headers
	if server := resp.Header.Get("Server"); server != "" {
		tc.Technologies = appendUnique(tc.Technologies, server)
	}

	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		tc.Technologies = appendUnique(tc.Technologies, powered)
	}

	// Check for API indicators
	if resp.Header.Get("Content-Type") == "application/json" ||
		resp.Header.Get("X-API-Version") != "" ||
		strings.Contains(target, "/api") {
		tc.IsAPI = true
	}

	// Check for authentication headers
	if auth := resp.Header.Get("WWW-Authenticate"); auth != "" {
		tc.HasAuthentication = true
		tc.AuthMethods = appendUnique(tc.AuthMethods, parseAuthMethod(auth))
	}

	// Check common webmail/admin paths
	webmailPaths := []string{
		"/webmail", "/roundcube", "/squirrelmail", "/horde",
		"/zimbra", "/owa", "/exchange", "/sogo",
		"/admin", "/administrator", "/mailman", "/postfixadmin",
		"/mailcow", "/mail", "/email",
	}

	for _, path := range webmailPaths {
		checkURL := strings.TrimSuffix(target, "/") + path
		if resp, err := sc.httpClient.Head(checkURL); err == nil {
			if resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 401 {
				tc.Metadata[path] = fmt.Sprintf("Found (status: %d)", resp.StatusCode)
				if strings.Contains(path, "mail") || strings.Contains(path, "owa") {
					tc.IsMailServer = true
				}
			}
			resp.Body.Close()
		}
	}
}

// analyzeServices determines service types based on collected data
func (sc *ServiceClassifier) analyzeServices(tc *TargetContext) {
	// Check for mail server indicators
	mailPorts := map[int]bool{25: true, 465: true, 587: true, 143: true, 993: true, 110: true, 995: true}
	mailPortCount := 0

	for _, port := range tc.Ports {
		if mailPorts[port.Port] {
			mailPortCount++
			tc.Services = append(tc.Services, ServiceInfo{
				Type:       ServiceTypeMailServer,
				Port:       port.Port,
				Protocol:   port.Protocol,
				Confidence: 0.9,
			})
		}

		// Web services
		if port.Port == 80 || port.Port == 443 || port.Port == 8080 || port.Port == 8443 {
			tc.IsWebApp = true
			tc.Services = append(tc.Services, ServiceInfo{
				Type:       ServiceTypeWebApplication,
				Port:       port.Port,
				Protocol:   port.Protocol,
				Confidence: 0.9,
			})
		}

		// Database services
		if port.Service == "mysql" || port.Service == "postgresql" || port.Service == "mongodb" {
			tc.Services = append(tc.Services, ServiceInfo{
				Type:       ServiceTypeDatabase,
				Port:       port.Port,
				Protocol:   port.Protocol,
				Confidence: 0.8,
			})
		}
	}

	// Strong mail server indicator
	if mailPortCount >= 2 || tc.IsMailServer {
		tc.IsMailServer = true
		tc.PrimaryService = ServiceTypeMailServer
	} else if tc.IsAPI {
		tc.PrimaryService = ServiceTypeAPI
	} else if tc.IsWebApp {
		tc.PrimaryService = ServiceTypeWebApplication
	} else {
		tc.PrimaryService = ServiceTypeUnknown
	}
}

// detectAuthMethods detects authentication methods
func (sc *ServiceClassifier) detectAuthMethods(tc *TargetContext) {
	// Mail authentication
	if tc.IsMailServer {
		// SMTP AUTH methods
		if sc.hasPort(tc, 25) || sc.hasPort(tc, 465) || sc.hasPort(tc, 587) {
			tc.AuthMethods = append(tc.AuthMethods, "SMTP-AUTH", "SMTP-PLAIN", "SMTP-LOGIN")
		}

		// IMAP/POP3 auth
		if sc.hasPort(tc, 143) || sc.hasPort(tc, 993) {
			tc.AuthMethods = append(tc.AuthMethods, "IMAP-LOGIN", "IMAP-PLAIN")
		}

		if sc.hasPort(tc, 110) || sc.hasPort(tc, 995) {
			tc.AuthMethods = append(tc.AuthMethods, "POP3-USER")
		}

		// Webmail auth
		if _, ok := tc.Metadata["/webmail"]; ok {
			tc.AuthMethods = append(tc.AuthMethods, "Webmail-Login")
		}

		// Admin panel auth
		if _, ok := tc.Metadata["/admin"]; ok {
			tc.AuthMethods = append(tc.AuthMethods, "Admin-Panel")
		}
	}
}

// extractOrganization attempts to extract organization information
func (sc *ServiceClassifier) extractOrganization(tc *TargetContext) {
	// Extract from domain
	parts := strings.Split(tc.Target, ".")
	if len(parts) >= 2 {
		// Get the main domain (e.g., "cybermonkey" from "mail.cybermonkey.sh")
		tc.Organization = parts[len(parts)-2]

		// Add parent domain to related domains
		parentDomain := strings.Join(parts[len(parts)-2:], ".")
		tc.RelatedDomains = appendUnique(tc.RelatedDomains, parentDomain)
	}
}

// extractSPFDomains extracts domains from SPF record
func (sc *ServiceClassifier) extractSPFDomains(spf string, tc *TargetContext) {
	// Look for include: directives
	parts := strings.Fields(spf)
	for _, part := range parts {
		if strings.HasPrefix(part, "include:") {
			domain := strings.TrimPrefix(part, "include:")
			tc.RelatedDomains = appendUnique(tc.RelatedDomains, domain)
		}
		if strings.HasPrefix(part, "mx:") {
			domain := strings.TrimPrefix(part, "mx:")
			tc.RelatedDomains = appendUnique(tc.RelatedDomains, domain)
		}
		if strings.HasPrefix(part, "a:") {
			domain := strings.TrimPrefix(part, "a:")
			tc.RelatedDomains = appendUnique(tc.RelatedDomains, domain)
		}
	}
}

// Helper methods

func (sc *ServiceClassifier) extractHostname(target string) string {
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

func (sc *ServiceClassifier) isPortOpen(host string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (sc *ServiceClassifier) grabBanner(host string, port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Read banner
	banner := make([]byte, 1024)
	n, err := conn.Read(banner)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(banner[:n]))
}

func (sc *ServiceClassifier) hasPort(tc *TargetContext, port int) bool {
	for _, p := range tc.Ports {
		if p.Port == port {
			return true
		}
	}
	return false
}

func parseAuthMethod(authHeader string) string {
	authLower := strings.ToLower(authHeader)
	if strings.Contains(authLower, "basic") {
		return "Basic"
	} else if strings.Contains(authLower, "digest") {
		return "Digest"
	} else if strings.Contains(authLower, "bearer") {
		return "Bearer/JWT"
	} else if strings.Contains(authLower, "negotiate") {
		return "Negotiate/Kerberos"
	} else if strings.Contains(authLower, "ntlm") {
		return "NTLM"
	}
	return "Unknown"
}

func appendUnique(slice []string, item string) []string {
	for _, existing := range slice {
		if existing == item {
			return slice
		}
	}
	return append(slice, item)
}

// PortScanner handles port scanning operations
type PortScanner struct {
	logger *logger.Logger
}

func NewPortScanner(logger *logger.Logger) *PortScanner {
	return &PortScanner{logger: logger}
}
