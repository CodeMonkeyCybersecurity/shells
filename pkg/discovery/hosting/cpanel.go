package hosting

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type CPanelDiscovery struct {
	ports    []int
	patterns []Pattern
	client   *http.Client
	timeout  time.Duration
	workers  int
}

type CPanelInstance struct {
	URL             string          `json:"url"`
	Type            string          `json:"type"`
	Version         string          `json:"version"`
	Features        []string        `json:"features"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Accessible      bool            `json:"accessible"`
	LastChecked     time.Time       `json:"last_checked"`
	Response        ResponseInfo    `json:"response"`
	SSL             SSLInfo         `json:"ssl"`
}

type CPanelCheck struct {
	Port int    `json:"port"`
	Path string `json:"path"`
	Type string `json:"type"`
}

type Pattern struct {
	Name        string `json:"name"`
	Regex       string `json:"regex"`
	Description string `json:"description"`
	Type        string `json:"type"`
}

type Vulnerability struct {
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	Details     string   `json:"details"`
	CVEs        []string `json:"cves"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references"`
}

type ResponseInfo struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Title      string            `json:"title"`
	Server     string            `json:"server"`
	Size       int64             `json:"size"`
}

type SSLInfo struct {
	Enabled     bool      `json:"enabled"`
	Certificate string    `json:"certificate"`
	Issuer      string    `json:"issuer"`
	ValidFrom   time.Time `json:"valid_from"`
	ValidTo     time.Time `json:"valid_to"`
	SelfSigned  bool      `json:"self_signed"`
}

type MisconfigCheck struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type CPanelReport struct {
	Domain      string           `json:"domain"`
	Instances   []CPanelInstance `json:"instances"`
	Summary     Summary          `json:"summary"`
	Findings    []Finding        `json:"findings"`
	Subdomains  []string         `json:"subdomains_checked"`
	LastUpdated time.Time        `json:"last_updated"`
}

type Summary struct {
	TotalInstances      int `json:"total_instances"`
	AccessibleInstances int `json:"accessible_instances"`
	VulnerableInstances int `json:"vulnerable_instances"`
	HighRiskFindings    int `json:"high_risk_findings"`
	MediumRiskFindings  int `json:"medium_risk_findings"`
	LowRiskFindings     int `json:"low_risk_findings"`
}

type Finding struct {
	Type     string    `json:"type"`
	Severity string    `json:"severity"`
	Title    string    `json:"title"`
	Details  string    `json:"details"`
	URL      string    `json:"url"`
	Evidence string    `json:"evidence"`
	Time     time.Time `json:"time"`
}

func NewCPanelDiscovery() *CPanelDiscovery {
	return &CPanelDiscovery{
		ports:   []int{2082, 2083, 2086, 2087, 2095, 2096, 443, 80, 8080, 8443},
		timeout: 10 * time.Second,
		workers: 20,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
		patterns: getCPanelPatterns(),
	}
}

func (c *CPanelDiscovery) FindCPanelInstances(ctx context.Context, domain string) (*CPanelReport, error) {
	report := &CPanelReport{
		Domain:      domain,
		Instances:   []CPanelInstance{},
		Findings:    []Finding{},
		Subdomains:  []string{},
		LastUpdated: time.Now(),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make(chan CPanelInstance, 100)

	// Common cPanel/WHM ports and paths
	checks := []CPanelCheck{
		{Port: 2082, Path: "/", Type: "cPanel"},
		{Port: 2083, Path: "/", Type: "cPanel SSL"},
		{Port: 2086, Path: "/", Type: "WHM"},
		{Port: 2087, Path: "/", Type: "WHM SSL"},
		{Port: 2095, Path: "/webmail", Type: "Webmail"},
		{Port: 2096, Path: "/", Type: "Webmail SSL"},
		// Non-standard but common
		{Port: 443, Path: "/cpanel", Type: "cPanel Proxy"},
		{Port: 443, Path: "/whm", Type: "WHM Proxy"},
		{Port: 443, Path: ":2083", Type: "cPanel Proxy Alt"},
		{Port: 80, Path: "/cpanel", Type: "cPanel HTTP"},
		{Port: 8080, Path: "/cpanel", Type: "cPanel Alt Port"},
		{Port: 8443, Path: "/cpanel", Type: "cPanel Alt SSL"},
	}

	// Check main domain
	for _, check := range checks {
		wg.Add(1)
		go func(ch CPanelCheck) {
			defer wg.Done()
			if instance := c.checkCPanelInstance(ctx, domain, ch); instance != nil {
				results <- *instance
			}
		}(check)
	}

	// Check subdomains
	cpanelSubdomains := []string{
		"cpanel", "whm", "webmail", "mail", "hosting",
		"server", "host", "secure", "client", "customer",
		"admin", "control", "panel", "management", "manager",
		"support", "help", "service", "portal", "dashboard",
	}

	for _, sub := range cpanelSubdomains {
		subdomain := fmt.Sprintf("%s.%s", sub, domain)
		report.Subdomains = append(report.Subdomains, subdomain)

		for _, check := range checks {
			wg.Add(1)
			go func(sd string, ch CPanelCheck) {
				defer wg.Done()
				if instance := c.checkCPanelInstance(ctx, sd, ch); instance != nil {
					results <- *instance
				}
			}(subdomain, check)
		}
	}

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	for instance := range results {
		mu.Lock()
		report.Instances = append(report.Instances, instance)
		mu.Unlock()
	}

	// Generate findings and summary
	c.generateFindings(report)
	c.generateSummary(report)

	return report, nil
}

func (c *CPanelDiscovery) checkCPanelInstance(ctx context.Context, domain string, check CPanelCheck) *CPanelInstance {
	var url string
	if check.Port == 443 {
		url = fmt.Sprintf("https://%s%s", domain, check.Path)
	} else if check.Port == 80 {
		url = fmt.Sprintf("http://%s%s", domain, check.Path)
	} else {
		url = fmt.Sprintf("https://%s:%d%s", domain, check.Port, check.Path)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	content := string(body)

	// Check if this is actually a cPanel instance
	if !c.isCPanelInstance(content, resp) {
		return nil
	}

	instance := &CPanelInstance{
		URL:         url,
		Type:        check.Type,
		Version:     c.detectVersion(content),
		Features:    c.detectFeatures(content),
		Accessible:  resp.StatusCode == 200,
		LastChecked: time.Now(),
		Response: ResponseInfo{
			StatusCode: resp.StatusCode,
			Headers:    c.extractHeaders(resp.Header),
			Title:      c.extractTitle(content),
			Server:     resp.Header.Get("Server"),
			Size:       int64(len(body)),
		},
		SSL: c.extractSSLInfo(resp),
	}

	// Check for vulnerabilities
	instance.Vulnerabilities = c.checkVulnerabilities(*instance, content)

	return instance
}

func (c *CPanelDiscovery) isCPanelInstance(content string, resp *http.Response) bool {
	// Check for cPanel-specific indicators
	indicators := []string{
		"cpanel",
		"whm",
		"webmail",
		"cpsess",
		"cpanellogd",
		"paper_lantern",
		"jupiter",
		"x3",
		"retro",
		"monster",
		"crimson",
		"cPanel, Inc.",
		"cPanel, L.L.C.",
		"WHM",
		"WebHost Manager",
		"horde",
		"squirrelmail",
		"roundcube",
	}

	contentLower := strings.ToLower(content)

	for _, indicator := range indicators {
		if strings.Contains(contentLower, strings.ToLower(indicator)) {
			return true
		}
	}

	// Check headers
	server := resp.Header.Get("Server")
	if strings.Contains(strings.ToLower(server), "cpanel") {
		return true
	}

	// Check for specific cPanel patterns
	patterns := []string{
		`(?i)cPanel`,
		`(?i)webmail`,
		`(?i)whm`,
		`(?i)cpanellogd`,
		`(?i)paper_lantern`,
		`(?i)cpsess`,
		`(?i)frontend.*paper_lantern`,
		`(?i)cpanel.*login`,
		`(?i)webhost.*manager`,
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, content); matched {
			return true
		}
	}

	return false
}

func (c *CPanelDiscovery) detectVersion(content string) string {
	// Version detection patterns
	patterns := []string{
		`(?i)cPanel\s+Version\s+([0-9.]+)`,
		`(?i)WHM\s+([0-9.]+)`,
		`(?i)version\s*:\s*([0-9.]+)`,
		`(?i)cpanel\s+([0-9.]+)`,
		`(?i)build\s+([0-9.]+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(content); len(matches) > 1 {
			return matches[1]
		}
	}

	return "unknown"
}

func (c *CPanelDiscovery) detectFeatures(content string) []string {
	features := []string{}

	featurePatterns := map[string][]string{
		"File Manager":  {"filemanager", "file_manager", "fileman"},
		"Email":         {"webmail", "email", "horde", "squirrelmail", "roundcube"},
		"Database":      {"phpmyadmin", "mysql", "database", "phpMyAdmin"},
		"FTP":           {"ftp", "file_transfer", "net2ftp"},
		"DNS":           {"dns", "zone", "subdomain"},
		"SSL":           {"ssl", "certificate", "https"},
		"Backup":        {"backup", "restore", "backups"},
		"Cron Jobs":     {"cron", "scheduled", "tasks"},
		"Logs":          {"logs", "error_log", "access_log"},
		"Security":      {"security", "ip_blocker", "hotlink", "leech"},
		"Redirects":     {"redirect", "301", "302"},
		"Subdomains":    {"subdomain", "parked", "addon"},
		"Statistics":    {"awstats", "webalizer", "statistics", "stats"},
		"Autoinstaller": {"softaculous", "fantastico", "installer"},
	}

	contentLower := strings.ToLower(content)

	for feature, patterns := range featurePatterns {
		for _, pattern := range patterns {
			if strings.Contains(contentLower, pattern) {
				features = append(features, feature)
				break
			}
		}
	}

	return features
}

func (c *CPanelDiscovery) checkVulnerabilities(instance CPanelInstance, content string) []Vulnerability {
	vulnerabilities := []Vulnerability{}

	// Version-based vulnerabilities
	if instance.Version != "unknown" && instance.Version != "" {
		if vulns := c.checkVersionVulnerabilities(instance.Version); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}

	// Configuration vulnerabilities
	configVulns := c.checkConfigurationVulnerabilities(instance, content)
	vulnerabilities = append(vulnerabilities, configVulns...)

	// Feature-specific vulnerabilities
	featureVulns := c.checkFeatureVulnerabilities(instance.Features, content)
	vulnerabilities = append(vulnerabilities, featureVulns...)

	// Common misconfigurations
	misconfigs := c.checkMisconfigurations(instance)
	vulnerabilities = append(vulnerabilities, misconfigs...)

	return vulnerabilities
}

func (c *CPanelDiscovery) checkVersionVulnerabilities(version string) []Vulnerability {
	vulnerabilities := []Vulnerability{}

	// Known vulnerable versions (simplified)
	knownVulns := map[string][]Vulnerability{
		"11.70": {
			{
				Type:        "OUTDATED_CPANEL",
				Severity:    "HIGH",
				Details:     "cPanel version 11.70 has known security vulnerabilities",
				CVEs:        []string{"CVE-2019-6505", "CVE-2019-6507"},
				Remediation: "Update to latest stable version",
				References:  []string{"https://documentation.cpanel.net/display/CKB/Security+Advisories"},
			},
		},
		"11.80": {
			{
				Type:        "OUTDATED_CPANEL",
				Severity:    "MEDIUM",
				Details:     "cPanel version 11.80 has known security issues",
				CVEs:        []string{"CVE-2020-8587"},
				Remediation: "Update to latest stable version",
				References:  []string{"https://documentation.cpanel.net/display/CKB/Security+Advisories"},
			},
		},
	}

	if vulns, exists := knownVulns[version]; exists {
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	// Check if version is very old (approximate)
	if c.isOldVersion(version) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "OUTDATED_CPANEL",
			Severity:    "HIGH",
			Details:     fmt.Sprintf("cPanel version %s is outdated and likely vulnerable", version),
			Remediation: "Update to latest stable version immediately",
		})
	}

	return vulnerabilities
}

func (c *CPanelDiscovery) isOldVersion(version string) bool {
	// Simple version comparison - in practice, you'd want proper semver
	oldVersions := []string{"11.60", "11.70", "11.80", "11.90"}

	for _, oldVer := range oldVersions {
		if strings.HasPrefix(version, oldVer) {
			return true
		}
	}

	return false
}

func (c *CPanelDiscovery) checkConfigurationVulnerabilities(instance CPanelInstance, content string) []Vulnerability {
	vulnerabilities := []Vulnerability{}

	// Check for default credentials
	if c.hasDefaultCredentials(content) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "DEFAULT_CREDENTIALS",
			Severity:    "CRITICAL",
			Details:     "Default or weak credentials detected",
			Remediation: "Change default credentials immediately",
		})
	}

	// Check for exposed configuration
	if c.hasExposedConfig(content) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "EXPOSED_CONFIGURATION",
			Severity:    "HIGH",
			Details:     "Configuration information exposed",
			Remediation: "Restrict access to configuration files",
		})
	}

	// Check for debugging enabled
	if c.hasDebugEnabled(content) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "DEBUG_ENABLED",
			Severity:    "MEDIUM",
			Details:     "Debug mode appears to be enabled",
			Remediation: "Disable debug mode in production",
		})
	}

	return vulnerabilities
}

func (c *CPanelDiscovery) checkFeatureVulnerabilities(features []string, content string) []Vulnerability {
	vulnerabilities := []Vulnerability{}

	for _, feature := range features {
		switch feature {
		case "File Manager":
			if c.hasFileManagerVulns(content) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:        "FILE_MANAGER_VULN",
					Severity:    "HIGH",
					Details:     "File Manager may allow unauthorized file access",
					Remediation: "Update File Manager or restrict access",
				})
			}
		case "Database":
			if c.hasPhpMyAdminVulns(content) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:        "PHPMYADMIN_VULN",
					Severity:    "HIGH",
					Details:     "phpMyAdmin version may be vulnerable",
					Remediation: "Update phpMyAdmin to latest version",
				})
			}
		}
	}

	return vulnerabilities
}

func (c *CPanelDiscovery) checkMisconfigurations(instance CPanelInstance) []Vulnerability {
	vulnerabilities := []Vulnerability{}

	// Check for common misconfigurations
	misconfigs := []MisconfigCheck{
		{
			Name:        "Open File Manager",
			Path:        "/cpsess/frontend/paper_lantern/filemanager/index.html",
			Description: "File Manager accessible without authentication",
			Severity:    "HIGH",
		},
		{
			Name:        "Backup Downloads",
			Path:        "/download?skipencode=1",
			Description: "Backup files may be downloadable",
			Severity:    "HIGH",
		},
		{
			Name:        "Account Suspension Bypass",
			Path:        "/cgi-sys/suspendedpage.cgi",
			Description: "Suspended account bypass possible",
			Severity:    "MEDIUM",
		},
		{
			Name:        "Error Logs Exposed",
			Path:        "/error_log",
			Description: "Error logs may be publicly accessible",
			Severity:    "MEDIUM",
		},
		{
			Name:        "phpinfo() Exposed",
			Path:        "/phpinfo.php",
			Description: "PHP information disclosure",
			Severity:    "HIGH",
		},
		{
			Name:        "cPanel Login Bypass",
			Path:        "/reset_pass",
			Description: "Password reset functionality exposed",
			Severity:    "CRITICAL",
		},
	}

	for _, config := range misconfigs {
		if c.checkMisconfiguration(instance, config) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "CPANEL_MISCONFIGURATION",
				Severity:    config.Severity,
				Details:     config.Description,
				Remediation: fmt.Sprintf("Fix misconfiguration: %s", config.Name),
			})
		}
	}

	return vulnerabilities
}

func (c *CPanelDiscovery) checkMisconfiguration(instance CPanelInstance, config MisconfigCheck) bool {
	// This would make actual HTTP requests to test misconfigurations
	// For now, return false as placeholder
	return false
}

func (c *CPanelDiscovery) hasDefaultCredentials(content string) bool {
	// Check for indicators of default credentials
	patterns := []string{
		"admin:admin",
		"root:root",
		"cpanel:cpanel",
		"demo:demo",
		"test:test",
		"default login",
		"change default password",
	}

	contentLower := strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(contentLower, pattern) {
			return true
		}
	}

	return false
}

func (c *CPanelDiscovery) hasExposedConfig(content string) bool {
	// Check for exposed configuration information
	patterns := []string{
		"database password",
		"mysql password",
		"ftp password",
		"api key",
		"secret key",
		"private key",
		"config.php",
		"wp-config.php",
	}

	contentLower := strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(contentLower, pattern) {
			return true
		}
	}

	return false
}

func (c *CPanelDiscovery) hasDebugEnabled(content string) bool {
	// Check for debug mode indicators
	patterns := []string{
		"debug mode",
		"debug: true",
		"debug=1",
		"debug=on",
		"display_errors = on",
		"error_reporting",
		"debug output",
	}

	contentLower := strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(contentLower, pattern) {
			return true
		}
	}

	return false
}

func (c *CPanelDiscovery) hasFileManagerVulns(content string) bool {
	// Check for File Manager vulnerabilities
	patterns := []string{
		"filemanager",
		"file_manager",
		"upload",
		"directory traversal",
		"../",
		"path traversal",
	}

	contentLower := strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(contentLower, pattern) {
			return true
		}
	}

	return false
}

func (c *CPanelDiscovery) hasPhpMyAdminVulns(content string) bool {
	// Check for phpMyAdmin vulnerabilities
	patterns := []string{
		"phpmyadmin",
		"pma_",
		"mysql",
		"database",
		"sql injection",
		"authentication bypass",
	}

	contentLower := strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(contentLower, pattern) {
			return true
		}
	}

	return false
}

func (c *CPanelDiscovery) extractHeaders(headers http.Header) map[string]string {
	headerMap := make(map[string]string)

	for key, values := range headers {
		if len(values) > 0 {
			headerMap[key] = values[0]
		}
	}

	return headerMap
}

func (c *CPanelDiscovery) extractTitle(content string) string {
	re := regexp.MustCompile(`<title[^>]*>([^<]*)</title>`)
	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func (c *CPanelDiscovery) extractSSLInfo(resp *http.Response) SSLInfo {
	sslInfo := SSLInfo{}

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		sslInfo.Enabled = true
		sslInfo.Certificate = cert.Subject.CommonName
		sslInfo.Issuer = cert.Issuer.CommonName
		sslInfo.ValidFrom = cert.NotBefore
		sslInfo.ValidTo = cert.NotAfter
		sslInfo.SelfSigned = cert.Subject.String() == cert.Issuer.String()
	}

	return sslInfo
}

func (c *CPanelDiscovery) generateFindings(report *CPanelReport) {
	for _, instance := range report.Instances {
		if instance.Accessible {
			report.Findings = append(report.Findings, Finding{
				Type:     "CPANEL_INSTANCE_FOUND",
				Severity: "MEDIUM",
				Title:    "cPanel/WHM Instance Discovered",
				Details:  fmt.Sprintf("Found %s instance at %s", instance.Type, instance.URL),
				URL:      instance.URL,
				Time:     instance.LastChecked,
			})
		}

		for _, vuln := range instance.Vulnerabilities {
			report.Findings = append(report.Findings, Finding{
				Type:     vuln.Type,
				Severity: vuln.Severity,
				Title:    vuln.Type,
				Details:  vuln.Details,
				URL:      instance.URL,
				Time:     instance.LastChecked,
			})
		}
	}
}

func (c *CPanelDiscovery) generateSummary(report *CPanelReport) {
	summary := Summary{}

	summary.TotalInstances = len(report.Instances)

	for _, instance := range report.Instances {
		if instance.Accessible {
			summary.AccessibleInstances++
		}

		if len(instance.Vulnerabilities) > 0 {
			summary.VulnerableInstances++
		}
	}

	for _, finding := range report.Findings {
		switch finding.Severity {
		case "HIGH", "CRITICAL":
			summary.HighRiskFindings++
		case "MEDIUM":
			summary.MediumRiskFindings++
		case "LOW":
			summary.LowRiskFindings++
		}
	}

	report.Summary = summary
}

func getCPanelPatterns() []Pattern {
	return []Pattern{
		{
			Name:        "cPanel Login",
			Regex:       `(?i)cpanel.*login`,
			Description: "cPanel login page",
			Type:        "login",
		},
		{
			Name:        "WHM Login",
			Regex:       `(?i)whm.*login`,
			Description: "WHM login page",
			Type:        "login",
		},
		{
			Name:        "Webmail",
			Regex:       `(?i)webmail`,
			Description: "Webmail interface",
			Type:        "webmail",
		},
		{
			Name:        "File Manager",
			Regex:       `(?i)filemanager`,
			Description: "File manager interface",
			Type:        "filemanager",
		},
		{
			Name:        "Database",
			Regex:       `(?i)phpmyadmin`,
			Description: "Database management",
			Type:        "database",
		},
	}
}
