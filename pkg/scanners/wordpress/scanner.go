package wordpress

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type WordPressScanner struct {
	client    *http.Client
	userAgent string
	timeout   time.Duration
	workers   int
	pluginDB  *PluginVulnDB
	themeDB   *ThemeVulnDB
	rateLimit time.Duration
}

type WordPressReport struct {
	URL              string            `json:"url"`
	Version          string            `json:"version"`
	Themes           []Theme           `json:"themes"`
	Plugins          []Plugin          `json:"plugins"`
	Users            []User            `json:"users"`
	Vulnerabilities  []Vulnerability   `json:"vulnerabilities"`
	AdvancedFindings []AdvancedFinding `json:"advanced_findings"`
	Configuration    Configuration     `json:"configuration"`
	SecurityHeaders  SecurityHeaders   `json:"security_headers"`
	LastUpdated      time.Time         `json:"last_updated"`
	ScanDuration     time.Duration     `json:"scan_duration"`
	IsWordPress      bool              `json:"is_wordpress"`
	ConfidenceScore  float64           `json:"confidence_score"`
}

type Theme struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	Author          string          `json:"author"`
	Active          bool            `json:"active"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	LastUpdated     time.Time       `json:"last_updated"`
	Directory       string          `json:"directory"`
}

type Plugin struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	Author          string          `json:"author"`
	Active          bool            `json:"active"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	LastUpdated     time.Time       `json:"last_updated"`
	Directory       string          `json:"directory"`
	Description     string          `json:"description"`
}

type User struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Role        string `json:"role"`
	PostCount   int    `json:"post_count"`
	AvatarURL   string `json:"avatar_url"`
	Source      string `json:"source"`
}

type Vulnerability struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVSS        float64   `json:"cvss"`
	CVE         string    `json:"cve"`
	References  []string  `json:"references"`
	FixedIn     string    `json:"fixed_in"`
	Published   time.Time `json:"published"`
	Component   string    `json:"component"`
	Version     string    `json:"version"`
}

type AdvancedFinding struct {
	Type        string    `json:"type"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	URL         string    `json:"url"`
	Evidence    string    `json:"evidence"`
	Remediation string    `json:"remediation"`
	Timestamp   time.Time `json:"timestamp"`
}

type Configuration struct {
	DebuggingEnabled    bool     `json:"debugging_enabled"`
	DirectoryListing    bool     `json:"directory_listing"`
	FileEditing         bool     `json:"file_editing"`
	RegistrationEnabled bool     `json:"registration_enabled"`
	CommentsEnabled     bool     `json:"comments_enabled"`
	PingbacksEnabled    bool     `json:"pingbacks_enabled"`
	XMLRPCEnabled       bool     `json:"xmlrpc_enabled"`
	RestAPIEnabled      bool     `json:"rest_api_enabled"`
	ExposedFiles        []string `json:"exposed_files"`
	BackupFiles         []string `json:"backup_files"`
	LogFiles            []string `json:"log_files"`
}

type SecurityHeaders struct {
	XFrameOptions           string `json:"x_frame_options"`
	XContentTypeOptions     string `json:"x_content_type_options"`
	XSSProtection           string `json:"xss_protection"`
	StrictTransportSecurity string `json:"strict_transport_security"`
	ContentSecurityPolicy   string `json:"content_security_policy"`
	ReferrerPolicy          string `json:"referrer_policy"`
	PermissionsPolicy       string `json:"permissions_policy"`
}

type PluginVulnDB struct {
	Vulnerabilities map[string][]Vulnerability `json:"vulnerabilities"`
	LastUpdated     time.Time                  `json:"last_updated"`
}

type ThemeVulnDB struct {
	Vulnerabilities map[string][]Vulnerability `json:"vulnerabilities"`
	LastUpdated     time.Time                  `json:"last_updated"`
}

type WPCheck struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type CheckResult struct {
	Found   bool   `json:"found"`
	Details string `json:"details"`
	Content string `json:"content"`
}

func NewWordPressScanner() *WordPressScanner {
	return &WordPressScanner{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
		userAgent: "Mozilla/5.0 (compatible; WordPressScanner/1.0)",
		timeout:   30 * time.Second,
		workers:   20,
		pluginDB:  loadPluginVulnDB(),
		themeDB:   loadThemeVulnDB(),
		rateLimit: 100 * time.Millisecond,
	}
}

func (w *WordPressScanner) DeepScan(ctx context.Context, target string) (*WordPressReport, error) {
	startTime := time.Now()

	report := &WordPressReport{
		URL:              target,
		Themes:           []Theme{},
		Plugins:          []Plugin{},
		Users:            []User{},
		Vulnerabilities:  []Vulnerability{},
		AdvancedFindings: []AdvancedFinding{},
		LastUpdated:      time.Now(),
		IsWordPress:      false,
	}

	// 1. Detect WordPress
	if !w.isWordPress(ctx, target) {
		return report, fmt.Errorf("target is not a WordPress site")
	}

	report.IsWordPress = true
	report.ConfidenceScore = w.calculateConfidence(target)

	// 2. Version detection
	report.Version = w.detectVersion(ctx, target)

	// 3. Security headers analysis
	report.SecurityHeaders = w.analyzeSecurityHeaders(ctx, target)

	// 4. Configuration analysis
	report.Configuration = w.analyzeConfiguration(ctx, target)

	// 5. Plugin enumeration
	plugins, err := w.enumeratePlugins(ctx, target)
	if err == nil {
		report.Plugins = plugins
	}

	// 6. Theme detection
	themes, err := w.enumerateThemes(ctx, target)
	if err == nil {
		report.Themes = themes
	}

	// 7. User enumeration
	users, err := w.enumerateUsers(ctx, target)
	if err == nil {
		report.Users = users
	}

	// 8. Vulnerability scanning
	report.Vulnerabilities = w.scanVulnerabilities(report)

	// 9. Advanced checks
	report.AdvancedFindings = w.advancedChecks(ctx, target)

	report.ScanDuration = time.Since(startTime)

	return report, nil
}

func (w *WordPressScanner) isWordPress(ctx context.Context, target string) bool {
	indicators := []string{
		"/wp-content/",
		"/wp-includes/",
		"/wp-admin/",
		"wp-json",
		"WordPress",
		"wp-embed",
		"wp-emoji",
		"wp-content",
		"wp-includes",
	}

	// Check main page
	if content, err := w.fetchContent(ctx, target); err == nil {
		for _, indicator := range indicators {
			if strings.Contains(content, indicator) {
				return true
			}
		}
	}

	// Check specific WordPress paths
	paths := []string{
		"/wp-admin/",
		"/wp-login.php",
		"/wp-content/",
		"/wp-includes/",
		"/wp-json/",
		"/readme.html",
		"/license.txt",
	}

	for _, path := range paths {
		if resp, err := w.makeRequest(ctx, target+path); err == nil {
			if resp.StatusCode == 200 || resp.StatusCode == 403 {
				return true
			}
		}
	}

	return false
}

func (w *WordPressScanner) calculateConfidence(target string) float64 {
	// Implement confidence scoring based on detected indicators
	return 0.9 // Simplified
}

func (w *WordPressScanner) detectVersion(ctx context.Context, target string) string {
	// Check generator meta tag
	if content, err := w.fetchContent(ctx, target); err == nil {
		patterns := []string{
			`<meta name="generator" content="WordPress ([^"]+)"`,
			`wp-includes/js/wp-emoji-release\.min\.js\?ver=([^"]+)`,
			`wp-content/themes/[^/]+/style\.css\?ver=([^"]+)`,
			`wp-includes/css/dist/block-library/style\.min\.css\?ver=([^"]+)`,
		}

		for _, pattern := range patterns {
			re := regexp.MustCompile(pattern)
			if matches := re.FindStringSubmatch(content); len(matches) > 1 {
				return matches[1]
			}
		}
	}

	// Check readme.html
	if content, err := w.fetchContent(ctx, target+"/readme.html"); err == nil {
		re := regexp.MustCompile(`<br />\s*Version\s+([0-9.]+)`)
		if matches := re.FindStringSubmatch(content); len(matches) > 1 {
			return matches[1]
		}
	}

	// Check RSS feed
	if content, err := w.fetchContent(ctx, target+"/feed/"); err == nil {
		re := regexp.MustCompile(`<generator>.*WordPress ([0-9.]+)</generator>`)
		if matches := re.FindStringSubmatch(content); len(matches) > 1 {
			return matches[1]
		}
	}

	return "unknown"
}

func (w *WordPressScanner) analyzeSecurityHeaders(ctx context.Context, target string) SecurityHeaders {
	headers := SecurityHeaders{}

	if resp, err := w.makeRequest(ctx, target); err == nil {
		headers.XFrameOptions = resp.Header.Get("X-Frame-Options")
		headers.XContentTypeOptions = resp.Header.Get("X-Content-Type-Options")
		headers.XSSProtection = resp.Header.Get("X-XSS-Protection")
		headers.StrictTransportSecurity = resp.Header.Get("Strict-Transport-Security")
		headers.ContentSecurityPolicy = resp.Header.Get("Content-Security-Policy")
		headers.ReferrerPolicy = resp.Header.Get("Referrer-Policy")
		headers.PermissionsPolicy = resp.Header.Get("Permissions-Policy")
	}

	return headers
}

func (w *WordPressScanner) analyzeConfiguration(ctx context.Context, target string) Configuration {
	config := Configuration{
		ExposedFiles: []string{},
		BackupFiles:  []string{},
		LogFiles:     []string{},
	}

	// Check for debugging
	if content, err := w.fetchContent(ctx, target); err == nil {
		if strings.Contains(content, "wp_debug") || strings.Contains(content, "WP_DEBUG") {
			config.DebuggingEnabled = true
		}
	}

	// Check directory listing
	if resp, err := w.makeRequest(ctx, target+"/wp-content/"); err == nil {
		if resp.StatusCode == 200 {
			if body, err := io.ReadAll(resp.Body); err == nil {
				if strings.Contains(string(body), "Index of") {
					config.DirectoryListing = true
				}
			}
		}
	}

	// Check registration
	if resp, err := w.makeRequest(ctx, target+"/wp-register.php"); err == nil {
		if resp.StatusCode == 200 {
			config.RegistrationEnabled = true
		}
	}

	// Check XMLRPC
	if resp, err := w.makeRequest(ctx, target+"/xmlrpc.php"); err == nil {
		if resp.StatusCode == 200 {
			config.XMLRPCEnabled = true
		}
	}

	// Check REST API
	if resp, err := w.makeRequest(ctx, target+"/wp-json/"); err == nil {
		if resp.StatusCode == 200 {
			config.RestAPIEnabled = true
		}
	}

	// Check for exposed files
	exposedFiles := []string{
		"/wp-config.php",
		"/wp-config.php.bak",
		"/.wp-config.php.swp",
		"/wp-config.old",
		"/debug.log",
		"/error_log",
		"/wp-content/debug.log",
		"/wp-content/backup-db/",
		"/wp-content/uploads/dump.sql",
		"/.htaccess",
		"/robots.txt",
		"/sitemap.xml",
		"/readme.html",
		"/license.txt",
	}

	for _, file := range exposedFiles {
		if resp, err := w.makeRequest(ctx, target+file); err == nil {
			if resp.StatusCode == 200 {
				config.ExposedFiles = append(config.ExposedFiles, file)
			}
		}
	}

	return config
}

func (w *WordPressScanner) enumeratePlugins(ctx context.Context, target string) ([]Plugin, error) {
	plugins := []Plugin{}

	// Method 1: Extract from HTML/CSS/JS
	if content, err := w.fetchContent(ctx, target); err == nil {
		extractedPlugins := w.extractPluginsFromSource(content)
		plugins = append(plugins, extractedPlugins...)
	}

	// Method 2: Common plugin paths
	commonPlugins := w.getCommonPlugins()

	// Use worker pool for concurrent checking
	pluginChan := make(chan string, len(commonPlugins))
	resultChan := make(chan Plugin, len(commonPlugins))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < w.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pluginSlug := range pluginChan {
				if plugin := w.checkPlugin(ctx, target, pluginSlug); plugin != nil {
					resultChan <- *plugin
				}
			}
		}()
	}

	// Send work
	go func() {
		for _, plugin := range commonPlugins {
			pluginChan <- plugin
		}
		close(pluginChan)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for plugin := range resultChan {
		plugins = append(plugins, plugin)
	}

	// Method 3: Fuzzing with smart wordlist
	fuzzedPlugins := w.fuzzPluginPaths(ctx, target)
	plugins = append(plugins, fuzzedPlugins...)

	// Check vulnerabilities for each plugin
	for i := range plugins {
		plugins[i].Vulnerabilities = w.checkPluginVulnerabilities(plugins[i])
	}

	return plugins, nil
}

func (w *WordPressScanner) extractPluginsFromSource(content string) []Plugin {
	plugins := []Plugin{}

	// Extract from wp-content/plugins/ paths
	pluginPattern := regexp.MustCompile(`wp-content/plugins/([^/\s"']+)`)
	matches := pluginPattern.FindAllStringSubmatch(content, -1)

	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			plugins = append(plugins, Plugin{
				Name:      match[1],
				Directory: match[1],
				Active:    true, // Likely active if referenced
			})
		}
	}

	return plugins
}

func (w *WordPressScanner) checkPlugin(ctx context.Context, target, pluginSlug string) *Plugin {
	pluginURL := fmt.Sprintf("%s/wp-content/plugins/%s/", target, pluginSlug)

	if resp, err := w.makeRequest(ctx, pluginURL); err == nil {
		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			plugin := &Plugin{
				Name:      pluginSlug,
				Directory: pluginSlug,
				Active:    true,
			}

			// Try to get plugin details from readme.txt
			if readmeContent, err := w.fetchContent(ctx, pluginURL+"readme.txt"); err == nil {
				w.parsePluginReadme(plugin, readmeContent)
			}

			return plugin
		}
	}

	return nil
}

func (w *WordPressScanner) parsePluginReadme(plugin *Plugin, content string) {
	// Extract version
	versionPattern := regexp.MustCompile(`(?i)stable tag:\s*([^\r\n]+)`)
	if matches := versionPattern.FindStringSubmatch(content); len(matches) > 1 {
		plugin.Version = strings.TrimSpace(matches[1])
	}

	// Extract description
	descPattern := regexp.MustCompile(`(?i)description:\s*([^\r\n]+)`)
	if matches := descPattern.FindStringSubmatch(content); len(matches) > 1 {
		plugin.Description = strings.TrimSpace(matches[1])
	}

	// Extract author
	authorPattern := regexp.MustCompile(`(?i)contributors?:\s*([^\r\n]+)`)
	if matches := authorPattern.FindStringSubmatch(content); len(matches) > 1 {
		plugin.Author = strings.TrimSpace(matches[1])
	}
}

func (w *WordPressScanner) fuzzPluginPaths(ctx context.Context, target string) []Plugin {
	// This would implement fuzzing logic
	return []Plugin{}
}

func (w *WordPressScanner) enumerateThemes(ctx context.Context, target string) ([]Theme, error) {
	themes := []Theme{}

	// Method 1: Extract active theme from source
	if content, err := w.fetchContent(ctx, target); err == nil {
		if activeTheme := w.extractActiveTheme(content); activeTheme != nil {
			themes = append(themes, *activeTheme)
		}
	}

	// Method 2: Common theme paths
	commonThemes := w.getCommonThemes()

	for _, themeSlug := range commonThemes {
		if theme := w.checkTheme(ctx, target, themeSlug); theme != nil {
			themes = append(themes, *theme)
		}
	}

	// Check vulnerabilities for each theme
	for i := range themes {
		themes[i].Vulnerabilities = w.checkThemeVulnerabilities(themes[i])
	}

	return themes, nil
}

func (w *WordPressScanner) extractActiveTheme(content string) *Theme {
	// Extract active theme from wp-content/themes/ paths
	themePattern := regexp.MustCompile(`wp-content/themes/([^/\s"']+)`)
	matches := themePattern.FindAllStringSubmatch(content, -1)

	if len(matches) > 0 {
		return &Theme{
			Name:      matches[0][1],
			Directory: matches[0][1],
			Active:    true,
		}
	}

	return nil
}

func (w *WordPressScanner) checkTheme(ctx context.Context, target, themeSlug string) *Theme {
	themeURL := fmt.Sprintf("%s/wp-content/themes/%s/", target, themeSlug)

	if resp, err := w.makeRequest(ctx, themeURL); err == nil {
		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			theme := &Theme{
				Name:      themeSlug,
				Directory: themeSlug,
				Active:    false, // We can't determine if it's active just from this
			}

			// Try to get theme details from style.css
			if styleContent, err := w.fetchContent(ctx, themeURL+"style.css"); err == nil {
				w.parseThemeStyle(theme, styleContent)
			}

			return theme
		}
	}

	return nil
}

func (w *WordPressScanner) parseThemeStyle(theme *Theme, content string) {
	// Extract theme information from style.css header
	versionPattern := regexp.MustCompile(`(?i)version:\s*([^\r\n]+)`)
	if matches := versionPattern.FindStringSubmatch(content); len(matches) > 1 {
		theme.Version = strings.TrimSpace(matches[1])
	}

	authorPattern := regexp.MustCompile(`(?i)author:\s*([^\r\n]+)`)
	if matches := authorPattern.FindStringSubmatch(content); len(matches) > 1 {
		theme.Author = strings.TrimSpace(matches[1])
	}
}

func (w *WordPressScanner) enumerateUsers(ctx context.Context, target string) ([]User, error) {
	users := []User{}

	// Method 1: REST API
	if restUsers, err := w.getUsersFromRESTAPI(ctx, target); err == nil {
		users = append(users, restUsers...)
	}

	// Method 2: Author enumeration
	if authorUsers, err := w.getUsersFromAuthors(ctx, target); err == nil {
		users = append(users, authorUsers...)
	}

	// Method 3: Login enumeration (careful with this)
	if loginUsers, err := w.getUsersFromLogin(ctx, target); err == nil {
		users = append(users, loginUsers...)
	}

	return users, nil
}

func (w *WordPressScanner) getUsersFromRESTAPI(ctx context.Context, target string) ([]User, error) {
	users := []User{}

	apiURL := target + "/wp-json/wp/v2/users"
	if content, err := w.fetchContent(ctx, apiURL); err == nil {
		var apiUsers []map[string]interface{}
		if err := json.Unmarshal([]byte(content), &apiUsers); err == nil {
			for _, apiUser := range apiUsers {
				user := User{
					Source: "rest_api",
				}

				if id, ok := apiUser["id"].(float64); ok {
					user.ID = int(id)
				}
				if name, ok := apiUser["name"].(string); ok {
					user.DisplayName = name
				}
				if slug, ok := apiUser["slug"].(string); ok {
					user.Username = slug
				}

				users = append(users, user)
			}
		}
	}

	return users, nil
}

func (w *WordPressScanner) getUsersFromAuthors(ctx context.Context, target string) ([]User, error) {
	users := []User{}

	// Try author enumeration
	for i := 1; i <= 10; i++ {
		authorURL := fmt.Sprintf("%s/?author=%d", target, i)
		if resp, err := w.makeRequest(ctx, authorURL); err == nil {
			if resp.StatusCode == 200 {
				// Extract username from redirect or content
				if username := w.extractUsernameFromAuthorPage(resp); username != "" {
					users = append(users, User{
						ID:       i,
						Username: username,
						Source:   "author_enumeration",
					})
				}
			}
		}
	}

	return users, nil
}

func (w *WordPressScanner) extractUsernameFromAuthorPage(resp *http.Response) string {
	// Check for redirect to author slug
	if location := resp.Header.Get("Location"); location != "" {
		authorPattern := regexp.MustCompile(`/author/([^/\s"']+)`)
		if matches := authorPattern.FindStringSubmatch(location); len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

func (w *WordPressScanner) getUsersFromLogin(ctx context.Context, target string) ([]User, error) {
	// This would implement login enumeration - be careful about rate limiting
	return []User{}, nil
}

func (w *WordPressScanner) scanVulnerabilities(report *WordPressReport) []Vulnerability {
	vulnerabilities := []Vulnerability{}

	// Core WordPress vulnerabilities
	if report.Version != "unknown" {
		coreVulns := w.checkCoreVulnerabilities(report.Version)
		vulnerabilities = append(vulnerabilities, coreVulns...)
	}

	// Plugin vulnerabilities
	for _, plugin := range report.Plugins {
		vulnerabilities = append(vulnerabilities, plugin.Vulnerabilities...)
	}

	// Theme vulnerabilities
	for _, theme := range report.Themes {
		vulnerabilities = append(vulnerabilities, theme.Vulnerabilities...)
	}

	return vulnerabilities
}

func (w *WordPressScanner) checkCoreVulnerabilities(version string) []Vulnerability {
	// Check against known WordPress core vulnerabilities
	// This would query a vulnerability database
	return []Vulnerability{}
}

func (w *WordPressScanner) checkPluginVulnerabilities(plugin Plugin) []Vulnerability {
	if vulns, exists := w.pluginDB.Vulnerabilities[plugin.Name]; exists {
		var applicableVulns []Vulnerability
		for _, vuln := range vulns {
			if w.isVersionVulnerable(plugin.Version, vuln.Version, vuln.FixedIn) {
				applicableVulns = append(applicableVulns, vuln)
			}
		}
		return applicableVulns
	}
	return []Vulnerability{}
}

func (w *WordPressScanner) checkThemeVulnerabilities(theme Theme) []Vulnerability {
	if vulns, exists := w.themeDB.Vulnerabilities[theme.Name]; exists {
		var applicableVulns []Vulnerability
		for _, vuln := range vulns {
			if w.isVersionVulnerable(theme.Version, vuln.Version, vuln.FixedIn) {
				applicableVulns = append(applicableVulns, vuln)
			}
		}
		return applicableVulns
	}
	return []Vulnerability{}
}

func (w *WordPressScanner) isVersionVulnerable(currentVersion, vulnVersion, fixedIn string) bool {
	// Implement version comparison logic
	return true // Simplified
}

func (w *WordPressScanner) advancedChecks(ctx context.Context, target string) []AdvancedFinding {
	findings := []AdvancedFinding{}

	checks := []WPCheck{
		// File exposure
		{Path: "/wp-config.php.bak", Type: "CONFIG_BACKUP", Severity: "CRITICAL"},
		{Path: "/.wp-config.php.swp", Type: "CONFIG_SWAP", Severity: "HIGH"},
		{Path: "/wp-config.old", Type: "CONFIG_OLD", Severity: "HIGH"},
		{Path: "/debug.log", Type: "DEBUG_LOG", Severity: "MEDIUM"},

		// Database exposure
		{Path: "/wp-content/backup-db/", Type: "DB_BACKUP", Severity: "CRITICAL"},
		{Path: "/wp-content/uploads/dump.sql", Type: "DB_DUMP", Severity: "CRITICAL"},

		// User enumeration endpoints
		{Path: "/wp-json/wp/v2/users", Type: "REST_API_USERS", Severity: "MEDIUM"},
		{Path: "/?author=1", Type: "AUTHOR_ENUM", Severity: "LOW"},

		// XMLRPC
		{Path: "/xmlrpc.php", Type: "XMLRPC_ENABLED", Severity: "MEDIUM"},

		// Upload directory listing
		{Path: "/wp-content/uploads/", Type: "UPLOAD_LISTING", Severity: "LOW"},

		// Admin interfaces
		{Path: "/wp-admin/", Type: "ADMIN_ACCESS", Severity: "LOW"},
		{Path: "/wp-login.php", Type: "LOGIN_PAGE", Severity: "LOW"},

		// Information disclosure
		{Path: "/readme.html", Type: "README_EXPOSED", Severity: "LOW"},
		{Path: "/license.txt", Type: "LICENSE_EXPOSED", Severity: "LOW"},

		// Backup files
		{Path: "/wp-config.php~", Type: "CONFIG_BACKUP", Severity: "HIGH"},
		{Path: "/wp-config.bak", Type: "CONFIG_BACKUP", Severity: "HIGH"},
	}

	for _, check := range checks {
		if result := w.checkPath(ctx, target, check); result.Found {
			findings = append(findings, AdvancedFinding{
				Type:        check.Type,
				Title:       w.getCheckTitle(check.Type),
				Description: w.getCheckDescription(check.Type),
				Severity:    check.Severity,
				URL:         target + check.Path,
				Evidence:    result.Details,
				Remediation: w.getRemediation(check.Type),
				Timestamp:   time.Now(),
			})
		}
	}

	// WordPress specific attack checks
	findings = append(findings, w.checkRegistrationEnabled(ctx, target)...)
	findings = append(findings, w.checkDefaultAdmin(ctx, target)...)
	findings = append(findings, w.checkOutdatedVersion(ctx, target)...)
	findings = append(findings, w.checkDirectoryListing(ctx, target)...)

	return findings
}

func (w *WordPressScanner) checkPath(ctx context.Context, target string, check WPCheck) CheckResult {
	resp, err := w.makeRequest(ctx, target+check.Path)
	if err != nil {
		return CheckResult{Found: false}
	}

	if resp.StatusCode == 200 {
		if body, err := io.ReadAll(resp.Body); err == nil {
			return CheckResult{
				Found:   true,
				Details: fmt.Sprintf("Status: %d, Size: %d bytes", resp.StatusCode, len(body)),
				Content: string(body),
			}
		}
	}

	return CheckResult{Found: false}
}

func (w *WordPressScanner) getCheckTitle(checkType string) string {
	titles := map[string]string{
		"CONFIG_BACKUP":   "WordPress Configuration Backup Exposed",
		"CONFIG_SWAP":     "WordPress Configuration Swap File Exposed",
		"CONFIG_OLD":      "WordPress Configuration Old File Exposed",
		"DEBUG_LOG":       "Debug Log File Exposed",
		"DB_BACKUP":       "Database Backup Exposed",
		"DB_DUMP":         "Database Dump Exposed",
		"REST_API_USERS":  "User Information via REST API",
		"AUTHOR_ENUM":     "Author Enumeration Possible",
		"XMLRPC_ENABLED":  "XML-RPC Enabled",
		"UPLOAD_LISTING":  "Upload Directory Listing",
		"ADMIN_ACCESS":    "Admin Interface Accessible",
		"LOGIN_PAGE":      "Login Page Accessible",
		"README_EXPOSED":  "README File Exposed",
		"LICENSE_EXPOSED": "License File Exposed",
	}

	if title, exists := titles[checkType]; exists {
		return title
	}
	return checkType
}

func (w *WordPressScanner) getCheckDescription(checkType string) string {
	descriptions := map[string]string{
		"CONFIG_BACKUP":   "WordPress configuration backup file found, may contain sensitive information",
		"CONFIG_SWAP":     "WordPress configuration swap file found, may contain sensitive information",
		"CONFIG_OLD":      "WordPress configuration old file found, may contain sensitive information",
		"DEBUG_LOG":       "Debug log file found, may contain sensitive information",
		"DB_BACKUP":       "Database backup directory found, may contain sensitive data",
		"DB_DUMP":         "Database dump file found, may contain sensitive data",
		"REST_API_USERS":  "User information is accessible via REST API",
		"AUTHOR_ENUM":     "Author enumeration is possible",
		"XMLRPC_ENABLED":  "XML-RPC is enabled and may be used for attacks",
		"UPLOAD_LISTING":  "Upload directory listing is enabled",
		"ADMIN_ACCESS":    "Admin interface is accessible",
		"LOGIN_PAGE":      "Login page is accessible",
		"README_EXPOSED":  "README file is exposed, reveals WordPress version",
		"LICENSE_EXPOSED": "License file is exposed",
	}

	if desc, exists := descriptions[checkType]; exists {
		return desc
	}
	return "Security check failed"
}

func (w *WordPressScanner) getRemediation(checkType string) string {
	remediations := map[string]string{
		"CONFIG_BACKUP":   "Remove backup configuration files from web root",
		"CONFIG_SWAP":     "Remove swap files from web root",
		"CONFIG_OLD":      "Remove old configuration files from web root",
		"DEBUG_LOG":       "Disable debug logging or move logs outside web root",
		"DB_BACKUP":       "Remove database backup files from web root",
		"DB_DUMP":         "Remove database dump files from web root",
		"REST_API_USERS":  "Disable REST API user endpoints or implement authentication",
		"AUTHOR_ENUM":     "Disable author enumeration or implement rate limiting",
		"XMLRPC_ENABLED":  "Disable XML-RPC if not needed",
		"UPLOAD_LISTING":  "Disable directory listing for uploads",
		"ADMIN_ACCESS":    "Restrict admin access with IP filtering",
		"LOGIN_PAGE":      "Implement strong authentication and rate limiting",
		"README_EXPOSED":  "Remove or restrict access to readme.html",
		"LICENSE_EXPOSED": "Remove or restrict access to license.txt",
	}

	if remediation, exists := remediations[checkType]; exists {
		return remediation
	}
	return "Review and fix security issue"
}

func (w *WordPressScanner) checkRegistrationEnabled(ctx context.Context, target string) []AdvancedFinding {
	// Check if user registration is enabled
	return []AdvancedFinding{}
}

func (w *WordPressScanner) checkDefaultAdmin(ctx context.Context, target string) []AdvancedFinding {
	// Check for default admin user
	return []AdvancedFinding{}
}

func (w *WordPressScanner) checkOutdatedVersion(ctx context.Context, target string) []AdvancedFinding {
	// Check if WordPress version is outdated
	return []AdvancedFinding{}
}

func (w *WordPressScanner) checkDirectoryListing(ctx context.Context, target string) []AdvancedFinding {
	// Check for directory listing vulnerabilities
	return []AdvancedFinding{}
}

func (w *WordPressScanner) makeRequest(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", w.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	// Rate limiting
	time.Sleep(w.rateLimit)

	return w.client.Do(req)
}

func (w *WordPressScanner) fetchContent(ctx context.Context, url string) (string, error) {
	resp, err := w.makeRequest(ctx, url)
	if err != nil {
		return "", err
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (w *WordPressScanner) getCommonPlugins() []string {
	return []string{
		"akismet", "jetpack", "wordpress-seo", "contact-form-7", "woocommerce",
		"elementor", "classic-editor", "wpforms-lite", "wordfence", "updraftplus",
		"wp-super-cache", "really-simple-ssl", "duplicate-post", "wp-optimize",
		"all-in-one-seo-pack", "wp-smushit", "mailchimp-for-wp", "wp-file-manager",
		"advanced-custom-fields", "wp-rocket", "tinymce-advanced", "wp-security-audit-log",
		"wp-fastest-cache", "google-analytics-for-wordpress", "wp-user-avatar",
		"wp-mail-smtp", "wp-migrate-db", "wp-db-backup", "wp-config-file-editor",
		"user-role-editor", "wp-reset", "wp-clone", "wp-backup-to-dropbox",
		"wp-maintenance-mode", "wp-staging", "wp-database-backup", "wp-security-scan",
		"wp-login-security", "wp-limit-login-attempts", "wp-ban", "wp-hide-login",
		"wp-captcha", "wp-antispam", "wp-spamshield", "wp-defender", "wp-cerber",
		"wp-security", "wp-firewall", "wp-malware-scanner", "wp-virus-scanner",
		"wp-file-permissions", "wp-hide-wp-version", "wp-remove-wp-version",
		"wp-disable-xmlrpc", "wp-disable-rest-api", "wp-disable-comments",
		"wp-disable-users", "wp-disable-feeds", "wp-disable-emojis",
	}
}

func (w *WordPressScanner) getCommonThemes() []string {
	return []string{
		"twentytwentyone", "twentytwenty", "twentynineteen", "twentyseventeen",
		"twentysixteen", "twentyfifteen", "twentyfourteen", "twentythirteen",
		"twentytwelve", "twentyeleven", "twentyten", "astra", "generatepress",
		"oceanwp", "customizr", "hestia", "neve", "storefront", "divi",
		"avada", "enfold", "jupiter", "bridge", "salient", "the7", "x",
		"flatsome", "betheme", "porto", "uncode", "kalium", "soledad",
		"newspaper", "sahifa", "jnews", "publisher", "magazine", "newsmag",
		"newsmax", "herald", "voice", "valenti", "goodnews", "jarida",
		"enfold", "avada", "divi", "jupiter", "bridge", "salient", "the7",
		"x", "flatsome", "betheme", "porto", "uncode", "kalium", "soledad",
	}
}

func loadPluginVulnDB() *PluginVulnDB {
	return &PluginVulnDB{
		Vulnerabilities: make(map[string][]Vulnerability),
		LastUpdated:     time.Now(),
	}
}

func loadThemeVulnDB() *ThemeVulnDB {
	return &ThemeVulnDB{
		Vulnerabilities: make(map[string][]Vulnerability),
		LastUpdated:     time.Now(),
	}
}
