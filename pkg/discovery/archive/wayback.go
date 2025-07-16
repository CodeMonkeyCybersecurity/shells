package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type WaybackScanner struct {
	client    *http.Client
	cache     *ArchiveCache
	rateLimit time.Duration
	userAgent string
}

func NewWaybackScanner() *WaybackScanner {
	return &WaybackScanner{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:     NewArchiveCache(),
		rateLimit: 100 * time.Millisecond,
		userAgent: "Mozilla/5.0 (compatible; SecurityTool/1.0)",
	}
}

func NewArchiveCache() *ArchiveCache {
	return &ArchiveCache{
		URLs:     make(map[string]ArchivedURL),
		Content:  make(map[string]string),
		Metadata: make(map[string]interface{}),
	}
}

func (w *WaybackScanner) ScanDomain(ctx context.Context, domain string) (*ArchiveReport, error) {
	report := &ArchiveReport{
		Domain:         domain,
		URLs:           []ArchivedURL{},
		Secrets:        []Secret{},
		AdminPanels:    []AdminPanel{},
		SensitiveFiles: []SensitiveFile{},
		ParameterNames: []string{},
		Endpoints:      []Endpoint{},
		JSFiles:        []JSFile{},
		Comments:       []Comment{},
		Sources:        []string{"wayback"},
	}

	// Get all archived URLs
	urls, err := w.getAllArchivedURLs(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get archived URLs: %v", err)
	}

	report.URLs = urls
	report.TotalSnapshots = len(urls)

	if len(urls) > 0 {
		report.DateRange = DateRange{
			Start: urls[0].Timestamp,
			End:   urls[len(urls)-1].Timestamp,
		}
	}

	// Parallel processing with rate limiting
	semaphore := make(chan struct{}, 10)
	results := make(chan ArchiveFinding, len(urls))
	var wg sync.WaitGroup

	for _, archivedURL := range urls {
		wg.Add(1)
		go func(u ArchivedURL) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Rate limiting
			time.Sleep(w.rateLimit)

			// Fetch archived content
			content, err := w.fetchArchivedContent(ctx, u)
			if err != nil {
				return
			}

			// Extract interesting data
			w.extractSecrets(content, u, results)
			w.extractEndpoints(content, u, results)
			w.extractComments(content, u, results)
			w.extractJSFiles(content, u, results)
			w.extractParameters(content, u, results)
			w.extractAdminPanels(content, u, results)
			w.extractSensitiveFiles(content, u, results)

		}(archivedURL)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	w.processResults(results, report)

	return report, nil
}

func (w *WaybackScanner) getAllArchivedURLs(ctx context.Context, domain string) ([]ArchivedURL, error) {
	// Wayback Machine CDX API
	apiURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=timestamp,original,statuscode,mimetype,length", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", w.userAgent)

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rawData [][]string
	if err := json.Unmarshal(body, &rawData); err != nil {
		return nil, err
	}

	// Skip header row
	if len(rawData) > 0 {
		rawData = rawData[1:]
	}

	urls := make([]ArchivedURL, 0, len(rawData))
	for _, row := range rawData {
		if len(row) < 5 {
			continue
		}

		timestamp, err := time.Parse("20060102150405", row[0])
		if err != nil {
			continue
		}

		statusCode := 0
		if row[2] != "" {
			fmt.Sscanf(row[2], "%d", &statusCode)
		}

		size := int64(0)
		if row[4] != "" {
			fmt.Sscanf(row[4], "%d", &size)
		}

		urls = append(urls, ArchivedURL{
			URL:        row[1],
			Timestamp:  timestamp,
			StatusCode: statusCode,
			MimeType:   row[3],
			Size:       size,
			Source:     "wayback",
		})
	}

	return urls, nil
}

func (w *WaybackScanner) fetchArchivedContent(ctx context.Context, u ArchivedURL) (string, error) {
	// Check cache first
	if cached, exists := w.cache.Content[u.URL]; exists {
		return cached, nil
	}

	// Construct wayback URL
	waybackURL := fmt.Sprintf("https://web.archive.org/web/%s/%s", u.Timestamp.Format("20060102150405"), u.URL)

	req, err := http.NewRequestWithContext(ctx, "GET", waybackURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", w.userAgent)

	resp, err := w.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch archived content: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	content := string(body)

	// Cache the content
	w.cache.Content[u.URL] = content
	w.cache.URLs[u.URL] = u

	return content, nil
}

func (w *WaybackScanner) extractSecrets(content string, u ArchivedURL, results chan<- ArchiveFinding) {
	patterns := w.getSecretPatterns()

	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern.Pattern)
		matches := regex.FindAllStringSubmatch(content, -1)

		for _, match := range matches {
			if len(match) > 1 {
				results <- ArchiveFinding{
					Type:      "SECRET",
					Name:      pattern.Name,
					Value:     match[len(match)-1],
					URL:       u.URL,
					Timestamp: u.Timestamp,
					Severity:  pattern.Severity,
					Context:   w.getContext(content, match[0]),
				}
			}
		}
	}
}

func (w *WaybackScanner) extractEndpoints(content string, u ArchivedURL, results chan<- ArchiveFinding) {
	// Extract API endpoints
	apiPatterns := []string{
		`/api/[v\d/]*[\w\-]+`,
		`/rest/[v\d/]*[\w\-]+`,
		`/graphql\b`,
		`/webhook\b`,
		`\.json\b`,
		`\.xml\b`,
	}

	for _, pattern := range apiPatterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllString(content, -1)

		for _, match := range matches {
			results <- ArchiveFinding{
				Type:      "ENDPOINT",
				Name:      "api_endpoint",
				Value:     match,
				URL:       u.URL,
				Timestamp: u.Timestamp,
				Severity:  "MEDIUM",
			}
		}
	}

	// Extract form actions
	formPattern := regexp.MustCompile(`<form[^>]*action=["\']([^"\']+)["\']`)
	matches := formPattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			results <- ArchiveFinding{
				Type:      "ENDPOINT",
				Name:      "form_action",
				Value:     match[1],
				URL:       u.URL,
				Timestamp: u.Timestamp,
				Severity:  "LOW",
			}
		}
	}
}

func (w *WaybackScanner) extractComments(content string, u ArchivedURL, results chan<- ArchiveFinding) {
	// HTML comments
	htmlPattern := regexp.MustCompile(`<!--\s*(.+?)\s*-->`)
	matches := htmlPattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 && w.isInterestingComment(match[1]) {
			results <- ArchiveFinding{
				Type:      "COMMENT",
				Name:      "html_comment",
				Value:     match[1],
				URL:       u.URL,
				Timestamp: u.Timestamp,
				Severity:  "LOW",
			}
		}
	}

	// JavaScript comments
	jsPattern := regexp.MustCompile(`//\s*(.+?)[\r\n]`)
	matches = jsPattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 && w.isInterestingComment(match[1]) {
			results <- ArchiveFinding{
				Type:      "COMMENT",
				Name:      "js_comment",
				Value:     match[1],
				URL:       u.URL,
				Timestamp: u.Timestamp,
				Severity:  "LOW",
			}
		}
	}
}

func (w *WaybackScanner) extractJSFiles(content string, u ArchivedURL, results chan<- ArchiveFinding) {
	// Extract JavaScript file references
	jsPattern := regexp.MustCompile(`<script[^>]*src=["\']([^"\']+\.js)["\']`)
	matches := jsPattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			results <- ArchiveFinding{
				Type:      "JS_FILE",
				Name:      "javascript_file",
				Value:     match[1],
				URL:       u.URL,
				Timestamp: u.Timestamp,
				Severity:  "LOW",
			}
		}
	}

	// Extract inline JavaScript
	inlinePattern := regexp.MustCompile(`<script[^>]*>(.*?)</script>`)
	matches = inlinePattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 && len(match[1]) > 100 { // Only capture substantial inline JS
			results <- ArchiveFinding{
				Type:      "INLINE_JS",
				Name:      "inline_javascript",
				Value:     match[1][:200] + "...", // Truncate for storage
				URL:       u.URL,
				Timestamp: u.Timestamp,
				Severity:  "LOW",
			}
		}
	}
}

func (w *WaybackScanner) extractParameters(content string, u ArchivedURL, results chan<- ArchiveFinding) {
	// Extract URL parameters
	paramPattern := regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_]*)\=`)
	matches := paramPattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			results <- ArchiveFinding{
				Type:      "PARAMETER",
				Name:      "url_parameter",
				Value:     match[1],
				URL:       u.URL,
				Timestamp: u.Timestamp,
				Severity:  "LOW",
			}
		}
	}

	// Extract form input names
	inputPattern := regexp.MustCompile(`<input[^>]*name=["\']([^"\']+)["\']`)
	matches = inputPattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			results <- ArchiveFinding{
				Type:      "PARAMETER",
				Name:      "form_input",
				Value:     match[1],
				URL:       u.URL,
				Timestamp: u.Timestamp,
				Severity:  "LOW",
			}
		}
	}
}

func (w *WaybackScanner) extractAdminPanels(content string, u ArchivedURL, results chan<- ArchiveFinding) {
	// Check for admin panel indicators
	adminPatterns := []string{
		`admin`,
		`administrator`,
		`control panel`,
		`dashboard`,
		`management`,
		`cpanel`,
		`phpmyadmin`,
		`webmail`,
		`login`,
		`auth`,
	}

	urlLower := strings.ToLower(u.URL)
	contentLower := strings.ToLower(content)

	for _, pattern := range adminPatterns {
		if strings.Contains(urlLower, pattern) || strings.Contains(contentLower, pattern) {
			results <- ArchiveFinding{
				Type:      "ADMIN_PANEL",
				Name:      "potential_admin_panel",
				Value:     pattern,
				URL:       u.URL,
				Timestamp: u.Timestamp,
				Severity:  "HIGH",
			}
			break // Only report once per URL
		}
	}
}

func (w *WaybackScanner) extractSensitiveFiles(content string, u ArchivedURL, results chan<- ArchiveFinding) {
	// Check for sensitive file patterns in URL
	sensitivePatterns := []string{
		`\.env`,
		`\.git`,
		`\.htaccess`,
		`\.htpasswd`,
		`web\.config`,
		`\.bak`,
		`\.backup`,
		`\.sql`,
		`\.log`,
		`robots\.txt`,
		`sitemap\.xml`,
		`crossdomain\.xml`,
		`phpinfo\.php`,
		`config\.php`,
		`wp-config\.php`,
	}

	urlLower := strings.ToLower(u.URL)

	for _, pattern := range sensitivePatterns {
		if matched, _ := regexp.MatchString(pattern, urlLower); matched {
			results <- ArchiveFinding{
				Type:      "SENSITIVE_FILE",
				Name:      "sensitive_file_pattern",
				Value:     pattern,
				URL:       u.URL,
				Timestamp: u.Timestamp,
				Severity:  "HIGH",
			}
		}
	}
}

func (w *WaybackScanner) getSecretPatterns() []SecretPattern {
	return []SecretPattern{
		{
			Name:        "api_key",
			Pattern:     `(?i)(api[_-]?key|apikey)['"\s]*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})`,
			Description: "API Key",
			Severity:    "HIGH",
		},
		{
			Name:        "password",
			Pattern:     `(?i)password['"\s]*[:=]\s*['"]?([^'"\s]{8,})`,
			Description: "Password",
			Severity:    "HIGH",
		},
		{
			Name:        "private_key",
			Pattern:     `-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----`,
			Description: "Private Key",
			Severity:    "CRITICAL",
		},
		{
			Name:        "aws_access_key",
			Pattern:     `AKIA[0-9A-Z]{16}`,
			Description: "AWS Access Key",
			Severity:    "HIGH",
		},
		{
			Name:        "aws_secret_key",
			Pattern:     `(?i)aws[_-]?secret[_-]?access[_-]?key['"\s]*[:=]\s*['"]?([a-zA-Z0-9/+=]{40})`,
			Description: "AWS Secret Key",
			Severity:    "CRITICAL",
		},
		{
			Name:        "google_api_key",
			Pattern:     `AIza[0-9A-Za-z\-_]{35}`,
			Description: "Google API Key",
			Severity:    "HIGH",
		},
		{
			Name:        "slack_token",
			Pattern:     `xox[baprs]-[0-9a-zA-Z]{10,48}`,
			Description: "Slack Token",
			Severity:    "HIGH",
		},
		{
			Name:        "jwt_token",
			Pattern:     `eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`,
			Description: "JWT Token",
			Severity:    "MEDIUM",
		},
		{
			Name:        "github_token",
			Pattern:     `ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`,
			Description: "GitHub Token",
			Severity:    "HIGH",
		},
		{
			Name:        "database_url",
			Pattern:     `(?i)(database_url|db_url)['"\s]*[:=]\s*['"]?([^'"\s]+)`,
			Description: "Database URL",
			Severity:    "HIGH",
		},
	}
}

func (w *WaybackScanner) getContext(content, match string) string {
	index := strings.Index(content, match)
	if index == -1 {
		return ""
	}

	start := index - 50
	if start < 0 {
		start = 0
	}

	end := index + len(match) + 50
	if end > len(content) {
		end = len(content)
	}

	return content[start:end]
}

func (w *WaybackScanner) isInterestingComment(comment string) bool {
	comment = strings.ToLower(comment)

	interestingKeywords := []string{
		"password", "secret", "key", "token", "api",
		"admin", "auth", "login", "user", "pass",
		"config", "debug", "test", "todo", "fixme",
		"hack", "bug", "issue", "problem", "error",
		"database", "db", "sql", "server", "host",
	}

	for _, keyword := range interestingKeywords {
		if strings.Contains(comment, keyword) {
			return true
		}
	}

	return false
}

func (w *WaybackScanner) processResults(results <-chan ArchiveFinding, report *ArchiveReport) {
	secretMap := make(map[string]Secret)
	adminMap := make(map[string]AdminPanel)
	fileMap := make(map[string]SensitiveFile)
	endpointMap := make(map[string]Endpoint)
	jsFileMap := make(map[string]JSFile)
	commentMap := make(map[string]Comment)
	paramMap := make(map[string]bool)

	for finding := range results {
		switch finding.Type {
		case "SECRET":
			key := finding.Name + ":" + finding.Value
			secretMap[key] = Secret{
				Type:      finding.Name,
				Value:     finding.Value,
				URL:       finding.URL,
				Context:   finding.Context,
				Timestamp: finding.Timestamp,
				Severity:  finding.Severity,
			}

		case "ADMIN_PANEL":
			adminMap[finding.URL] = AdminPanel{
				URL:        finding.URL,
				Type:       finding.Name,
				Timestamp:  finding.Timestamp,
				Accessible: false, // Would need to test
			}

		case "SENSITIVE_FILE":
			fileMap[finding.URL] = SensitiveFile{
				URL:       finding.URL,
				Type:      finding.Name,
				Timestamp: finding.Timestamp,
			}

		case "ENDPOINT":
			key := finding.Value
			if existing, exists := endpointMap[key]; exists {
				existing.Frequency++
				if finding.Timestamp.After(existing.LastSeen) {
					existing.LastSeen = finding.Timestamp
				}
				if finding.Timestamp.Before(existing.FirstSeen) {
					existing.FirstSeen = finding.Timestamp
				}
				endpointMap[key] = existing
			} else {
				endpointMap[key] = Endpoint{
					Path:        finding.Value,
					FirstSeen:   finding.Timestamp,
					LastSeen:    finding.Timestamp,
					Frequency:   1,
					Confidence:  "MEDIUM",
					StillExists: false, // Would need to test
				}
			}

		case "JS_FILE":
			jsFileMap[finding.URL] = JSFile{
				URL:       finding.Value,
				Timestamp: finding.Timestamp,
			}

		case "COMMENT":
			key := finding.URL + ":" + finding.Value
			commentMap[key] = Comment{
				Content:   finding.Value,
				URL:       finding.URL,
				Timestamp: finding.Timestamp,
				Type:      finding.Name,
			}

		case "PARAMETER":
			paramMap[finding.Value] = true
		}
	}

	// Convert maps to slices
	for _, secret := range secretMap {
		report.Secrets = append(report.Secrets, secret)
	}

	for _, admin := range adminMap {
		report.AdminPanels = append(report.AdminPanels, admin)
	}

	for _, file := range fileMap {
		report.SensitiveFiles = append(report.SensitiveFiles, file)
	}

	for _, endpoint := range endpointMap {
		report.Endpoints = append(report.Endpoints, endpoint)
	}

	for _, jsFile := range jsFileMap {
		report.JSFiles = append(report.JSFiles, jsFile)
	}

	for _, comment := range commentMap {
		report.Comments = append(report.Comments, comment)
	}

	for param := range paramMap {
		report.ParameterNames = append(report.ParameterNames, param)
	}
}

func (w *WaybackScanner) FindOldEndpoints(ctx context.Context, domain string) ([]Endpoint, error) {
	endpoints := []Endpoint{}

	// Get historical URLs
	historicalURLs, err := w.getAllArchivedURLs(ctx, domain)
	if err != nil {
		return endpoints, err
	}

	// Group by path patterns
	pathGroups := make(map[string][]ArchivedURL)
	for _, url := range historicalURLs {
		path := w.extractPath(url.URL)
		pathGroups[path] = append(pathGroups[path], url)
	}

	// Test if old endpoints still exist
	for path, urls := range pathGroups {
		// If seen multiple times in history, likely important
		if len(urls) > 3 {
			stillExists := w.endpointStillExists(ctx, domain, path)

			endpoints = append(endpoints, Endpoint{
				Path:        path,
				FirstSeen:   urls[0].Timestamp,
				LastSeen:    urls[len(urls)-1].Timestamp,
				Frequency:   len(urls),
				Confidence:  "HIGH",
				StillExists: stillExists,
			})
		}
	}

	return endpoints, nil
}

func (w *WaybackScanner) extractPath(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return u.Path
}

func (w *WaybackScanner) endpointStillExists(ctx context.Context, domain, path string) bool {
	testURL := fmt.Sprintf("https://%s%s", domain, path)

	req, err := http.NewRequestWithContext(ctx, "HEAD", testURL, nil)
	if err != nil {
		return false
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode < 400
}
