package javascript

import (
	"context"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/core"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

type jsAnalyzer struct {
	client *http.Client
	logger interface {
		Info(msg string, keysAndValues ...interface{})
		Error(msg string, keysAndValues ...interface{})
		Debug(msg string, keysAndValues ...interface{})
	}
	linkFinderPath   string
	secretFinderPath string
	retireJSPath     string
}

type JSAnalysisResult struct {
	URLs      []URLFound      `json:"urls"`
	Secrets   []SecretFound   `json:"secrets"`
	Libraries []LibraryFound  `json:"libraries"`
	APIKeys   []APIKeyFound   `json:"api_keys"`
	Endpoints []EndpointFound `json:"endpoints"`
	DOMSinks  []DOMSink       `json:"dom_sinks"`
}

type URLFound struct {
	URL        string `json:"url"`
	Source     string `json:"source"`
	LineNumber int    `json:"line_number"`
	Context    string `json:"context"`
}

type SecretFound struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	Source     string `json:"source"`
	LineNumber int    `json:"line_number"`
	Confidence string `json:"confidence"`
}

type LibraryFound struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Vulnerabilities []string `json:"vulnerabilities"`
	Severity        string   `json:"severity"`
}

type APIKeyFound struct {
	Service    string `json:"service"`
	Key        string `json:"key"`
	Source     string `json:"source"`
	LineNumber int    `json:"line_number"`
}

type EndpointFound struct {
	Endpoint   string   `json:"endpoint"`
	Method     string   `json:"method"`
	Parameters []string `json:"parameters"`
	Source     string   `json:"source"`
}

type DOMSink struct {
	Sink       string `json:"sink"`
	Source     string `json:"source"`
	LineNumber int    `json:"line_number"`
	Risk       string `json:"risk"`
}

func NewJSAnalyzer(logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}) core.Scanner {
	return &jsAnalyzer{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger:           logger,
		linkFinderPath:   "linkfinder",
		secretFinderPath: "secretfinder",
		retireJSPath:     "retire",
	}
}

func (a *jsAnalyzer) Name() string {
	return "javascript"
}

func (a *jsAnalyzer) Type() types.ScanType {
	return types.ScanType("javascript")
}

func (a *jsAnalyzer) Validate(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	// Check if target is URL or file path
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		if _, err := os.Stat(target); os.IsNotExist(err) {
			return fmt.Errorf("target must be a valid URL or file path")
		}
	}

	return nil
}

func (a *jsAnalyzer) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	findings := []types.Finding{}

	a.logger.Info("Starting JavaScript analysis", "target", target)

	// Determine if target is URL or file
	var jsFiles []string
	var err error

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		jsFiles, err = a.fetchJavaScriptFiles(ctx, target)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch JavaScript files: %w", err)
		}
	} else {
		jsFiles = []string{target}
	}

	// Analyze each JavaScript file
	for _, jsFile := range jsFiles {
		fileFindings := a.analyzeJSFile(ctx, jsFile, options)
		findings = append(findings, fileFindings...)
	}

	// Deduplicate findings
	findings = a.deduplicateFindings(findings)

	return findings, nil
}

func (a *jsAnalyzer) fetchJavaScriptFiles(ctx context.Context, targetURL string) ([]string, error) {
	var jsFiles []string

	// Fetch main page
	resp, err := a.client.Get(targetURL)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Extract JavaScript URLs
	jsURLs := a.extractJSURLs(string(body), targetURL)

	// Download each JS file
	tempDir := filepath.Join(os.TempDir(), fmt.Sprintf("jsanalysis_%d", time.Now().Unix()))
	os.MkdirAll(tempDir, 0755)
	defer os.RemoveAll(tempDir)

	for i, jsURL := range jsURLs {
		filePath := filepath.Join(tempDir, fmt.Sprintf("script_%d.js", i))
		if err := a.downloadFile(jsURL, filePath); err != nil {
			a.logger.Error("Failed to download JS file", "url", jsURL, "error", err)
			continue
		}
		jsFiles = append(jsFiles, filePath)
	}

	return jsFiles, nil
}

func (a *jsAnalyzer) analyzeJSFile(ctx context.Context, jsFile string, options map[string]string) []types.Finding {
	findings := []types.Finding{}

	// 1. Find URLs and endpoints
	if urlFindings := a.findURLs(ctx, jsFile); len(urlFindings) > 0 {
		findings = append(findings, urlFindings...)
	}

	// 2. Find secrets and API keys
	if secretFindings := a.findSecrets(ctx, jsFile); len(secretFindings) > 0 {
		findings = append(findings, secretFindings...)
	}

	// 3. Check for vulnerable libraries
	if libFindings := a.checkVulnerableLibraries(ctx, jsFile); len(libFindings) > 0 {
		findings = append(findings, libFindings...)
	}

	// 4. Find potential DOM XSS sinks
	if domFindings := a.findDOMXSSSinks(ctx, jsFile); len(domFindings) > 0 {
		findings = append(findings, domFindings...)
	}

	// 5. OAuth2/Authentication specific patterns
	if authFindings := a.findAuthPatterns(ctx, jsFile); len(authFindings) > 0 {
		findings = append(findings, authFindings...)
	}

	// 6. Find GraphQL/API endpoints
	if apiFindings := a.findAPIEndpoints(ctx, jsFile); len(apiFindings) > 0 {
		findings = append(findings, apiFindings...)
	}

	return findings
}

func (a *jsAnalyzer) findURLs(ctx context.Context, jsFile string) []types.Finding {
	findings := []types.Finding{}

	content, err := os.ReadFile(jsFile)
	if err != nil {
		return findings
	}

	// Regular expressions for finding URLs and endpoints
	patterns := []struct {
		name     string
		pattern  string
		severity types.Severity
	}{
		{"api_endpoint", `["\']/(api|v\d+)/[^"\']*["\']`, types.SeverityInfo},
		{"admin_path", `["\']/(admin|administrator|wp-admin|phpmyadmin)[^"\']*["\']`, types.SeverityMedium},
		{"config_file", `["\'][^"\']*\.(config|conf|cfg|env|ini)["\']`, types.SeverityMedium},
		{"internal_url", `["\'](https?://localhost|https?://127\.0\.0\.1|https?://192\.168|https?://10\.)[^"\']*["\']`, types.SeverityLow},
		{"s3_bucket", `["\']s3://[^"\']+["\']|["\']https?://[^"\']*.s3[^"\']*amazonaws\.com[^"\']*["\']`, types.SeverityMedium},
		{"oauth_endpoint", `["\'][^"\']*/(oauth|auth|authorize|token|callback)[^"\']*["\']`, types.SeverityInfo},
		{"graphql_endpoint", `["\'][^"\']*(graphql|gql)[^"\']*["\']`, types.SeverityInfo},
		{"websocket", `wss?://[^"\']+["\']`, types.SeverityInfo},
		{"file_upload", `["\'][^"\']*/(upload|file|attachment)[^"\']*["\']`, types.SeverityMedium},
	}

	lines := strings.Split(string(content), "\n")

	for _, p := range patterns {
		re := regexp.MustCompile(p.pattern)

		for lineNum, line := range lines {
			matches := re.FindAllString(line, -1)
			for _, match := range matches {
				// Clean up the match
				cleanMatch := strings.Trim(match, `"'`)

				finding := types.Finding{
					Tool:        "javascript",
					Type:        "js_url_discovery",
					Severity:    p.severity,
					Title:       fmt.Sprintf("JavaScript %s Found", strings.Replace(p.name, "_", " ", -1)),
					Description: fmt.Sprintf("Found %s in JavaScript file: %s", p.name, cleanMatch),
					Evidence:    fmt.Sprintf("Line %d: %s", lineNum+1, strings.TrimSpace(line)),
					Metadata: map[string]interface{}{
						"file":        jsFile,
						"line_number": lineNum + 1,
						"url":         cleanMatch,
						"pattern":     p.name,
					},
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func (a *jsAnalyzer) findSecrets(ctx context.Context, jsFile string) []types.Finding {
	findings := []types.Finding{}

	content, err := os.ReadFile(jsFile)
	if err != nil {
		return findings
	}

	// Patterns for various secrets and API keys
	secretPatterns := []struct {
		name     string
		pattern  string
		severity types.Severity
	}{
		{"aws_access_key", `AKIA[0-9A-Z]{16}`, types.SeverityCritical},
		{"aws_secret_key", `["\'][0-9a-zA-Z/+=]{40}["\']`, types.SeverityCritical},
		{"google_api_key", `AIza[0-9A-Za-z\-_]{35}`, types.SeverityHigh},
		{"github_token", `[gG][hH][pP]_[0-9a-zA-Z]{36}`, types.SeverityCritical},
		{"slack_token", `xox[baprs]-[0-9a-zA-Z]{10,48}`, types.SeverityHigh},
		{"stripe_key", `(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}`, types.SeverityHigh},
		{"jwt_token", `eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+`, types.SeverityHigh},
		{"oauth_secret", `["\']client_secret["\']\s*[:=]\s*["\'][^"\']{20,}["\']`, types.SeverityCritical},
		{"api_key_generic", `["\']api[_-]?key["\']\s*[:=]\s*["\'][^"\']{20,}["\']`, types.SeverityHigh},
		{"private_key", `-----BEGIN (RSA |EC )?PRIVATE KEY-----`, types.SeverityCritical},
		{"password_field", `["\']password["\']\s*[:=]\s*["\'][^"\']+["\']`, types.SeverityHigh},
		{"hardcoded_secret", `["\']secret["\']\s*[:=]\s*["\'][^"\']{8,}["\']`, types.SeverityHigh},
	}

	lines := strings.Split(string(content), "\n")

	for _, sp := range secretPatterns {
		re := regexp.MustCompile(sp.pattern)

		for lineNum, line := range lines {
			matches := re.FindAllString(line, -1)
			for _, match := range matches {
				// Sanitize the secret for display
				sanitized := a.sanitizeSecret(match)

				finding := types.Finding{
					Tool:     "javascript",
					Type:     "js_secret_exposure",
					Severity: sp.severity,
					Title:    fmt.Sprintf("%s Exposed in JavaScript", strings.Replace(sp.name, "_", " ", -1)),
					Description: fmt.Sprintf("Found potential %s in JavaScript file. This could lead to unauthorized access.",
						strings.Replace(sp.name, "_", " ", -1)),
					Evidence: fmt.Sprintf("Line %d: %s", lineNum+1, sanitized),
					Solution: "Remove hardcoded secrets from JavaScript files:\n" +
						"1. Use environment variables on the server side\n" +
						"2. Implement proper authentication flows\n" +
						"3. Never expose sensitive credentials in client-side code\n" +
						"4. Rotate any exposed credentials immediately",
					References: []string{
						"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
					},
					Metadata: map[string]interface{}{
						"file":        jsFile,
						"line_number": lineNum + 1,
						"secret_type": sp.name,
						"sanitized":   sanitized,
					},
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func (a *jsAnalyzer) checkVulnerableLibraries(ctx context.Context, jsFile string) []types.Finding {
	findings := []types.Finding{}

	content, err := os.ReadFile(jsFile)
	if err != nil {
		return findings
	}

	// Known vulnerable library patterns
	vulnLibraries := []struct {
		name     string
		pattern  string
		versions string
		cve      string
		severity types.Severity
	}{
		{"jQuery", `jquery[^"]*(?:\.min)?\.js.*?(?:v|version[:\s]*)?(1\.[0-9]\.|2\.[0-2]\.)`, "< 3.0.0", "Multiple XSS vulnerabilities", types.SeverityHigh},
		{"Angular", `angular[^"]*(?:\.min)?\.js.*?(?:v|version[:\s]*)?(1\.[0-5]\.)`, "< 1.6.0", "Multiple security issues", types.SeverityHigh},
		{"Bootstrap", `bootstrap[^"]*(?:\.min)?\.js.*?(?:v|version[:\s]*)?(3\.[0-3]\.|2\.)`, "< 3.4.0", "XSS vulnerabilities", types.SeverityMedium},
		{"Lodash", `lodash[^"]*(?:\.min)?\.js.*?(?:v|version[:\s]*)?(4\.[0-9]\.|3\.)`, "< 4.17.11", "Prototype pollution", types.SeverityHigh},
		{"Moment.js", `moment[^"]*(?:\.min)?\.js`, "All versions", "ReDoS vulnerability", types.SeverityLow},
	}

	contentStr := string(content)

	for _, lib := range vulnLibraries {
		re := regexp.MustCompile(lib.pattern)
		if matches := re.FindStringSubmatch(contentStr); len(matches) > 0 {
			finding := types.Finding{
				Tool:     "javascript",
				Type:     "js_vulnerable_library",
				Severity: lib.severity,
				Title:    fmt.Sprintf("Vulnerable %s Library Detected", lib.name),
				Description: fmt.Sprintf("Using %s version %s which has known vulnerabilities: %s",
					lib.name, lib.versions, lib.cve),
				Evidence: fmt.Sprintf("Detected pattern: %s", matches[0]),
				Solution: fmt.Sprintf("Update %s to the latest version:\n"+
					"1. Check current version in use\n"+
					"2. Review changelog for breaking changes\n"+
					"3. Update to latest stable version\n"+
					"4. Test thoroughly after update", lib.name),
				References: []string{
					"https://snyk.io/vuln/npm:" + strings.ToLower(lib.name),
				},
				Metadata: map[string]interface{}{
					"file":                jsFile,
					"library":             lib.name,
					"vulnerable_versions": lib.versions,
					"vulnerability":       lib.cve,
				},
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

func (a *jsAnalyzer) findDOMXSSSinks(ctx context.Context, jsFile string) []types.Finding {
	findings := []types.Finding{}

	content, err := os.ReadFile(jsFile)
	if err != nil {
		return findings
	}

	// DOM XSS sinks
	xssSinks := []struct {
		sink     string
		pattern  string
		risk     string
		severity types.Severity
	}{
		{"innerHTML", `\.innerHTML\s*=`, "Direct HTML injection", types.SeverityHigh},
		{"outerHTML", `\.outerHTML\s*=`, "Direct HTML injection", types.SeverityHigh},
		{"document.write", `document\.write\(`, "Direct HTML injection", types.SeverityHigh},
		{"document.writeln", `document\.writeln\(`, "Direct HTML injection", types.SeverityHigh},
		{"eval", `eval\(`, "Code execution", types.SeverityCritical},
		{"setTimeout", `setTimeout\([^,]+,\s*[^0-9]`, "Code execution if first param is string", types.SeverityHigh},
		{"setInterval", `setInterval\([^,]+,\s*[^0-9]`, "Code execution if first param is string", types.SeverityHigh},
		{"Function", `new\s+Function\(`, "Code execution", types.SeverityCritical},
		{"location", `location\s*=|location\.href\s*=`, "Open redirect", types.SeverityMedium},
		{"window.open", `window\.open\(`, "Potential open redirect", types.SeverityMedium},
	}

	lines := strings.Split(string(content), "\n")

	for _, sink := range xssSinks {
		re := regexp.MustCompile(sink.pattern)

		for lineNum, line := range lines {
			if re.MatchString(line) {
				// Try to determine if user input flows into this sink
				userInputPattern := `(location\.|document\.|window\.|params\.|query\.|input\.|user\.|data\.)`
				if regexp.MustCompile(userInputPattern).MatchString(line) {
					sink.severity = types.SeverityCritical
				}

				finding := types.Finding{
					Tool:     "javascript",
					Type:     "js_dom_xss_sink",
					Severity: sink.severity,
					Title:    fmt.Sprintf("DOM XSS Sink: %s", sink.sink),
					Description: fmt.Sprintf("Usage of %s detected. %s. If user input reaches this sink, XSS is possible.",
						sink.sink, sink.risk),
					Evidence: fmt.Sprintf("Line %d: %s", lineNum+1, strings.TrimSpace(line)),
					Solution: "Prevent DOM XSS:\n" +
						"1. Sanitize user input before using in dangerous sinks\n" +
						"2. Use textContent instead of innerHTML when possible\n" +
						"3. Implement Content Security Policy\n" +
						"4. Use DOMPurify for HTML sanitization\n" +
						"5. Validate and encode all user input",
					References: []string{
						"https://portswigger.net/web-security/cross-site-scripting/dom-based",
						"https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
					},
					Metadata: map[string]interface{}{
						"file":        jsFile,
						"line_number": lineNum + 1,
						"sink":        sink.sink,
						"risk":        sink.risk,
					},
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func (a *jsAnalyzer) findAuthPatterns(ctx context.Context, jsFile string) []types.Finding {
	findings := []types.Finding{}

	content, err := os.ReadFile(jsFile)
	if err != nil {
		return findings
	}

	// OAuth2 and authentication patterns
	authPatterns := []struct {
		name     string
		pattern  string
		severity types.Severity
		desc     string
	}{
		{"oauth2_config", `["\']client_id["\']\s*:\s*["\'][^"\']+["\']`, types.SeverityInfo, "OAuth2 client ID exposed"},
		{"jwt_decode", `jwt[_-]?decode|decodeJWT|parseJWT`, types.SeverityMedium, "JWT decoding without verification"},
		{"auth_header", `["\']Authorization["\']\s*:\s*["\']Bearer\s+[^"\']+["\']`, types.SeverityHigh, "Hardcoded authorization header"},
		{"api_endpoint_auth", `["\'][^"\']*/(login|signin|authenticate|oauth/token)[^"\']*["\']`, types.SeverityInfo, "Authentication endpoint found"},
		{"localStorage_token", `localStorage\.(setItem|getItem)\(["\']token["\']`, types.SeverityMedium, "Token stored in localStorage (vulnerable to XSS)"},
		{"cookie_httponly", `document\.cookie.*httpOnly`, types.SeverityLow, "Attempting to access httpOnly cookie"},
		{"weak_random", `Math\.random\(\).*token|Math\.random\(\).*secret`, types.SeverityHigh, "Weak randomness for security tokens"},
	}

	lines := strings.Split(string(content), "\n")

	for _, ap := range authPatterns {
		re := regexp.MustCompile(ap.pattern)

		for lineNum, line := range lines {
			if re.MatchString(line) {
				finding := types.Finding{
					Tool:        "javascript",
					Type:        "js_auth_issue",
					Severity:    ap.severity,
					Title:       fmt.Sprintf("Authentication Issue: %s", ap.name),
					Description: ap.desc,
					Evidence:    fmt.Sprintf("Line %d: %s", lineNum+1, strings.TrimSpace(line)),
					Solution:    a.getAuthSolution(ap.name),
					Metadata: map[string]interface{}{
						"file":        jsFile,
						"line_number": lineNum + 1,
						"pattern":     ap.name,
					},
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func (a *jsAnalyzer) findAPIEndpoints(ctx context.Context, jsFile string) []types.Finding {
	findings := []types.Finding{}

	content, err := os.ReadFile(jsFile)
	if err != nil {
		return findings
	}

	// API endpoint patterns
	apiPatterns := []struct {
		name    string
		pattern string
		method  string
	}{
		{"fetch_api", `fetch\(["\']([^"\']+)["\']`, ""},
		{"axios_get", `axios\.get\(["\']([^"\']+)["\']`, "GET"},
		{"axios_post", `axios\.post\(["\']([^"\']+)["\']`, "POST"},
		{"ajax_call", `\$\.ajax\({[^}]*url:\s*["\']([^"\']+)["\']`, ""},
		{"xmlhttprequest", `\.open\(["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']`, ""},
	}

	for _, ap := range apiPatterns {
		re := regexp.MustCompile(ap.pattern)
		matches := re.FindAllStringSubmatch(string(content), -1)

		for _, match := range matches {
			endpoint := ""
			method := ap.method

			if len(match) > 1 {
				endpoint = match[1]
			}
			if len(match) > 2 && method == "" {
				method = match[1]
				endpoint = match[2]
			}

			if endpoint != "" && !strings.HasPrefix(endpoint, "http") {
				finding := types.Finding{
					Tool:        "javascript",
					Type:        "js_api_endpoint",
					Severity:    types.SeverityInfo,
					Title:       fmt.Sprintf("API Endpoint Discovered: %s", endpoint),
					Description: fmt.Sprintf("Found API endpoint in JavaScript: %s %s", method, endpoint),
					Metadata: map[string]interface{}{
						"file":     jsFile,
						"endpoint": endpoint,
						"method":   method,
						"pattern":  ap.name,
					},
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// Helper functions
func (a *jsAnalyzer) extractJSURLs(html, baseURL string) []string {
	var jsURLs []string

	// Extract script tags
	scriptPattern := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["'][^>]*>`)
	matches := scriptPattern.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) > 1 {
			jsURL := a.resolveURL(match[1], baseURL)
			if jsURL != "" {
				jsURLs = append(jsURLs, jsURL)
			}
		}
	}

	// Also look for dynamically loaded scripts
	dynamicPatterns := []string{
		`["']([^"']+\.js)["']`,
		`import\s+.*from\s+["']([^"']+)["']`,
		`require\(["']([^"']+)["']\)`,
	}

	for _, pattern := range dynamicPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(html, -1)
		for _, match := range matches {
			if len(match) > 1 {
				jsURL := a.resolveURL(match[1], baseURL)
				if jsURL != "" && strings.HasSuffix(jsURL, ".js") {
					jsURLs = append(jsURLs, jsURL)
				}
			}
		}
	}

	return a.uniqueStrings(jsURLs)
}

func (a *jsAnalyzer) resolveURL(relativeURL, baseURL string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	rel, err := url.Parse(relativeURL)
	if err != nil {
		return ""
	}

	return base.ResolveReference(rel).String()
}

func (a *jsAnalyzer) downloadFile(url, filepath string) error {
	resp, err := a.client.Get(url)
	if err != nil {
		return err
	}
	defer httpclient.CloseBody(resp)

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func (a *jsAnalyzer) sanitizeSecret(secret string) string {
	if len(secret) > 20 {
		return secret[:10] + "..." + secret[len(secret)-5:]
	}
	return secret[:len(secret)/2] + "..."
}

func (a *jsAnalyzer) getAuthSolution(pattern string) string {
	solutions := map[string]string{
		"oauth2_config":      "Move OAuth2 configuration to server-side. Only expose necessary public information.",
		"jwt_decode":         "Always verify JWT signatures on the server side. Never trust client-side JWT validation.",
		"auth_header":        "Never hardcode authentication tokens. Use secure token storage and rotation.",
		"localStorage_token": "Consider using httpOnly cookies instead of localStorage for sensitive tokens.",
		"weak_random":        "Use crypto.getRandomValues() or server-generated tokens for security-sensitive randomness.",
	}

	if sol, ok := solutions[pattern]; ok {
		return sol
	}
	return "Review and secure authentication implementation"
}

func (a *jsAnalyzer) uniqueStrings(strs []string) []string {
	seen := make(map[string]bool)
	unique := []string{}

	for _, str := range strs {
		if !seen[str] {
			seen[str] = true
			unique = append(unique, str)
		}
	}

	return unique
}

func (a *jsAnalyzer) deduplicateFindings(findings []types.Finding) []types.Finding {
	seen := make(map[string]bool)
	deduplicated := []types.Finding{}

	for _, finding := range findings {
		key := fmt.Sprintf("%s-%s-%v", finding.Type, finding.Title, finding.Metadata["url"])
		if !seen[key] {
			seen[key] = true
			deduplicated = append(deduplicated, finding)
		}
	}

	return deduplicated
}
