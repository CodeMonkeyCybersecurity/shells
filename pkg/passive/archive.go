// pkg/passive/archive.go
package passive

import (
	"encoding/json"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

// ArchiveIntel provides web archive archaeological intelligence
type ArchiveIntel struct {
	logger     *logger.Logger
	httpClient *http.Client
	sources    []ArchiveSource
	jsAnalyzer *JavaScriptAnalyzer
	diffEngine *DiffEngine
}

// ArchiveSource represents a web archive source
type ArchiveSource interface {
	Name() string
	GetSnapshots(domain string) ([]Snapshot, error)
	GetSnapshotContent(url string, timestamp time.Time) (string, error)
}

// Snapshot represents a point-in-time capture of a webpage
type Snapshot struct {
	URL        string
	Timestamp  time.Time
	StatusCode int
	MimeType   string
	Digest     string
}

// NewArchiveIntel creates a new archive intelligence module
func NewArchiveIntel(logger *logger.Logger) *ArchiveIntel {
	return &ArchiveIntel{
		logger:     logger,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		sources: []ArchiveSource{
			NewWaybackMachine(),
			NewArchiveToday(),
			NewCommonCrawl(),
		},
		jsAnalyzer: NewJavaScriptAnalyzer(),
		diffEngine: NewDiffEngine(),
	}
}

// ExtractIntelligence performs comprehensive archive analysis
func (a *ArchiveIntel) ExtractIntelligence(domain string) (*ArchiveFindings, error) {
	findings := &ArchiveFindings{
		Domain:           domain,
		DeletedEndpoints: []ArchivedEndpoint{},
		OldParameters:    []string{},
		DevURLs:          []string{},
		APIDocumentation: []APIDoc{},
		ExposedSecrets:   []Secret{},
		TechStackChanges: []TechChange{},
		SecurityHeaders:  make(map[string][]HeaderChange),
	}

	// Collect snapshots from all sources
	allSnapshots := a.collectAllSnapshots(domain)
	if len(allSnapshots) == 0 {
		return findings, fmt.Errorf("no archived snapshots found for %s", domain)
	}

	a.logger.Infow("Collected archive snapshots", "domain", domain, "count", len(allSnapshots))

	// Analyze snapshots in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Process snapshots in batches
	batchSize := 10
	for i := 0; i < len(allSnapshots); i += batchSize {
		end := i + batchSize
		if end > len(allSnapshots) {
			end = len(allSnapshots)
		}

		batch := allSnapshots[i:end]
		for _, snapshot := range batch {
			wg.Add(1)
			go func(snap Snapshot) {
				defer wg.Done()
				a.analyzeSnapshot(snap, findings, &mu)
			}(snapshot)
		}

		wg.Wait() // Wait for batch to complete
	}

	// Perform temporal analysis
	a.performTemporalAnalysis(findings, allSnapshots)

	// Identify patterns and predict endpoints
	a.identifyPatterns(findings)

	return findings, nil
}

// analyzeSnapshot analyzes a single archive snapshot
func (a *ArchiveIntel) analyzeSnapshot(snapshot Snapshot, findings *ArchiveFindings, mu *sync.Mutex) {
	content, err := a.getSnapshotContent(snapshot)
	if err != nil {
		a.logger.Error("Failed to get snapshot content", "url", snapshot.URL, "error", err)
		return
	}

	// Extract various intelligence from content
	endpoints := a.extractEndpoints(content, snapshot.URL)
	parameters := a.extractParameters(content)
	devURLs := a.extractDevURLs(content)
	secrets := a.extractSecrets(content, snapshot.URL)
	apiDocs := a.extractAPIDocs(content, snapshot.URL)

	// JavaScript analysis
	jsFindings := a.jsAnalyzer.AnalyzeJavaScript(content, snapshot.URL)

	mu.Lock()
	defer mu.Unlock()

	// Add findings
	for _, endpoint := range endpoints {
		a.addOrUpdateEndpoint(findings, endpoint, snapshot.Timestamp)
	}

	findings.OldParameters = a.deduplicateStrings(append(findings.OldParameters, parameters...))
	findings.DevURLs = a.deduplicateStrings(append(findings.DevURLs, devURLs...))
	findings.ExposedSecrets = append(findings.ExposedSecrets, secrets...)
	findings.APIDocumentation = append(findings.APIDocumentation, apiDocs...)

	// Add JS findings
	findings.OldParameters = a.deduplicateStrings(append(findings.OldParameters, jsFindings.Parameters...))
	findings.DevURLs = a.deduplicateStrings(append(findings.DevURLs, jsFindings.APIEndpoints...))
}

// extractEndpoints extracts endpoints from archived content
func (a *ArchiveIntel) extractEndpoints(content, baseURL string) []ArchivedEndpoint {
	var endpoints []ArchivedEndpoint

	// Regular expressions for different endpoint patterns
	patterns := []struct {
		regex  *regexp.Regexp
		method string
	}{
		{regexp.MustCompile(`href=["']([^"']+)["']`), "GET"},
		{regexp.MustCompile(`action=["']([^"']+)["']`), "POST"},
		{regexp.MustCompile(`url:\s*["']([^"']+)["']`), "AJAX"},
		{regexp.MustCompile(`fetch\(["']([^"']+)["']`), "FETCH"},
		{regexp.MustCompile(`\.ajax\(\{\s*url:\s*["']([^"']+)["']`), "AJAX"},
		{regexp.MustCompile(`api/[a-zA-Z0-9/_-]+`), "API"},
	}

	base, _ := url.Parse(baseURL)

	for _, pattern := range patterns {
		matches := pattern.regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				endpoint := match[1]

				// Resolve relative URLs
				if !strings.HasPrefix(endpoint, "http") {
					if resolved, err := base.Parse(endpoint); err == nil {
						endpoint = resolved.String()
					}
				}

				// Extract parameters from URL
				params := a.extractURLParameters(endpoint)

				endpoints = append(endpoints, ArchivedEndpoint{
					URL:        endpoint,
					Method:     pattern.method,
					Parameters: params,
				})
			}
		}
	}

	return endpoints
}

// extractParameters extracts parameter names from forms and JavaScript
func (a *ArchiveIntel) extractParameters(content string) []string {
	var parameters []string
	paramSet := make(map[string]bool)

	// Form input names
	inputPattern := regexp.MustCompile(`<input[^>]+name=["']([^"']+)["']`)
	matches := inputPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 && !paramSet[match[1]] {
			paramSet[match[1]] = true
			parameters = append(parameters, match[1])
		}
	}

	// JavaScript object keys that look like parameters
	jsParamPattern := regexp.MustCompile(`["']([a-zA-Z_][a-zA-Z0-9_]{2,30})["']\s*:\s*["']?[^"']+["']?`)
	matches = jsParamPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 && !paramSet[match[1]] {
			// Filter out common JS keywords
			if !a.isCommonJSKeyword(match[1]) {
				paramSet[match[1]] = true
				parameters = append(parameters, match[1])
			}
		}
	}

	return parameters
}

// extractDevURLs extracts development and staging URLs
func (a *ArchiveIntel) extractDevURLs(content string) []string {
	var devURLs []string
	urlSet := make(map[string]bool)

	// Patterns for dev/staging URLs
	patterns := []string{
		`https?://[^"'\s]*(?:dev|test|staging|stage|qa|uat|sandbox|demo|beta|alpha)[^"'\s]*\.[^"'\s]+`,
		`https?://[^"'\s]+\.(?:dev|test|staging|stage|qa|uat|sandbox|demo|beta|alpha)\.[^"'\s]+`,
		`https?://(?:dev|test|staging|stage|qa|uat|sandbox|demo|beta|alpha)[^"'\s]*\.[^"'\s]+`,
		`https?://[^"'\s]+[:\d]+`, // Non-standard ports often indicate dev
	}

	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllString(content, -1)
		for _, match := range matches {
			if !urlSet[match] {
				urlSet[match] = true
				devURLs = append(devURLs, match)
			}
		}
	}

	return devURLs
}

// extractSecrets looks for exposed credentials and API keys
func (a *ArchiveIntel) extractSecrets(content, sourceURL string) []Secret {
	var secrets []Secret

	// Secret patterns with their types
	secretPatterns := []struct {
		pattern  *regexp.Regexp
		typeName string
		severity string
	}{
		{regexp.MustCompile(`(?i)(api[_-]?key|apikey)['"\s]*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]`), "API_KEY", "HIGH"},
		{regexp.MustCompile(`(?i)(api[_-]?secret|apisecret)['"\s]*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]`), "API_SECRET", "CRITICAL"},
		{regexp.MustCompile(`(?i)aws[_-]?access[_-]?key[_-]?id['"\s]*[:=]\s*['"]([A-Z0-9]{20})['"]`), "AWS_ACCESS_KEY", "CRITICAL"},
		{regexp.MustCompile(`(?i)aws[_-]?secret[_-]?access[_-]?key['"\s]*[:=]\s*['"]([a-zA-Z0-9/+=]{40})['"]`), "AWS_SECRET_KEY", "CRITICAL"},
		{regexp.MustCompile(`(?i)(password|passwd|pwd)['"\s]*[:=]\s*['"]([^'"]{8,})['"]`), "PASSWORD", "HIGH"},
		{regexp.MustCompile(`(?i)github[_-]?token['"\s]*[:=]\s*['"]([a-zA-Z0-9]{40})['"]`), "GITHUB_TOKEN", "HIGH"},
		{regexp.MustCompile(`(?i)slack[_-]?webhook['"\s]*[:=]\s*['"]([^'"]+hooks\.slack\.com[^'"]+)['"]`), "SLACK_WEBHOOK", "MEDIUM"},
		{regexp.MustCompile(`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----`), "PRIVATE_KEY", "CRITICAL"},
		{regexp.MustCompile(`(?i)stripe[_-]?(?:secret|api)[_-]?key['"\s]*[:=]\s*['"]([^'"]+)['"]`), "STRIPE_KEY", "CRITICAL"},
		{regexp.MustCompile(`(?i)twilio[_-]?(?:account[_-]?sid|auth[_-]?token)['"\s]*[:=]\s*['"]([^'"]+)['"]`), "TWILIO_CRED", "HIGH"},
	}

	for _, sp := range secretPatterns {
		matches := sp.pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			value := ""
			if len(match) > 2 {
				value = match[2]
			} else if len(match) > 1 {
				value = match[1]
			}

			if value != "" && !a.isPlaceholder(value) {
				// Extract context around the secret
				context := a.extractContext(content, match[0], 100)

				secrets = append(secrets, Secret{
					Type:      sp.typeName,
					Value:     a.redactSecret(value),
					URL:       sourceURL,
					Timestamp: time.Now(),
					Severity:  sp.severity,
					Context:   context,
				})
			}
		}
	}

	return secrets
}

// performTemporalAnalysis analyzes changes over time
func (a *ArchiveIntel) performTemporalAnalysis(findings *ArchiveFindings, snapshots []Snapshot) {
	// Group snapshots by URL
	urlSnapshots := make(map[string][]Snapshot)
	for _, snap := range snapshots {
		urlSnapshots[snap.URL] = append(urlSnapshots[snap.URL], snap)
	}

	// Analyze each URL's history
	for url, snaps := range urlSnapshots {
		if len(snaps) < 2 {
			continue
		}

		// Sort by timestamp
		a.sortSnapshotsByTime(snaps)

		// Compare consecutive snapshots
		for i := 1; i < len(snaps); i++ {
			oldContent, err1 := a.getSnapshotContent(snaps[i-1])
			newContent, err2 := a.getSnapshotContent(snaps[i])

			if err1 != nil || err2 != nil {
				continue
			}

			// Check for security header changes
			oldHeaders := a.extractSecurityHeaders(oldContent)
			newHeaders := a.extractSecurityHeaders(newContent)

			for header, oldValue := range oldHeaders {
				newValue, exists := newHeaders[header]
				if !exists {
					// Header was removed
					findings.SecurityHeaders[header] = append(findings.SecurityHeaders[header], HeaderChange{
						Timestamp: snaps[i].Timestamp,
						OldValue:  oldValue,
						Removed:   true,
					})
				} else if oldValue != newValue {
					// Header was changed
					findings.SecurityHeaders[header] = append(findings.SecurityHeaders[header], HeaderChange{
						Timestamp: snaps[i].Timestamp,
						OldValue:  oldValue,
						NewValue:  newValue,
					})
				}
			}

			// Check for technology changes
			oldTech := a.detectTechnology(oldContent)
			newTech := a.detectTechnology(newContent)

			if oldTech != newTech {
				findings.TechStackChanges = append(findings.TechStackChanges, TechChange{
					Timestamp:  snaps[i].Timestamp,
					OldTech:    oldTech,
					NewTech:    newTech,
					ChangeType: "migration",
					Endpoints:  []string{url},
				})
			}
		}
	}
}

// AnalyzeChanges performs deep analysis of security changes over time
func (a *ArchiveIntel) AnalyzeChanges(snapshots []Snapshot) []SecurityDegradation {
	var degradations []SecurityDegradation

	// Implementation would analyze security posture changes
	// This is a placeholder for the complex analysis logic

	return degradations
}

// Helper methods

func (a *ArchiveIntel) extractContext(content, match string, contextSize int) string {
	index := strings.Index(content, match)
	if index == -1 {
		return ""
	}

	start := index - contextSize
	if start < 0 {
		start = 0
	}

	end := index + len(match) + contextSize
	if end > len(content) {
		end = len(content)
	}

	return content[start:end]
}

func (a *ArchiveIntel) redactSecret(secret string) string {
	if len(secret) <= 4 {
		return "****"
	}
	return secret[:4] + strings.Repeat("*", len(secret)-4)
}

func (a *ArchiveIntel) isPlaceholder(value string) bool {
	placeholders := []string{
		"your-api-key-here",
		"xxxxxxxxxxxx",
		"sk_test_",
		"pk_test_",
		"example",
		"changeme",
		"placeholder",
	}

	valueLower := strings.ToLower(value)
	for _, placeholder := range placeholders {
		if strings.Contains(valueLower, placeholder) {
			return true
		}
	}

	return false
}

func (a *ArchiveIntel) isCommonJSKeyword(word string) bool {
	keywords := []string{
		"function", "return", "var", "let", "const", "if", "else", "for", "while",
		"do", "switch", "case", "break", "continue", "new", "this", "class",
		"export", "import", "default", "extends", "super", "static", "async",
		"await", "try", "catch", "finally", "throw", "typeof", "instanceof",
	}

	for _, keyword := range keywords {
		if word == keyword {
			return true
		}
	}

	return false
}

func (a *ArchiveIntel) deduplicateStrings(strs []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, str := range strs {
		if !seen[str] {
			seen[str] = true
			result = append(result, str)
		}
	}

	return result
}

func (a *ArchiveIntel) extractURLParameters(urlStr string) []string {
	var params []string

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return params
	}

	for key := range parsed.Query() {
		params = append(params, key)
	}

	return params
}

// WaybackMachine implements the ArchiveSource interface
type WaybackMachine struct {
	baseURL string
	client  *http.Client
}

func NewWaybackMachine() *WaybackMachine {
	return &WaybackMachine{
		baseURL: "https://web.archive.org",
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (w *WaybackMachine) Name() string {
	return "wayback_machine"
}

func (w *WaybackMachine) GetSnapshots(domain string) ([]Snapshot, error) {
	// Implementation of Wayback Machine CDX API
	cdxURL := fmt.Sprintf("%s/cdx/search/cdx?url=%s/*&output=json&fl=timestamp,original,statuscode,mimetype,digest",
		w.baseURL, domain)

	resp, err := w.client.Get(cdxURL)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	var snapshots []Snapshot
	decoder := json.NewDecoder(resp.Body)

	// Skip the header row
	var header []interface{}
	if err := decoder.Decode(&header); err != nil {
		return nil, err
	}

	// Decode snapshots
	for decoder.More() {
		var row []interface{}
		if err := decoder.Decode(&row); err != nil {
			continue
		}

		if len(row) >= 5 {
			timestamp, _ := row[0].(string)
			original, _ := row[1].(string)
			statusCode, _ := row[2].(string)
			mimeType, _ := row[3].(string)
			digest, _ := row[4].(string)

			// Parse timestamp
			t, err := time.Parse("20060102150405", timestamp)
			if err != nil {
				continue
			}

			var status int
			fmt.Sscanf(statusCode, "%d", &status)

			snapshots = append(snapshots, Snapshot{
				URL:        original,
				Timestamp:  t,
				StatusCode: status,
				MimeType:   mimeType,
				Digest:     digest,
			})
		}
	}

	return snapshots, nil
}

func (w *WaybackMachine) GetSnapshotContent(url string, timestamp time.Time) (string, error) {
	// Construct Wayback Machine URL
	waybackURL := fmt.Sprintf("%s/web/%s/%s",
		w.baseURL,
		timestamp.Format("20060102150405"),
		url)

	resp, err := w.client.Get(waybackURL)
	if err != nil {
		return "", err
	}
	defer httpclient.CloseBody(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
