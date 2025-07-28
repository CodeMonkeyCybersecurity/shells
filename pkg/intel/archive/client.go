// pkg/intel/archive/client.go
package archive

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// ArchiveSource represents a web archive source
type ArchiveSource interface {
	GetSnapshots(ctx context.Context, domain string) ([]Snapshot, error)
	GetContent(ctx context.Context, url string, timestamp time.Time) (string, error)
	Name() string
}

// Snapshot represents a point-in-time archive of a URL
type Snapshot struct {
	URL       string
	Timestamp time.Time
	Status    int
	MimeType  string
	Source    string
}

// ArchiveFindings contains intelligence extracted from archives
type ArchiveFindings struct {
	DeletedEndpoints    []EndpointFinding
	OldParameters       []ParameterFinding
	DevelopmentURLs     []URLFinding
	APIDocumentation    []APIDocFinding
	ExposedCredentials  []CredentialFinding
	TechnologyEvolution []TechStackChange
	SecurityDegradation []SecurityChange
}

// EndpointFinding represents a deleted endpoint that still exists
type EndpointFinding struct {
	URL             string
	LastSeen        time.Time
	StillExists     bool
	StatusCode      int
	Functionality   string
	ConfidenceScore float64
}

// ParameterFinding represents historical parameter names
type ParameterFinding struct {
	Parameter     string
	Endpoint      string
	FirstSeen     time.Time
	LastSeen      time.Time
	ExampleValues []string
	StillAccepted bool
}

// SecurityChange represents security degradation over time
type SecurityChange struct {
	Type        string // "header_removed", "auth_weakened", etc.
	Description string
	ChangedAt   time.Time
	OldValue    string
	NewValue    string
	Severity    string
}

// ArchiveIntel provides web archive intelligence
type ArchiveIntel struct {
	logger      *logger.Logger
	httpClient  *http.Client
	sources     []ArchiveSource
	workers     int
	mu          sync.Mutex
	rateLimiter *time.Ticker
}

// NewArchiveIntel creates a new archive intelligence client
func NewArchiveIntel(log *logger.Logger) *ArchiveIntel {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &ArchiveIntel{
		logger:      log,
		httpClient:  client,
		workers:     5,
		rateLimiter: time.NewTicker(time.Second), // 1 request per second
		sources: []ArchiveSource{
			NewWaybackMachine(client, log),
			NewArchiveToday(client, log),
			// Additional sources can be added here
		},
	}
}

// ExtractIntelligence extracts security intelligence from web archives
func (a *ArchiveIntel) ExtractIntelligence(ctx context.Context, domain string) (*ArchiveFindings, error) {
	findings := &ArchiveFindings{
		DeletedEndpoints:    []EndpointFinding{},
		OldParameters:       []ParameterFinding{},
		DevelopmentURLs:     []URLFinding{},
		APIDocumentation:    []APIDocFinding{},
		ExposedCredentials:  []CredentialFinding{},
		TechnologyEvolution: []TechStackChange{},
		SecurityDegradation: []SecurityChange{},
	}

	// Get all snapshots from all sources
	allSnapshots, err := a.getAllSnapshots(ctx, domain)
	if err != nil {
		return findings, err
	}

	a.logger.Infow("Found snapshots", "count", len(allSnapshots), "domain", domain)

	// Group snapshots by URL
	urlSnapshots := a.groupSnapshotsByURL(allSnapshots)

	// Analyze each URL's history
	var wg sync.WaitGroup
	findingsChan := make(chan interface{}, 100)

	// Process URLs in parallel
	semaphore := make(chan struct{}, a.workers)

	for url, snapshots := range urlSnapshots {
		wg.Add(1)
		go func(u string, snaps []Snapshot) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			a.analyzeURLHistory(ctx, u, snaps, findingsChan)
		}(url, snapshots)
	}

	// Collector goroutine
	done := make(chan bool)
	go func() {
		for finding := range findingsChan {
			a.mu.Lock()
			switch f := finding.(type) {
			case EndpointFinding:
				findings.DeletedEndpoints = append(findings.DeletedEndpoints, f)
			case ParameterFinding:
				findings.OldParameters = append(findings.OldParameters, f)
			case URLFinding:
				findings.DevelopmentURLs = append(findings.DevelopmentURLs, f)
			case APIDocFinding:
				findings.APIDocumentation = append(findings.APIDocumentation, f)
			case CredentialFinding:
				findings.ExposedCredentials = append(findings.ExposedCredentials, f)
			case SecurityChange:
				findings.SecurityDegradation = append(findings.SecurityDegradation, f)
			}
			a.mu.Unlock()
		}
		done <- true
	}()

	wg.Wait()
	close(findingsChan)
	<-done

	// Analyze technology evolution and security changes
	a.analyzeTechnologyEvolution(ctx, allSnapshots, findings)
	a.analyzeSecurityPosture(ctx, urlSnapshots, findings)

	return findings, nil
}

// AnalyzeChanges performs temporal analysis on snapshots
func (a *ArchiveIntel) AnalyzeChanges(ctx context.Context, snapshots []Snapshot) []SecurityDegradation {
	degradations := []SecurityDegradation{}

	// Sort snapshots by time
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Timestamp.Before(snapshots[j].Timestamp)
	})

	// Compare consecutive snapshots
	for i := 1; i < len(snapshots); i++ {
		prev := snapshots[i-1]
		curr := snapshots[i]

		if prev.URL != curr.URL {
			continue
		}

		// Get content for both snapshots
		prevContent, err1 := a.getSnapshotContent(ctx, prev)
		currContent, err2 := a.getSnapshotContent(ctx, curr)

		if err1 != nil || err2 != nil {
			continue
		}

		// Analyze changes
		changes := a.compareSnapshots(prevContent, currContent, prev.Timestamp, curr.Timestamp)
		degradations = append(degradations, changes...)
	}

	return degradations
}

// Helper methods

// getAllSnapshots retrieves snapshots from all archive sources
func (a *ArchiveIntel) getAllSnapshots(ctx context.Context, domain string) ([]Snapshot, error) {
	var allSnapshots []Snapshot
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, source := range a.sources {
		wg.Add(1)
		go func(s ArchiveSource) {
			defer wg.Done()

			snapshots, err := s.GetSnapshots(ctx, domain)
			if err != nil {
				a.logger.Error("Failed to get snapshots", "source", s.Name(), "error", err)
				return
			}

			mu.Lock()
			allSnapshots = append(allSnapshots, snapshots...)
			mu.Unlock()
		}(source)
	}

	wg.Wait()
	return allSnapshots, nil
}

// groupSnapshotsByURL groups snapshots by their URL
func (a *ArchiveIntel) groupSnapshotsByURL(snapshots []Snapshot) map[string][]Snapshot {
	grouped := make(map[string][]Snapshot)

	for _, snapshot := range snapshots {
		grouped[snapshot.URL] = append(grouped[snapshot.URL], snapshot)
	}

	// Sort each group by timestamp
	for url, snaps := range grouped {
		sort.Slice(snaps, func(i, j int) bool {
			return snaps[i].Timestamp.Before(snaps[j].Timestamp)
		})
		grouped[url] = snaps
	}

	return grouped
}

// analyzeURLHistory analyzes the history of a specific URL
func (a *ArchiveIntel) analyzeURLHistory(ctx context.Context, url string, snapshots []Snapshot, findings chan<- interface{}) {
	if len(snapshots) == 0 {
		return
	}

	// Check if this endpoint was deleted
	lastSeen := snapshots[len(snapshots)-1].Timestamp
	if time.Since(lastSeen) > 90*24*time.Hour { // Not seen in 90 days
		// Check if it still exists
		exists, statusCode := a.checkEndpointExists(url)
		if exists {
			findings <- EndpointFinding{
				URL:             url,
				LastSeen:        lastSeen,
				StillExists:     true,
				StatusCode:      statusCode,
				Functionality:   a.guessEndpointFunction(url),
				ConfidenceScore: 0.8,
			}
		}
	}

	// Analyze content from different time periods
	for _, snapshot := range snapshots {
		content, err := a.getSnapshotContent(ctx, snapshot)
		if err != nil {
			continue
		}

		// Extract parameters
		params := a.extractParameters(content, url)
		for _, param := range params {
			findings <- param
		}

		// Check for development URLs
		devURLs := a.findDevelopmentURLs(content)
		for _, devURL := range devURLs {
			findings <- devURL
		}

		// Check for API documentation
		apiDocs := a.findAPIDocumentation(content)
		for _, doc := range apiDocs {
			findings <- doc
		}

		// Check for exposed credentials
		creds := a.findExposedCredentials(content)
		for _, cred := range creds {
			findings <- cred
		}
	}
}

// extractParameters extracts parameter names from HTML content
func (a *ArchiveIntel) extractParameters(content, url string) []ParameterFinding {
	findings := []ParameterFinding{}

	// Regular expressions for parameter extraction
	patterns := []string{
		`<input[^>]+name=["']([^"']+)["']`, // Form inputs
		`\?([a-zA-Z0-9_]+)=`,               // URL parameters
		`["']([a-zA-Z0-9_]+)["']\s*:\s*`,   // JSON keys
		`data-([a-zA-Z0-9_-]+)=`,           // Data attributes
	}

	foundParams := make(map[string]bool)

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1)

		for _, match := range matches {
			if len(match) > 1 {
				param := match[1]
				if !foundParams[param] && a.isInterestingParameter(param) {
					foundParams[param] = true
					findings = append(findings, ParameterFinding{
						Parameter:     param,
						Endpoint:      url,
						FirstSeen:     time.Now(), // This would be the snapshot time
						StillAccepted: false,      // To be tested
					})
				}
			}
		}
	}

	return findings
}

// findDevelopmentURLs finds development and staging URLs in content
func (a *ArchiveIntel) findDevelopmentURLs(content string) []URLFinding {
	findings := []URLFinding{}

	// Patterns for development URLs
	patterns := []string{
		`(https?://[^"'\s]*(?:dev|development|staging|stage|test|qa|uat)[^"'\s]*)`,
		`(https?://(?:dev|staging|test|qa)\.[^"'\s]+)`,
		`(https?://[^"'\s]*\.(?:dev|staging|test|local)[^"'\s]*)`,
		`(https?://localhost[^"'\s]*)`,
		`(https?://127\.0\.0\.1[^"'\s]*)`,
		`(https?://192\.168\.[0-9]{1,3}\.[0-9]{1,3}[^"'\s]*)`,
		`(https?://10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[^"'\s]*)`,
		`(https?://172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}[^"'\s]*)`,
	}

	foundURLs := make(map[string]bool)

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1)

		for _, match := range matches {
			if len(match) > 1 {
				devURL := match[1]
				if !foundURLs[devURL] && a.isValidURL(devURL) {
					foundURLs[devURL] = true
					findings = append(findings, URLFinding{
						URL:        devURL,
						Type:       "development",
						FirstSeen:  time.Now(),
						Confidence: 0.7,
					})
				}
			}
		}
	}

	return findings
}

// findAPIDocumentation looks for API documentation in content
func (a *ArchiveIntel) findAPIDocumentation(content string) []APIDocFinding {
	findings := []APIDocFinding{}

	// Look for API documentation patterns
	apiPatterns := []string{
		`/api/v[0-9]+`,
		`/swagger`,
		`/api-docs`,
		`/graphql`,
		`"openapi":\s*"[0-9.]+`,
		`"swagger":\s*"[0-9.]+`,
	}

	for _, pattern := range apiPatterns {
		if matched, _ := regexp.MatchString(pattern, content); matched {
			findings = append(findings, APIDocFinding{
				Type:       "api_documentation",
				Content:    pattern,
				Confidence: 0.8,
			})
		}
	}

	return findings
}

// findExposedCredentials searches for exposed credentials in content
func (a *ArchiveIntel) findExposedCredentials(content string) []CredentialFinding {
	findings := []CredentialFinding{}

	// Credential patterns
	credPatterns := map[string]string{
		"api_key":        `(?i)(api[_-]?key|apikey)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})["']?`,
		"aws_access_key": `AKIA[0-9A-Z]{16}`,
		"private_key":    `-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----`,
		"password":       `(?i)password\s*[:=]\s*["']([^"']{8,})["']`,
		"secret":         `(?i)secret\s*[:=]\s*["']([^"']{8,})["']`,
		"token":          `(?i)token\s*[:=]\s*["']([a-zA-Z0-9_\-\.]{20,})["']`,
	}

	for credType, pattern := range credPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1)

		for _, match := range matches {
			value := match[0]
			if len(match) > 1 {
				value = match[1]
			}

			findings = append(findings, CredentialFinding{
				Type:       credType,
				Value:      a.sanitizeCredential(value),
				Confidence: 0.9,
			})
		}
	}

	return findings
}

// compareSnapshots compares two snapshots for security changes
func (a *ArchiveIntel) compareSnapshots(prevContent, currContent string, prevTime, currTime time.Time) []SecurityDegradation {
	degradations := []SecurityDegradation{}

	// Check for removed security headers
	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
	}

	for _, header := range securityHeaders {
		prevHas := strings.Contains(prevContent, header)
		currHas := strings.Contains(currContent, header)

		if prevHas && !currHas {
			degradations = append(degradations, SecurityDegradation{
				Type:        "security_header_removed",
				Description: fmt.Sprintf("Security header '%s' was removed", header),
				ChangedAt:   currTime,
				Severity:    "medium",
			})
		}
	}

	// Check for authentication weakening
	authPatterns := map[string]string{
		"oauth": `oauth|OAuth`,
		"saml":  `saml|SAML`,
		"jwt":   `jwt|JWT|bearer`,
		"basic": `basic auth|Basic Auth`,
	}

	for authType, pattern := range authPatterns {
		prevMatches, _ := regexp.MatchString(pattern, prevContent)
		currMatches, _ := regexp.MatchString(pattern, currContent)

		if prevMatches && !currMatches {
			degradations = append(degradations, SecurityDegradation{
				Type:        "authentication_removed",
				Description: fmt.Sprintf("%s authentication appears to have been removed", authType),
				ChangedAt:   currTime,
				Severity:    "high",
			})
		}
	}

	return degradations
}

// Helper utility methods

func (a *ArchiveIntel) checkEndpointExists(url string) (bool, int) {
	resp, err := a.httpClient.Get(url)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()

	return resp.StatusCode < 500, resp.StatusCode
}

func (a *ArchiveIntel) guessEndpointFunction(url string) string {
	urlLower := strings.ToLower(url)

	functionMap := map[string]string{
		"admin":    "Administration panel",
		"api":      "API endpoint",
		"upload":   "File upload",
		"config":   "Configuration",
		"backup":   "Backup file",
		"test":     "Test endpoint",
		"debug":    "Debug interface",
		"console":  "Console access",
		"manage":   "Management interface",
		"internal": "Internal endpoint",
	}

	for keyword, function := range functionMap {
		if strings.Contains(urlLower, keyword) {
			return function
		}
	}

	return "Unknown"
}

func (a *ArchiveIntel) isInterestingParameter(param string) bool {
	// Filter out common uninteresting parameters
	boring := []string{"submit", "button", "csrf", "token", "_", "callback"}
	paramLower := strings.ToLower(param)

	for _, b := range boring {
		if paramLower == b {
			return false
		}
	}

	return len(param) > 2
}

func (a *ArchiveIntel) isValidURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	return u.Scheme != "" && u.Host != ""
}

func (a *ArchiveIntel) sanitizeCredential(cred string) string {
	// Partially mask credentials for safety
	if len(cred) > 10 {
		return cred[:5] + "..." + cred[len(cred)-5:]
	}
	return "***"
}

func (a *ArchiveIntel) getSnapshotContent(ctx context.Context, snapshot Snapshot) (string, error) {
	<-a.rateLimiter.C // Rate limiting

	for _, source := range a.sources {
		if source.Name() == snapshot.Source {
			return source.GetContent(ctx, snapshot.URL, snapshot.Timestamp)
		}
	}

	return "", fmt.Errorf("source not found: %s", snapshot.Source)
}

// Additional types for findings

type URLFinding struct {
	URL        string
	Type       string
	FirstSeen  time.Time
	Confidence float64
}

type APIDocFinding struct {
	Type       string
	Content    string
	Confidence float64
}

type CredentialFinding struct {
	Type       string
	Value      string
	Confidence float64
}

type TechStackChange struct {
	Technology string
	OldVersion string
	NewVersion string
	ChangedAt  time.Time
}

type SecurityDegradation struct {
	Type        string
	Description string
	ChangedAt   time.Time
	Severity    string
}

// analyzeTechnologyEvolution tracks technology changes over time
func (a *ArchiveIntel) analyzeTechnologyEvolution(ctx context.Context, snapshots []Snapshot, findings *ArchiveFindings) {
	// Track technology indicators over time
	techIndicators := map[string]string{
		"PHP":       `\.php|PHP/[0-9.]+`,
		"ASP.NET":   `\.aspx|ASP\.NET|X-AspNet-Version`,
		"Java":      `\.jsp|\.do|Java/[0-9.]+|Tomcat|JBoss`,
		"Python":    `wsgi|Django|Flask|Python/[0-9.]+`,
		"Ruby":      `\.rb|Ruby/[0-9.]+|Rails`,
		"Node.js":   `Express|Node\.js/[0-9.]+`,
		"WordPress": `wp-content|wp-includes|WordPress`,
		"Drupal":    `drupal|Drupal`,
		"Django":    `django|Django`,
	}

	techHistory := make(map[string][]time.Time)

	// Analyze each snapshot for technology indicators
	for _, snapshot := range snapshots {
		content, err := a.getSnapshotContent(ctx, snapshot)
		if err != nil {
			continue
		}

		for tech, pattern := range techIndicators {
			if matched, _ := regexp.MatchString(pattern, content); matched {
				techHistory[tech] = append(techHistory[tech], snapshot.Timestamp)
			}
		}
	}

	// Identify technology changes
	for tech, timestamps := range techHistory {
		if len(timestamps) > 0 {
			sort.Slice(timestamps, func(i, j int) bool {
				return timestamps[i].Before(timestamps[j])
			})

			// Check if technology was abandoned
			lastSeen := timestamps[len(timestamps)-1]
			if time.Since(lastSeen) > 180*24*time.Hour {
				findings.TechnologyEvolution = append(findings.TechnologyEvolution, TechStackChange{
					Technology: tech,
					OldVersion: "Present",
					NewVersion: "Removed",
					ChangedAt:  lastSeen,
				})
			}
		}
	}
}

// analyzeSecurityPosture analyzes security posture changes
func (a *ArchiveIntel) analyzeSecurityPosture(ctx context.Context, urlSnapshots map[string][]Snapshot, findings *ArchiveFindings) {
	// For each URL, analyze security posture over time
	for url, snapshots := range urlSnapshots {
		if len(snapshots) < 2 {
			continue
		}

		// Compare first and last snapshots
		first := snapshots[0]
		last := snapshots[len(snapshots)-1]

		firstContent, err1 := a.getSnapshotContent(ctx, first)
		lastContent, err2 := a.getSnapshotContent(ctx, last)

		if err1 != nil || err2 != nil {
			continue
		}

		// Check for HTTPS downgrade
		if strings.HasPrefix(first.URL, "https://") && strings.HasPrefix(last.URL, "http://") {
			findings.SecurityDegradation = append(findings.SecurityDegradation, SecurityChange{
				Type:        "https_downgrade",
				Description: fmt.Sprintf("Endpoint downgraded from HTTPS to HTTP: %s", url),
				ChangedAt:   last.Timestamp,
				Severity:    "high",
			})
		}

		// Check for authentication removal
		authKeywords := []string{"login", "signin", "authenticate", "oauth", "saml"}
		hadAuth := false
		hasAuth := false

		for _, keyword := range authKeywords {
			if strings.Contains(strings.ToLower(firstContent), keyword) {
				hadAuth = true
			}
			if strings.Contains(strings.ToLower(lastContent), keyword) {
				hasAuth = true
			}
		}

		if hadAuth && !hasAuth {
			findings.SecurityDegradation = append(findings.SecurityDegradation, SecurityChange{
				Type:        "authentication_removed",
				Description: fmt.Sprintf("Authentication appears to have been removed from: %s", url),
				ChangedAt:   last.Timestamp,
				Severity:    "critical",
			})
		}
	}
}
