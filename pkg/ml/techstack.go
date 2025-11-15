// pkg/ml/techstack.go
package ml

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

// TechStackAnalyzer performs adaptive scanning based on technology fingerprinting
type TechStackAnalyzer struct {
	fingerprints   map[string]*TechFingerprint
	scanStrategies map[string]*ScanStrategy
	httpClient     *http.Client
	cache          *TechStackCache
	config         AnalyzerConfig
	logger         *logger.Logger
	mu             sync.RWMutex
}

// AnalyzerConfig holds configuration for the tech stack analyzer
type AnalyzerConfig struct {
	FingerprintDB  string
	StrategyDB     string
	CacheSize      int
	CacheTTL       time.Duration
	MaxConcurrency int
	RequestTimeout time.Duration
	UserAgent      string
	UpdateInterval time.Duration
}

// TechFingerprint represents a technology fingerprint
type TechFingerprint struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Category        string              `json:"category"`
	Version         string              `json:"version,omitempty"`
	Headers         map[string]string   `json:"headers"`
	Cookies         map[string]string   `json:"cookies"`
	HTML            []string            `json:"html"`
	Scripts         []string            `json:"scripts"`
	Meta            map[string]string   `json:"meta"`
	Implies         []string            `json:"implies"`
	Excludes        []string            `json:"excludes"`
	Confidence      float64             `json:"confidence"`
	CVEs            []string            `json:"cves,omitempty"`
	Vulnerabilities []TechVulnerability `json:"vulnerabilities"`
}

// TechVulnerability represents known vulnerabilities for a technology
type TechVulnerability struct {
	Type        string   `json:"type"`
	Versions    []string `json:"versions"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	CVE         string   `json:"cve,omitempty"`
	Exploit     bool     `json:"exploit"`
}

// ScanStrategy represents an adaptive scanning strategy for a technology stack
type ScanStrategy struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Technologies    []string          `json:"technologies"`
	Priority        int               `json:"priority"`
	Scanners        []string          `json:"scanners"`
	SkipScanners    []string          `json:"skip_scanners"`
	CustomOptions   map[string]string `json:"custom_options"`
	RateLimits      RateLimitConfig   `json:"rate_limits"`
	TimeoutOverride time.Duration     `json:"timeout_override"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	RequestsPerSecond int           `json:"requests_per_second"`
	BurstSize         int           `json:"burst_size"`
	BackoffDuration   time.Duration `json:"backoff_duration"`
}

// TechStackResult represents the analysis result
type TechStackResult struct {
	Target          string                   `json:"target"`
	Technologies    []DetectedTechnology     `json:"technologies"`
	Strategy        *ScanStrategy            `json:"strategy"`
	Vulnerabilities []PotentialVulnerability `json:"vulnerabilities"`
	ScanPriority    []string                 `json:"scan_priority"`
	AnalyzedAt      time.Time                `json:"analyzed_at"`
}

// DetectedTechnology represents a detected technology
type DetectedTechnology struct {
	Name       string                 `json:"name"`
	Version    string                 `json:"version,omitempty"`
	Category   string                 `json:"category"`
	Confidence float64                `json:"confidence"`
	Evidence   []string               `json:"evidence"`
	CVEs       []string               `json:"cves,omitempty"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// PotentialVulnerability represents a potential vulnerability based on tech stack
type PotentialVulnerability struct {
	Technology  string   `json:"technology"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	CVE         string   `json:"cve,omitempty"`
	Versions    []string `json:"versions"`
	Exploitable bool     `json:"exploitable"`
}

// TechStackCache caches technology detection results
type TechStackCache struct {
	results map[string]*CachedResult
	mu      sync.RWMutex
	maxSize int
	ttl     time.Duration
}

// CachedResult represents a cached tech stack result
type CachedResult struct {
	Result    *TechStackResult
	ExpiresAt time.Time
}

// NewTechStackAnalyzer creates a new technology stack analyzer
func NewTechStackAnalyzer(config AnalyzerConfig, log *logger.Logger) (*TechStackAnalyzer, error) {
	analyzer := &TechStackAnalyzer{
		fingerprints:   make(map[string]*TechFingerprint),
		scanStrategies: make(map[string]*ScanStrategy),
		httpClient: &http.Client{
			Timeout: config.RequestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		cache:  newTechStackCache(config.CacheSize, config.CacheTTL),
		config: config,
		logger: log.WithComponent("techstack"),
	}

	// Load fingerprints and strategies
	if err := analyzer.loadFingerprints(config.FingerprintDB); err != nil {
		return nil, fmt.Errorf("failed to load fingerprints: %w", err)
	}

	if err := analyzer.loadStrategies(config.StrategyDB); err != nil {
		return nil, fmt.Errorf("failed to load strategies: %w", err)
	}

	// Start update routine
	go analyzer.updateDatabasesPeriodically()

	return analyzer, nil
}

// AnalyzeTechStack analyzes the technology stack of a target
func (tsa *TechStackAnalyzer) AnalyzeTechStack(ctx context.Context, target string) (*TechStackResult, error) {
	// Check cache first
	if cached := tsa.cache.get(target); cached != nil {
		return cached, nil
	}

	// Perform initial HTTP request
	resp, err := tsa.makeRequest(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze target: %w", err)
	}
	defer httpclient.CloseBody(resp)

	// Detect technologies
	technologies := tsa.detectTechnologies(resp)

	// Find matching scan strategy
	strategy := tsa.findBestStrategy(technologies)

	// Identify potential vulnerabilities
	vulnerabilities := tsa.identifyVulnerabilities(technologies)

	// Generate scan priority
	scanPriority := tsa.generateScanPriority(technologies, vulnerabilities)

	result := &TechStackResult{
		Target:          target,
		Technologies:    technologies,
		Strategy:        strategy,
		Vulnerabilities: vulnerabilities,
		ScanPriority:    scanPriority,
		AnalyzedAt:      time.Now(),
	}

	// Cache the result
	tsa.cache.set(target, result)

	return result, nil
}

// detectTechnologies detects technologies from HTTP response
func (tsa *TechStackAnalyzer) detectTechnologies(resp *http.Response) []DetectedTechnology {
	tsa.mu.RLock()
	defer tsa.mu.RUnlock()

	detected := make([]DetectedTechnology, 0)
	confidenceMap := make(map[string]*DetectedTechnology)

	// Read response body
	bodyBytes := make([]byte, 50000) // Read first 50KB
	n, _ := resp.Body.Read(bodyBytes)
	body := string(bodyBytes[:n])

	// Check each fingerprint
	for _, fingerprint := range tsa.fingerprints {
		confidence := 0.0
		evidence := make([]string, 0)

		// Check headers
		for header, pattern := range fingerprint.Headers {
			if value := resp.Header.Get(header); value != "" {
				if matched, _ := regexp.MatchString(pattern, value); matched {
					confidence += 0.3
					evidence = append(evidence, fmt.Sprintf("Header %s: %s", header, value))
				}
			}
		}

		// Check cookies
		for _, cookie := range resp.Cookies() {
			if pattern, exists := fingerprint.Cookies[cookie.Name]; exists {
				if matched, _ := regexp.MatchString(pattern, cookie.Value); matched {
					confidence += 0.2
					evidence = append(evidence, fmt.Sprintf("Cookie %s", cookie.Name))
				}
			}
		}

		// Check HTML patterns
		for _, htmlPattern := range fingerprint.HTML {
			if matched, _ := regexp.MatchString(htmlPattern, body); matched {
				confidence += 0.2
				evidence = append(evidence, fmt.Sprintf("HTML pattern: %s", htmlPattern))
			}
		}

		// Check script patterns
		for _, scriptPattern := range fingerprint.Scripts {
			if matched, _ := regexp.MatchString(scriptPattern, body); matched {
				confidence += 0.2
				evidence = append(evidence, fmt.Sprintf("Script pattern: %s", scriptPattern))
			}
		}

		// Check meta tags
		for metaName, pattern := range fingerprint.Meta {
			metaRegex := regexp.MustCompile(fmt.Sprintf(`<meta[^>]*name=["']%s["'][^>]*content=["']([^"']+)["']`, metaName))
			if matches := metaRegex.FindStringSubmatch(body); len(matches) > 1 {
				if matched, _ := regexp.MatchString(pattern, matches[1]); matched {
					confidence += 0.1
					evidence = append(evidence, fmt.Sprintf("Meta %s: %s", metaName, matches[1]))
				}
			}
		}

		// If confidence is high enough, add to detected technologies
		if confidence >= 0.3 {
			// Extract version if possible
			version := tsa.extractVersion(body, fingerprint)

			tech := &DetectedTechnology{
				Name:       fingerprint.Name,
				Version:    version,
				Category:   fingerprint.Category,
				Confidence: confidence,
				Evidence:   evidence,
				CVEs:       fingerprint.CVEs,
				Metadata:   make(map[string]interface{}),
			}

			// Check if we already detected this tech with lower confidence
			if existing, exists := confidenceMap[fingerprint.Name]; exists {
				if confidence > existing.Confidence {
					confidenceMap[fingerprint.Name] = tech
				}
			} else {
				confidenceMap[fingerprint.Name] = tech
			}
		}
	}

	// Convert map to slice
	for _, tech := range confidenceMap {
		detected = append(detected, *tech)
	}

	// Apply implies relationships
	detected = tsa.applyImplies(detected)

	// Remove excluded technologies
	detected = tsa.applyExcludes(detected)

	return detected
}

// findBestStrategy finds the best scanning strategy for detected technologies
func (tsa *TechStackAnalyzer) findBestStrategy(technologies []DetectedTechnology) *ScanStrategy {
	tsa.mu.RLock()
	defer tsa.mu.RUnlock()

	var bestStrategy *ScanStrategy
	bestScore := 0

	techNames := make([]string, len(technologies))
	for i, tech := range technologies {
		techNames[i] = strings.ToLower(tech.Name)
	}

	for _, strategy := range tsa.scanStrategies {
		score := 0

		// Calculate match score
		for _, requiredTech := range strategy.Technologies {
			for _, detectedTech := range techNames {
				if strings.Contains(detectedTech, strings.ToLower(requiredTech)) {
					score++
				}
			}
		}

		// Add priority to score
		score += strategy.Priority

		if score > bestScore {
			bestScore = score
			bestStrategy = strategy
		}
	}

	return bestStrategy
}

// identifyVulnerabilities identifies potential vulnerabilities based on tech stack
func (tsa *TechStackAnalyzer) identifyVulnerabilities(technologies []DetectedTechnology) []PotentialVulnerability {
	vulnerabilities := make([]PotentialVulnerability, 0)

	for _, tech := range technologies {
		// Get fingerprint for detailed vulnerability info
		tsa.mu.RLock()
		fingerprint, exists := tsa.fingerprints[tech.Name]
		tsa.mu.RUnlock()

		if !exists {
			continue
		}

		// Check version-specific vulnerabilities
		for _, vuln := range fingerprint.Vulnerabilities {
			if tsa.versionMatches(tech.Version, vuln.Versions) {
				vulnerabilities = append(vulnerabilities, PotentialVulnerability{
					Technology:  tech.Name,
					Type:        vuln.Type,
					Description: vuln.Description,
					Severity:    vuln.Severity,
					CVE:         vuln.CVE,
					Versions:    vuln.Versions,
					Exploitable: vuln.Exploit,
				})
			}
		}

		// Add CVEs if present
		for _, cve := range tech.CVEs {
			vulnerabilities = append(vulnerabilities, PotentialVulnerability{
				Technology:  tech.Name,
				Type:        "CVE",
				Description: fmt.Sprintf("Known vulnerability: %s", cve),
				Severity:    "HIGH",
				CVE:         cve,
				Exploitable: true,
			})
		}
	}

	return vulnerabilities
}

// generateScanPriority generates prioritized list of scans based on tech stack
func (tsa *TechStackAnalyzer) generateScanPriority(technologies []DetectedTechnology, vulnerabilities []PotentialVulnerability) []string {
	scanMap := make(map[string]int)

	// Technology-based scan recommendations
	techToScans := map[string][]string{
		"wordpress":        {"wpscan", "nuclei-wordpress"},
		"drupal":           {"droopescan", "nuclei-drupal"},
		"joomla":           {"joomscan", "nuclei-joomla"},
		"apache":           {"nikto", "nuclei-apache"},
		"nginx":            {"nuclei-nginx"},
		"php":              {"phpinfo-finder", "nuclei-php"},
		"asp.net":          {"nuclei-aspnet"},
		"jenkins":          {"jenkins-scan", "nuclei-jenkins"},
		"gitlab":           {"nuclei-gitlab"},
		"graphql":          {"graphql-cop", "nuclei-graphql"},
		"wordpress-plugin": {"wpscan-aggressive"},
		"jquery":           {"retire-js", "nuclei-js"},
		"angular":          {"retire-js", "nuclei-angular"},
		"react":            {"nuclei-react"},
		"node.js":          {"npm-audit", "nuclei-nodejs"},
	}

	// Add scans based on detected technologies
	for _, tech := range technologies {
		techLower := strings.ToLower(tech.Name)
		if scans, exists := techToScans[techLower]; exists {
			for _, scan := range scans {
				scanMap[scan] += int(tech.Confidence * 10)
			}
		}

		// Add category-based scans
		switch tech.Category {
		case "cms":
			scanMap["nuclei-cms"] += 5
		case "database":
			scanMap["nuclei-database"] += 5
		case "webserver":
			scanMap["nikto"] += 3
		case "javascript":
			scanMap["retire-js"] += 4
		}
	}

	// Add scans based on vulnerabilities
	vulnToScans := map[string][]string{
		"sql_injection": {"sqlmap", "nuclei-sqli"},
		"xss":           {"xsstrike", "nuclei-xss"},
		"xxe":           {"xxe-scan", "nuclei-xxe"},
		"ssrf":          {"ssrfmap", "nuclei-ssrf"},
		"rce":           {"nuclei-rce"},
		"lfi":           {"nuclei-lfi"},
	}

	for _, vuln := range vulnerabilities {
		vulnType := strings.ToLower(vuln.Type)
		if scans, exists := vulnToScans[vulnType]; exists {
			priority := 10
			if vuln.Severity == "CRITICAL" {
				priority = 20
			} else if vuln.Severity == "HIGH" {
				priority = 15
			}

			for _, scan := range scans {
				scanMap[scan] += priority
			}
		}
	}

	// Sort scans by priority
	return sortScansByScore(scanMap)
}

// Helper methods

func (tsa *TechStackAnalyzer) extractVersion(body string, fingerprint *TechFingerprint) string {
	// Common version patterns
	versionPatterns := []string{
		fmt.Sprintf(`%s[\/\s]+v?(\d+\.?\d*\.?\d*)`, fingerprint.Name),
		fmt.Sprintf(`version[:\s]+(\d+\.?\d*\.?\d*)`),
		fmt.Sprintf(`v(\d+\.?\d*\.?\d*)`),
	}

	for _, pattern := range versionPatterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(body); len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

func (tsa *TechStackAnalyzer) versionMatches(detectedVersion string, vulnerableVersions []string) bool {
	if detectedVersion == "" {
		return true // If we can't detect version, assume vulnerable
	}

	for _, vulnVersion := range vulnerableVersions {
		if strings.Contains(vulnVersion, "*") {
			// Handle wildcard versions like "2.*"
			prefix := strings.TrimSuffix(vulnVersion, "*")
			if strings.HasPrefix(detectedVersion, prefix) {
				return true
			}
		} else if strings.Contains(vulnVersion, "-") {
			// Handle version ranges like "2.0-2.5"
			parts := strings.Split(vulnVersion, "-")
			if len(parts) == 2 {
				if detectedVersion >= parts[0] && detectedVersion <= parts[1] {
					return true
				}
			}
		} else if detectedVersion == vulnVersion {
			return true
		}
	}

	return false
}

func (tsa *TechStackAnalyzer) applyImplies(technologies []DetectedTechnology) []DetectedTechnology {
	// Apply implies relationships
	techMap := make(map[string]bool)
	for _, tech := range technologies {
		techMap[tech.Name] = true
	}

	for _, tech := range technologies {
		tsa.mu.RLock()
		fingerprint, exists := tsa.fingerprints[tech.Name]
		tsa.mu.RUnlock()

		if exists {
			for _, implied := range fingerprint.Implies {
				if !techMap[implied] {
					if impliedFP, exists := tsa.fingerprints[implied]; exists {
						technologies = append(technologies, DetectedTechnology{
							Name:       implied,
							Category:   impliedFP.Category,
							Confidence: tech.Confidence * 0.8, // Slightly lower confidence for implied tech
							Evidence:   []string{fmt.Sprintf("Implied by %s", tech.Name)},
						})
						techMap[implied] = true
					}
				}
			}
		}
	}

	return technologies
}

func (tsa *TechStackAnalyzer) applyExcludes(technologies []DetectedTechnology) []DetectedTechnology {
	// Remove excluded technologies
	excludeMap := make(map[string]bool)

	for _, tech := range technologies {
		tsa.mu.RLock()
		fingerprint, exists := tsa.fingerprints[tech.Name]
		tsa.mu.RUnlock()

		if exists {
			for _, excluded := range fingerprint.Excludes {
				excludeMap[excluded] = true
			}
		}
	}

	filtered := make([]DetectedTechnology, 0)
	for _, tech := range technologies {
		if !excludeMap[tech.Name] {
			filtered = append(filtered, tech)
		}
	}

	return filtered
}

// Cache implementation

func newTechStackCache(maxSize int, ttl time.Duration) *TechStackCache {
	cache := &TechStackCache{
		results: make(map[string]*CachedResult),
		maxSize: maxSize,
		ttl:     ttl,
	}

	// Start cleanup routine
	go cache.cleanup()

	return cache
}

func (c *TechStackCache) get(target string) *TechStackResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if cached, exists := c.results[target]; exists {
		if time.Now().Before(cached.ExpiresAt) {
			return cached.Result
		}
	}

	return nil
}

func (c *TechStackCache) set(target string, result *TechStackResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Implement simple LRU eviction if cache is full
	if len(c.results) >= c.maxSize {
		// Remove oldest entry
		var oldestKey string
		var oldestTime time.Time

		for key, cached := range c.results {
			if oldestTime.IsZero() || cached.ExpiresAt.Before(oldestTime) {
				oldestKey = key
				oldestTime = cached.ExpiresAt
			}
		}

		delete(c.results, oldestKey)
	}

	c.results[target] = &CachedResult{
		Result:    result,
		ExpiresAt: time.Now().Add(c.ttl),
	}
}

func (c *TechStackCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, cached := range c.results {
			if now.After(cached.ExpiresAt) {
				delete(c.results, key)
			}
		}
		c.mu.Unlock()
	}
}

// loadFingerprints loads technology fingerprints from database
func (tsa *TechStackAnalyzer) loadFingerprints(dbPath string) error {
	// In a real implementation, this would load from a JSON file or database
	// For now, we'll initialize with some common fingerprints

	tsa.mu.Lock()
	defer tsa.mu.Unlock()

	// WordPress fingerprint
	tsa.fingerprints["WordPress"] = &TechFingerprint{
		ID:       "wordpress",
		Name:     "WordPress",
		Category: "cms",
		Headers: map[string]string{
			"X-Powered-By": "W3 Total Cache",
		},
		HTML: []string{
			`<meta name="generator" content="WordPress`,
			`/wp-content/`,
			`/wp-includes/`,
		},
		Scripts: []string{
			`/wp-includes/js/`,
			`/wp-content/plugins/`,
		},
		Meta: map[string]string{
			"generator": "WordPress",
		},
		Implies: []string{"PHP", "MySQL"},
	}

	// Add more fingerprints as needed
	tsa.logger.Infow("Loaded technology fingerprints", "count", len(tsa.fingerprints))
	return nil
}

// loadStrategies loads scanning strategies from database
func (tsa *TechStackAnalyzer) loadStrategies(dbPath string) error {
	// In a real implementation, this would load from a JSON file or database
	// For now, we'll initialize with some common strategies

	tsa.mu.Lock()
	defer tsa.mu.Unlock()

	// WordPress strategy
	tsa.scanStrategies["wordpress"] = &ScanStrategy{
		ID:           "wordpress-strategy",
		Name:         "WordPress Security Scan",
		Technologies: []string{"WordPress"},
		Priority:     10,
		Scanners:     []string{"wpscan", "nuclei-wordpress"},
		SkipScanners: []string{"sqlmap"}, // WP has its own SQL handling
		CustomOptions: map[string]string{
			"enumerate": "vap,vt,tt,cb,dbe,u,m",
		},
	}

	tsa.logger.Infow("Loaded scan strategies", "count", len(tsa.scanStrategies))
	return nil
}

// makeRequest performs HTTP request to the target
func (tsa *TechStackAnalyzer) makeRequest(ctx context.Context, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", tsa.config.UserAgent)

	tsa.logger.Debugw("Making HTTP request", "target", target)
	resp, err := tsa.httpClient.Do(req)
	if err != nil {
		tsa.logger.Errorw("HTTP request failed", "target", target, "error", err)
		return nil, err
	}

	// Read and buffer the body so it can be read multiple times
	bodyBytes, err := io.ReadAll(resp.Body)
	httpclient.CloseBody(resp)
	if err != nil {
		return nil, err
	}

	// Create a new ReadCloser from the buffered body
	resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

	return resp, nil
}

// updateDatabasesPeriodically updates fingerprint and strategy databases
func (tsa *TechStackAnalyzer) updateDatabasesPeriodically() {
	if tsa.config.UpdateInterval == 0 {
		return // No updates if interval is 0
	}

	ticker := time.NewTicker(tsa.config.UpdateInterval)
	defer ticker.Stop()

	for range ticker.C {
		tsa.logger.Infow("Updating fingerprint databases")

		// Reload fingerprints
		if err := tsa.loadFingerprints(tsa.config.FingerprintDB); err != nil {
			tsa.logger.Errorw("Failed to update fingerprints", "error", err)
		}

		// Reload strategies
		if err := tsa.loadStrategies(tsa.config.StrategyDB); err != nil {
			tsa.logger.Errorw("Failed to update strategies", "error", err)
		}
	}
}

// sortScansByScore sorts scans by their priority score
func sortScansByScore(scanMap map[string]int) []string {
	type scanScore struct {
		scan  string
		score int
	}

	scores := make([]scanScore, 0, len(scanMap))
	for scan, score := range scanMap {
		scores = append(scores, scanScore{scan, score})
	}

	// Sort by score descending
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].score > scores[j].score
	})

	// Extract scan names
	result := make([]string, len(scores))
	for i, ss := range scores {
		result[i] = ss.scan
	}

	return result
}
