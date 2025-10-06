// pkg/ml/programrules.go
package ml

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ProgramRules validates targets against bug bounty program scopes
type ProgramRules struct {
	programs      map[string]*BugBountyProgram
	scopeCache    *ScopeCache
	platformAPIs  map[string]PlatformAPI
	ipResolver    *IPResolver
	domainMatcher *DomainMatcher
	config        ProgramRulesConfig
	logger        interface {
		Errorw(msg string, keysAndValues ...interface{})
	} // Optional logger for structured logging
	mu sync.RWMutex
}

// ProgramRulesConfig holds configuration for program rules
type ProgramRulesConfig struct {
	ProgramsDB      string
	UpdateInterval  time.Duration
	CacheSize       int
	CacheTTL        time.Duration
	StrictMode      bool
	AutoUpdate      bool
	PlatformConfigs map[string]PlatformConfig
}

// PlatformConfig holds platform-specific configuration
type PlatformConfig struct {
	APIKey      string
	APIEndpoint string
	RateLimit   int
}

// BugBountyProgram represents a bug bounty program
type BugBountyProgram struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Platform     string            `json:"platform"`
	InScope      []ScopeItem       `json:"in_scope"`
	OutOfScope   []ScopeItem       `json:"out_of_scope"`
	Rules        []ProgramRule     `json:"rules"`
	Severity     SeverityRules     `json:"severity"`
	RateLimit    RateLimitRules    `json:"rate_limit"`
	RequiresVPN  bool              `json:"requires_vpn"`
	TestAccounts []TestAccount     `json:"test_accounts"`
	UpdatedAt    time.Time         `json:"updated_at"`
	Metadata     map[string]string `json:"metadata"`
}

// ScopeItem represents an in-scope or out-of-scope item
type ScopeItem struct {
	Type           string   `json:"type"` // domain, ip, url, mobile_app, api
	Target         string   `json:"target"`
	Severity       string   `json:"severity"`
	Description    string   `json:"description"`
	Wildcards      bool     `json:"wildcards"`
	Ports          []int    `json:"ports,omitempty"`
	AllowedMethods []string `json:"allowed_methods,omitempty"`
	ExcludedPaths  []string `json:"excluded_paths,omitempty"`
}

// ProgramRule represents a specific rule for the program
type ProgramRule struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	Description string          `json:"description"`
	Enforcement string          `json:"enforcement"` // strict, warning, info
	Conditions  []RuleCondition `json:"conditions"`
}

// RuleCondition represents a condition for a rule
type RuleCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// SeverityRules defines severity calculations for the program
type SeverityRules struct {
	Critical []string          `json:"critical"`
	High     []string          `json:"high"`
	Medium   []string          `json:"medium"`
	Low      []string          `json:"low"`
	Payouts  map[string]Payout `json:"payouts"`
}

// Payout represents payout information
type Payout struct {
	Min      float64 `json:"min"`
	Max      float64 `json:"max"`
	Average  float64 `json:"average"`
	Currency string  `json:"currency"`
}

// RateLimitRules defines rate limiting rules
type RateLimitRules struct {
	RequestsPerMinute int `json:"requests_per_minute"`
	RequestsPerHour   int `json:"requests_per_hour"`
	BurstSize         int `json:"burst_size"`
	BackoffMinutes    int `json:"backoff_minutes"`
}

// TestAccount represents provided test accounts
type TestAccount struct {
	Type        string            `json:"type"`
	Credentials map[string]string `json:"credentials"`
	Permissions []string          `json:"permissions"`
	Notes       string            `json:"notes"`
}

// ValidationResult represents the result of scope validation
type ValidationResult struct {
	Target           string          `json:"target"`
	Program          string          `json:"program"`
	InScope          bool            `json:"in_scope"`
	ScopeItem        *ScopeItem      `json:"scope_item,omitempty"`
	OutOfScopeReason string          `json:"out_of_scope_reason,omitempty"`
	Warnings         []string        `json:"warnings"`
	Rules            []RuleViolation `json:"rule_violations"`
	Severity         string          `json:"severity"`
	EstimatedPayout  *Payout         `json:"estimated_payout,omitempty"`
	RateLimit        *RateLimitRules `json:"rate_limit,omitempty"`
	TestAccounts     []TestAccount   `json:"test_accounts,omitempty"`
	Recommendations  []string        `json:"recommendations"`
}

// RuleViolation represents a violated program rule
type RuleViolation struct {
	Rule        ProgramRule `json:"rule"`
	Violated    bool        `json:"violated"`
	Message     string      `json:"message"`
	Enforcement string      `json:"enforcement"`
}

// PlatformAPI interface for bug bounty platform APIs
type PlatformAPI interface {
	GetProgram(programID string) (*BugBountyProgram, error)
	ListPrograms() ([]*BugBountyProgram, error)
	GetProgramByDomain(domain string) (*BugBountyProgram, error)
	ReportFinding(programID string, finding interface{}) error
}

// ScopeCache caches scope validation results
type ScopeCache struct {
	validations map[string]*CachedValidation
	mu          sync.RWMutex
	maxSize     int
	ttl         time.Duration
}

// CachedValidation represents a cached validation result
type CachedValidation struct {
	Result    *ValidationResult
	ExpiresAt time.Time
}

// IPResolver resolves domains to IPs and vice versa
type IPResolver struct {
	cache map[string][]string
	mu    sync.RWMutex
}

// DomainMatcher matches domains with wildcard support
type DomainMatcher struct {
	patterns map[string]*regexp.Regexp
	mu       sync.RWMutex
}

// NewProgramRules creates a new program rules validator
func NewProgramRules(config ProgramRulesConfig) (*ProgramRules, error) {
	pr := &ProgramRules{
		programs:      make(map[string]*BugBountyProgram),
		scopeCache:    newScopeCache(config.CacheSize, config.CacheTTL),
		platformAPIs:  make(map[string]PlatformAPI),
		ipResolver:    newIPResolver(),
		domainMatcher: newDomainMatcher(),
		config:        config,
	}

	// Initialize platform APIs
	for platform, platformConfig := range config.PlatformConfigs {
		api, err := createPlatformAPI(platform, platformConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create %s API: %w", platform, err)
		}
		pr.platformAPIs[platform] = api
	}

	// Load programs from database
	if err := pr.loadPrograms(config.ProgramsDB); err != nil {
		return nil, fmt.Errorf("failed to load programs: %w", err)
	}

	// Start auto-update routine if enabled
	if config.AutoUpdate {
		go pr.updateProgramsPeriodically()
	}

	return pr, nil
}

// ValidateTarget validates if a target is in scope for a program
func (pr *ProgramRules) ValidateTarget(ctx context.Context, target string, programID string) (*ValidationResult, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("%s:%s", programID, target)
	if cached := pr.scopeCache.get(cacheKey); cached != nil {
		return cached, nil
	}

	// Get program
	pr.mu.RLock()
	program, exists := pr.programs[programID]
	pr.mu.RUnlock()

	if !exists {
		// Try to fetch from platform API
		program, err := pr.fetchProgramFromAPI(programID)
		if err != nil {
			return nil, fmt.Errorf("program not found: %s", programID)
		}

		pr.mu.Lock()
		pr.programs[programID] = program
		pr.mu.Unlock()
	}

	// Validate target
	result := pr.validateTargetAgainstProgram(ctx, target, program)

	// Cache result
	pr.scopeCache.set(cacheKey, result)

	return result, nil
}

// FindProgramsForTarget finds all programs where the target is in scope
func (pr *ProgramRules) FindProgramsForTarget(ctx context.Context, target string) ([]*ValidationResult, error) {
	results := make([]*ValidationResult, 0)

	pr.mu.RLock()
	programs := make([]*BugBountyProgram, 0, len(pr.programs))
	for _, program := range pr.programs {
		programs = append(programs, program)
	}
	pr.mu.RUnlock()

	// Check target against all programs
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, 10) // Limit concurrent validations

	for _, program := range programs {
		wg.Add(1)
		go func(p *BugBountyProgram) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := pr.validateTargetAgainstProgram(ctx, target, p)
			if result.InScope {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(program)
	}

	wg.Wait()

	// Sort by estimated payout (highest first)
	sortResultsByPayout(results)

	return results, nil
}

// validateTargetAgainstProgram validates a target against a specific program
func (pr *ProgramRules) validateTargetAgainstProgram(ctx context.Context, target string, program *BugBountyProgram) *ValidationResult {
	result := &ValidationResult{
		Target:          target,
		Program:         program.Name,
		InScope:         false,
		Warnings:        make([]string, 0),
		Rules:           make([]RuleViolation, 0),
		Recommendations: make([]string, 0),
	}

	// Parse target
	targetURL, err := url.Parse(target)
	if err != nil {
		// Might be a domain or IP
		if net.ParseIP(target) != nil {
			targetURL = &url.URL{Host: target}
		} else {
			targetURL = &url.URL{Host: target, Scheme: "https"}
		}
	}

	// Check out of scope first
	for _, outScope := range program.OutOfScope {
		if pr.matchesScope(targetURL, &outScope) {
			result.OutOfScopeReason = fmt.Sprintf("Matches out-of-scope item: %s", outScope.Description)
			return result
		}
	}

	// Check in scope
	var matchedScope *ScopeItem
	for _, inScope := range program.InScope {
		if pr.matchesScope(targetURL, &inScope) {
			result.InScope = true
			matchedScope = &inScope
			result.ScopeItem = matchedScope
			break
		}
	}

	if !result.InScope {
		result.OutOfScopeReason = "No matching in-scope items"
		return result
	}

	// Validate against program rules
	for _, rule := range program.Rules {
		violation := pr.evaluateRule(targetURL, &rule)
		if violation.Violated {
			result.Rules = append(result.Rules, violation)

			switch rule.Enforcement {
			case "strict":
				result.InScope = false
				result.OutOfScopeReason = fmt.Sprintf("Violates strict rule: %s", rule.Description)
			case "warning":
				result.Warnings = append(result.Warnings, violation.Message)
			}
		}
	}

	// Set severity and payout information
	if matchedScope != nil {
		result.Severity = matchedScope.Severity
		if payout, exists := program.Severity.Payouts[matchedScope.Severity]; exists {
			result.EstimatedPayout = &payout
		}
	}

	// Add rate limits
	result.RateLimit = &program.RateLimit

	// Add test accounts if relevant
	if len(program.TestAccounts) > 0 {
		result.TestAccounts = program.TestAccounts
	}

	// Generate recommendations
	result.Recommendations = pr.generateRecommendations(targetURL, program, matchedScope)

	return result
}

// matchesScope checks if a target matches a scope item
func (pr *ProgramRules) matchesScope(targetURL *url.URL, scope *ScopeItem) bool {
	switch scope.Type {
	case "domain":
		return pr.matchesDomain(targetURL.Host, scope.Target, scope.Wildcards)
	case "ip":
		return pr.matchesIP(targetURL.Host, scope.Target)
	case "url":
		return pr.matchesURL(targetURL.String(), scope.Target)
	case "api":
		return pr.matchesAPI(targetURL, scope.Target)
	default:
		return false
	}
}

// matchesDomain checks if a domain matches with wildcard support
func (pr *ProgramRules) matchesDomain(targetDomain, scopeDomain string, wildcard bool) bool {
	targetDomain = strings.ToLower(strings.TrimPrefix(targetDomain, "www."))
	scopeDomain = strings.ToLower(strings.TrimPrefix(scopeDomain, "www."))

	if wildcard && strings.HasPrefix(scopeDomain, "*.") {
		baseDomain := strings.TrimPrefix(scopeDomain, "*.")
		return targetDomain == baseDomain || strings.HasSuffix(targetDomain, "."+baseDomain)
	}

	return targetDomain == scopeDomain
}

// matchesIP checks if an IP matches
func (pr *ProgramRules) matchesIP(targetHost, scopeIP string) bool {
	// Check if target is IP
	targetIP := net.ParseIP(targetHost)
	if targetIP == nil {
		// Try to resolve domain to IP
		ips, err := net.LookupIP(targetHost)
		if err != nil || len(ips) == 0 {
			return false
		}
		targetIP = ips[0]
	}

	// Check if scope is CIDR
	if strings.Contains(scopeIP, "/") {
		_, ipNet, err := net.ParseCIDR(scopeIP)
		if err != nil {
			return false
		}
		return ipNet.Contains(targetIP)
	}

	// Direct IP match
	scopeIPParsed := net.ParseIP(scopeIP)
	return scopeIPParsed != nil && targetIP.Equal(scopeIPParsed)
}

// matchesURL checks if a URL matches
func (pr *ProgramRules) matchesURL(targetURL, scopeURL string) bool {
	// Normalize URLs
	targetURL = strings.TrimSuffix(targetURL, "/")
	scopeURL = strings.TrimSuffix(scopeURL, "/")

	// Check for wildcard in path
	if strings.Contains(scopeURL, "*") {
		pattern := strings.ReplaceAll(scopeURL, "*", ".*")
		matched, _ := regexp.MatchString("^"+pattern+"$", targetURL)
		return matched
	}

	return strings.HasPrefix(targetURL, scopeURL)
}

// matchesAPI checks if target matches API scope
func (pr *ProgramRules) matchesAPI(targetURL *url.URL, scopeAPI string) bool {
	// Check if target has API indicators
	apiIndicators := []string{"/api/", "/v1/", "/v2/", "/graphql", "/rest/"}

	for _, indicator := range apiIndicators {
		if strings.Contains(targetURL.Path, indicator) {
			return pr.matchesDomain(targetURL.Host, scopeAPI, true)
		}
	}

	return false
}

// evaluateRule evaluates a program rule
func (pr *ProgramRules) evaluateRule(targetURL *url.URL, rule *ProgramRule) RuleViolation {
	violation := RuleViolation{
		Rule:        *rule,
		Violated:    false,
		Enforcement: rule.Enforcement,
	}

	// Evaluate all conditions
	allConditionsMet := true
	for _, condition := range rule.Conditions {
		if !pr.evaluateCondition(targetURL, condition) {
			allConditionsMet = false
			break
		}
	}

	if allConditionsMet {
		violation.Violated = true
		violation.Message = fmt.Sprintf("Rule violated: %s", rule.Description)
	}

	return violation
}

// evaluateCondition evaluates a single rule condition
func (pr *ProgramRules) evaluateCondition(targetURL *url.URL, condition RuleCondition) bool {
	var fieldValue interface{}

	// Extract field value
	switch condition.Field {
	case "port":
		port := targetURL.Port()
		if port == "" {
			if targetURL.Scheme == "https" {
				fieldValue = 443
			} else {
				fieldValue = 80
			}
		} else {
			fieldValue = port
		}
	case "path":
		fieldValue = targetURL.Path
	case "scheme":
		fieldValue = targetURL.Scheme
	case "host":
		fieldValue = targetURL.Host
	case "query":
		fieldValue = targetURL.RawQuery
	default:
		return false
	}

	// Evaluate operator
	switch condition.Operator {
	case "equals":
		return fieldValue == condition.Value
	case "not_equals":
		return fieldValue != condition.Value
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", fieldValue), fmt.Sprintf("%v", condition.Value))
	case "not_contains":
		return !strings.Contains(fmt.Sprintf("%v", fieldValue), fmt.Sprintf("%v", condition.Value))
	case "matches":
		pattern := fmt.Sprintf("%v", condition.Value)
		matched, _ := regexp.MatchString(pattern, fmt.Sprintf("%v", fieldValue))
		return matched
	case "in":
		if values, ok := condition.Value.([]interface{}); ok {
			for _, v := range values {
				if fmt.Sprintf("%v", fieldValue) == fmt.Sprintf("%v", v) {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}

// generateRecommendations generates scanning recommendations
func (pr *ProgramRules) generateRecommendations(targetURL *url.URL, program *BugBountyProgram, scope *ScopeItem) []string {
	recommendations := make([]string, 0)

	// Port-based recommendations
	if scope != nil && len(scope.Ports) > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Focus on allowed ports: %v", scope.Ports))
	}

	// Method-based recommendations
	if scope != nil && len(scope.AllowedMethods) > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Only test HTTP methods: %v", scope.AllowedMethods))
	}

	// Path exclusions
	if scope != nil && len(scope.ExcludedPaths) > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Avoid testing paths: %v", scope.ExcludedPaths))
	}

	// Rate limiting recommendations
	if program.RateLimit.RequestsPerMinute > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Limit requests to %d per minute", program.RateLimit.RequestsPerMinute))
	}

	// VPN requirements
	if program.RequiresVPN {
		recommendations = append(recommendations, "VPN connection required for testing")
	}

	// Severity-based recommendations
	if scope != nil {
		switch scope.Severity {
		case "critical":
			recommendations = append(recommendations, "Focus on authentication bypass, RCE, and data exposure")
		case "high":
			recommendations = append(recommendations, "Look for SQL injection, XSS, and privilege escalation")
		case "medium":
			recommendations = append(recommendations, "Test for CSRF, open redirects, and information disclosure")
		}
	}

	return recommendations
}

// updateProgramsPeriodically updates programs from platform APIs
func (pr *ProgramRules) updateProgramsPeriodically() {
	ticker := time.NewTicker(pr.config.UpdateInterval)
	defer ticker.Stop()

	for range ticker.C {
		pr.updatePrograms()
	}
}

// updatePrograms updates all programs from platform APIs
func (pr *ProgramRules) updatePrograms() {
	for platform, api := range pr.platformAPIs {
		programs, err := api.ListPrograms()
		if err != nil {
			// Structured logging with otelzap (if logger configured)
			if pr.logger != nil {
				pr.logger.Errorw("Failed to update bug bounty programs from platform",
					"error", err,
					"platform", platform,
					"operation", "program_update",
					"component", "program_rules",
				)
			}
			continue
		}

		pr.mu.Lock()
		for _, program := range programs {
			pr.programs[program.ID] = program
		}
		pr.mu.Unlock()
	}
}

// fetchProgramFromAPI fetches a program from platform APIs
func (pr *ProgramRules) fetchProgramFromAPI(programID string) (*BugBountyProgram, error) {
	for _, api := range pr.platformAPIs {
		program, err := api.GetProgram(programID)
		if err == nil && program != nil {
			return program, nil
		}
	}
	return nil, fmt.Errorf("program not found in any platform")
}

// loadPrograms loads programs from database
func (pr *ProgramRules) loadPrograms(dbPath string) error {
	// In a real implementation, this would load from a database
	// For now, we'll create some example programs

	examplePrograms := []*BugBountyProgram{
		{
			ID:       "example-corp",
			Name:     "Example Corporation",
			Platform: "hackerone",
			InScope: []ScopeItem{
				{
					Type:        "domain",
					Target:      "*.example.com",
					Severity:    "high",
					Wildcards:   true,
					Description: "All subdomains of example.com",
				},
				{
					Type:        "ip",
					Target:      "192.168.1.0/24",
					Severity:    "medium",
					Description: "Corporate IP range",
				},
			},
			OutOfScope: []ScopeItem{
				{
					Type:        "domain",
					Target:      "blog.example.com",
					Description: "Third-party hosted blog",
				},
			},
			Rules: []ProgramRule{
				{
					ID:          "no-dos",
					Type:        "dos",
					Description: "No denial of service testing",
					Enforcement: "strict",
					Conditions: []RuleCondition{
						{
							Field:    "path",
							Operator: "contains",
							Value:    "/api/bulk",
						},
					},
				},
			},
			Severity: SeverityRules{
				Critical: []string{"RCE", "Authentication Bypass", "SQL Injection"},
				High:     []string{"XSS", "SSRF", "XXE"},
				Medium:   []string{"CSRF", "Open Redirect"},
				Low:      []string{"Information Disclosure", "Missing Headers"},
				Payouts: map[string]Payout{
					"critical": {Min: 1000, Max: 10000, Average: 5000, Currency: "USD"},
					"high":     {Min: 500, Max: 5000, Average: 2000, Currency: "USD"},
					"medium":   {Min: 100, Max: 1000, Average: 500, Currency: "USD"},
					"low":      {Min: 50, Max: 500, Average: 200, Currency: "USD"},
				},
			},
			RateLimit: RateLimitRules{
				RequestsPerMinute: 60,
				RequestsPerHour:   3600,
				BurstSize:         100,
				BackoffMinutes:    5,
			},
			RequiresVPN: false,
			TestAccounts: []TestAccount{
				{
					Type: "web",
					Credentials: map[string]string{
						"username": "testuser",
						"password": "testpass123",
					},
					Permissions: []string{"read", "write"},
					Notes:       "Standard test account with limited permissions",
				},
			},
			UpdatedAt: time.Now(),
		},
	}

	pr.mu.Lock()
	for _, program := range examplePrograms {
		pr.programs[program.ID] = program
	}
	pr.mu.Unlock()

	return nil
}

// Helper functions

func newScopeCache(maxSize int, ttl time.Duration) *ScopeCache {
	cache := &ScopeCache{
		validations: make(map[string]*CachedValidation),
		maxSize:     maxSize,
		ttl:         ttl,
	}

	go cache.cleanup()
	return cache
}

func (c *ScopeCache) get(key string) *ValidationResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if cached, exists := c.validations[key]; exists {
		if time.Now().Before(cached.ExpiresAt) {
			return cached.Result
		}
	}
	return nil
}

func (c *ScopeCache) set(key string, result *ValidationResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.validations) >= c.maxSize {
		// Simple eviction - remove first item found
		for k := range c.validations {
			delete(c.validations, k)
			break
		}
	}

	c.validations[key] = &CachedValidation{
		Result:    result,
		ExpiresAt: time.Now().Add(c.ttl),
	}
}

func (c *ScopeCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, cached := range c.validations {
			if now.After(cached.ExpiresAt) {
				delete(c.validations, key)
			}
		}
		c.mu.Unlock()
	}
}

func newIPResolver() *IPResolver {
	return &IPResolver{
		cache: make(map[string][]string),
	}
}

func newDomainMatcher() *DomainMatcher {
	return &DomainMatcher{
		patterns: make(map[string]*regexp.Regexp),
	}
}

func createPlatformAPI(platform string, config PlatformConfig) (PlatformAPI, error) {
	// In a real implementation, this would create actual platform API clients
	// For now, return a mock implementation
	return &MockPlatformAPI{platform: platform}, nil
}

// MockPlatformAPI is a mock implementation for testing
type MockPlatformAPI struct {
	platform string
}

func (m *MockPlatformAPI) GetProgram(programID string) (*BugBountyProgram, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockPlatformAPI) ListPrograms() ([]*BugBountyProgram, error) {
	return []*BugBountyProgram{}, nil
}

func (m *MockPlatformAPI) GetProgramByDomain(domain string) (*BugBountyProgram, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockPlatformAPI) ReportFinding(programID string, finding interface{}) error {
	return fmt.Errorf("not implemented")
}

func sortResultsByPayout(results []*ValidationResult) {
	// Sort by estimated payout (highest first)
	for i := 0; i < len(results)-1; i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i].EstimatedPayout != nil && results[j].EstimatedPayout != nil {
				if results[i].EstimatedPayout.Average < results[j].EstimatedPayout.Average {
					results[i], results[j] = results[j], results[i]
				}
			}
		}
	}
}
