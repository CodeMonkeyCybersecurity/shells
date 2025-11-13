package recovery

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/logic"
	"github.com/google/uuid"
)

// PasswordResetAnalyzer analyzes password reset flows for vulnerabilities
type PasswordResetAnalyzer struct {
	httpClient      *http.Client
	emailChecker    *EmailChecker
	tokenAnalyzer   *TokenAnalyzer
	config          *logic.TestConfig
	vulnerabilities []logic.Vulnerability
	mutex           sync.Mutex
}

// NewPasswordResetAnalyzer creates a new password reset analyzer
func NewPasswordResetAnalyzer(config *logic.TestConfig) *PasswordResetAnalyzer {
	if config == nil {
		config = &logic.TestConfig{
			MaxWorkers:        10,
			Timeout:           30 * time.Second,
			TokenSamples:      100,
			BruteForceThreads: 50,
			TestHostHeader:    true,
			TestTokenEntropy:  true,
		}
	}

	return &PasswordResetAnalyzer{
		httpClient:      &http.Client{Timeout: config.Timeout},
		emailChecker:    NewEmailChecker(),
		tokenAnalyzer:   NewTokenAnalyzer(),
		config:          config,
		vulnerabilities: []logic.Vulnerability{},
	}
}

// ResetFlowVulnerabilities represents all possible reset flow vulnerabilities
type ResetFlowVulnerabilities struct {
	// Token vulnerabilities
	WeakTokenEntropy  bool `json:"weak_token_entropy"`
	PredictableTokens bool `json:"predictable_tokens"`
	TokenNotExpiring  bool `json:"token_not_expiring"`
	TokenReuse        bool `json:"token_reuse"`

	// Flow vulnerabilities
	UserEnumeration     bool `json:"user_enumeration"`
	HostHeaderInjection bool `json:"host_header_injection"`
	RaceCondition       bool `json:"race_condition"`
	BruteForceableToken bool `json:"brute_forceable_token"`

	// Email vulnerabilities
	EmailParamPollution bool `json:"email_param_pollution"`
	CarbonCopyInjection bool `json:"carbon_copy_injection"`
	HTMLInjection       bool `json:"html_injection"`

	// Session vulnerabilities
	SessionNotInvalidated bool `json:"session_not_invalidated"`
	ConcurrentResets      bool `json:"concurrent_resets"`

	// Logic flaws
	PasswordChangeNoToken bool `json:"password_change_no_token"`
	DirectObjectReference bool `json:"direct_object_reference"`
	MissingRateLimit      bool `json:"missing_rate_limit"`
}

// ResetFlowAnalysis represents the complete analysis results
type ResetFlowAnalysis struct {
	Target          string                   `json:"target"`
	Endpoints       []ResetEndpoint          `json:"endpoints"`
	TokenAnalysis   logic.TokenAnalysis      `json:"token_analysis"`
	Vulnerabilities []logic.Vulnerability    `json:"vulnerabilities"`
	SecurityScore   int                      `json:"security_score"`
	TestDuration    time.Duration            `json:"test_duration"`
	FlowVulns       ResetFlowVulnerabilities `json:"flow_vulnerabilities"`
	Recommendations []logic.Recommendation   `json:"recommendations"`
}

// ResetEndpoint represents a password reset endpoint
type ResetEndpoint struct {
	URL          string            `json:"url"`
	Method       string            `json:"method"`
	Parameters   map[string]string `json:"parameters"`
	ContentType  string            `json:"content_type"`
	IsActive     bool              `json:"is_active"`
	ResponseTime time.Duration     `json:"response_time"`
}

// AnalyzeResetFlow performs comprehensive password reset flow analysis
func (p *PasswordResetAnalyzer) AnalyzeResetFlow(target string) *ResetFlowAnalysis {
	startTime := time.Now()

	analysis := &ResetFlowAnalysis{
		Target:          target,
		Endpoints:       []ResetEndpoint{},
		Vulnerabilities: []logic.Vulnerability{},
		FlowVulns:       ResetFlowVulnerabilities{},
	}

	// 1. Discover reset endpoints
	endpoints := p.discoverResetEndpoints(target)
	analysis.Endpoints = endpoints

	// 2. Test each endpoint for vulnerabilities
	for _, endpoint := range endpoints {
		if !endpoint.IsActive {
			continue
		}

		// Test token generation vulnerabilities
		if p.config.TestTokenEntropy {
			tokenVulns := p.testTokenGeneration(endpoint)
			analysis.Vulnerabilities = append(analysis.Vulnerabilities, tokenVulns...)
		}

		// Test email handling vulnerabilities
		emailVulns := p.testEmailHandling(endpoint)
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, emailVulns...)

		// Test host header injection
		if p.config.TestHostHeader {
			if hostVuln := p.testHostHeaderInjection(endpoint); hostVuln != nil {
				analysis.Vulnerabilities = append(analysis.Vulnerabilities, *hostVuln)
				analysis.FlowVulns.HostHeaderInjection = true
			}
		}

		// Test race conditions
		raceVulns := p.testRaceConditions(endpoint)
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, raceVulns...)

		// Test flow manipulation
		flowVulns := p.testFlowManipulation(endpoint)
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, flowVulns...)

		// Test user enumeration
		if userEnumVuln := p.testUserEnumeration(endpoint); userEnumVuln != nil {
			analysis.Vulnerabilities = append(analysis.Vulnerabilities, *userEnumVuln)
			analysis.FlowVulns.UserEnumeration = true
		}

		// Test rate limiting
		if rateLimitVuln := p.testRateLimiting(endpoint); rateLimitVuln != nil {
			analysis.Vulnerabilities = append(analysis.Vulnerabilities, *rateLimitVuln)
			analysis.FlowVulns.MissingRateLimit = true
		}
	}

	// 3. Calculate security score
	analysis.SecurityScore = p.calculateSecurityScore(analysis.Vulnerabilities)
	analysis.TestDuration = time.Since(startTime)
	analysis.Recommendations = p.generateRecommendations(analysis.Vulnerabilities)

	return analysis
}

// discoverResetEndpoints finds password reset endpoints
func (p *PasswordResetAnalyzer) discoverResetEndpoints(target string) []ResetEndpoint {
	endpoints := []ResetEndpoint{}

	// Common reset endpoint patterns
	patterns := []string{
		"/password/reset",
		"/password/forgot",
		"/auth/reset",
		"/auth/forgot",
		"/account/reset",
		"/reset",
		"/forgot",
		"/password-reset",
		"/forgot-password",
		"/user/reset",
		"/api/password/reset",
		"/api/auth/reset",
		"/v1/password/reset",
		"/v2/auth/reset",
	}

	for _, pattern := range patterns {
		endpoint := ResetEndpoint{
			URL:    target + pattern,
			Method: "POST",
			Parameters: map[string]string{
				"email":    "test@example.com",
				"username": "testuser",
			},
			ContentType: "application/x-www-form-urlencoded",
		}

		// Test if endpoint is active
		if p.testEndpointActive(endpoint) {
			endpoint.IsActive = true
			endpoints = append(endpoints, endpoint)
		}

		// Also test GET method
		getEndpoint := endpoint
		getEndpoint.Method = "GET"
		if p.testEndpointActive(getEndpoint) {
			getEndpoint.IsActive = true
			endpoints = append(endpoints, getEndpoint)
		}
	}

	return endpoints
}

// testEndpointActive checks if an endpoint is active
func (p *PasswordResetAnalyzer) testEndpointActive(endpoint ResetEndpoint) bool {
	startTime := time.Now()

	var req *http.Request
	var err error

	if endpoint.Method == "GET" {
		req, err = http.NewRequest("GET", endpoint.URL, nil)
	} else {
		values := url.Values{}
		for key, value := range endpoint.Parameters {
			values.Set(key, value)
		}
		req, err = http.NewRequest("POST", endpoint.URL, strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", endpoint.ContentType)
	}

	if err != nil {
		return false
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer httpclient.CloseBody(resp)

	endpoint.ResponseTime = time.Since(startTime)

	// Consider endpoint active if we get anything other than 404
	return resp.StatusCode != 404
}

// testTokenGeneration tests for token generation vulnerabilities
func (p *PasswordResetAnalyzer) testTokenGeneration(endpoint ResetEndpoint) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Collect multiple tokens
	tokens := []string{}
	emails := []string{}

	for i := 0; i < p.config.TokenSamples; i++ {
		email := fmt.Sprintf("test%d@example.com", i)
		token := p.requestPasswordReset(endpoint, email)
		if token != "" {
			tokens = append(tokens, token)
			emails = append(emails, email)
		}
	}

	if len(tokens) == 0 {
		return vulnerabilities
	}

	// Analyze token patterns
	analysis := p.tokenAnalyzer.AnalyzeTokens(tokens)

	// Check for weak entropy
	if analysis.Entropy < 64 {
		vuln := logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnWeakToken,
			Severity:    logic.SeverityHigh,
			Title:       "Weak Password Reset Token Entropy",
			Description: "Password reset tokens have insufficient entropy",
			Details:     fmt.Sprintf("Token entropy: %.2f bits (should be ≥64)", analysis.Entropy),
			Impact:      "Tokens can be brute forced or predicted, leading to account takeover",
			PoC:         p.generateTokenEntropyPoC(analysis),
			CWE:         "CWE-331",
			CVSS:        7.5,
			Remediation: "Use cryptographically secure random number generators with at least 64 bits of entropy",
			Timestamp:   time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// Check for predictable patterns
	if analysis.IsPredictable {
		vuln := logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnPredictableToken,
			Severity:    logic.SeverityCritical,
			Title:       "Predictable Password Reset Tokens",
			Description: "Password reset tokens follow a predictable pattern",
			Details:     fmt.Sprintf("Pattern detected: %s", analysis.Pattern),
			Impact:      "Attackers can predict valid tokens and perform account takeover",
			PoC:         p.generateTokenPredictionPoC(analysis),
			CWE:         "CWE-330",
			CVSS:        9.8,
			Remediation: "Use cryptographically secure random token generation",
			Timestamp:   time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// Check for token collisions
	if analysis.Collisions > 0 {
		vuln := logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnTokenReuse,
			Severity:    logic.SeverityHigh,
			Title:       "Password Reset Token Collisions",
			Description: "Multiple users received identical reset tokens",
			Details:     fmt.Sprintf("Found %d token collisions out of %d samples", analysis.Collisions, len(tokens)),
			Impact:      "Token collisions can lead to unauthorized password resets",
			CWE:         "CWE-330",
			CVSS:        7.5,
			Remediation: "Ensure unique token generation for each reset request",
			Timestamp:   time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// Test token expiration
	if expVuln := p.testTokenExpiration(endpoint, tokens[0]); expVuln != nil {
		vulnerabilities = append(vulnerabilities, *expVuln)
	}

	// Test token reuse
	if reuseVuln := p.testTokenReuse(endpoint, tokens[0]); reuseVuln != nil {
		vulnerabilities = append(vulnerabilities, *reuseVuln)
	}

	return vulnerabilities
}

// testHostHeaderInjection tests for host header injection vulnerabilities
func (p *PasswordResetAnalyzer) testHostHeaderInjection(endpoint ResetEndpoint) *logic.Vulnerability {
	// Test various host header injections
	injections := []string{
		"evil.com",
		"evil.com@legitimate.com",
		"legitimate.com.evil.com",
		"legitimate.com\\.evil.com",
		"legitimate.com/.evil.com",
		"127.0.0.1:8080",
		"attacker.com",
	}

	testEmail := "victim@example.com"

	for _, injection := range injections {
		req := p.buildResetRequest(endpoint, testEmail)
		req.Header.Set("Host", injection)
		req.Header.Set("X-Forwarded-Host", injection)
		req.Header.Set("X-Host", injection)
		req.Header.Set("X-Forwarded-Server", injection)

		resp, err := p.httpClient.Do(req)
		if err != nil {
			continue
		}
		httpclient.CloseBody(resp)

		// Check if email contains injected host
		time.Sleep(2 * time.Second) // Wait for email processing
		if email := p.emailChecker.GetLastEmail(testEmail); email != nil {
			if strings.Contains(email.Body, injection) {
				return &logic.Vulnerability{
					ID:          uuid.New().String(),
					Type:        logic.VulnHostHeaderInjection,
					Severity:    logic.SeverityCritical,
					Title:       "Host Header Injection in Password Reset",
					Description: "Password reset URLs can be controlled via Host header manipulation",
					Details:     fmt.Sprintf("Injected host '%s' appears in reset email", injection),
					Impact:      "Attackers can redirect password reset links to malicious servers",
					PoC:         fmt.Sprintf("POST %s\nHost: %s\n\nemail=%s", endpoint.URL, injection, testEmail),
					CWE:         "CWE-20",
					CVSS:        9.1,
					Remediation: "Validate Host header and use absolute URLs in emails",
					Timestamp:   time.Now(),
				}
			}
		}
	}

	return nil
}

// testRaceConditions tests for race condition vulnerabilities
func (p *PasswordResetAnalyzer) testRaceConditions(endpoint ResetEndpoint) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Test multiple token generation race
	if vuln := p.testMultipleTokenGeneration(endpoint); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test concurrent password changes
	if vuln := p.testConcurrentPasswordChanges(endpoint); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	return vulnerabilities
}

// testMultipleTokenGeneration tests for race conditions in token generation
func (p *PasswordResetAnalyzer) testMultipleTokenGeneration(endpoint ResetEndpoint) *logic.Vulnerability {
	email := "victim@example.com"
	tokens := make(chan string, 100)
	var wg sync.WaitGroup

	// Send multiple reset requests concurrently
	workers := p.config.BruteForceThreads
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token := p.requestPasswordReset(endpoint, email)
			if token != "" {
				tokens <- token
			}
		}()
	}

	wg.Wait()
	close(tokens)

	// Check if multiple valid tokens were generated
	validTokens := []string{}
	uniqueTokens := make(map[string]bool)

	for token := range tokens {
		if token != "" && !uniqueTokens[token] {
			if p.isTokenValid(endpoint, token) {
				validTokens = append(validTokens, token)
				uniqueTokens[token] = true
			}
		}
	}

	if len(validTokens) > 1 {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnRaceCondition,
			Severity:    logic.SeverityHigh,
			Title:       "Race Condition in Password Reset Token Generation",
			Description: "Multiple valid reset tokens can be generated simultaneously",
			Details:     fmt.Sprintf("Generated %d valid tokens via race condition", len(validTokens)),
			Impact:      "Attackers can generate multiple valid tokens for the same account",
			Evidence:    map[string]interface{}{"tokens": validTokens},
			CWE:         "CWE-362",
			CVSS:        7.5,
			Remediation: "Implement proper synchronization and token invalidation",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

// testUserEnumeration tests for user enumeration vulnerabilities
func (p *PasswordResetAnalyzer) testUserEnumeration(endpoint ResetEndpoint) *logic.Vulnerability {
	validEmail := "admin@example.com"
	invalidEmail := "nonexistent@example.com"

	// Test with valid email
	validReq := p.buildResetRequest(endpoint, validEmail)
	validResp, err := p.httpClient.Do(validReq)
	if err != nil {
		return nil
	}
	validBody, _ := io.ReadAll(validResp.Body)
	validResp.Body.Close()

	// Test with invalid email
	invalidReq := p.buildResetRequest(endpoint, invalidEmail)
	invalidResp, err := p.httpClient.Do(invalidReq)
	if err != nil {
		return nil
	}
	invalidBody, _ := io.ReadAll(invalidResp.Body)
	invalidResp.Body.Close()

	// Check for differences that indicate user enumeration
	differences := []string{}

	if validResp.StatusCode != invalidResp.StatusCode {
		differences = append(differences, fmt.Sprintf("Status code: %d vs %d", validResp.StatusCode, invalidResp.StatusCode))
	}

	if len(validBody) != len(invalidBody) {
		differences = append(differences, fmt.Sprintf("Response length: %d vs %d", len(validBody), len(invalidBody)))
	}

	if string(validBody) != string(invalidBody) {
		differences = append(differences, "Response content differs")
	}

	if len(differences) > 0 {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnUserEnumeration,
			Severity:    logic.SeverityMedium,
			Title:       "User Enumeration via Password Reset",
			Description: "Password reset responses reveal whether email addresses are registered",
			Details:     fmt.Sprintf("Differences found: %s", strings.Join(differences, ", ")),
			Impact:      "Attackers can enumerate valid email addresses",
			CWE:         "CWE-204",
			CVSS:        5.3,
			Remediation: "Return identical responses for valid and invalid email addresses",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

// testRateLimiting tests for rate limiting vulnerabilities
func (p *PasswordResetAnalyzer) testRateLimiting(endpoint ResetEndpoint) *logic.Vulnerability {
	email := "test@example.com"
	successCount := 0
	totalRequests := 20

	for i := 0; i < totalRequests; i++ {
		req := p.buildResetRequest(endpoint, email)
		resp, err := p.httpClient.Do(req)
		if err != nil {
			continue
		}
		httpclient.CloseBody(resp)

		if resp.StatusCode == 200 || resp.StatusCode == 302 {
			successCount++
		}

		// Small delay between requests
		time.Sleep(100 * time.Millisecond)
	}

	// If more than 80% succeed, likely no rate limiting
	if float64(successCount)/float64(totalRequests) > 0.8 {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnMissingRateLimit,
			Severity:    logic.SeverityMedium,
			Title:       "Missing Rate Limiting on Password Reset",
			Description: "Password reset endpoint lacks proper rate limiting",
			Details:     fmt.Sprintf("%d/%d requests succeeded without rate limiting", successCount, totalRequests),
			Impact:      "Attackers can abuse password reset functionality and spam users",
			CWE:         "CWE-770",
			CVSS:        5.3,
			Remediation: "Implement rate limiting based on IP address and email",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

// Helper methods

func (p *PasswordResetAnalyzer) requestPasswordReset(endpoint ResetEndpoint, email string) string {
	req := p.buildResetRequest(endpoint, email)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer httpclient.CloseBody(resp)

	// Extract token from response or location header
	if token := p.extractTokenFromResponse(resp); token != "" {
		return token
	}

	// Check email for token
	time.Sleep(2 * time.Second)
	if emailMsg := p.emailChecker.GetLastEmail(email); emailMsg != nil {
		return p.extractTokenFromEmail(emailMsg.Body)
	}

	return ""
}

func (p *PasswordResetAnalyzer) buildResetRequest(endpoint ResetEndpoint, email string) *http.Request {
	values := url.Values{}
	values.Set("email", email)

	req, _ := http.NewRequest(endpoint.Method, endpoint.URL, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityTester/1.0)")

	return req
}

func (p *PasswordResetAnalyzer) extractTokenFromResponse(resp *http.Response) string {
	// Check Location header for token
	if location := resp.Header.Get("Location"); location != "" {
		if token := p.extractTokenFromURL(location); token != "" {
			return token
		}
	}

	// Check response body
	body, _ := io.ReadAll(resp.Body)
	return p.extractTokenFromHTML(string(body))
}

func (p *PasswordResetAnalyzer) extractTokenFromURL(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}

	// Common token parameter names
	tokenParams := []string{"token", "reset_token", "code", "key", "t"}
	for _, param := range tokenParams {
		if token := u.Query().Get(param); token != "" {
			return token
		}
	}

	return ""
}

func (p *PasswordResetAnalyzer) extractTokenFromHTML(html string) string {
	// Look for token in various HTML elements
	patterns := []string{
		`token["\s]*[:=]["\s]*([a-zA-Z0-9\-_\.]+)`,
		`reset_token["\s]*[:=]["\s]*([a-zA-Z0-9\-_\.]+)`,
		`value["\s]*=["\s]*([a-zA-Z0-9\-_\.]{20,})`,
		`href["\s]*=["\s]*[^"]*token=([a-zA-Z0-9\-_\.]+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(html); len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

func (p *PasswordResetAnalyzer) extractTokenFromEmail(body string) string {
	// Extract token from email body
	patterns := []string{
		`token[=:]?\s*([a-zA-Z0-9\-_\.]{20,})`,
		`reset[^a-zA-Z0-9]*([a-zA-Z0-9\-_\.]{20,})`,
		`https?://[^/]+/[^?]*[?&]token=([a-zA-Z0-9\-_\.]+)`,
		`https?://[^/]+/reset/([a-zA-Z0-9\-_\.]+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(body); len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

func (p *PasswordResetAnalyzer) isTokenValid(endpoint ResetEndpoint, token string) bool {
	// Try to use the token to reset password
	resetURL := strings.Replace(endpoint.URL, "/forgot", "/reset", 1)
	resetURL = strings.Replace(resetURL, "/password/reset", "/password/confirm", 1)

	values := url.Values{}
	values.Set("token", token)
	values.Set("password", "newpassword123")
	values.Set("password_confirmation", "newpassword123")

	req, _ := http.NewRequest("POST", resetURL, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer httpclient.CloseBody(resp)

	// Token is valid if we don't get an error response
	return resp.StatusCode != 400 && resp.StatusCode != 403 && resp.StatusCode != 404
}

func (p *PasswordResetAnalyzer) calculateSecurityScore(vulnerabilities []logic.Vulnerability) int {
	score := 100

	for _, vuln := range vulnerabilities {
		switch vuln.Severity {
		case logic.SeverityCritical:
			score -= 25
		case logic.SeverityHigh:
			score -= 15
		case logic.SeverityMedium:
			score -= 8
		case logic.SeverityLow:
			score -= 3
		}
	}

	if score < 0 {
		score = 0
	}

	return score
}

func (p *PasswordResetAnalyzer) generateRecommendations(vulnerabilities []logic.Vulnerability) []logic.Recommendation {
	recommendations := []logic.Recommendation{}

	vulnTypes := make(map[string]bool)
	for _, vuln := range vulnerabilities {
		vulnTypes[vuln.Type] = true
	}

	if vulnTypes[logic.VulnHostHeaderInjection] {
		recommendations = append(recommendations, logic.Recommendation{
			Priority:    "CRITICAL",
			Category:    "Security",
			Title:       "Fix Host Header Injection",
			Description: "Validate Host header and use absolute URLs in password reset emails",
			Timeline:    "Immediate",
			Effort:      "Low",
			Impact:      "High",
		})
	}

	if vulnTypes[logic.VulnWeakToken] || vulnTypes[logic.VulnPredictableToken] {
		recommendations = append(recommendations, logic.Recommendation{
			Priority:    "HIGH",
			Category:    "Cryptography",
			Title:       "Improve Token Generation",
			Description: "Use cryptographically secure random number generators with sufficient entropy",
			Timeline:    "1 week",
			Effort:      "Medium",
			Impact:      "High",
		})
	}

	if vulnTypes[logic.VulnUserEnumeration] {
		recommendations = append(recommendations, logic.Recommendation{
			Priority:    "MEDIUM",
			Category:    "Information Disclosure",
			Title:       "Prevent User Enumeration",
			Description: "Return identical responses for valid and invalid email addresses",
			Timeline:    "2 weeks",
			Effort:      "Low",
			Impact:      "Medium",
		})
	}

	return recommendations
}

// Additional testing methods

func (p *PasswordResetAnalyzer) testEmailHandling(endpoint ResetEndpoint) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Test email parameter pollution
	if vuln := p.testEmailParameterPollution(endpoint); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test HTML injection in emails
	if vuln := p.testHTMLInjection(endpoint); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	return vulnerabilities
}

func (p *PasswordResetAnalyzer) testEmailParameterPollution(endpoint ResetEndpoint) *logic.Vulnerability {
	// Test multiple email parameters
	emails := []string{"victim@example.com", "attacker@evil.com"}

	values := url.Values{}
	for _, email := range emails {
		values.Add("email", email)
	}

	req, _ := http.NewRequest(endpoint.Method, endpoint.URL, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	// Check if multiple emails received reset links
	time.Sleep(3 * time.Second)

	victimEmail := p.emailChecker.GetLastEmail("victim@example.com")
	attackerEmail := p.emailChecker.GetLastEmail("attacker@evil.com")

	if victimEmail != nil && attackerEmail != nil {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        "EMAIL_PARAMETER_POLLUTION",
			Severity:    logic.SeverityMedium,
			Title:       "Email Parameter Pollution",
			Description: "Multiple email parameters cause reset links to be sent to multiple addresses",
			Details:     "Reset links sent to both victim and attacker emails",
			Impact:      "Attackers can receive password reset links for other users",
			CWE:         "CWE-20",
			CVSS:        6.5,
			Remediation: "Validate and sanitize email parameters, accept only single email",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

func (p *PasswordResetAnalyzer) testHTMLInjection(endpoint ResetEndpoint) *logic.Vulnerability {
	// Test HTML injection in email parameter
	maliciousEmail := `test@example.com<script>alert('XSS')</script>`

	req := p.buildResetRequest(endpoint, maliciousEmail)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	// Check email for injected HTML
	time.Sleep(2 * time.Second)
	if email := p.emailChecker.GetLastEmail("test@example.com"); email != nil {
		if strings.Contains(email.Body, "<script>") {
			return &logic.Vulnerability{
				ID:          uuid.New().String(),
				Type:        "HTML_INJECTION_EMAIL",
				Severity:    logic.SeverityMedium,
				Title:       "HTML Injection in Password Reset Emails",
				Description: "HTML content can be injected into password reset emails",
				Details:     "Script tag successfully injected into email body",
				Impact:      "Potential for email-based XSS attacks",
				CWE:         "CWE-79",
				CVSS:        5.4,
				Remediation: "Properly escape user input in email templates",
				Timestamp:   time.Now(),
			}
		}
	}

	return nil
}

func (p *PasswordResetAnalyzer) testFlowManipulation(endpoint ResetEndpoint) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Test direct password change without token
	if vuln := p.testDirectPasswordChange(endpoint); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test IDOR in reset flow
	if vuln := p.testIDORInReset(endpoint); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	return vulnerabilities
}

func (p *PasswordResetAnalyzer) testDirectPasswordChange(endpoint ResetEndpoint) *logic.Vulnerability {
	// Try to change password without token
	changeURL := strings.Replace(endpoint.URL, "/reset", "/change", 1)
	changeURL = strings.Replace(changeURL, "/forgot", "/change", 1)

	values := url.Values{}
	values.Set("email", "victim@example.com")
	values.Set("password", "newpassword123")
	values.Set("password_confirmation", "newpassword123")

	req, _ := http.NewRequest("POST", changeURL, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode == 200 || resp.StatusCode == 302 {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnPasswordChangeNoToken,
			Severity:    logic.SeverityCritical,
			Title:       "Password Change Without Token Verification",
			Description: "Passwords can be changed without valid reset token",
			Details:     "Direct password change succeeded without token validation",
			Impact:      "Complete account takeover without token verification",
			CWE:         "CWE-306",
			CVSS:        9.8,
			Remediation: "Require valid reset token for all password changes",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

func (p *PasswordResetAnalyzer) testIDORInReset(endpoint ResetEndpoint) *logic.Vulnerability {
	// Generate reset for user A
	userAEmail := "usera@example.com"
	tokenA := p.requestPasswordReset(endpoint, userAEmail)
	if tokenA == "" {
		return nil
	}

	// Try to use token A to reset user B's password
	userBEmail := "userb@example.com"

	resetURL := strings.Replace(endpoint.URL, "/forgot", "/reset", 1)

	values := url.Values{}
	values.Set("email", userBEmail) // Different user
	values.Set("token", tokenA)     // Token from user A
	values.Set("password", "newpassword123")
	values.Set("password_confirmation", "newpassword123")

	req, _ := http.NewRequest("POST", resetURL, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode == 200 || resp.StatusCode == 302 {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnIDOR,
			Severity:    logic.SeverityCritical,
			Title:       "IDOR in Password Reset Flow",
			Description: "Password reset tokens can be used for different users",
			Details:     "Token from user A successfully reset password for user B",
			Impact:      "Attackers can reset passwords for arbitrary users",
			CWE:         "CWE-639",
			CVSS:        9.8,
			Remediation: "Bind reset tokens to specific user accounts",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

func (p *PasswordResetAnalyzer) testTokenExpiration(endpoint ResetEndpoint, token string) *logic.Vulnerability {
	// Wait and test if token still works after expected expiration
	time.Sleep(10 * time.Minute) // Most tokens should expire within 10 minutes for testing

	if p.isTokenValid(endpoint, token) {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        "TOKEN_NOT_EXPIRING",
			Severity:    logic.SeverityMedium,
			Title:       "Password Reset Tokens Do Not Expire",
			Description: "Password reset tokens remain valid indefinitely",
			Details:     "Token still valid after 10 minutes",
			Impact:      "Long-lived tokens increase attack window",
			CWE:         "CWE-613",
			CVSS:        5.3,
			Remediation: "Implement token expiration (recommended: 15-30 minutes)",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

func (p *PasswordResetAnalyzer) testTokenReuse(endpoint ResetEndpoint, token string) *logic.Vulnerability {
	// Use token once
	resetURL := strings.Replace(endpoint.URL, "/forgot", "/reset", 1)

	values := url.Values{}
	values.Set("token", token)
	values.Set("password", "newpassword123")
	values.Set("password_confirmation", "newpassword123")

	req, _ := http.NewRequest("POST", resetURL, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil
	}
	httpclient.CloseBody(resp)

	// Try to use the same token again
	resp2, err := p.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp2)

	if resp2.StatusCode == 200 || resp2.StatusCode == 302 {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnTokenReuse,
			Severity:    logic.SeverityHigh,
			Title:       "Password Reset Token Reuse",
			Description: "Password reset tokens can be reused multiple times",
			Details:     "Same token successfully used twice",
			Impact:      "Tokens remain valid after use, extending attack window",
			CWE:         "CWE-613",
			CVSS:        7.5,
			Remediation: "Invalidate tokens after successful use",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

func (p *PasswordResetAnalyzer) testConcurrentPasswordChanges(endpoint ResetEndpoint) *logic.Vulnerability {
	// Generate a valid token
	email := "victim@example.com"
	token := p.requestPasswordReset(endpoint, email)
	if token == "" {
		return nil
	}

	resetURL := strings.Replace(endpoint.URL, "/forgot", "/reset", 1)

	// Prepare two different password change requests
	req1 := p.buildPasswordChangeRequest(resetURL, token, "password1")
	req2 := p.buildPasswordChangeRequest(resetURL, token, "password2")

	// Execute concurrently
	var wg sync.WaitGroup
	results := make(chan bool, 2)

	wg.Add(2)
	go func() {
		defer wg.Done()
		resp, err := p.httpClient.Do(req1)
		if err == nil {
			defer httpclient.CloseBody(resp)
			results <- (resp.StatusCode == 200 || resp.StatusCode == 302)
		} else {
			results <- false
		}
	}()

	go func() {
		defer wg.Done()
		resp, err := p.httpClient.Do(req2)
		if err == nil {
			defer httpclient.CloseBody(resp)
			results <- (resp.StatusCode == 200 || resp.StatusCode == 302)
		} else {
			results <- false
		}
	}()

	wg.Wait()
	close(results)

	successCount := 0
	for success := range results {
		if success {
			successCount++
		}
	}

	if successCount > 1 {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnRaceCondition,
			Severity:    logic.SeverityMedium,
			Title:       "Race Condition in Password Change",
			Description: "Multiple password changes can be performed with the same token",
			Details:     "Both concurrent password changes succeeded",
			Impact:      "Race conditions may lead to unexpected password states",
			CWE:         "CWE-362",
			CVSS:        5.3,
			Remediation: "Implement proper synchronization for password changes",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

func (p *PasswordResetAnalyzer) buildPasswordChangeRequest(resetURL, token, password string) *http.Request {
	values := url.Values{}
	values.Set("token", token)
	values.Set("password", password)
	values.Set("password_confirmation", password)

	req, _ := http.NewRequest("POST", resetURL, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req
}

func (p *PasswordResetAnalyzer) generateTokenEntropyPoC(analysis logic.TokenAnalysis) string {
	return fmt.Sprintf(`
# Token Entropy Analysis
Samples analyzed: %d
Calculated entropy: %.2f bits
Expected minimum: 64 bits

# Sample tokens:
%s

# Attack scenario:
1. Collect token samples through legitimate reset requests
2. Analyze patterns and entropy
3. Generate potential tokens based on pattern
4. Brute force account takeover
`, len(analysis.Tokens), analysis.Entropy, strings.Join(analysis.Tokens[:min(5, len(analysis.Tokens))], "\n"))
}

func (p *PasswordResetAnalyzer) generateTokenPredictionPoC(analysis logic.TokenAnalysis) string {
	return fmt.Sprintf(`
# Token Prediction PoC
Pattern detected: %s
Algorithm: %s

# Prediction method:
1. Analyze token generation pattern
2. Predict next tokens in sequence
3. Use predicted tokens for account takeover

# Sample prediction:
If current token: %s
Next token might be: %s
`, analysis.Pattern, analysis.Algorithm,
		analysis.Tokens[len(analysis.Tokens)-1],
		p.predictNextToken(analysis))
}

func (p *PasswordResetAnalyzer) predictNextToken(analysis logic.TokenAnalysis) string {
	// Simple prediction based on pattern (placeholder implementation)
	if len(analysis.Tokens) > 0 {
		lastToken := analysis.Tokens[len(analysis.Tokens)-1]
		if len(lastToken) > 8 {
			// Try incrementing last digits
			if lastChar := lastToken[len(lastToken)-1]; lastChar >= '0' && lastChar <= '8' {
				return lastToken[:len(lastToken)-1] + string(lastChar+1)
			}
		}
	}
	return "PREDICTED_TOKEN_EXAMPLE"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
