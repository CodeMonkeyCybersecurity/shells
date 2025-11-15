// pkg/scanners/restapi/scanner.go
package restapi

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

	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
	"gopkg.in/yaml.v3"
)

// RESTAPIScanner performs comprehensive REST API security testing
//
// Key capabilities:
// - OpenAPI/Swagger spec parsing and security testing
// - HTTP method fuzzing (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, TRACE)
// - API versioning bypass testing (/api/v1 vs /api/v2, /api/v1.0 vs /api/v1.1)
// - Authentication bypass testing (API keys, bearer tokens, JWT)
// - Rate limiting detection and bypass
// - IDOR testing on REST endpoints (/api/users/1, /api/users/2)
// - Mass assignment vulnerabilities
// - API-specific injection (JSON injection, XXE in XML APIs)
// - CORS misconfiguration detection
// - Information disclosure via error messages
type RESTAPIScanner struct {
	client      *http.Client
	config      RESTAPIConfig
	logger      Logger
	rateLimiter *RateLimiter
	results     chan APIFinding
}

// RESTAPIConfig contains REST API scanner configuration
type RESTAPIConfig struct {
	// Discovery settings
	EnableSwaggerDiscovery bool     // Auto-discover Swagger/OpenAPI specs
	SwaggerPaths           []string // Custom Swagger spec paths
	EnableMethodFuzzing    bool     // Test all HTTP methods
	EnableVersionFuzzing   bool     // Test API version variations

	// Security testing
	EnableAuthBypass       bool // Test authentication bypass
	EnableIDORTesting      bool // Test IDOR on REST endpoints
	EnableMassAssignment   bool // Test mass assignment vulnerabilities
	EnableInjectionTesting bool // Test injection vulnerabilities
	EnableCORSTesting      bool // Test CORS misconfigurations
	EnableRateLimitTest    bool // Test rate limiting

	// Authentication contexts
	AuthHeaders   map[string]string // Valid authentication headers
	VictimHeaders map[string]string // Victim user headers (for IDOR)
	NoAuthHeaders map[string]string // Unauthenticated requests

	// Request parameters
	Timeout         time.Duration
	MaxWorkers      int
	RateLimit       int // Requests per second
	FollowRedirects bool
	UserAgent       string
	CustomHeaders   map[string]string

	// Detection thresholds
	StatusCodeFilters []int   // Valid status codes to flag (default: 200, 201)
	MinResponseSize   int     // Minimum response size
	SimilarityThresh  float64 // Response similarity threshold

	// Smart features
	EnableSmartFuzzing    bool // Learn from responses and adapt
	EnablePatternLearning bool // Learn API patterns
	ExtractModelsFromSpec bool // Extract data models from spec
}

// APIFinding represents a discovered API vulnerability
type APIFinding struct {
	FindingType     string         // Type of vulnerability
	Severity        types.Severity // Severity level
	Method          string         // HTTP method
	URL             string         // Affected URL
	Endpoint        string         // API endpoint pattern
	StatusCode      int            // Response status
	Description     string         // Human-readable description
	Evidence        string         // Evidence of vulnerability
	Impact          string         // Security impact
	Remediation     string         // Fix recommendations
	Payload         string         // Attack payload used
	Response        string         // Response excerpt
	ConfidenceScore float64        // 0.0-1.0
	Timestamp       time.Time      // When discovered
	Context         map[string]interface{}
}

// Logger interface for structured logging
type Logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
}

// NewRESTAPIScanner creates a new REST API scanner
func NewRESTAPIScanner(config RESTAPIConfig, logger Logger) *RESTAPIScanner {
	// Set defaults
	if config.Timeout == 0 {
		config.Timeout = 15 * time.Second
	}
	if config.MaxWorkers == 0 {
		config.MaxWorkers = 20
	}
	if config.RateLimit == 0 {
		config.RateLimit = 50
	}
	if config.UserAgent == "" {
		config.UserAgent = "shells-restapi-scanner/1.0"
	}
	if config.SimilarityThresh == 0 {
		config.SimilarityThresh = 0.85
	}
	if len(config.StatusCodeFilters) == 0 {
		config.StatusCodeFilters = []int{200, 201, 202, 204}
	}
	if len(config.SwaggerPaths) == 0 {
		config.SwaggerPaths = []string{
			"/swagger.json",
			"/swagger.yaml",
			"/swagger.yml",
			"/openapi.json",
			"/openapi.yaml",
			"/openapi.yml",
			"/api-docs",
			"/api-docs.json",
			"/api/swagger.json",
			"/api/openapi.json",
			"/v1/swagger.json",
			"/v2/swagger.json",
			"/docs/swagger.json",
		}
	}

	// Enable all tests by default
	if !config.EnableSwaggerDiscovery && !config.EnableMethodFuzzing && !config.EnableVersionFuzzing {
		config.EnableSwaggerDiscovery = true
		config.EnableMethodFuzzing = true
		config.EnableVersionFuzzing = true
		config.EnableAuthBypass = true
		config.EnableIDORTesting = true
		config.EnableMassAssignment = true
		config.EnableInjectionTesting = true
		config.EnableCORSTesting = true
		config.EnableRateLimitTest = true
	}

	client := &http.Client{
		Timeout: config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !config.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return &RESTAPIScanner{
		client:      client,
		config:      config,
		logger:      logger,
		rateLimiter: NewRateLimiter(config.RateLimit),
		results:     make(chan APIFinding, 1000),
	}
}

// Scan performs comprehensive REST API security testing
func (s *RESTAPIScanner) Scan(ctx context.Context, targetURL string) ([]APIFinding, error) {
	s.logger.Info("Starting comprehensive REST API security scan", "target", targetURL)

	findings := []APIFinding{}
	var mu sync.Mutex

	// Phase 1: Discover API endpoints
	endpoints := []APIEndpoint{}

	// 1.1: Try to discover Swagger/OpenAPI spec
	if s.config.EnableSwaggerDiscovery {
		s.logger.Info("Attempting Swagger/OpenAPI spec discovery")
		if spec := s.discoverSwaggerSpec(ctx, targetURL); spec != nil {
			s.logger.Info("Swagger/OpenAPI spec discovered!",
				"version", spec.Info.Version,
				"title", spec.Info.Title,
				"endpoints", len(spec.Paths))

			// Extract endpoints from spec
			specEndpoints := s.extractEndpointsFromSpec(spec, targetURL)
			endpoints = append(endpoints, specEndpoints...)

			// Test spec-specific vulnerabilities
			specFindings := s.testSwaggerSpecVulnerabilities(ctx, spec, targetURL)
			mu.Lock()
			findings = append(findings, specFindings...)
			mu.Unlock()
		}
	}

	// 1.2: If no spec found, discover endpoints via pattern matching
	if len(endpoints) == 0 {
		s.logger.Info("No Swagger spec found - using pattern-based endpoint discovery")
		endpoints = s.discoverEndpointsByPattern(ctx, targetURL)
	}

	s.logger.Info("API endpoint discovery completed", "endpoints", len(endpoints))

	// Phase 2: HTTP method fuzzing
	if s.config.EnableMethodFuzzing {
		s.logger.Info("Starting HTTP method fuzzing")
		methodFindings := s.testHTTPMethods(ctx, endpoints)
		mu.Lock()
		findings = append(findings, methodFindings...)
		mu.Unlock()
	}

	// Phase 3: API versioning bypass
	if s.config.EnableVersionFuzzing {
		s.logger.Info("Testing API versioning bypass")
		versionFindings := s.testAPIVersioning(ctx, endpoints)
		mu.Lock()
		findings = append(findings, versionFindings...)
		mu.Unlock()
	}

	// Phase 4: Authentication bypass
	if s.config.EnableAuthBypass {
		s.logger.Info("Testing authentication bypass")
		authFindings := s.testAuthenticationBypass(ctx, endpoints)
		mu.Lock()
		findings = append(findings, authFindings...)
		mu.Unlock()
	}

	// Phase 5: IDOR testing on REST endpoints
	if s.config.EnableIDORTesting {
		s.logger.Info("Testing IDOR vulnerabilities on REST endpoints")
		idorFindings := s.testRESTIDOR(ctx, endpoints)
		mu.Lock()
		findings = append(findings, idorFindings...)
		mu.Unlock()
	}

	// Phase 6: Mass assignment
	if s.config.EnableMassAssignment {
		s.logger.Info("Testing mass assignment vulnerabilities")
		massFindings := s.testMassAssignment(ctx, endpoints)
		mu.Lock()
		findings = append(findings, massFindings...)
		mu.Unlock()
	}

	// Phase 7: Injection testing
	if s.config.EnableInjectionTesting {
		s.logger.Info("Testing injection vulnerabilities")
		injectionFindings := s.testInjectionVulnerabilities(ctx, endpoints)
		mu.Lock()
		findings = append(findings, injectionFindings...)
		mu.Unlock()
	}

	// Phase 8: CORS misconfiguration
	if s.config.EnableCORSTesting {
		s.logger.Info("Testing CORS misconfigurations")
		corsFindings := s.testCORSMisconfigurations(ctx, endpoints)
		mu.Lock()
		findings = append(findings, corsFindings...)
		mu.Unlock()
	}

	// Phase 9: Rate limiting
	if s.config.EnableRateLimitTest {
		s.logger.Info("Testing rate limiting")
		rateLimitFindings := s.testRateLimiting(ctx, endpoints)
		mu.Lock()
		findings = append(findings, rateLimitFindings...)
		mu.Unlock()
	}

	s.logger.Info("REST API security scan completed",
		"findings", len(findings),
		"target", targetURL)

	return findings, nil
}

// discoverSwaggerSpec attempts to discover Swagger/OpenAPI specification
func (s *RESTAPIScanner) discoverSwaggerSpec(ctx context.Context, baseURL string) *OpenAPISpec {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	baseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// Try each common Swagger path
	for _, path := range s.config.SwaggerPaths {
		specURL := baseURL + path
		s.logger.Debug("Trying Swagger spec path", "url", specURL)

		req, err := http.NewRequestWithContext(ctx, "GET", specURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", s.config.UserAgent)
		req.Header.Set("Accept", "application/json, application/yaml")

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		defer httpclient.CloseBody(resp)

		if resp.StatusCode != 200 {
			continue
		}

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		// Try to parse as JSON first
		var spec OpenAPISpec
		if err := json.Unmarshal(body, &spec); err == nil {
			s.logger.Info("Swagger spec found (JSON)", "url", specURL)
			return &spec
		}

		// Try YAML
		if err := yaml.Unmarshal(body, &spec); err == nil {
			s.logger.Info("Swagger spec found (YAML)", "url", specURL)
			return &spec
		}
	}

	return nil
}

// testHTTPMethods tests all HTTP methods on discovered endpoints
func (s *RESTAPIScanner) testHTTPMethods(ctx context.Context, endpoints []APIEndpoint) []APIFinding {
	findings := []APIFinding{}
	var wg sync.WaitGroup
	var mu sync.Mutex

	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"}

	for _, endpoint := range endpoints {
		for _, method := range methods {
			// Skip if method is already known to work
			if s.methodAlreadyTested(endpoint, method) {
				continue
			}

			wg.Add(1)
			go func(ep APIEndpoint, m string) {
				defer wg.Done()

				s.rateLimiter.Wait()

				req, err := http.NewRequestWithContext(ctx, m, ep.URL, nil)
				if err != nil {
					return
				}

				s.setHeaders(req)

				resp, err := s.client.Do(req)
				if err != nil {
					return
				}
				defer httpclient.CloseBody(resp)

				// Check if method is allowed (unexpected success)
				if s.isSuccessStatus(resp.StatusCode) {
					finding := APIFinding{
						FindingType: "http_method_allowed",
						Severity:    s.determineMethodSeverity(m, resp.StatusCode),
						Method:      m,
						URL:         ep.URL,
						Endpoint:    ep.Pattern,
						StatusCode:  resp.StatusCode,
						Description: fmt.Sprintf("HTTP method %s is allowed on endpoint %s", m, ep.Pattern),
						Evidence: fmt.Sprintf("Request: %s %s\nResponse: %d\nExpected: Method not allowed",
							m, ep.URL, resp.StatusCode),
						Impact:          s.determineMethodImpact(m),
						Remediation:     s.getMethodRemediation(m),
						ConfidenceScore: 0.90,
						Timestamp:       time.Now(),
						Context: map[string]interface{}{
							"method":   m,
							"endpoint": ep.Pattern,
						},
					}

					mu.Lock()
					findings = append(findings, finding)
					mu.Unlock()
				}
			}(endpoint, method)
		}
	}

	wg.Wait()
	return findings
}

// testAPIVersioning tests API version bypass vulnerabilities
func (s *RESTAPIScanner) testAPIVersioning(ctx context.Context, endpoints []APIEndpoint) []APIFinding {
	findings := []APIFinding{}

	for _, endpoint := range endpoints {
		// Extract version from URL
		versions := s.extractVersions(endpoint.URL)
		if len(versions) == 0 {
			continue
		}

		// Test version variations
		testVersions := s.generateVersionVariations(versions[0])

		for _, testVersion := range testVersions {
			testURL := strings.Replace(endpoint.URL, versions[0], testVersion, 1)

			s.rateLimiter.Wait()

			req, err := http.NewRequestWithContext(ctx, endpoint.Method, testURL, nil)
			if err != nil {
				continue
			}

			s.setHeaders(req)

			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}
			defer httpclient.CloseBody(resp)

			if s.isSuccessStatus(resp.StatusCode) {
				finding := APIFinding{
					FindingType: "api_version_bypass",
					Severity:    types.SeverityMedium,
					Method:      endpoint.Method,
					URL:         testURL,
					Endpoint:    endpoint.Pattern,
					StatusCode:  resp.StatusCode,
					Description: fmt.Sprintf("API version %s is accessible (bypass of %s)", testVersion, versions[0]),
					Evidence: fmt.Sprintf("Original version: %s\nAccessible version: %s\nStatus: %d",
						versions[0], testVersion, resp.StatusCode),
					Impact: "Attacker may access deprecated or vulnerable API versions with weaker security controls",
					Remediation: "1. Deprecate and disable old API versions\n" +
						"2. Implement version-specific access controls\n" +
						"3. Use API gateway to enforce version restrictions",
					ConfidenceScore: 0.85,
					Timestamp:       time.Now(),
					Context: map[string]interface{}{
						"original_version": versions[0],
						"bypass_version":   testVersion,
					},
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// testAuthenticationBypass tests authentication bypass vulnerabilities
func (s *RESTAPIScanner) testAuthenticationBypass(ctx context.Context, endpoints []APIEndpoint) []APIFinding {
	findings := []APIFinding{}

	for _, endpoint := range endpoints {
		// Test 1: No authentication headers
		s.rateLimiter.Wait()

		req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.URL, nil)
		if err != nil {
			continue
		}

		// Only set basic headers, NO auth
		req.Header.Set("User-Agent", s.config.UserAgent)
		for k, v := range s.config.NoAuthHeaders {
			req.Header.Set(k, v)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		defer httpclient.CloseBody(resp)

		if s.isSuccessStatus(resp.StatusCode) {
			finding := APIFinding{
				FindingType: "authentication_bypass",
				Severity:    types.SeverityCritical,
				Method:      endpoint.Method,
				URL:         endpoint.URL,
				Endpoint:    endpoint.Pattern,
				StatusCode:  resp.StatusCode,
				Description: "API endpoint accessible without authentication",
				Evidence: fmt.Sprintf("Request without authentication headers returned %d (success)\n"+
					"Expected: 401 Unauthorized or 403 Forbidden", resp.StatusCode),
				Impact: "CRITICAL: Unauthenticated attackers can access protected API endpoints",
				Remediation: "1. Implement proper authentication middleware\n" +
					"2. Validate authentication tokens on all protected endpoints\n" +
					"3. Return 401 for missing/invalid authentication\n" +
					"4. Use API gateway for centralized authentication",
				ConfidenceScore: 0.95,
				Timestamp:       time.Now(),
				Context: map[string]interface{}{
					"bypass_type": "no_authentication",
				},
			}
			findings = append(findings, finding)
		}

		// Test 2: Malformed authentication headers
		malformedTests := []struct {
			name   string
			header map[string]string
		}{
			{"empty_token", map[string]string{"Authorization": "Bearer "}},
			{"null_token", map[string]string{"Authorization": "Bearer null"}},
			{"invalid_format", map[string]string{"Authorization": "Invalid"}},
			{"no_bearer", map[string]string{"Authorization": "token123"}},
		}

		for _, test := range malformedTests {
			s.rateLimiter.Wait()

			req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.URL, nil)
			if err != nil {
				continue
			}

			req.Header.Set("User-Agent", s.config.UserAgent)
			for k, v := range test.header {
				req.Header.Set(k, v)
			}

			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}
			httpclient.CloseBody(resp)

			if s.isSuccessStatus(resp.StatusCode) {
				finding := APIFinding{
					FindingType: "authentication_bypass",
					Severity:    types.SeverityCritical,
					Method:      endpoint.Method,
					URL:         endpoint.URL,
					StatusCode:  resp.StatusCode,
					Description: fmt.Sprintf("Authentication bypass via malformed token (%s)", test.name),
					Evidence: fmt.Sprintf("Malformed auth header '%s' bypassed authentication (Status: %d)",
						test.header["Authorization"], resp.StatusCode),
					Impact:          "Authentication can be bypassed with malformed tokens",
					Remediation:     "Implement strict token validation and return 401 for invalid tokens",
					ConfidenceScore: 0.90,
					Timestamp:       time.Now(),
					Context: map[string]interface{}{
						"bypass_technique": test.name,
					},
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// Placeholder methods (to be implemented)

func (s *RESTAPIScanner) testRESTIDOR(ctx context.Context, endpoints []APIEndpoint) []APIFinding {
	// TODO: Implement REST IDOR testing by detecting ID parameters in URLs and testing access
	return []APIFinding{}
}

func (s *RESTAPIScanner) testMassAssignment(ctx context.Context, endpoints []APIEndpoint) []APIFinding {
	// TODO: Implement mass assignment testing by adding unexpected fields to POST/PUT requests
	return []APIFinding{}
}

func (s *RESTAPIScanner) testInjectionVulnerabilities(ctx context.Context, endpoints []APIEndpoint) []APIFinding {
	// TODO: Implement JSON injection, XXE, SQL injection testing
	return []APIFinding{}
}

func (s *RESTAPIScanner) testCORSMisconfigurations(ctx context.Context, endpoints []APIEndpoint) []APIFinding {
	// TODO: Implement CORS misconfiguration testing
	return []APIFinding{}
}

func (s *RESTAPIScanner) testRateLimiting(ctx context.Context, endpoints []APIEndpoint) []APIFinding {
	// TODO: Implement rate limiting detection
	return []APIFinding{}
}

// Helper methods

func (s *RESTAPIScanner) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", s.config.UserAgent)
	for k, v := range s.config.AuthHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range s.config.CustomHeaders {
		req.Header.Set(k, v)
	}
}

func (s *RESTAPIScanner) isSuccessStatus(code int) bool {
	for _, valid := range s.config.StatusCodeFilters {
		if code == valid {
			return true
		}
	}
	return false
}

func (s *RESTAPIScanner) methodAlreadyTested(endpoint APIEndpoint, method string) bool {
	return endpoint.Method == method
}

func (s *RESTAPIScanner) determineMethodSeverity(method string, statusCode int) types.Severity {
	// Dangerous methods
	if method == "DELETE" || method == "TRACE" {
		return types.SeverityHigh
	}
	if method == "PUT" || method == "PATCH" {
		return types.SeverityMedium
	}
	return types.SeverityLow
}

func (s *RESTAPIScanner) determineMethodImpact(method string) string {
	impacts := map[string]string{
		"DELETE": "Attackers may be able to delete resources",
		"PUT":    "Attackers may be able to modify resources",
		"PATCH":  "Attackers may be able to partially modify resources",
		"TRACE":  "TRACE method enabled - potential for XST (Cross-Site Tracing) attacks",
		"POST":   "Attackers may be able to create unauthorized resources",
	}
	if impact, ok := impacts[method]; ok {
		return impact
	}
	return "Unexpected HTTP method allowed"
}

func (s *RESTAPIScanner) getMethodRemediation(method string) string {
	return fmt.Sprintf("1. Disable %s method if not required\n"+
		"2. Implement proper authorization checks for %s requests\n"+
		"3. Use allow-list approach for HTTP methods\n"+
		"4. Configure web server to reject unwanted methods", method, method)
}

func (s *RESTAPIScanner) extractVersions(urlStr string) []string {
	versionPattern := regexp.MustCompile(`/v\d+(?:\.\d+)?/`)
	matches := versionPattern.FindAllString(urlStr, -1)
	return matches
}

func (s *RESTAPIScanner) generateVersionVariations(version string) []string {
	// Extract numeric version (future: could use this for smarter variations)
	numPattern := regexp.MustCompile(`\d+(?:\.\d+)?`)
	_ = numPattern.FindString(version)

	variations := []string{
		"/v1/", "/v2/", "/v3/",
		"/v1.0/", "/v1.1/", "/v2.0/",
		"/api/v1/", "/api/v2/",
	}

	return variations
}

func NewRateLimiter(requestsPerSecond int) *RateLimiter {
	if requestsPerSecond <= 0 {
		requestsPerSecond = 50
	}
	interval := time.Second / time.Duration(requestsPerSecond)
	return &RateLimiter{
		rate:   requestsPerSecond,
		ticker: time.NewTicker(interval),
	}
}

type RateLimiter struct {
	rate   int
	ticker *time.Ticker
}

func (r *RateLimiter) Wait() {
	<-r.ticker.C
}
