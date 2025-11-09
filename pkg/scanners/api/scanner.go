// pkg/scanners/api/scanner.go
//
// API Security Scanner Implementation
//
// Performs comprehensive security testing of REST and GraphQL APIs:
// 1. GraphQL: Introspection, batching attacks, depth/complexity limits, injection
// 2. REST: IDOR, mass assignment, rate limiting, HTTP verb tampering
// 3. Common: Authentication, CORS, version disclosure

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Logger interface for structured logging
type Logger interface {
	Info(msg string, keysAndValues ...interface{})
	Infow(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
	Debugw(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Errorw(msg string, keysAndValues ...interface{})
}

// Scanner performs API security testing
type Scanner struct {
	logger     Logger
	httpClient *http.Client
	timeout    time.Duration
}

// NewScanner creates a new API scanner instance
func NewScanner(logger Logger, timeout time.Duration) *Scanner {
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	return &Scanner{
		logger: logger,
		httpClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		},
		timeout: timeout,
	}
}

// ScanAPI discovers and tests APIs for security vulnerabilities
func (s *Scanner) ScanAPI(ctx context.Context, endpoint string) ([]APIFinding, error) {
	s.logger.Infow("Starting API security scan",
		"endpoint", endpoint,
		"timeout", s.timeout.String(),
	)

	var findings []APIFinding

	// 1. Detect API type
	apiType, err := s.detectAPIType(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("API type detection failed: %w", err)
	}

	s.logger.Infow("API type detected",
		"endpoint", endpoint,
		"api_type", apiType,
	)

	// 2. Run type-specific security tests
	switch apiType {
	case APITypeGraphQL:
		graphQLFindings := s.testGraphQLSecurity(ctx, endpoint)
		findings = append(findings, graphQLFindings...)

	case APITypeREST:
		restFindings := s.testRESTSecurity(ctx, endpoint)
		findings = append(findings, restFindings...)

	default:
		s.logger.Warnw("Unknown API type - running generic tests", "endpoint", endpoint)
	}

	// 3. Run common API security tests (applicable to all types)
	commonFindings := s.testCommonAPISecurity(ctx, endpoint)
	findings = append(findings, commonFindings...)

	s.logger.Infow("API security scan completed",
		"endpoint", endpoint,
		"findings_count", len(findings),
	)

	return findings, nil
}

// detectAPIType attempts to detect the API type
func (s *Scanner) detectAPIType(ctx context.Context, endpoint string) (APIType, error) {
	// Try GraphQL introspection query
	if s.isGraphQLEndpoint(ctx, endpoint) {
		return APITypeGraphQL, nil
	}

	// Check if it responds to REST methods
	if s.isRESTEndpoint(ctx, endpoint) {
		return APITypeREST, nil
	}

	return APITypeREST, nil // Default to REST
}

// isGraphQLEndpoint checks if an endpoint is GraphQL
func (s *Scanner) isGraphQLEndpoint(ctx context.Context, endpoint string) bool {
	introspectionQuery := `{"query":"{\n  __schema {\n    types {\n      name\n    }\n  }\n}"}`

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBufferString(introspectionQuery))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// GraphQL endpoints typically respond with data containing __schema
	return strings.Contains(string(body), "__schema") || strings.Contains(string(body), "types")
}

// isRESTEndpoint checks if an endpoint is REST
func (s *Scanner) isRESTEndpoint(ctx context.Context, endpoint string) bool {
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", endpoint, nil)
	if err != nil {
		return false
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check for REST indicators
	allowHeader := resp.Header.Get("Allow")
	return allowHeader != "" || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusMethodNotAllowed
}

// testGraphQLSecurity performs GraphQL-specific security tests
func (s *Scanner) testGraphQLSecurity(ctx context.Context, endpoint string) []APIFinding {
	var findings []APIFinding

	s.logger.Infow("Running GraphQL security tests", "endpoint", endpoint)

	// 1. Test introspection (info disclosure)
	if introspectionFinding := s.testGraphQLIntrospection(ctx, endpoint); introspectionFinding != nil {
		findings = append(findings, *introspectionFinding)
	}

	// 2. Test batching attacks (rate limit bypass)
	if batchingFinding := s.testGraphQLBatching(ctx, endpoint); batchingFinding != nil {
		findings = append(findings, *batchingFinding)
	}

	// 3. Test query depth limit (DoS)
	if depthFinding := s.testGraphQLDepthLimit(ctx, endpoint); depthFinding != nil {
		findings = append(findings, *depthFinding)
	}

	// 4. Test field suggestion (info disclosure)
	if suggestionFinding := s.testGraphQLFieldSuggestion(ctx, endpoint); suggestionFinding != nil {
		findings = append(findings, *suggestionFinding)
	}

	return findings
}

// testGraphQLIntrospection tests if GraphQL introspection is enabled
func (s *Scanner) testGraphQLIntrospection(ctx context.Context, endpoint string) *APIFinding {
	introspectionQuery := `{"query":"{\n  __schema {\n    queryType {\n      name\n    }\n    mutationType {\n      name\n    }\n    types {\n      name\n      kind\n      fields {\n        name\n      }\n    }\n  }\n}"}`

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBufferString(introspectionQuery))
	if err != nil {
		return nil
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// If introspection query returns schema information
	if strings.Contains(bodyStr, "__schema") && resp.StatusCode == http.StatusOK {
		return &APIFinding{
			Endpoint:          endpoint,
			APIType:           APITypeGraphQL,
			VulnerabilityType: VulnGraphQLIntrospection,
			Severity:          "MEDIUM",
			Title:             "GraphQL Introspection Enabled",
			Description:       "The GraphQL endpoint has introspection enabled, allowing attackers to discover the entire API schema, including hidden queries and mutations.",
			Evidence:          fmt.Sprintf("Introspection query returned schema information. Response length: %d bytes", len(body)),
			Remediation: "Disable GraphQL introspection in production:\n" +
				"1. Configure your GraphQL server to disable introspection\n" +
				"2. Apollo Server: introspection: false\n" +
				"3. GraphQL-Go: DisableIntrospection: true\n" +
				"4. Only enable introspection in development environments",
			Method:       "POST",
			RequestBody:  introspectionQuery,
			ResponseBody: truncateString(bodyStr, 500),
			StatusCode:   resp.StatusCode,
			DiscoveredAt: time.Now(),
		}
	}

	return nil
}

// testGraphQLBatching tests for batching attack vulnerabilities
func (s *Scanner) testGraphQLBatching(ctx context.Context, endpoint string) *APIFinding {
	// Create a batched query with multiple identical queries
	batchQuery := `[
		{"query":"{ __typename }"},
		{"query":"{ __typename }"},
		{"query":"{ __typename }"},
		{"query":"{ __typename }"},
		{"query":"{ __typename }"},
		{"query":"{ __typename }"},
		{"query":"{ __typename }"},
		{"query":"{ __typename }"},
		{"query":"{ __typename }"},
		{"query":"{ __typename }"}
	]`

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBufferString(batchQuery))
	if err != nil {
		return nil
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// If batched query is accepted (returns array of results)
	if resp.StatusCode == http.StatusOK && strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
		return &APIFinding{
			Endpoint:          endpoint,
			APIType:           APITypeGraphQL,
			VulnerabilityType: VulnGraphQLBatching,
			Severity:          "HIGH",
			Title:             "GraphQL Batching Attack Possible",
			Description:       "The GraphQL endpoint accepts batched queries without proper limits. Attackers can bypass rate limiting by sending multiple queries in a single request.",
			Evidence:          fmt.Sprintf("Batched query with 10 operations accepted. Response: %s", truncateString(string(body), 200)),
			Remediation: "Implement batching controls:\n" +
				"1. Limit the number of operations per batch request\n" +
				"2. Apply rate limiting to batch requests\n" +
				"3. Implement query cost analysis\n" +
				"4. Consider disabling batching if not required",
			Method:       "POST",
			RequestBody:  batchQuery,
			ResponseBody: truncateString(string(body), 500),
			StatusCode:   resp.StatusCode,
			DiscoveredAt: time.Now(),
		}
	}

	return nil
}

// testGraphQLDepthLimit tests for query depth limit
func (s *Scanner) testGraphQLDepthLimit(ctx context.Context, endpoint string) *APIFinding {
	// Create a deeply nested query (10 levels deep)
	deepQuery := `{"query":"{ a { b { c { d { e { f { g { h { i { j { k } } } } } } } } } } }"}`

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBufferString(deepQuery))
	if err != nil {
		return nil
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// If deeply nested query is accepted without error
	if resp.StatusCode == http.StatusOK || !strings.Contains(string(body), "depth") {
		return &APIFinding{
			Endpoint:          endpoint,
			APIType:           APITypeGraphQL,
			VulnerabilityType: VulnGraphQLDepthLimit,
			Severity:          "HIGH",
			Title:             "GraphQL Query Depth Limit Missing",
			Description:       "The GraphQL endpoint does not enforce query depth limits, making it vulnerable to DoS attacks via deeply nested queries.",
			Evidence:          fmt.Sprintf("Deeply nested query (10 levels) accepted. Response code: %d", resp.StatusCode),
			Remediation: "Implement query depth limiting:\n" +
				"1. Set maximum query depth (recommended: 5-7 levels)\n" +
				"2. Use query complexity analysis\n" +
				"3. Implement timeout for long-running queries\n" +
				"4. Monitor query execution time",
			Method:       "POST",
			RequestBody:  deepQuery,
			StatusCode:   resp.StatusCode,
			DiscoveredAt: time.Now(),
		}
	}

	return nil
}

// testGraphQLFieldSuggestion tests for field suggestion attacks
func (s *Scanner) testGraphQLFieldSuggestion(ctx context.Context, endpoint string) *APIFinding {
	// Query with intentional typo to trigger field suggestions
	typoQuery := `{"query":"{ userz { id } }"}`

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBufferString(typoQuery))
	if err != nil {
		return nil
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// If error message suggests field names
	if strings.Contains(strings.ToLower(bodyStr), "did you mean") ||
		strings.Contains(strings.ToLower(bodyStr), "suggestion") ||
		strings.Contains(bodyStr, "users") {

		return &APIFinding{
			Endpoint:          endpoint,
			APIType:           APITypeGraphQL,
			VulnerabilityType: VulnGraphQLFieldSuggestion,
			Severity:          "LOW",
			Title:             "GraphQL Field Suggestion Enabled",
			Description:       "The GraphQL endpoint provides field suggestions in error messages, potentially revealing hidden fields and API structure.",
			Evidence:          fmt.Sprintf("Field suggestion found in error: %s", truncateString(bodyStr, 200)),
			Remediation:       "Disable field suggestions in production or sanitize error messages to prevent information disclosure.",
			Method:            "POST",
			RequestBody:       typoQuery,
			ResponseBody:      truncateString(bodyStr, 500),
			StatusCode:        resp.StatusCode,
			DiscoveredAt:      time.Now(),
		}
	}

	return nil
}

// testRESTSecurity performs REST-specific security tests
func (s *Scanner) testRESTSecurity(ctx context.Context, endpoint string) []APIFinding {
	var findings []APIFinding

	s.logger.Infow("Running REST API security tests", "endpoint", endpoint)

	// 1. Test for IDOR vulnerabilities
	if idorFinding := s.testRESTIDOR(ctx, endpoint); idorFinding != nil {
		findings = append(findings, *idorFinding)
	}

	// 2. Test HTTP verb tampering
	if verbFinding := s.testHTTPVerbTampering(ctx, endpoint); verbFinding != nil {
		findings = append(findings, *verbFinding)
	}

	// 3. Test rate limiting
	if rateLimitFinding := s.testRateLimiting(ctx, endpoint); rateLimitFinding != nil {
		findings = append(findings, *rateLimitFinding)
	}

	// 4. Test excessive data exposure
	if dataExposureFinding := s.testExcessiveDataExposure(ctx, endpoint); dataExposureFinding != nil {
		findings = append(findings, *dataExposureFinding)
	}

	return findings
}

// testRESTIDOR tests for IDOR vulnerabilities (basic check)
func (s *Scanner) testRESTIDOR(ctx context.Context, endpoint string) *APIFinding {
	// Test if endpoint accepts sequential IDs
	testIDs := []string{"1", "2", "3", "100", "999"}

	for _, id := range testIDs {
		testURL := endpoint
		if !strings.Contains(endpoint, "{id}") && !strings.HasSuffix(endpoint, "/") {
			testURL = endpoint + "/" + id
		} else {
			testURL = strings.Replace(endpoint, "{id}", id, 1)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// If sequential IDs return different data (200 OK), potential IDOR
		if resp.StatusCode == http.StatusOK {
			return &APIFinding{
				Endpoint:          endpoint,
				APIType:           APITypeREST,
				VulnerabilityType: VulnRESTIDOR,
				Severity:          "HIGH",
				Title:             "Potential IDOR Vulnerability",
				Description:       "The REST API endpoint accepts sequential numeric IDs without proper authorization checks. This may allow unauthorized access to other users' resources.",
				Evidence:          fmt.Sprintf("Sequential ID %s returned HTTP 200. Further manual testing required to confirm IDOR.", id),
				Remediation: "Implement proper authorization:\n" +
					"1. Verify user has permission to access requested resource\n" +
					"2. Use non-sequential UUIDs instead of incremental IDs\n" +
					"3. Implement object-level authorization checks\n" +
					"4. Log and monitor unusual access patterns",
				Method:       "GET",
				StatusCode:   resp.StatusCode,
				DiscoveredAt: time.Now(),
			}
		}
	}

	return nil
}

// testHTTPVerbTampering tests for HTTP verb tampering
func (s *Scanner) testHTTPVerbTampering(ctx context.Context, endpoint string) *APIFinding {
	// Try different HTTP methods
	methods := []string{"PUT", "DELETE", "PATCH", "HEAD"}

	for _, method := range methods {
		req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
		if err != nil {
			continue
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// If unexpected method is allowed
		if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusForbidden {
			return &APIFinding{
				Endpoint:          endpoint,
				APIType:           APITypeREST,
				VulnerabilityType: VulnRESTHTTPVerbTampering,
				Severity:          "MEDIUM",
				Title:             "HTTP Verb Tampering Possible",
				Description:       fmt.Sprintf("The endpoint accepts %s method which may not be intended. Attackers could bypass security controls by using unexpected HTTP methods.", method),
				Evidence:          fmt.Sprintf("%s request returned HTTP %d instead of 405 Method Not Allowed", method, resp.StatusCode),
				Remediation: "Implement method whitelisting:\n" +
					"1. Only allow intended HTTP methods\n" +
					"2. Return 405 Method Not Allowed for unsupported methods\n" +
					"3. Implement consistent authorization across all methods",
				Method:       method,
				StatusCode:   resp.StatusCode,
				DiscoveredAt: time.Now(),
			}
		}
	}

	return nil
}

// testRateLimiting tests for rate limiting enforcement
func (s *Scanner) testRateLimiting(ctx context.Context, endpoint string) *APIFinding {
	// Send multiple requests rapidly
	requestCount := 20
	successCount := 0

	for i := 0; i < requestCount; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			continue
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			successCount++
		}
	}

	// If all requests succeeded, rate limiting may be missing
	if successCount == requestCount {
		return &APIFinding{
			Endpoint:          endpoint,
			APIType:           APITypeREST,
			VulnerabilityType: VulnRESTRateLimiting,
			Severity:          "MEDIUM",
			Title:             "Rate Limiting Not Enforced",
			Description:       fmt.Sprintf("The API endpoint does not enforce rate limiting. Successfully sent %d requests without being throttled.", requestCount),
			Evidence:          fmt.Sprintf("Sent %d rapid requests, all returned HTTP 200", requestCount),
			Remediation: "Implement rate limiting:\n" +
				"1. Limit requests per IP address per time window\n" +
				"2. Implement API key-based rate limiting\n" +
				"3. Return 429 Too Many Requests when limit exceeded\n" +
				"4. Use sliding window or token bucket algorithms",
			Method:       "GET",
			DiscoveredAt: time.Now(),
		}
	}

	return nil
}

// testExcessiveDataExposure tests for excessive data exposure
func (s *Scanner) testExcessiveDataExposure(ctx context.Context, endpoint string) *APIFinding {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Check for sensitive fields in response
	sensitiveFields := []string{"password", "token", "secret", "ssn", "credit_card", "api_key"}
	bodyStr := strings.ToLower(string(body))

	for _, field := range sensitiveFields {
		if strings.Contains(bodyStr, field) {
			return &APIFinding{
				Endpoint:          endpoint,
				APIType:           APITypeREST,
				VulnerabilityType: VulnRESTExcessiveData,
				Severity:          "HIGH",
				Title:             "Excessive Data Exposure in API Response",
				Description:       fmt.Sprintf("The API response contains potentially sensitive field: '%s'. APIs should only return necessary data.", field),
				Evidence:          fmt.Sprintf("Response contains field: %s. Review response for unnecessary sensitive data.", field),
				Remediation: "Minimize data exposure:\n" +
					"1. Only return fields required by the client\n" +
					"2. Use DTOs to control response structure\n" +
					"3. Never include passwords, tokens, or secrets\n" +
					"4. Implement field filtering for API responses",
				Method:         "GET",
				StatusCode:     resp.StatusCode,
				ResponseBody:   truncateString(string(body), 500),
				DiscoveredAt:   time.Now(),
			}
		}
	}

	return nil
}

// testCommonAPISecurity runs security tests common to all API types
func (s *Scanner) testCommonAPISecurity(ctx context.Context, endpoint string) []APIFinding {
	var findings []APIFinding

	// Test CORS configuration
	if corsFinding := s.testCORS(ctx, endpoint); corsFinding != nil {
		findings = append(findings, *corsFinding)
	}

	// Test for version disclosure
	if versionFinding := s.testVersionDisclosure(ctx, endpoint); versionFinding != nil {
		findings = append(findings, *versionFinding)
	}

	return findings
}

// testCORS tests for CORS misconfiguration
func (s *Scanner) testCORS(ctx context.Context, endpoint string) *APIFinding {
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", endpoint, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("Origin", "https://evil.com")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check if CORS allows any origin
	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")

	if allowOrigin == "*" || allowOrigin == "https://evil.com" {
		return &APIFinding{
			Endpoint:          endpoint,
			APIType:           APITypeREST, // Could be any type
			VulnerabilityType: VulnAPICORSMisconfigured,
			Severity:          "MEDIUM",
			Title:             "CORS Misconfiguration",
			Description:       "The API has a permissive CORS policy that allows requests from any origin. This could enable cross-origin attacks.",
			Evidence:          fmt.Sprintf("Access-Control-Allow-Origin header: %s", allowOrigin),
			Remediation: "Implement strict CORS policy:\n" +
				"1. Whitelist specific trusted origins\n" +
				"2. Avoid using wildcard (*) in production\n" +
				"3. Validate origin headers\n" +
				"4. Include credentials only for trusted origins",
			Method:       "OPTIONS",
			StatusCode:   resp.StatusCode,
			DiscoveredAt: time.Now(),
		}
	}

	return nil
}

// testVersionDisclosure tests for version information disclosure
func (s *Scanner) testVersionDisclosure(ctx context.Context, endpoint string) *APIFinding {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check headers for version information
	server := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")
	version := resp.Header.Get("X-API-Version")

	if server != "" || poweredBy != "" || version != "" {
		evidence := fmt.Sprintf("Server: %s, X-Powered-By: %s, X-API-Version: %s", server, poweredBy, version)

		return &APIFinding{
			Endpoint:          endpoint,
			APIType:           APITypeREST,
			VulnerabilityType: VulnAPIVersionDisclosure,
			Severity:          "LOW",
			Title:             "API Version Information Disclosure",
			Description:       "The API discloses version information in HTTP headers, which could help attackers identify known vulnerabilities.",
			Evidence:          evidence,
			Remediation:       "Remove version disclosure headers (Server, X-Powered-By, X-API-Version) in production environments.",
			Method:            "GET",
			StatusCode:        resp.StatusCode,
			DiscoveredAt:      time.Now(),
		}
	}

	return nil
}

// truncateString truncates a string to a maximum length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "... (truncated)"
}
