package scim

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
)

// Scanner implements the SCIM vulnerability scanner
type Scanner struct {
	client     *http.Client
	config     *SCIMConfig
	discoverer *Discoverer
	attacker   *Attacker
	logger     *logger.Logger
}

// NewScanner creates a new SCIM scanner
func NewScanner() core.Scanner {
	start := time.Now()
	
	// Initialize logger for SCIM scanner
	log, err := logger.New(config.LoggerConfig{Level: "debug", Format: "json"})
	if err != nil {
		// Fallback to basic logger if initialization fails
		log, _ = logger.New(config.LoggerConfig{Level: "info", Format: "json"})
	}
	log = log.WithComponent("scim-scanner")

	ctx := context.Background()
	ctx, span := log.StartOperation(ctx, "scim.NewScanner")
	defer func() {
		log.FinishOperation(ctx, span, "scim.NewScanner", start, nil)
	}()

	log.WithContext(ctx).Infow("Initializing SCIM scanner",
		"scanner_type", "scim",
		"component", "vulnerability_scanner",
	)

	config := &SCIMConfig{
		Timeout:            30 * time.Second,
		MaxRetries:         3,
		UserAgent:          "shells-scim-scanner/1.0",
		FollowRedirects:    true,
		VerifySSL:          true,
		MaxBulkOperations:  10,
		TestAuthentication: true,
		TestProvisions:     true,
		TestFilters:        true,
		TestBulkOps:        true,
	}

	log.WithContext(ctx).Debugw("SCIM scanner configuration",
		"timeout", config.Timeout,
		"max_retries", config.MaxRetries,
		"user_agent", config.UserAgent,
		"follow_redirects", config.FollowRedirects,
		"verify_ssl", config.VerifySSL,
		"max_bulk_operations", config.MaxBulkOperations,
		"test_authentication", config.TestAuthentication,
		"test_provisions", config.TestProvisions,
		"test_filters", config.TestFilters,
		"test_bulk_ops", config.TestBulkOps,
	)

	clientStart := time.Now()
	client := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !config.VerifySSL,
			},
		},
	}

	if !config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
		log.WithContext(ctx).Debugw("HTTP client configured with no redirect following",
			"follow_redirects", false,
		)
	}

	log.LogDuration(ctx, "scim.NewScanner.httpClient", clientStart,
		"ssl_verify", config.VerifySSL,
		"timeout", config.Timeout,
		"follow_redirects", config.FollowRedirects,
	)

	scanner := &Scanner{
		client: client,
		config: config,
		logger: log,
	}

	// Initialize components with logging
	componentStart := time.Now()
	scanner.discoverer = NewDiscoverer(client, config)
	scanner.attacker = NewAttacker(client, config)

	log.LogDuration(ctx, "scim.NewScanner.components", componentStart,
		"discoverer_initialized", true,
		"attacker_initialized", true,
	)

	log.WithContext(ctx).Infow("SCIM scanner initialized successfully",
		"scanner_type", "scim",
		"total_init_duration_ms", time.Since(start).Milliseconds(),
		"capabilities", []string{"discovery", "authentication_testing", "filter_injection", "bulk_operations", "user_enumeration", "provisioning_abuse", "schema_disclosure"},
	)

	return scanner
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return "scim"
}

// Type returns the scan type
func (s *Scanner) Type() types.ScanType {
	return types.ScanType("scim")
}

// Validate validates the target URL
func (s *Scanner) Validate(target string) error {
	start := time.Now()
	ctx := context.Background()
	ctx, span := s.logger.StartOperation(ctx, "scim.Validate",
		"target", target,
	)
	var err error
	defer func() {
		s.logger.FinishOperation(ctx, span, "scim.Validate", start, err)
	}()

	s.logger.WithContext(ctx).Debugw("Validating SCIM target",
		"target", target,
		"target_length", len(target),
	)

	if target == "" {
		err = fmt.Errorf("target URL cannot be empty")
		s.logger.LogError(ctx, err, "scim.Validate.empty",
			"validation_type", "empty_target",
		)
		return err
	}

	parseStart := time.Now()
	parsedURL, err := url.Parse(target)
	if err != nil {
		s.logger.LogError(ctx, err, "scim.Validate.parse",
			"target", target,
			"validation_type", "url_parse",
			"parse_duration_ms", time.Since(parseStart).Milliseconds(),
		)
		err = fmt.Errorf("invalid target URL: %w", err)
		return err
	}

	s.logger.LogDuration(ctx, "scim.Validate.parse", parseStart,
		"target", target,
		"scheme", parsedURL.Scheme,
		"host", parsedURL.Host,
		"path", parsedURL.Path,
	)

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		err = fmt.Errorf("target URL must use HTTP or HTTPS scheme")
		s.logger.LogError(ctx, err, "scim.Validate.scheme",
			"target", target,
			"scheme", parsedURL.Scheme,
			"validation_type", "invalid_scheme",
			"supported_schemes", []string{"http", "https"},
		)
		return err
	}

	s.logger.WithContext(ctx).Infow("SCIM target validation successful",
		"target", target,
		"scheme", parsedURL.Scheme,
		"host", parsedURL.Host,
		"validation_duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

// Scan performs the SCIM vulnerability scan
func (s *Scanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	start := time.Now()
	ctx, span := s.logger.StartSpanWithAttributes(ctx, "scim.Scan",
		[]attribute.KeyValue{
			attribute.String("target", target),
			attribute.Int("options_count", len(options)),
			attribute.String("scanner_type", "scim"),
		},
	)
	var err error
	defer func() {
		s.logger.FinishOperation(ctx, span, "scim.Scan", start, err)
	}()

	s.logger.WithContext(ctx).Infow("Starting SCIM vulnerability scan",
		"target", target,
		"options_count", len(options),
		"scanner_type", "scim",
		"capabilities", []string{"discovery", "authentication", "filter_injection", "bulk_operations", "enumeration", "provisioning", "schema"},
	)

	// Log scan options for debugging
	if len(options) > 0 {
		s.logger.WithContext(ctx).Debugw("SCIM scan options provided",
			"target", target,
			"options", options,
		)
	}

	// Validate target
	validateStart := time.Now()
	if err = s.Validate(target); err != nil {
		s.logger.LogError(ctx, err, "scim.Scan.validate",
			"target", target,
			"validation_duration_ms", time.Since(validateStart).Milliseconds(),
		)
		err = fmt.Errorf("target validation failed: %w", err)
		return nil, err
	}

	s.logger.LogDuration(ctx, "scim.Scan.validate", validateStart,
		"target", target,
		"validation_success", true,
	)

	// Update configuration from options
	configStart := time.Now()
	s.updateConfigFromOptions(ctx, options)
	s.logger.LogDuration(ctx, "scim.Scan.updateConfig", configStart,
		"options_applied", len(options),
	)

	findings := []types.Finding{}

	// Phase 1: Discovery
	s.logger.WithContext(ctx).Infow("Starting SCIM endpoint discovery phase",
		"target", target,
		"phase", "discovery",
	)

	discoveryStart := time.Now()
	endpoints, err := s.discoverer.DiscoverEndpoints(ctx, target)
	discoveryDuration := time.Since(discoveryStart)
	
	if err != nil {
		s.logger.LogError(ctx, err, "scim.Scan.discovery",
			"target", target,
			"discovery_duration_ms", discoveryDuration.Milliseconds(),
			"phase", "discovery",
		)
		err = fmt.Errorf("endpoint discovery failed: %w", err)
		return nil, err
	}

	s.logger.WithContext(ctx).Infow("SCIM endpoint discovery completed",
		"target", target,
		"endpoints_found", len(endpoints),
		"discovery_duration_ms", discoveryDuration.Milliseconds(),
		"phase", "discovery",
	)

	if len(endpoints) == 0 {
		s.logger.WithContext(ctx).Infow("No SCIM endpoints discovered - scan completed",
			"target", target,
			"endpoints_found", 0,
			"findings_count", 0,
			"total_duration_ms", time.Since(start).Milliseconds(),
		)
		return findings, nil
	}

	// Log discovered endpoints
	endpointURLs := make([]string, len(endpoints))
	for i, ep := range endpoints {
		endpointURLs[i] = ep.URL
	}
	s.logger.WithContext(ctx).Infow("SCIM endpoints discovered for testing",
		"target", target,
		"endpoint_urls", endpointURLs,
		"endpoints_count", len(endpoints),
	)

	// Phase 2: Test each discovered endpoint
	s.logger.WithContext(ctx).Infow("Starting SCIM vulnerability testing phase",
		"target", target,
		"endpoints_to_test", len(endpoints),
		"phase", "vulnerability_testing",
	)

	testingStart := time.Now()
	totalFindings := 0
	errorCount := 0

	for i, endpoint := range endpoints {
		endpointStart := time.Now()
		s.logger.WithContext(ctx).Infow("Testing SCIM endpoint",
			"endpoint_url", endpoint.URL,
			"endpoint_index", i+1,
			"total_endpoints", len(endpoints),
			"filter_supported", endpoint.FilterSupported,
			"bulk_supported", endpoint.BulkSupported,
		)

		endpointFindings, err := s.testEndpoint(ctx, endpoint)
		endpointDuration := time.Since(endpointStart)
		
		if err != nil {
			errorCount++
			s.logger.LogError(ctx, err, "scim.Scan.testEndpoint",
				"endpoint_url", endpoint.URL,
				"endpoint_index", i+1,
				"endpoint_duration_ms", endpointDuration.Milliseconds(),
				"error_count", errorCount,
			)
			// Continue with other endpoints even if one fails
			continue
		}

		findings = append(findings, endpointFindings...)
		totalFindings += len(endpointFindings)

		s.logger.WithContext(ctx).Infow("SCIM endpoint testing completed",
			"endpoint_url", endpoint.URL,
			"endpoint_index", i+1,
			"findings_found", len(endpointFindings),
			"endpoint_duration_ms", endpointDuration.Milliseconds(),
		)

		// Log any high-severity findings immediately
		for _, finding := range endpointFindings {
			if finding.Severity == types.SeverityCritical || finding.Severity == types.SeverityHigh {
				s.logger.LogVulnerability(ctx, map[string]interface{}{
					"finding_id": finding.ID,
					"endpoint_url": endpoint.URL,
					"severity": string(finding.Severity),
					"title": finding.Title,
					"type": finding.Type,
					"tool": finding.Tool,
					"target": target,
				})
			}
		}
	}

	testingDuration := time.Since(testingStart)
	s.logger.WithContext(ctx).Infow("SCIM vulnerability testing phase completed",
		"target", target,
		"endpoints_tested", len(endpoints),
		"error_count", errorCount,
		"total_findings", totalFindings,
		"testing_duration_ms", testingDuration.Milliseconds(),
		"phase", "vulnerability_testing",
	)

	// Analyze findings by severity
	severityCounts := make(map[types.Severity]int)
	for _, finding := range findings {
		severityCounts[finding.Severity]++
	}

	s.logger.WithContext(ctx).Infow("SCIM vulnerability scan completed",
		"target", target,
		"total_findings", len(findings),
		"severity_breakdown", severityCounts,
		"endpoints_discovered", len(endpoints),
		"endpoints_tested", len(endpoints) - errorCount,
		"error_count", errorCount,
		"total_duration_ms", time.Since(start).Milliseconds(),
		"discovery_duration_ms", discoveryDuration.Milliseconds(),
		"testing_duration_ms", testingDuration.Milliseconds(),
	)

	return findings, nil
}

// updateConfigFromOptions updates scanner configuration from options
func (s *Scanner) updateConfigFromOptions(ctx context.Context, options map[string]string) {
	start := time.Now()
	ctx, span := s.logger.StartOperation(ctx, "scim.updateConfigFromOptions",
		"options_count", len(options),
	)
	defer func() {
		s.logger.FinishOperation(ctx, span, "scim.updateConfigFromOptions", start, nil)
	}()

	if len(options) == 0 {
		s.logger.WithContext(ctx).Debugw("No configuration options provided",
			"options_count", 0,
		)
		return
	}

	s.logger.WithContext(ctx).Debugw("Updating SCIM scanner configuration from options",
		"options_provided", len(options),
		"option_keys", getStringMapKeys(options),
	)

	updatedSettings := make(map[string]interface{})
	if authToken, exists := options["auth-token"]; exists {
		s.config.AuthToken = authToken
		updatedSettings["auth_token"] = "[REDACTED]"
		s.logger.WithContext(ctx).Debugw("Auth token configured",
			"setting", "auth_token",
			"token_length", len(authToken),
		)
	}

	if authType, exists := options["auth-type"]; exists {
		s.config.AuthType = authType
		updatedSettings["auth_type"] = authType
		s.logger.WithContext(ctx).Debugw("Auth type configured",
			"setting", "auth_type",
			"auth_type", authType,
		)
	}

	if username, exists := options["username"]; exists {
		s.config.Username = username
		updatedSettings["username"] = username
		s.logger.WithContext(ctx).Debugw("Username configured",
			"setting", "username",
			"username", username,
		)
	}

	if password, exists := options["password"]; exists {
		s.config.Password = password
		updatedSettings["password"] = "[REDACTED]"
		s.logger.WithContext(ctx).Debugw("Password configured",
			"setting", "password",
			"password_length", len(password),
		)
	}

	if timeout, exists := options["timeout"]; exists {
		if t, err := time.ParseDuration(timeout); err == nil {
			oldTimeout := s.config.Timeout
			s.config.Timeout = t
			s.client.Timeout = t
			updatedSettings["timeout"] = t
			s.logger.WithContext(ctx).Debugw("Timeout configured",
				"setting", "timeout",
				"old_timeout", oldTimeout,
				"new_timeout", t,
			)
		} else {
			s.logger.LogError(ctx, err, "scim.updateConfig.timeout",
				"setting", "timeout",
				"invalid_value", timeout,
			)
		}
	}

	if userAgent, exists := options["user-agent"]; exists {
		s.config.UserAgent = userAgent
		updatedSettings["user_agent"] = userAgent
		s.logger.WithContext(ctx).Debugw("User agent configured",
			"setting", "user_agent",
			"user_agent", userAgent,
		)
	}

	if verifySSL, exists := options["verify-ssl"]; exists {
		oldVerifySSL := s.config.VerifySSL
		s.config.VerifySSL = strings.ToLower(verifySSL) == "true"
		updatedSettings["verify_ssl"] = s.config.VerifySSL
		s.logger.WithContext(ctx).Debugw("SSL verification configured",
			"setting", "verify_ssl",
			"old_value", oldVerifySSL,
			"new_value", s.config.VerifySSL,
		)
	}

	if testAuth, exists := options["test-auth"]; exists {
		oldTestAuth := s.config.TestAuthentication
		s.config.TestAuthentication = strings.ToLower(testAuth) == "true"
		updatedSettings["test_authentication"] = s.config.TestAuthentication
		s.logger.WithContext(ctx).Debugw("Authentication testing configured",
			"setting", "test_authentication",
			"old_value", oldTestAuth,
			"new_value", s.config.TestAuthentication,
		)
	}

	if testFilters, exists := options["test-filters"]; exists {
		oldTestFilters := s.config.TestFilters
		s.config.TestFilters = strings.ToLower(testFilters) == "true"
		updatedSettings["test_filters"] = s.config.TestFilters
		s.logger.WithContext(ctx).Debugw("Filter testing configured",
			"setting", "test_filters",
			"old_value", oldTestFilters,
			"new_value", s.config.TestFilters,
		)
	}

	if testBulk, exists := options["test-bulk"]; exists {
		oldTestBulk := s.config.TestBulkOps
		s.config.TestBulkOps = strings.ToLower(testBulk) == "true"
		updatedSettings["test_bulk_ops"] = s.config.TestBulkOps
		s.logger.WithContext(ctx).Debugw("Bulk operations testing configured",
			"setting", "test_bulk_ops",
			"old_value", oldTestBulk,
			"new_value", s.config.TestBulkOps,
		)
	}

	s.logger.WithContext(ctx).Infow("SCIM scanner configuration updated",
		"settings_updated", len(updatedSettings),
		"updated_settings", updatedSettings,
		"update_duration_ms", time.Since(start).Milliseconds(),
	)
}

// testEndpoint tests a single SCIM endpoint for vulnerabilities
func (s *Scanner) testEndpoint(ctx context.Context, endpoint *SCIMEndpoint) ([]types.Finding, error) {
	start := time.Now()
	ctx, span := s.logger.StartSpanWithAttributes(ctx, "scim.testEndpoint",
		[]attribute.KeyValue{
			attribute.String("endpoint_url", endpoint.URL),
			attribute.Bool("filter_supported", endpoint.FilterSupported),
			attribute.Bool("bulk_supported", endpoint.BulkSupported),
		},
	)
	var err error
	defer func() {
		s.logger.FinishOperation(ctx, span, "scim.testEndpoint", start, err)
	}()

	s.logger.WithContext(ctx).Infow("Starting SCIM endpoint vulnerability testing",
		"endpoint_url", endpoint.URL,
		"filter_supported", endpoint.FilterSupported,
		"bulk_supported", endpoint.BulkSupported,
		"test_phases", []string{"authentication", "filter_injection", "bulk_operations", "user_enumeration", "provisioning", "schema_disclosure"},
	)

	findings := []types.Finding{}
	testResults := make(map[string]int)

	// Test authentication if enabled
	if s.config.TestAuthentication {
		s.logger.WithContext(ctx).Debugw("Starting authentication testing",
			"endpoint_url", endpoint.URL,
			"test_phase", "authentication",
		)
		authStart := time.Now()
		authFindings := s.testAuthentication(ctx, endpoint)
		findings = append(findings, authFindings...)
		testResults["authentication"] = len(authFindings)
		s.logger.LogDuration(ctx, "scim.testEndpoint.authentication", authStart,
			"endpoint_url", endpoint.URL,
			"findings_found", len(authFindings),
		)
	} else {
		s.logger.WithContext(ctx).Debugw("Authentication testing disabled",
			"endpoint_url", endpoint.URL,
			"test_phase", "authentication",
		)
	}

	// Test filter injection if enabled
	if s.config.TestFilters && endpoint.FilterSupported {
		s.logger.WithContext(ctx).Debugw("Starting filter injection testing",
			"endpoint_url", endpoint.URL,
			"test_phase", "filter_injection",
		)
		filterStart := time.Now()
		filterFindings := s.testFilterInjection(ctx, endpoint)
		findings = append(findings, filterFindings...)
		testResults["filter_injection"] = len(filterFindings)
		s.logger.LogDuration(ctx, "scim.testEndpoint.filterInjection", filterStart,
			"endpoint_url", endpoint.URL,
			"findings_found", len(filterFindings),
		)
	} else {
		s.logger.WithContext(ctx).Debugw("Filter injection testing skipped",
			"endpoint_url", endpoint.URL,
			"test_phase", "filter_injection",
			"test_enabled", s.config.TestFilters,
			"filter_supported", endpoint.FilterSupported,
		)
	}

	// Test bulk operations if enabled
	if s.config.TestBulkOps && endpoint.BulkSupported {
		s.logger.WithContext(ctx).Debugw("Starting bulk operations testing",
			"endpoint_url", endpoint.URL,
			"test_phase", "bulk_operations",
		)
		bulkStart := time.Now()
		bulkFindings := s.testBulkOperations(ctx, endpoint)
		findings = append(findings, bulkFindings...)
		testResults["bulk_operations"] = len(bulkFindings)
		s.logger.LogDuration(ctx, "scim.testEndpoint.bulkOperations", bulkStart,
			"endpoint_url", endpoint.URL,
			"findings_found", len(bulkFindings),
		)
	} else {
		s.logger.WithContext(ctx).Debugw("Bulk operations testing skipped",
			"endpoint_url", endpoint.URL,
			"test_phase", "bulk_operations",
			"test_enabled", s.config.TestBulkOps,
			"bulk_supported", endpoint.BulkSupported,
		)
	}

	// Test user enumeration
	s.logger.WithContext(ctx).Debugw("Starting user enumeration testing",
		"endpoint_url", endpoint.URL,
		"test_phase", "user_enumeration",
	)
	enumStart := time.Now()
	enumFindings := s.testUserEnumeration(ctx, endpoint)
	findings = append(findings, enumFindings...)
	testResults["user_enumeration"] = len(enumFindings)
	s.logger.LogDuration(ctx, "scim.testEndpoint.userEnumeration", enumStart,
		"endpoint_url", endpoint.URL,
		"findings_found", len(enumFindings),
	)

	// Test provisioning abuse
	if s.config.TestProvisions {
		s.logger.WithContext(ctx).Debugw("Starting provisioning abuse testing",
			"endpoint_url", endpoint.URL,
			"test_phase", "provisioning_abuse",
		)
		provisionStart := time.Now()
		provisionFindings := s.testProvisioningAbuse(ctx, endpoint)
		findings = append(findings, provisionFindings...)
		testResults["provisioning_abuse"] = len(provisionFindings)
		s.logger.LogDuration(ctx, "scim.testEndpoint.provisioningAbuse", provisionStart,
			"endpoint_url", endpoint.URL,
			"findings_found", len(provisionFindings),
		)
	} else {
		s.logger.WithContext(ctx).Debugw("Provisioning testing disabled",
			"endpoint_url", endpoint.URL,
			"test_phase", "provisioning_abuse",
		)
	}

	// Test schema disclosure
	s.logger.WithContext(ctx).Debugw("Starting schema disclosure testing",
		"endpoint_url", endpoint.URL,
		"test_phase", "schema_disclosure",
	)
	schemaStart := time.Now()
	schemaFindings := s.testSchemaDisclosure(ctx, endpoint)
	findings = append(findings, schemaFindings...)
	testResults["schema_disclosure"] = len(schemaFindings)
	s.logger.LogDuration(ctx, "scim.testEndpoint.schemaDisclosure", schemaStart,
		"endpoint_url", endpoint.URL,
		"findings_found", len(schemaFindings),
	)

	// Calculate severity breakdown
	severityCounts := make(map[types.Severity]int)
	for _, finding := range findings {
		severityCounts[finding.Severity]++
	}

	s.logger.WithContext(ctx).Infow("SCIM endpoint testing completed",
		"endpoint_url", endpoint.URL,
		"total_findings", len(findings),
		"test_results", testResults,
		"severity_breakdown", severityCounts,
		"total_duration_ms", time.Since(start).Milliseconds(),
		"filter_supported", endpoint.FilterSupported,
		"bulk_supported", endpoint.BulkSupported,
	)

	return findings, nil
}

// testAuthentication tests authentication-related vulnerabilities
func (s *Scanner) testAuthentication(ctx context.Context, endpoint *SCIMEndpoint) []types.Finding {
	findings := []types.Finding{}

	// Test unauthorized access
	if finding := s.testUnauthorizedAccess(ctx, endpoint); finding != nil {
		findings = append(findings, *finding)
	}

	// Test weak authentication
	if finding := s.testWeakAuthentication(ctx, endpoint); finding != nil {
		findings = append(findings, *finding)
	}

	return findings
}

// testUnauthorizedAccess tests for unauthorized access to SCIM endpoints
func (s *Scanner) testUnauthorizedAccess(ctx context.Context, endpoint *SCIMEndpoint) *types.Finding {
	start := time.Now()
	ctx, span := s.logger.StartOperation(ctx, "scim.testUnauthorizedAccess",
		"endpoint_url", endpoint.URL,
		"test_type", "unauthorized_access",
	)
	defer func() {
		s.logger.FinishOperation(ctx, span, "scim.testUnauthorizedAccess", start, nil)
	}()

	testURL := endpoint.URL + "/Users"
	s.logger.WithContext(ctx).Debugw("Testing unauthorized access to SCIM endpoint",
		"endpoint_url", endpoint.URL,
		"test_url", testURL,
		"test_type", "unauthorized_access",
		"method", "GET",
	)

	// Create request without authentication
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		s.logger.LogError(ctx, err, "scim.testUnauthorizedAccess.createRequest",
			"endpoint_url", endpoint.URL,
			"test_url", testURL,
			"method", "GET",
		)
		return nil
	}

	req.Header.Set("User-Agent", s.config.UserAgent)
	req.Header.Set("Accept", "application/scim+json")

	s.logger.WithContext(ctx).Debugw("Sending unauthorized SCIM request",
		"test_url", testURL,
		"method", "GET",
		"user_agent", s.config.UserAgent,
		"headers", map[string]string{
			"Accept": "application/scim+json",
			"User-Agent": s.config.UserAgent,
		},
	)

	httpStart := time.Now()
	resp, err := s.client.Do(req)
	httpDuration := time.Since(httpStart)
	if err != nil {
		s.logger.LogError(ctx, err, "scim.testUnauthorizedAccess.httpRequest",
			"endpoint_url", endpoint.URL,
			"test_url", testURL,
			"http_duration_ms", httpDuration.Milliseconds(),
		)
		return nil
	}
	defer resp.Body.Close()

	s.logger.LogHTTPRequest(ctx, "GET", testURL, resp.StatusCode, httpDuration,
		"endpoint_url", endpoint.URL,
		"test_type", "unauthorized_access",
		"response_headers", resp.Header,
	)

	// If we get 200 OK without authentication, it's a vulnerability
	if resp.StatusCode == http.StatusOK {
		finding := &types.Finding{
			ID:          uuid.New().String(),
			Tool:        "scim",
			Type:        VulnSCIMUnauthorizedAccess,
			Severity:    types.SeverityHigh,
			Title:       "Unauthorized Access to SCIM Endpoint",
			Description: "SCIM endpoint allows access without authentication",
			Evidence:    fmt.Sprintf("GET %s returned %d without authentication", testURL, resp.StatusCode),
			Solution:    "Implement proper authentication for SCIM endpoints",
			References:  []string{"https://tools.ietf.org/html/rfc7644#section-2"},
			Metadata: map[string]interface{}{
				"endpoint":    endpoint.URL,
				"method":      "GET",
				"status_code": resp.StatusCode,
				"resource":    "Users",
				"test_url":    testURL,
				"response_headers": resp.Header,
			},
			CreatedAt: time.Now(),
		}

		s.logger.LogVulnerability(ctx, map[string]interface{}{
			"finding_id": finding.ID,
			"vulnerability_type": "unauthorized_access",
			"endpoint_url": endpoint.URL,
			"severity": string(finding.Severity),
			"status_code": resp.StatusCode,
			"test_url": testURL,
		})

		s.logger.WithContext(ctx).Warnw("SCIM unauthorized access vulnerability found",
			"finding_id", finding.ID,
			"endpoint_url", endpoint.URL,
			"test_url", testURL,
			"status_code", resp.StatusCode,
			"severity", string(finding.Severity),
			"test_duration_ms", time.Since(start).Milliseconds(),
		)

		return finding
	} else {
		s.logger.WithContext(ctx).Debugw("SCIM endpoint properly protected",
			"endpoint_url", endpoint.URL,
			"test_url", testURL,
			"status_code", resp.StatusCode,
			"test_duration_ms", time.Since(start).Milliseconds(),
			"result", "no_vulnerability",
		)
	}

	return nil
}

// testWeakAuthentication tests for weak authentication mechanisms
func (s *Scanner) testWeakAuthentication(ctx context.Context, endpoint *SCIMEndpoint) *types.Finding {
	// Test common weak credentials
	weakCredentials := []struct {
		username string
		password string
	}{
		{"admin", "admin"},
		{"admin", "password"},
		{"scim", "scim"},
		{"test", "test"},
		{"", ""},
	}

	for _, cred := range weakCredentials {
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint.URL+"/Users", nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", s.config.UserAgent)
		req.Header.Set("Accept", "application/scim+json")
		req.SetBasicAuth(cred.username, cred.password)

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return &types.Finding{
				ID:          uuid.New().String(),
				Tool:        "scim",
				Type:        VulnSCIMWeakAuthentication,
				Severity:    types.SeverityCritical,
				Title:       "Weak Authentication in SCIM Endpoint",
				Description: "SCIM endpoint uses weak or default credentials",
				Evidence:    fmt.Sprintf("Successfully authenticated with %s:%s", cred.username, cred.password),
				Solution:    "Use strong authentication mechanisms and avoid default credentials",
				References:  []string{"https://tools.ietf.org/html/rfc7644#section-2"},
				Metadata: map[string]interface{}{
					"endpoint":    endpoint.URL,
					"username":    cred.username,
					"password":    cred.password,
					"status_code": resp.StatusCode,
				},
				CreatedAt: time.Now(),
			}
		}
	}

	return nil
}

// testFilterInjection tests for SCIM filter injection vulnerabilities
func (s *Scanner) testFilterInjection(ctx context.Context, endpoint *SCIMEndpoint) []types.Finding {
	return s.attacker.TestFilterInjection(ctx, endpoint)
}

// testBulkOperations tests for bulk operation abuse
func (s *Scanner) testBulkOperations(ctx context.Context, endpoint *SCIMEndpoint) []types.Finding {
	return s.attacker.TestBulkOperations(ctx, endpoint)
}

// testUserEnumeration tests for user enumeration vulnerabilities
func (s *Scanner) testUserEnumeration(ctx context.Context, endpoint *SCIMEndpoint) []types.Finding {
	return s.attacker.TestUserEnumeration(ctx, endpoint)
}

// testProvisioningAbuse tests for provisioning abuse
func (s *Scanner) testProvisioningAbuse(ctx context.Context, endpoint *SCIMEndpoint) []types.Finding {
	return s.attacker.TestProvisioningAbuse(ctx, endpoint)
}

// testSchemaDisclosure tests for schema information disclosure
func (s *Scanner) testSchemaDisclosure(ctx context.Context, endpoint *SCIMEndpoint) []types.Finding {
	findings := []types.Finding{}

	// Test schema endpoint access
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint.URL+"/Schemas", nil)
	if err != nil {
		return findings
	}

	req.Header.Set("User-Agent", s.config.UserAgent)
	req.Header.Set("Accept", "application/scim+json")

	resp, err := s.client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	// If schemas are accessible without authentication, it might be information disclosure
	if resp.StatusCode == http.StatusOK {
		finding := &types.Finding{
			ID:          uuid.New().String(),
			Tool:        "scim",
			Type:        VulnSCIMSchemaDisclosure,
			Severity:    types.SeverityInfo,
			Title:       "SCIM Schema Information Disclosure",
			Description: "SCIM schemas are accessible without authentication",
			Evidence:    fmt.Sprintf("GET %s/Schemas returned %d", endpoint.URL, resp.StatusCode),
			Solution:    "Consider restricting access to schema information",
			References:  []string{"https://tools.ietf.org/html/rfc7644#section-4"},
			Metadata: map[string]interface{}{
				"endpoint":    endpoint.URL,
				"method":      "GET",
				"status_code": resp.StatusCode,
				"resource":    "Schemas",
			},
			CreatedAt: time.Now(),
		}
		findings = append(findings, *finding)
	}

	return findings
}


// Helper function for getting string map keys
func getStringMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

