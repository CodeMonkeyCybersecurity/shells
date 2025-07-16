package scim

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/google/uuid"
)

// Scanner implements the SCIM vulnerability scanner
type Scanner struct {
	client     *http.Client
	config     *SCIMConfig
	discoverer *Discoverer
	attacker   *Attacker
}

// NewScanner creates a new SCIM scanner
func NewScanner() core.Scanner {
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
	}

	scanner := &Scanner{
		client: client,
		config: config,
	}

	scanner.discoverer = NewDiscoverer(client, config)
	scanner.attacker = NewAttacker(client, config)

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
	if target == "" {
		return fmt.Errorf("target URL cannot be empty")
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("target URL must use HTTP or HTTPS scheme")
	}

	return nil
}

// Scan performs the SCIM vulnerability scan
func (s *Scanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	if err := s.Validate(target); err != nil {
		return nil, fmt.Errorf("target validation failed: %w", err)
	}

	// Update configuration from options
	s.updateConfigFromOptions(options)

	findings := []types.Finding{}

	// Phase 1: Discovery
	endpoints, err := s.discoverer.DiscoverEndpoints(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("endpoint discovery failed: %w", err)
	}

	if len(endpoints) == 0 {
		return findings, nil // No SCIM endpoints found
	}

	// Phase 2: Test each discovered endpoint
	for _, endpoint := range endpoints {
		endpointFindings, err := s.testEndpoint(ctx, endpoint)
		if err != nil {
			// Log error but continue with other endpoints
			continue
		}
		findings = append(findings, endpointFindings...)
	}

	return findings, nil
}

// updateConfigFromOptions updates scanner configuration from options
func (s *Scanner) updateConfigFromOptions(options map[string]string) {
	if authToken, exists := options["auth-token"]; exists {
		s.config.AuthToken = authToken
	}

	if authType, exists := options["auth-type"]; exists {
		s.config.AuthType = authType
	}

	if username, exists := options["username"]; exists {
		s.config.Username = username
	}

	if password, exists := options["password"]; exists {
		s.config.Password = password
	}

	if timeout, exists := options["timeout"]; exists {
		if t, err := time.ParseDuration(timeout); err == nil {
			s.config.Timeout = t
			s.client.Timeout = t
		}
	}

	if userAgent, exists := options["user-agent"]; exists {
		s.config.UserAgent = userAgent
	}

	if verifySSL, exists := options["verify-ssl"]; exists {
		s.config.VerifySSL = strings.ToLower(verifySSL) == "true"
	}

	if testAuth, exists := options["test-auth"]; exists {
		s.config.TestAuthentication = strings.ToLower(testAuth) == "true"
	}

	if testFilters, exists := options["test-filters"]; exists {
		s.config.TestFilters = strings.ToLower(testFilters) == "true"
	}

	if testBulk, exists := options["test-bulk"]; exists {
		s.config.TestBulkOps = strings.ToLower(testBulk) == "true"
	}
}

// testEndpoint tests a single SCIM endpoint for vulnerabilities
func (s *Scanner) testEndpoint(ctx context.Context, endpoint *SCIMEndpoint) ([]types.Finding, error) {
	findings := []types.Finding{}

	// Test authentication if enabled
	if s.config.TestAuthentication {
		authFindings := s.testAuthentication(ctx, endpoint)
		findings = append(findings, authFindings...)
	}

	// Test filter injection if enabled
	if s.config.TestFilters && endpoint.FilterSupported {
		filterFindings := s.testFilterInjection(ctx, endpoint)
		findings = append(findings, filterFindings...)
	}

	// Test bulk operations if enabled
	if s.config.TestBulkOps && endpoint.BulkSupported {
		bulkFindings := s.testBulkOperations(ctx, endpoint)
		findings = append(findings, bulkFindings...)
	}

	// Test user enumeration
	enumFindings := s.testUserEnumeration(ctx, endpoint)
	findings = append(findings, enumFindings...)

	// Test provisioning abuse
	if s.config.TestProvisions {
		provisionFindings := s.testProvisioningAbuse(ctx, endpoint)
		findings = append(findings, provisionFindings...)
	}

	// Test schema disclosure
	schemaFindings := s.testSchemaDisclosure(ctx, endpoint)
	findings = append(findings, schemaFindings...)

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
	// Create request without authentication
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint.URL+"/Users", nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.config.UserAgent)
	req.Header.Set("Accept", "application/scim+json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// If we get 200 OK without authentication, it's a vulnerability
	if resp.StatusCode == http.StatusOK {
		return &types.Finding{
			ID:          uuid.New().String(),
			Tool:        "scim",
			Type:        VulnSCIMUnauthorizedAccess,
			Severity:    types.SeverityHigh,
			Title:       "Unauthorized Access to SCIM Endpoint",
			Description: "SCIM endpoint allows access without authentication",
			Evidence:    fmt.Sprintf("GET %s returned %d without authentication", endpoint.URL+"/Users", resp.StatusCode),
			Solution:    "Implement proper authentication for SCIM endpoints",
			References:  []string{"https://tools.ietf.org/html/rfc7644#section-2"},
			Metadata: map[string]interface{}{
				"endpoint":    endpoint.URL,
				"method":      "GET",
				"status_code": resp.StatusCode,
				"resource":    "Users",
			},
			CreatedAt: time.Now(),
		}
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