// pkg/scanners/restapi/types.go
package restapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// OpenAPISpec represents a parsed OpenAPI/Swagger specification
type OpenAPISpec struct {
	OpenAPI    string                         `json:"openapi" yaml:"openapi"` // OpenAPI version
	Swagger    string                         `json:"swagger" yaml:"swagger"` // Swagger version
	Info       SpecInfo                       `json:"info" yaml:"info"`
	Servers    []SpecServer                   `json:"servers" yaml:"servers"`
	Paths      map[string]map[string]PathItem `json:"paths" yaml:"paths"`
	Components SpecComponents                 `json:"components" yaml:"components"`
	Security   []map[string][]string          `json:"security" yaml:"security"`
}

// SpecInfo contains API metadata
type SpecInfo struct {
	Title       string `json:"title" yaml:"title"`
	Description string `json:"description" yaml:"description"`
	Version     string `json:"version" yaml:"version"`
}

// SpecServer represents an API server
type SpecServer struct {
	URL         string `json:"url" yaml:"url"`
	Description string `json:"description" yaml:"description"`
}

// PathItem represents a single API path with operations
type PathItem struct {
	Summary     string                `json:"summary" yaml:"summary"`
	Description string                `json:"description" yaml:"description"`
	Parameters  []Parameter           `json:"parameters" yaml:"parameters"`
	RequestBody *RequestBody          `json:"requestBody" yaml:"requestBody"`
	Responses   map[string]Response   `json:"responses" yaml:"responses"`
	Security    []map[string][]string `json:"security" yaml:"security"`
}

// Parameter represents an API parameter
type Parameter struct {
	Name        string  `json:"name" yaml:"name"`
	In          string  `json:"in" yaml:"in"` // path, query, header, cookie
	Description string  `json:"description" yaml:"description"`
	Required    bool    `json:"required" yaml:"required"`
	Schema      *Schema `json:"schema" yaml:"schema"`
}

// RequestBody represents request body specification
type RequestBody struct {
	Description string               `json:"description" yaml:"description"`
	Required    bool                 `json:"required" yaml:"required"`
	Content     map[string]MediaType `json:"content" yaml:"content"`
}

// MediaType represents a media type (e.g., application/json)
type MediaType struct {
	Schema *Schema `json:"schema" yaml:"schema"`
}

// Schema represents a data schema
type Schema struct {
	Type       string             `json:"type" yaml:"type"`
	Format     string             `json:"format" yaml:"format"`
	Properties map[string]*Schema `json:"properties" yaml:"properties"`
	Required   []string           `json:"required" yaml:"required"`
	Items      *Schema            `json:"items" yaml:"items"` // For arrays
}

// Response represents an API response
type Response struct {
	Description string               `json:"description" yaml:"description"`
	Content     map[string]MediaType `json:"content" yaml:"content"`
}

// SpecComponents contains reusable components
type SpecComponents struct {
	Schemas         map[string]*Schema        `json:"schemas" yaml:"schemas"`
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes" yaml:"securitySchemes"`
}

// SecurityScheme represents an authentication scheme
type SecurityScheme struct {
	Type        string `json:"type" yaml:"type"`     // apiKey, http, oauth2, openIdConnect
	Scheme      string `json:"scheme" yaml:"scheme"` // For http type: bearer, basic
	In          string `json:"in" yaml:"in"`         // For apiKey: header, query, cookie
	Name        string `json:"name" yaml:"name"`     // For apiKey: header name
	Description string `json:"description" yaml:"description"`
}

// APIEndpoint represents a discovered API endpoint
type APIEndpoint struct {
	URL          string      // Full URL
	Pattern      string      // URL pattern (e.g., /api/users/{id})
	Method       string      // HTTP method
	Parameters   []Parameter // Parameters
	RequiresAuth bool        // Whether authentication is required
	DataModel    *Schema     // Expected request/response schema
	Context      map[string]interface{}
}

// extractEndpointsFromSpec extracts all API endpoints from OpenAPI spec
func (s *RESTAPIScanner) extractEndpointsFromSpec(spec *OpenAPISpec, baseURL string) []APIEndpoint {
	endpoints := []APIEndpoint{}

	// Determine base URL from spec servers or use provided baseURL
	specBaseURL := baseURL
	if len(spec.Servers) > 0 {
		specBaseURL = spec.Servers[0].URL
	}

	// Iterate through all paths
	for path, methods := range spec.Paths {
		// For each HTTP method
		for method, pathItem := range methods {
			method = strings.ToUpper(method)

			// Build full URL
			fullURL := s.buildFullURL(specBaseURL, path)

			// Check if authentication is required
			requiresAuth := s.requiresAuthentication(pathItem, spec)

			endpoint := APIEndpoint{
				URL:          fullURL,
				Pattern:      path,
				Method:       method,
				Parameters:   pathItem.Parameters,
				RequiresAuth: requiresAuth,
				Context: map[string]interface{}{
					"from_spec": true,
					"summary":   pathItem.Summary,
				},
			}

			// Extract data model if available
			if pathItem.RequestBody != nil {
				endpoint.DataModel = s.extractSchemaFromRequestBody(pathItem.RequestBody)
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	s.logger.Info("Extracted endpoints from OpenAPI spec", "count", len(endpoints))

	return endpoints
}

// buildFullURL builds a full URL from base URL and path pattern
func (s *RESTAPIScanner) buildFullURL(baseURL, path string) string {
	// Remove trailing slash from baseURL
	baseURL = strings.TrimRight(baseURL, "/")

	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Replace path parameters with example values
	// e.g., /users/{id} -> /users/1
	path = s.replacePathParameters(path)

	return baseURL + path
}

// replacePathParameters replaces {param} with example values
func (s *RESTAPIScanner) replacePathParameters(path string) string {
	// Find all {param} patterns
	paramPattern := regexp.MustCompile(`\{([^}]+)\}`)

	return paramPattern.ReplaceAllStringFunc(path, func(match string) string {
		// Extract parameter name
		param := strings.Trim(match, "{}")

		// Return appropriate example value based on parameter name
		if strings.Contains(strings.ToLower(param), "id") {
			return "1" // Use ID = 1 for testing
		}
		if strings.Contains(strings.ToLower(param), "uuid") {
			return "00000000-0000-0000-0000-000000000001"
		}
		if strings.Contains(strings.ToLower(param), "user") {
			return "testuser"
		}

		return "test" // Default value
	})
}

// requiresAuthentication checks if endpoint requires authentication
func (s *RESTAPIScanner) requiresAuthentication(pathItem PathItem, spec *OpenAPISpec) bool {
	// Check path-level security
	if len(pathItem.Security) > 0 {
		return true
	}

	// Check global security
	if len(spec.Security) > 0 {
		return true
	}

	return false
}

// extractSchemaFromRequestBody extracts schema from request body
func (s *RESTAPIScanner) extractSchemaFromRequestBody(body *RequestBody) *Schema {
	// Try to find JSON schema
	if mediaType, ok := body.Content["application/json"]; ok {
		return mediaType.Schema
	}

	// Try any available content type
	for _, mediaType := range body.Content {
		if mediaType.Schema != nil {
			return mediaType.Schema
		}
	}

	return nil
}

// testSwaggerSpecVulnerabilities tests for vulnerabilities in the Swagger spec itself
func (s *RESTAPIScanner) testSwaggerSpecVulnerabilities(ctx context.Context, spec *OpenAPISpec, baseURL string) []APIFinding {
	findings := []APIFinding{}

	// Check 1: Swagger UI publicly accessible
	if spec != nil {
		finding := APIFinding{
			FindingType: "swagger_spec_exposed",
			Severity:    types.SeverityMedium,
			Method:      "GET",
			URL:         baseURL,
			Description: "Swagger/OpenAPI specification is publicly accessible",
			Evidence: fmt.Sprintf("Spec version: %s %s\nTitle: %s\nEndpoints: %d",
				spec.OpenAPI, spec.Swagger, spec.Info.Title, len(spec.Paths)),
			Impact: "Attackers can enumerate all API endpoints, parameters, and data models. " +
				"This provides detailed reconnaissance for targeted attacks.",
			Remediation: "1. Restrict Swagger UI access to internal networks only\n" +
				"2. Require authentication for API documentation\n" +
				"3. Use separate documentation for internal vs external APIs\n" +
				"4. Remove sensitive endpoints from public spec",
			ConfidenceScore: 1.0,
			Timestamp:       time.Now(),
			Context: map[string]interface{}{
				"spec_version": fmt.Sprintf("%s%s", spec.OpenAPI, spec.Swagger),
				"total_paths":  len(spec.Paths),
				"has_security": len(spec.Security) > 0,
			},
		}
		findings = append(findings, finding)
	}

	// Check 2: Sensitive information in spec
	if s.containsSensitiveInfo(spec) {
		finding := APIFinding{
			FindingType:     "swagger_sensitive_info",
			Severity:        types.SeverityHigh,
			Method:          "GET",
			URL:             baseURL,
			Description:     "Swagger specification contains sensitive information",
			Evidence:        "Spec contains potentially sensitive endpoint descriptions, parameter names, or data models",
			Impact:          "Exposed internal implementation details and potential attack vectors",
			Remediation:     "Review and sanitize Swagger spec - remove internal notes, debug endpoints, and sensitive parameter descriptions",
			ConfidenceScore: 0.85,
			Timestamp:       time.Now(),
		}
		findings = append(findings, finding)
	}

	// Check 3: No authentication schemes defined
	if len(spec.Components.SecuritySchemes) == 0 && len(spec.Security) == 0 {
		finding := APIFinding{
			FindingType:     "swagger_no_auth_schemes",
			Severity:        types.SeverityMedium,
			Method:          "GET",
			URL:             baseURL,
			Description:     "Swagger spec defines no authentication schemes",
			Evidence:        "No securitySchemes defined in components and no global security requirements",
			Impact:          "API may lack proper authentication or spec is incomplete",
			Remediation:     "Define proper authentication schemes in Swagger spec",
			ConfidenceScore: 0.70,
			Timestamp:       time.Now(),
		}
		findings = append(findings, finding)
	}

	return findings
}

// containsSensitiveInfo checks if spec contains sensitive information
func (s *RESTAPIScanner) containsSensitiveInfo(spec *OpenAPISpec) bool {
	sensitiveKeywords := []string{
		"password", "secret", "token", "key", "credential",
		"internal", "debug", "admin", "test", "dev",
	}

	// Check path descriptions
	for path, methods := range spec.Paths {
		pathLower := strings.ToLower(path)
		for _, keyword := range sensitiveKeywords {
			if strings.Contains(pathLower, keyword) {
				return true
			}
		}

		// Check method descriptions
		for _, pathItem := range methods {
			descLower := strings.ToLower(pathItem.Description + pathItem.Summary)
			for _, keyword := range sensitiveKeywords {
				if strings.Contains(descLower, keyword) {
					return true
				}
			}
		}
	}

	return false
}

// discoverEndpointsByPattern discovers endpoints using common REST API patterns
func (s *RESTAPIScanner) discoverEndpointsByPattern(ctx context.Context, baseURL string) []APIEndpoint {
	endpoints := []APIEndpoint{}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return endpoints
	}

	baseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// Common REST API patterns
	patterns := []string{
		"/api/users",
		"/api/v1/users",
		"/api/v2/users",
		"/api/user",
		"/api/account",
		"/api/profile",
		"/api/products",
		"/api/items",
		"/api/orders",
		"/api/posts",
		"/api/comments",
		"/api/auth",
		"/api/login",
		"/api/register",
		"/v1/users",
		"/v2/users",
	}

	for _, pattern := range patterns {
		testURL := baseURL + pattern

		s.rateLimiter.Wait()

		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}

		s.setHeaders(req)

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		httpclient.CloseBody(resp)

		// If endpoint exists (not 404)
		if resp.StatusCode != 404 {
			endpoint := APIEndpoint{
				URL:     testURL,
				Pattern: pattern,
				Method:  "GET",
				Context: map[string]interface{}{
					"discovered_by": "pattern_matching",
					"status_code":   resp.StatusCode,
				},
			}
			endpoints = append(endpoints, endpoint)

			s.logger.Debug("Discovered endpoint", "url", testURL, "status", resp.StatusCode)
		}
	}

	return endpoints
}
