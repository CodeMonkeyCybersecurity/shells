// pkg/scanners/api/types.go
//
// API Security Scanner - Type Definitions
//
// Tests REST and GraphQL APIs for common security vulnerabilities:
// - GraphQL: Introspection, injection, DoS, batching attacks, field suggestions
// - REST: IDOR, mass assignment, rate limiting, HTTP verb tampering, excessive data exposure

package api

import "time"

// APIType represents the type of API
type APIType string

const (
	APITypeREST    APIType = "REST"
	APITypeGraphQL APIType = "GraphQL"
	APITypeSOAP    APIType = "SOAP"
	APITypeGRPC    APIType = "gRPC"
)

// APIVulnerabilityType represents specific API vulnerabilities
type APIVulnerabilityType string

const (
	// GraphQL vulnerabilities
	VulnGraphQLIntrospection   APIVulnerabilityType = "graphql_introspection_enabled"
	VulnGraphQLBatching        APIVulnerabilityType = "graphql_batching_attack"
	VulnGraphQLDepthLimit      APIVulnerabilityType = "graphql_depth_limit_missing"
	VulnGraphQLComplexityLimit APIVulnerabilityType = "graphql_complexity_limit_missing"
	VulnGraphQLFieldSuggestion APIVulnerabilityType = "graphql_field_suggestion"
	VulnGraphQLInjection       APIVulnerabilityType = "graphql_injection"

	// REST vulnerabilities
	VulnRESTIDOR                APIVulnerabilityType = "rest_idor"
	VulnRESTMassAssignment      APIVulnerabilityType = "rest_mass_assignment"
	VulnRESTRateLimiting        APIVulnerabilityType = "rest_rate_limiting_missing"
	VulnRESTHTTPVerbTampering   APIVulnerabilityType = "rest_http_verb_tampering"
	VulnRESTExcessiveData       APIVulnerabilityType = "rest_excessive_data_exposure"
	VulnRESTAuthBypass          APIVulnerabilityType = "rest_auth_bypass"
	VulnRESTPrivilegeEscalation APIVulnerabilityType = "rest_privilege_escalation"

	// Common API vulnerabilities
	VulnAPINoAuthentication APIVulnerabilityType = "api_no_authentication"
	VulnAPIWeakAuth         APIVulnerabilityType = "api_weak_authentication"
	VulnAPICORSMisconfigured APIVulnerabilityType = "api_cors_misconfigured"
	VulnAPIVersionDisclosure APIVulnerabilityType = "api_version_disclosure"
)

// APIFinding represents an API security finding
type APIFinding struct {
	Endpoint          string               `json:"endpoint"`
	APIType           APIType              `json:"api_type"`
	VulnerabilityType APIVulnerabilityType `json:"vulnerability_type"`
	Severity          string               `json:"severity"`
	Title             string               `json:"title"`
	Description       string               `json:"description"`
	Evidence          string               `json:"evidence"`
	Remediation       string               `json:"remediation"`

	// API-specific metadata
	Method         string                 `json:"method,omitempty"`
	RequestBody    string                 `json:"request_body,omitempty"`
	ResponseBody   string                 `json:"response_body,omitempty"`
	StatusCode     int                    `json:"status_code,omitempty"`
	Authentication string                 `json:"authentication,omitempty"`
	ExploitPayload string                 `json:"exploit_payload,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`

	DiscoveredAt time.Time `json:"discovered_at"`
}

// GraphQLSchema represents a discovered GraphQL schema
type GraphQLSchema struct {
	Types      []string          `json:"types"`
	Queries    []string          `json:"queries"`
	Mutations  []string          `json:"mutations"`
	Fields     map[string]string `json:"fields"`
	Introspect bool              `json:"introspection_enabled"`
}

// RESTEndpointInfo contains information about a REST API endpoint
type RESTEndpointInfo struct {
	URL            string            `json:"url"`
	Methods        []string          `json:"methods"`
	Parameters     []string          `json:"parameters"`
	Authentication bool              `json:"requires_authentication"`
	RateLimited    bool              `json:"rate_limited"`
	Headers        map[string]string `json:"headers"`
	ResponseFormat string            `json:"response_format"` // json, xml, etc.
}
