package scim

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// SCIMEndpoint represents a discovered SCIM endpoint
type SCIMEndpoint struct {
	URL             string                 `json:"url"`
	Version         string                 `json:"version"`
	AuthType        string                 `json:"auth_type"`
	Resources       []string               `json:"resources"`
	Schemas         []string               `json:"schemas"`
	Operations      []string               `json:"operations"`
	BulkSupported   bool                   `json:"bulk_supported"`
	FilterSupported bool                   `json:"filter_supported"`
	SortSupported   bool                   `json:"sort_supported"`
	ETagSupported   bool                   `json:"etag_supported"`
	Metadata        map[string]interface{} `json:"metadata"`
	DiscoveredAt    time.Time              `json:"discovered_at"`
}

// SCIMVulnerability represents a SCIM-specific vulnerability
type SCIMVulnerability struct {
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	Severity    types.Severity `json:"severity"`
	Endpoint    string         `json:"endpoint"`
	Resource    string         `json:"resource,omitempty"`
	Method      string         `json:"method,omitempty"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Details     string         `json:"details"`
	Impact      string         `json:"impact"`
	PoC         string         `json:"poc,omitempty"`
	Evidence    []Evidence     `json:"evidence"`
	Remediation Remediation    `json:"remediation"`
	CVSS        float64        `json:"cvss"`
	CWE         string         `json:"cwe"`
	References  []string       `json:"references"`
	CreatedAt   time.Time      `json:"created_at"`
}

// Evidence represents evidence for a vulnerability
type Evidence struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Request     *HTTPRequest           `json:"request,omitempty"`
	Response    *HTTPResponse          `json:"response,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// HTTPRequest represents an HTTP request
type HTTPRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Time       time.Duration     `json:"time"`
}

// Remediation represents remediation steps
type Remediation struct {
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
	Priority    string   `json:"priority"`
}

// AuthMethod represents authentication method
type AuthMethod struct {
	Type     string `json:"type"`
	Token    string `json:"token,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// FilterPayload represents a SCIM filter injection payload
type FilterPayload struct {
	Name        string `json:"name"`
	Filter      string `json:"filter"`
	Expected    string `json:"expected"`
	Impact      string `json:"impact"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// BulkOperation represents a SCIM bulk operation
type BulkOperation struct {
	Method  string                 `json:"method"`
	BulkID  string                 `json:"bulkId"`
	Path    string                 `json:"path"`
	Data    map[string]interface{} `json:"data"`
	Version string                 `json:"version,omitempty"`
}

// BulkRequest represents a SCIM bulk request
type BulkRequest struct {
	FailOnErrors int             `json:"failOnErrors"`
	Operations   []BulkOperation `json:"Operations"`
}

// SCIMResource represents a SCIM resource
type SCIMResource struct {
	ID         string                 `json:"id"`
	ExternalID string                 `json:"externalId,omitempty"`
	Meta       map[string]interface{} `json:"meta"`
	Schemas    []string               `json:"schemas"`
	Data       map[string]interface{} `json:"data"`
}

// SCIMError represents a SCIM error response
type SCIMError struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail"`
	ScimType string   `json:"scimType,omitempty"`
}

// SCIMConfig represents scanner configuration
type SCIMConfig struct {
	AuthToken          string        `json:"auth_token"`
	AuthType           string        `json:"auth_type"`
	Username           string        `json:"username"`
	Password           string        `json:"password"`
	Timeout            time.Duration `json:"timeout"`
	MaxRetries         int           `json:"max_retries"`
	UserAgent          string        `json:"user_agent"`
	FollowRedirects    bool          `json:"follow_redirects"`
	VerifySSL          bool          `json:"verify_ssl"`
	MaxBulkOperations  int           `json:"max_bulk_operations"`
	TestAuthentication bool          `json:"test_authentication"`
	TestProvisions     bool          `json:"test_provisions"`
	TestFilters        bool          `json:"test_filters"`
	TestBulkOps        bool          `json:"test_bulk_ops"`
}

// Constants for SCIM vulnerability types
const (
	VulnSCIMFilterInjection     = "SCIM_FILTER_INJECTION"
	VulnSCIMUserEnumeration     = "SCIM_USER_ENUMERATION"
	VulnSCIMUnauthorizedAccess  = "SCIM_UNAUTHORIZED_ACCESS"
	VulnSCIMBulkAbuse           = "SCIM_BULK_ABUSE"
	VulnSCIMSchemaDisclosure    = "SCIM_SCHEMA_DISCLOSURE"
	VulnSCIMProvisionAbuse      = "SCIM_PROVISION_ABUSE"
	VulnSCIMWeakAuthentication  = "SCIM_WEAK_AUTHENTICATION"
	VulnSCIMRateLimitBypass     = "SCIM_RATE_LIMIT_BYPASS"
	VulnSCIMDataExfiltration    = "SCIM_DATA_EXFILTRATION"
	VulnSCIMPrivilegeEscalation = "SCIM_PRIVILEGE_ESCALATION"
)

// SCIM standard schemas
const (
	SchemaUser            = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup           = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaServiceProvider = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResourceType    = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchema          = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	SchemaError           = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaBulkRequest     = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	SchemaBulkResponse    = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"
	SchemaSearchRequest   = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"
	SchemaListResponse    = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaPatchOp         = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

// SCIM standard resource types
const (
	ResourceTypeUser  = "User"
	ResourceTypeGroup = "Group"
)

// SCIM standard operations
const (
	OperationCreate = "POST"
	OperationRead   = "GET"
	OperationUpdate = "PUT"
	OperationPatch  = "PATCH"
	OperationDelete = "DELETE"
)
