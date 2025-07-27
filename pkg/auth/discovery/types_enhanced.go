package discovery

import (
	"regexp"
	"time"
)

// Enhanced authentication types for comprehensive discovery
type AuthType string

const (
	// Modern authentication types
	AuthTypeOAuth2   AuthType = "oauth2"
	AuthTypeOIDC     AuthType = "oidc"
	AuthTypeSAML     AuthType = "saml"
	AuthTypeWebAuthn AuthType = "webauthn"
	AuthTypeFIDO2    AuthType = "fido2"
	AuthTypeJWT      AuthType = "jwt"

	// Traditional authentication types
	AuthTypeBasicAuth  AuthType = "basic"
	AuthTypeDigestAuth AuthType = "digest"
	AuthTypeFormLogin  AuthType = "form"
	AuthTypeCookie     AuthType = "cookie"
	AuthTypeAPIKey     AuthType = "apikey"
	AuthTypeCustom     AuthType = "custom"

	// Directory services
	AuthTypeLDAP      AuthType = "ldap"
	AuthTypeKerberos  AuthType = "kerberos"
	AuthTypeNTLM      AuthType = "ntlm"
	AuthTypeActiveDir AuthType = "activedirectory"

	// Multi-factor authentication
	AuthTypeTOTP AuthType = "totp"
	AuthTypeSMS  AuthType = "sms"
	AuthTypeU2F  AuthType = "u2f"
	AuthTypePush AuthType = "push"

	// JavaScript-based authentication
	AuthTypeJavaScript AuthType = "javascript"

	// Unknown/unidentified
	AuthTypeUnknown AuthType = "unknown"
)

// AuthImplementation represents a discovered authentication implementation
type AuthImplementation struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Type             AuthType               `json:"type"`
	Domain           string                 `json:"domain"`
	Endpoints        []AuthEndpoint         `json:"endpoints"`
	Flows            []AuthFlow             `json:"flows"`
	Technologies     []string               `json:"technologies"`
	SecurityFeatures []string               `json:"security_features"`
	Vulnerabilities  []string               `json:"vulnerabilities"`
	Metadata         map[string]interface{} `json:"metadata"`
	Confidence       float64                `json:"confidence"`
	DiscoveredAt     time.Time              `json:"discovered_at"`
	LastSeen         time.Time              `json:"last_seen"`
}

// AuthEndpoint represents a discovered authentication endpoint
type AuthEndpoint struct {
	ID         string                 `json:"id"`
	URL        string                 `json:"url"`
	Type       AuthType               `json:"type"`
	Methods    []string               `json:"methods"`
	Parameters []AuthParameter        `json:"parameters"`
	Headers    map[string]string      `json:"headers"`
	Cookies    map[string]string      `json:"cookies"`
	Metadata   map[string]interface{} `json:"metadata"`
	Confidence float64                `json:"confidence"`
}

// AuthParameter represents an authentication parameter
type AuthParameter struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Location    string                 `json:"location"` // query, header, body, cookie
	Required    bool                   `json:"required"`
	Constraints []string               `json:"constraints,omitempty"`
	Example     string                 `json:"example,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AuthFlow represents an authentication flow (login process)
type AuthFlow struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Type          string                 `json:"type"`
	Steps         []AuthFlowStep         `json:"steps"`
	TotalSteps    int                    `json:"total_steps"`
	RequiresMFA   bool                   `json:"requires_mfa"`
	Metadata      map[string]interface{} `json:"metadata"`
	Description   string                 `json:"description,omitempty"`
	StartURL      string                 `json:"start_url,omitempty"`
	CompleteURL   string                 `json:"complete_url,omitempty"`
	ErrorHandling string                 `json:"error_handling,omitempty"`
}

// AuthFlowStep represents a step in an authentication flow
type AuthFlowStep struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	URL         string          `json:"url"`
	Method      string          `json:"method"`
	Parameters  []AuthParameter `json:"parameters"`
	Headers     []string        `json:"headers,omitempty"`
	Description string          `json:"description,omitempty"`
	Optional    bool            `json:"optional,omitempty"`
	Order       int             `json:"order"`
}

// AuthSignal represents a detected authentication signal
type AuthSignal struct {
	Type       string                 `json:"type"`
	Source     string                 `json:"source"`     // where it was found
	Location   string                 `json:"location"`   // URL, header, etc.
	Content    string                 `json:"content"`    // raw content
	Data       map[string]interface{} `json:"data"`       // parsed data
	Confidence float64                `json:"confidence"` // 0.0 - 1.0
	Timestamp  time.Time              `json:"timestamp"`
}

// AuthTechnology represents a detected authentication technology
type AuthTechnology struct {
	Name        string   `json:"name"`
	Version     string   `json:"version,omitempty"`
	Vendor      string   `json:"vendor,omitempty"`
	Category    string   `json:"category"`
	Confidence  float64  `json:"confidence"`
	Indicators  []string `json:"indicators"`
	Description string   `json:"description,omitempty"`
}

// AuthEndpointPattern represents patterns for discovering auth endpoints
type AuthEndpointPattern struct {
	Pattern     *regexp.Regexp `json:"-"`
	PatternStr  string         `json:"pattern"`
	Type        AuthType       `json:"type"`
	Method      string         `json:"method,omitempty"`
	Description string         `json:"description"`
	Priority    int            `json:"priority"`
}

// DiscoveryResult represents the result of authentication discovery
type DiscoveryResult struct {
	Target          string                 `json:"target"`
	DiscoveryTime   time.Duration          `json:"discovery_time"`
	TotalEndpoints  int                    `json:"total_endpoints"`
	Implementations []AuthImplementation   `json:"implementations"`
	Technologies    []AuthTechnology       `json:"technologies"`
	RiskScore       float64                `json:"risk_score"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
	DiscoveredAt    time.Time              `json:"discovered_at"`
}

// Config represents configuration for authentication discovery
type Config struct {
	MaxDepth           int           `yaml:"max_depth"`
	FollowRedirects    bool          `yaml:"follow_redirects"`
	MaxRedirects       int           `yaml:"max_redirects"`
	Timeout            time.Duration `yaml:"timeout"`
	UserAgent          string        `yaml:"user_agent"`
	Threads            int           `yaml:"threads"`
	EnableJSAnalysis   bool          `yaml:"enable_js_analysis"`
	EnableAPIDiscovery bool          `yaml:"enable_api_discovery"`
	EnablePortScanning bool          `yaml:"enable_port_scanning"`
	CustomPorts        []int         `yaml:"custom_ports"`
}

// OrgAuthReport represents organization-wide authentication report
type OrgAuthReport struct {
	Organization         string                 `json:"organization"`
	AllImplementations   []AuthImplementation   `json:"all_implementations"`
	UniqueAuthTypes      []AuthType             `json:"unique_auth_types"`
	AuthTypeDistribution map[AuthType]int       `json:"auth_type_distribution"`
	DomainsByAuthType    map[AuthType][]string  `json:"domains_by_auth_type"`
	HighRiskFindings     []string               `json:"high_risk_findings"`
	Recommendations      []string               `json:"recommendations"`
	TotalDomains         int                    `json:"total_domains"`
	DomainsWithAuth      int                    `json:"domains_with_auth"`
	RiskScore            float64                `json:"risk_score"`
	GeneratedAt          time.Time              `json:"generated_at"`
	Metadata             map[string]interface{} `json:"metadata"`
}

// Helper function to deduplicate strings
func deduplicateStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}
