package common

import (
	"crypto/x509"
	"net/http"
	"time"
)

// AuthProtocol represents different authentication protocols
type AuthProtocol string

const (
	ProtocolSAML     AuthProtocol = "SAML"
	ProtocolOAuth2   AuthProtocol = "OAuth2"
	ProtocolOIDC     AuthProtocol = "OIDC"
	ProtocolWebAuthn AuthProtocol = "WebAuthn"
	ProtocolFIDO2    AuthProtocol = "FIDO2"
	ProtocolJWT      AuthProtocol = "JWT"
)

// Vulnerability represents a security vulnerability in authentication
type Vulnerability struct {
	ID          string       `json:"id"`
	Type        string       `json:"type"`
	Protocol    AuthProtocol `json:"protocol"`
	Severity    string       `json:"severity"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Impact      string       `json:"impact"`
	Evidence    []Evidence   `json:"evidence"`
	References  []string     `json:"references"`
	Remediation Remediation  `json:"remediation"`
	CVSS        float64      `json:"cvss"`
	CWE         string       `json:"cwe"`
	CreatedAt   time.Time    `json:"created_at"`
}

// Evidence represents proof of a vulnerability
type Evidence struct {
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Data        string            `json:"data"`
	Headers     map[string]string `json:"headers,omitempty"`
	Request     *http.Request     `json:"request,omitempty"`
	Response    *http.Response    `json:"response,omitempty"`
	Payload     string            `json:"payload,omitempty"`
}

// Remediation provides fix guidance
type Remediation struct {
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
	References  []string `json:"references"`
	Priority    string   `json:"priority"`
}

// AttackChain represents a sequence of attacks
type AttackChain struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	Description   string       `json:"description"`
	Steps         []AttackStep `json:"steps"`
	Impact        string       `json:"impact"`
	Severity      string       `json:"severity"`
	Prerequisites []string     `json:"prerequisites"`
	Mitigations   []string     `json:"mitigations"`
}

// AttackStep represents a single step in an attack chain
type AttackStep struct {
	Order       int          `json:"order"`
	Protocol    AuthProtocol `json:"protocol"`
	Technique   string       `json:"technique"`
	Description string       `json:"description"`
	Payload     string       `json:"payload,omitempty"`
	Evidence    []Evidence   `json:"evidence"`
	Success     bool         `json:"success"`
}

// AuthEndpoint represents an authentication endpoint
type AuthEndpoint struct {
	URL      string            `json:"url"`
	Protocol AuthProtocol      `json:"protocol"`
	Method   string            `json:"method"`
	Headers  map[string]string `json:"headers"`
	Metadata map[string]string `json:"metadata"`
	Verified bool              `json:"verified"`
}

// AuthConfiguration represents authentication configuration
type AuthConfiguration struct {
	Endpoints    []AuthEndpoint     `json:"endpoints"`
	Protocols    []AuthProtocol     `json:"protocols"`
	Certificates []x509.Certificate `json:"certificates"`
	Metadata     map[string]string  `json:"metadata"`
}

// Finding represents a general security finding
type Finding struct {
	ID          string     `json:"id"`
	Type        string     `json:"type"`
	Severity    string     `json:"severity"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	URL         string     `json:"url"`
	Method      string     `json:"method"`
	Evidence    []Evidence `json:"evidence"`
	Risk        string     `json:"risk"`
	Confidence  string     `json:"confidence"`
	CreatedAt   time.Time  `json:"created_at"`
}

// TestResult represents the result of a single security test
type TestResult struct {
	Name        string       `json:"name"`
	Protocol    AuthProtocol `json:"protocol"`
	Vulnerable  bool         `json:"vulnerable"`
	Severity    string       `json:"severity"`
	Description string       `json:"description"`
	Evidence    []Evidence   `json:"evidence,omitempty"`
	ExecutedAt  time.Time    `json:"executed_at"`
}

// AuthReport represents the main authentication report
type AuthReport struct {
	Target          string                 `json:"target"`
	StartTime       time.Time              `json:"start_time"`
	EndTime         time.Time              `json:"end_time"`
	Configuration   AuthConfiguration      `json:"configuration"`
	Vulnerabilities []Vulnerability        `json:"vulnerabilities"`
	AttackChains    []AttackChain          `json:"attack_chains"`
	Tests           []TestResult           `json:"tests"` // Individual test results for audit trail
	Summary         ReportSummary          `json:"summary"`
	Protocols       map[string]interface{} `json:"protocols"`
}

// ReportSummary provides high-level statistics
type ReportSummary struct {
	TotalVulnerabilities int            `json:"total_vulnerabilities"`
	BySeverity           map[string]int `json:"by_severity"`
	ByProtocol           map[string]int `json:"by_protocol"`
	HighestSeverity      string         `json:"highest_severity"`
	AttackChains         int            `json:"attack_chains"`
	Exploitable          int            `json:"exploitable"`
}

// Scanner interface for all authentication scanners
type Scanner interface {
	Scan(target string, options map[string]interface{}) (*AuthReport, error)
	GetProtocol() AuthProtocol
	GetCapabilities() []string
}

// Analyzer interface for vulnerability analysis
type Analyzer interface {
	Analyze(config AuthConfiguration) []Vulnerability
	GetProtocol() AuthProtocol
}

// High-value authentication vulnerabilities for bug bounties
var HighValueVulnerabilities = map[string]struct {
	Severity    string
	Impact      string
	BountyValue string
}{
	"SAML_GOLDEN_TICKET": {
		Severity:    "CRITICAL",
		Impact:      "Complete authentication bypass",
		BountyValue: "HIGH",
	},
	"SAML_SIGNATURE_EXCLUSION": {
		Severity:    "CRITICAL",
		Impact:      "Forge any user identity",
		BountyValue: "HIGH",
	},
	"OAUTH2_CODE_INJECTION": {
		Severity:    "CRITICAL",
		Impact:      "Account takeover",
		BountyValue: "HIGH",
	},
	"JWT_NONE_ALGORITHM": {
		Severity:    "CRITICAL",
		Impact:      "Token forgery",
		BountyValue: "HIGH",
	},
	"WEBAUTHN_DOWNGRADE": {
		Severity:    "HIGH",
		Impact:      "Bypass strong authentication",
		BountyValue: "MEDIUM",
	},
	"FEDERATION_CONFUSION": {
		Severity:    "CRITICAL",
		Impact:      "Authenticate as any federated user",
		BountyValue: "HIGH",
	},
}
