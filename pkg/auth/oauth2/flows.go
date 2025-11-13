package oauth2

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/auth/common"
)

// FlowAnalyzer analyzes OAuth2 flows for security vulnerabilities
type FlowAnalyzer struct {
	httpClient  *http.Client
	interceptor *RequestInterceptor
	logger      common.Logger
}

// NewFlowAnalyzer creates a new flow analyzer
func NewFlowAnalyzer(client *http.Client, logger common.Logger) *FlowAnalyzer {
	return &FlowAnalyzer{
		httpClient:  client,
		interceptor: NewRequestInterceptor(client, logger),
		logger:      logger,
	}
}

// OAuth2Flow represents an OAuth2 flow
type OAuth2Flow struct {
	Type                string                 `json:"type"`
	AuthorizationURL    string                 `json:"authorization_url"`
	TokenURL            string                 `json:"token_url"`
	ClientID            string                 `json:"client_id"`
	RedirectURI         string                 `json:"redirect_uri"`
	Scope               string                 `json:"scope"`
	State               string                 `json:"state"`
	CodeChallenge       string                 `json:"code_challenge,omitempty"`
	CodeChallengeMethod string                 `json:"code_challenge_method,omitempty"`
	Requests            []OAuth2Request        `json:"requests"`
	Responses           []OAuth2Response       `json:"responses"`
	Vulnerabilities     []common.Vulnerability `json:"vulnerabilities"`
	MultipleAS          bool                   `json:"multiple_as"`
	ASIdentifier        string                 `json:"as_identifier"`
}

// OAuth2Request represents an OAuth2 request
type OAuth2Request struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Step    string            `json:"step"`
}

// OAuth2Response represents an OAuth2 response
type OAuth2Response struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Step       string            `json:"step"`
}

// FlowAnalysis represents flow analysis results
type FlowAnalysis struct {
	Flow            OAuth2Flow             `json:"flow"`
	Vulnerabilities []common.Vulnerability `json:"vulnerabilities"`
	Summary         FlowSummary            `json:"summary"`
}

// FlowSummary provides analysis summary
type FlowSummary struct {
	FlowType        string   `json:"flow_type"`
	SecurityLevel   string   `json:"security_level"`
	PKCEEnabled     bool     `json:"pkce_enabled"`
	StateValidated  bool     `json:"state_validated"`
	NonceValidated  bool     `json:"nonce_validated"`
	VulnerableSteps []string `json:"vulnerable_steps"`
}

// RequestInterceptor captures OAuth2 flow requests
type RequestInterceptor struct {
	httpClient *http.Client
	logger     common.Logger
}

// NewRequestInterceptor creates a new request interceptor
func NewRequestInterceptor(client *http.Client, logger common.Logger) *RequestInterceptor {
	return &RequestInterceptor{
		httpClient: client,
		logger:     logger,
	}
}

// AnalyzeAuthFlow analyzes complete OAuth2 authentication flow
func (f *FlowAnalyzer) AnalyzeAuthFlow(startURL string) []common.Vulnerability {
	f.logger.Info("Starting OAuth2 flow analysis", "url", startURL)

	vulnerabilities := []common.Vulnerability{}

	// Capture the entire OAuth2 flow
	flow := f.interceptor.CaptureFlow(startURL)

	// Analyze each step of the flow
	checks := []FlowCheck{
		f.checkStateParameter,
		f.checkNonceParameter,
		f.checkPKCEImplementation,
		f.checkRedirectURIValidation,
		f.checkResponseTypeConfusion,
		f.checkScopeValidation,
		f.checkTokenBinding,
		f.checkMixUpAttack,
		f.checkCodeInjection,
		f.checkCSRFProtection,
	}

	for _, check := range checks {
		vulns := check(flow)
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	f.logger.Info("OAuth2 flow analysis completed", "vulnerabilities", len(vulnerabilities))

	return vulnerabilities
}

// FlowCheck represents a flow security check
type FlowCheck func(flow OAuth2Flow) []common.Vulnerability

// CaptureFlow captures an OAuth2 flow
func (r *RequestInterceptor) CaptureFlow(startURL string) OAuth2Flow {
	r.logger.Info("Capturing OAuth2 flow", "start_url", startURL)

	flow := OAuth2Flow{
		Type:         "authorization_code",
		Requests:     []OAuth2Request{},
		Responses:    []OAuth2Response{},
		MultipleAS:   false,
		ASIdentifier: "",
	}

	// Parse the authorization URL
	if authURL, err := url.Parse(startURL); err == nil {
		flow.AuthorizationURL = startURL

		// Extract parameters
		params := authURL.Query()
		flow.ClientID = params.Get("client_id")
		flow.RedirectURI = params.Get("redirect_uri")
		flow.Scope = params.Get("scope")
		flow.State = params.Get("state")
		flow.CodeChallenge = params.Get("code_challenge")
		flow.CodeChallengeMethod = params.Get("code_challenge_method")

		// Determine flow type
		responseType := params.Get("response_type")
		switch responseType {
		case "code":
			flow.Type = "authorization_code"
		case "token":
			flow.Type = "implicit"
		case "code token":
			flow.Type = "hybrid"
		}
	}

	// Simulate flow capture (in real implementation, this would use a browser/proxy)
	flow.Requests = append(flow.Requests, OAuth2Request{
		URL:    startURL,
		Method: "GET",
		Step:   "authorization_request",
	})

	return flow
}

// Flow security checks

func (f *FlowAnalyzer) checkStateParameter(flow OAuth2Flow) []common.Vulnerability {
	vulnerabilities := []common.Vulnerability{}

	// Check if state parameter is present
	if flow.State == "" {
		vuln := common.Vulnerability{
			ID:          "OAUTH2_MISSING_STATE",
			Type:        "State Parameter",
			Protocol:    common.ProtocolOAuth2,
			Severity:    "MEDIUM",
			Title:       "Missing State Parameter",
			Description: "OAuth2 flow missing state parameter",
			Impact:      "Vulnerable to CSRF attacks",
			Evidence: []common.Evidence{
				{
					Type:        "OAuth2_Flow",
					Description: "Authorization request without state parameter",
					Data:        flow.AuthorizationURL,
				},
			},
			Remediation: common.Remediation{
				Description: "Implement state parameter",
				Steps: []string{
					"Generate cryptographically secure state values",
					"Include state in authorization requests",
					"Validate state on callback",
				},
				Priority: "MEDIUM",
			},
			CVSS:      6.1,
			CWE:       "CWE-352",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// Check state entropy
	if len(flow.State) > 0 && len(flow.State) < 16 {
		vuln := common.Vulnerability{
			ID:          "OAUTH2_WEAK_STATE",
			Type:        "State Parameter",
			Protocol:    common.ProtocolOAuth2,
			Severity:    "MEDIUM",
			Title:       "Weak State Parameter",
			Description: "OAuth2 state parameter has insufficient entropy",
			Impact:      "State parameter may be predictable",
			Remediation: common.Remediation{
				Description: "Use cryptographically secure state values",
				Steps: []string{
					"Generate state with at least 128 bits of entropy",
					"Use cryptographically secure random generator",
					"Validate state length requirements",
				},
				Priority: "MEDIUM",
			},
			CVSS:      5.3,
			CWE:       "CWE-330",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities
}

func (f *FlowAnalyzer) checkNonceParameter(flow OAuth2Flow) []common.Vulnerability {
	vulnerabilities := []common.Vulnerability{}

	// Check nonce for OIDC flows
	if strings.Contains(flow.Scope, "openid") {
		// Parse authorization URL to check for nonce
		if authURL, err := url.Parse(flow.AuthorizationURL); err == nil {
			params := authURL.Query()
			nonce := params.Get("nonce")

			if nonce == "" {
				vuln := common.Vulnerability{
					ID:          "OIDC_MISSING_NONCE",
					Type:        "Nonce Parameter",
					Protocol:    common.ProtocolOIDC,
					Severity:    "MEDIUM",
					Title:       "Missing Nonce Parameter",
					Description: "OIDC flow missing nonce parameter",
					Impact:      "Vulnerable to replay attacks",
					Remediation: common.Remediation{
						Description: "Implement nonce parameter for OIDC",
						Steps: []string{
							"Generate unique nonce for each request",
							"Include nonce in authorization requests",
							"Validate nonce in ID tokens",
						},
						Priority: "MEDIUM",
					},
					CVSS:      5.4,
					CWE:       "CWE-294",
					CreatedAt: time.Now(),
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities
}

func (f *FlowAnalyzer) checkPKCEImplementation(flow OAuth2Flow) []common.Vulnerability {
	vulnerabilities := []common.Vulnerability{}

	// Check if PKCE is implemented
	if flow.CodeChallenge == "" {
		vuln := common.Vulnerability{
			ID:          "OAUTH2_MISSING_PKCE",
			Type:        "PKCE",
			Protocol:    common.ProtocolOAuth2,
			Severity:    "HIGH",
			Title:       "Missing PKCE Implementation",
			Description: "OAuth2 flow missing PKCE protection",
			Impact:      "Vulnerable to authorization code interception",
			Evidence: []common.Evidence{
				{
					Type:        "OAuth2_Flow",
					Description: "Authorization request without PKCE",
					Data:        flow.AuthorizationURL,
				},
			},
			Remediation: common.Remediation{
				Description: "Implement PKCE for OAuth2 flows",
				Steps: []string{
					"Generate code verifier and challenge",
					"Include code_challenge in authorization requests",
					"Send code_verifier in token requests",
					"Use S256 challenge method",
				},
				Priority: "HIGH",
			},
			CVSS:      7.5,
			CWE:       "CWE-319",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// Check PKCE method
	if flow.CodeChallengeMethod == "plain" {
		vuln := common.Vulnerability{
			ID:          "OAUTH2_WEAK_PKCE",
			Type:        "PKCE",
			Protocol:    common.ProtocolOAuth2,
			Severity:    "MEDIUM",
			Title:       "Weak PKCE Method",
			Description: "OAuth2 flow uses plain PKCE method instead of S256",
			Impact:      "PKCE protection is weaker than optimal",
			Remediation: common.Remediation{
				Description: "Use S256 PKCE method",
				Steps: []string{
					"Use S256 code challenge method",
					"Avoid plain PKCE method",
					"Implement proper PKCE validation",
				},
				Priority: "MEDIUM",
			},
			CVSS:      5.3,
			CWE:       "CWE-327",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities
}

func (f *FlowAnalyzer) checkRedirectURIValidation(flow OAuth2Flow) []common.Vulnerability {
	vulnerabilities := []common.Vulnerability{}

	// Check for common redirect URI vulnerabilities
	if flow.RedirectURI != "" {
		// Check for open redirects
		if f.testOpenRedirect(flow.RedirectURI) {
			vuln := common.Vulnerability{
				ID:          "OAUTH2_OPEN_REDIRECT",
				Type:        "Redirect URI",
				Protocol:    common.ProtocolOAuth2,
				Severity:    "HIGH",
				Title:       "Open Redirect Vulnerability",
				Description: "OAuth2 redirect URI vulnerable to open redirect",
				Impact:      "Attackers can redirect users to malicious sites",
				Evidence: []common.Evidence{
					{
						Type:        "Redirect_URI",
						Description: "Vulnerable redirect URI",
						Data:        flow.RedirectURI,
					},
				},
				Remediation: common.Remediation{
					Description: "Implement strict redirect URI validation",
					Steps: []string{
						"Use exact match for redirect URIs",
						"Implement redirect URI whitelist",
						"Validate URI components",
					},
					Priority: "HIGH",
				},
				CVSS:      8.1,
				CWE:       "CWE-601",
				CreatedAt: time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}

		// Check for subdomain takeover risks
		if f.testSubdomainTakeover(flow.RedirectURI) {
			vuln := common.Vulnerability{
				ID:          "OAUTH2_SUBDOMAIN_TAKEOVER",
				Type:        "Redirect URI",
				Protocol:    common.ProtocolOAuth2,
				Severity:    "HIGH",
				Title:       "Subdomain Takeover Risk",
				Description: "OAuth2 redirect URI may be vulnerable to subdomain takeover",
				Impact:      "Attackers can take over subdomains and intercept codes",
				Remediation: common.Remediation{
					Description: "Avoid wildcard redirect URIs",
					Steps: []string{
						"Use specific redirect URIs",
						"Avoid wildcard domains",
						"Monitor subdomain registrations",
					},
					Priority: "HIGH",
				},
				CVSS:      7.5,
				CWE:       "CWE-20",
				CreatedAt: time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities
}

func (f *FlowAnalyzer) checkResponseTypeConfusion(flow OAuth2Flow) []common.Vulnerability {
	vulnerabilities := []common.Vulnerability{}

	// Check for response type confusion
	if f.testResponseTypeConfusion(flow) {
		vuln := common.Vulnerability{
			ID:          "OAUTH2_RESPONSE_TYPE_CONFUSION",
			Type:        "Response Type",
			Protocol:    common.ProtocolOAuth2,
			Severity:    "MEDIUM",
			Title:       "Response Type Confusion",
			Description: "OAuth2 flow vulnerable to response type confusion",
			Impact:      "Attackers can confuse response type handling",
			Remediation: common.Remediation{
				Description: "Implement strict response type validation",
				Steps: []string{
					"Validate response type parameter",
					"Use specific response type handlers",
					"Implement response type whitelist",
				},
				Priority: "MEDIUM",
			},
			CVSS:      5.4,
			CWE:       "CWE-346",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities
}

func (f *FlowAnalyzer) checkScopeValidation(flow OAuth2Flow) []common.Vulnerability {
	vulnerabilities := []common.Vulnerability{}

	// Check for scope escalation
	if f.testScopeEscalation(flow) {
		vuln := common.Vulnerability{
			ID:          "OAUTH2_SCOPE_ESCALATION",
			Type:        "Scope Validation",
			Protocol:    common.ProtocolOAuth2,
			Severity:    "HIGH",
			Title:       "Scope Escalation Vulnerability",
			Description: "OAuth2 flow allows scope escalation",
			Impact:      "Attackers can request higher privileges than intended",
			Remediation: common.Remediation{
				Description: "Implement strict scope validation",
				Steps: []string{
					"Validate requested scopes",
					"Implement scope restrictions",
					"Use principle of least privilege",
				},
				Priority: "HIGH",
			},
			CVSS:      7.5,
			CWE:       "CWE-269",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities
}

func (f *FlowAnalyzer) checkTokenBinding(flow OAuth2Flow) []common.Vulnerability {
	vulnerabilities := []common.Vulnerability{}

	// Check for token binding
	if f.testTokenBinding(flow) {
		vuln := common.Vulnerability{
			ID:          "OAUTH2_MISSING_TOKEN_BINDING",
			Type:        "Token Binding",
			Protocol:    common.ProtocolOAuth2,
			Severity:    "MEDIUM",
			Title:       "Missing Token Binding",
			Description: "OAuth2 flow missing token binding",
			Impact:      "Tokens can be used by unintended parties",
			Remediation: common.Remediation{
				Description: "Implement token binding",
				Steps: []string{
					"Use certificate-bound tokens",
					"Implement DPoP (Demonstration of Proof-of-Possession)",
					"Bind tokens to client certificates",
				},
				Priority: "MEDIUM",
			},
			CVSS:      5.4,
			CWE:       "CWE-346",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities
}

func (f *FlowAnalyzer) checkMixUpAttack(flow OAuth2Flow) []common.Vulnerability {
	vulnerabilities := []common.Vulnerability{}

	// Check for mix-up attack vulnerability
	if f.detectMixUpAttack(flow) {
		vuln := common.Vulnerability{
			ID:          "OAUTH2_MIXUP_ATTACK",
			Type:        "Mix-Up Attack",
			Protocol:    common.ProtocolOAuth2,
			Severity:    "CRITICAL",
			Title:       "OAuth2 Mix-Up Attack Vulnerability",
			Description: "OAuth2 flow vulnerable to mix-up attacks",
			Impact:      "Attackers can confuse authorization server identity",
			Remediation: common.Remediation{
				Description: "Implement authorization server identification",
				Steps: []string{
					"Include issuer in responses",
					"Validate authorization server identity",
					"Use different redirect URIs per AS",
				},
				Priority: "CRITICAL",
			},
			CVSS:      9.1,
			CWE:       "CWE-346",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities
}

func (f *FlowAnalyzer) checkCodeInjection(flow OAuth2Flow) []common.Vulnerability {
	vulnerabilities := []common.Vulnerability{}

	// Check for authorization code injection
	if f.testCodeInjection(flow) {
		vuln := common.Vulnerability{
			ID:          "OAUTH2_CODE_INJECTION",
			Type:        "Code Injection",
			Protocol:    common.ProtocolOAuth2,
			Severity:    "CRITICAL",
			Title:       "Authorization Code Injection",
			Description: "OAuth2 flow vulnerable to authorization code injection",
			Impact:      "Attackers can inject authorization codes for account takeover",
			Remediation: common.Remediation{
				Description: "Implement PKCE and proper validation",
				Steps: []string{
					"Implement PKCE for all flows",
					"Validate code-to-client binding",
					"Use nonce in OIDC flows",
				},
				Priority: "CRITICAL",
			},
			CVSS:      9.8,
			CWE:       "CWE-94",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities
}

func (f *FlowAnalyzer) checkCSRFProtection(flow OAuth2Flow) []common.Vulnerability {
	vulnerabilities := []common.Vulnerability{}

	// Check for CSRF protection
	if flow.State == "" {
		vuln := common.Vulnerability{
			ID:          "OAUTH2_CSRF_VULNERABLE",
			Type:        "CSRF Protection",
			Protocol:    common.ProtocolOAuth2,
			Severity:    "MEDIUM",
			Title:       "CSRF Vulnerability",
			Description: "OAuth2 flow vulnerable to CSRF attacks",
			Impact:      "Attackers can perform unauthorized OAuth2 actions",
			Remediation: common.Remediation{
				Description: "Implement state parameter and CSRF protection",
				Steps: []string{
					"Use state parameter for CSRF protection",
					"Implement additional CSRF tokens",
					"Validate request origin",
				},
				Priority: "MEDIUM",
			},
			CVSS:      6.1,
			CWE:       "CWE-352",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities
}

// Helper methods for testing

func (f *FlowAnalyzer) testOpenRedirect(redirectURI string) bool {
	// Test for open redirect vulnerability
	return false // Placeholder
}

func (f *FlowAnalyzer) testSubdomainTakeover(redirectURI string) bool {
	// Test for subdomain takeover risk
	return false // Placeholder
}

func (f *FlowAnalyzer) testResponseTypeConfusion(flow OAuth2Flow) bool {
	// Test for response type confusion
	return false // Placeholder
}

func (f *FlowAnalyzer) testScopeEscalation(flow OAuth2Flow) bool {
	// Test for scope escalation
	return false // Placeholder
}

func (f *FlowAnalyzer) testTokenBinding(flow OAuth2Flow) bool {
	// Test for token binding
	return false // Placeholder
}

func (f *FlowAnalyzer) detectMixUpAttack(flow OAuth2Flow) bool {
	// Detect mix-up attack vulnerability
	return flow.MultipleAS && flow.ASIdentifier == ""
}

func (f *FlowAnalyzer) testCodeInjection(flow OAuth2Flow) bool {
	// Test for code injection
	return false // Placeholder
}

// UsesMultipleAS checks if flow uses multiple authorization servers
func (flow OAuth2Flow) UsesMultipleAS() bool {
	return flow.MultipleAS
}

// HasASIdentifier checks if flow has authorization server identifier
func (flow OAuth2Flow) HasASIdentifier() bool {
	return flow.ASIdentifier != ""
}
