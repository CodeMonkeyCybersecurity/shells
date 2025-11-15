package oauth2

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/auth/common"
)

// OAuth2Discoverer discovers OAuth2/OIDC endpoints
type OAuth2Discoverer struct {
	httpClient *http.Client
	logger     common.Logger
}

// NewOAuth2Discoverer creates a new OAuth2 discoverer
func NewOAuth2Discoverer(client *http.Client, logger common.Logger) *OAuth2Discoverer {
	return &OAuth2Discoverer{
		httpClient: client,
		logger:     logger,
	}
}

// OIDCConfiguration represents OIDC configuration
type OIDCConfiguration struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	UserInfoEndpoint              string   `json:"userinfo_endpoint"`
	JWKSUri                       string   `json:"jwks_uri"`
	ScopesSupported               []string `json:"scopes_supported"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	TokenEndpointAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

// DiscoverEndpoints discovers OAuth2/OIDC endpoints
func (d *OAuth2Discoverer) DiscoverEndpoints(target string) (*common.AuthConfiguration, error) {
	d.logger.Info("Discovering OAuth2/OIDC endpoints", "target", target)

	config := &common.AuthConfiguration{
		Endpoints: []common.AuthEndpoint{},
		Protocols: []common.AuthProtocol{},
		Metadata:  make(map[string]string),
	}

	// Try OIDC discovery
	if oidcConfig := d.discoverOIDCConfiguration(target); oidcConfig != nil {
		d.addOIDCEndpoints(config, oidcConfig)
	}

	// Try manual OAuth2 discovery
	d.discoverOAuth2Endpoints(config, target)

	// Set protocols
	if len(config.Endpoints) > 0 {
		config.Protocols = append(config.Protocols, common.ProtocolOAuth2)

		// Check if it's OIDC
		for _, endpoint := range config.Endpoints {
			if endpoint.Metadata["type"] == "oidc" {
				config.Protocols = append(config.Protocols, common.ProtocolOIDC)
				break
			}
		}
	}

	d.logger.Info("OAuth2/OIDC discovery completed", "endpoints", len(config.Endpoints))

	if len(config.Endpoints) == 0 {
		return nil, nil
	}

	return config, nil
}

// discoverOIDCConfiguration discovers OIDC configuration
func (d *OAuth2Discoverer) discoverOIDCConfiguration(target string) *OIDCConfiguration {
	// Try well-known OIDC discovery endpoint
	discoveryURL := strings.TrimSuffix(target, "/") + "/.well-known/openid_configuration"

	resp, err := d.httpClient.Get(discoveryURL)
	if err != nil {
		d.logger.Debug("OIDC discovery failed", "url", discoveryURL, "error", err)
		return nil
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != 200 {
		d.logger.Debug("OIDC discovery endpoint not found", "url", discoveryURL, "status", resp.StatusCode)
		return nil
	}

	var config OIDCConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		d.logger.Debug("Failed to parse OIDC configuration", "error", err)
		return nil
	}

	d.logger.Info("OIDC configuration discovered", "issuer", config.Issuer)

	return &config
}

// addOIDCEndpoints adds OIDC endpoints to configuration
func (d *OAuth2Discoverer) addOIDCEndpoints(config *common.AuthConfiguration, oidcConfig *OIDCConfiguration) {
	// Authorization endpoint
	if oidcConfig.AuthorizationEndpoint != "" {
		endpoint := common.AuthEndpoint{
			URL:      oidcConfig.AuthorizationEndpoint,
			Protocol: common.ProtocolOIDC,
			Method:   "GET",
			Headers:  make(map[string]string),
			Metadata: map[string]string{
				"type":   "oidc",
				"role":   "authorization",
				"issuer": oidcConfig.Issuer,
			},
		}
		config.Endpoints = append(config.Endpoints, endpoint)
	}

	// Token endpoint
	if oidcConfig.TokenEndpoint != "" {
		endpoint := common.AuthEndpoint{
			URL:      oidcConfig.TokenEndpoint,
			Protocol: common.ProtocolOAuth2,
			Method:   "POST",
			Headers:  make(map[string]string),
			Metadata: map[string]string{
				"type":   "oidc",
				"role":   "token",
				"issuer": oidcConfig.Issuer,
			},
		}
		config.Endpoints = append(config.Endpoints, endpoint)
	}

	// UserInfo endpoint
	if oidcConfig.UserInfoEndpoint != "" {
		endpoint := common.AuthEndpoint{
			URL:      oidcConfig.UserInfoEndpoint,
			Protocol: common.ProtocolOIDC,
			Method:   "GET",
			Headers:  make(map[string]string),
			Metadata: map[string]string{
				"type":   "oidc",
				"role":   "userinfo",
				"issuer": oidcConfig.Issuer,
			},
		}
		config.Endpoints = append(config.Endpoints, endpoint)
	}

	// JWKS endpoint
	if oidcConfig.JWKSUri != "" {
		endpoint := common.AuthEndpoint{
			URL:      oidcConfig.JWKSUri,
			Protocol: common.ProtocolOAuth2,
			Method:   "GET",
			Headers:  make(map[string]string),
			Metadata: map[string]string{
				"type":   "oidc",
				"role":   "jwks",
				"issuer": oidcConfig.Issuer,
			},
		}
		config.Endpoints = append(config.Endpoints, endpoint)
	}

	// Store OIDC configuration in metadata
	configJSON, _ := json.Marshal(oidcConfig)
	config.Metadata["oidc_configuration"] = string(configJSON)
}

// discoverOAuth2Endpoints discovers OAuth2 endpoints manually
func (d *OAuth2Discoverer) discoverOAuth2Endpoints(config *common.AuthConfiguration, target string) {
	// Common OAuth2 paths
	oauth2Paths := []struct {
		path string
		role string
	}{
		{"/oauth2/authorize", "authorization"},
		{"/oauth2/token", "token"},
		{"/oauth/authorize", "authorization"},
		{"/oauth/token", "token"},
		{"/auth/oauth2/authorize", "authorization"},
		{"/auth/oauth2/token", "token"},
		{"/auth/oauth/authorize", "authorization"},
		{"/auth/oauth/token", "token"},
		{"/api/oauth2/authorize", "authorization"},
		{"/api/oauth2/token", "token"},
		{"/connect/authorize", "authorization"},
		{"/connect/token", "token"},
	}

	baseURL := strings.TrimSuffix(target, "/")

	for _, pathInfo := range oauth2Paths {
		fullURL := baseURL + pathInfo.path

		resp, err := d.httpClient.Get(fullURL)
		if err != nil {
			continue
		}
		httpclient.CloseBody(resp)

		// Check if endpoint exists (may return 400 for missing parameters)
		if resp.StatusCode == 200 || resp.StatusCode == 400 || resp.StatusCode == 302 {
			method := "GET"
			if pathInfo.role == "token" {
				method = "POST"
			}

			endpoint := common.AuthEndpoint{
				URL:      fullURL,
				Protocol: common.ProtocolOAuth2,
				Method:   method,
				Headers:  make(map[string]string),
				Metadata: map[string]string{
					"type": "oauth2",
					"role": pathInfo.role,
				},
			}

			config.Endpoints = append(config.Endpoints, endpoint)
		}
	}
}

// OAuth2AttackGenerator generates OAuth2 attacks
type OAuth2AttackGenerator struct {
	httpClient *http.Client
	logger     common.Logger
}

// NewOAuth2AttackGenerator creates a new attack generator
func NewOAuth2AttackGenerator(client *http.Client, logger common.Logger) *OAuth2AttackGenerator {
	return &OAuth2AttackGenerator{
		httpClient: client,
		logger:     logger,
	}
}

// OAuth2Attack represents an OAuth2 attack
type OAuth2Attack struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Type        string            `json:"type"`
	Severity    string            `json:"severity"`
	Parameters  map[string]string `json:"parameters"`
	Payload     string            `json:"payload"`
	Success     bool              `json:"success"`
}

// GenerateOAuth2Attacks generates OAuth2 attacks
func (g *OAuth2AttackGenerator) GenerateOAuth2Attacks(config common.AuthConfiguration) []OAuth2Attack {
	attacks := []OAuth2Attack{}

	// Generate attacks based on discovered endpoints
	for _, endpoint := range config.Endpoints {
		switch endpoint.Metadata["role"] {
		case "authorization":
			attacks = append(attacks, g.generateAuthorizationAttacks(endpoint)...)
		case "token":
			attacks = append(attacks, g.generateTokenAttacks(endpoint)...)
		}
	}

	return attacks
}

// generateAuthorizationAttacks generates authorization endpoint attacks
func (g *OAuth2AttackGenerator) generateAuthorizationAttacks(endpoint common.AuthEndpoint) []OAuth2Attack {
	attacks := []OAuth2Attack{}

	// Parse the endpoint URL
	baseURL, err := url.Parse(endpoint.URL)
	if err != nil {
		return attacks
	}

	// Attack 1: Open Redirect
	openRedirectAttack := OAuth2Attack{
		Name:        "Open Redirect",
		Description: "Test for open redirect vulnerability via redirect_uri parameter",
		Type:        "Open Redirect",
		Severity:    "HIGH",
		Parameters: map[string]string{
			"redirect_uri":  "https://evil.com/callback",
			"client_id":     "test",
			"response_type": "code",
		},
	}

	// Build attack URL
	params := url.Values{}
	for key, value := range openRedirectAttack.Parameters {
		params.Add(key, value)
	}
	baseURL.RawQuery = params.Encode()
	openRedirectAttack.Payload = baseURL.String()

	attacks = append(attacks, openRedirectAttack)

	// Attack 2: State Parameter Bypass
	stateBypassAttack := OAuth2Attack{
		Name:        "State Parameter Bypass",
		Description: "Test if state parameter can be bypassed",
		Type:        "CSRF",
		Severity:    "MEDIUM",
		Parameters: map[string]string{
			"redirect_uri":  "https://client.com/callback",
			"client_id":     "test",
			"response_type": "code",
			// No state parameter
		},
	}

	params = url.Values{}
	for key, value := range stateBypassAttack.Parameters {
		params.Add(key, value)
	}
	baseURL.RawQuery = params.Encode()
	stateBypassAttack.Payload = baseURL.String()

	attacks = append(attacks, stateBypassAttack)

	// Attack 3: Response Type Confusion
	responseTypeAttack := OAuth2Attack{
		Name:        "Response Type Confusion",
		Description: "Test for response type confusion vulnerability",
		Type:        "Response Type Confusion",
		Severity:    "MEDIUM",
		Parameters: map[string]string{
			"redirect_uri":  "https://client.com/callback",
			"client_id":     "test",
			"response_type": "code token", // Hybrid flow
		},
	}

	params = url.Values{}
	for key, value := range responseTypeAttack.Parameters {
		params.Add(key, value)
	}
	baseURL.RawQuery = params.Encode()
	responseTypeAttack.Payload = baseURL.String()

	attacks = append(attacks, responseTypeAttack)

	// Attack 4: Scope Escalation
	scopeEscalationAttack := OAuth2Attack{
		Name:        "Scope Escalation",
		Description: "Test for scope escalation vulnerability",
		Type:        "Scope Escalation",
		Severity:    "HIGH",
		Parameters: map[string]string{
			"redirect_uri":  "https://client.com/callback",
			"client_id":     "test",
			"response_type": "code",
			"scope":         "read write admin", // Escalated scope
		},
	}

	params = url.Values{}
	for key, value := range scopeEscalationAttack.Parameters {
		params.Add(key, value)
	}
	baseURL.RawQuery = params.Encode()
	scopeEscalationAttack.Payload = baseURL.String()

	attacks = append(attacks, scopeEscalationAttack)

	return attacks
}

// generateTokenAttacks generates token endpoint attacks
func (g *OAuth2AttackGenerator) generateTokenAttacks(endpoint common.AuthEndpoint) []OAuth2Attack {
	attacks := []OAuth2Attack{}

	// Attack 1: Authorization Code Reuse
	codeReuseAttack := OAuth2Attack{
		Name:        "Authorization Code Reuse",
		Description: "Test if authorization codes can be reused",
		Type:        "Code Reuse",
		Severity:    "HIGH",
		Parameters: map[string]string{
			"grant_type":   "authorization_code",
			"code":         "test_code",
			"redirect_uri": "https://client.com/callback",
			"client_id":    "test",
		},
	}

	// Build form data
	formData := url.Values{}
	for key, value := range codeReuseAttack.Parameters {
		formData.Add(key, value)
	}
	codeReuseAttack.Payload = formData.Encode()

	attacks = append(attacks, codeReuseAttack)

	// Attack 2: Client Impersonation
	clientImpersonationAttack := OAuth2Attack{
		Name:        "Client Impersonation",
		Description: "Test if client can be impersonated",
		Type:        "Client Impersonation",
		Severity:    "HIGH",
		Parameters: map[string]string{
			"grant_type":   "authorization_code",
			"code":         "test_code",
			"redirect_uri": "https://client.com/callback",
			"client_id":    "malicious_client",
		},
	}

	formData = url.Values{}
	for key, value := range clientImpersonationAttack.Parameters {
		formData.Add(key, value)
	}
	clientImpersonationAttack.Payload = formData.Encode()

	attacks = append(attacks, clientImpersonationAttack)

	// Attack 3: PKCE Bypass
	pkceBypassAttack := OAuth2Attack{
		Name:        "PKCE Bypass",
		Description: "Test if PKCE can be bypassed",
		Type:        "PKCE Bypass",
		Severity:    "HIGH",
		Parameters: map[string]string{
			"grant_type":   "authorization_code",
			"code":         "test_code",
			"redirect_uri": "https://client.com/callback",
			"client_id":    "test",
			// No code_verifier
		},
	}

	formData = url.Values{}
	for key, value := range pkceBypassAttack.Parameters {
		formData.Add(key, value)
	}
	pkceBypassAttack.Payload = formData.Encode()

	attacks = append(attacks, pkceBypassAttack)

	return attacks
}

// ExecuteOAuth2Attack executes an OAuth2 attack
func (g *OAuth2AttackGenerator) ExecuteOAuth2Attack(attack OAuth2Attack, endpoint common.AuthEndpoint) bool {
	g.logger.Info("Executing OAuth2 attack", "attack", attack.Name, "endpoint", endpoint.URL)

	switch endpoint.Method {
	case "GET":
		return g.executeGetAttack(attack, endpoint)
	case "POST":
		return g.executePostAttack(attack, endpoint)
	default:
		g.logger.Debug("Unsupported method for attack", "method", endpoint.Method)
		return false
	}
}

// executeGetAttack executes a GET-based attack
func (g *OAuth2AttackGenerator) executeGetAttack(attack OAuth2Attack, endpoint common.AuthEndpoint) bool {
	resp, err := g.httpClient.Get(attack.Payload)
	if err != nil {
		g.logger.Debug("GET attack failed", "error", err)
		return false
	}
	defer httpclient.CloseBody(resp)

	// Analyze response for signs of successful attack
	return g.analyzeResponse(resp, attack)
}

// executePostAttack executes a POST-based attack
func (g *OAuth2AttackGenerator) executePostAttack(attack OAuth2Attack, endpoint common.AuthEndpoint) bool {
	resp, err := g.httpClient.PostForm(endpoint.URL, url.Values{})
	if err != nil {
		g.logger.Debug("POST attack failed", "error", err)
		return false
	}
	defer httpclient.CloseBody(resp)

	// Analyze response for signs of successful attack
	return g.analyzeResponse(resp, attack)
}

// analyzeResponse analyzes response for attack success indicators
func (g *OAuth2AttackGenerator) analyzeResponse(resp *http.Response, attack OAuth2Attack) bool {
	// Simple analysis - in real implementation, this would be more sophisticated
	switch attack.Type {
	case "Open Redirect":
		// Check for redirect to malicious domain
		if location := resp.Header.Get("Location"); location != "" {
			return strings.Contains(location, "evil.com")
		}
	case "CSRF":
		// Check if request was accepted without state
		return resp.StatusCode == 302 || resp.StatusCode == 200
	case "Code Reuse":
		// Check if code was accepted multiple times
		return resp.StatusCode == 200
	case "Client Impersonation":
		// Check if malicious client was accepted
		return resp.StatusCode == 200
	case "PKCE Bypass":
		// Check if request was accepted without PKCE
		return resp.StatusCode == 200
	}

	return false
}

// OAuth2SecurityTests represents comprehensive OAuth2 security tests
type OAuth2SecurityTests struct {
	// Authorization Code Flow
	CodeReuse        bool `json:"code_reuse"`
	CodeInterception bool `json:"code_interception"`
	PKCEDowngrade    bool `json:"pkce_downgrade"`
	PKCEBypass       bool `json:"pkce_bypass"`

	// Token Security
	TokenLeakage         bool `json:"token_leakage"`
	RefreshTokenRotation bool `json:"refresh_token_rotation"`
	BearerTokenReplay    bool `json:"bearer_token_replay"`

	// Client Security
	ClientAuthentication bool `json:"client_authentication"`
	ClientImpersonation  bool `json:"client_impersonation"`
	OpenRedirects        bool `json:"open_redirects"`

	// JWT/JWS/JWE Security
	AlgorithmConfusion bool `json:"algorithm_confusion"`
	KeyConfusion       bool `json:"key_confusion"`
	ClaimManipulation  bool `json:"claim_manipulation"`

	// Advanced Attacks
	MixUpAttack       bool `json:"mixup_attack"`
	CrossJWTConfusion bool `json:"cross_jwt_confusion"`
	IDTokenReplay     bool `json:"id_token_replay"`
}

// RunOAuth2SecurityTests runs comprehensive OAuth2 security tests
func (g *OAuth2AttackGenerator) RunOAuth2SecurityTests(config common.AuthConfiguration) OAuth2SecurityTests {
	tests := OAuth2SecurityTests{}

	// Run each test category
	g.logger.Info("Running OAuth2 security tests")

	// Test authorization code flow
	tests.CodeReuse = g.testCodeReuse(config)
	tests.CodeInterception = g.testCodeInterception(config)
	tests.PKCEDowngrade = g.testPKCEDowngrade(config)
	tests.PKCEBypass = g.testPKCEBypass(config)

	// Test token security
	tests.TokenLeakage = g.testTokenLeakage(config)
	tests.RefreshTokenRotation = g.testRefreshTokenRotation(config)
	tests.BearerTokenReplay = g.testBearerTokenReplay(config)

	// Test client security
	tests.ClientAuthentication = g.testClientAuthentication(config)
	tests.ClientImpersonation = g.testClientImpersonation(config)
	tests.OpenRedirects = g.testOpenRedirects(config)

	// Test JWT security
	tests.AlgorithmConfusion = g.testAlgorithmConfusion(config)
	tests.KeyConfusion = g.testKeyConfusion(config)
	tests.ClaimManipulation = g.testClaimManipulation(config)

	// Test advanced attacks
	tests.MixUpAttack = g.testMixUpAttack(config)
	tests.CrossJWTConfusion = g.testCrossJWTConfusion(config)
	tests.IDTokenReplay = g.testIDTokenReplay(config)

	g.logger.Info("OAuth2 security tests completed")

	return tests
}

// Individual test implementations (placeholders)

func (g *OAuth2AttackGenerator) testCodeReuse(config common.AuthConfiguration) bool {
	// Test if authorization codes can be reused
	return false
}

func (g *OAuth2AttackGenerator) testCodeInterception(config common.AuthConfiguration) bool {
	// Test for code interception vulnerabilities
	return false
}

func (g *OAuth2AttackGenerator) testPKCEDowngrade(config common.AuthConfiguration) bool {
	// Test if PKCE can be downgraded
	return false
}

func (g *OAuth2AttackGenerator) testPKCEBypass(config common.AuthConfiguration) bool {
	// Test if PKCE can be bypassed
	return false
}

func (g *OAuth2AttackGenerator) testTokenLeakage(config common.AuthConfiguration) bool {
	// Test for token leakage
	return false
}

func (g *OAuth2AttackGenerator) testRefreshTokenRotation(config common.AuthConfiguration) bool {
	// Test refresh token rotation
	return false
}

func (g *OAuth2AttackGenerator) testBearerTokenReplay(config common.AuthConfiguration) bool {
	// Test bearer token replay
	return false
}

func (g *OAuth2AttackGenerator) testClientAuthentication(config common.AuthConfiguration) bool {
	// Test client authentication
	return false
}

func (g *OAuth2AttackGenerator) testClientImpersonation(config common.AuthConfiguration) bool {
	// Test client impersonation
	return false
}

func (g *OAuth2AttackGenerator) testOpenRedirects(config common.AuthConfiguration) bool {
	// Test for open redirects
	return false
}

func (g *OAuth2AttackGenerator) testAlgorithmConfusion(config common.AuthConfiguration) bool {
	// Test JWT algorithm confusion
	return false
}

func (g *OAuth2AttackGenerator) testKeyConfusion(config common.AuthConfiguration) bool {
	// Test JWT key confusion
	return false
}

func (g *OAuth2AttackGenerator) testClaimManipulation(config common.AuthConfiguration) bool {
	// Test JWT claim manipulation
	return false
}

func (g *OAuth2AttackGenerator) testMixUpAttack(config common.AuthConfiguration) bool {
	// Test OAuth2 mix-up attack
	return false
}

func (g *OAuth2AttackGenerator) testCrossJWTConfusion(config common.AuthConfiguration) bool {
	// Test cross-JWT confusion
	return false
}

func (g *OAuth2AttackGenerator) testIDTokenReplay(config common.AuthConfiguration) bool {
	// Test ID token replay
	return false
}
