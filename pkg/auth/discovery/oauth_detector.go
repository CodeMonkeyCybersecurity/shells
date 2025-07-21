package discovery

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// OAuthDetector discovers OAuth2/OIDC authentication implementations
type OAuthDetector struct {
	logger     *logger.Logger
	httpClient *http.Client
	patterns   map[string]*regexp.Regexp
}

// OAuth2Discovery represents discovered OAuth2/OIDC configuration
type OAuth2Discovery struct {
	AuthorizationEndpoint string                 `json:"authorization_endpoint"`
	TokenEndpoint         string                 `json:"token_endpoint"`
	UserInfoEndpoint      string                 `json:"userinfo_endpoint,omitempty"`
	JWKSUri               string                 `json:"jwks_uri,omitempty"`
	RegistrationEndpoint  string                 `json:"registration_endpoint,omitempty"`
	RevocationEndpoint    string                 `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint string                 `json:"introspection_endpoint,omitempty"`
	Issuer                string                 `json:"issuer,omitempty"`
	ClientID              string                 `json:"client_id,omitempty"`
	ResponseTypesSupported []string              `json:"response_types_supported"`
	GrantTypesSupported   []string               `json:"grant_types_supported"`
	ScopesSupported       []string               `json:"scopes_supported"`
	TokenEndpointAuthMethods []string            `json:"token_endpoint_auth_methods_supported"`
	SigningAlgValues      []string               `json:"id_token_signing_alg_values_supported"`
	PKCESupported         bool                   `json:"pkce_supported"`
	OpenIDConnect         bool                   `json:"openid_connect"`
	WellKnownConfig       map[string]interface{} `json:"well_known_config,omitempty"`
	Flows                 []OAuthFlow            `json:"flows"`
	SecurityFeatures      []string               `json:"security_features"`
	Vulnerabilities       []string               `json:"vulnerabilities"`
	Confidence            float64                `json:"confidence"`
}

// OAuthFlow represents an OAuth2 flow
type OAuthFlow struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	StartURL    string `json:"start_url"`
	Secure      bool   `json:"secure"`
}

// NewOAuthDetector creates a new OAuth detector
func NewOAuthDetector(logger *logger.Logger) *OAuthDetector {
	detector := &OAuthDetector{
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // For testing purposes
				},
			},
		},
		patterns: make(map[string]*regexp.Regexp),
	}

	detector.initializePatterns()
	return detector
}

func (o *OAuthDetector) initializePatterns() {
	// OAuth2 endpoint patterns
	o.patterns["authorize_endpoint"] = regexp.MustCompile(`(?i)/oauth2?/authorize|/connect/authorize|/auth/authorize`)
	o.patterns["token_endpoint"] = regexp.MustCompile(`(?i)/oauth2?/token|/connect/token|/auth/token`)
	o.patterns["userinfo_endpoint"] = regexp.MustCompile(`(?i)/oauth2?/userinfo|/connect/userinfo|/auth/userinfo`)
	o.patterns["jwks_endpoint"] = regexp.MustCompile(`(?i)/.well-known/jwks|/oauth2?/jwks|/connect/jwks`)
	
	// OIDC patterns
	o.patterns["oidc_config"] = regexp.MustCompile(`(?i)/.well-known/openid[_-]configuration`)
	o.patterns["discovery_doc"] = regexp.MustCompile(`(?i)/.well-known/oauth-authorization-server`)
	
	// OAuth2 parameter patterns
	o.patterns["client_id"] = regexp.MustCompile(`(?i)client_id[\s]*[:=][\s]*['"](.*?)['"]`)
	o.patterns["response_type"] = regexp.MustCompile(`(?i)response_type[\s]*[:=][\s]*['"](.*?)['"]`)
	o.patterns["redirect_uri"] = regexp.MustCompile(`(?i)redirect_uri[\s]*[:=][\s]*['"](.*?)['"]`)
	o.patterns["scope"] = regexp.MustCompile(`(?i)scope[\s]*[:=][\s]*['"](.*?)['"]`)
	o.patterns["state"] = regexp.MustCompile(`(?i)state[\s]*[:=][\s]*['"](.*?)['"]`)
	
	// PKCE patterns
	o.patterns["code_challenge"] = regexp.MustCompile(`(?i)code_challenge[\s]*[:=]`)
	o.patterns["code_verifier"] = regexp.MustCompile(`(?i)code_verifier[\s]*[:=]`)
	
	// JWT patterns
	o.patterns["jwt_token"] = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	o.patterns["bearer_token"] = regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9._-]+`)
	
	// Authorization Code flow
	o.patterns["auth_code"] = regexp.MustCompile(`(?i)[?&]code=([^&\s]+)`)
	
	// Provider patterns
	o.patterns["google_oauth"] = regexp.MustCompile(`accounts\.google\.com/oauth`)
	o.patterns["facebook_oauth"] = regexp.MustCompile(`facebook\.com/.*oauth`)
	o.patterns["microsoft_oauth"] = regexp.MustCompile(`login\.microsoftonline\.com`)
	o.patterns["github_oauth"] = regexp.MustCompile(`github\.com/login/oauth`)
}

// DetectOAuth discovers OAuth2/OIDC implementations on a target
func (o *OAuthDetector) DetectOAuth(ctx context.Context, target string) (*OAuth2Discovery, error) {
	o.logger.Info("Starting OAuth2/OIDC detection", "target", target)
	
	discovery := &OAuth2Discovery{
		ResponseTypesSupported:   []string{},
		GrantTypesSupported:     []string{},
		ScopesSupported:         []string{},
		TokenEndpointAuthMethods: []string{},
		SigningAlgValues:        []string{},
		Flows:                   []OAuthFlow{},
		SecurityFeatures:        []string{},
		Vulnerabilities:         []string{},
	}

	baseURL := o.getBaseURL(target)
	
	// 1. Check for OIDC well-known configuration
	if config := o.discoverWellKnownConfig(ctx, baseURL); config != nil {
		o.parseWellKnownConfig(config, discovery)
		discovery.Confidence += 0.5
		discovery.OpenIDConnect = true
	}
	
	// 2. Check for OAuth2 discovery document
	if !discovery.OpenIDConnect {
		if config := o.discoverOAuth2Config(ctx, baseURL); config != nil {
			o.parseOAuth2Config(config, discovery)
			discovery.Confidence += 0.4
		}
	}
	
	// 3. Probe common OAuth endpoints
	oauthPaths := o.generateOAuthPaths(baseURL)
	for _, path := range oauthPaths {
		if o.probeOAuthEndpoint(ctx, path, discovery) {
			discovery.Confidence += 0.1
		}
	}
	
	// 4. Analyze main page for OAuth indicators
	if o.analyzePageForOAuth(ctx, target, discovery) {
		discovery.Confidence += 0.2
	}
	
	// 5. Detect OAuth flows
	o.detectOAuthFlows(ctx, target, discovery)
	
	// 6. Security analysis
	o.analyzeOAuthSecurity(discovery)
	
	o.logger.Info("OAuth2/OIDC detection completed", 
		"target", target, 
		"confidence", discovery.Confidence,
		"is_oidc", discovery.OpenIDConnect)
	
	if discovery.Confidence < 0.3 {
		return nil, nil // Not enough evidence
	}
	
	return discovery, nil
}

// discoverWellKnownConfig discovers OIDC well-known configuration
func (o *OAuthDetector) discoverWellKnownConfig(ctx context.Context, baseURL string) map[string]interface{} {
	configURL := baseURL + "/.well-known/openid_configuration"
	
	req, err := http.NewRequestWithContext(ctx, "GET", configURL, nil)
	if err != nil {
		return nil
	}
	
	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil
	}
	
	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil
	}
	
	o.logger.Debug("Found OIDC well-known configuration", "url", configURL)
	return config
}

// discoverOAuth2Config discovers OAuth2 authorization server metadata
func (o *OAuthDetector) discoverOAuth2Config(ctx context.Context, baseURL string) map[string]interface{} {
	configURL := baseURL + "/.well-known/oauth-authorization-server"
	
	req, err := http.NewRequestWithContext(ctx, "GET", configURL, nil)
	if err != nil {
		return nil
	}
	
	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil
	}
	
	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil
	}
	
	o.logger.Debug("Found OAuth2 authorization server metadata", "url", configURL)
	return config
}

// parseWellKnownConfig parses OIDC well-known configuration
func (o *OAuthDetector) parseWellKnownConfig(config map[string]interface{}, discovery *OAuth2Discovery) {
	discovery.WellKnownConfig = config
	
	if issuer, ok := config["issuer"].(string); ok {
		discovery.Issuer = issuer
	}
	
	if authEndpoint, ok := config["authorization_endpoint"].(string); ok {
		discovery.AuthorizationEndpoint = authEndpoint
	}
	
	if tokenEndpoint, ok := config["token_endpoint"].(string); ok {
		discovery.TokenEndpoint = tokenEndpoint
	}
	
	if userinfoEndpoint, ok := config["userinfo_endpoint"].(string); ok {
		discovery.UserInfoEndpoint = userinfoEndpoint
	}
	
	if jwksUri, ok := config["jwks_uri"].(string); ok {
		discovery.JWKSUri = jwksUri
	}
	
	if regEndpoint, ok := config["registration_endpoint"].(string); ok {
		discovery.RegistrationEndpoint = regEndpoint
	}
	
	// Parse supported features
	if responseTypes, ok := config["response_types_supported"].([]interface{}); ok {
		for _, rt := range responseTypes {
			if rtStr, ok := rt.(string); ok {
				discovery.ResponseTypesSupported = append(discovery.ResponseTypesSupported, rtStr)
			}
		}
	}
	
	if grantTypes, ok := config["grant_types_supported"].([]interface{}); ok {
		for _, gt := range grantTypes {
			if gtStr, ok := gt.(string); ok {
				discovery.GrantTypesSupported = append(discovery.GrantTypesSupported, gtStr)
			}
		}
	}
	
	if scopes, ok := config["scopes_supported"].([]interface{}); ok {
		for _, scope := range scopes {
			if scopeStr, ok := scope.(string); ok {
				discovery.ScopesSupported = append(discovery.ScopesSupported, scopeStr)
			}
		}
	}
	
	if authMethods, ok := config["token_endpoint_auth_methods_supported"].([]interface{}); ok {
		for _, method := range authMethods {
			if methodStr, ok := method.(string); ok {
				discovery.TokenEndpointAuthMethods = append(discovery.TokenEndpointAuthMethods, methodStr)
			}
		}
	}
	
	if signingAlgs, ok := config["id_token_signing_alg_values_supported"].([]interface{}); ok {
		for _, alg := range signingAlgs {
			if algStr, ok := alg.(string); ok {
				discovery.SigningAlgValues = append(discovery.SigningAlgValues, algStr)
			}
		}
	}
	
	// Check for PKCE support
	if codeChallengeMethods, ok := config["code_challenge_methods_supported"].([]interface{}); ok {
		if len(codeChallengeMethods) > 0 {
			discovery.PKCESupported = true
			discovery.SecurityFeatures = append(discovery.SecurityFeatures, "PKCE Support")
		}
	}
}

// parseOAuth2Config parses OAuth2 authorization server metadata
func (o *OAuthDetector) parseOAuth2Config(config map[string]interface{}, discovery *OAuth2Discovery) {
	// Similar to parseWellKnownConfig but for OAuth2 metadata
	if authEndpoint, ok := config["authorization_endpoint"].(string); ok {
		discovery.AuthorizationEndpoint = authEndpoint
	}
	
	if tokenEndpoint, ok := config["token_endpoint"].(string); ok {
		discovery.TokenEndpoint = tokenEndpoint
	}
	
	// Parse other OAuth2-specific fields...
}

// generateOAuthPaths generates common OAuth paths to check
func (o *OAuthDetector) generateOAuthPaths(baseURL string) []string {
	return []string{
		baseURL + "/oauth/authorize",
		baseURL + "/oauth2/authorize", 
		baseURL + "/auth/oauth2/authorize",
		baseURL + "/connect/authorize",
		baseURL + "/oauth/token",
		baseURL + "/oauth2/token",
		baseURL + "/auth/oauth2/token",
		baseURL + "/connect/token",
		baseURL + "/oauth/userinfo",
		baseURL + "/oauth2/userinfo",
		baseURL + "/connect/userinfo",
	}
}

// probeOAuthEndpoint probes an OAuth endpoint
func (o *OAuthDetector) probeOAuthEndpoint(ctx context.Context, endpoint string, discovery *OAuth2Discovery) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return false
	}
	
	resp, err := o.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	// OAuth endpoints typically return 400 for malformed requests
	if resp.StatusCode == 400 || resp.StatusCode == 401 {
		// Check for OAuth error responses
		if body, err := io.ReadAll(resp.Body); err == nil {
			content := string(body)
			if strings.Contains(content, "invalid_request") ||
			   strings.Contains(content, "unauthorized_client") ||
			   strings.Contains(content, "unsupported_response_type") {
				return true
			}
		}
	}
	
	// Check for OAuth-related headers
	if wwwAuth := resp.Header.Get("WWW-Authenticate"); wwwAuth != "" {
		if strings.Contains(strings.ToLower(wwwAuth), "bearer") {
			return true
		}
	}
	
	return false
}

// analyzePageForOAuth analyzes a page for OAuth indicators
func (o *OAuthDetector) analyzePageForOAuth(ctx context.Context, pageURL string, discovery *OAuth2Discovery) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return false
	}
	
	resp, err := o.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	
	content := string(body)
	found := false
	
	// Look for OAuth parameters
	if matches := o.patterns["client_id"].FindStringSubmatch(content); len(matches) > 1 {
		discovery.ClientID = matches[1]
		found = true
	}
	
	// Look for PKCE indicators
	if o.patterns["code_challenge"].MatchString(content) ||
	   o.patterns["code_verifier"].MatchString(content) {
		discovery.PKCESupported = true
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "PKCE Support")
		found = true
	}
	
	// Look for JWT tokens
	if o.patterns["jwt_token"].MatchString(content) {
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "JWT Tokens")
		found = true
	}
	
	// Check for known OAuth providers
	if o.patterns["google_oauth"].MatchString(content) {
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "Google OAuth Integration")
		found = true
	}
	
	if o.patterns["microsoft_oauth"].MatchString(content) {
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "Microsoft OAuth Integration")
		found = true
	}
	
	return found
}

// detectOAuthFlows detects OAuth2 flows in use
func (o *OAuthDetector) detectOAuthFlows(ctx context.Context, target string, discovery *OAuth2Discovery) {
	// Authorization Code Flow
	if discovery.AuthorizationEndpoint != "" && discovery.TokenEndpoint != "" {
		flow := OAuthFlow{
			Type:        "authorization_code",
			Description: "Authorization Code Flow",
			StartURL:    discovery.AuthorizationEndpoint,
			Secure:      discovery.PKCESupported,
		}
		discovery.Flows = append(discovery.Flows, flow)
	}
	
	// Implicit Flow (less secure)
	for _, responseType := range discovery.ResponseTypesSupported {
		if strings.Contains(responseType, "token") {
			flow := OAuthFlow{
				Type:        "implicit",
				Description: "Implicit Flow",
				StartURL:    discovery.AuthorizationEndpoint,
				Secure:      false,
			}
			discovery.Flows = append(discovery.Flows, flow)
			discovery.Vulnerabilities = append(discovery.Vulnerabilities, "Implicit Flow (less secure)")
			break
		}
	}
	
	// Client Credentials Flow
	for _, grantType := range discovery.GrantTypesSupported {
		if grantType == "client_credentials" {
			flow := OAuthFlow{
				Type:        "client_credentials",
				Description: "Client Credentials Flow",
				StartURL:    discovery.TokenEndpoint,
				Secure:      true,
			}
			discovery.Flows = append(discovery.Flows, flow)
			break
		}
	}
}

// analyzeOAuthSecurity analyzes OAuth configuration for security issues
func (o *OAuthDetector) analyzeOAuthSecurity(discovery *OAuth2Discovery) {
	// Check for security features
	if discovery.PKCESupported {
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "PKCE Protection")
	}
	
	if discovery.JWKSUri != "" {
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "JWT Key Rotation")
	}
	
	if len(discovery.SigningAlgValues) > 0 {
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "Signed ID Tokens")
		
		// Check for weak algorithms
		for _, alg := range discovery.SigningAlgValues {
			if alg == "none" {
				discovery.Vulnerabilities = append(discovery.Vulnerabilities, "Unsigned tokens allowed (none algorithm)")
			}
			if alg == "HS256" && len(discovery.SigningAlgValues) == 1 {
				discovery.Vulnerabilities = append(discovery.Vulnerabilities, "Only HMAC signing (symmetric key)")
			}
		}
	}
	
	// Check for insecure client authentication
	hasSecureAuth := false
	for _, method := range discovery.TokenEndpointAuthMethods {
		if method != "none" && method != "client_secret_basic" {
			hasSecureAuth = true
			break
		}
	}
	
	if !hasSecureAuth && len(discovery.TokenEndpointAuthMethods) > 0 {
		discovery.Vulnerabilities = append(discovery.Vulnerabilities, "Weak client authentication methods")
	}
	
	// Check for missing PKCE
	if !discovery.PKCESupported && len(discovery.ResponseTypesSupported) > 0 {
		discovery.Vulnerabilities = append(discovery.Vulnerabilities, "PKCE not supported (CSRF vulnerability)")
	}
}

// Helper methods
func (o *OAuthDetector) getBaseURL(fullURL string) string {
	if parsed, err := url.Parse(fullURL); err == nil {
		return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	}
	return fullURL
}