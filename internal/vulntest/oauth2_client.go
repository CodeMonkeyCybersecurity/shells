package vulntest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// OAuth2Client handles OAuth2/OIDC vulnerability testing
type OAuth2Client struct {
	httpClient *HTTPClient
}

// NewOAuth2Client creates a new OAuth2 testing client
func NewOAuth2Client() *OAuth2Client {
	return &OAuth2Client{
		httpClient: NewHTTPClient(),
	}
}

// OAuth2Config represents discovered OAuth2 configuration
type OAuth2Config struct {
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	JWKSUri                       string   `json:"jwks_uri"`
	Issuer                        string   `json:"issuer"`
	SupportedGrantTypes           []string `json:"grant_types_supported"`
	SupportedScopes               []string `json:"scopes_supported"`
	SupportedCodeChallengeMethods []string `json:"code_challenge_methods_supported"`
}

// JWTHeader represents JWT header
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// JWTPayload represents JWT payload
type JWTPayload struct {
	Iss   string      `json:"iss,omitempty"`
	Sub   string      `json:"sub,omitempty"`
	Aud   interface{} `json:"aud,omitempty"`
	Exp   int64       `json:"exp,omitempty"`
	Iat   int64       `json:"iat,omitempty"`
	Scope string      `json:"scope,omitempty"`
}

// DiscoverOAuth2Config attempts to discover OAuth2/OIDC configuration
func (o *OAuth2Client) DiscoverOAuth2Config(baseURL string) (*OAuth2Config, error) {
	// Common OIDC discovery endpoints
	discoveryPaths := []string{
		"/.well-known/openid_configuration",
		"/.well-known/oauth-authorization-server",
		"/oauth2/.well-known/openid_configuration",
		"/auth/.well-known/openid_configuration",
	}

	for _, path := range discoveryPaths {
		discoveryURL := strings.TrimSuffix(baseURL, "/") + path

		body, err := o.httpClient.GetResponseBody(discoveryURL)
		if err != nil {
			continue
		}

		var config OAuth2Config
		if err := json.Unmarshal([]byte(body), &config); err != nil {
			continue
		}

		// Validate we got a proper OAuth2 config
		if config.AuthorizationEndpoint != "" || config.TokenEndpoint != "" {
			return &config, nil
		}
	}

	return nil, fmt.Errorf("no OAuth2 configuration found")
}

// TestJWTAlgorithmConfusion tests for JWT algorithm confusion vulnerabilities
func (o *OAuth2Client) TestJWTAlgorithmConfusion(token string) (bool, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, "", fmt.Errorf("invalid JWT format")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false, "", fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false, "", fmt.Errorf("failed to parse JWT header: %w", err)
	}

	vulnerabilities := []string{}

	// Test 1: 'none' algorithm bypass
	if header.Alg != "none" {
		noneToken := o.createNoneAlgorithmToken(parts[1])
		if o.testTokenValidity(noneToken) {
			vulnerabilities = append(vulnerabilities, "JWT accepts 'none' algorithm bypass")
		}
	}

	// Test 2: RS256 to HS256 confusion
	if header.Alg == "RS256" {
		hs256Token, err := o.createHS256Token(parts[1], "public_key_as_secret")
		if err == nil && o.testTokenValidity(hs256Token) {
			vulnerabilities = append(vulnerabilities, "JWT vulnerable to RS256 to HS256 algorithm confusion")
		}
	}

	// Test 3: Weak signature secrets
	if header.Alg == "HS256" {
		weakSecrets := []string{"secret", "password", "123456", "key", "jwt", ""}
		for _, secret := range weakSecrets {
			if o.verifyHMACSignature(token, secret) {
				vulnerabilities = append(vulnerabilities, fmt.Sprintf("JWT uses weak HMAC secret: '%s'", secret))
				break
			}
		}
	}

	if len(vulnerabilities) > 0 {
		return true, strings.Join(vulnerabilities, "; "), nil
	}

	return false, "", nil
}

// TestOAuth2FlowVulnerabilities tests OAuth2 authorization flow vulnerabilities
func (o *OAuth2Client) TestOAuth2FlowVulnerabilities(config *OAuth2Config, clientID string) ([]string, error) {
	var vulnerabilities []string

	// Test 1: Missing state parameter (CSRF protection)
	authURL := fmt.Sprintf("%s?client_id=%s&response_type=code&redirect_uri=https://evil.com",
		config.AuthorizationEndpoint, clientID)

	statusCode, err := o.httpClient.CheckEndpoint(authURL)
	if err == nil && statusCode == 200 {
		vulnerabilities = append(vulnerabilities, "Authorization endpoint accepts requests without state parameter")
	}

	// Test 2: Redirect URI manipulation
	redirectURIs := []string{
		"https://evil.com",
		"http://evil.com",
		"https://attacker.com/callback",
		"javascript:alert('XSS')",
	}

	for _, redirectURI := range redirectURIs {
		testURL := fmt.Sprintf("%s?client_id=%s&response_type=code&redirect_uri=%s&state=test",
			config.AuthorizationEndpoint, clientID, url.QueryEscape(redirectURI))

		statusCode, err := o.httpClient.CheckEndpoint(testURL)
		if err == nil && statusCode == 200 {
			vulnerabilities = append(vulnerabilities,
				fmt.Sprintf("Authorization endpoint accepts malicious redirect_uri: %s", redirectURI))
			break // Only report first successful redirect manipulation
		}
	}

	// Test 3: PKCE bypass (if supported)
	if contains(config.SupportedCodeChallengeMethods, "S256") {
		// Try authorization without code_challenge when PKCE should be required
		noPKCEURL := fmt.Sprintf("%s?client_id=%s&response_type=code&redirect_uri=https://example.com&state=test",
			config.AuthorizationEndpoint, clientID)

		statusCode, err := o.httpClient.CheckEndpoint(noPKCEURL)
		if err == nil && statusCode == 200 {
			vulnerabilities = append(vulnerabilities, "PKCE protection can be bypassed")
		}
	}

	// Test 4: Scope escalation
	escalatedScopes := []string{"admin", "root", "write:all", "delete:all", "system"}
	baseScopes := strings.Join(config.SupportedScopes, " ")

	for _, scope := range escalatedScopes {
		testScopes := baseScopes + " " + scope
		scopeURL := fmt.Sprintf("%s?client_id=%s&response_type=code&scope=%s&redirect_uri=https://example.com&state=test",
			config.AuthorizationEndpoint, clientID, url.QueryEscape(testScopes))

		statusCode, err := o.httpClient.CheckEndpoint(scopeURL)
		if err == nil && statusCode == 200 {
			vulnerabilities = append(vulnerabilities,
				fmt.Sprintf("Authorization endpoint accepts escalated scope: %s", scope))
		}
	}

	return vulnerabilities, nil
}

// TestTokenEndpointVulnerabilities tests token endpoint for vulnerabilities
func (o *OAuth2Client) TestTokenEndpointVulnerabilities(config *OAuth2Config, clientID, clientSecret string) ([]string, error) {
	var vulnerabilities []string

	if config.TokenEndpoint == "" {
		return vulnerabilities, nil
	}

	// Test 1: Client credential stuffing
	commonSecrets := []string{"", "secret", "password", clientID, "123456"}

	for _, secret := range commonSecrets {
		if o.testClientCredentials(config.TokenEndpoint, clientID, secret) {
			vulnerabilities = append(vulnerabilities,
				fmt.Sprintf("Token endpoint accepts weak client credentials: %s:%s", clientID, secret))
			break
		}
	}

	// Test 2: Authorization code injection
	fakeCode := "fake_auth_code_12345"
	if o.testAuthorizationCode(config.TokenEndpoint, clientID, clientSecret, fakeCode) {
		vulnerabilities = append(vulnerabilities, "Token endpoint vulnerable to authorization code injection")
	}

	return vulnerabilities, nil
}

// Helper functions

func (o *OAuth2Client) createNoneAlgorithmToken(payload string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	return header + "." + payload + "."
}

func (o *OAuth2Client) createHS256Token(payload, secret string) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	message := header + "." + payload

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return message + "." + signature, nil
}

func (o *OAuth2Client) verifyHMACSignature(token, secret string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	message := parts[0] + "." + parts[1]
	expectedSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	actualSig := h.Sum(nil)

	return hmac.Equal(expectedSig, actualSig)
}

func (o *OAuth2Client) testTokenValidity(token string) bool {
	// This would typically involve making a request to a protected resource
	// For now, return false as we can't test without a specific endpoint
	return false
}

func (o *OAuth2Client) testClientCredentials(tokenEndpoint, clientID, clientSecret string) bool {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := o.httpClient.Client.Post(tokenEndpoint, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return false
	}
	defer req.Body.Close()

	return req.StatusCode == 200
}

func (o *OAuth2Client) testAuthorizationCode(tokenEndpoint, clientID, clientSecret, code string) bool {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", "https://example.com")

	req, err := o.httpClient.Client.Post(tokenEndpoint, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return false
	}
	defer req.Body.Close()

	// If it doesn't immediately reject fake code, it's vulnerable
	return req.StatusCode != 400
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
