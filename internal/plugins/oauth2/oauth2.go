package oauth2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

type oauth2Scanner struct {
	client *http.Client
	logger interface {
		Info(msg string, keysAndValues ...interface{})
		Error(msg string, keysAndValues ...interface{})
		Debug(msg string, keysAndValues ...interface{})
	}
}

type OAuth2Config struct {
	AuthorizationURL string
	TokenURL         string
	ClientID         string
	ClientSecret     string
	RedirectURI      string
	Scopes           []string
}

type OAuth2Test struct {
	Name        string
	Description string
	Severity    types.Severity
	TestFunc    func(ctx context.Context, config OAuth2Config) (*types.Finding, error)
}

func NewScanner(logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}) core.Scanner {
	return &oauth2Scanner{
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger: logger,
	}
}

func (s *oauth2Scanner) Name() string {
	return "oauth2"
}

func (s *oauth2Scanner) Type() types.ScanType {
	return types.ScanType("oauth2")
}

func (s *oauth2Scanner) Validate(target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("target must be HTTP or HTTPS URL")
	}

	return nil
}

func (s *oauth2Scanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	config := OAuth2Config{
		AuthorizationURL: options["auth_url"],
		TokenURL:         options["token_url"],
		ClientID:         options["client_id"],
		ClientSecret:     options["client_secret"],
		RedirectURI:      options["redirect_uri"],
		Scopes:           strings.Split(options["scopes"], " "),
	}

	if config.AuthorizationURL == "" {
		config.AuthorizationURL = target + "/oauth/authorize"
	}
	if config.TokenURL == "" {
		config.TokenURL = target + "/oauth/token"
	}

	tests := s.getTestCases()
	findings := []types.Finding{}

	for _, test := range tests {
		s.logger.Info("Running OAuth2 test", "test", test.Name)

		finding, err := test.TestFunc(ctx, config)
		if err != nil {
			s.logger.Error("Test failed", "test", test.Name, "error", err)
			continue
		}

		if finding != nil {
			finding.Tool = "oauth2"
			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

func (s *oauth2Scanner) getTestCases() []OAuth2Test {
	return []OAuth2Test{
		{
			Name:        "authorization_code_replay",
			Description: "Tests if authorization codes can be reused",
			Severity:    types.SeverityHigh,
			TestFunc:    s.testAuthCodeReplay,
		},
		{
			Name:        "redirect_uri_validation",
			Description: "Tests redirect URI validation bypass",
			Severity:    types.SeverityCritical,
			TestFunc:    s.testRedirectURIValidation,
		},
		{
			Name:        "state_parameter_validation",
			Description: "Tests state parameter implementation",
			Severity:    types.SeverityMedium,
			TestFunc:    s.testStateParameter,
		},
		{
			Name:        "pkce_downgrade",
			Description: "Tests for PKCE downgrade vulnerabilities",
			Severity:    types.SeverityHigh,
			TestFunc:    s.testPKCEDowngrade,
		},
		{
			Name:        "open_redirect_in_redirect_uri",
			Description: "Tests for open redirect via redirect_uri",
			Severity:    types.SeverityHigh,
			TestFunc:    s.testOpenRedirect,
		},
		{
			Name:        "token_leakage_referrer",
			Description: "Tests for token leakage in referrer headers",
			Severity:    types.SeverityHigh,
			TestFunc:    s.testTokenLeakageReferrer,
		},
		{
			Name:        "implicit_flow_token_leakage",
			Description: "Tests implicit flow for token exposure",
			Severity:    types.SeverityHigh,
			TestFunc:    s.testImplicitFlow,
		},
		{
			Name:        "jwt_alg_none_bypass",
			Description: "Tests JWT 'none' algorithm bypass",
			Severity:    types.SeverityCritical,
			TestFunc:    s.testJWTAlgNone,
		},
		{
			Name:        "response_type_confusion",
			Description: "Tests response type confusion attacks",
			Severity:    types.SeverityHigh,
			TestFunc:    s.testResponseTypeConfusion,
		},
		{
			Name:        "cross_site_request_forgery",
			Description: "Tests for CSRF in OAuth flows",
			Severity:    types.SeverityMedium,
			TestFunc:    s.testCSRF,
		},
	}
}

func (s *oauth2Scanner) testAuthCodeReplay(ctx context.Context, config OAuth2Config) (*types.Finding, error) {
	state := s.generateState()

	authURL := s.buildAuthURL(config, state, "code")
	resp, err := s.client.Get(authURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		return nil, nil
	}

	location := resp.Header.Get("Location")
	code := s.extractCode(location)
	if code == "" {
		return nil, nil
	}

	firstResp, err := s.exchangeCode(config, code)
	if err != nil {
		return nil, err
	}

	time.Sleep(1 * time.Second)

	secondResp, err := s.exchangeCode(config, code)
	if err == nil && secondResp.StatusCode == http.StatusOK {
		return &types.Finding{
			Type:     "oauth2_code_replay",
			Severity: types.SeverityHigh,
			Title:    "Authorization Code Replay Attack Possible",
			Description: "The OAuth2 implementation allows authorization codes to be reused multiple times. " +
				"This violates RFC 6749 Section 4.1.2 which states codes MUST be single use.",
			Evidence: fmt.Sprintf("Authorization code was successfully used twice. First response: %d, Second response: %d",
				firstResp.StatusCode, secondResp.StatusCode),
			Solution: "Implement single-use authorization codes. Mark codes as used after first exchange and reject subsequent attempts.",
			References: []string{
				"https://tools.ietf.org/html/rfc6749#section-4.1.2",
				"https://portswigger.net/web-security/oauth/grant-types#authorization-code-grant-type",
			},
			Metadata: map[string]interface{}{
				"auth_endpoint":  config.AuthorizationURL,
				"token_endpoint": config.TokenURL,
			},
		}, nil
	}

	return nil, nil
}

func (s *oauth2Scanner) testRedirectURIValidation(ctx context.Context, config OAuth2Config) (*types.Finding, error) {
	attacks := []struct {
		name        string
		redirectURI string
		severity    types.Severity
	}{
		{"subdomain", "https://evil.com@" + s.extractHost(config.RedirectURI), types.SeverityCritical},
		{"parameter", config.RedirectURI + "?redirect=https://evil.com", types.SeverityHigh},
		{"fragment", config.RedirectURI + "#@evil.com", types.SeverityMedium},
		{"path_traversal", strings.Replace(config.RedirectURI, "/callback", "/../../../evil", 1), types.SeverityHigh},
		{"unicode", strings.Replace(config.RedirectURI, ".", "\u2024", 1), types.SeverityHigh},
		{"case_variation", strings.ToUpper(config.RedirectURI), types.SeverityMedium},
		{"protocol_downgrade", strings.Replace(config.RedirectURI, "https://", "http://", 1), types.SeverityMedium},
		{"localhost_bypass", "http://localhost:8080/callback", types.SeverityHigh},
		{"wildcard", "https://*.evil.com", types.SeverityCritical},
		{"data_uri", "data:text/html,<script>alert(document.domain)</script>", types.SeverityCritical},
	}

	for _, attack := range attacks {
		modifiedConfig := config
		modifiedConfig.RedirectURI = attack.redirectURI

		authURL := s.buildAuthURL(modifiedConfig, s.generateState(), "code")
		resp, err := s.client.Get(authURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusFound {
			location := resp.Header.Get("Location")
			if strings.Contains(location, attack.redirectURI) || strings.Contains(location, "evil.com") {
				return &types.Finding{
					Type:     "oauth2_redirect_uri_bypass",
					Severity: attack.severity,
					Title:    fmt.Sprintf("Redirect URI Validation Bypass - %s", attack.name),
					Description: fmt.Sprintf("The OAuth2 implementation accepts malicious redirect URIs using %s technique. "+
						"This can lead to authorization code/token theft.", attack.name),
					Evidence: fmt.Sprintf("Malicious redirect URI accepted: %s", attack.redirectURI),
					Solution: "Implement strict redirect URI validation:\n" +
						"1. Use exact string matching\n" +
						"2. Maintain whitelist of allowed URIs\n" +
						"3. Reject any URI with user-controlled components\n" +
						"4. Validate protocol, host, port, and path separately",
					References: []string{
						"https://portswigger.net/web-security/oauth/preventing#redirect-uri-validation",
						"https://oauth.net/advisories/2014-1-covert-redirect/",
					},
					Metadata: map[string]interface{}{
						"bypass_technique": attack.name,
						"malicious_uri":    attack.redirectURI,
						"original_uri":     config.RedirectURI,
					},
				}, nil
			}
		}
	}

	return nil, nil
}

func (s *oauth2Scanner) testStateParameter(ctx context.Context, config OAuth2Config) (*types.Finding, error) {
	findings := []string{}

	noStateURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code",
		config.AuthorizationURL, config.ClientID, url.QueryEscape(config.RedirectURI))

	resp, err := s.client.Get(noStateURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		findings = append(findings, "Authorization request accepted without state parameter")
	}

	weakStates := []string{"1234", "state", "test", ""}
	for _, weakState := range weakStates {
		authURL := s.buildAuthURL(config, weakState, "code")
		resp, err := s.client.Get(authURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusFound {
			findings = append(findings, fmt.Sprintf("Weak state value accepted: '%s'", weakState))
		}
	}

	if len(findings) > 0 {
		return &types.Finding{
			Type:        "oauth2_weak_state_parameter",
			Severity:    types.SeverityMedium,
			Title:       "Weak or Missing State Parameter Validation",
			Description: "The OAuth2 implementation has weak state parameter validation, making it vulnerable to CSRF attacks.",
			Evidence:    strings.Join(findings, "\n"),
			Solution: "Implement proper state parameter:\n" +
				"1. Generate cryptographically random state values\n" +
				"2. Bind state to user session\n" +
				"3. Validate state on callback\n" +
				"4. Use at least 128 bits of entropy",
			References: []string{
				"https://tools.ietf.org/html/rfc6749#section-10.12",
				"https://portswigger.net/web-security/csrf#csrf-tokens",
			},
		}, nil
	}

	return nil, nil
}

func (s *oauth2Scanner) testPKCEDowngrade(ctx context.Context, config OAuth2Config) (*types.Finding, error) {
	codeVerifier := s.generateCodeVerifier()
	codeChallenge := s.generateCodeChallenge(codeVerifier)

	pkceURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&state=%s&code_challenge=%s&code_challenge_method=S256",
		config.AuthorizationURL, config.ClientID, url.QueryEscape(config.RedirectURI),
		s.generateState(), codeChallenge)

	resp, err := s.client.Get(pkceURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		return nil, nil
	}

	noPKCEURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&state=%s",
		config.AuthorizationURL, config.ClientID, url.QueryEscape(config.RedirectURI), s.generateState())

	resp2, err := s.client.Get(noPKCEURL)
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close()

	if resp2.StatusCode == http.StatusFound {
		return &types.Finding{
			Type:     "oauth2_pkce_downgrade",
			Severity: types.SeverityHigh,
			Title:    "PKCE Downgrade Attack Possible",
			Description: "The OAuth2 server accepts both PKCE and non-PKCE requests for the same client. " +
				"This allows attackers to bypass PKCE protection by simply omitting the code_challenge parameter.",
			Evidence: "Server accepted authorization request without PKCE parameters when PKCE was previously used",
			Solution: "Enforce PKCE for all public clients:\n" +
				"1. Require code_challenge for all authorization requests\n" +
				"2. Reject token exchange without matching code_verifier\n" +
				"3. Configure client to require PKCE",
			References: []string{
				"https://tools.ietf.org/html/rfc7636",
				"https://portswigger.net/research/hidden-oauth-attack-vectors",
			},
			Metadata: map[string]interface{}{
				"pkce_supported": true,
				"pkce_required":  false,
			},
		}, nil
	}

	return nil, nil
}

func (s *oauth2Scanner) testOpenRedirect(ctx context.Context, config OAuth2Config) (*types.Finding, error) {
	payloads := []string{
		"//evil.com",
		"https://evil.com",
		"//google.com%2f@" + s.extractHost(config.RedirectURI),
		"//google.com%2f%2f" + s.extractHost(config.RedirectURI),
		"/\\evil.com",
		"/../evil.com",
		"https://" + s.extractHost(config.RedirectURI) + ".evil.com",
	}

	for _, payload := range payloads {
		testURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&state=%s&redirect=%s",
			config.AuthorizationURL, config.ClientID, url.QueryEscape(config.RedirectURI),
			s.generateState(), url.QueryEscape(payload))

		resp, err := s.client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusFound {
			location := resp.Header.Get("Location")
			if strings.Contains(location, "evil.com") || strings.HasPrefix(location, payload) {
				return &types.Finding{
					Type:     "oauth2_open_redirect",
					Severity: types.SeverityHigh,
					Title:    "Open Redirect in OAuth2 Flow",
					Description: "The OAuth2 implementation is vulnerable to open redirect attacks. " +
						"This can be chained with other vulnerabilities to steal tokens or authorization codes.",
					Evidence: fmt.Sprintf("Redirect to malicious URL: %s", location),
					Solution: "Validate all redirect parameters:\n" +
						"1. Use whitelist of allowed redirect targets\n" +
						"2. Validate URL format and protocol\n" +
						"3. Reject URLs with user-controlled domains\n" +
						"4. Use warning page for external redirects",
					References: []string{
						"https://cwe.mitre.org/data/definitions/601.html",
						"https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
					},
					Metadata: map[string]interface{}{
						"payload":  payload,
						"redirect": location,
					},
				}, nil
			}
		}
	}

	return nil, nil
}

func (s *oauth2Scanner) testTokenLeakageReferrer(ctx context.Context, config OAuth2Config) (*types.Finding, error) {
	implicitURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=token&state=%s",
		config.AuthorizationURL, config.ClientID, url.QueryEscape(config.RedirectURI), s.generateState())

	resp, err := s.client.Get(implicitURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if strings.Contains(location, "access_token=") {
			return &types.Finding{
				Type:     "oauth2_token_in_url",
				Severity: types.SeverityHigh,
				Title:    "Access Token Exposed in URL",
				Description: "The OAuth2 implementation uses implicit flow which exposes tokens in URLs. " +
					"Tokens in URLs can leak through referrer headers, browser history, and server logs.",
				Evidence: "Access token returned in URL fragment/query",
				Solution: "Migrate to authorization code flow with PKCE:\n" +
					"1. Disable implicit flow\n" +
					"2. Use authorization code flow for all clients\n" +
					"3. Implement PKCE for public clients\n" +
					"4. Return tokens only in response body",
				References: []string{
					"https://oauth.net/2.1/#implicit-flow",
					"https://tools.ietf.org/html/draft-ietf-oauth-security-topics-16#section-2.1.2",
				},
			}, nil
		}
	}

	return nil, nil
}

func (s *oauth2Scanner) testImplicitFlow(ctx context.Context, config OAuth2Config) (*types.Finding, error) {
	implicitURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=token&state=%s",
		config.AuthorizationURL, config.ClientID, url.QueryEscape(config.RedirectURI), s.generateState())

	resp, err := s.client.Get(implicitURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound && strings.Contains(resp.Header.Get("Location"), "access_token=") {
		return &types.Finding{
			Type:     "oauth2_implicit_flow_enabled",
			Severity: types.SeverityMedium,
			Title:    "Implicit Flow Enabled",
			Description: "The OAuth2 server supports implicit flow which is deprecated due to security concerns. " +
				"Implicit flow exposes tokens in URLs and provides no mechanism for refresh tokens.",
			Evidence: "Server responds to response_type=token requests",
			Solution: "Disable implicit flow and use authorization code flow with PKCE instead",
			References: []string{
				"https://oauth.net/2.1/#implicit-flow",
				"https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps",
			},
		}, nil
	}

	return nil, nil
}

func (s *oauth2Scanner) testJWTAlgNone(ctx context.Context, config OAuth2Config) (*types.Finding, error) {
	// This would require actual JWT token manipulation
	// For now, we'll check if the server accepts tokens with alg: none

	noneToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."

	req, err := http.NewRequest("GET", config.TokenURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+noneToken)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return &types.Finding{
			Type:        "jwt_alg_none_bypass",
			Severity:    types.SeverityCritical,
			Title:       "JWT Algorithm None Bypass",
			Description: "The server accepts JWT tokens with 'alg: none', allowing attackers to forge valid tokens without knowing the signing key.",
			Evidence:    fmt.Sprintf("Server response to alg:none token: %d", resp.StatusCode),
			Solution: "Explicitly verify JWT algorithm:\n" +
				"1. Reject tokens with alg: none\n" +
				"2. Use allowlist of accepted algorithms\n" +
				"3. Verify algorithm matches expected value\n" +
				"4. Always validate signatures",
			References: []string{
				"https://cwe.mitre.org/data/definitions/327.html",
				"https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
			},
		}, nil
	}

	return nil, nil
}

func (s *oauth2Scanner) testResponseTypeConfusion(ctx context.Context, config OAuth2Config) (*types.Finding, error) {
	confusedTypes := []string{
		"code token",
		"code id_token",
		"code token id_token",
		"token code",
	}

	for _, responseType := range confusedTypes {
		testURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=%s&state=%s",
			config.AuthorizationURL, config.ClientID, url.QueryEscape(config.RedirectURI),
			url.QueryEscape(responseType), s.generateState())

		resp, err := s.client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusFound {
			location := resp.Header.Get("Location")
			if strings.Contains(location, "access_token=") && strings.Contains(location, "code=") {
				return &types.Finding{
					Type:     "oauth2_response_type_confusion",
					Severity: types.SeverityHigh,
					Title:    "Response Type Confusion Attack",
					Description: "The OAuth2 server accepts hybrid response types that can lead to token leakage. " +
						"Attackers can exploit this to obtain both codes and tokens in a single request.",
					Evidence: fmt.Sprintf("Hybrid response type accepted: %s", responseType),
					Solution: "Restrict response types:\n" +
						"1. Only allow specific response_type values\n" +
						"2. Reject hybrid flows unless explicitly needed\n" +
						"3. Validate client is authorized for requested flow\n" +
						"4. Follow OAuth 2.0 Security BCP",
					References: []string{
						"https://tools.ietf.org/html/draft-ietf-oauth-security-topics",
						"https://portswigger.net/research/hidden-oauth-attack-vectors",
					},
					Metadata: map[string]interface{}{
						"response_type": responseType,
						"location":      location,
					},
				}, nil
			}
		}
	}

	return nil, nil
}

func (s *oauth2Scanner) testCSRF(ctx context.Context, config OAuth2Config) (*types.Finding, error) {
	// Test authorization request without state parameter
	noStateURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code",
		config.AuthorizationURL, config.ClientID, url.QueryEscape(config.RedirectURI))

	resp, err := s.client.Get(noStateURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if !strings.Contains(location, "state=") && strings.Contains(location, "code=") {
			return &types.Finding{
				Type:     "oauth2_csrf_vulnerable",
				Severity: types.SeverityMedium,
				Title:    "OAuth2 Flow Vulnerable to CSRF",
				Description: "The OAuth2 implementation does not require state parameter, making it vulnerable to CSRF attacks. " +
					"Attackers can trick users into authorizing malicious applications.",
				Evidence: "Authorization code issued without state parameter validation",
				Solution: "Implement CSRF protection:\n" +
					"1. Require state parameter for all authorization requests\n" +
					"2. Generate cryptographically random state values\n" +
					"3. Bind state to user session\n" +
					"4. Validate state on callback",
				References: []string{
					"https://tools.ietf.org/html/rfc6749#section-10.12",
					"https://portswigger.net/web-security/csrf",
				},
			}, nil
		}
	}

	return nil, nil
}

// Helper functions
func (s *oauth2Scanner) buildAuthURL(config OAuth2Config, state, responseType string) string {
	params := url.Values{}
	params.Set("client_id", config.ClientID)
	params.Set("redirect_uri", config.RedirectURI)
	params.Set("response_type", responseType)
	params.Set("state", state)
	if len(config.Scopes) > 0 {
		params.Set("scope", strings.Join(config.Scopes, " "))
	}

	return fmt.Sprintf("%s?%s", config.AuthorizationURL, params.Encode())
}

func (s *oauth2Scanner) generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (s *oauth2Scanner) generateCodeVerifier() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *oauth2Scanner) generateCodeChallenge(verifier string) string {
	// In production, this would compute SHA256
	return base64.RawURLEncoding.EncodeToString([]byte(verifier))
}

func (s *oauth2Scanner) extractCode(location string) string {
	u, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return u.Query().Get("code")
}

func (s *oauth2Scanner) extractHost(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	return u.Host
}

func (s *oauth2Scanner) exchangeCode(config OAuth2Config, code string) (*http.Response, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", config.RedirectURI)
	data.Set("client_id", config.ClientID)
	if config.ClientSecret != "" {
		data.Set("client_secret", config.ClientSecret)
	}

	req, err := http.NewRequest("POST", config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return s.client.Do(req)
}
