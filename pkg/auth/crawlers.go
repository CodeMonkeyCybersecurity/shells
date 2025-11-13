// pkg/auth/crawlers.go
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"golang.org/x/net/html"
)

// SAMLCrawler discovers SAML endpoints
type SAMLCrawler struct {
	logger     *logger.Logger
	httpClient *http.Client
}

func NewSAMLCrawler(log *logger.Logger) *SAMLCrawler {
	return &SAMLCrawler{
		logger: log.WithComponent("saml-crawler"),
		httpClient: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects automatically
			},
		},
	}
}

func (c *SAMLCrawler) Name() string { return "saml" }

func (c *SAMLCrawler) Crawl(ctx context.Context, target string) (*AuthEndpoints, error) {
	saml := &SAMLEndpoints{}
	found := false

	// Check common SAML endpoints
	endpoints := []struct {
		path string
		typ  string
	}{
		{"/saml/metadata", "metadata"},
		{"/saml2/metadata", "metadata"},
		{"/sso/saml/metadata", "metadata"},
		{"/auth/saml/metadata", "metadata"},
		{"/saml", "sso"},
		{"/saml/sso", "sso"},
		{"/saml/login", "sso"},
		{"/sso/saml", "sso"},
		{"/saml/slo", "slo"},
		{"/saml/logout", "slo"},
		{"/Shibboleth.sso/Metadata", "metadata"},
		{"/simplesaml/saml2/idp/metadata.php", "metadata"},
	}

	baseURL := strings.TrimSuffix(target, "/")

	for _, ep := range endpoints {
		url := baseURL + ep.path
		resp, err := c.httpClient.Get(url)
		if err != nil {
			continue
		}
		defer httpclient.CloseBody(resp)

		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit

			// Check if it's SAML metadata
			if strings.Contains(string(body), "EntityDescriptor") ||
				strings.Contains(string(body), "urn:oasis:names:tc:SAML") {
				found = true

				switch ep.typ {
				case "metadata":
					saml.MetadataURL = url
					// Try to extract entity ID
					if entityID := extractEntityID(string(body)); entityID != "" {
						saml.EntityID = entityID
					}
				case "sso":
					saml.SSOUrl = url
				case "slo":
					saml.SLOUrl = url
				}
			}
		}
	}

	// Check main page for SAML indicators
	resp, err := c.httpClient.Get(baseURL)
	if err == nil {
		defer httpclient.CloseBody(resp)
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

		// Look for SAML form actions
		if urls := findSAMLUrls(string(body)); len(urls) > 0 {
			found = true
			for _, url := range urls {
				if strings.Contains(url, "sso") || strings.Contains(url, "login") {
					if saml.SSOUrl == "" {
						saml.SSOUrl = url
					}
				}
			}
		}
	}

	if !found {
		return nil, fmt.Errorf("no SAML endpoints found")
	}

	return &AuthEndpoints{
		Type: "saml",
		Endpoints: map[string]interface{}{
			"saml": saml,
		},
	}, nil
}

// OAuth2Crawler discovers OAuth2 endpoints
type OAuth2Crawler struct {
	logger     *logger.Logger
	httpClient *http.Client
}

func NewOAuth2Crawler(log *logger.Logger) *OAuth2Crawler {
	return &OAuth2Crawler{
		logger:     log.WithComponent("oauth2-crawler"),
		httpClient: &http.Client{},
	}
}

func (c *OAuth2Crawler) Name() string { return "oauth2" }

func (c *OAuth2Crawler) Crawl(ctx context.Context, target string) (*AuthEndpoints, error) {
	oauth2 := &OAuth2Endpoints{}
	found := false

	// Common OAuth2 endpoints
	endpoints := []struct {
		path string
		typ  string
	}{
		{"/oauth/authorize", "authorize"},
		{"/oauth2/authorize", "authorize"},
		{"/oauth2/v2/authorize", "authorize"},
		{"/oauth/token", "token"},
		{"/oauth2/token", "token"},
		{"/oauth2/v2/token", "token"},
		{"/oauth/revoke", "revoke"},
		{"/oauth2/revoke", "revoke"},
		{"/oauth/introspect", "introspect"},
		{"/oauth2/introspect", "introspect"},
		{"/userinfo", "userinfo"},
		{"/oauth2/userinfo", "userinfo"},
		{"/api/oauth/authorize", "authorize"},
		{"/api/oauth/token", "token"},
	}

	baseURL := strings.TrimSuffix(target, "/")

	for _, ep := range endpoints {
		url := baseURL + ep.path
		resp, err := c.httpClient.Get(url)
		if err != nil {
			continue
		}
		httpclient.CloseBody(resp)

		// OAuth2 endpoints often return 400/401/405 for GET requests
		if resp.StatusCode != 404 {
			found = true
			switch ep.typ {
			case "authorize":
				oauth2.AuthorizationURL = url
			case "token":
				oauth2.TokenURL = url
			case "revoke":
				oauth2.RevokeURL = url
			case "introspect":
				oauth2.IntrospectURL = url
			case "userinfo":
				oauth2.UserInfoURL = url
			}
		}
	}

	if !found {
		return nil, fmt.Errorf("no OAuth2 endpoints found")
	}

	return &AuthEndpoints{
		Type: "oauth2",
		Endpoints: map[string]interface{}{
			"oauth2": oauth2,
		},
	}, nil
}

// OIDCCrawler discovers OpenID Connect endpoints
type OIDCCrawler struct {
	logger     *logger.Logger
	httpClient *http.Client
}

func NewOIDCCrawler(log *logger.Logger) *OIDCCrawler {
	return &OIDCCrawler{
		logger:     log.WithComponent("oidc-crawler"),
		httpClient: &http.Client{},
	}
}

func (c *OIDCCrawler) Name() string { return "oidc" }

func (c *OIDCCrawler) Crawl(ctx context.Context, target string) (*AuthEndpoints, error) {
	oidc := &OIDCEndpoints{}

	// Check well-known configuration
	configPaths := []string{
		"/.well-known/openid-configuration",
		"/auth/realms/master/.well-known/openid-configuration", // Keycloak
		"/.well-known/oauth-authorization-server",              // OAuth2 metadata
		"/oauth2/.well-known/openid-configuration",
		"/oidc/.well-known/openid-configuration",
	}

	baseURL := strings.TrimSuffix(target, "/")

	for _, path := range configPaths {
		url := baseURL + path
		resp, err := c.httpClient.Get(url)
		if err != nil {
			continue
		}
		defer httpclient.CloseBody(resp)

		if resp.StatusCode == 200 {
			var config map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&config); err == nil {
				oidc.ConfigurationURL = url

				// Extract key URLs
				if issuer, ok := config["issuer"].(string); ok {
					oidc.Issuer = issuer
				}
				if jwks, ok := config["jwks_uri"].(string); ok {
					oidc.JWKSURL = jwks
				}

				// Extract OAuth2 endpoints
				oauth2 := &OAuth2Endpoints{}
				if auth, ok := config["authorization_endpoint"].(string); ok {
					oauth2.AuthorizationURL = auth
				}
				if token, ok := config["token_endpoint"].(string); ok {
					oauth2.TokenURL = token
				}
				if userinfo, ok := config["userinfo_endpoint"].(string); ok {
					oauth2.UserInfoURL = userinfo
				}
				if revoke, ok := config["revocation_endpoint"].(string); ok {
					oauth2.RevokeURL = revoke
				}
				if introspect, ok := config["introspection_endpoint"].(string); ok {
					oauth2.IntrospectURL = introspect
				}

				// Extract supported features
				if scopes, ok := config["scopes_supported"].([]interface{}); ok {
					for _, scope := range scopes {
						if s, ok := scope.(string); ok {
							oauth2.Scopes = append(oauth2.Scopes, s)
						}
					}
				}
				if grants, ok := config["grant_types_supported"].([]interface{}); ok {
					for _, grant := range grants {
						if g, ok := grant.(string); ok {
							oauth2.GrantTypes = append(oauth2.GrantTypes, g)
						}
					}
				}

				oidc.OAuth2 = oauth2

				return &AuthEndpoints{
					Type: "oidc",
					Endpoints: map[string]interface{}{
						"oidc": oidc,
					},
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no OIDC configuration found")
}

// WebAuthnCrawler discovers WebAuthn endpoints
type WebAuthnCrawler struct {
	logger     *logger.Logger
	httpClient *http.Client
}

func NewWebAuthnCrawler(log *logger.Logger) *WebAuthnCrawler {
	return &WebAuthnCrawler{
		logger:     log.WithComponent("webauthn-crawler"),
		httpClient: &http.Client{},
	}
}

func (c *WebAuthnCrawler) Name() string { return "webauthn" }

func (c *WebAuthnCrawler) Crawl(ctx context.Context, target string) (*AuthEndpoints, error) {
	webauthn := &WebAuthnEndpoints{}
	found := false

	// Common WebAuthn endpoints
	endpoints := []struct {
		path string
		typ  string
	}{
		{"/webauthn/register", "register"},
		{"/webauthn/login", "login"},
		{"/webauthn/authenticate", "login"},
		{"/api/webauthn/register", "register"},
		{"/api/webauthn/login", "login"},
		{"/api/webauthn/challenge", "challenge"},
		{"/auth/webauthn/register", "register"},
		{"/auth/webauthn/login", "login"},
		{"/fido2/register", "register"},
		{"/fido2/authenticate", "login"},
		{"/passkeys/register", "register"},
		{"/passkeys/authenticate", "login"},
	}

	baseURL := strings.TrimSuffix(target, "/")

	// First check if the main page mentions WebAuthn
	resp, err := c.httpClient.Get(baseURL)
	if err == nil {
		defer httpclient.CloseBody(resp)
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		bodyStr := string(body)

		// Look for WebAuthn indicators
		if strings.Contains(bodyStr, "navigator.credentials") ||
			strings.Contains(bodyStr, "webauthn") ||
			strings.Contains(bodyStr, "publicKeyCredential") ||
			strings.Contains(bodyStr, "passkey") {
			found = true

			// Try to extract RP info from JavaScript
			if rpName := extractRPName(bodyStr); rpName != "" {
				webauthn.RPName = rpName
			}
			if rpID := extractRPID(bodyStr); rpID != "" {
				webauthn.RPID = rpID
			}
		}
	}

	// Check specific endpoints
	for _, ep := range endpoints {
		url := baseURL + ep.path
		resp, err := c.httpClient.Get(url)
		if err != nil {
			continue
		}
		httpclient.CloseBody(resp)

		if resp.StatusCode != 404 {
			found = true
			switch ep.typ {
			case "register":
				webauthn.RegisterURL = url
			case "login":
				webauthn.LoginURL = url
			case "challenge":
				webauthn.ChallengeURL = url
			}
		}
	}

	if !found {
		return nil, fmt.Errorf("no WebAuthn endpoints found")
	}

	return &AuthEndpoints{
		Type: "webauthn",
		Endpoints: map[string]interface{}{
			"webauthn": webauthn,
		},
	}, nil
}

// FormCrawler discovers form-based authentication
type FormCrawler struct {
	logger     *logger.Logger
	httpClient *http.Client
}

func NewFormCrawler(log *logger.Logger) *FormCrawler {
	return &FormCrawler{
		logger:     log.WithComponent("form-crawler"),
		httpClient: &http.Client{},
	}
}

func (c *FormCrawler) Name() string { return "forms" }

func (c *FormCrawler) Crawl(ctx context.Context, target string) (*AuthEndpoints, error) {
	forms := []FormEndpoint{}

	// Common login pages
	loginPaths := []string{
		"/login", "/signin", "/auth", "/authenticate",
		"/account/login", "/accounts/login", "/user/login",
		"/wp-login.php", "/wp-admin",
		"/admin", "/admin/login", "/administrator",
		"/portal/login", "/secure/login",
	}

	baseURL := strings.TrimSuffix(target, "/")

	for _, path := range loginPaths {
		url := baseURL + path
		resp, err := c.httpClient.Get(url)
		if err != nil {
			continue
		}
		defer httpclient.CloseBody(resp)

		if resp.StatusCode == 200 {
			// Parse HTML and look for forms
			doc, err := html.Parse(resp.Body)
			if err != nil {
				continue
			}

			if loginForms := findLoginForms(doc, url); len(loginForms) > 0 {
				forms = append(forms, loginForms...)
			}
		}
	}

	// Also check the main page
	resp, err := c.httpClient.Get(baseURL)
	if err == nil {
		defer httpclient.CloseBody(resp)
		doc, _ := html.Parse(resp.Body)
		if loginForms := findLoginForms(doc, baseURL); len(loginForms) > 0 {
			forms = append(forms, loginForms...)
		}
	}

	if len(forms) == 0 {
		return nil, fmt.Errorf("no login forms found")
	}

	return &AuthEndpoints{
		Type: "forms",
		Endpoints: map[string]interface{}{
			"forms": forms,
		},
	}, nil
}

// Helper functions

func extractEntityID(metadata string) string {
	// Simple regex to extract entityID
	re := regexp.MustCompile(`entityID="([^"]+)"`)
	if matches := re.FindStringSubmatch(metadata); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func findSAMLUrls(body string) []string {
	urls := []string{}

	// Look for SAML-related URLs in HTML
	re := regexp.MustCompile(`(?i)(href|action)="([^"]*saml[^"]*)"`)
	matches := re.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		if len(match) > 2 {
			urls = append(urls, match[2])
		}
	}

	return urls
}

func extractRPName(body string) string {
	// Look for RP name in JavaScript
	re := regexp.MustCompile(`(?i)rp["\s]*:["\s]*{[^}]*name["\s]*:["\s]*["']([^"']+)["']`)
	if matches := re.FindStringSubmatch(body); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func extractRPID(body string) string {
	// Look for RP ID in JavaScript
	re := regexp.MustCompile(`(?i)rp["\s]*:["\s]*{[^}]*id["\s]*:["\s]*["']([^"']+)["']`)
	if matches := re.FindStringSubmatch(body); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func findLoginForms(n *html.Node, pageURL string) []FormEndpoint {
	forms := []FormEndpoint{}

	// Traverse HTML looking for forms
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			form := analyzeForm(n, pageURL)
			if form != nil && isLoginForm(form) {
				forms = append(forms, *form)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(n)
	return forms
}

func analyzeForm(n *html.Node, pageURL string) *FormEndpoint {
	form := &FormEndpoint{
		URL:         pageURL,
		Method:      "POST",
		OtherFields: make(map[string]string),
	}

	// Extract form attributes
	for _, attr := range n.Attr {
		switch attr.Key {
		case "action":
			form.FormAction = attr.Val
		case "method":
			form.Method = strings.ToUpper(attr.Val)
		}
	}

	// Find input fields
	findInputs(n, form)

	return form
}

func findInputs(n *html.Node, form *FormEndpoint) {
	if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "button") {
		var name, typ, value string

		for _, attr := range n.Attr {
			switch attr.Key {
			case "name":
				name = attr.Val
			case "type":
				typ = attr.Val
			case "value":
				value = attr.Val
			}
		}

		// Classify input
		nameLower := strings.ToLower(name)
		if strings.Contains(nameLower, "user") || strings.Contains(nameLower, "email") ||
			strings.Contains(nameLower, "login") || typ == "email" {
			form.UsernameField = name
		} else if strings.Contains(nameLower, "pass") || typ == "password" {
			form.PasswordField = name
		} else if typ == "submit" {
			form.SubmitValue = value
		} else if name != "" {
			form.OtherFields[name] = value
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		findInputs(c, form)
	}
}

func isLoginForm(form *FormEndpoint) bool {
	// Form must have both username and password fields
	return form.UsernameField != "" && form.PasswordField != ""
}
