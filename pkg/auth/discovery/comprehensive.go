// pkg/auth/discovery/comprehensive.go
package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/PuerkitoBio/goquery"
	"github.com/go-ldap/ldap/v3"
)

// ComprehensiveAuthDiscovery provides intelligent authentication discovery
type ComprehensiveAuthDiscovery struct {
	logger           *logger.Logger
	httpClient       *http.Client
	portScanner      *PortScanner
	webCrawler       *WebCrawler
	jsAnalyzer       *JavaScriptAnalyzer
	mlDetector       *MLAuthDetectorEngine
	apiExtractor     *APIExtractor
	securityAnalyzer *SecurityAnalyzer
}

// AuthInventory contains all discovered authentication methods
type AuthInventory struct {
	Target      string                 `json:"target"`
	Timestamp   time.Time              `json:"timestamp"`
	NetworkAuth *NetworkAuthMethods    `json:"network_auth,omitempty"`
	WebAuth     *WebAuthMethods        `json:"web_auth,omitempty"`
	APIAuth     *APIAuthMethods        `json:"api_auth,omitempty"`
	CustomAuth  []CustomAuthMethod     `json:"custom_auth,omitempty"`
	Confidence  map[string]float64     `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NetworkAuthMethods contains network-based authentication discoveries
type NetworkAuthMethods struct {
	LDAP     []LDAPEndpoint     `json:"ldap,omitempty"`
	Kerberos []KerberosEndpoint `json:"kerberos,omitempty"`
	RADIUS   []RADIUSEndpoint   `json:"radius,omitempty"`
	SMB      []SMBEndpoint      `json:"smb,omitempty"`
	RDP      []RDPEndpoint      `json:"rdp,omitempty"`
	SSH      []SSHEndpoint      `json:"ssh,omitempty"`
	SMTP     []SMTPAuthMethod   `json:"smtp,omitempty"`
	IMAP     []IMAPAuthMethod   `json:"imap,omitempty"`
	Database []DatabaseAuth     `json:"database,omitempty"`
}

// WebAuthMethods contains web-based authentication discoveries
type WebAuthMethods struct {
	BasicAuth []BasicAuthEndpoint `json:"basic_auth,omitempty"`
	FormLogin []FormLoginEndpoint `json:"form_login,omitempty"`
	SAML      []SAMLEndpoint      `json:"saml,omitempty"`
	OAuth2    []OAuth2Endpoint    `json:"oauth2,omitempty"`
	OIDC      []OIDCEndpoint      `json:"oidc,omitempty"`
	WebAuthn  []WebAuthnEndpoint  `json:"webauthn,omitempty"`
	CAS       []CASEndpoint       `json:"cas,omitempty"`
	JWT       []JWTEndpoint       `json:"jwt,omitempty"`
	NTLM      []NTLMEndpoint      `json:"ntlm,omitempty"`
	Cookies   []CookieAuth        `json:"cookie_auth,omitempty"`
	Headers   []HeaderAuth        `json:"header_auth,omitempty"`
}

// NewComprehensiveAuthDiscovery creates a new comprehensive auth discovery instance
func NewComprehensiveAuthDiscovery(logger *logger.Logger) *ComprehensiveAuthDiscovery {
	return &ComprehensiveAuthDiscovery{
		logger: logger,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // For bug bounty testing
				},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects automatically
			},
		},
		portScanner:      NewPortScanner(logger),
		webCrawler:       NewWebCrawler(logger),
		jsAnalyzer:       NewJavaScriptAnalyzer(logger),
		mlDetector:       NewMLAuthDetector(logger),
		apiExtractor:     NewAPIExtractor(logger),
		securityAnalyzer: NewSecurityAnalyzer(logger),
	}
}

// DiscoverAll performs comprehensive authentication discovery
func (c *ComprehensiveAuthDiscovery) DiscoverAll(ctx context.Context, target string) (*AuthInventory, error) {
	c.logger.Info("Starting comprehensive auth discovery",
		"target", target,
		"operation", "auth.DiscoverAll")

	inventory := &AuthInventory{
		Target:     target,
		Timestamp:  time.Now(),
		Confidence: make(map[string]float64),
		Metadata:   make(map[string]interface{}),
	}

	// Parse target to understand what we're dealing with
	targetInfo, err := c.parseTarget(target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target: %w", err)
	}

	// Run discovery in parallel
	var wg sync.WaitGroup
	discoveryErrors := make(chan error, 10)

	// Network-based authentication discovery
	wg.Add(1)
	go func() {
		defer wg.Done()
		if networkAuth, err := c.discoverNetworkAuth(ctx, targetInfo); err != nil {
			discoveryErrors <- fmt.Errorf("network auth discovery: %w", err)
		} else {
			inventory.NetworkAuth = networkAuth
		}
	}()

	// Web-based authentication discovery
	wg.Add(1)
	go func() {
		defer wg.Done()
		if webAuth, err := c.discoverWebAuth(ctx, targetInfo); err != nil {
			discoveryErrors <- fmt.Errorf("web auth discovery: %w", err)
		} else {
			inventory.WebAuth = webAuth
		}
	}()

	// API authentication discovery
	wg.Add(1)
	go func() {
		defer wg.Done()
		if apiAuth, err := c.discoverAPIAuth(ctx, targetInfo); err != nil {
			discoveryErrors <- fmt.Errorf("API auth discovery: %w", err)
		} else {
			inventory.APIAuth = apiAuth
		}
	}()

	// Custom authentication discovery using ML
	wg.Add(1)
	go func() {
		defer wg.Done()
		if customAuth, err := c.discoverCustomAuth(ctx, targetInfo); err != nil {
			discoveryErrors <- fmt.Errorf("custom auth discovery: %w", err)
		} else {
			inventory.CustomAuth = customAuth
		}
	}()

	// Wait for all discovery operations
	wg.Wait()
	close(discoveryErrors)

	// Collect any errors
	var errs []string
	for err := range discoveryErrors {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		inventory.Metadata["discovery_errors"] = errs
	}

	// Calculate confidence scores
	c.calculateConfidenceScores(inventory)

	// Log summary
	c.logDiscoverySummary(inventory)

	return inventory, nil
}

// DiscoverEndpoints method is now implemented in api_extractor.go

// discoverNetworkAuth discovers network-based authentication methods
func (c *ComprehensiveAuthDiscovery) discoverNetworkAuth(ctx context.Context, target *TargetInfo) (*NetworkAuthMethods, error) {
	networkAuth := &NetworkAuthMethods{}

	// Define auth-related ports to scan
	authPorts := []PortDefinition{
		{Port: 389, Protocol: "LDAP", SSL: false},
		{Port: 636, Protocol: "LDAPS", SSL: true},
		{Port: 88, Protocol: "Kerberos", SSL: false},
		{Port: 1812, Protocol: "RADIUS", SSL: false},
		{Port: 445, Protocol: "SMB", SSL: false},
		{Port: 3389, Protocol: "RDP", SSL: false},
		{Port: 22, Protocol: "SSH", SSL: false},
		{Port: 25, Protocol: "SMTP", SSL: false},
		{Port: 587, Protocol: "SMTP-TLS", SSL: true},
		{Port: 143, Protocol: "IMAP", SSL: false},
		{Port: 993, Protocol: "IMAPS", SSL: true},
		{Port: 3306, Protocol: "MySQL", SSL: false},
		{Port: 5432, Protocol: "PostgreSQL", SSL: false},
		{Port: 1433, Protocol: "MSSQL", SSL: false},
		{Port: 27017, Protocol: "MongoDB", SSL: false},
		{Port: 6379, Protocol: "Redis", SSL: false},
	}

	// Scan ports in parallel
	results := c.portScanner.ScanPorts(ctx, target, authPorts)

	// Process results based on discovered services
	for _, result := range results {
		switch result.Protocol {
		case "LDAP", "LDAPS":
			if ldapEndpoint := c.probeLDAP(ctx, result); ldapEndpoint != nil {
				networkAuth.LDAP = append(networkAuth.LDAP, *ldapEndpoint)
			}
		case "Kerberos":
			if krbEndpoint := c.probeKerberos(ctx, result); krbEndpoint != nil {
				networkAuth.Kerberos = append(networkAuth.Kerberos, *krbEndpoint)
			}
		case "RADIUS":
			if radiusEndpoint := c.probeRADIUS(ctx, result); radiusEndpoint != nil {
				networkAuth.RADIUS = append(networkAuth.RADIUS, *radiusEndpoint)
			}
		case "SMB":
			if smbEndpoint := c.probeSMB(ctx, result); smbEndpoint != nil {
				networkAuth.SMB = append(networkAuth.SMB, *smbEndpoint)
			}
		case "SMTP", "SMTP-TLS":
			if smtpAuth := c.probeSMTPAuth(ctx, result); smtpAuth != nil {
				networkAuth.SMTP = append(networkAuth.SMTP, *smtpAuth)
			}
		case "IMAP", "IMAPS":
			if imapAuth := c.probeIMAPAuth(ctx, result); imapAuth != nil {
				networkAuth.IMAP = append(networkAuth.IMAP, *imapAuth)
			}
		default:
			// Database auth methods
			if dbAuth := c.probeDatabaseAuth(ctx, result); dbAuth != nil {
				networkAuth.Database = append(networkAuth.Database, *dbAuth)
			}
		}
	}

	return networkAuth, nil
}

// probeLDAP probes an LDAP endpoint for authentication details
func (c *ComprehensiveAuthDiscovery) probeLDAP(ctx context.Context, port PortScanResult) *LDAPEndpoint {
	endpoint := &LDAPEndpoint{
		Host:         port.Host,
		Port:         port.Port,
		SSL:          port.SSL,
		DiscoveredAt: time.Now(),
	}

	// Try anonymous bind to get information
	ldapURL := fmt.Sprintf("ldap://%s:%d", port.Host, port.Port)
	if port.SSL {
		ldapURL = fmt.Sprintf("ldaps://%s:%d", port.Host, port.Port)
	}

	l, err := ldap.DialURL(ldapURL)
	if err != nil {
		c.logger.Debug("Failed to connect to LDAP", "error", err, "url", ldapURL)
		return endpoint
	}
	defer l.Close()

	// Try anonymous bind
	err = l.Bind("", "")
	endpoint.AnonymousBindAllowed = (err == nil)

	// Search for root DSE to get naming contexts
	if endpoint.AnonymousBindAllowed {
		searchRequest := ldap.NewSearchRequest(
			"",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0, 0, false,
			"(objectClass=*)",
			[]string{"namingContexts", "supportedSASLMechanisms", "vendorName"},
			nil,
		)

		sr, err := l.Search(searchRequest)
		if err == nil && len(sr.Entries) > 0 {
			entry := sr.Entries[0]
			endpoint.NamingContexts = entry.GetAttributeValues("namingContexts")
			endpoint.SupportedSASLMechanisms = entry.GetAttributeValues("supportedSASLMechanisms")
			if vendor := entry.GetAttributeValue("vendorName"); vendor != "" {
				endpoint.VendorName = vendor
			}

			// Try to determine LDAP type
			endpoint.Type = c.determineLDAPType(endpoint)
		}
	}

	// Try to enumerate users if we can
	if len(endpoint.NamingContexts) > 0 {
		endpoint.UserEnumerationPossible = c.checkLDAPUserEnumeration(l, endpoint.NamingContexts[0])
	}

	return endpoint
}

// discoverWebAuth discovers web-based authentication methods
func (c *ComprehensiveAuthDiscovery) discoverWebAuth(ctx context.Context, target *TargetInfo) (*WebAuthMethods, error) {
	webAuth := &WebAuthMethods{}

	// Start with the base URL
	baseURLs := c.generateBaseURLs(target)

	for _, baseURL := range baseURLs {
		// Crawl the site to find auth endpoints
		authPages := c.webCrawler.FindAuthPages(ctx, baseURL)

		for _, page := range authPages {
			// TODO: Implement analyzeAuthPage method
			// methods := c.analyzeAuthPage(ctx, page)
			// c.categorizeWebAuthMethods(methods, webAuth)
			_ = page // Prevent unused variable error
		}

		// Check well-known auth endpoints
		c.checkWellKnownEndpoints(ctx, baseURL, webAuth)

		// JavaScript analysis for modern auth
		jsAuth := c.jsAnalyzer.FindAuthInJavaScript(ctx, baseURL)
		c.mergeJavaScriptAuth(jsAuth, webAuth)
	}

	// Check for authentication headers
	c.checkAuthHeaders(ctx, target, webAuth)

	return webAuth, nil
}

// analyzeAuthPage analyzes a single page for authentication methods
func (c *ComprehensiveAuthDiscovery) analyzeAuthPage(ctx context.Context, pageURL string) []AuthMethod {
	var methods []AuthMethod

	resp, err := c.httpClient.Get(pageURL)
	if err != nil {
		return methods
	}
	defer httpclient.CloseBody(resp)

	// Check response headers first
	if authHeader := resp.Header.Get("WWW-Authenticate"); authHeader != "" {
		methods = append(methods, c.parseWWWAuthenticate(authHeader, pageURL)...)
	}

	// Parse HTML
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return methods
	}

	// Look for login forms
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		if form := c.analyzeLoginForm(s, pageURL); form != nil {
			methods = append(methods, form)
		}
	})

	// Look for OAuth2/OIDC buttons
	doc.Find("a, button").Each(func(i int, s *goquery.Selection) {
		if oauth := c.detectOAuthButton(s, pageURL); oauth != nil {
			methods = append(methods, oauth)
		}
	})

	// Look for WebAuthn/FIDO2
	if c.detectWebAuthn(doc) {
		methods = append(methods, &WebAuthnMethod{
			URL:  pageURL,
			Type: "WebAuthn",
		})
	}

	// Look for SAML
	if saml := c.detectSAML(doc, resp); saml != nil {
		methods = append(methods, saml)
	}

	return methods
}

// checkWellKnownEndpoints checks standard authentication endpoints
func (c *ComprehensiveAuthDiscovery) checkWellKnownEndpoints(ctx context.Context, baseURL string, webAuth *WebAuthMethods) {
	wellKnownEndpoints := []struct {
		Path     string
		AuthType string
		Checker  func(string) AuthMethod
	}{
		// OAuth2/OIDC
		{"/.well-known/openid-configuration", "OIDC", c.checkOIDCConfiguration},
		{"/.well-known/oauth-authorization-server", "OAuth2", c.checkOAuth2Configuration},
		{"/oauth/authorize", "OAuth2", c.checkOAuth2Endpoint},
		{"/oauth/token", "OAuth2", c.checkOAuth2Endpoint},

		// SAML
		{"/saml/metadata", "SAML", c.checkSAMLMetadata},
		{"/saml/sso", "SAML", c.checkSAMLEndpoint},
		{"/Shibboleth.sso/Metadata", "Shibboleth", c.checkShibboleth},

		// CAS
		{"/cas/login", "CAS", c.checkCASEndpoint},

		// Common login paths
		{"/login", "Generic", c.checkGenericLogin},
		{"/signin", "Generic", c.checkGenericLogin},
		{"/auth/login", "Generic", c.checkGenericLogin},
		{"/user/login", "Generic", c.checkGenericLogin},
		{"/account/login", "Generic", c.checkGenericLogin},
		{"/admin/login", "Admin", c.checkGenericLogin},
		{"/wp-login.php", "WordPress", c.checkWordPressLogin},

		// API auth
		{"/api/auth", "API", c.checkAPIAuth},
		{"/api/login", "API", c.checkAPIAuth},
		{"/api/v1/auth", "API", c.checkAPIAuth},
		{"/api/v1/login", "API", c.checkAPIAuth},

		// WebAuthn
		{"/webauthn/register", "WebAuthn", c.checkWebAuthnEndpoint},
		{"/fido2/register", "FIDO2", c.checkWebAuthnEndpoint},
	}

	var wg sync.WaitGroup
	mu := &sync.Mutex{}

	for _, endpoint := range wellKnownEndpoints {
		wg.Add(1)
		go func(ep struct {
			Path     string
			AuthType string
			Checker  func(string) AuthMethod
		}) {
			defer wg.Done()

			fullURL := strings.TrimRight(baseURL, "/") + ep.Path
			if method := ep.Checker(fullURL); method != nil {
				mu.Lock()
				c.categorizeAuthMethod(method, webAuth)
				mu.Unlock()

				c.logger.Debug("Found auth endpoint",
					"url", fullURL,
					"type", ep.AuthType)
			}
		}(endpoint)
	}

	wg.Wait()
}

type RESTEndpoint struct {
	URL string `json:"url"`
}

type GraphQLEndpoint struct {
	URL string `json:"url"`
}

type SOAPEndpoint struct {
	URL string `json:"url"`
}

// APIAuthMethods contains API-based authentication discoveries
type APIAuthMethods struct {
	REST    []RESTEndpoint    `json:"rest,omitempty"`
	GraphQL []GraphQLEndpoint `json:"graphql,omitempty"`
	SOAP    []SOAPEndpoint    `json:"soap,omitempty"`
}

// TargetInfo contains information about the discovery target
type TargetInfo struct {
	Host    string
	BaseURL string
}

// AuthMethod represents a discovered authentication method
type AuthMethod interface {
	GetType() string
	GetURL() string
}

// WebAuthnMethod represents WebAuthn authentication
type WebAuthnMethod struct {
	URL  string
	Type string
}

func (w *WebAuthnMethod) GetType() string { return w.Type }
func (w *WebAuthnMethod) GetURL() string  { return w.URL }

// OIDCMethod represents OpenID Connect authentication
type OIDCMethod struct {
	URL  string
	Type string
}

func (o *OIDCMethod) GetType() string { return o.Type }
func (o *OIDCMethod) GetURL() string  { return o.URL }

// OAuth2Method represents OAuth2 authentication
type OAuth2Method struct {
	URL  string
	Type string
}

func (o *OAuth2Method) GetType() string { return o.Type }
func (o *OAuth2Method) GetURL() string  { return o.URL }

// SAMLMethod represents SAML authentication
type SAMLMethod struct {
	URL  string
	Type string
}

func (s *SAMLMethod) GetType() string { return s.Type }
func (s *SAMLMethod) GetURL() string  { return s.URL }

// ShibbolethMethod represents Shibboleth authentication
type ShibbolethMethod struct {
	URL  string
	Type string
}

func (s *ShibbolethMethod) GetType() string { return s.Type }
func (s *ShibbolethMethod) GetURL() string  { return s.URL }

// CASMethod represents CAS authentication
type CASMethod struct {
	URL  string
	Type string
}

func (c *CASMethod) GetType() string { return c.Type }
func (c *CASMethod) GetURL() string  { return c.URL }

// GenericLoginMethod represents generic form-based login
type GenericLoginMethod struct {
	URL  string
	Type string
}

func (g *GenericLoginMethod) GetType() string { return g.Type }
func (g *GenericLoginMethod) GetURL() string  { return g.URL }

// WordPressMethod represents WordPress authentication
type WordPressMethod struct {
	URL  string
	Type string
}

func (w *WordPressMethod) GetType() string { return w.Type }
func (w *WordPressMethod) GetURL() string  { return w.URL }

// APIAuthMethod represents API authentication
type APIAuthMethod struct {
	URL      string
	Type     string
	AuthType string
}

func (a *APIAuthMethod) GetType() string { return a.Type }
func (a *APIAuthMethod) GetURL() string  { return a.URL }

// APIExtractor is now defined in api_extractor.go

// verifyCustomAuth verifies a custom authentication method
func (c *ComprehensiveAuthDiscovery) verifyCustomAuth(ctx context.Context, method *CustomAuthMethod) bool {
	// Basic verification - can be enhanced later
	return method.Confidence > 0.5
}

// detectCustomAuth finds non-standard authentication implementations
func (c *ComprehensiveAuthDiscovery) discoverCustomAuth(ctx context.Context, target *TargetInfo) ([]CustomAuthMethod, error) {
	var customMethods []CustomAuthMethod

	// Use ML to detect custom auth patterns
	patterns := c.mlDetector.DetectAuthPatterns(ctx, target)

	for _, pattern := range patterns {
		customMethod := CustomAuthMethod{
			Type:        pattern.Type,
			Endpoint:    pattern.Endpoint,
			Confidence:  pattern.Confidence,
			Indicators:  pattern.Indicators,
			Description: pattern.Description,
		}

		// Verify the custom auth method
		if c.verifyCustomAuth(ctx, &customMethod) {
			customMethods = append(customMethods, customMethod)
		}
	}

	return customMethods, nil
}

// Stub methods for compilation
func (c *ComprehensiveAuthDiscovery) parseTarget(target string) (*TargetInfo, error) {
	return &TargetInfo{
		Host:    target,
		BaseURL: "https://" + target,
	}, nil
}

func (c *ComprehensiveAuthDiscovery) generateBaseURLs(target *TargetInfo) []string {
	return []string{target.BaseURL}
}

func (c *ComprehensiveAuthDiscovery) categorizeWebAuthMethods(methods []AuthMethod, webAuth *WebAuthMethods) {
	// Stub implementation
}

func (c *ComprehensiveAuthDiscovery) mergeJavaScriptAuth(jsAuth []JSAuthDiscovery, webAuth *WebAuthMethods) {
	// Convert JSAuthDiscovery to appropriate endpoint types
	for _, js := range jsAuth {
		switch js.Type {
		case "oauth2", "openid":
			if js.OAuth != nil {
				endpoint := OAuth2Endpoint{
					AuthorizeURL: js.OAuth.AuthURL,
					TokenURL:     js.OAuth.TokenURL,
					Scopes:       js.OAuth.Scopes,
				}
				webAuth.OAuth2 = append(webAuth.OAuth2, endpoint)
			}
		case "oidc":
			for _, ep := range js.Endpoints {
				endpoint := OIDCEndpoint{
					ConfigURL: ep,
				}
				webAuth.OIDC = append(webAuth.OIDC, endpoint)
			}
		case "saml":
			for _, ep := range js.Endpoints {
				endpoint := SAMLEndpoint{
					SSOURL: ep,
				}
				webAuth.SAML = append(webAuth.SAML, endpoint)
			}
		case "webauthn", "fido2":
			if js.WebAuthn != nil {
				endpoint := WebAuthnEndpoint{
					RegisterURL:     js.Endpoints[0], // Assuming first endpoint is register
					AttestationType: js.WebAuthn.Attestation,
				}
				if len(js.Endpoints) > 1 {
					endpoint.LoginURL = js.Endpoints[1]
				}
				webAuth.WebAuthn = append(webAuth.WebAuthn, endpoint)
			}
		case "jwt":
			for _, ep := range js.Endpoints {
				endpoint := JWTEndpoint{
					URL: ep,
				}
				webAuth.JWT = append(webAuth.JWT, endpoint)
			}
		}
	}
}

func (c *ComprehensiveAuthDiscovery) checkAuthHeaders(ctx context.Context, target *TargetInfo, webAuth *WebAuthMethods) {
	// Stub implementation
}

func (c *ComprehensiveAuthDiscovery) parseWWWAuthenticate(authHeader, pageURL string) []AuthMethod {
	return []AuthMethod{}
}

func (c *ComprehensiveAuthDiscovery) analyzeLoginForm(s interface{}, pageURL string) AuthMethod {
	return nil
}

func (c *ComprehensiveAuthDiscovery) detectOAuthButton(s interface{}, pageURL string) AuthMethod {
	return nil
}

func (c *ComprehensiveAuthDiscovery) detectWebAuthn(doc interface{}) bool {
	return false
}

func (c *ComprehensiveAuthDiscovery) detectSAML(doc interface{}, resp *http.Response) AuthMethod {
	return nil
}

func (c *ComprehensiveAuthDiscovery) categorizeAuthMethod(method AuthMethod, webAuth *WebAuthMethods) {
	// Stub implementation
}

func (c *ComprehensiveAuthDiscovery) checkOIDCConfiguration(url string) AuthMethod {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != 200 {
		return nil
	}

	// Check if it's a valid OIDC configuration
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return nil
	}

	// For now, just return a basic OIDC endpoint
	// In a real implementation, you would parse the JSON response
	return &OIDCMethod{
		URL:  url,
		Type: "oidc",
	}
}

func (c *ComprehensiveAuthDiscovery) checkOAuth2Configuration(url string) AuthMethod {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != 200 {
		return nil
	}

	// Check if it's a valid OAuth2 configuration
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return nil
	}

	return &OAuth2Method{
		URL:  url,
		Type: "oauth2",
	}
}

func (c *ComprehensiveAuthDiscovery) checkOAuth2Endpoint(url string) AuthMethod {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	// OAuth2 endpoints often return specific responses
	if resp.StatusCode == 400 || resp.StatusCode == 401 {
		// Check for OAuth2-specific error messages in body
		body := make([]byte, 1024)
		n, _ := resp.Body.Read(body)
		if n > 0 {
			bodyStr := string(body[:n])
			if strings.Contains(bodyStr, "client_id") ||
				strings.Contains(bodyStr, "grant_type") ||
				strings.Contains(bodyStr, "redirect_uri") {
				return &OAuth2Method{
					URL:  url,
					Type: "oauth2",
				}
			}
		}
	}

	return nil
}

func (c *ComprehensiveAuthDiscovery) checkSAMLMetadata(url string) AuthMethod {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != 200 {
		return nil
	}

	// Check if it's XML (SAML metadata is XML)
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "xml") || strings.Contains(contentType, "saml") {
		// Read a bit of the body to check for SAML indicators
		body := make([]byte, 1024)
		n, _ := resp.Body.Read(body)
		if n > 0 {
			bodyStr := string(body[:n])
			if strings.Contains(bodyStr, "EntityDescriptor") ||
				strings.Contains(bodyStr, "urn:oasis:names:tc:SAML") {
				return &SAMLMethod{
					URL:  url,
					Type: "saml",
				}
			}
		}
	}

	return nil
}

func (c *ComprehensiveAuthDiscovery) checkSAMLEndpoint(url string) AuthMethod {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	// SAML SSO endpoints often redirect or return specific content
	if resp.StatusCode == 302 || resp.StatusCode == 200 {
		// Check headers for SAML indicators
		if resp.Header.Get("SAMLRequest") != "" ||
			resp.Header.Get("SAMLResponse") != "" {
			return &SAMLMethod{
				URL:  url,
				Type: "saml",
			}
		}

		// Check body for SAML forms
		body := make([]byte, 2048)
		n, _ := resp.Body.Read(body)
		if n > 0 {
			bodyStr := string(body[:n])
			if strings.Contains(bodyStr, "SAMLRequest") ||
				strings.Contains(bodyStr, "SAMLResponse") ||
				strings.Contains(bodyStr, "RelayState") {
				return &SAMLMethod{
					URL:  url,
					Type: "saml",
				}
			}
		}
	}

	return nil
}

func (c *ComprehensiveAuthDiscovery) checkShibboleth(url string) AuthMethod {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	// Shibboleth specific checks
	if resp.StatusCode == 200 {
		// Check for Shibboleth headers
		if resp.Header.Get("Shib-Session-ID") != "" ||
			resp.Header.Get("Shib-Identity-Provider") != "" {
			return &ShibbolethMethod{
				URL:  url,
				Type: "shibboleth",
			}
		}

		// Check content type for Shibboleth metadata
		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "xml") {
			body := make([]byte, 1024)
			n, _ := resp.Body.Read(body)
			if n > 0 && strings.Contains(string(body[:n]), "shibboleth") {
				return &ShibbolethMethod{
					URL:  url,
					Type: "shibboleth",
				}
			}
		}
	}

	return nil
}

func (c *ComprehensiveAuthDiscovery) checkCASEndpoint(url string) AuthMethod {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	// CAS login pages have specific characteristics
	if resp.StatusCode == 200 {
		body := make([]byte, 2048)
		n, _ := resp.Body.Read(body)
		if n > 0 {
			bodyStr := string(body[:n])
			// Look for CAS-specific elements
			if strings.Contains(bodyStr, "cas:serviceResponse") ||
				strings.Contains(bodyStr, "login-form") && strings.Contains(bodyStr, "lt") ||
				strings.Contains(bodyStr, "execution") && strings.Contains(bodyStr, "_eventId") {
				return &CASMethod{
					URL:  url,
					Type: "cas",
				}
			}
		}
	}

	return nil
}

func (c *ComprehensiveAuthDiscovery) checkGenericLogin(url string) AuthMethod {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != 200 {
		return nil
	}

	// Parse HTML to find login forms
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil
	}

	// Look for login forms
	hasLoginForm := false
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		// Check for password fields
		if s.Find("input[type='password']").Length() > 0 {
			hasLoginForm = true
		}
	})

	if hasLoginForm {
		return &GenericLoginMethod{
			URL:  url,
			Type: "form_login",
		}
	}

	return nil
}

func (c *ComprehensiveAuthDiscovery) checkWordPressLogin(url string) AuthMethod {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != 200 {
		return nil
	}

	// Check for WordPress-specific indicators
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	if n > 0 {
		bodyStr := string(body[:n])
		// WordPress login page indicators
		if strings.Contains(bodyStr, "wp-login.php") ||
			strings.Contains(bodyStr, "wordpress") ||
			strings.Contains(bodyStr, "wp-submit") ||
			strings.Contains(bodyStr, "user_login") && strings.Contains(bodyStr, "user_pass") {
			return &WordPressMethod{
				URL:  url,
				Type: "wordpress",
			}
		}
	}

	return nil
}

func (c *ComprehensiveAuthDiscovery) checkAPIAuth(url string) AuthMethod {
	// Try common API authentication patterns
	req, _ := http.NewRequest("GET", url, nil)

	// Test without auth first
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	// API endpoints often return 401/403 without auth
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		// Check WWW-Authenticate header
		authHeader := resp.Header.Get("WWW-Authenticate")
		if authHeader != "" {
			return &APIAuthMethod{
				URL:      url,
				Type:     "api_auth",
				AuthType: authHeader,
			}
		}

		// Check for API-specific error responses
		body := make([]byte, 1024)
		n, _ := resp.Body.Read(body)
		if n > 0 {
			bodyStr := string(body[:n])
			if strings.Contains(bodyStr, "api_key") ||
				strings.Contains(bodyStr, "access_token") ||
				strings.Contains(bodyStr, "authorization") {
				return &APIAuthMethod{
					URL:  url,
					Type: "api_auth",
				}
			}
		}
	}

	return nil
}

func (c *ComprehensiveAuthDiscovery) checkWebAuthnEndpoint(url string) AuthMethod {
	// WebAuthn endpoints typically accept POST requests
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	// WebAuthn endpoints often return JSON
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "json") {
		body := make([]byte, 1024)
		n, _ := resp.Body.Read(body)
		if n > 0 {
			bodyStr := string(body[:n])
			// Look for WebAuthn/FIDO2 specific fields
			if strings.Contains(bodyStr, "challenge") ||
				strings.Contains(bodyStr, "publicKey") ||
				strings.Contains(bodyStr, "credentialId") ||
				strings.Contains(bodyStr, "authenticator") {
				return &WebAuthnMethod{
					URL:  url,
					Type: "webauthn",
				}
			}
		}
	}

	return nil
}

func (c *ComprehensiveAuthDiscovery) calculateConfidenceScores(inventory *AuthInventory) {
	// Stub implementation
}

func (c *ComprehensiveAuthDiscovery) logDiscoverySummary(inventory *AuthInventory) {
	c.logger.Info("Auth discovery summary",
		"target", inventory.Target,
		"timestamp", inventory.Timestamp)
}

func (c *ComprehensiveAuthDiscovery) discoverAPIAuth(ctx context.Context, target *TargetInfo) (*APIAuthMethods, error) {
	return &APIAuthMethods{}, nil
}

func (c *ComprehensiveAuthDiscovery) probeKerberos(ctx context.Context, port PortScanResult) *KerberosEndpoint {
	// Kerberos typically runs on port 88
	endpoint := &KerberosEndpoint{
		Host: port.Host,
		Port: port.Port,
	}

	// Basic connectivity check
	// In a real implementation, you would send Kerberos protocol messages
	c.logger.Debugw("Probing Kerberos endpoint",
		"host", port.Host,
		"port", port.Port)

	// Extract realm from banner if available
	if port.Banner != "" {
		// Look for realm information in banner
		if strings.Contains(port.Banner, "REALM") {
			// Extract realm name
			endpoint.Realm = "DETECTED.REALM"
		}
	}

	return endpoint
}

func (c *ComprehensiveAuthDiscovery) probeRADIUS(ctx context.Context, port PortScanResult) *RADIUSEndpoint {
	// RADIUS typically runs on port 1812 (auth) and 1813 (accounting)
	endpoint := &RADIUSEndpoint{
		Host: port.Host,
		Port: port.Port,
	}

	c.logger.Debugw("Probing RADIUS endpoint",
		"host", port.Host,
		"port", port.Port)

	// In a real implementation, you would send RADIUS Access-Request packets
	// to test the server and potentially enumerate supported authentication methods

	return endpoint
}

func (c *ComprehensiveAuthDiscovery) probeSMB(ctx context.Context, port PortScanResult) *SMBEndpoint {
	// SMB/CIFS typically runs on port 445 (or 139 for NetBIOS)
	endpoint := &SMBEndpoint{
		Host: port.Host,
		Port: port.Port,
	}

	c.logger.Debugw("Probing SMB endpoint",
		"host", port.Host,
		"port", port.Port)

	// In a real implementation, you would:
	// 1. Attempt SMB negotiation
	// 2. Check for null session access
	// 3. Enumerate shares if possible
	// 4. Check authentication methods supported

	return endpoint
}

func (c *ComprehensiveAuthDiscovery) probeSMTPAuth(ctx context.Context, port PortScanResult) *SMTPAuthMethod {
	endpoint := &SMTPAuthMethod{
		Host:              port.Host,
		Port:              port.Port,
		TLS:               port.SSL,
		AuthMechanisms:    []string{},
		StartTLSAvailable: false,
	}

	// Simple SMTP AUTH detection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", port.Host, port.Port), 5*time.Second)
	if err != nil {
		return endpoint
	}
	defer conn.Close()

	// Read banner
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := conn.Read(buffer)

	if n > 0 && strings.Contains(string(buffer[:n]), "220") {
		// Send EHLO
		conn.Write([]byte("EHLO test\r\n"))
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ = conn.Read(buffer)

		if n > 0 {
			response := string(buffer[:n])
			// Parse AUTH mechanisms
			if strings.Contains(response, "AUTH") {
				lines := strings.Split(response, "\n")
				for _, line := range lines {
					if strings.Contains(line, "AUTH") {
						// Extract auth mechanisms
						parts := strings.Fields(line)
						if len(parts) > 1 {
							endpoint.AuthMechanisms = parts[1:]
						}
					}
					if strings.Contains(line, "STARTTLS") {
						endpoint.StartTLSAvailable = true
					}
				}
			}
		}
	}

	return endpoint
}

func (c *ComprehensiveAuthDiscovery) probeIMAPAuth(ctx context.Context, port PortScanResult) *IMAPAuthMethod {
	endpoint := &IMAPAuthMethod{
		Host:           port.Host,
		Port:           port.Port,
		TLS:            port.SSL,
		AuthMechanisms: []string{},
	}

	// Simple IMAP capability detection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", port.Host, port.Port), 5*time.Second)
	if err != nil {
		return endpoint
	}
	defer conn.Close()

	// Read banner
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := conn.Read(buffer)

	if n > 0 && strings.Contains(string(buffer[:n]), "OK") {
		// Send CAPABILITY command
		conn.Write([]byte("a001 CAPABILITY\r\n"))
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ = conn.Read(buffer)

		if n > 0 {
			response := string(buffer[:n])
			// Parse AUTH mechanisms
			if strings.Contains(response, "AUTH=") {
				// Extract auth mechanisms from CAPABILITY response
				parts := strings.Split(response, " ")
				for _, part := range parts {
					if strings.HasPrefix(part, "AUTH=") {
						mech := strings.TrimPrefix(part, "AUTH=")
						endpoint.AuthMechanisms = append(endpoint.AuthMechanisms, mech)
					}
				}
			}
		}
	}

	return endpoint
}

func (c *ComprehensiveAuthDiscovery) probeDatabaseAuth(ctx context.Context, port PortScanResult) *DatabaseAuth {
	endpoint := &DatabaseAuth{
		Host: port.Host,
		Port: port.Port,
	}

	// Identify database type based on port and banner
	switch port.Port {
	case 3306:
		endpoint.DatabaseType = "MySQL"
		endpoint.AuthMethod = "mysql_native_password"
	case 5432:
		endpoint.DatabaseType = "PostgreSQL"
		endpoint.AuthMethod = "md5/scram-sha-256"
	case 1433:
		endpoint.DatabaseType = "MSSQL"
		endpoint.AuthMethod = "sql_server_auth"
	case 27017:
		endpoint.DatabaseType = "MongoDB"
		endpoint.AuthMethod = "scram-sha"
	case 6379:
		endpoint.DatabaseType = "Redis"
		endpoint.AuthMethod = "password/acl"
	default:
		// Try to identify from banner
		if port.Banner != "" {
			bannerLower := strings.ToLower(port.Banner)
			if strings.Contains(bannerLower, "mysql") {
				endpoint.DatabaseType = "MySQL"
			} else if strings.Contains(bannerLower, "postgresql") {
				endpoint.DatabaseType = "PostgreSQL"
			} else if strings.Contains(bannerLower, "oracle") {
				endpoint.DatabaseType = "Oracle"
			}
		}
	}

	c.logger.Debugw("Identified database",
		"host", port.Host,
		"port", port.Port,
		"type", endpoint.DatabaseType)

	return endpoint
}

func (c *ComprehensiveAuthDiscovery) determineLDAPType(endpoint *LDAPEndpoint) string {
	// Determine LDAP server type based on various indicators

	// Check vendor name first
	if endpoint.VendorName != "" {
		vendorLower := strings.ToLower(endpoint.VendorName)
		if strings.Contains(vendorLower, "microsoft") {
			return "Active Directory"
		} else if strings.Contains(vendorLower, "openldap") {
			return "OpenLDAP"
		} else if strings.Contains(vendorLower, "389") {
			return "389 Directory Server"
		} else if strings.Contains(vendorLower, "oracle") {
			return "Oracle Directory Server"
		}
	}

	// Check naming contexts
	for _, nc := range endpoint.NamingContexts {
		ncLower := strings.ToLower(nc)
		if strings.Contains(ncLower, "dc=") && strings.Contains(ncLower, "domaincontroller") {
			return "Active Directory"
		}
	}

	// Check SASL mechanisms
	for _, mech := range endpoint.SupportedSASLMechanisms {
		if mech == "GSSAPI" || mech == "GSS-SPNEGO" {
			// These are strongly associated with AD
			return "Active Directory"
		}
	}

	return "Generic LDAP"
}

func (c *ComprehensiveAuthDiscovery) checkLDAPUserEnumeration(l interface{}, context string) bool {
	// Check if user enumeration is possible
	// In a real implementation, you would:
	// 1. Try to search for common user attributes
	// 2. Check if anonymous bind allows user searches
	// 3. Test for timing differences in user lookups

	// For now, return true if we have a valid context
	return context != ""
}

// Integration with existing discovery engine
type AuthDiscoveryModule struct {
	comprehensiveAuth *ComprehensiveAuthDiscovery
	logger            *logger.Logger
	httpClient        *http.Client
}

// Implement the DiscoveryModule interface
func (a *AuthDiscoveryModule) Name() string {
	return "comprehensive_auth_discovery"
}

func (a *AuthDiscoveryModule) Priority() int {
	return 95 // High priority
}

func (a *AuthDiscoveryModule) CanHandle(target *discovery.Target) bool {
	// Handle all target types
	return true
}

func (a *AuthDiscoveryModule) Discover(ctx context.Context, target *discovery.Target, session *discovery.DiscoverySession) (*discovery.DiscoveryResult, error) {
	// Run comprehensive auth discovery
	inventory, err := a.comprehensiveAuth.DiscoverAll(ctx, target.Value)
	if err != nil {
		return nil, err
	}

	// Convert to discovery assets
	result := &discovery.DiscoveryResult{
		Assets:        a.convertToAssets(inventory),
		Relationships: a.extractRelationships(inventory),
		Source:        a.Name(),
	}

	return result, nil
}

// convertToAssets converts auth inventory to discovery assets (dummy implementation)
func (a *AuthDiscoveryModule) convertToAssets(inventory *AuthInventory) []*discovery.Asset {
	return []*discovery.Asset{}
}

// extractRelationships extracts relationships from auth inventory (dummy implementation)
func (a *AuthDiscoveryModule) extractRelationships(inventory *AuthInventory) []*discovery.Relationship {
	return []*discovery.Relationship{}
}

// NewAuthDiscoveryModule creates a new auth discovery module
func NewAuthDiscoveryModule(logger *logger.Logger) *AuthDiscoveryModule {
	return &AuthDiscoveryModule{
		comprehensiveAuth: NewComprehensiveAuthDiscovery(logger),
		logger:            logger,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}
