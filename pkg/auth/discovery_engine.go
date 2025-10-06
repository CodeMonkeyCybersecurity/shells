// pkg/auth/discovery_engine.go
package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// AuthDiscoveryEngine discovers all authentication mechanisms for a target
type AuthDiscoveryEngine struct {
	crawlers    map[string]AuthCrawler
	portScanner *PortScanner
	httpClient  *http.Client
	logger      *logger.Logger
	config      DiscoveryConfig
}

// DiscoveryConfig contains configuration for auth discovery
type DiscoveryConfig struct {
	EnablePortScan    bool
	EnableWebCrawl    bool
	EnableMLDetection bool
	MaxDepth          int
	Timeout           time.Duration
	UserAgent         string
}

// AuthCrawler interface for protocol-specific crawlers
type AuthCrawler interface {
	Crawl(ctx context.Context, target string) (*AuthEndpoints, error)
	Name() string
}

// AuthInventory contains all discovered authentication mechanisms
type AuthInventory struct {
	Target       string                 `json:"target"`
	SAML         *SAMLEndpoints         `json:"saml,omitempty"`
	OAuth2       *OAuth2Endpoints       `json:"oauth2,omitempty"`
	OIDC         *OIDCEndpoints         `json:"oidc,omitempty"`
	WebAuthn     *WebAuthnEndpoints     `json:"webauthn,omitempty"`
	LDAP         *LDAPEndpoints         `json:"ldap,omitempty"`
	Kerberos     *KerberosEndpoints     `json:"kerberos,omitempty"`
	RADIUS       *RADIUSEndpoints       `json:"radius,omitempty"`
	APIKeys      *APIKeyEndpoints       `json:"api_keys,omitempty"`
	JWT          *JWTEndpoints          `json:"jwt,omitempty"`
	Basic        *BasicAuthEndpoints    `json:"basic,omitempty"`
	Digest       *DigestAuthEndpoints   `json:"digest,omitempty"`
	Certificate  *CertAuthEndpoints     `json:"certificate,omitempty"`
	Custom       *CustomAuthEndpoints   `json:"custom,omitempty"`
	Forms        []FormEndpoint         `json:"forms,omitempty"`
	Headers      map[string]string      `json:"auth_headers,omitempty"`
	Cookies      map[string]string      `json:"auth_cookies,omitempty"`
	DiscoveredAt time.Time              `json:"discovered_at"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// Individual endpoint structures
type SAMLEndpoints struct {
	MetadataURL  string   `json:"metadata_url,omitempty"`
	SSOUrl       string   `json:"sso_url,omitempty"`
	SLOUrl       string   `json:"slo_url,omitempty"`
	EntityID     string   `json:"entity_id,omitempty"`
	IdPUrls      []string `json:"idp_urls,omitempty"`
	SPUrls       []string `json:"sp_urls,omitempty"`
	AssertionURL string   `json:"assertion_url,omitempty"`
	X509Cert     string   `json:"x509_cert,omitempty"`
}

type OAuth2Endpoints struct {
	AuthorizationURL string   `json:"authorization_url,omitempty"`
	TokenURL         string   `json:"token_url,omitempty"`
	RevokeURL        string   `json:"revoke_url,omitempty"`
	IntrospectURL    string   `json:"introspect_url,omitempty"`
	UserInfoURL      string   `json:"userinfo_url,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	GrantTypes       []string `json:"grant_types,omitempty"`
	ResponseTypes    []string `json:"response_types,omitempty"`
}

type OIDCEndpoints struct {
	ConfigurationURL string           `json:"configuration_url,omitempty"`
	JWKSURL          string           `json:"jwks_url,omitempty"`
	Issuer           string           `json:"issuer,omitempty"`
	OAuth2           *OAuth2Endpoints `json:"oauth2,omitempty"`
}

type WebAuthnEndpoints struct {
	RegisterURL        string   `json:"register_url,omitempty"`
	LoginURL           string   `json:"login_url,omitempty"`
	ChallengeURL       string   `json:"challenge_url,omitempty"`
	AttestationOptions []string `json:"attestation_options,omitempty"`
	RPName             string   `json:"rp_name,omitempty"`
	RPID               string   `json:"rp_id,omitempty"`
}

type LDAPEndpoints struct {
	Host         string `json:"host,omitempty"`
	Port         int    `json:"port,omitempty"`
	TLS          bool   `json:"tls"`
	BaseDN       string `json:"base_dn,omitempty"`
	BindDN       string `json:"bind_dn,omitempty"`
	SearchFilter string `json:"search_filter,omitempty"`
}

type KerberosEndpoints struct {
	KDCHost   string `json:"kdc_host,omitempty"`
	KDCPort   int    `json:"kdc_port,omitempty"`
	Realm     string `json:"realm,omitempty"`
	AdminHost string `json:"admin_host,omitempty"`
	AdminPort int    `json:"admin_port,omitempty"`
}

type RADIUSEndpoints struct {
	Host   string `json:"host,omitempty"`
	Port   int    `json:"port,omitempty"`
	Secret string `json:"secret_hint,omitempty"`
}

type APIKeyEndpoints struct {
	HeaderName string   `json:"header_name,omitempty"`
	QueryParam string   `json:"query_param,omitempty"`
	CookieName string   `json:"cookie_name,omitempty"`
	Endpoints  []string `json:"endpoints,omitempty"`
	Format     string   `json:"format,omitempty"`
}

type JWTEndpoints struct {
	LoginURL      string   `json:"login_url,omitempty"`
	RefreshURL    string   `json:"refresh_url,omitempty"`
	ValidateURL   string   `json:"validate_url,omitempty"`
	Algorithm     string   `json:"algorithm,omitempty"`
	TokenLocation string   `json:"token_location,omitempty"`
	HeaderName    string   `json:"header_name,omitempty"`
	CookieName    string   `json:"cookie_name,omitempty"`
	Claims        []string `json:"claims,omitempty"`
}

type BasicAuthEndpoints struct {
	Endpoints []string `json:"endpoints,omitempty"`
	Realm     string   `json:"realm,omitempty"`
}

type DigestAuthEndpoints struct {
	Endpoints []string `json:"endpoints,omitempty"`
	Realm     string   `json:"realm,omitempty"`
	Qop       string   `json:"qop,omitempty"`
	Algorithm string   `json:"algorithm,omitempty"`
}

type CertAuthEndpoints struct {
	Endpoints        []string `json:"endpoints,omitempty"`
	ClientCertHeader string   `json:"client_cert_header,omitempty"`
	CAInfo           string   `json:"ca_info,omitempty"`
}

type CustomAuthEndpoints struct {
	Type        string   `json:"type,omitempty"`
	Endpoints   []string `json:"endpoints,omitempty"`
	Headers     []string `json:"headers,omitempty"`
	Description string   `json:"description,omitempty"`
}

type FormEndpoint struct {
	URL           string            `json:"url"`
	Method        string            `json:"method"`
	UsernameField string            `json:"username_field,omitempty"`
	PasswordField string            `json:"password_field,omitempty"`
	OtherFields   map[string]string `json:"other_fields,omitempty"`
	SubmitValue   string            `json:"submit_value,omitempty"`
	FormAction    string            `json:"form_action,omitempty"`
}

type AuthEndpoints struct {
	Type      string
	Endpoints map[string]interface{}
}

// PortScanner performs port scanning for auth services
type PortScanner struct {
	logger  *logger.Logger
	timeout time.Duration
}

// NewAuthDiscoveryEngine creates a new auth discovery engine
func NewAuthDiscoveryEngine(discoveryConfig DiscoveryConfig, log *logger.Logger) *AuthDiscoveryEngine {
	if log == nil {
		cfg := config.LoggerConfig{Level: "error", Format: "json"}
		log, _ = logger.New(cfg)
	}

	engine := &AuthDiscoveryEngine{
		crawlers:    make(map[string]AuthCrawler),
		portScanner: NewPortScanner(discoveryConfig.Timeout, log),
		httpClient: &http.Client{
			Timeout: discoveryConfig.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		logger: log.WithComponent("auth-discovery"),
		config: discoveryConfig,
	}

	// Register default crawlers
	engine.RegisterCrawler("saml", NewSAMLCrawler(log))
	engine.RegisterCrawler("oauth2", NewOAuth2Crawler(log))
	engine.RegisterCrawler("oidc", NewOIDCCrawler(log))
	engine.RegisterCrawler("webauthn", NewWebAuthnCrawler(log))
	engine.RegisterCrawler("forms", NewFormCrawler(log))

	return engine
}

// RegisterCrawler registers an auth crawler
func (e *AuthDiscoveryEngine) RegisterCrawler(name string, crawler AuthCrawler) {
	e.crawlers[name] = crawler
}

// DiscoverAllAuth discovers all authentication mechanisms for a target
func (e *AuthDiscoveryEngine) DiscoverAllAuth(ctx context.Context, target string) (*AuthInventory, error) {
	inventory := &AuthInventory{
		Target:       target,
		Headers:      make(map[string]string),
		Cookies:      make(map[string]string),
		Metadata:     make(map[string]interface{}),
		DiscoveredAt: time.Now(),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	errChan := make(chan error, 10)

	// Port-based discovery
	if e.config.EnablePortScan {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.logger.Infow("Starting port-based authentication discovery",
				"target", target,
				"checking_ports", "LDAP(389,636), Kerberos(88), RADIUS(1812,1813)",
			)
			e.discoverPortBasedAuth(ctx, target, inventory, &mu)
		}()
	}

	// Web-based discovery
	if e.config.EnableWebCrawl {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.logger.Infow("Starting web-based authentication discovery",
				"target", target,
				"methods", "SAML, OAuth2, OIDC, WebAuthn, Forms",
			)
			e.discoverWebBasedAuth(ctx, target, inventory, &mu)
		}()
	}

	// Wait for all discovery to complete
	wg.Wait()
	close(errChan)

	// Analyze discovered endpoints for patterns
	e.analyzeAuthPatterns(inventory)

	return inventory, nil
}

// discoverPortBasedAuth discovers auth services on non-standard ports
func (e *AuthDiscoveryEngine) discoverPortBasedAuth(ctx context.Context, target string, inventory *AuthInventory, mu *sync.Mutex) {
	// Extract hostname from target
	host := e.extractHostname(target)

	// LDAP ports
	if e.checkPort(host, 389) || e.checkPort(host, 636) {
		mu.Lock()
		inventory.LDAP = &LDAPEndpoints{
			Host: host,
			Port: 389,
			TLS:  e.checkPort(host, 636),
		}
		mu.Unlock()
		e.logger.Info("LDAP service discovered", "host", host)
	}

	// Kerberos ports
	if e.checkPort(host, 88) {
		mu.Lock()
		inventory.Kerberos = &KerberosEndpoints{
			KDCHost: host,
			KDCPort: 88,
		}
		mu.Unlock()
		e.logger.Info("Kerberos service discovered", "host", host)
	}

	// RADIUS ports
	if e.checkPort(host, 1812) || e.checkPort(host, 1813) {
		mu.Lock()
		inventory.RADIUS = &RADIUSEndpoints{
			Host: host,
			Port: 1812,
		}
		mu.Unlock()
		e.logger.Info("RADIUS service discovered", "host", host)
	}
}

// discoverWebBasedAuth discovers web-based auth mechanisms
func (e *AuthDiscoveryEngine) discoverWebBasedAuth(ctx context.Context, target string, inventory *AuthInventory, mu *sync.Mutex) {
	// Ensure target has protocol
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	var wg sync.WaitGroup

	// Run all web crawlers in parallel
	for name, crawler := range e.crawlers {
		wg.Add(1)
		go func(n string, c AuthCrawler) {
			defer wg.Done()

			e.logger.Infow("Discovering authentication endpoints",
				"target", target,
				"method", n,
			)

			endpoints, err := c.Crawl(ctx, target)
			if err != nil {
				e.logger.Debugw("Crawler failed", "crawler", n, "error", err)
				return
			}

			if endpoints != nil && len(endpoints.Endpoints) > 0 {
				e.logger.Infow("Found authentication endpoints",
					"target", target,
					"method", n,
					"count", len(endpoints.Endpoints),
				)
				e.processAuthEndpoints(n, endpoints, inventory, mu)
			}
		}(name, crawler)
	}

	// Check common auth endpoints
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.logger.Infow("Checking common authentication endpoints", "target", target)
		e.checkCommonEndpoints(ctx, target, inventory, mu)
	}()

	// Check for auth headers
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.logger.Infow("Analyzing authentication headers", "target", target)
		e.checkAuthHeaders(ctx, target, inventory, mu)
	}()

	wg.Wait()
}

// processAuthEndpoints processes discovered auth endpoints
func (e *AuthDiscoveryEngine) processAuthEndpoints(authType string, endpoints *AuthEndpoints, inventory *AuthInventory, mu *sync.Mutex) {
	mu.Lock()
	defer mu.Unlock()

	switch authType {
	case "saml":
		if saml, ok := endpoints.Endpoints["saml"].(*SAMLEndpoints); ok {
			inventory.SAML = saml
		}
	case "oauth2":
		if oauth2, ok := endpoints.Endpoints["oauth2"].(*OAuth2Endpoints); ok {
			inventory.OAuth2 = oauth2
		}
	case "oidc":
		if oidc, ok := endpoints.Endpoints["oidc"].(*OIDCEndpoints); ok {
			inventory.OIDC = oidc
		}
	case "webauthn":
		if webauthn, ok := endpoints.Endpoints["webauthn"].(*WebAuthnEndpoints); ok {
			inventory.WebAuthn = webauthn
		}
	case "forms":
		if forms, ok := endpoints.Endpoints["forms"].([]FormEndpoint); ok {
			inventory.Forms = append(inventory.Forms, forms...)
		}
	}
}

// checkCommonEndpoints checks common authentication endpoints
func (e *AuthDiscoveryEngine) checkCommonEndpoints(ctx context.Context, baseURL string, inventory *AuthInventory, mu *sync.Mutex) {
	commonEndpoints := []string{
		"/login", "/signin", "/auth", "/authenticate",
		"/api/login", "/api/auth", "/api/authenticate",
		"/user/login", "/account/login", "/accounts/login",
		"/wp-login.php", "/wp-admin", "/admin", "/administrator",
		"/jwt/login", "/jwt/auth", "/token",
		"/oauth/authorize", "/oauth/token",
		"/.well-known/openid-configuration",
		"/saml/metadata", "/saml/login",
		"/api/v1/auth", "/api/v2/auth",
		"/auth/realms/master", // Keycloak
		"/cas/login",          // CAS
	}

	e.logger.Infow("Checking common endpoints",
		"target", baseURL,
		"total_endpoints", len(commonEndpoints),
	)

	foundCount := 0
	for i, endpoint := range commonEndpoints {
		url := strings.TrimSuffix(baseURL, "/") + endpoint

		resp, err := e.httpClient.Get(url)
		if err != nil {
			continue
		}
		defer httpclient.CloseBody(resp)

		// Check if endpoint exists and analyze
		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 302 {
			foundCount++
			e.logger.Debugw("Found potential auth endpoint",
				"url", url,
				"status", resp.StatusCode,
				"progress", fmt.Sprintf("%d/%d", i+1, len(commonEndpoints)),
			)
			e.analyzeEndpoint(url, resp, inventory, mu)
		}
	}

	if foundCount > 0 {
		e.logger.Infow("Common endpoint check complete",
			"target", baseURL,
			"found", foundCount,
			"total_checked", len(commonEndpoints),
		)
	}
}

// checkAuthHeaders checks for authentication headers
func (e *AuthDiscoveryEngine) checkAuthHeaders(ctx context.Context, target string, inventory *AuthInventory, mu *sync.Mutex) {
	resp, err := e.httpClient.Get(target)
	if err != nil {
		return
	}
	defer httpclient.CloseBody(resp)

	mu.Lock()
	defer mu.Unlock()

	// Check WWW-Authenticate header
	if auth := resp.Header.Get("WWW-Authenticate"); auth != "" {
		inventory.Headers["WWW-Authenticate"] = auth

		// Parse auth type
		authLower := strings.ToLower(auth)
		if strings.Contains(authLower, "basic") {
			inventory.Basic = &BasicAuthEndpoints{
				Endpoints: []string{target},
				Realm:     extractRealm(auth),
			}
		} else if strings.Contains(authLower, "digest") {
			inventory.Digest = &DigestAuthEndpoints{
				Endpoints: []string{target},
				Realm:     extractRealm(auth),
			}
		} else if strings.Contains(authLower, "bearer") {
			if inventory.JWT == nil {
				inventory.JWT = &JWTEndpoints{}
			}
			inventory.JWT.HeaderName = "Authorization"
		}
	}

	// Check for API key headers
	apiKeyHeaders := []string{
		"X-API-Key", "X-Api-Key", "x-api-key",
		"API-Key", "Api-Key", "api-key",
		"X-Auth-Token", "X-Auth", "Authorization",
	}

	for _, header := range apiKeyHeaders {
		if resp.Header.Get(header) != "" || resp.Header.Get(strings.ToLower(header)) != "" {
			if inventory.APIKeys == nil {
				inventory.APIKeys = &APIKeyEndpoints{}
			}
			inventory.APIKeys.HeaderName = header
			break
		}
	}
}

// analyzeEndpoint analyzes a discovered endpoint
func (e *AuthDiscoveryEngine) analyzeEndpoint(url string, resp *http.Response, inventory *AuthInventory, mu *sync.Mutex) {
	// This is a simplified version - in reality would parse HTML and analyze
	e.logger.Debugw("Analyzing endpoint", "url", url, "status", resp.StatusCode)
}

// analyzeAuthPatterns analyzes patterns in discovered auth
func (e *AuthDiscoveryEngine) analyzeAuthPatterns(inventory *AuthInventory) {
	// Count auth methods
	authCount := 0
	if inventory.SAML != nil {
		authCount++
	}
	if inventory.OAuth2 != nil {
		authCount++
	}
	if inventory.OIDC != nil {
		authCount++
	}
	if inventory.WebAuthn != nil {
		authCount++
	}
	if inventory.LDAP != nil {
		authCount++
	}
	if len(inventory.Forms) > 0 {
		authCount++
	}

	inventory.Metadata["auth_method_count"] = authCount
	inventory.Metadata["has_mfa"] = inventory.WebAuthn != nil
	inventory.Metadata["has_sso"] = inventory.SAML != nil || inventory.OIDC != nil
}

// Helper methods

func (e *AuthDiscoveryEngine) checkPort(host string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), e.config.Timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (e *AuthDiscoveryEngine) extractHostname(target string) string {
	// Remove protocol
	host := strings.TrimPrefix(target, "https://")
	host = strings.TrimPrefix(host, "http://")

	// Remove path
	if idx := strings.Index(host, "/"); idx > 0 {
		host = host[:idx]
	}

	// Remove port
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}

	return host
}

func extractRealm(authHeader string) string {
	// Extract realm="..." from WWW-Authenticate header
	if idx := strings.Index(authHeader, `realm="`); idx >= 0 {
		start := idx + 7
		if end := strings.Index(authHeader[start:], `"`); end >= 0 {
			return authHeader[start : start+end]
		}
	}
	return ""
}

// NewPortScanner creates a new port scanner
func NewPortScanner(timeout time.Duration, logger *logger.Logger) *PortScanner {
	return &PortScanner{
		logger:  logger,
		timeout: timeout,
	}
}
