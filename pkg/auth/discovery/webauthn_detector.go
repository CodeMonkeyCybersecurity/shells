package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// WebAuthnDetector discovers WebAuthn/FIDO2 authentication implementations
type WebAuthnDetector struct {
	logger     *logger.Logger
	httpClient *http.Client
	patterns   map[string]*regexp.Regexp
}

// WebAuthn2Discovery represents discovered WebAuthn configuration
type WebAuthn2Discovery struct {
	RPID                   string               `json:"rp_id"`
	RPName                 string               `json:"rp_name"`
	Origins                []string             `json:"origins"`
	RegistrationEndpoint   string               `json:"registration_endpoint,omitempty"`
	AuthenticationEndpoint string               `json:"authentication_endpoint,omitempty"`
	AttestationFormats     []string             `json:"attestation_formats"`
	AuthenticatorSelection AttestationSelection `json:"authenticator_selection"`
	Extensions             []string             `json:"extensions"`
	UserVerification       string               `json:"user_verification"`
	ResidentKeys           string               `json:"resident_keys"`
	AttachmentModes        []string             `json:"attachment_modes"`
	TransportMethods       []string             `json:"transport_methods"`
	Algorithms             []Algorithm          `json:"algorithms"`
	SecurityFeatures       []string             `json:"security_features"`
	Vulnerabilities        []string             `json:"vulnerabilities"`
	Confidence             float64              `json:"confidence"`
	JSImplementation       *JSWebAuthnImpl      `json:"js_implementation,omitempty"`
}

// AttestationSelection represents authenticator selection criteria
type AttestationSelection struct {
	AuthenticatorAttachment string `json:"authenticator_attachment,omitempty"`
	ResidentKey             string `json:"resident_key,omitempty"`
	UserVerification        string `json:"user_verification,omitempty"`
}

// Algorithm represents a WebAuthn algorithm
type Algorithm struct {
	Name string `json:"name"`
	ID   int    `json:"id"`
}

// JSWebAuthnImpl represents JavaScript WebAuthn implementation details
type JSWebAuthnImpl struct {
	HasNavigatorCredentials bool     `json:"has_navigator_credentials"`
	HasPublicKeyCredential  bool     `json:"has_public_key_credential"`
	SupportedFeatures       []string `json:"supported_features"`
	RegistrationFlow        []string `json:"registration_flow"`
	AuthenticationFlow      []string `json:"authentication_flow"`
	ErrorHandling           []string `json:"error_handling"`
}

// NewWebAuthnDetector creates a new WebAuthn detector
func NewWebAuthnDetector(logger *logger.Logger) *WebAuthnDetector {
	detector := &WebAuthnDetector{
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

func (w *WebAuthnDetector) initializePatterns() {
	// WebAuthn API patterns
	w.patterns["navigator_credentials"] = regexp.MustCompile(`(?i)navigator\.credentials`)
	w.patterns["public_key_credential"] = regexp.MustCompile(`(?i)PublicKeyCredential`)
	w.patterns["webauthn_create"] = regexp.MustCompile(`(?i)navigator\.credentials\.create`)
	w.patterns["webauthn_get"] = regexp.MustCompile(`(?i)navigator\.credentials\.get`)

	// WebAuthn endpoint patterns
	w.patterns["webauthn_paths"] = regexp.MustCompile(`(?i)/webauthn|/fido2?|/u2f`)
	w.patterns["register_path"] = regexp.MustCompile(`(?i)/(register|attestation|create)`)
	w.patterns["authenticate_path"] = regexp.MustCompile(`(?i)/(authenticate|assertion|login)`)

	// WebAuthn configuration patterns
	w.patterns["rp_id"] = regexp.MustCompile(`(?i)rpId[\s]*[:=][\s]*['"](.*?)['"]`)
	w.patterns["rp_name"] = regexp.MustCompile(`(?i)rpName[\s]*[:=][\s]*['"](.*?)['"]`)
	w.patterns["user_id"] = regexp.MustCompile(`(?i)userId[\s]*[:=]`)
	w.patterns["challenge"] = regexp.MustCompile(`(?i)challenge[\s]*[:=]`)
	w.patterns["timeout"] = regexp.MustCompile(`(?i)timeout[\s]*[:=][\s]*(\d+)`)

	// Attestation patterns
	w.patterns["attestation_none"] = regexp.MustCompile(`(?i)attestation[\s]*[:=][\s]*['"](none)['"]`)
	w.patterns["attestation_indirect"] = regexp.MustCompile(`(?i)attestation[\s]*[:=][\s]*['"](indirect)['"]`)
	w.patterns["attestation_direct"] = regexp.MustCompile(`(?i)attestation[\s]*[:=][\s]*['"](direct)['"]`)

	// User verification patterns
	w.patterns["user_verification_required"] = regexp.MustCompile(`(?i)userVerification[\s]*[:=][\s]*['"](required)['"]`)
	w.patterns["user_verification_preferred"] = regexp.MustCompile(`(?i)userVerification[\s]*[:=][\s]*['"](preferred)['"]`)
	w.patterns["user_verification_discouraged"] = regexp.MustCompile(`(?i)userVerification[\s]*[:=][\s]*['"](discouraged)['"]`)

	// Authenticator attachment
	w.patterns["platform_auth"] = regexp.MustCompile(`(?i)authenticatorAttachment[\s]*[:=][\s]*['"](platform)['"]`)
	w.patterns["cross_platform_auth"] = regexp.MustCompile(`(?i)authenticatorAttachment[\s]*[:=][\s]*['"](cross-platform)['"]`)

	// Resident keys
	w.patterns["resident_key_required"] = regexp.MustCompile(`(?i)residentKey[\s]*[:=][\s]*['"](required)['"]`)
	w.patterns["resident_key_preferred"] = regexp.MustCompile(`(?i)residentKey[\s]*[:=][\s]*['"](preferred)['"]`)
	w.patterns["resident_key_discouraged"] = regexp.MustCompile(`(?i)residentKey[\s]*[:=][\s]*['"](discouraged)['"]`)

	// Transport methods
	w.patterns["transport_usb"] = regexp.MustCompile(`(?i)['"](usb)['"]`)
	w.patterns["transport_nfc"] = regexp.MustCompile(`(?i)['"](nfc)['"]`)
	w.patterns["transport_ble"] = regexp.MustCompile(`(?i)['"](ble)['"]`)
	w.patterns["transport_internal"] = regexp.MustCompile(`(?i)['"](internal)['"]`)

	// Algorithm patterns
	w.patterns["algorithm_es256"] = regexp.MustCompile(`(?i)(ES256|-7)`)
	w.patterns["algorithm_rs256"] = regexp.MustCompile(`(?i)(RS256|-257)`)
	w.patterns["algorithm_ps256"] = regexp.MustCompile(`(?i)(PS256|-37)`)

	// Error handling patterns
	w.patterns["webauthn_error"] = regexp.MustCompile(`(?i)(NotAllowedError|InvalidStateError|NotSupportedError|SecurityError|NetworkError)`)
}

// DetectWebAuthn discovers WebAuthn implementations on a target
func (w *WebAuthnDetector) DetectWebAuthn(ctx context.Context, target string) (*WebAuthn2Discovery, error) {
	w.logger.Info("Starting WebAuthn detection", "target", target)

	discovery := &WebAuthn2Discovery{
		Origins:            []string{},
		AttestationFormats: []string{},
		Extensions:         []string{},
		AttachmentModes:    []string{},
		TransportMethods:   []string{},
		Algorithms:         []Algorithm{},
		SecurityFeatures:   []string{},
		Vulnerabilities:    []string{},
	}

	baseURL := w.getBaseURL(target)
	discovery.Origins = append(discovery.Origins, baseURL)

	// 1. Analyze main page for WebAuthn indicators
	if w.analyzePageForWebAuthn(ctx, target, discovery) {
		discovery.Confidence += 0.3
	}

	// 2. Probe common WebAuthn endpoints
	webauthnPaths := w.generateWebAuthnPaths(baseURL)
	for _, path := range webauthnPaths {
		if w.probeWebAuthnEndpoint(ctx, path, discovery) {
			discovery.Confidence += 0.2
		}
	}

	// 3. Analyze JavaScript implementation
	if jsImpl := w.analyzeJavaScriptImplementation(ctx, target); jsImpl != nil {
		discovery.JSImplementation = jsImpl
		discovery.Confidence += 0.3
	}

	// 4. Security analysis
	w.analyzeWebAuthnSecurity(discovery)

	w.logger.Info("WebAuthn detection completed",
		"target", target,
		"confidence", discovery.Confidence)

	if discovery.Confidence < 0.3 {
		return nil, nil // Not enough evidence
	}

	return discovery, nil
}

// analyzePageForWebAuthn analyzes a page for WebAuthn indicators
func (w *WebAuthnDetector) analyzePageForWebAuthn(ctx context.Context, pageURL string, discovery *WebAuthn2Discovery) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return false
	}

	resp, err := w.httpClient.Do(req)
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

	// Check for WebAuthn API usage
	if w.patterns["navigator_credentials"].MatchString(content) {
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "Navigator Credentials API")
		found = true
	}

	if w.patterns["public_key_credential"].MatchString(content) {
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "Public Key Credential")
		found = true
	}

	if w.patterns["webauthn_create"].MatchString(content) {
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "Credential Registration")
		found = true
	}

	if w.patterns["webauthn_get"].MatchString(content) {
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "Credential Authentication")
		found = true
	}

	// Extract configuration
	if matches := w.patterns["rp_id"].FindStringSubmatch(content); len(matches) > 1 {
		discovery.RPID = matches[1]
		found = true
	}

	if matches := w.patterns["rp_name"].FindStringSubmatch(content); len(matches) > 1 {
		discovery.RPName = matches[1]
		found = true
	}

	// Extract user verification requirements
	if w.patterns["user_verification_required"].MatchString(content) {
		discovery.UserVerification = "required"
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "User Verification Required")
	} else if w.patterns["user_verification_preferred"].MatchString(content) {
		discovery.UserVerification = "preferred"
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "User Verification Preferred")
	} else if w.patterns["user_verification_discouraged"].MatchString(content) {
		discovery.UserVerification = "discouraged"
	}

	// Extract authenticator attachment preferences
	if w.patterns["platform_auth"].MatchString(content) {
		discovery.AttachmentModes = append(discovery.AttachmentModes, "platform")
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "Platform Authenticators")
	}

	if w.patterns["cross_platform_auth"].MatchString(content) {
		discovery.AttachmentModes = append(discovery.AttachmentModes, "cross-platform")
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "Cross-Platform Authenticators")
	}

	// Extract resident key preferences
	if w.patterns["resident_key_required"].MatchString(content) {
		discovery.ResidentKeys = "required"
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "Resident Keys Required")
	} else if w.patterns["resident_key_preferred"].MatchString(content) {
		discovery.ResidentKeys = "preferred"
	} else if w.patterns["resident_key_discouraged"].MatchString(content) {
		discovery.ResidentKeys = "discouraged"
	}

	// Extract transport methods
	if w.patterns["transport_usb"].MatchString(content) {
		discovery.TransportMethods = append(discovery.TransportMethods, "usb")
	}
	if w.patterns["transport_nfc"].MatchString(content) {
		discovery.TransportMethods = append(discovery.TransportMethods, "nfc")
	}
	if w.patterns["transport_ble"].MatchString(content) {
		discovery.TransportMethods = append(discovery.TransportMethods, "ble")
	}
	if w.patterns["transport_internal"].MatchString(content) {
		discovery.TransportMethods = append(discovery.TransportMethods, "internal")
	}

	// Extract supported algorithms
	if w.patterns["algorithm_es256"].MatchString(content) {
		discovery.Algorithms = append(discovery.Algorithms, Algorithm{Name: "ES256", ID: -7})
	}
	if w.patterns["algorithm_rs256"].MatchString(content) {
		discovery.Algorithms = append(discovery.Algorithms, Algorithm{Name: "RS256", ID: -257})
	}
	if w.patterns["algorithm_ps256"].MatchString(content) {
		discovery.Algorithms = append(discovery.Algorithms, Algorithm{Name: "PS256", ID: -37})
	}

	return found
}

// generateWebAuthnPaths generates common WebAuthn paths to check
func (w *WebAuthnDetector) generateWebAuthnPaths(baseURL string) []string {
	return []string{
		baseURL + "/webauthn",
		baseURL + "/webauthn/register",
		baseURL + "/webauthn/authenticate",
		baseURL + "/webauthn/attestation/options",
		baseURL + "/webauthn/attestation/result",
		baseURL + "/webauthn/assertion/options",
		baseURL + "/webauthn/assertion/result",
		baseURL + "/fido2",
		baseURL + "/fido2/register",
		baseURL + "/fido2/authenticate",
		baseURL + "/auth/webauthn",
		baseURL + "/api/webauthn",
		baseURL + "/api/fido2",
		baseURL + "/u2f",
		baseURL + "/u2f/register",
		baseURL + "/u2f/authenticate",
	}
}

// probeWebAuthnEndpoint probes a WebAuthn endpoint
func (w *WebAuthnDetector) probeWebAuthnEndpoint(ctx context.Context, endpoint string, discovery *WebAuthn2Discovery) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return false
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	content := string(body)

	// Look for WebAuthn/FIDO2 responses
	if strings.Contains(content, "challenge") ||
		strings.Contains(content, "publicKey") ||
		strings.Contains(content, "allowCredentials") ||
		strings.Contains(content, "excludeCredentials") {

		// Try to identify endpoint type
		if strings.Contains(endpoint, "register") || strings.Contains(endpoint, "attestation") {
			discovery.RegistrationEndpoint = endpoint
		} else if strings.Contains(endpoint, "authenticate") || strings.Contains(endpoint, "assertion") {
			discovery.AuthenticationEndpoint = endpoint
		}

		return true
	}

	return false
}

// analyzeJavaScriptImplementation analyzes JavaScript WebAuthn implementation
func (w *WebAuthnDetector) analyzeJavaScriptImplementation(ctx context.Context, target string) *JSWebAuthnImpl {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	content := string(body)

	impl := &JSWebAuthnImpl{
		SupportedFeatures:  []string{},
		RegistrationFlow:   []string{},
		AuthenticationFlow: []string{},
		ErrorHandling:      []string{},
	}

	// Check for basic WebAuthn support
	if w.patterns["navigator_credentials"].MatchString(content) {
		impl.HasNavigatorCredentials = true
		impl.SupportedFeatures = append(impl.SupportedFeatures, "Navigator Credentials")
	}

	if w.patterns["public_key_credential"].MatchString(content) {
		impl.HasPublicKeyCredential = true
		impl.SupportedFeatures = append(impl.SupportedFeatures, "Public Key Credential")
	}

	// Check for registration flow
	if w.patterns["webauthn_create"].MatchString(content) {
		impl.RegistrationFlow = append(impl.RegistrationFlow, "navigator.credentials.create()")
	}

	// Check for authentication flow
	if w.patterns["webauthn_get"].MatchString(content) {
		impl.AuthenticationFlow = append(impl.AuthenticationFlow, "navigator.credentials.get()")
	}

	// Check for error handling
	if w.patterns["webauthn_error"].MatchString(content) {
		impl.ErrorHandling = append(impl.ErrorHandling, "WebAuthn Error Handling")
	}

	if len(impl.SupportedFeatures) == 0 {
		return nil
	}

	return impl
}

// analyzeWebAuthnSecurity analyzes WebAuthn configuration for security issues
func (w *WebAuthnDetector) analyzeWebAuthnSecurity(discovery *WebAuthn2Discovery) {
	// Check for security features
	if discovery.UserVerification == "required" {
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "Strong User Verification")
	}

	if discovery.ResidentKeys == "required" {
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "Resident Keys (passwordless)")
	}

	if len(discovery.Algorithms) > 0 {
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "Cryptographic Algorithms")
	}

	// Check for potential vulnerabilities
	if discovery.UserVerification == "discouraged" {
		discovery.Vulnerabilities = append(discovery.Vulnerabilities, "User verification discouraged")
	}

	if discovery.RPID == "" {
		discovery.Vulnerabilities = append(discovery.Vulnerabilities, "Missing RP ID specification")
	}

	// Check for insecure attestation
	if len(discovery.AttestationFormats) == 0 {
		discovery.Vulnerabilities = append(discovery.Vulnerabilities, "No attestation format specified")
	}

	// Check for JavaScript implementation issues
	if discovery.JSImplementation != nil {
		if !discovery.JSImplementation.HasNavigatorCredentials {
			discovery.Vulnerabilities = append(discovery.Vulnerabilities, "Missing navigator.credentials support")
		}

		if len(discovery.JSImplementation.ErrorHandling) == 0 {
			discovery.Vulnerabilities = append(discovery.Vulnerabilities, "Insufficient error handling")
		}
	}

	// Check transport methods
	hasSecureTransport := false
	for _, transport := range discovery.TransportMethods {
		if transport == "internal" || transport == "usb" {
			hasSecureTransport = true
			break
		}
	}

	if !hasSecureTransport && len(discovery.TransportMethods) > 0 {
		discovery.Vulnerabilities = append(discovery.Vulnerabilities, "Only wireless transports available")
	}
}

// Helper methods
func (w *WebAuthnDetector) getBaseURL(fullURL string) string {
	if parsed, err := url.Parse(fullURL); err == nil {
		return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	}
	return fullURL
}
