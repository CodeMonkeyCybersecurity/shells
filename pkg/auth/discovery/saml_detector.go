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

// SAMLDetector discovers SAML authentication implementations
type SAMLDetector struct {
	logger     *logger.Logger
	httpClient *http.Client
	patterns   map[string]*regexp.Regexp
}

// SAMLDiscovery represents discovered SAML configuration
type SAMLDiscovery struct {
	EntityID           string            `json:"entity_id"`
	MetadataURL        string            `json:"metadata_url"`
	SSOServiceURL      string            `json:"sso_service_url"`
	SLOServiceURL      string            `json:"slo_service_url"`
	Certificate        string            `json:"certificate,omitempty"`
	NameIDFormats      []string          `json:"name_id_formats"`
	SigningMethods     []string          `json:"signing_methods"`
	EncryptionMethods  []string          `json:"encryption_methods"`
	Bindings           []string          `json:"bindings"`
	Attributes         []SAMLAttribute   `json:"attributes"`
	IdentityProviders  []IdentityProvider `json:"identity_providers"`
	ServiceProviders   []ServiceProvider `json:"service_providers"`
	Confidence         float64           `json:"confidence"`
	SecurityFeatures   []string          `json:"security_features"`
	Vulnerabilities    []string          `json:"vulnerabilities"`
}

// SAMLAttribute represents a SAML attribute
type SAMLAttribute struct {
	Name         string `json:"name"`
	FriendlyName string `json:"friendly_name"`
	Required     bool   `json:"required"`
}

// IdentityProvider represents a SAML IdP
type IdentityProvider struct {
	EntityID     string `json:"entity_id"`
	Name         string `json:"name"`
	MetadataURL  string `json:"metadata_url"`
	SSOURL       string `json:"sso_url"`
	Certificate  string `json:"certificate,omitempty"`
}

// ServiceProvider represents a SAML SP
type ServiceProvider struct {
	EntityID    string `json:"entity_id"`
	Name        string `json:"name"`
	MetadataURL string `json:"metadata_url"`
	ACSURL      string `json:"acs_url"`
}

// NewSAMLDetector creates a new SAML detector
func NewSAMLDetector(logger *logger.Logger) *SAMLDetector {
	detector := &SAMLDetector{
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

func (s *SAMLDetector) initializePatterns() {
	// SAML endpoint patterns
	s.patterns["saml_paths"] = regexp.MustCompile(`(?i)/saml[2]?(/[^/\s"'<>]*)*`)
	s.patterns["sso_paths"] = regexp.MustCompile(`(?i)/sso[^/\s"'<>]*`)
	s.patterns["metadata_paths"] = regexp.MustCompile(`(?i)/(metadata|samlmetadata)[^/\s"'<>]*`)
	
	// SAML XML patterns
	s.patterns["saml_response"] = regexp.MustCompile(`(?i)<saml[p]?:Response[^>]*>`)
	s.patterns["saml_assertion"] = regexp.MustCompile(`(?i)<saml[p]?:Assertion[^>]*>`)
	s.patterns["entity_descriptor"] = regexp.MustCompile(`(?i)<md:EntityDescriptor[^>]*entityID=['"](.*?)['"]`)
	s.patterns["sso_service"] = regexp.MustCompile(`(?i)<md:SingleSignOnService[^>]*Location=['"](.*?)['"]`)
	s.patterns["slo_service"] = regexp.MustCompile(`(?i)<md:SingleLogoutService[^>]*Location=['"](.*?)['"]`)
	s.patterns["x509_cert"] = regexp.MustCompile(`<ds:X509Certificate>(.*?)</ds:X509Certificate>`)
	
	// SAML protocol indicators
	s.patterns["saml_request"] = regexp.MustCompile(`(?i)SAMLRequest=`)
	s.patterns["saml_response_param"] = regexp.MustCompile(`(?i)SAMLResponse=`)
	s.patterns["relay_state"] = regexp.MustCompile(`(?i)RelayState=`)
	
	// Name ID formats
	s.patterns["nameid_formats"] = regexp.MustCompile(`urn:oasis:names:tc:SAML:[0-9.]+:nameid-format:([^"'\s>]+)`)
	
	// Binding patterns
	s.patterns["http_post"] = regexp.MustCompile(`urn:oasis:names:tc:SAML:[0-9.]+:bindings:HTTP-POST`)
	s.patterns["http_redirect"] = regexp.MustCompile(`urn:oasis:names:tc:SAML:[0-9.]+:bindings:HTTP-Redirect`)
	s.patterns["http_artifact"] = regexp.MustCompile(`urn:oasis:names:tc:SAML:[0-9.]+:bindings:HTTP-Artifact`)
}

// DetectSAML discovers SAML implementations on a target
func (s *SAMLDetector) DetectSAML(ctx context.Context, target string) (*SAMLDiscovery, error) {
	s.logger.Info("Starting SAML detection", "target", target)
	
	discovery := &SAMLDiscovery{
		NameIDFormats:     []string{},
		SigningMethods:    []string{},
		EncryptionMethods: []string{},
		Bindings:          []string{},
		Attributes:        []SAMLAttribute{},
		IdentityProviders: []IdentityProvider{},
		ServiceProviders:  []ServiceProvider{},
		SecurityFeatures:  []string{},
		Vulnerabilities:   []string{},
	}

	baseURL := s.getBaseURL(target)
	
	// 1. Check for SAML metadata
	metadata := s.discoverMetadata(ctx, baseURL)
	if metadata != nil {
		s.parseMetadata(metadata, discovery)
		discovery.Confidence += 0.4
	}
	
	// 2. Check common SAML paths
	samlPaths := s.generateSAMLPaths(baseURL)
	for _, path := range samlPaths {
		if s.probeSAMLEndpoint(ctx, path, discovery) {
			discovery.Confidence += 0.2
		}
	}
	
	// 3. Analyze main page for SAML indicators
	if s.analyzePageForSAML(ctx, target, discovery) {
		discovery.Confidence += 0.2
	}
	
	// 4. Security analysis
	s.analyzeSAMLSecurity(discovery)
	
	s.logger.Info("SAML detection completed", 
		"target", target, 
		"confidence", discovery.Confidence)
	
	if discovery.Confidence < 0.3 {
		return nil, nil // Not enough evidence
	}
	
	return discovery, nil
}

// discoverMetadata attempts to discover SAML metadata
func (s *SAMLDetector) discoverMetadata(ctx context.Context, baseURL string) *MetadataDocument {
	metadataPaths := []string{
		"/metadata",
		"/saml/metadata",
		"/saml2/metadata",
		"/sso/metadata",
		"/auth/saml/metadata",
		"/samlmetadata",
		"/.well-known/saml-metadata",
		"/FederationMetadata/2007-06/FederationMetadata.xml", // ADFS
	}
	
	for _, path := range metadataPaths {
		metadataURL := baseURL + path
		
		if metadata := s.fetchMetadata(ctx, metadataURL); metadata != nil {
			s.logger.Debug("Found SAML metadata", "url", metadataURL)
			return metadata
		}
	}
	
	return nil
}

// MetadataDocument represents SAML metadata
type MetadataDocument struct {
	URL     string
	Content string
}

// fetchMetadata fetches SAML metadata from a URL
func (s *SAMLDetector) fetchMetadata(ctx context.Context, metadataURL string) *MetadataDocument {
	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		return nil
	}
	
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil
	}
	
	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "xml") && !strings.Contains(contentType, "application/samlmetadata") {
		return nil
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	
	content := string(body)
	
	// Verify this looks like SAML metadata
	if !s.patterns["entity_descriptor"].MatchString(content) {
		return nil
	}
	
	return &MetadataDocument{
		URL:     metadataURL,
		Content: content,
	}
}

// parseMetadata parses SAML metadata XML
func (s *SAMLDetector) parseMetadata(metadata *MetadataDocument, discovery *SAMLDiscovery) {
	content := metadata.Content
	discovery.MetadataURL = metadata.URL
	
	// Extract Entity ID
	if matches := s.patterns["entity_descriptor"].FindStringSubmatch(content); len(matches) > 1 {
		discovery.EntityID = matches[1]
	}
	
	// Extract SSO Service URL
	if matches := s.patterns["sso_service"].FindStringSubmatch(content); len(matches) > 1 {
		discovery.SSOServiceURL = matches[1]
	}
	
	// Extract SLO Service URL  
	if matches := s.patterns["slo_service"].FindStringSubmatch(content); len(matches) > 1 {
		discovery.SLOServiceURL = matches[1]
	}
	
	// Extract certificates
	certMatches := s.patterns["x509_cert"].FindAllStringSubmatch(content, -1)
	if len(certMatches) > 0 {
		discovery.Certificate = strings.TrimSpace(certMatches[0][1])
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "X.509 Certificate")
	}
	
	// Extract Name ID formats
	nameIDMatches := s.patterns["nameid_formats"].FindAllStringSubmatch(content, -1)
	for _, match := range nameIDMatches {
		if len(match) > 1 {
			discovery.NameIDFormats = append(discovery.NameIDFormats, match[1])
		}
	}
	
	// Extract bindings
	if s.patterns["http_post"].MatchString(content) {
		discovery.Bindings = append(discovery.Bindings, "HTTP-POST")
	}
	if s.patterns["http_redirect"].MatchString(content) {
		discovery.Bindings = append(discovery.Bindings, "HTTP-Redirect")
	}
	if s.patterns["http_artifact"].MatchString(content) {
		discovery.Bindings = append(discovery.Bindings, "HTTP-Artifact")
	}
}

// generateSAMLPaths generates common SAML paths to check
func (s *SAMLDetector) generateSAMLPaths(baseURL string) []string {
	return []string{
		baseURL + "/saml",
		baseURL + "/saml2",
		baseURL + "/sso",
		baseURL + "/auth/saml",
		baseURL + "/saml/login",
		baseURL + "/saml/sso",
		baseURL + "/saml2/sso",
		baseURL + "/adfs/ls", // ADFS
		baseURL + "/adfs/services/trust", // ADFS WS-Trust
	}
}

// probeSAMLEndpoint probes a SAML endpoint
func (s *SAMLDetector) probeSAMLEndpoint(ctx context.Context, endpoint string, discovery *SAMLDiscovery) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return false
	}
	
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	// Check for SAML-related headers
	for header, values := range resp.Header {
		headerLower := strings.ToLower(header)
		if strings.Contains(headerLower, "saml") {
			return true
		}
		for _, value := range values {
			if strings.Contains(strings.ToLower(value), "saml") {
				return true
			}
		}
	}
	
	// Check redirect location for SAML patterns
	if location := resp.Header.Get("Location"); location != "" {
		if s.patterns["saml_request"].MatchString(location) ||
		   s.patterns["saml_response_param"].MatchString(location) ||
		   s.patterns["relay_state"].MatchString(location) {
			return true
		}
	}
	
	return false
}

// analyzePageForSAML analyzes a page for SAML indicators
func (s *SAMLDetector) analyzePageForSAML(ctx context.Context, pageURL string, discovery *SAMLDiscovery) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return false
	}
	
	resp, err := s.httpClient.Do(req)
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
	
	// Look for SAML forms or redirects
	if s.patterns["saml_request"].MatchString(content) ||
	   s.patterns["saml_response_param"].MatchString(content) ||
	   s.patterns["relay_state"].MatchString(content) {
		found = true
	}
	
	// Look for SAML JavaScript references
	if strings.Contains(content, "SAMLRequest") ||
	   strings.Contains(content, "SAMLResponse") ||
	   strings.Contains(content, "RelayState") {
		found = true
	}
	
	return found
}

// analyzeSAMLSecurity analyzes SAML configuration for security issues
func (s *SAMLDetector) analyzeSAMLSecurity(discovery *SAMLDiscovery) {
	// Check for security features
	if discovery.Certificate != "" {
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "XML Signature Verification")
	}
	
	if len(discovery.NameIDFormats) > 0 {
		discovery.SecurityFeatures = append(discovery.SecurityFeatures, "Name ID Format Specification")
	}
	
	// Check for potential vulnerabilities
	if discovery.Certificate == "" {
		discovery.Vulnerabilities = append(discovery.Vulnerabilities, "Missing X.509 Certificate")
	}
	
	// Check for insecure bindings
	hasSecureBinding := false
	for _, binding := range discovery.Bindings {
		if binding == "HTTP-POST" {
			hasSecureBinding = true
			break
		}
	}
	
	if !hasSecureBinding && len(discovery.Bindings) > 0 {
		discovery.Vulnerabilities = append(discovery.Vulnerabilities, "Only HTTP-Redirect binding (potential CSRF)")
	}
	
	// Check for weak Name ID formats
	for _, format := range discovery.NameIDFormats {
		if strings.Contains(format, "unspecified") {
			discovery.Vulnerabilities = append(discovery.Vulnerabilities, "Unspecified Name ID Format")
		}
	}
}

// Helper methods
func (s *SAMLDetector) getBaseURL(fullURL string) string {
	if parsed, err := url.Parse(fullURL); err == nil {
		return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	}
	return fullURL
}