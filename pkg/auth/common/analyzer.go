package common

import (
	"fmt"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CrossProtocolAnalyzer analyzes vulnerabilities across authentication protocols
type CrossProtocolAnalyzer struct {
	httpClient *http.Client
	logger     Logger
}

// Logger interface for logging
type Logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}

// NewCrossProtocolAnalyzer creates a new cross-protocol analyzer
func NewCrossProtocolAnalyzer(logger Logger) *CrossProtocolAnalyzer {
	return &CrossProtocolAnalyzer{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// AnalyzeTarget performs comprehensive authentication analysis
func (c *CrossProtocolAnalyzer) AnalyzeTarget(target string) (*AuthReport, error) {
	c.logger.Info("Starting cross-protocol authentication analysis", "target", target)

	report := &AuthReport{
		Target:          target,
		StartTime:       time.Now(),
		Vulnerabilities: []Vulnerability{},
		AttackChains:    []AttackChain{},
		Protocols:       make(map[string]interface{}),
	}

	// Discover authentication endpoints
	config, err := c.discoverAuthEndpoints(target)
	if err != nil {
		return nil, fmt.Errorf("failed to discover endpoints: %w", err)
	}
	report.Configuration = *config

	// Analyze each protocol
	for _, endpoint := range config.Endpoints {
		vulns := c.analyzeEndpoint(endpoint)
		report.Vulnerabilities = append(report.Vulnerabilities, vulns...)
	}

	// Find attack chains
	chains := c.findAttackChains(report.Vulnerabilities)
	report.AttackChains = chains

	report.EndTime = time.Now()
	report.Summary = c.generateSummary(report)

	return report, nil
}

// discoverAuthEndpoints discovers authentication endpoints
func (c *CrossProtocolAnalyzer) discoverAuthEndpoints(target string) (*AuthConfiguration, error) {
	config := &AuthConfiguration{
		Endpoints: []AuthEndpoint{},
		Protocols: []AuthProtocol{},
		Metadata:  make(map[string]string),
	}

	// Common authentication paths
	authPaths := []string{
		"/.well-known/openid_configuration",
		"/.well-known/saml/metadata",
		"/.well-known/webauthn",
		"/auth/saml/metadata",
		"/auth/oauth2/authorize",
		"/auth/oidc/authorize",
		"/sso/saml2/metadata",
		"/oauth2/authorize",
		"/oidc/authorize",
		"/webauthn/register",
		"/webauthn/authenticate",
		"/auth/login",
		"/login",
		"/sso",
	}

	baseURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	for _, path := range authPaths {
		endpointURL := baseURL.ResolveReference(&url.URL{Path: path})

		resp, err := c.httpClient.Get(endpointURL.String())
		if err != nil {
			continue
		}
		httpclient.CloseBody(resp)

		if resp.StatusCode == 200 {
			endpoint := c.classifyEndpoint(endpointURL.String(), resp)
			if endpoint != nil {
				config.Endpoints = append(config.Endpoints, *endpoint)
			}
		}
	}

	// Deduplicate protocols
	protocolMap := make(map[AuthProtocol]bool)
	for _, endpoint := range config.Endpoints {
		protocolMap[endpoint.Protocol] = true
	}

	for protocol := range protocolMap {
		config.Protocols = append(config.Protocols, protocol)
	}

	return config, nil
}

// classifyEndpoint classifies an endpoint by protocol
func (c *CrossProtocolAnalyzer) classifyEndpoint(url string, resp *http.Response) *AuthEndpoint {
	endpoint := &AuthEndpoint{
		URL:      url,
		Method:   "GET",
		Headers:  make(map[string]string),
		Metadata: make(map[string]string),
		Verified: true,
	}

	// Copy response headers
	for key, values := range resp.Header {
		if len(values) > 0 {
			endpoint.Headers[key] = values[0]
		}
	}

	// Classify by URL patterns and headers
	urlLower := strings.ToLower(url)
	contentType := resp.Header.Get("Content-Type")

	switch {
	case strings.Contains(urlLower, "saml") || strings.Contains(contentType, "saml"):
		endpoint.Protocol = ProtocolSAML
	case strings.Contains(urlLower, "oauth2") || strings.Contains(urlLower, "oauth"):
		endpoint.Protocol = ProtocolOAuth2
	case strings.Contains(urlLower, "oidc") || strings.Contains(urlLower, "openid"):
		endpoint.Protocol = ProtocolOIDC
	case strings.Contains(urlLower, "webauthn") || strings.Contains(urlLower, "fido"):
		endpoint.Protocol = ProtocolWebAuthn
	default:
		// Try to determine from response content
		if strings.Contains(contentType, "json") {
			endpoint.Protocol = ProtocolOAuth2 // Likely OAuth2/OIDC
		} else {
			return nil // Unknown protocol
		}
	}

	return endpoint
}

// analyzeEndpoint analyzes a single endpoint for vulnerabilities
func (c *CrossProtocolAnalyzer) analyzeEndpoint(endpoint AuthEndpoint) []Vulnerability {
	vulnerabilities := []Vulnerability{}

	// Common authentication vulnerabilities
	commonVulns := []func(AuthEndpoint) *Vulnerability{
		c.checkInsecureTransport,
		c.checkWeakHeaders,
		c.checkInformationDisclosure,
		c.checkCSRFProtection,
	}

	for _, check := range commonVulns {
		if vuln := check(endpoint); vuln != nil {
			vulnerabilities = append(vulnerabilities, *vuln)
		}
	}

	return vulnerabilities
}

// checkInsecureTransport checks for insecure transport
func (c *CrossProtocolAnalyzer) checkInsecureTransport(endpoint AuthEndpoint) *Vulnerability {
	if strings.HasPrefix(endpoint.URL, "http://") {
		return &Vulnerability{
			ID:          "AUTH_INSECURE_TRANSPORT",
			Type:        "Transport Security",
			Protocol:    endpoint.Protocol,
			Severity:    "HIGH",
			Title:       "Authentication over insecure transport",
			Description: "Authentication endpoint is accessible over HTTP instead of HTTPS",
			Impact:      "Credentials and tokens can be intercepted",
			Evidence: []Evidence{
				{
					Type:        "URL",
					Description: "Insecure authentication endpoint",
					Data:        endpoint.URL,
				},
			},
			Remediation: Remediation{
				Description: "Force HTTPS for all authentication endpoints",
				Steps: []string{
					"Configure web server to redirect HTTP to HTTPS",
					"Implement HSTS headers",
					"Use secure cookies",
				},
				Priority: "HIGH",
			},
			CVSS:      7.5,
			CWE:       "CWE-319",
			CreatedAt: time.Now(),
		}
	}
	return nil
}

// checkWeakHeaders checks for weak security headers
func (c *CrossProtocolAnalyzer) checkWeakHeaders(endpoint AuthEndpoint) *Vulnerability {
	requiredHeaders := []string{
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Content-Security-Policy",
	}

	missing := []string{}
	for _, header := range requiredHeaders {
		if _, exists := endpoint.Headers[header]; !exists {
			missing = append(missing, header)
		}
	}

	if len(missing) > 0 {
		return &Vulnerability{
			ID:          "AUTH_WEAK_HEADERS",
			Type:        "Security Headers",
			Protocol:    endpoint.Protocol,
			Severity:    "MEDIUM",
			Title:       "Missing security headers",
			Description: fmt.Sprintf("Authentication endpoint missing security headers: %s", strings.Join(missing, ", ")),
			Impact:      "Increased attack surface for XSS, clickjacking, and other attacks",
			Evidence: []Evidence{
				{
					Type:        "Headers",
					Description: "Missing security headers",
					Data:        strings.Join(missing, ", "),
				},
			},
			Remediation: Remediation{
				Description: "Implement missing security headers",
				Steps: []string{
					"Add Strict-Transport-Security header",
					"Add X-Content-Type-Options: nosniff",
					"Add X-Frame-Options: DENY",
					"Add Content-Security-Policy header",
				},
				Priority: "MEDIUM",
			},
			CVSS:      5.3,
			CWE:       "CWE-693",
			CreatedAt: time.Now(),
		}
	}
	return nil
}

// checkInformationDisclosure checks for information disclosure
func (c *CrossProtocolAnalyzer) checkInformationDisclosure(endpoint AuthEndpoint) *Vulnerability {
	disclosureHeaders := []string{
		"Server",
		"X-Powered-By",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
	}

	disclosed := []string{}
	for _, header := range disclosureHeaders {
		if value, exists := endpoint.Headers[header]; exists {
			disclosed = append(disclosed, fmt.Sprintf("%s: %s", header, value))
		}
	}

	if len(disclosed) > 0 {
		return &Vulnerability{
			ID:          "AUTH_INFO_DISCLOSURE",
			Type:        "Information Disclosure",
			Protocol:    endpoint.Protocol,
			Severity:    "LOW",
			Title:       "Server information disclosure",
			Description: "Authentication endpoint discloses server information",
			Impact:      "Helps attackers identify software versions and potential vulnerabilities",
			Evidence: []Evidence{
				{
					Type:        "Headers",
					Description: "Disclosed server information",
					Data:        strings.Join(disclosed, ", "),
				},
			},
			Remediation: Remediation{
				Description: "Remove or obfuscate server information headers",
				Steps: []string{
					"Remove Server header",
					"Remove X-Powered-By header",
					"Remove version-specific headers",
				},
				Priority: "LOW",
			},
			CVSS:      3.1,
			CWE:       "CWE-200",
			CreatedAt: time.Now(),
		}
	}
	return nil
}

// checkCSRFProtection checks for CSRF protection
func (c *CrossProtocolAnalyzer) checkCSRFProtection(endpoint AuthEndpoint) *Vulnerability {
	// This is a simplified check - real implementation would need to test actual CSRF protection
	if endpoint.Method == "POST" {
		return &Vulnerability{
			ID:          "AUTH_CSRF_POTENTIAL",
			Type:        "CSRF Protection",
			Protocol:    endpoint.Protocol,
			Severity:    "MEDIUM",
			Title:       "Potential CSRF vulnerability",
			Description: "Authentication endpoint may be vulnerable to CSRF attacks",
			Impact:      "Attackers could perform unauthorized actions on behalf of users",
			Evidence: []Evidence{
				{
					Type:        "Method",
					Description: "POST endpoint without CSRF protection verification",
					Data:        endpoint.URL,
				},
			},
			Remediation: Remediation{
				Description: "Implement CSRF protection mechanisms",
				Steps: []string{
					"Implement CSRF tokens",
					"Validate Origin/Referer headers",
					"Use SameSite cookies",
				},
				Priority: "MEDIUM",
			},
			CVSS:      6.5,
			CWE:       "CWE-352",
			CreatedAt: time.Now(),
		}
	}
	return nil
}

// findAttackChains finds potential attack chains
func (c *CrossProtocolAnalyzer) findAttackChains(vulnerabilities []Vulnerability) []AttackChain {
	chains := []AttackChain{}

	// Group vulnerabilities by protocol
	protocolVulns := make(map[AuthProtocol][]Vulnerability)
	for _, vuln := range vulnerabilities {
		protocolVulns[vuln.Protocol] = append(protocolVulns[vuln.Protocol], vuln)
	}

	// Look for cross-protocol attack opportunities
	if len(protocolVulns) > 1 {
		chain := AttackChain{
			ID:          "CROSS_PROTOCOL_CHAIN",
			Name:        "Cross-Protocol Authentication Bypass",
			Description: "Multiple authentication protocols with vulnerabilities enable bypass chains",
			Impact:      "Complete authentication bypass through protocol confusion",
			Severity:    "CRITICAL",
			Steps:       []AttackStep{},
		}

		// Add steps for each vulnerable protocol
		order := 1
		for protocol, vulns := range protocolVulns {
			for _, vuln := range vulns {
				if vuln.Severity == "CRITICAL" || vuln.Severity == "HIGH" {
					step := AttackStep{
						Order:       order,
						Protocol:    protocol,
						Technique:   vuln.Type,
						Description: vuln.Description,
						Success:     true,
					}
					chain.Steps = append(chain.Steps, step)
					order++
				}
			}
		}

		if len(chain.Steps) > 1 {
			chains = append(chains, chain)
		}
	}

	return chains
}

// generateSummary generates a report summary
func (c *CrossProtocolAnalyzer) generateSummary(report *AuthReport) ReportSummary {
	summary := ReportSummary{
		BySeverity: make(map[string]int),
		ByProtocol: make(map[string]int),
	}

	summary.TotalVulnerabilities = len(report.Vulnerabilities)
	summary.AttackChains = len(report.AttackChains)

	for _, vuln := range report.Vulnerabilities {
		summary.BySeverity[vuln.Severity]++
		summary.ByProtocol[string(vuln.Protocol)]++

		if vuln.Severity == "CRITICAL" {
			summary.Exploitable++
		}
	}

	// Determine highest severity
	if summary.BySeverity["CRITICAL"] > 0 {
		summary.HighestSeverity = "CRITICAL"
	} else if summary.BySeverity["HIGH"] > 0 {
		summary.HighestSeverity = "HIGH"
	} else if summary.BySeverity["MEDIUM"] > 0 {
		summary.HighestSeverity = "MEDIUM"
	} else {
		summary.HighestSeverity = "LOW"
	}

	return summary
}
