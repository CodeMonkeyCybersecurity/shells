package smuggling

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/core"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
	"github.com/google/uuid"
)

// Scanner implements the HTTP Request Smuggling scanner
type Scanner struct {
	client    *http.Client
	config    *SmugglingConfig
	detector  *Detector
	exploiter *Exploiter
}

// NewScanner creates a new HTTP Request Smuggling scanner
func NewScanner() core.Scanner {
	config := &SmugglingConfig{
		Timeout:                    DefaultTimeout,
		MaxRetries:                 3,
		UserAgent:                  "shells-smuggling-scanner/1.0",
		FollowRedirects:            false, // Important for smuggling detection
		VerifySSL:                  true,
		DifferentialDelay:          DefaultDifferentialDelay,
		MaxPayloadSize:             MaxResponseSize,
		Techniques:                 []string{TechniqueCLTE, TechniqueTECL, TechniqueTETE, TechniqueHTTP2},
		EnableTimingAnalysis:       true,
		EnableDifferentialAnalysis: true,
		CustomHeaders:              make(map[string]string),
	}

	client := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !config.VerifySSL,
			},
			DisableKeepAlives: false, // Keep connections alive for smuggling
			MaxIdleConns:      100,
			IdleConnTimeout:   90 * time.Second,
		},
	}

	// Disable redirects for smuggling detection
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	scanner := &Scanner{
		client: client,
		config: config,
	}

	scanner.detector = NewDetector(client, config)
	scanner.exploiter = NewExploiter(client, config)

	return scanner
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return "smuggling"
}

// Type returns the scan type
func (s *Scanner) Type() types.ScanType {
	return types.ScanType("smuggling")
}

// Validate validates the target URL
func (s *Scanner) Validate(target string) error {
	if target == "" {
		return fmt.Errorf("target URL cannot be empty")
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("target URL must use HTTP or HTTPS scheme")
	}

	return nil
}

// Scan performs the HTTP Request Smuggling scan
func (s *Scanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	if err := s.Validate(target); err != nil {
		return nil, fmt.Errorf("target validation failed: %w", err)
	}

	// Update configuration from options
	s.updateConfigFromOptions(options)

	findings := []types.Finding{}

	// Test each smuggling technique
	for _, technique := range s.config.Techniques {
		techniqueFindings, err := s.testTechnique(ctx, target, technique)
		if err != nil {
			// Log error but continue with other techniques
			continue
		}
		findings = append(findings, techniqueFindings...)
	}

	return findings, nil
}

// updateConfigFromOptions updates scanner configuration from options
func (s *Scanner) updateConfigFromOptions(options map[string]string) {
	if timeout, exists := options["timeout"]; exists {
		if t, err := time.ParseDuration(timeout); err == nil {
			s.config.Timeout = t
			s.client.Timeout = t
		}
	}

	if userAgent, exists := options["user-agent"]; exists {
		s.config.UserAgent = userAgent
	}

	if verifySSL, exists := options["verify-ssl"]; exists {
		s.config.VerifySSL = strings.ToLower(verifySSL) == "true"
	}

	if technique, exists := options["technique"]; exists {
		if technique != "all" {
			s.config.Techniques = []string{technique}
		}
	}

	if differential, exists := options["differential"]; exists {
		s.config.EnableDifferentialAnalysis = strings.ToLower(differential) == "true"
	}

	if timing, exists := options["timing"]; exists {
		s.config.EnableTimingAnalysis = strings.ToLower(timing) == "true"
	}

	if delay, exists := options["differential-delay"]; exists {
		if d, err := time.ParseDuration(delay); err == nil {
			s.config.DifferentialDelay = d
		}
	}

	// Parse custom headers
	for key, value := range options {
		if strings.HasPrefix(key, "header-") {
			headerName := strings.TrimPrefix(key, "header-")
			s.config.CustomHeaders[headerName] = value
		}
	}
}

// testTechnique tests a specific smuggling technique
func (s *Scanner) testTechnique(ctx context.Context, target, technique string) ([]types.Finding, error) {
	findings := []types.Finding{}

	switch technique {
	case TechniqueCLTE:
		clteFindings := s.testCLTE(ctx, target)
		findings = append(findings, clteFindings...)

	case TechniqueTECL:
		teclFindings := s.testTECL(ctx, target)
		findings = append(findings, teclFindings...)

	case TechniqueTETE:
		teteFindings := s.testTETE(ctx, target)
		findings = append(findings, teteFindings...)

	case TechniqueHTTP2:
		http2Findings := s.testHTTP2(ctx, target)
		findings = append(findings, http2Findings...)

	default:
		return nil, fmt.Errorf("unsupported technique: %s", technique)
	}

	return findings, nil
}

// testCLTE tests for Content-Length Transfer-Encoding smuggling
func (s *Scanner) testCLTE(ctx context.Context, target string) []types.Finding {
	findings := []types.Finding{}

	for _, payload := range CLTEPayloads {
		result := s.detector.TestCLTE(ctx, target, payload)
		if result.Vulnerable {
			finding := s.createFinding(target, VulnSmugglingCLTE, payload, result)
			findings = append(findings, finding)
		}
	}

	return findings
}

// testTECL tests for Transfer-Encoding Content-Length smuggling
func (s *Scanner) testTECL(ctx context.Context, target string) []types.Finding {
	findings := []types.Finding{}

	for _, payload := range TECLPayloads {
		result := s.detector.TestTECL(ctx, target, payload)
		if result.Vulnerable {
			finding := s.createFinding(target, VulnSmugglingTECL, payload, result)
			findings = append(findings, finding)
		}
	}

	return findings
}

// testTETE tests for Transfer-Encoding Transfer-Encoding smuggling
func (s *Scanner) testTETE(ctx context.Context, target string) []types.Finding {
	findings := []types.Finding{}

	for _, payload := range TETEPayloads {
		result := s.detector.TestTETE(ctx, target, payload)
		if result.Vulnerable {
			finding := s.createFinding(target, VulnSmugglingTETE, payload, result)
			findings = append(findings, finding)
		}
	}

	return findings
}

// testHTTP2 tests for HTTP/2 smuggling
func (s *Scanner) testHTTP2(ctx context.Context, target string) []types.Finding {
	findings := []types.Finding{}

	for _, payload := range HTTP2Payloads {
		result := s.detector.TestHTTP2(ctx, target, payload)
		if result.Vulnerable {
			finding := s.createFinding(target, VulnSmugglingHTTP2, payload, result)
			findings = append(findings, finding)
		}
	}

	return findings
}

// createFinding creates a types.Finding from a smuggling result
func (s *Scanner) createFinding(target, vulnType string, payload SmugglingPayload, result SmugglingResult) types.Finding {
	// Build evidence string
	evidenceBuilder := strings.Builder{}
	evidenceBuilder.WriteString(fmt.Sprintf("Technique: %s\n", payload.Technique))
	evidenceBuilder.WriteString(fmt.Sprintf("Confidence: %.2f\n", result.Confidence))
	evidenceBuilder.WriteString(fmt.Sprintf("Duration: %v\n", result.Duration))

	if len(result.Evidence) > 0 {
		evidenceBuilder.WriteString("Evidence:\n")
		for _, evidence := range result.Evidence {
			evidenceBuilder.WriteString(fmt.Sprintf("- %s: %s\n", evidence.Type, evidence.Description))
		}
	}

	// Build solution
	solution := s.buildSolution(payload.Technique)

	// Build references
	references := s.buildReferences(payload.Technique)

	return types.Finding{
		ID:          uuid.New().String(),
		Tool:        "smuggling",
		Type:        vulnType,
		Severity:    s.getSeverityFromString(payload.Severity),
		Title:       fmt.Sprintf("HTTP Request Smuggling - %s", payload.Name),
		Description: payload.Description,
		Evidence:    evidenceBuilder.String(),
		Solution:    solution,
		References:  references,
		Metadata: map[string]interface{}{
			"target":     target,
			"technique":  payload.Technique,
			"confidence": result.Confidence,
			"duration":   result.Duration.String(),
			"payload":    payload.Name,
			"impact":     payload.Impact,
			"evidence":   result.Evidence,
		},
		CreatedAt: time.Now(),
	}
}

// buildSolution builds solution text for a technique
func (s *Scanner) buildSolution(technique string) string {
	solutions := map[string]string{
		TechniqueCLTE:  "Ensure frontend and backend handle Content-Length and Transfer-Encoding headers consistently. Disable Transfer-Encoding on frontend or reject requests with conflicting headers.",
		TechniqueTECL:  "Normalize Transfer-Encoding header processing between frontend and backend. Reject requests with both Content-Length and Transfer-Encoding headers.",
		TechniqueTETE:  "Implement strict Transfer-Encoding header validation. Reject requests with duplicate or obfuscated Transfer-Encoding headers.",
		TechniqueHTTP2: "Ensure proper HTTP/2 to HTTP/1.1 downgrade handling. Validate headers during protocol conversion and reject malformed requests.",
	}

	if solution, exists := solutions[technique]; exists {
		return solution
	}

	return "Implement proper HTTP request parsing and validation between frontend and backend systems"
}

// buildReferences builds reference URLs for a technique
func (s *Scanner) buildReferences(technique string) []string {
	baseReferences := []string{
		"https://portswigger.net/web-security/request-smuggling",
		"https://tools.ietf.org/html/rfc7230#section-3.3.3",
		"https://owasp.org/www-community/attacks/HTTP_Request_Smuggling",
	}

	techniqueReferences := map[string][]string{
		TechniqueCLTE: {
			"https://portswigger.net/web-security/request-smuggling/exploiting#cl-te-vulnerabilities",
		},
		TechniqueTECL: {
			"https://portswigger.net/web-security/request-smuggling/exploiting#te-cl-vulnerabilities",
		},
		TechniqueTETE: {
			"https://portswigger.net/web-security/request-smuggling/exploiting#te-te-vulnerabilities",
		},
		TechniqueHTTP2: {
			"https://portswigger.net/web-security/request-smuggling/advanced#http-2-request-smuggling",
		},
	}

	if refs, exists := techniqueReferences[technique]; exists {
		return append(baseReferences, refs...)
	}

	return baseReferences
}

// getSeverityFromString converts string severity to types.Severity
func (s *Scanner) getSeverityFromString(severity string) types.Severity {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return types.SeverityCritical
	case "HIGH":
		return types.SeverityHigh
	case "MEDIUM":
		return types.SeverityMedium
	case "LOW":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}
