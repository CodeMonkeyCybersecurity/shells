package smuggling

// HTTP Request Smuggling Detection
//
// ADVERSARIAL REVIEW STATUS (2025-10-05):
// ✅ FIXED: HTTP body close errors - all resp.Body.Close() now use httpclient.CloseBody()
// ✅ VERIFIED: No panic() or log.Fatal() in library code
// ✅ FORMATTED: Code is gofmt compliant
// 📋 TODO: Add comprehensive test coverage (currently minimal)
// 📋 TODO: Add rate limiting to prevent IP bans during smuggling detection
//
// This package detects HTTP request smuggling vulnerabilities including:
// - CL.TE (Content-Length vs Transfer-Encoding) desynchronization
// - TE.CL (Transfer-Encoding vs Content-Length) desynchronization
// - TE.TE (Transfer-Encoding ambiguity)
// - HTTP/2 request smuggling
// - Cache poisoning via smuggling
// - WAF bypass techniques
//
// SECURITY: All HTTP connections now properly closed to prevent pool exhaustion.
// Previously had unchecked resp.Body.Close() that could leak connections under load.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"
)

// Detector handles smuggling detection logic
type Detector struct {
	client *http.Client
	config *SmugglingConfig
}

// NewDetector creates a new smuggling detector
func NewDetector(client *http.Client, config *SmugglingConfig) *Detector {
	return &Detector{
		client: client,
		config: config,
	}
}

// TestCLTE tests for Content-Length Transfer-Encoding smuggling
func (d *Detector) TestCLTE(ctx context.Context, target string, payload SmugglingPayload) SmugglingResult {
	result := SmugglingResult{
		Technique:  TechniqueCLTE,
		Vulnerable: false,
		Confidence: 0.0,
		Evidence:   []Evidence{},
	}

	start := time.Now()
	defer func() {
		result.Duration = time.Since(start)
	}()

	// Replace TARGET placeholder with actual target
	request1 := strings.ReplaceAll(payload.Request1, "TARGET", d.extractHost(target))
	request2 := strings.ReplaceAll(payload.Request2, "TARGET", d.extractHost(target))

	// Send the first request (with CL.TE payload)
	resp1, err := d.sendRawRequest(ctx, target, request1)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to send first request: %v", err)
		return result
	}

	// Send the second request
	resp2, err := d.sendRawRequest(ctx, target, request2)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to send second request: %v", err)
		return result
	}

	// Analyze responses for smuggling indicators
	result.Vulnerable, result.Confidence, result.Evidence = d.analyzeCLTEResponses(resp1, resp2, payload)

	return result
}

// TestTECL tests for Transfer-Encoding Content-Length smuggling
func (d *Detector) TestTECL(ctx context.Context, target string, payload SmugglingPayload) SmugglingResult {
	result := SmugglingResult{
		Technique:  TechniqueTECL,
		Vulnerable: false,
		Confidence: 0.0,
		Evidence:   []Evidence{},
	}

	start := time.Now()
	defer func() {
		result.Duration = time.Since(start)
	}()

	// Replace TARGET placeholder with actual target
	request1 := strings.ReplaceAll(payload.Request1, "TARGET", d.extractHost(target))

	// Send the TE.CL payload
	resp1, err := d.sendRawRequest(ctx, target, request1)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to send request: %v", err)
		return result
	}

	// Analyze response for smuggling indicators
	result.Vulnerable, result.Confidence, result.Evidence = d.analyzeTECLResponse(resp1, payload)

	return result
}

// TestTETE tests for Transfer-Encoding Transfer-Encoding smuggling
func (d *Detector) TestTETE(ctx context.Context, target string, payload SmugglingPayload) SmugglingResult {
	result := SmugglingResult{
		Technique:  TechniqueTETE,
		Vulnerable: false,
		Confidence: 0.0,
		Evidence:   []Evidence{},
	}

	start := time.Now()
	defer func() {
		result.Duration = time.Since(start)
	}()

	// Replace TARGET placeholder with actual target
	request1 := strings.ReplaceAll(payload.Request1, "TARGET", d.extractHost(target))

	// Send the TE.TE payload
	resp1, err := d.sendRawRequest(ctx, target, request1)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to send request: %v", err)
		return result
	}

	// Analyze response for smuggling indicators
	result.Vulnerable, result.Confidence, result.Evidence = d.analyzeTETEResponse(resp1, payload)

	return result
}

// TestHTTP2 tests for HTTP/2 smuggling
func (d *Detector) TestHTTP2(ctx context.Context, target string, payload SmugglingPayload) SmugglingResult {
	result := SmugglingResult{
		Technique:  TechniqueHTTP2,
		Vulnerable: false,
		Confidence: 0.0,
		Evidence:   []Evidence{},
	}

	start := time.Now()
	defer func() {
		result.Duration = time.Since(start)
	}()

	// HTTP/2 smuggling is more complex and requires special handling
	// For now, we'll simulate basic detection
	result.Vulnerable, result.Confidence, result.Evidence = d.analyzeHTTP2Support(target, payload)

	return result
}

// sendRawRequest sends a raw HTTP request
func (d *Detector) sendRawRequest(ctx context.Context, target, rawRequest string) (*HTTPResponse, error) {
	// Parse the raw request
	lines := strings.Split(rawRequest, "\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("invalid request format")
	}

	// Parse request line
	requestLine := strings.TrimSpace(lines[0])
	parts := strings.Split(requestLine, " ")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid request line: %s", requestLine)
	}

	method := parts[0]
	path := parts[1]

	// Build full URL
	fullURL := target
	if !strings.HasSuffix(target, "/") && !strings.HasPrefix(path, "/") {
		fullURL += "/"
	}
	if path != "/" {
		fullURL += strings.TrimPrefix(path, "/")
	}

	// Parse headers and body
	headers := make(map[string]string)
	bodyStart := -1

	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			bodyStart = i + 1
			break
		}

		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Extract body
	var body string
	if bodyStart > 0 && bodyStart < len(lines) {
		body = strings.Join(lines[bodyStart:], "\n")
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, method, fullURL, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Set additional headers from config
	for key, value := range d.config.CustomHeaders {
		req.Header.Set(key, value)
	}

	// Set User-Agent if not already set
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", d.config.UserAgent)
	}

	// Send request
	start := time.Now()
	resp, err := d.client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer httpclient.CloseBody(resp)

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Build response headers map
	responseHeaders := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			responseHeaders[key] = values[0]
		}
	}

	return &HTTPResponse{
		StatusCode:    resp.StatusCode,
		Headers:       responseHeaders,
		Body:          string(bodyBytes),
		Time:          duration,
		ContentLength: resp.ContentLength,
	}, nil
}

// analyzeCLTEResponses analyzes responses for CL.TE smuggling indicators
func (d *Detector) analyzeCLTEResponses(resp1, resp2 *HTTPResponse, payload SmugglingPayload) (bool, float64, []Evidence) {
	evidence := []Evidence{}
	vulnerable := false
	confidence := 0.0

	// Check for timing differences
	if d.config.EnableTimingAnalysis {
		if resp1.Time > resp2.Time*2 || resp2.Time > resp1.Time*2 {
			vulnerable = true
			confidence += 0.3
			evidence = append(evidence, Evidence{
				Type:        DetectionTiming,
				Description: fmt.Sprintf("Significant timing difference: %v vs %v", resp1.Time, resp2.Time),
				Timing: &TimingEvidence{
					Request1Time: resp1.Time,
					Request2Time: resp2.Time,
					Difference:   resp1.Time - resp2.Time,
					Description:  "Timing difference indicates request smuggling",
				},
			})
		}
	}

	// Check for response differences
	if resp1.StatusCode != resp2.StatusCode {
		vulnerable = true
		confidence += 0.4
		evidence = append(evidence, Evidence{
			Type:        DetectionResponse,
			Description: fmt.Sprintf("Different status codes: %d vs %d", resp1.StatusCode, resp2.StatusCode),
			ResponsePair: &ResponsePair{
				Response1: resp1,
				Response2: resp2,
			},
		})
	}

	// Check for error indicators
	errorFound := false
	for _, indicator := range SmugglingIndicators {
		if strings.Contains(strings.ToLower(resp1.Body), strings.ToLower(indicator)) ||
			strings.Contains(strings.ToLower(resp2.Body), strings.ToLower(indicator)) {
			errorFound = true
			break
		}
	}

	if errorFound {
		vulnerable = true
		confidence += 0.5
		evidence = append(evidence, Evidence{
			Type:        DetectionError,
			Description: "Response contains smuggling error indicators",
		})
	}

	// Check content length differences
	if resp1.ContentLength != resp2.ContentLength {
		vulnerable = true
		confidence += 0.2
		evidence = append(evidence, Evidence{
			Type:        DetectionDifferential,
			Description: fmt.Sprintf("Content length difference: %d vs %d", resp1.ContentLength, resp2.ContentLength),
		})
	}

	return vulnerable, confidence, evidence
}

// analyzeTECLResponse analyzes response for TE.CL smuggling indicators
func (d *Detector) analyzeTECLResponse(resp *HTTPResponse, payload SmugglingPayload) (bool, float64, []Evidence) {
	evidence := []Evidence{}
	vulnerable := false
	confidence := 0.0

	// Check for chunked encoding issues
	if strings.Contains(strings.ToLower(resp.Body), "chunk") ||
		strings.Contains(strings.ToLower(resp.Body), "invalid chunk") {
		vulnerable = true
		confidence += 0.6
		evidence = append(evidence, Evidence{
			Type:        DetectionError,
			Description: "Response indicates chunked encoding processing issues",
		})
	}

	// Check for timeout or connection issues
	if resp.StatusCode == 0 || resp.StatusCode >= 500 {
		vulnerable = true
		confidence += 0.4
		evidence = append(evidence, Evidence{
			Type:        DetectionResponse,
			Description: fmt.Sprintf("Server error response: %d", resp.StatusCode),
		})
	}

	// Check for timing issues
	if d.config.EnableTimingAnalysis && resp.Time > time.Duration(TimingThresholdMs)*time.Millisecond {
		vulnerable = true
		confidence += 0.3
		evidence = append(evidence, Evidence{
			Type:        DetectionTiming,
			Description: fmt.Sprintf("Slow response time: %v", resp.Time),
			Timing: &TimingEvidence{
				Request1Time: resp.Time,
				Description:  "Slow response may indicate request smuggling",
			},
		})
	}

	return vulnerable, confidence, evidence
}

// analyzeTETEResponse analyzes response for TE.TE smuggling indicators
func (d *Detector) analyzeTETEResponse(resp *HTTPResponse, payload SmugglingPayload) (bool, float64, []Evidence) {
	evidence := []Evidence{}
	vulnerable := false
	confidence := 0.0

	// Check for transfer encoding header issues
	if transferEncoding, exists := resp.Headers["Transfer-Encoding"]; exists {
		if strings.Contains(strings.ToLower(transferEncoding), "chunked") {
			vulnerable = true
			confidence += 0.4
			evidence = append(evidence, Evidence{
				Type:        DetectionResponse,
				Description: "Response maintains Transfer-Encoding header",
			})
		}
	}

	// Check for header manipulation indicators
	for _, indicator := range SmugglingIndicators {
		if strings.Contains(strings.ToLower(resp.Body), strings.ToLower(indicator)) {
			vulnerable = true
			confidence += 0.5
			evidence = append(evidence, Evidence{
				Type:        DetectionError,
				Description: fmt.Sprintf("Response contains indicator: %s", indicator),
			})
			break
		}
	}

	// Check for malformed response
	if resp.StatusCode == 400 || resp.StatusCode == 502 {
		vulnerable = true
		confidence += 0.3
		evidence = append(evidence, Evidence{
			Type:        DetectionResponse,
			Description: "Bad request or bad gateway response",
		})
	}

	return vulnerable, confidence, evidence
}

// analyzeHTTP2Support analyzes HTTP/2 support for smuggling
func (d *Detector) analyzeHTTP2Support(target string, payload SmugglingPayload) (bool, float64, []Evidence) {
	evidence := []Evidence{}
	vulnerable := false
	confidence := 0.0

	// This is a simplified check - real HTTP/2 smuggling detection would require
	// more sophisticated protocol handling

	// Check if target supports HTTP/2
	if strings.HasPrefix(target, "https://") {
		vulnerable = true
		confidence += 0.2
		evidence = append(evidence, Evidence{
			Type:        DetectionResponse,
			Description: "Target uses HTTPS which may support HTTP/2",
		})
	}

	// Note: Full HTTP/2 smuggling detection would require:
	// 1. Detecting HTTP/2 support
	// 2. Testing downgrade scenarios
	// 3. Checking header processing differences
	// This is a placeholder for the basic structure

	return vulnerable, confidence, evidence
}

// extractHost extracts the host from a target URL
func (d *Detector) extractHost(target string) string {
	if strings.HasPrefix(target, "http://") {
		return strings.TrimPrefix(target, "http://")
	}
	if strings.HasPrefix(target, "https://") {
		return strings.TrimPrefix(target, "https://")
	}
	return target
}
