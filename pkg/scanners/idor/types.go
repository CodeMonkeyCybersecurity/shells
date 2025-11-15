// pkg/scanners/idor/types.go
package idor

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"github.com/google/uuid"
)

// IDType represents the type of ID parameter detected
type IDType string

const (
	IDTypeSequential   IDType = "sequential"   // Numeric sequential IDs (1, 2, 3, 123, etc.)
	IDTypeUUID         IDType = "uuid"         // UUID format (v1, v4, etc.)
	IDTypeGUID         IDType = "guid"         // GUID format (Microsoft)
	IDTypeHashed       IDType = "hashed"       // Hashed IDs (MD5, SHA1, SHA256, etc.)
	IDTypeAlphanumeric IDType = "alphanumeric" // Mixed alphanumeric (abc123, user_456)
	IDTypeBase64       IDType = "base64"       // Base64 encoded
	IDTypeUnknown      IDType = "unknown"      // Unknown/custom format
)

// IDInfo contains extracted information about an ID parameter
type IDInfo struct {
	Value      string  // The actual ID value (e.g., "123", "abc-def-ghi")
	Type       IDType  // The detected ID type
	Location   string  // "path" or "query"
	ParamName  string  // Query parameter name (if location is "query")
	Pattern    string  // Regex pattern matched
	Confidence float64 // Confidence in type detection (0.0-1.0)
}

// BaselineResponse represents the baseline (expected) response for comparison
type BaselineResponse struct {
	StatusCode   int
	Size         int
	ResponseHash string
	Headers      map[string]string
	ContentType  string
}

// IDRange represents a detected valid ID range
type IDRange struct {
	Start int64
	End   int64
}

// IDPatternAnalyzer analyzes ID patterns to predict valid IDs
type IDPatternAnalyzer struct {
	patterns map[string]*regexp.Regexp
}

// NewIDPatternAnalyzer creates a new ID pattern analyzer
func NewIDPatternAnalyzer() *IDPatternAnalyzer {
	return &IDPatternAnalyzer{
		patterns: map[string]*regexp.Regexp{
			// UUID patterns
			"uuid_v1":  regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`),
			"uuid_v4":  regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`),
			"uuid_any": regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),

			// Sequential numeric
			"sequential": regexp.MustCompile(`^\d+$`),

			// Hashed IDs
			"md5":    regexp.MustCompile(`^[a-f0-9]{32}$`),
			"sha1":   regexp.MustCompile(`^[a-f0-9]{40}$`),
			"sha256": regexp.MustCompile(`^[a-f0-9]{64}$`),

			// Base64
			"base64": regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`),

			// Alphanumeric
			"alphanumeric": regexp.MustCompile(`^[a-zA-Z0-9_-]+$`),

			// GUID (Microsoft format - similar to UUID but uppercase)
			"guid": regexp.MustCompile(`^[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}$`),
		},
	}
}

// AccessTracker tracks which IDs have been successfully accessed
type AccessTracker struct {
	accessed map[string]AccessRecord
}

// AccessRecord tracks when and how an ID was accessed
type AccessRecord struct {
	ID           string
	Timestamp    time.Time
	StatusCode   int
	ResponseSize int
	Accessible   bool
}

// NewAccessTracker creates a new access tracker
func NewAccessTracker() *AccessTracker {
	return &AccessTracker{
		accessed: make(map[string]AccessRecord),
	}
}

// Record records an access attempt
func (a *AccessTracker) Record(id string, statusCode, size int, accessible bool) {
	a.accessed[id] = AccessRecord{
		ID:           id,
		Timestamp:    time.Now(),
		StatusCode:   statusCode,
		ResponseSize: size,
		Accessible:   accessible,
	}
}

// GetAccessible returns all accessible IDs
func (a *AccessTracker) GetAccessible() []string {
	var accessible []string
	for id, record := range a.accessed {
		if record.Accessible {
			accessible = append(accessible, id)
		}
	}
	return accessible
}

// RateLimiter controls request rate
type RateLimiter struct {
	rate   int
	ticker *time.Ticker
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requestsPerSecond int) *RateLimiter {
	if requestsPerSecond <= 0 {
		requestsPerSecond = 100
	}
	interval := time.Second / time.Duration(requestsPerSecond)
	return &RateLimiter{
		rate:   requestsPerSecond,
		ticker: time.NewTicker(interval),
	}
}

// Wait waits for rate limiter
func (r *RateLimiter) Wait() {
	<-r.ticker.C
}

// extractIDInfo extracts ID information from a URL
func (s *IDORScanner) extractIDInfo(targetURL string) (*IDInfo, error) {
	// Try to extract ID from path first
	if idInfo := s.extractFromPath(targetURL); idInfo != nil {
		return idInfo, nil
	}

	// Try to extract from query parameters
	if idInfo := s.extractFromQuery(targetURL); idInfo != nil {
		return idInfo, nil
	}

	return nil, fmt.Errorf("no ID parameter found in URL")
}

// extractFromPath extracts ID from URL path
func (s *IDORScanner) extractFromPath(targetURL string) *IDInfo {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	// Split path into segments
	segments := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")

	// Look for ID-like segments (usually the last segment)
	for i := len(segments) - 1; i >= 0; i-- {
		segment := segments[i]
		if segment == "" {
			continue
		}

		// Try to identify ID type
		idType, confidence := s.idPatterns.IdentifyType(segment)
		if confidence > 0.5 {
			return &IDInfo{
				Value:      segment,
				Type:       idType,
				Location:   "path",
				ParamName:  "",
				Confidence: confidence,
			}
		}
	}

	return nil
}

// extractFromQuery extracts ID from query parameters
func (s *IDORScanner) extractFromQuery(targetURL string) *IDInfo {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	query := parsedURL.Query()

	// Common ID parameter names
	idParams := []string{"id", "user_id", "userId", "uid", "object_id", "resource_id", "item_id", "doc_id", "post_id"}

	// Check common parameter names first
	for _, param := range idParams {
		if value := query.Get(param); value != "" {
			idType, confidence := s.idPatterns.IdentifyType(value)
			if confidence > 0.5 {
				return &IDInfo{
					Value:      value,
					Type:       idType,
					Location:   "query",
					ParamName:  param,
					Confidence: confidence,
				}
			}
		}
	}

	// Check all parameters for ID-like values
	for param, values := range query {
		if len(values) == 0 {
			continue
		}
		value := values[0]

		idType, confidence := s.idPatterns.IdentifyType(value)
		if confidence > 0.5 {
			return &IDInfo{
				Value:      value,
				Type:       idType,
				Location:   "query",
				ParamName:  param,
				Confidence: confidence,
			}
		}
	}

	return nil
}

// IdentifyType identifies the type of an ID value
func (p *IDPatternAnalyzer) IdentifyType(value string) (IDType, float64) {
	value = strings.TrimSpace(value)
	if value == "" {
		return IDTypeUnknown, 0.0
	}

	// Check UUID patterns (highest priority)
	if p.patterns["uuid_v1"].MatchString(value) {
		return IDTypeUUID, 1.0
	}
	if p.patterns["uuid_v4"].MatchString(value) {
		return IDTypeUUID, 1.0
	}
	if p.patterns["uuid_any"].MatchString(value) {
		// Try to parse as UUID to confirm
		if _, err := uuid.Parse(value); err == nil {
			return IDTypeUUID, 0.95
		}
	}

	// Check GUID (uppercase)
	if p.patterns["guid"].MatchString(value) {
		return IDTypeGUID, 0.95
	}

	// Check sequential numeric
	if p.patterns["sequential"].MatchString(value) {
		// Verify it's actually a number
		if _, err := strconv.ParseInt(value, 10, 64); err == nil {
			return IDTypeSequential, 0.98
		}
	}

	// Check hashed IDs
	if p.patterns["md5"].MatchString(value) {
		return IDTypeHashed, 0.90
	}
	if p.patterns["sha1"].MatchString(value) {
		return IDTypeHashed, 0.90
	}
	if p.patterns["sha256"].MatchString(value) {
		return IDTypeHashed, 0.90
	}

	// Check base64 (less confident - many false positives)
	if len(value) > 8 && p.patterns["base64"].MatchString(value) {
		return IDTypeBase64, 0.60
	}

	// Check alphanumeric
	if p.patterns["alphanumeric"].MatchString(value) {
		return IDTypeAlphanumeric, 0.50
	}

	return IDTypeUnknown, 0.0
}

// getBaselineResponse gets the baseline response for the original ID
func (s *IDORScanner) getBaselineResponse(ctx context.Context, target string, idInfo *IDInfo) (*BaselineResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("User-Agent", s.config.UserAgent)
	for k, v := range s.config.AuthHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range s.config.CustomHeaders {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	body, err := s.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	// Extract headers
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return &BaselineResponse{
		StatusCode:   resp.StatusCode,
		Size:         len(body),
		ResponseHash: s.hashResponse(body),
		Headers:      headers,
		ContentType:  resp.Header.Get("Content-Type"),
	}, nil
}
