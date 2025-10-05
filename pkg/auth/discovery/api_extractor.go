package discovery

import (
	"context"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// APIExtractor discovers API endpoints that may contain authentication
type APIExtractor struct {
	logger     *logger.Logger
	httpClient *http.Client
	patterns   map[string]*regexp.Regexp
}

// NewAPIExtractor creates a new API endpoint extractor
func NewAPIExtractor(logger *logger.Logger) *APIExtractor {
	extractor := &APIExtractor{
		logger: logger,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		patterns: make(map[string]*regexp.Regexp),
	}

	// Initialize API endpoint patterns
	extractor.initializePatterns()

	return extractor
}

func (a *APIExtractor) initializePatterns() {
	// Common API path patterns
	a.patterns["api_paths"] = regexp.MustCompile(`(?i)/api(/v?\d+)?/[^\s"'<>]+`)

	// Authentication-related API endpoints
	a.patterns["auth_apis"] = regexp.MustCompile(`(?i)/api[^/]*/(auth|login|token|oauth|saml|sso)[^\s"'<>]*`)

	// REST API patterns
	a.patterns["rest_patterns"] = regexp.MustCompile(`(?i)(GET|POST|PUT|DELETE|PATCH)\s+(/api/[^\s"'<>]+)`)

	// OpenAPI/Swagger patterns
	a.patterns["swagger"] = regexp.MustCompile(`(?i)(/swagger|/openapi|/api-docs)[^\s"'<>]*`)

	// GraphQL endpoints
	a.patterns["graphql"] = regexp.MustCompile(`(?i)/graphql[^\s"'<>]*`)
}

// DiscoverEndpoints discovers API endpoints from a target URL
func (a *APIExtractor) DiscoverEndpoints(ctx context.Context, targetURL string) ([]string, error) {
	a.logger.Info("Starting API endpoint discovery", "target", targetURL)

	var endpoints []string
	visited := make(map[string]bool)

	// 1. Check the main page for API references
	mainEndpoints, err := a.extractEndpointsFromPage(ctx, targetURL)
	if err != nil {
		a.logger.Warn("Failed to extract endpoints from main page", "error", err)
	} else {
		for _, endpoint := range mainEndpoints {
			if !visited[endpoint] {
				endpoints = append(endpoints, endpoint)
				visited[endpoint] = true
			}
		}
	}

	// 2. Try common API discovery paths
	commonPaths := a.generateCommonAPIPaths(targetURL)
	for _, path := range commonPaths {
		if a.isValidAPIEndpoint(ctx, path) {
			if !visited[path] {
				endpoints = append(endpoints, path)
				visited[path] = true
			}
		}
	}

	// 3. Try to discover through robots.txt
	robotsEndpoints := a.discoverFromRobots(ctx, targetURL)
	for _, endpoint := range robotsEndpoints {
		if !visited[endpoint] {
			endpoints = append(endpoints, endpoint)
			visited[endpoint] = true
		}
	}

	// 4. Try to discover through sitemap.xml
	sitemapEndpoints := a.discoverFromSitemap(ctx, targetURL)
	for _, endpoint := range sitemapEndpoints {
		if !visited[endpoint] {
			endpoints = append(endpoints, endpoint)
			visited[endpoint] = true
		}
	}

	a.logger.Info("API endpoint discovery completed",
		"target", targetURL,
		"endpoints_found", len(endpoints))

	return endpoints, nil
}

// extractEndpointsFromPage extracts API endpoints from a web page
func (a *APIExtractor) extractEndpointsFromPage(ctx context.Context, pageURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	// Read page content
	content, err := a.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var endpoints []string
	baseURL := a.getBaseURL(pageURL)

	// Extract API endpoints using patterns
	for patternName, pattern := range a.patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			var endpoint string
			if len(match) > 1 {
				endpoint = match[1]
			} else {
				endpoint = match[0]
			}

			// Convert relative URLs to absolute
			if strings.HasPrefix(endpoint, "/") {
				endpoint = baseURL + endpoint
			}

			// Only include if it looks like an auth-related endpoint
			if a.isAuthRelatedEndpoint(endpoint) {
				endpoints = append(endpoints, endpoint)
				a.logger.Debug("Found API endpoint",
					"endpoint", endpoint,
					"pattern", patternName)
			}
		}
	}

	return endpoints, nil
}

// generateCommonAPIPaths generates common API paths to check
func (a *APIExtractor) generateCommonAPIPaths(baseURL string) []string {
	commonPaths := []string{
		"/api",
		"/api/v1",
		"/api/v2",
		"/api/auth",
		"/api/login",
		"/api/token",
		"/api/oauth",
		"/api/oauth2",
		"/api/saml",
		"/api/sso",
		"/auth/api",
		"/oauth/api",
		"/saml/api",
		"/v1/auth",
		"/v2/auth",
		"/rest/api",
		"/rest/auth",
		"/graphql",
		"/swagger.json",
		"/swagger.yml",
		"/swagger.yaml",
		"/openapi.json",
		"/openapi.yml",
		"/openapi.yaml",
		"/api-docs",
		"/api-docs.json",
		"/.well-known/openid_configuration",
	}

	var fullPaths []string
	for _, path := range commonPaths {
		fullPaths = append(fullPaths, baseURL+path)
	}

	return fullPaths
}

// isValidAPIEndpoint checks if a path is a valid API endpoint
func (a *APIExtractor) isValidAPIEndpoint(ctx context.Context, endpoint string) bool {
	req, err := http.NewRequestWithContext(ctx, "HEAD", endpoint, nil)
	if err != nil {
		return false
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer httpclient.CloseBody(resp)

	// Check if it's a valid HTTP response (not 404)
	if resp.StatusCode == 404 {
		return false
	}

	// Check content type for API-like responses
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "xml") ||
		strings.Contains(contentType, "application/") {
		return true
	}

	return false
}

// isAuthRelatedEndpoint checks if an endpoint is authentication-related
func (a *APIExtractor) isAuthRelatedEndpoint(endpoint string) bool {
	lowerEndpoint := strings.ToLower(endpoint)

	authKeywords := []string{
		"auth", "login", "signin", "token", "oauth", "saml", "sso",
		"oidc", "jwt", "bearer", "credential", "identity", "session",
		"user", "account", "profile", "me", "whoami",
	}

	for _, keyword := range authKeywords {
		if strings.Contains(lowerEndpoint, keyword) {
			return true
		}
	}

	return false
}

// discoverFromRobots discovers endpoints from robots.txt
func (a *APIExtractor) discoverFromRobots(ctx context.Context, baseURL string) []string {
	robotsURL := baseURL + "/robots.txt"

	req, err := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
	if err != nil {
		return []string{}
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return []string{}
	}
	defer httpclient.CloseBody(resp)

	content, err := a.readResponseBody(resp)
	if err != nil {
		return []string{}
	}

	var endpoints []string
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Disallow:") || strings.HasPrefix(line, "Allow:") {
			path := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			if a.isAuthRelatedEndpoint(path) {
				fullURL := baseURL + path
				endpoints = append(endpoints, fullURL)
			}
		}
	}

	return endpoints
}

// discoverFromSitemap discovers endpoints from sitemap.xml
func (a *APIExtractor) discoverFromSitemap(ctx context.Context, baseURL string) []string {
	sitemapURL := baseURL + "/sitemap.xml"

	req, err := http.NewRequestWithContext(ctx, "GET", sitemapURL, nil)
	if err != nil {
		return []string{}
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return []string{}
	}
	defer httpclient.CloseBody(resp)

	content, err := a.readResponseBody(resp)
	if err != nil {
		return []string{}
	}

	var endpoints []string

	// Extract URLs from sitemap XML
	urlPattern := regexp.MustCompile(`<loc>(.*?)</loc>`)
	matches := urlPattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			url := match[1]
			if a.isAuthRelatedEndpoint(url) {
				endpoints = append(endpoints, url)
			}
		}
	}

	return endpoints
}

// Helper methods

func (a *APIExtractor) getBaseURL(fullURL string) string {
	if parsed, err := url.Parse(fullURL); err == nil {
		return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	}
	return fullURL
}

func (a *APIExtractor) readResponseBody(resp *http.Response) (string, error) {
	defer httpclient.CloseBody(resp)

	// Limit response size to prevent memory issues
	const maxBodySize = 10 * 1024 * 1024 // 10MB
	body := http.MaxBytesReader(nil, resp.Body, maxBodySize)

	bodyBytes := make([]byte, maxBodySize)
	n, err := body.Read(bodyBytes)
	if err != nil && err.Error() != "EOF" {
		return "", err
	}

	return string(bodyBytes[:n]), nil
}
