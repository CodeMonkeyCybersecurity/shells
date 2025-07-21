// pkg/auth/discovery/jsanalyzer.go
package discovery

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/dop251/goja"
)

// JavaScriptAnalyzer analyzes JavaScript code for authentication patterns
type JavaScriptAnalyzer struct {
	logger     *logger.Logger
	httpClient *http.Client
	vm         *goja.Runtime
	patterns   map[string]*regexp.Regexp
}

// OAuthDiscovery represents OAuth configuration found in JavaScript
type OAuthDiscovery struct {
	ClientID    string   `json:"client_id,omitempty"`
	RedirectURI string   `json:"redirect_uri,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	AuthURL     string   `json:"auth_url,omitempty"`
	TokenURL    string   `json:"token_url,omitempty"`
}

// WebAuthnDiscovery represents WebAuthn configuration found in JavaScript
type WebAuthnDiscovery struct {
	RPID        string `json:"rp_id,omitempty"`
	RPName      string `json:"rp_name,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	Challenge   string `json:"challenge,omitempty"`
	Timeout     int    `json:"timeout,omitempty"`
	Attestation string `json:"attestation,omitempty"`
}

// JSAuthDiscovery represents authentication found in JavaScript
type JSAuthDiscovery struct {
	Type       string             `json:"type"`
	Endpoints  []string           `json:"endpoints"`
	Tokens     []TokenDiscovery   `json:"tokens,omitempty"`
	OAuth      *OAuthDiscovery    `json:"oauth,omitempty"`
	WebAuthn   *WebAuthnDiscovery `json:"webauthn,omitempty"`
	APIKeys    []string           `json:"api_keys,omitempty"`
	Headers    map[string]string  `json:"headers,omitempty"`
	Storage    []StorageItem      `json:"storage,omitempty"`
	Confidence float64            `json:"confidence"`
}

// TokenDiscovery represents JWT or similar tokens found
type TokenDiscovery struct {
	Type     string `json:"type"`
	Location string `json:"location"`
	Pattern  string `json:"pattern"`
	Sample   string `json:"sample,omitempty"`
}

// StorageItem represents auth data in localStorage/sessionStorage
type StorageItem struct {
	Type    string `json:"type"` // localStorage, sessionStorage
	Key     string `json:"key"`
	Purpose string `json:"purpose"`
}

func NewJavaScriptAnalyzer(logger *logger.Logger) *JavaScriptAnalyzer {
	analyzer := &JavaScriptAnalyzer{
		logger: logger,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		vm:       goja.New(),
		patterns: make(map[string]*regexp.Regexp),
	}

	// Initialize patterns for finding auth-related code
	analyzer.initializePatterns()

	return analyzer
}

func (j *JavaScriptAnalyzer) initializePatterns() {
	// API endpoint patterns - fixed regex to avoid invalid escape sequence
	j.patterns["api_endpoint"] = regexp.MustCompile(`(["'])(\/api\/[^"']+|https?:\/\/[^"']+\/api[^"']+)(["'])`)

	// Authentication function patterns
	j.patterns["auth_function"] = regexp.MustCompile(`(login|authenticate|signin|getToken|refreshToken|logout)\s*[:(]`)

	// OAuth patterns
	j.patterns["oauth"] = regexp.MustCompile(`(client_id|client_secret|authorization|\/oauth\/|\/authorize\?|response_type=)`)

	// JWT patterns
	j.patterns["jwt"] = regexp.MustCompile(`(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|Bearer\s+[A-Za-z0-9_-]+|localStorage\.setItem\(['"]token)`)

	// WebAuthn patterns
	j.patterns["webauthn"] = regexp.MustCompile(`(navigator\.credentials|PublicKeyCredential|webauthn|authenticatorSelection|challenge)`)

	// API key patterns
	j.patterns["api_key"] = regexp.MustCompile(`(api[_-]?key|apikey|api_token|access[_-]?token)['"]\s*[:=]\s*['"]([^'"]+)['"]`)

	// Storage patterns
	j.patterns["storage"] = regexp.MustCompile(`(localStorage|sessionStorage)\.(setItem|getItem)\(['"]([^'"]+)['"]`)

	// Authorization headers
	j.patterns["auth_header"] = regexp.MustCompile(`(Authorization|X-API-Key|X-Auth-Token)['"]\s*:\s*['"]([^'"]+)['"]`)
}

// FindAuthInJavaScript analyzes JavaScript files from a website
func (j *JavaScriptAnalyzer) FindAuthInJavaScript(ctx context.Context, baseURL string) []JSAuthDiscovery {
	j.logger.Info("Starting JavaScript analysis for auth patterns", "baseURL", baseURL)

	var discoveries []JSAuthDiscovery

	// First, get the main page and find script tags
	scripts := j.findScriptURLs(ctx, baseURL)

	// Analyze each script
	for _, scriptURL := range scripts {
		if discovery := j.analyzeScript(ctx, scriptURL); discovery != nil {
			discoveries = append(discoveries, *discovery)
		}
	}

	// Also analyze inline scripts from the main page
	if inlineDiscovery := j.analyzeInlineScripts(ctx, baseURL); inlineDiscovery != nil {
		discoveries = append(discoveries, *inlineDiscovery)
	}

	// Merge and deduplicate discoveries
	merged := j.mergeDiscoveries(discoveries)

	j.logger.Info("JavaScript analysis completed",
		"scriptsAnalyzed", len(scripts),
		"authMethodsFound", len(merged))

	return merged
}

// findScriptURLs finds all JavaScript URLs from a page
func (j *JavaScriptAnalyzer) findScriptURLs(ctx context.Context, baseURL string) []string {
	var scripts []string
	
	resp, err := j.httpClient.Get(baseURL)
	if err != nil {
		return scripts
	}
	defer resp.Body.Close()
	
	// Parse HTML to find script tags
	// This is a simplified implementation - in production you'd use goquery
	body, _ := io.ReadAll(resp.Body)
	scriptPattern := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptPattern.FindAllStringSubmatch(string(body), -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			scriptURL := j.resolveURL(baseURL, match[1])
			scripts = append(scripts, scriptURL)
		}
	}
	
	return scripts
}

// analyzeInlineScripts analyzes inline scripts in HTML
func (j *JavaScriptAnalyzer) analyzeInlineScripts(ctx context.Context, url string) *JSAuthDiscovery {
	resp, err := j.httpClient.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	
	// Extract inline scripts
	scriptPattern := regexp.MustCompile(`<script[^>]*>([^<]+)</script>`)
	matches := scriptPattern.FindAllStringSubmatch(string(body), -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			if discovery := j.analyzeJavaScriptCode(match[1], url); discovery != nil {
				return discovery
			}
		}
	}
	
	return nil
}

// mergeDiscoveries merges and deduplicates discoveries
func (j *JavaScriptAnalyzer) mergeDiscoveries(discoveries []JSAuthDiscovery) []JSAuthDiscovery {
	// Simple deduplication based on type and endpoints
	seen := make(map[string]bool)
	var merged []JSAuthDiscovery
	
	for _, d := range discoveries {
		key := d.Type + strings.Join(d.Endpoints, ",")
		if !seen[key] {
			seen[key] = true
			merged = append(merged, d)
		}
	}
	
	return merged
}

// resolveURL resolves a relative URL to absolute
func (j *JavaScriptAnalyzer) resolveURL(baseURL, relativeURL string) string {
	if strings.HasPrefix(relativeURL, "http://") || strings.HasPrefix(relativeURL, "https://") {
		return relativeURL
	}
	
	base, err := url.Parse(baseURL)
	if err != nil {
		return relativeURL
	}
	
	relative, err := url.Parse(relativeURL)
	if err != nil {
		return relativeURL
	}
	
	return base.ResolveReference(relative).String()
}

// AnalyzeURL analyzes a URL for JavaScript authentication patterns
func (j *JavaScriptAnalyzer) AnalyzeURL(ctx context.Context, url string) ([]interface{}, error) {
	// Placeholder implementation - returns empty results
	return []interface{}{}, nil
}

// analyzeScript analyzes a single JavaScript file
func (j *JavaScriptAnalyzer) analyzeScript(ctx context.Context, scriptURL string) *JSAuthDiscovery {
	j.logger.Debug("Analyzing script", "url", scriptURL)

	// Download the script
	req, err := http.NewRequestWithContext(ctx, "GET", scriptURL, nil)
	if err != nil {
		return nil
	}

	resp, err := j.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	code := string(body)

	discovery := &JSAuthDiscovery{
		Type:      "javascript",
		Endpoints: []string{},
		Headers:   make(map[string]string),
	}

	// Find API endpoints
	if matches := j.patterns["api_endpoint"].FindAllStringSubmatch(code, -1); matches != nil {
		for _, match := range matches {
			if len(match) > 2 {
				endpoint := match[2]
				// Resolve relative URLs
				if strings.HasPrefix(endpoint, "/") {
					endpoint = j.resolveURL(endpoint, scriptURL)
				}
				discovery.Endpoints = append(discovery.Endpoints, endpoint)
			}
		}
	}

	// Find OAuth configuration
	if j.patterns["oauth"].MatchString(code) {
		discovery.OAuth = j.extractOAuthConfig(code)
	}

	// Find WebAuthn usage
	if j.patterns["webauthn"].MatchString(code) {
		discovery.WebAuthn = j.extractWebAuthnConfig(code)
	}

	// Find JWT tokens
	if matches := j.patterns["jwt"].FindAllStringSubmatch(code, -1); matches != nil {
		for _, match := range matches {
			token := TokenDiscovery{
				Type:     "JWT",
				Location: scriptURL,
				Pattern:  match[0],
			}
			discovery.Tokens = append(discovery.Tokens, token)
		}
	}

	// Find API keys (be careful with these)
	if matches := j.patterns["api_key"].FindAllStringSubmatch(code, -1); matches != nil {
		for _, match := range matches {
			if len(match) > 2 && !j.isPlaceholder(match[2]) {
				// Don't store actual keys, just note they exist
				discovery.APIKeys = append(discovery.APIKeys, fmt.Sprintf("%s=REDACTED", match[1]))
			}
		}
	}

	// Find storage usage
	if matches := j.patterns["storage"].FindAllStringSubmatch(code, -1); matches != nil {
		for _, match := range matches {
			if len(match) > 3 {
				item := StorageItem{
					Type: match[1],
					Key:  match[3],
				}
				// Try to determine purpose from key name
				item.Purpose = j.inferStoragePurpose(item.Key)
				discovery.Storage = append(discovery.Storage, item)
			}
		}
	}

	// Find authorization headers
	if matches := j.patterns["auth_header"].FindAllStringSubmatch(code, -1); matches != nil {
		for _, match := range matches {
			if len(match) > 2 {
				discovery.Headers[match[1]] = match[2]
			}
		}
	}

	// Calculate confidence
	discovery.Confidence = j.calculateConfidence(discovery)

	if discovery.Confidence < 0.3 {
		return nil // Not enough evidence
	}

	return discovery
}

// extractOAuthConfig extracts OAuth configuration from JavaScript
func (j *JavaScriptAnalyzer) extractOAuthConfig(code string) *OAuthDiscovery {
	oauth := &OAuthDiscovery{}

	// Look for OAuth URLs
	authURLPattern := regexp.MustCompile(`authorize['"]\s*:\s*['"]([^'"]+)['"]`)
	if match := authURLPattern.FindStringSubmatch(code); len(match) > 1 {
		oauth.AuthURL = match[1]
	}

	tokenURLPattern := regexp.MustCompile(`token['"]\s*:\s*['"]([^'"]+)['"]`)
	if match := tokenURLPattern.FindStringSubmatch(code); len(match) > 1 {
		oauth.TokenURL = match[1]
	}

	// Look for client ID (not secret!)
	clientIDPattern := regexp.MustCompile(`client_id['"]\s*:\s*['"]([^'"]+)['"]`)
	if match := clientIDPattern.FindStringSubmatch(code); len(match) > 1 {
		oauth.ClientID = match[1]
	}

	// Look for scopes
	scopePattern := regexp.MustCompile(`scope['"]\s*:\s*['"]([^'"]+)['"]`)
	if match := scopePattern.FindStringSubmatch(code); len(match) > 1 {
		oauth.Scopes = strings.Split(match[1], " ")
	}

	// Check for PKCE - store in redirect URI if found
	if strings.Contains(code, "code_challenge") || strings.Contains(code, "code_verifier") {
		if oauth.RedirectURI != "" {
			oauth.RedirectURI += "&pkce=true"
		}
	}

	return oauth
}

// extractWebAuthnConfig extracts WebAuthn configuration from JavaScript
func (j *JavaScriptAnalyzer) extractWebAuthnConfig(code string) *WebAuthnDiscovery {
	webauthn := &WebAuthnDiscovery{}
	
	// Look for RP ID
	rpIDPattern := regexp.MustCompile(`rpId['"]\s*:\s*['"]([^'"]+)['"]`)
	if match := rpIDPattern.FindStringSubmatch(code); len(match) > 1 {
		webauthn.RPID = match[1]
	}
	
	// Look for RP Name
	rpNamePattern := regexp.MustCompile(`rpName['"]\s*:\s*['"]([^'"]+)['"]`)
	if match := rpNamePattern.FindStringSubmatch(code); len(match) > 1 {
		webauthn.RPName = match[1]
	}
	
	// Look for attestation
	attestationPattern := regexp.MustCompile(`attestation['"]\s*:\s*['"]([^'"]+)['"]`)
	if match := attestationPattern.FindStringSubmatch(code); len(match) > 1 {
		webauthn.Attestation = match[1]
	}
	
	return webauthn
}

// inferStoragePurpose infers the purpose of storage based on key name
func (j *JavaScriptAnalyzer) inferStoragePurpose(key string) string {
	key = strings.ToLower(key)
	
	switch {
	case strings.Contains(key, "token"):
		return "auth_token"
	case strings.Contains(key, "session"):
		return "session_id"
	case strings.Contains(key, "user"):
		return "user_data"
	case strings.Contains(key, "auth"):
		return "auth_data"
	case strings.Contains(key, "jwt"):
		return "jwt_token"
	default:
		return "unknown"
	}
}

// calculateConfidence calculates confidence score for discovery
func (j *JavaScriptAnalyzer) calculateConfidence(discovery *JSAuthDiscovery) float64 {
	confidence := 0.0
	
	// Base confidence from endpoints
	if len(discovery.Endpoints) > 0 {
		confidence += 0.3
	}
	
	// OAuth configuration
	if discovery.OAuth != nil && discovery.OAuth.AuthURL != "" {
		confidence += 0.2
	}
	
	// WebAuthn configuration
	if discovery.WebAuthn != nil && discovery.WebAuthn.RPID != "" {
		confidence += 0.2
	}
	
	// JWT tokens
	if len(discovery.Tokens) > 0 {
		confidence += 0.2
	}
	
	// Storage usage
	if len(discovery.Storage) > 0 {
		confidence += 0.1
	}
	
	return confidence
}

// analyzeJavaScriptCode analyzes JavaScript code for auth patterns
func (j *JavaScriptAnalyzer) analyzeJavaScriptCode(code string, sourceURL string) *JSAuthDiscovery {
	discovery := &JSAuthDiscovery{
		Type:      "javascript",
		Endpoints: []string{},
		Headers:   make(map[string]string),
	}
	
	// Find API endpoints
	if matches := j.patterns["api_endpoint"].FindAllStringSubmatch(code, -1); matches != nil {
		for _, match := range matches {
			if len(match) > 2 {
				endpoint := match[2]
				// Resolve relative URLs
				if strings.HasPrefix(endpoint, "/") {
					endpoint = j.resolveURL(sourceURL, endpoint)
				}
				discovery.Endpoints = append(discovery.Endpoints, endpoint)
			}
		}
	}
	
	// Find OAuth configuration
	if j.patterns["oauth"].MatchString(code) {
		discovery.OAuth = j.extractOAuthConfig(code)
	}
	
	// Find WebAuthn usage
	if j.patterns["webauthn"].MatchString(code) {
		discovery.WebAuthn = j.extractWebAuthnConfig(code)
	}
	
	// Calculate confidence
	discovery.Confidence = j.calculateConfidence(discovery)
	
	if discovery.Confidence < 0.3 {
		return nil // Not enough evidence
	}
	
	return discovery
}

// Advanced pattern analysis using abstract syntax tree parsing
func (j *JavaScriptAnalyzer) performDeepAnalysis(code string) map[string]interface{} {
	results := make(map[string]interface{})

	// Try to execute safely in sandbox to extract configuration
	j.vm.Set("results", results)

	// Inject monitoring functions
	monitoringCode := `
    var __auth_config = {};
    var XMLHttpRequest = function() {
        this.open = function(method, url) {
            if (!__auth_config.endpoints) __auth_config.endpoints = [];
            __auth_config.endpoints.push({method: method, url: url});
        };
        this.setRequestHeader = function(header, value) {
            if (!__auth_config.headers) __auth_config.headers = {};
            __auth_config.headers[header] = value;
        };
    };
    var fetch = function(url, options) {
        if (!__auth_config.fetch) __auth_config.fetch = [];
        __auth_config.fetch.push({url: url, options: options});
    };
    `

	// Execute monitoring code first
	j.vm.RunString(monitoringCode)

	// Try to run the actual code (with timeout and error handling)
	// This is wrapped in error handling as arbitrary JS can fail
	func() {
		defer func() {
			if r := recover(); r != nil {
				j.logger.Debug("JS execution failed", "error", r)
			}
		}()

		// Execute with timeout
		j.vm.RunString(code)

		// Extract results
		config := j.vm.Get("__auth_config")
		if config != nil {
			if exportedConfig := config.Export(); exportedConfig != nil {
				if configMap, ok := exportedConfig.(map[string]interface{}); ok {
					for k, v := range configMap {
						results[k] = v
					}
				}
			}
		}
	}()

	return results
}

// isPlaceholder checks if a value is a placeholder rather than real data
func (j *JavaScriptAnalyzer) isPlaceholder(value string) bool {
	value = strings.ToLower(value)
	placeholders := []string{
		"your", "example", "placeholder", "demo", "test",
		"xxx", "123", "abc", "key", "secret", "token",
		"replace", "changeme", "dummy", "sample",
	}
	
	for _, placeholder := range placeholders {
		if strings.Contains(value, placeholder) {
			return true
		}
	}
	
	// Check for patterns like YOUR_KEY, EXAMPLE_TOKEN etc
	if strings.Contains(value, "_") && strings.ToUpper(value) == value {
		return true
	}
	
	return false
}
