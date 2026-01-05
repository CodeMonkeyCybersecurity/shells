package discovery

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// Engine is the main authentication discovery engine
type Engine struct {
	logger           *logger.Logger
	config           *Config
	httpClient       *http.Client
	webCrawler       *WebCrawler
	jsAnalyzer       *JavaScriptAnalyzer
	apiExtractor     *APIExtractor
	securityAnalyzer *SecurityAnalyzer
	patterns         []AuthEndpointPattern
}

// NewEngine creates a new authentication discovery engine
func NewEngine(logger *logger.Logger, config *Config) *Engine {
	if config == nil {
		config = &Config{
			MaxDepth:           3,
			FollowRedirects:    true,
			MaxRedirects:       10,
			Timeout:            30 * time.Second,
			UserAgent:          "shells-auth-discovery/1.0",
			Threads:            10,
			EnableJSAnalysis:   true,
			EnableAPIDiscovery: true,
			EnablePortScanning: false,
		}
	}

	httpClient := &http.Client{
		Timeout: config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !config.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= config.MaxRedirects {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	engine := &Engine{
		logger:           logger,
		config:           config,
		httpClient:       httpClient,
		webCrawler:       NewWebCrawler(logger),
		jsAnalyzer:       NewJavaScriptAnalyzer(logger),
		apiExtractor:     NewAPIExtractor(logger),
		securityAnalyzer: NewSecurityAnalyzer(logger),
	}

	engine.initializePatterns()
	return engine
}

// Discover performs comprehensive authentication discovery on a target
func (e *Engine) Discover(ctx context.Context, target string) (*DiscoveryResult, error) {
	startTime := time.Now()

	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled before discovery: %w", err)
	}

	e.logger.Info("Starting authentication discovery",
		"target", target,
		"max_depth", e.config.MaxDepth,
		"enable_js", e.config.EnableJSAnalysis)

	result := &DiscoveryResult{
		Target:          target,
		Implementations: []AuthImplementation{},
		Technologies:    []AuthTechnology{},
		Recommendations: []string{},
		Metadata:        make(map[string]interface{}),
		DiscoveredAt:    startTime,
	}

	// Parse target to understand what we're dealing with
	targetURL, err := parseTarget(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	// 1. Web-based discovery
	webImplementations, err := e.discoverWebAuth(ctx, targetURL)
	if err != nil {
		// Check if context was cancelled
		if ctx.Err() != nil {
			return nil, fmt.Errorf("discovery cancelled during web auth: %w", ctx.Err())
		}
		e.logger.Warn("Web auth discovery failed", "error", err)
	} else {
		result.Implementations = append(result.Implementations, webImplementations...)
	}

	// Check context between major steps
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("discovery cancelled after web auth: %w", err)
	}

	// 2. API discovery
	if e.config.EnableAPIDiscovery {
		apiImplementations, err := e.discoverAPIAuth(ctx, targetURL)
		if err != nil {
			// Check if context was cancelled
			if ctx.Err() != nil {
				return nil, fmt.Errorf("discovery cancelled during API auth: %w", ctx.Err())
			}
			e.logger.Warn("API auth discovery failed", "error", err)
		} else {
			result.Implementations = append(result.Implementations, apiImplementations...)
		}
	}

	// Check context between major steps
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("discovery cancelled after API auth: %w", err)
	}

	// 3. JavaScript analysis
	if e.config.EnableJSAnalysis {
		jsImplementations, err := e.discoverJSAuth(ctx, targetURL)
		if err != nil {
			// Check if context was cancelled
			if ctx.Err() != nil {
				return nil, fmt.Errorf("discovery cancelled during JS auth: %w", ctx.Err())
			}
			e.logger.Warn("JS auth discovery failed", "error", err)
		} else {
			result.Implementations = append(result.Implementations, jsImplementations...)
		}
	}

	// Check context between major steps
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("discovery cancelled after JS auth: %w", err)
	}

	// 4. Security analysis for each implementation
	for i := range result.Implementations {
		features, vulns := e.securityAnalyzer.AnalyzeImplementation(&result.Implementations[i])
		result.Implementations[i].SecurityFeatures = features
		result.Implementations[i].Vulnerabilities = vulns
	}

	// 5. Calculate metrics
	result.DiscoveryTime = time.Since(startTime)
	result.TotalEndpoints = e.countTotalEndpoints(result.Implementations)
	result.RiskScore = e.calculateRiskScore(result.Implementations)
	result.Recommendations = e.generateRecommendations(result.Implementations)

	e.logger.Info("Authentication discovery completed",
		"target", target,
		"implementations", len(result.Implementations),
		"endpoints", result.TotalEndpoints,
		"risk_score", result.RiskScore,
		"duration", result.DiscoveryTime)

	return result, nil
}

// discoverWebAuth discovers web-based authentication
func (e *Engine) discoverWebAuth(ctx context.Context, targetURL *url.URL) ([]AuthImplementation, error) {
	var implementations []AuthImplementation

	// Crawl the website for auth-related pages
	pages, err := e.webCrawler.CrawlForAuth(ctx, targetURL.String(), e.config.MaxDepth)
	if err != nil {
		return nil, err
	}

	e.logger.Debug("Web crawling completed", "pages", len(pages))

	// Analyze each page for authentication
	for _, page := range pages {
		impls := e.analyzePageForAuth(page)
		implementations = append(implementations, impls...)
	}

	// Deduplicate and merge similar implementations
	implementations = e.deduplicateImplementations(implementations)

	return implementations, nil
}

// discoverAPIAuth discovers API-based authentication
func (e *Engine) discoverAPIAuth(ctx context.Context, targetURL *url.URL) ([]AuthImplementation, error) {
	var implementations []AuthImplementation

	// Extract API endpoints
	endpoints, err := e.apiExtractor.DiscoverEndpoints(ctx, targetURL.String())
	if err != nil {
		return nil, err
	}

	e.logger.Debug("API discovery completed", "endpoints", len(endpoints))

	// Analyze each API endpoint for auth
	for _, endpoint := range endpoints {
		impl := e.analyzeAPIEndpointForAuth(endpoint)
		if impl != nil {
			implementations = append(implementations, *impl)
		}
	}

	return implementations, nil
}

// discoverJSAuth discovers JavaScript-based authentication
func (e *Engine) discoverJSAuth(ctx context.Context, targetURL *url.URL) ([]AuthImplementation, error) {
	var implementations []AuthImplementation

	// Analyze JavaScript for auth patterns
	jsResults, err := e.jsAnalyzer.AnalyzeURL(ctx, targetURL.String())
	if err != nil {
		return nil, err
	}

	e.logger.Debug("JavaScript analysis completed", "results", len(jsResults))

	// Convert JS results to implementations
	for _, result := range jsResults {
		impl := e.convertJSResultToImplementation(result)
		if impl != nil {
			implementations = append(implementations, *impl)
		}
	}

	return implementations, nil
}

// analyzePageForAuth analyzes a web page for authentication patterns
func (e *Engine) analyzePageForAuth(page WebPage) []AuthImplementation {
	var implementations []AuthImplementation

	// Look for login forms
	if forms := e.findLoginForms(page.Content); len(forms) > 0 {
		impl := e.createFormAuthImplementation(page, forms)
		implementations = append(implementations, impl)
	}

	// Look for OAuth/SAML indicators
	if oauthSignals := e.findOAuthSignals(page.Content); len(oauthSignals) > 0 {
		impl := e.createOAuthImplementation(page, oauthSignals)
		implementations = append(implementations, impl)
	}

	// Look for other auth types
	for _, pattern := range e.patterns {
		if pattern.Pattern.MatchString(page.Content) {
			impl := e.createPatternBasedImplementation(page, pattern)
			implementations = append(implementations, impl)
		}
	}

	return implementations
}

// Helper methods for implementation creation
func (e *Engine) createFormAuthImplementation(page WebPage, forms []LoginForm) AuthImplementation {
	impl := AuthImplementation{
		ID:           generateImplementationID(page.URL, "form"),
		Name:         "Form-based Authentication",
		Type:         AuthTypeFormLogin,
		Domain:       extractDomain(page.URL),
		Endpoints:    []AuthEndpoint{},
		Technologies: []string{"HTML Forms"},
		Confidence:   0.9,
		DiscoveredAt: time.Now(),
		LastSeen:     time.Now(),
		Metadata:     make(map[string]interface{}),
	}

	// Create endpoints from forms
	for _, form := range forms {
		endpoint := AuthEndpoint{
			ID:         generateEndpointID(form.Action),
			URL:        form.Action,
			Type:       AuthTypeFormLogin,
			Methods:    []string{form.Method},
			Parameters: convertFormFieldsToParameters(form.Fields),
			Confidence: 0.9,
		}
		impl.Endpoints = append(impl.Endpoints, endpoint)
	}

	return impl
}

func (e *Engine) createOAuthImplementation(page WebPage, signals []OAuthSignal) AuthImplementation {
	impl := AuthImplementation{
		ID:           generateImplementationID(page.URL, "oauth"),
		Name:         "OAuth2/OIDC Authentication",
		Type:         AuthTypeOAuth2,
		Domain:       extractDomain(page.URL),
		Endpoints:    []AuthEndpoint{},
		Technologies: []string{"OAuth2"},
		Confidence:   0.8,
		DiscoveredAt: time.Now(),
		LastSeen:     time.Now(),
		Metadata:     make(map[string]interface{}),
	}

	// Check if it's OIDC
	for _, signal := range signals {
		if strings.Contains(signal.Content, "openid") {
			impl.Type = AuthTypeOIDC
			impl.Name = "OpenID Connect Authentication"
			impl.Technologies = append(impl.Technologies, "OIDC")
		}
	}

	return impl
}

// Helper functions
func (e *Engine) initializePatterns() {
	patterns := []AuthEndpointPattern{
		{
			Pattern:     regexp.MustCompile(`(?i)\/login|\/signin|\/auth|\/sso`),
			PatternStr:  "login/signin/auth/sso paths",
			Type:        AuthTypeFormLogin,
			Description: "Common authentication endpoint paths",
			Priority:    1,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)oauth|openid|saml`),
			PatternStr:  "oauth/openid/saml patterns",
			Type:        AuthTypeOAuth2,
			Description: "Modern authentication protocol patterns",
			Priority:    2,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)basic\s+realm=`),
			PatternStr:  "basic authentication realm",
			Type:        AuthTypeBasicAuth,
			Description: "HTTP Basic Authentication patterns",
			Priority:    1,
		},
	}

	for i := range patterns {
		// patterns[i].Pattern is already compiled
		e.patterns = append(e.patterns, patterns[i])
	}
}

func (e *Engine) countTotalEndpoints(implementations []AuthImplementation) int {
	total := 0
	for _, impl := range implementations {
		total += len(impl.Endpoints)
	}
	return total
}

func (e *Engine) calculateRiskScore(implementations []AuthImplementation) float64 {
	if len(implementations) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, impl := range implementations {
		score := 5.0 // Base score

		// Add points for vulnerabilities
		score += float64(len(impl.Vulnerabilities)) * 0.5

		// Subtract points for security features
		score -= float64(len(impl.SecurityFeatures)) * 0.3

		// Adjust for auth type risk
		switch impl.Type {
		case AuthTypeBasicAuth, AuthTypeDigestAuth:
			score += 2.0
		case AuthTypeFormLogin:
			score += 1.0
		case AuthTypeOAuth2, AuthTypeOIDC, AuthTypeSAML:
			score -= 1.0
		case AuthTypeWebAuthn, AuthTypeFIDO2:
			score -= 2.0
		}

		totalScore += score
	}

	avgScore := totalScore / float64(len(implementations))

	// Normalize to 0-10 scale
	if avgScore > 10.0 {
		avgScore = 10.0
	}
	if avgScore < 0.0 {
		avgScore = 0.0
	}

	return avgScore
}

func (e *Engine) generateRecommendations(implementations []AuthImplementation) []string {
	var recommendations []string

	hasWeakAuth := false
	hasModernAuth := false
	hasMFA := false

	for _, impl := range implementations {
		if impl.Type == AuthTypeBasicAuth || impl.Type == AuthTypeDigestAuth {
			hasWeakAuth = true
		}
		if impl.Type == AuthTypeOAuth2 || impl.Type == AuthTypeSAML || impl.Type == AuthTypeWebAuthn {
			hasModernAuth = true
		}
		if e.securityAnalyzer.hasMFA(&impl) {
			hasMFA = true
		}
	}

	if hasWeakAuth {
		recommendations = append(recommendations,
			"Replace weak authentication methods (Basic/Digest) with modern protocols")
	}

	if !hasModernAuth {
		recommendations = append(recommendations,
			"Implement modern authentication protocols like OAuth2, SAML, or WebAuthn")
	}

	if !hasMFA {
		recommendations = append(recommendations,
			"Implement multi-factor authentication for enhanced security")
	}

	if len(implementations) > 3 {
		recommendations = append(recommendations,
			"Consider consolidating multiple authentication methods for consistency")
	}

	return recommendations
}

func (e *Engine) deduplicateImplementations(implementations []AuthImplementation) []AuthImplementation {
	seen := make(map[string]*AuthImplementation)
	var result []AuthImplementation

	for _, impl := range implementations {
		key := fmt.Sprintf("%s:%s", impl.Domain, impl.Type)

		if existing, exists := seen[key]; exists {
			// Merge implementations
			existing.Endpoints = append(existing.Endpoints, impl.Endpoints...)
			existing.Technologies = deduplicateStrings(append(existing.Technologies, impl.Technologies...))
		} else {
			seen[key] = &impl
			result = append(result, impl)
		}
	}

	return result
}

// findLoginForms extracts login forms from HTML content
func (e *Engine) findLoginForms(content string) []LoginForm {
	var forms []LoginForm

	// Pattern to match form tags with their content
	formPattern := regexp.MustCompile(`(?s)<form[^>]*>(.*?)</form>`)
	formMatches := formPattern.FindAllStringSubmatch(content, -1)

	for _, formMatch := range formMatches {
		if len(formMatch) < 2 {
			continue
		}

		formHTML := formMatch[0]
		formContent := formMatch[1]

		// Extract form attributes
		form := LoginForm{
			Method: "GET",
			Fields: []AuthFormField{},
		}

		// Extract action attribute
		if actionMatch := regexp.MustCompile(`action=['"](.*?)['"]`).FindStringSubmatch(formHTML); len(actionMatch) > 1 {
			form.Action = actionMatch[1]
		}

		// Extract method attribute
		if methodMatch := regexp.MustCompile(`method=['"](.*?)['"]`).FindStringSubmatch(formHTML); len(methodMatch) > 1 {
			form.Method = strings.ToUpper(methodMatch[1])
		}

		// Extract input fields
		inputPattern := regexp.MustCompile(`<input[^>]*>`)
		inputs := inputPattern.FindAllString(formContent, -1)

		hasPasswordField := false
		hasUsernameField := false

		for _, input := range inputs {
			field := AuthFormField{}

			if nameMatch := regexp.MustCompile(`name=['"](.*?)['"]`).FindStringSubmatch(input); len(nameMatch) > 1 {
				field.Name = nameMatch[1]
			}

			if typeMatch := regexp.MustCompile(`type=['"](.*?)['"]`).FindStringSubmatch(input); len(typeMatch) > 1 {
				field.Type = typeMatch[1]
			} else {
				field.Type = "text" // default type
			}

			form.Fields = append(form.Fields, field)

			// Check for auth-related fields
			lowerName := strings.ToLower(field.Name)
			if field.Type == "password" || strings.Contains(lowerName, "pass") {
				hasPasswordField = true
			}
			if strings.Contains(lowerName, "user") || strings.Contains(lowerName, "email") || strings.Contains(lowerName, "login") {
				hasUsernameField = true
			}
		}

		// Only include forms that look like login forms
		if hasPasswordField && (hasUsernameField || len(form.Fields) >= 2) {
			forms = append(forms, form)
		}
	}

	return forms
}

// findOAuthSignals detects OAuth/OIDC patterns in content
func (e *Engine) findOAuthSignals(content string) []OAuthSignal {
	var signals []OAuthSignal

	// OAuth indicators
	oauthPatterns := []string{
		`oauth2?[\w\-/]*authorize`,
		`client_id[\s]*[:=]`,
		`response_type[\s]*[:=]`,
		`openid[\s\-_]connect`,
		`\.well-known/openid[_\-]configuration`,
		`access_token`,
		`authorization_code`,
		`implicit[\s\-_]flow`,
		`pkce`,
		`code_challenge`,
	}

	for _, patternStr := range oauthPatterns {
		pattern := regexp.MustCompile(`(?i)` + patternStr)
		if matches := pattern.FindAllString(content, -1); len(matches) > 0 {
			for _, match := range matches {
				signals = append(signals, OAuthSignal{Content: match})
			}
		}
	}

	return signals
}

// analyzeAPIEndpointForAuth analyzes an API endpoint for authentication
func (e *Engine) analyzeAPIEndpointForAuth(endpoint string) *AuthImplementation {
	// Check if endpoint looks like auth-related
	lowerEndpoint := strings.ToLower(endpoint)
	authKeywords := []string{"auth", "login", "token", "oauth", "saml", "sso", "signin"}

	isAuthEndpoint := false
	for _, keyword := range authKeywords {
		if strings.Contains(lowerEndpoint, keyword) {
			isAuthEndpoint = true
			break
		}
	}

	if !isAuthEndpoint {
		return nil
	}

	// Determine auth type based on endpoint patterns
	var authType AuthType = AuthTypeAPIKey
	var name string = "API Authentication"

	if strings.Contains(lowerEndpoint, "oauth") {
		authType = AuthTypeOAuth2
		name = "OAuth2 API Authentication"
	} else if strings.Contains(lowerEndpoint, "saml") {
		authType = AuthTypeSAML
		name = "SAML API Authentication"
	} else if strings.Contains(lowerEndpoint, "jwt") || strings.Contains(lowerEndpoint, "token") {
		authType = AuthTypeJWT
		name = "JWT API Authentication"
	}

	impl := &AuthImplementation{
		ID:           generateImplementationID(endpoint, string(authType)),
		Name:         name,
		Type:         authType,
		Domain:       extractDomain(endpoint),
		Endpoints:    []AuthEndpoint{},
		Technologies: []string{"REST API"},
		Confidence:   0.7,
		DiscoveredAt: time.Now(),
		LastSeen:     time.Now(),
		Metadata:     make(map[string]interface{}),
	}

	// Create endpoint
	authEndpoint := AuthEndpoint{
		ID:         generateEndpointID(endpoint),
		URL:        endpoint,
		Type:       authType,
		Methods:    []string{"GET", "POST"},
		Parameters: []AuthParameter{},
		Confidence: 0.7,
	}

	impl.Endpoints = append(impl.Endpoints, authEndpoint)

	return impl
}

// convertJSResultToImplementation converts JavaScript analysis results to auth implementation
func (e *Engine) convertJSResultToImplementation(result interface{}) *AuthImplementation {
	// Try to cast to JSAuthDiscovery
	jsResult, ok := result.(JSAuthDiscovery)
	if !ok {
		return nil
	}

	if jsResult.Confidence < 0.5 {
		return nil
	}

	// Determine auth type from JS discovery
	var authType AuthType = AuthTypeJavaScript
	var name string = "JavaScript Authentication"
	var technologies []string = []string{"JavaScript"}

	if jsResult.OAuth != nil {
		authType = AuthTypeOAuth2
		name = "OAuth2 JavaScript Authentication"
		technologies = append(technologies, "OAuth2")
	} else if jsResult.WebAuthn != nil {
		authType = AuthTypeWebAuthn
		name = "WebAuthn JavaScript Authentication"
		technologies = append(technologies, "WebAuthn", "FIDO2")
	} else if len(jsResult.Tokens) > 0 {
		authType = AuthTypeJWT
		name = "JWT JavaScript Authentication"
		technologies = append(technologies, "JWT")
	}

	impl := &AuthImplementation{
		ID:           generateImplementationID(jsResult.Type, string(authType)),
		Name:         name,
		Type:         authType,
		Domain:       extractDomainFromEndpoints(jsResult.Endpoints),
		Endpoints:    []AuthEndpoint{},
		Technologies: technologies,
		Confidence:   jsResult.Confidence,
		DiscoveredAt: time.Now(),
		LastSeen:     time.Now(),
		Metadata:     make(map[string]interface{}),
	}

	// Convert endpoints
	for _, endpoint := range jsResult.Endpoints {
		authEndpoint := AuthEndpoint{
			ID:         generateEndpointID(endpoint),
			URL:        endpoint,
			Type:       authType,
			Methods:    []string{"POST", "GET"},
			Parameters: []AuthParameter{},
			Confidence: jsResult.Confidence,
		}
		impl.Endpoints = append(impl.Endpoints, authEndpoint)
	}

	// Store additional metadata
	impl.Metadata["js_discovery"] = jsResult
	if jsResult.OAuth != nil {
		impl.Metadata["oauth_config"] = jsResult.OAuth
	}
	if jsResult.WebAuthn != nil {
		impl.Metadata["webauthn_config"] = jsResult.WebAuthn
	}

	return impl
}

// createPatternBasedImplementation creates an implementation based on detected patterns
func (e *Engine) createPatternBasedImplementation(page WebPage, pattern AuthEndpointPattern) AuthImplementation {
	impl := AuthImplementation{
		ID:           generateImplementationID(page.URL, string(pattern.Type)),
		Name:         fmt.Sprintf("%s Authentication", pattern.Description),
		Type:         pattern.Type,
		Domain:       extractDomain(page.URL),
		Endpoints:    []AuthEndpoint{},
		Technologies: []string{},
		Confidence:   0.6,
		DiscoveredAt: time.Now(),
		LastSeen:     time.Now(),
		Metadata:     make(map[string]interface{}),
	}

	// Add pattern-specific technologies
	switch pattern.Type {
	case AuthTypeBasicAuth:
		impl.Technologies = []string{"HTTP Basic Auth"}
	case AuthTypeDigestAuth:
		impl.Technologies = []string{"HTTP Digest Auth"}
	case AuthTypeOAuth2:
		impl.Technologies = []string{"OAuth2"}
	case AuthTypeSAML:
		impl.Technologies = []string{"SAML"}
	case AuthTypeFormLogin:
		impl.Technologies = []string{"HTML Forms"}
	}

	// Create endpoint based on pattern match
	endpoint := AuthEndpoint{
		ID:         generateEndpointID(page.URL),
		URL:        page.URL,
		Type:       pattern.Type,
		Methods:    []string{"GET", "POST"},
		Parameters: []AuthParameter{},
		Confidence: 0.6,
	}

	impl.Endpoints = append(impl.Endpoints, endpoint)
	impl.Metadata["pattern_match"] = pattern.PatternStr

	return impl
}

// Helper types
type LoginForm struct {
	Action string
	Method string
	Fields []AuthFormField
}

type AuthFormField struct {
	Name string
	Type string
}

type OAuthSignal struct {
	Content string
}

type WebPage struct {
	URL     string
	Content string
}

// Utility functions
func parseTarget(target string) (*url.URL, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	return url.Parse(target)
}

func generateImplementationID(url string, authType string) string {
	hash := md5.Sum([]byte(url + authType))
	return fmt.Sprintf("auth_%x", hash[:8])
}

func generateEndpointID(url string) string {
	hash := md5.Sum([]byte(url))
	return fmt.Sprintf("ep_%x", hash[:8])
}

func extractDomain(urlStr string) string {
	if u, err := url.Parse(urlStr); err == nil {
		return u.Host
	}
	return urlStr
}

func convertFormFieldsToParameters(fields []AuthFormField) []AuthParameter {
	var params []AuthParameter
	for _, field := range fields {
		params = append(params, AuthParameter{
			Name:     field.Name,
			Type:     field.Type,
			Location: "body",
			Required: true,
		})
	}
	return params
}

func extractDomainFromEndpoints(endpoints []string) string {
	if len(endpoints) == 0 {
		return ""
	}

	// Extract domain from the first endpoint
	return extractDomain(endpoints[0])
}
