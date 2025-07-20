// pkg/fuzzing/engines.go
package fuzzing

import (
	"fmt"
	"io"
	"math"
	"net/url"
	"regexp"
	"strings"
)

// PatternAnalyzer analyzes patterns in responses and URLs
type PatternAnalyzer struct {
	patterns map[string]*regexp.Regexp
	learned  map[string][]string
}

// NewPatternAnalyzer creates a new pattern analyzer
func NewPatternAnalyzer() *PatternAnalyzer {
	return &PatternAnalyzer{
		patterns: initializePatterns(),
		learned:  make(map[string][]string),
	}
}

// ExtractFromContent extracts patterns from content
func (p *PatternAnalyzer) ExtractFromContent(reader io.Reader, patterns []string) []string {
	content, err := io.ReadAll(reader)
	if err != nil {
		return []string{}
	}

	extracted := make(map[string]bool)
	contentStr := string(content)

	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}

		matches := re.FindAllStringSubmatch(contentStr, -1)
		for _, match := range matches {
			if len(match) > 1 {
				extracted[match[1]] = true
			}
		}
	}

	result := []string{}
	for param := range extracted {
		result = append(result, param)
	}

	return result
}

// GenerateParameterPatterns generates parameter patterns based on URL
func (p *PatternAnalyzer) GenerateParameterPatterns(target *url.URL) []string {
	patterns := []string{}

	// Extract base name from path
	pathParts := strings.Split(strings.Trim(target.Path, "/"), "/")
	
	for _, part := range pathParts {
		if part == "" {
			continue
		}

		// Generate variations
		patterns = append(patterns, part)
		patterns = append(patterns, part+"_id")
		patterns = append(patterns, part+"_name")
		patterns = append(patterns, part+"Id")
		patterns = append(patterns, part+"Name")
		patterns = append(patterns, strings.ToLower(part))
		patterns = append(patterns, strings.ToUpper(part))
		
		// Singular/plural variations
		if strings.HasSuffix(part, "s") {
			singular := strings.TrimSuffix(part, "s")
			patterns = append(patterns, singular)
			patterns = append(patterns, singular+"_id")
		} else {
			patterns = append(patterns, part+"s")
		}
	}

	// Add common patterns
	commonPatterns := []string{
		"id", "name", "user", "username", "email", "password", "token",
		"key", "api_key", "apikey", "auth", "authorization", "session",
		"csrf", "nonce", "state", "redirect", "return", "callback",
		"action", "method", "type", "format", "output", "debug",
		"page", "limit", "offset", "sort", "order", "filter", "search",
		"q", "query", "term", "keyword", "lang", "language", "locale",
	}

	patterns = append(patterns, commonPatterns...)

	return unique(patterns)
}

// HeuristicEngine applies heuristics for smart fuzzing
type HeuristicEngine struct {
	rules []HeuristicRule
}

// HeuristicRule represents a fuzzing heuristic
type HeuristicRule struct {
	Name      string
	Condition func(FuzzResult) bool
	Generate  func(FuzzResult) []string
}

// NewHeuristicEngine creates a new heuristic engine
func NewHeuristicEngine() *HeuristicEngine {
	return &HeuristicEngine{
		rules: initializeHeuristicRules(),
	}
}

// GeneratePaths generates new paths based on findings and heuristics
func (h *HeuristicEngine) GeneratePaths(findings []FuzzResult, framework string) []string {
	paths := make(map[string]bool)

	for _, finding := range findings {
		for _, rule := range h.rules {
			if rule.Condition(finding) {
				newPaths := rule.Generate(finding)
				for _, path := range newPaths {
					paths[path] = true
				}
			}
		}
	}

	// Framework-specific heuristics
	frameworkPaths := h.getFrameworkPaths(framework)
	for _, path := range frameworkPaths {
		paths[path] = true
	}

	result := []string{}
	for path := range paths {
		result = append(result, path)
	}

	return result
}

func (h *HeuristicEngine) getFrameworkPaths(framework string) []string {
	switch framework {
	case "php":
		return []string{
			"phpinfo.php", "info.php", "test.php", "config.php",
			"database.php", "db.php", "install.php", "setup.php",
		}
	case "aspnet":
		return []string{
			"web.config", "global.asax", "default.aspx", "login.aspx",
			"admin.aspx", "trace.axd", "elmah.axd",
		}
	case "express":
		return []string{
			"package.json", "package-lock.json", ".env", "config.json",
			"app.js", "server.js", "index.js",
		}
	default:
		return []string{
			".git/config", ".svn/entries", ".env", ".config",
			"config.xml", "settings.json", "database.yml",
		}
	}
}

// MLPredictor uses machine learning-like techniques for prediction
type MLPredictor struct {
	model     *SimpleModel
	features  *FeatureExtractor
	threshold float64
}

// SimpleModel represents a simple ML model for predictions
type SimpleModel struct {
	weights map[string]float64
	bias    float64
}

// FeatureExtractor extracts features from URLs and responses
type FeatureExtractor struct {
	features map[string]func(*url.URL) float64
}

// NewMLPredictor creates a new ML predictor
func NewMLPredictor() *MLPredictor {
	return &MLPredictor{
		model:     initializeModel(),
		features:  initializeFeatureExtractor(),
		threshold: 0.7,
	}
}

// PredictParameters predicts likely parameters for a URL
func (m *MLPredictor) PredictParameters(target *url.URL) []string {
	// Extract features
	featureVector := m.features.Extract(target)
	
	// Score parameter candidates
	candidates := m.generateCandidates(target)
	scored := make(map[string]float64)
	
	for _, candidate := range candidates {
		score := m.model.Score(candidate, featureVector)
		if score > m.threshold {
			scored[candidate] = score
		}
	}

	// Sort by score and return top candidates
	result := []string{}
	for param := range scored {
		result = append(result, param)
	}

	return result
}

func (m *MLPredictor) generateCandidates(target *url.URL) []string {
	candidates := []string{}

	// URL-based candidates
	parts := strings.Split(target.Path, "/")
	for _, part := range parts {
		if part != "" && !strings.Contains(part, ".") {
			candidates = append(candidates, part)
			candidates = append(candidates, part+"_id")
			candidates = append(candidates, part+"_name")
			candidates = append(candidates, part+"_type")
		}
	}

	// Domain-based candidates
	host := target.Hostname()
	if strings.Contains(host, "api") {
		candidates = append(candidates, "api_key", "api_version", "format")
	}
	if strings.Contains(host, "auth") {
		candidates = append(candidates, "token", "session", "user_id")
	}

	// Common parameters by context
	if strings.Contains(target.Path, "search") {
		candidates = append(candidates, "q", "query", "term", "filter")
	}
	if strings.Contains(target.Path, "user") {
		candidates = append(candidates, "username", "email", "id", "profile")
	}

	return candidates
}

// Extract extracts features from a URL
func (f *FeatureExtractor) Extract(target *url.URL) map[string]float64 {
	features := make(map[string]float64)
	
	for name, extractor := range f.features {
		features[name] = extractor(target)
	}
	
	return features
}

// Score calculates the likelihood score for a parameter
func (m *SimpleModel) Score(parameter string, features map[string]float64) float64 {
	score := m.bias

	// Parameter-based features
	paramFeatures := extractParameterFeatures(parameter)
	for feature, value := range paramFeatures {
		if weight, ok := m.weights[feature]; ok {
			score += weight * value
		}
	}

	// URL-based features
	for feature, value := range features {
		if weight, ok := m.weights["url_"+feature]; ok {
			score += weight * value
		}
	}

	// Apply sigmoid to get probability
	return sigmoid(score)
}

// Helper functions for ML

func extractParameterFeatures(param string) map[string]float64 {
	features := make(map[string]float64)
	
	// Length features
	features["length"] = float64(len(param))
	features["has_underscore"] = boolToFloat(strings.Contains(param, "_"))
	features["has_dash"] = boolToFloat(strings.Contains(param, "-"))
	features["is_camelcase"] = boolToFloat(isCamelCase(param))
	features["has_numbers"] = boolToFloat(hasNumbers(param))
	
	// Common parameter indicators
	commonPrefixes := []string{"get", "set", "is", "has", "can", "should"}
	for _, prefix := range commonPrefixes {
		if strings.HasPrefix(strings.ToLower(param), prefix) {
			features["prefix_"+prefix] = 1.0
		}
	}
	
	commonSuffixes := []string{"id", "name", "type", "key", "token", "code"}
	for _, suffix := range commonSuffixes {
		if strings.HasSuffix(strings.ToLower(param), suffix) {
			features["suffix_"+suffix] = 1.0
		}
	}
	
	return features
}

func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func isCamelCase(s string) bool {
	if len(s) < 2 {
		return false
	}
	hasLower := false
	hasUpper := false
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			hasLower = true
		}
		if r >= 'A' && r <= 'Z' {
			hasUpper = true
		}
	}
	return hasLower && hasUpper
}

func hasNumbers(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

// Initialization functions

func initializePatterns() map[string]*regexp.Regexp {
	patterns := map[string]string{
		"email":    `[\w\.-]+@[\w\.-]+\.\w+`,
		"url":      `https?://[\w\.-]+(?::\d+)?(?:/[^\s]*)?`,
		"api_key":  `[a-zA-Z0-9]{32,}`,
		"jwt":      `eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`,
		"base64":   `[A-Za-z0-9+/]{4,}={0,2}`,
		"hex":      `[0-9a-fA-F]{8,}`,
		"uuid":     `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
	}

	compiled := make(map[string]*regexp.Regexp)
	for name, pattern := range patterns {
		if re, err := regexp.Compile(pattern); err == nil {
			compiled[name] = re
		}
	}

	return compiled
}

func initializeHeuristicRules() []HeuristicRule {
	return []HeuristicRule{
		{
			Name: "admin_panel",
			Condition: func(r FuzzResult) bool {
				return strings.Contains(r.URL, "admin") && r.StatusCode == 401
			},
			Generate: func(r FuzzResult) []string {
				return []string{
					"admin/login", "admin/dashboard", "administrator",
					"wp-admin", "phpmyadmin", "adminer",
				}
			},
		},
		{
			Name: "api_versioning",
			Condition: func(r FuzzResult) bool {
				return strings.Contains(r.URL, "/api/") && r.StatusCode == 200
			},
			Generate: func(r FuzzResult) []string {
				paths := []string{}
				for i := 1; i <= 5; i++ {
					paths = append(paths, fmt.Sprintf("api/v%d", i))
					paths = append(paths, fmt.Sprintf("v%d", i))
				}
				return paths
			},
		},
		{
			Name: "backup_files",
			Condition: func(r FuzzResult) bool {
				return r.StatusCode == 200 && strings.HasSuffix(r.URL, ".php")
			},
			Generate: func(r FuzzResult) []string {
				base := strings.TrimSuffix(r.URL, ".php")
				return []string{
					base + ".bak",
					base + ".backup",
					base + ".old",
					base + ".orig",
					base + "~",
					"." + base + ".swp",
				}
			},
		},
	}
}

func initializeModel() *SimpleModel {
	// Pre-trained weights (in reality, these would be learned)
	return &SimpleModel{
		weights: map[string]float64{
			"length":           -0.1,
			"has_underscore":   0.3,
			"is_camelcase":     0.2,
			"suffix_id":        0.8,
			"suffix_name":      0.7,
			"suffix_key":       0.9,
			"suffix_token":     0.9,
			"prefix_get":       0.4,
			"url_has_api":      0.6,
			"url_path_depth":   0.2,
		},
		bias: -0.5,
	}
}

func initializeFeatureExtractor() *FeatureExtractor {
	return &FeatureExtractor{
		features: map[string]func(*url.URL)float64{
			"has_api": func(u *url.URL) float64 {
				if strings.Contains(u.Host, "api") || strings.Contains(u.Path, "/api/") {
					return 1.0
				}
				return 0.0
			},
			"path_depth": func(u *url.URL) float64 {
				parts := strings.Split(strings.Trim(u.Path, "/"), "/")
				return float64(len(parts)) / 10.0
			},
			"has_version": func(u *url.URL) float64 {
				if regexp.MustCompile(`/v\d+/`).MatchString(u.Path) {
					return 1.0
				}
				return 0.0
			},
		},
	}
}