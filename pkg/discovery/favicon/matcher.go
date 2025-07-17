package favicon

import (
	"fmt"
	"regexp"
	"strings"
)

// TechnologyMatcher provides advanced technology identification
type TechnologyMatcher struct {
	patterns map[string]TechnologyPattern
}

// TechnologyPattern defines rules for identifying technologies
type TechnologyPattern struct {
	Name        string         `json:"name"`
	Category    string         `json:"category"`
	Confidence  float64        `json:"confidence"`
	Rules       []MatchingRule `json:"rules"`
	Description string         `json:"description"`
}

// MatchingRule defines a single matching rule
type MatchingRule struct {
	Type     string  `json:"type"`     // "hash", "size", "content_type", "url_pattern"
	Pattern  string  `json:"pattern"`  // The pattern to match
	Weight   float64 `json:"weight"`   // Weight in final confidence calculation
	Required bool    `json:"required"` // Whether this rule must match
}

// NewTechnologyMatcher creates a new technology matcher
func NewTechnologyMatcher() *TechnologyMatcher {
	matcher := &TechnologyMatcher{
		patterns: make(map[string]TechnologyPattern),
	}

	matcher.loadDefaultPatterns()
	return matcher
}

// AnalyzeFavicon analyzes a favicon using pattern matching
func (tm *TechnologyMatcher) AnalyzeFavicon(favicon *HashResult) []TechnologyMatch {
	var matches []TechnologyMatch

	for _, pattern := range tm.patterns {
		confidence := tm.calculatePatternMatch(favicon, pattern)
		if confidence > 0.1 { // Minimum threshold
			match := TechnologyMatch{
				Technology: pattern.Name,
				Category:   pattern.Category,
				Confidence: confidence,
				Hash:       favicon.MMH3, // Use MMH3 as primary hash
				HashType:   "mmh3",
				Source:     "pattern",
			}
			matches = append(matches, match)
		}
	}

	return matches
}

// calculatePatternMatch calculates confidence based on pattern rules
func (tm *TechnologyMatcher) calculatePatternMatch(favicon *HashResult, pattern TechnologyPattern) float64 {
	var totalWeight float64
	var matchedWeight float64
	var requiredMatches int
	var requiredTotal int

	for _, rule := range pattern.Rules {
		totalWeight += rule.Weight

		if rule.Required {
			requiredTotal++
		}

		matched := tm.evaluateRule(favicon, rule)
		if matched {
			matchedWeight += rule.Weight
			if rule.Required {
				requiredMatches++
			}
		}
	}

	// All required rules must match
	if requiredTotal > 0 && requiredMatches < requiredTotal {
		return 0.0
	}

	// Calculate base confidence from weight ratio
	confidence := matchedWeight / totalWeight * pattern.Confidence

	// Apply bonuses for multiple matches
	if len(pattern.Rules) > 1 && matchedWeight > 0 {
		bonus := float64(requiredMatches) / float64(len(pattern.Rules)) * 0.2
		confidence += bonus
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// evaluateRule evaluates a single matching rule
func (tm *TechnologyMatcher) evaluateRule(favicon *HashResult, rule MatchingRule) bool {
	switch rule.Type {
	case "hash":
		return tm.matchHash(favicon, rule.Pattern)
	case "size":
		return tm.matchSize(favicon, rule.Pattern)
	case "content_type":
		return tm.matchContentType(favicon, rule.Pattern)
	case "url_pattern":
		return tm.matchURLPattern(favicon, rule.Pattern)
	default:
		return false
	}
}

// matchHash checks if any favicon hash matches the pattern
func (tm *TechnologyMatcher) matchHash(favicon *HashResult, pattern string) bool {
	hashes := []string{
		favicon.MD5,
		favicon.SHA256,
		favicon.MMH3,
		favicon.MMH3Signed,
	}

	for _, hash := range hashes {
		if hash == pattern {
			return true
		}
	}

	return false
}

// matchSize checks if favicon size matches the pattern
func (tm *TechnologyMatcher) matchSize(favicon *HashResult, pattern string) bool {
	// Pattern format: "min-max" or "exact"
	if strings.Contains(pattern, "-") {
		parts := strings.Split(pattern, "-")
		if len(parts) == 2 {
			// Range matching (simplified)
			return true // TODO: Implement proper range matching
		}
	} else {
		// Exact size matching (simplified)
		return true // TODO: Implement exact size matching
	}

	return false
}

// matchContentType checks if content type matches the pattern
func (tm *TechnologyMatcher) matchContentType(favicon *HashResult, pattern string) bool {
	if favicon.ContentType == "" {
		return false
	}

	// Use regex for flexible matching
	re, err := regexp.Compile(pattern)
	if err != nil {
		return strings.Contains(favicon.ContentType, pattern)
	}

	return re.MatchString(favicon.ContentType)
}

// matchURLPattern checks if favicon URL matches the pattern
func (tm *TechnologyMatcher) matchURLPattern(favicon *HashResult, pattern string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return strings.Contains(favicon.URL, pattern)
	}

	return re.MatchString(favicon.URL)
}

// loadDefaultPatterns loads default technology patterns
func (tm *TechnologyMatcher) loadDefaultPatterns() {
	defaultPatterns := []TechnologyPattern{
		{
			Name:        "WordPress",
			Category:    "cms",
			Confidence:  0.8,
			Description: "WordPress content management system",
			Rules: []MatchingRule{
				{Type: "url_pattern", Pattern: "/wp-content/", Weight: 0.6, Required: false},
				{Type: "url_pattern", Pattern: "/wp-admin/", Weight: 0.4, Required: false},
				{Type: "size", Pattern: "512-4096", Weight: 0.3, Required: false},
			},
		},
		{
			Name:        "Apache",
			Category:    "web-server",
			Confidence:  0.7,
			Description: "Apache HTTP Server",
			Rules: []MatchingRule{
				{Type: "url_pattern", Pattern: "/icons/apache_", Weight: 0.8, Required: false},
				{Type: "content_type", Pattern: "image/x-icon", Weight: 0.2, Required: false},
			},
		},
		{
			Name:        "Nginx",
			Category:    "web-server",
			Confidence:  0.7,
			Description: "Nginx web server",
			Rules: []MatchingRule{
				{Type: "url_pattern", Pattern: "/nginx", Weight: 0.6, Required: false},
				{Type: "size", Pattern: "16-64", Weight: 0.4, Required: false},
			},
		},
		{
			Name:        "Django",
			Category:    "framework",
			Confidence:  0.75,
			Description: "Django web framework",
			Rules: []MatchingRule{
				{Type: "url_pattern", Pattern: "/static/admin/", Weight: 0.7, Required: false},
				{Type: "url_pattern", Pattern: "django", Weight: 0.3, Required: false},
			},
		},
		{
			Name:        "Laravel",
			Category:    "framework",
			Confidence:  0.75,
			Description: "Laravel PHP framework",
			Rules: []MatchingRule{
				{Type: "url_pattern", Pattern: "/laravel", Weight: 0.6, Required: false},
				{Type: "url_pattern", Pattern: "/public/", Weight: 0.4, Required: false},
			},
		},
		{
			Name:        "Jenkins",
			Category:    "ci-cd",
			Confidence:  0.9,
			Description: "Jenkins automation server",
			Rules: []MatchingRule{
				{Type: "hash", Pattern: "-766957629", Weight: 0.9, Required: true},
				{Type: "url_pattern", Pattern: "/jenkins/", Weight: 0.1, Required: false},
			},
		},
		{
			Name:        "GitLab",
			Category:    "development",
			Confidence:  0.9,
			Description: "GitLab version control",
			Rules: []MatchingRule{
				{Type: "hash", Pattern: "81586312", Weight: 0.9, Required: true},
				{Type: "url_pattern", Pattern: "gitlab", Weight: 0.1, Required: false},
			},
		},
		{
			Name:        "Grafana",
			Category:    "monitoring",
			Confidence:  0.85,
			Description: "Grafana monitoring dashboard",
			Rules: []MatchingRule{
				{Type: "hash", Pattern: "-1255347784", Weight: 0.9, Required: true},
				{Type: "url_pattern", Pattern: "grafana", Weight: 0.1, Required: false},
			},
		},
		{
			Name:        "Joomla",
			Category:    "cms",
			Confidence:  0.8,
			Description: "Joomla content management system",
			Rules: []MatchingRule{
				{Type: "url_pattern", Pattern: "/administrator/", Weight: 0.6, Required: false},
				{Type: "url_pattern", Pattern: "joomla", Weight: 0.4, Required: false},
			},
		},
		{
			Name:        "Drupal",
			Category:    "cms",
			Confidence:  0.8,
			Description: "Drupal content management system",
			Rules: []MatchingRule{
				{Type: "url_pattern", Pattern: "/sites/default/", Weight: 0.6, Required: false},
				{Type: "url_pattern", Pattern: "drupal", Weight: 0.4, Required: false},
			},
		},
		{
			Name:        "phpMyAdmin",
			Category:    "database",
			Confidence:  0.85,
			Description: "phpMyAdmin MySQL interface",
			Rules: []MatchingRule{
				{Type: "url_pattern", Pattern: "phpmyadmin", Weight: 0.7, Required: false},
				{Type: "url_pattern", Pattern: "/pma/", Weight: 0.3, Required: false},
			},
		},
		{
			Name:        "Shopify",
			Category:    "ecommerce",
			Confidence:  0.85,
			Description: "Shopify e-commerce platform",
			Rules: []MatchingRule{
				{Type: "url_pattern", Pattern: "shopify", Weight: 0.6, Required: false},
				{Type: "url_pattern", Pattern: "myshopify.com", Weight: 0.4, Required: false},
			},
		},
		{
			Name:        "Magento",
			Category:    "ecommerce",
			Confidence:  0.85,
			Description: "Magento e-commerce platform",
			Rules: []MatchingRule{
				{Type: "url_pattern", Pattern: "magento", Weight: 0.6, Required: false},
				{Type: "url_pattern", Pattern: "/skin/", Weight: 0.4, Required: false},
			},
		},
		{
			Name:        "Fortinet",
			Category:    "security",
			Confidence:  0.95,
			Description: "Fortinet security appliance",
			Rules: []MatchingRule{
				{Type: "hash", Pattern: "2128322903", Weight: 0.95, Required: true},
				{Type: "url_pattern", Pattern: "fortinet", Weight: 0.05, Required: false},
			},
		},
		{
			Name:        "Palo Alto Networks",
			Category:    "security",
			Confidence:  0.95,
			Description: "Palo Alto Networks firewall",
			Rules: []MatchingRule{
				{Type: "hash", Pattern: "743365239", Weight: 0.95, Required: true},
			},
		},
	}

	// Add all patterns to the matcher
	for _, pattern := range defaultPatterns {
		tm.patterns[pattern.Name] = pattern
	}
}

// AddPattern adds a custom technology pattern
func (tm *TechnologyMatcher) AddPattern(pattern TechnologyPattern) {
	tm.patterns[pattern.Name] = pattern
}

// GetPatterns returns all loaded patterns
func (tm *TechnologyMatcher) GetPatterns() map[string]TechnologyPattern {
	return tm.patterns
}

// AnalyzeMultipleFavicons analyzes multiple favicons and provides aggregated results
func (tm *TechnologyMatcher) AnalyzeMultipleFavicons(favicons []*HashResult) []TechnologyMatch {
	technologyScores := make(map[string]float64)
	technologyDetails := make(map[string]TechnologyMatch)

	// Analyze each favicon
	for _, favicon := range favicons {
		matches := tm.AnalyzeFavicon(favicon)

		for _, match := range matches {
			key := match.Technology

			// Accumulate confidence scores
			if existing, exists := technologyScores[key]; exists {
				// Use maximum confidence for multiple matches
				if match.Confidence > existing {
					technologyScores[key] = match.Confidence
					technologyDetails[key] = match
				}
			} else {
				technologyScores[key] = match.Confidence
				technologyDetails[key] = match
			}
		}
	}

	// Convert back to slice
	var finalMatches []TechnologyMatch
	for _, match := range technologyDetails {
		finalMatches = append(finalMatches, match)
	}

	return finalMatches
}

// ValidatePattern validates a technology pattern
func (tm *TechnologyMatcher) ValidatePattern(pattern TechnologyPattern) error {
	if pattern.Name == "" {
		return fmt.Errorf("pattern name is required")
	}

	if pattern.Category == "" {
		return fmt.Errorf("pattern category is required")
	}

	if pattern.Confidence <= 0 || pattern.Confidence > 1.0 {
		return fmt.Errorf("confidence must be between 0 and 1.0")
	}

	if len(pattern.Rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}

	// Validate each rule
	for i, rule := range pattern.Rules {
		if rule.Type == "" {
			return fmt.Errorf("rule %d: type is required", i)
		}

		if rule.Pattern == "" {
			return fmt.Errorf("rule %d: pattern is required", i)
		}

		if rule.Weight <= 0 {
			return fmt.Errorf("rule %d: weight must be positive", i)
		}

		validTypes := []string{"hash", "size", "content_type", "url_pattern"}
		valid := false
		for _, validType := range validTypes {
			if rule.Type == validType {
				valid = true
				break
			}
		}

		if !valid {
			return fmt.Errorf("rule %d: invalid type '%s'", i, rule.Type)
		}
	}

	return nil
}

// GetTechnologyCategories returns all unique technology categories
func (tm *TechnologyMatcher) GetTechnologyCategories() []string {
	categories := make(map[string]bool)

	for _, pattern := range tm.patterns {
		categories[pattern.Category] = true
	}

	var result []string
	for category := range categories {
		result = append(result, category)
	}

	return result
}

// SearchPatterns searches for patterns by name or category
func (tm *TechnologyMatcher) SearchPatterns(query string) []TechnologyPattern {
	var results []TechnologyPattern
	query = strings.ToLower(query)

	for _, pattern := range tm.patterns {
		if strings.Contains(strings.ToLower(pattern.Name), query) ||
			strings.Contains(strings.ToLower(pattern.Category), query) ||
			strings.Contains(strings.ToLower(pattern.Description), query) {
			results = append(results, pattern)
		}
	}

	return results
}
