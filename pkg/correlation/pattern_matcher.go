// pkg/correlation/pattern_matcher.go
package correlation

import (
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// PatternMatcher extracts and matches patterns across findings
type PatternMatcher struct {
	domainPatterns    []DomainPattern
	endpointPatterns  []EndpointPattern
	parameterPatterns []ParameterPattern
}

// DomainPattern represents a pattern found in domain names
type DomainPattern struct {
	Pattern    string
	Regex      *regexp.Regexp
	Type       string
	Examples   []string
	Confidence float64
}

// EndpointPattern represents a pattern found in endpoints
type EndpointPattern struct {
	Pattern    string
	Regex      *regexp.Regexp
	Type       string
	Examples   []string
	Confidence float64
}

// ParameterPattern represents a pattern found in parameters
type ParameterPattern struct {
	Pattern    string
	Type       string
	Examples   []string
	Confidence float64
}

// NewPatternMatcher creates a new pattern matcher
func NewPatternMatcher() *PatternMatcher {
	return &PatternMatcher{
		domainPatterns:    []DomainPattern{},
		endpointPatterns:  []EndpointPattern{},
		parameterPatterns: []ParameterPattern{},
	}
}

// ExtractDomainPatterns extracts domain patterns from findings
func (pm *PatternMatcher) ExtractDomainPatterns(findings []types.Finding) []DomainPattern {
	var patterns []DomainPattern
	domainMap := make(map[string][]string)

	// Collect domains from findings
	for _, finding := range findings {
		if domain, ok := finding.Metadata["domain"].(string); ok {
			key := pm.identifyDomainPattern(domain)
			domainMap[key] = append(domainMap[key], domain)
		}
	}

	// Create patterns from grouped domains
	for patternKey, domains := range domainMap {
		if len(domains) >= 2 { // Only patterns with multiple examples
			pattern := DomainPattern{
				Pattern:    patternKey,
				Type:       pm.classifyDomainPattern(patternKey),
				Examples:   domains,
				Confidence: float64(len(domains)) / 10.0, // Simple confidence calculation
			}
			if pattern.Confidence > 1.0 {
				pattern.Confidence = 1.0
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

// ExtractEndpointPatterns extracts endpoint patterns from findings
func (pm *PatternMatcher) ExtractEndpointPatterns(findings []types.Finding) []EndpointPattern {
	var patterns []EndpointPattern
	endpointMap := make(map[string][]string)

	// Collect endpoints from findings
	for _, finding := range findings {
		if endpoint, ok := finding.Metadata["endpoint"].(string); ok {
			key := pm.identifyEndpointPattern(endpoint)
			endpointMap[key] = append(endpointMap[key], endpoint)
		}
	}

	// Create patterns from grouped endpoints
	for patternKey, endpoints := range endpointMap {
		if len(endpoints) >= 2 {
			pattern := EndpointPattern{
				Pattern:    patternKey,
				Type:       pm.classifyEndpointPattern(patternKey),
				Examples:   endpoints,
				Confidence: float64(len(endpoints)) / 10.0,
			}
			if pattern.Confidence > 1.0 {
				pattern.Confidence = 1.0
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

// ExtractParameterPatterns extracts parameter patterns from findings
func (pm *PatternMatcher) ExtractParameterPatterns(findings []types.Finding) []ParameterPattern {
	var patterns []ParameterPattern
	paramMap := make(map[string][]string)

	// Collect parameters from findings
	for _, finding := range findings {
		if params, ok := finding.Metadata["parameters"].([]string); ok {
			for _, param := range params {
				key := pm.identifyParameterPattern(param)
				paramMap[key] = append(paramMap[key], param)
			}
		}
	}

	// Create patterns from grouped parameters
	for patternKey, params := range paramMap {
		if len(params) >= 2 {
			pattern := ParameterPattern{
				Pattern:    patternKey,
				Type:       pm.classifyParameterPattern(patternKey),
				Examples:   params,
				Confidence: float64(len(params)) / 10.0,
			}
			if pattern.Confidence > 1.0 {
				pattern.Confidence = 1.0
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

// Helper methods for pattern identification

func (pm *PatternMatcher) identifyDomainPattern(domain string) string {
	// Simple pattern identification
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		// Look for numbered patterns
		if matched, _ := regexp.MatchString(`\d+`, parts[0]); matched {
			return "numbered_subdomain"
		}
		// Look for environment patterns
		if matched, _ := regexp.MatchString(`(dev|test|stage|staging|prod|production)`, parts[0]); matched {
			return "environment_subdomain"
		}
		// Look for region patterns
		if matched, _ := regexp.MatchString(`(us|eu|asia|uk|au|ca)-?(east|west|north|south|central)?-?\d*`, parts[0]); matched {
			return "region_subdomain"
		}
	}
	return "generic_subdomain"
}

func (pm *PatternMatcher) identifyEndpointPattern(endpoint string) string {
	// API patterns
	if matched, _ := regexp.MatchString(`/api/v\d+/`, endpoint); matched {
		return "versioned_api"
	}
	if matched, _ := regexp.MatchString(`/admin/`, endpoint); matched {
		return "admin_endpoint"
	}
	if matched, _ := regexp.MatchString(`/test/`, endpoint); matched {
		return "test_endpoint"
	}
	return "generic_endpoint"
}

func (pm *PatternMatcher) identifyParameterPattern(param string) string {
	// Common parameter patterns
	if matched, _ := regexp.MatchString(`(id|user_id|userId)`, param); matched {
		return "id_parameter"
	}
	if matched, _ := regexp.MatchString(`(token|auth|authorization)`, param); matched {
		return "auth_parameter"
	}
	if matched, _ := regexp.MatchString(`(debug|test|dev)`, param); matched {
		return "debug_parameter"
	}
	return "generic_parameter"
}

func (pm *PatternMatcher) classifyDomainPattern(pattern string) string {
	switch pattern {
	case "numbered_subdomain":
		return "sequential"
	case "environment_subdomain":
		return "environment"
	case "region_subdomain":
		return "regional"
	default:
		return "unknown"
	}
}

func (pm *PatternMatcher) classifyEndpointPattern(pattern string) string {
	switch pattern {
	case "versioned_api":
		return "api_versioning"
	case "admin_endpoint":
		return "administrative"
	case "test_endpoint":
		return "testing"
	default:
		return "unknown"
	}
}

func (pm *PatternMatcher) classifyParameterPattern(pattern string) string {
	switch pattern {
	case "id_parameter":
		return "identifier"
	case "auth_parameter":
		return "authentication"
	case "debug_parameter":
		return "debugging"
	default:
		return "unknown"
	}
}