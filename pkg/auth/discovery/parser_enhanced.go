// internal/discovery/parser_enhanced.go
package discovery

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// TargetType represents the type of target for parsing
type TargetType string

const (
	TargetTypeDomain  TargetType = "domain"
	TargetTypeEmail   TargetType = "email"
	TargetTypeURL     TargetType = "url"
	TargetTypeIP      TargetType = "ip"
	TargetTypeCompany TargetType = "company"
	TargetTypeIPRange TargetType = "ip_range"
	TargetTypeUnknown TargetType = "unknown"
)

// Target represents a parsed target with metadata
type Target struct {
	Raw        string            `json:"raw"`
	Type       TargetType        `json:"type"`
	Value      string            `json:"value"`
	Confidence float64           `json:"confidence"`
	Metadata   map[string]string `json:"metadata"`
}

// EnhancedTargetParser provides comprehensive target classification
type EnhancedTargetParser struct {
	logger     *logger.Logger
	patterns   map[TargetType]*regexp.Regexp
	validators map[TargetType]ValidatorFunc
	enrichers  map[TargetType]EnricherFunc
}

type ValidatorFunc func(string) bool
type EnricherFunc func(string, *Target) error

// NewEnhancedTargetParser creates an enhanced parser
func NewEnhancedTargetParser(logger *logger.Logger) *EnhancedTargetParser {
	parser := &EnhancedTargetParser{
		logger:     logger,
		patterns:   make(map[TargetType]*regexp.Regexp),
		validators: make(map[TargetType]ValidatorFunc),
		enrichers:  make(map[TargetType]EnricherFunc),
	}

	parser.initializePatterns()
	parser.initializeValidators()
	parser.initializeEnrichers()

	return parser
}

// ParseTarget performs comprehensive target classification
func (p *EnhancedTargetParser) ParseTarget(input string) *Target {
	input = strings.TrimSpace(input)

	// Create base target
	target := &Target{
		Raw:        input,
		Type:       TargetTypeUnknown,
		Value:      input,
		Confidence: 0.0,
		Metadata:   make(map[string]string),
	}

	// Try each classifier in order of specificity
	classifiers := []struct {
		targetType TargetType
		classifier func(string, *Target) bool
	}{
		{TargetTypeEmail, p.classifyEmail},
		{TargetTypeURL, p.classifyURL},
		{TargetTypeIPRange, p.classifyIPRange},
		{TargetTypeIP, p.classifyIP},
		{TargetTypeDomain, p.classifyDomain},
		{TargetTypeCompany, p.classifyCompany},
	}

	for _, c := range classifiers {
		if c.classifier(input, target) {
			target.Type = c.targetType

			// Run validator if available
			if validator, exists := p.validators[c.targetType]; exists {
				if !validator(target.Value) {
					target.Confidence *= 0.5 // Reduce confidence if validation fails
				}
			}

			// Run enricher if available
			if enricher, exists := p.enrichers[c.targetType]; exists {
				enricher(input, target)
			}

			break
		}
	}

	// Log classification result
	p.logger.Debug("Target classified",
		"input", input,
		"type", target.Type,
		"confidence", target.Confidence,
		"metadata", target.Metadata)

	return target
}

// initializePatterns sets up regex patterns for classification
func (p *EnhancedTargetParser) initializePatterns() {
	p.patterns[TargetTypeEmail] = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	p.patterns[TargetTypeIP] = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	p.patterns[TargetTypeIPRange] = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$`)
	p.patterns[TargetTypeDomain] = regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
	p.patterns[TargetTypeURL] = regexp.MustCompile(`^https?://`)
}

// initializeValidators sets up validation functions
func (p *EnhancedTargetParser) initializeValidators() {
	// Add validators for each type
}

// initializeEnrichers sets up enrichment functions
func (p *EnhancedTargetParser) initializeEnrichers() {
	// Add enrichers for each type
}

// Classification methods
func (p *EnhancedTargetParser) classifyEmail(input string, target *Target) bool {
	if p.patterns[TargetTypeEmail].MatchString(input) {
		target.Type = TargetTypeEmail
		target.Value = strings.ToLower(input)
		target.Confidence = 1.0
		
		// Extract domain from email
		parts := strings.Split(input, "@")
		if len(parts) == 2 {
			target.Metadata["domain"] = parts[1]
			target.Metadata["username"] = parts[0]
		}
		return true
	}
	return false
}

func (p *EnhancedTargetParser) classifyURL(input string, target *Target) bool {
	if p.patterns[TargetTypeURL].MatchString(input) {
		target.Type = TargetTypeURL
		target.Value = input
		target.Confidence = 1.0
		
		// Parse URL for metadata
		if u, err := url.Parse(input); err == nil {
			target.Metadata["scheme"] = u.Scheme
			target.Metadata["host"] = u.Host
			target.Metadata["path"] = u.Path
		}
		return true
	}
	return false
}

func (p *EnhancedTargetParser) classifyIPRange(input string, target *Target) bool {
	if p.patterns[TargetTypeIPRange].MatchString(input) {
		target.Type = TargetTypeIPRange
		target.Value = input
		target.Confidence = 1.0
		
		// Extract network and CIDR
		parts := strings.Split(input, "/")
		if len(parts) == 2 {
			target.Metadata["network"] = parts[0]
			target.Metadata["cidr"] = parts[1]
		}
		return true
	}
	return false
}

func (p *EnhancedTargetParser) classifyIP(input string, target *Target) bool {
	if p.patterns[TargetTypeIP].MatchString(input) {
		// Validate IP octets
		parts := strings.Split(input, ".")
		valid := true
		for _, part := range parts {
			if n, err := strconv.Atoi(part); err != nil || n > 255 {
				valid = false
				break
			}
		}
		
		if valid {
			target.Type = TargetTypeIP
			target.Value = input
			target.Confidence = 1.0
			return true
		}
	}
	return false
}

func (p *EnhancedTargetParser) classifyDomain(input string, target *Target) bool {
	// Remove protocol if present
	cleaned := strings.TrimPrefix(strings.TrimPrefix(input, "https://"), "http://")
	cleaned = strings.Split(cleaned, "/")[0] // Remove path
	
	if p.patterns[TargetTypeDomain].MatchString(cleaned) {
		target.Type = TargetTypeDomain
		target.Value = cleaned
		target.Confidence = 0.9
		return true
	}
	return false
}

func (p *EnhancedTargetParser) classifyCompany(input string, target *Target) bool {
	// If nothing else matched and it's text, assume company name
	if len(input) > 2 && !strings.Contains(input, "/") && !strings.Contains(input, ".") {
		target.Type = TargetTypeCompany
		target.Value = input
		target.Confidence = 0.7
		return true
	}
	return false
}
