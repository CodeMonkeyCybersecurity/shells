package discovery

import (
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// TargetParser parses and classifies input targets
type TargetParser struct {
	patterns map[TargetType]*regexp.Regexp
}

// NewTargetParser creates a new target parser
func NewTargetParser() *TargetParser {
	return &TargetParser{
		patterns: map[TargetType]*regexp.Regexp{
			TargetTypeEmail:   regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
			TargetTypeDomain:  regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`),
			TargetTypeIP:      regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`),
			TargetTypeIPRange: regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$`),
			TargetTypeURL:     regexp.MustCompile(`^https?:\/\/[^\s/$.?#].[^\s]*$`),
		},
	}
}

// ParseTarget parses and classifies an input target
func (p *TargetParser) ParseTarget(input string) *Target {
	input = strings.TrimSpace(input)
	if input == "" {
		return &Target{
			Raw:        input,
			Type:       TargetTypeUnknown,
			Value:      input,
			Metadata:   make(map[string]string),
			Confidence: 0.0,
			CreatedAt:  time.Now(),
		}
	}

	target := &Target{
		Raw:       input,
		Metadata:  make(map[string]string),
		CreatedAt: time.Now(),
	}

	// Try to parse as different target types
	if targetType, confidence := p.classifyTarget(input); targetType != TargetTypeUnknown {
		target.Type = targetType
		target.Confidence = confidence
		target.Value = p.normalizeTarget(input, targetType)
		p.extractMetadata(target)
	} else {
		// Try to classify as company name
		if p.isCompanyName(input) {
			target.Type = TargetTypeCompany
			target.Value = p.normalizeCompanyName(input)
			target.Confidence = 0.7
		} else {
			target.Type = TargetTypeUnknown
			target.Value = input
			target.Confidence = 0.0
		}
	}

	return target
}

// classifyTarget classifies the target type based on patterns
func (p *TargetParser) classifyTarget(input string) (TargetType, float64) {
	// Check URL first (most specific)
	if p.patterns[TargetTypeURL].MatchString(input) {
		return TargetTypeURL, 0.95
	}

	// Check email
	if p.patterns[TargetTypeEmail].MatchString(input) {
		return TargetTypeEmail, 0.9
	}

	// Check IP range
	if p.patterns[TargetTypeIPRange].MatchString(input) {
		return TargetTypeIPRange, 0.95
	}

	// Check IP
	if p.patterns[TargetTypeIP].MatchString(input) {
		// Validate it's actually a valid IP
		if net.ParseIP(input) != nil {
			return TargetTypeIP, 0.95
		}
	}

	// Check domain
	if p.patterns[TargetTypeDomain].MatchString(input) {
		// Additional validation for domain
		if p.isValidDomain(input) {
			return TargetTypeDomain, 0.9
		}
	}

	return TargetTypeUnknown, 0.0
}

// isValidDomain performs additional domain validation
func (p *TargetParser) isValidDomain(domain string) bool {
	// Check length
	if len(domain) > 253 {
		return false
	}

	// Check if it has at least one dot
	if !strings.Contains(domain, ".") {
		return false
	}

	// Check each label
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		// Label cannot start or end with hyphen
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}

	return true
}

// isCompanyName determines if input looks like a company name
func (p *TargetParser) isCompanyName(input string) bool {
	// Basic heuristics for company names
	
	// Must contain at least one letter
	hasLetter := false
	for _, r := range input {
		if unicode.IsLetter(r) {
			hasLetter = true
			break
		}
	}
	if !hasLetter {
		return false
	}

	// Common company indicators
	companyIndicators := []string{
		"inc", "corp", "corporation", "company", "co", "ltd", "llc",
		"limited", "enterprises", "group", "solutions", "systems",
		"technologies", "tech", "labs", "software", "services",
	}

	lowerInput := strings.ToLower(input)
	for _, indicator := range companyIndicators {
		if strings.Contains(lowerInput, indicator) {
			return true
		}
	}

	// If it has spaces and multiple words, likely a company name
	words := strings.Fields(input)
	if len(words) >= 2 && len(words) <= 10 {
		// Check if words are reasonable length
		for _, word := range words {
			if len(word) > 20 {
				return false
			}
		}
		return true
	}

	return false
}

// normalizeTarget normalizes the target value based on its type
func (p *TargetParser) normalizeTarget(input string, targetType TargetType) string {
	switch targetType {
	case TargetTypeDomain:
		return strings.ToLower(strings.TrimSpace(input))
	case TargetTypeEmail:
		return strings.ToLower(strings.TrimSpace(input))
	case TargetTypeURL:
		return strings.TrimSpace(input)
	case TargetTypeIP:
		return strings.TrimSpace(input)
	case TargetTypeIPRange:
		return strings.TrimSpace(input)
	default:
		return strings.TrimSpace(input)
	}
}

// normalizeCompanyName normalizes company name
func (p *TargetParser) normalizeCompanyName(input string) string {
	// Basic normalization
	name := strings.TrimSpace(input)
	
	// Remove quotes if present
	if strings.HasPrefix(name, "\"") && strings.HasSuffix(name, "\"") {
		name = name[1 : len(name)-1]
	}
	if strings.HasPrefix(name, "'") && strings.HasSuffix(name, "'") {
		name = name[1 : len(name)-1]
	}
	
	return name
}

// extractMetadata extracts metadata from the target
func (p *TargetParser) extractMetadata(target *Target) {
	switch target.Type {
	case TargetTypeEmail:
		parts := strings.Split(target.Value, "@")
		if len(parts) == 2 {
			target.Metadata["username"] = parts[0]
			target.Metadata["domain"] = parts[1]
		}
	case TargetTypeURL:
		if u, err := url.Parse(target.Value); err == nil {
			target.Metadata["scheme"] = u.Scheme
			target.Metadata["host"] = u.Host
			target.Metadata["path"] = u.Path
			if u.Port() != "" {
				target.Metadata["port"] = u.Port()
			}
		}
	case TargetTypeIPRange:
		_, network, err := net.ParseCIDR(target.Value)
		if err == nil {
			target.Metadata["network"] = network.String()
			target.Metadata["mask"] = network.Mask.String()
		}
	case TargetTypeDomain:
		parts := strings.Split(target.Value, ".")
		if len(parts) >= 2 {
			target.Metadata["tld"] = parts[len(parts)-1]
			target.Metadata["sld"] = parts[len(parts)-2]
			if len(parts) > 2 {
				target.Metadata["subdomain"] = strings.Join(parts[:len(parts)-2], ".")
			}
		}
	}
}

// GetDomainFromTarget extracts domain from any target type
func (p *TargetParser) GetDomainFromTarget(target *Target) string {
	switch target.Type {
	case TargetTypeDomain:
		return target.Value
	case TargetTypeEmail:
		if domain, exists := target.Metadata["domain"]; exists {
			return domain
		}
	case TargetTypeURL:
		if host, exists := target.Metadata["host"]; exists {
			// Remove port if present
			if strings.Contains(host, ":") {
				host = strings.Split(host, ":")[0]
			}
			return host
		}
	case TargetTypeIP:
		// Would need reverse DNS lookup
		return ""
	}
	return ""
}

// GetSearchTermsFromTarget generates search terms for the target
func (p *TargetParser) GetSearchTermsFromTarget(target *Target) []string {
	var terms []string
	
	switch target.Type {
	case TargetTypeCompany:
		terms = append(terms, target.Value)
		// Add variations
		terms = append(terms, "\""+target.Value+"\"")
		// Remove common suffixes for additional searches
		cleanName := p.removeCompanySuffixes(target.Value)
		if cleanName != target.Value {
			terms = append(terms, cleanName)
		}
	case TargetTypeDomain:
		terms = append(terms, target.Value)
		terms = append(terms, "site:"+target.Value)
		// Add root domain if subdomain
		if subdomain, exists := target.Metadata["subdomain"]; exists && subdomain != "" {
			rootDomain := target.Metadata["sld"] + "." + target.Metadata["tld"]
			terms = append(terms, rootDomain)
		}
	case TargetTypeEmail:
		if domain, exists := target.Metadata["domain"]; exists {
			terms = append(terms, domain)
			terms = append(terms, "site:"+domain)
		}
	case TargetTypeURL:
		if host, exists := target.Metadata["host"]; exists {
			terms = append(terms, host)
			terms = append(terms, "site:"+host)
		}
	}
	
	return terms
}

// removeCompanySuffixes removes common company suffixes
func (p *TargetParser) removeCompanySuffixes(name string) string {
	suffixes := []string{
		" Inc.", " Inc", " Corporation", " Corp.", " Corp",
		" Company", " Co.", " Co", " Ltd.", " Ltd", " Limited",
		" LLC", " L.L.C.", " LLP", " L.L.P.", " Enterprises",
		" Group", " Solutions", " Systems", " Technologies",
		" Tech", " Labs", " Software", " Services",
	}
	
	for _, suffix := range suffixes {
		if strings.HasSuffix(name, suffix) {
			return strings.TrimSpace(name[:len(name)-len(suffix)])
		}
	}
	
	return name
}

// IsHighValueAsset determines if an asset is high value
func IsHighValueAsset(asset *Asset) bool {
	// Check asset type
	switch asset.Type {
	case AssetTypeLogin, AssetTypeAdmin, AssetTypePayment, AssetTypeAPI:
		return true
	}

	// Check URL/title for high-value keywords
	checkText := strings.ToLower(asset.Value + " " + asset.Title)
	
	for _, indicators := range HighValueIndicators {
		for _, indicator := range indicators {
			if strings.Contains(checkText, indicator) {
				return true
			}
		}
	}

	// Check technology stack for high-value technologies
	for _, tech := range asset.Technology {
		lowerTech := strings.ToLower(tech)
		if strings.Contains(lowerTech, "admin") ||
		   strings.Contains(lowerTech, "management") ||
		   strings.Contains(lowerTech, "dashboard") ||
		   strings.Contains(lowerTech, "api") {
			return true
		}
	}

	return false
}

// CalculateAssetPriority calculates priority for an asset
func CalculateAssetPriority(asset *Asset) AssetPriority {
	if IsHighValueAsset(asset) {
		return PriorityCritical
	}

	// Check for medium priority indicators
	checkText := strings.ToLower(asset.Value + " " + asset.Title)
	mediumIndicators := []string{
		"www", "mail", "ftp", "ssh", "vpn", "remote",
		"portal", "app", "api", "service", "dev", "test",
	}

	for _, indicator := range mediumIndicators {
		if strings.Contains(checkText, indicator) {
			return PriorityHigh
		}
	}

	// Default based on asset type
	switch asset.Type {
	case AssetTypeDomain, AssetTypeSubdomain:
		return PriorityMedium
	case AssetTypeURL, AssetTypeEndpoint:
		return PriorityMedium
	case AssetTypeService, AssetTypePort:
		return PriorityMedium
	default:
		return PriorityLow
	}
}