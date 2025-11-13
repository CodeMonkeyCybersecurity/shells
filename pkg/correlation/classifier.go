// pkg/correlation/classifier.go
package correlation

import (
	"context"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

// IdentifierType represents the type of identifier provided
type IdentifierType string

const (
	TypeEmail       IdentifierType = "email"
	TypeDomain      IdentifierType = "domain"
	TypeIP          IdentifierType = "ip"
	TypeIPRange     IdentifierType = "ip_range"
	TypeCertHash    IdentifierType = "cert_hash"
	TypeCompanyName IdentifierType = "company"
	TypeURL         IdentifierType = "url"
	TypeUnknown     IdentifierType = "unknown"
)

// ClassifiedIdentifier represents a classified input with metadata
type ClassifiedIdentifier struct {
	Raw        string                 `json:"raw"`
	Type       IdentifierType         `json:"type"`
	Value      string                 `json:"value"`      // Normalized value
	Confidence float64                `json:"confidence"` // How sure we are about the classification
	Metadata   map[string]interface{} `json:"metadata"`
	Hints      []string               `json:"hints"` // Additional context that might help
}

// IdentifierClassifier classifies user input into specific types
type IdentifierClassifier struct {
	logger   *logger.Logger
	patterns map[IdentifierType]*regexp.Regexp
}

// NewIdentifierClassifier creates a new classifier instance
func NewIdentifierClassifier(logger *logger.Logger) *IdentifierClassifier {
	classifier := &IdentifierClassifier{
		logger:   logger,
		patterns: make(map[IdentifierType]*regexp.Regexp),
	}

	// Initialize patterns for different identifier types
	classifier.initializePatterns()

	return classifier
}

func (c *IdentifierClassifier) initializePatterns() {
	// Email pattern - comprehensive to catch various formats
	c.patterns[TypeEmail] = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	// IP address pattern (both IPv4 and IPv6)
	c.patterns[TypeIP] = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}$`)

	// IP range pattern (CIDR notation)
	c.patterns[TypeIPRange] = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:3[0-2]|[12]?[0-9])$`)

	// Certificate hash patterns (SHA256, SHA1, MD5)
	c.patterns[TypeCertHash] = regexp.MustCompile(`^([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})$`)

	// Domain pattern - allowing subdomains and TLDs
	c.patterns[TypeDomain] = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

	// URL pattern
	c.patterns[TypeURL] = regexp.MustCompile(`^https?://`)
}

// Classify determines the type of identifier and returns detailed classification
func (c *IdentifierClassifier) Classify(ctx context.Context, input string) (*ClassifiedIdentifier, error) {
	// Clean and normalize input
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("empty identifier provided")
	}

	c.logger.Debug("Classifying identifier",
		"input", input,
		"length", len(input))

	classified := &ClassifiedIdentifier{
		Raw:      input,
		Type:     TypeUnknown,
		Value:    input,
		Metadata: make(map[string]interface{}),
		Hints:    []string{},
	}

	// Try each classification method in order of specificity
	classifiers := []func(string) *ClassifiedIdentifier{
		c.classifyEmail,
		c.classifyURL,
		c.classifyIPRange,
		c.classifyIP,
		c.classifyCertHash,
		c.classifyDomain,
		c.classifyCompanyName, // This should be last as it's the most generic
	}

	for _, classifier := range classifiers {
		if result := classifier(input); result != nil {
			classified = result
			break
		}
	}

	// If still unknown, apply heuristics
	if classified.Type == TypeUnknown {
		classified = c.applyHeuristics(input)
	}

	c.logger.Info("Identifier classified",
		"type", classified.Type,
		"confidence", classified.Confidence,
		"value", classified.Value)

	return classified, nil
}

// classifyEmail checks if input is an email address
func (c *IdentifierClassifier) classifyEmail(input string) *ClassifiedIdentifier {
	// First try standard email parsing
	if addr, err := mail.ParseAddress(input); err == nil {
		email := addr.Address
		parts := strings.Split(email, "@")
		if len(parts) == 2 {
			return &ClassifiedIdentifier{
				Raw:        input,
				Type:       TypeEmail,
				Value:      email,
				Confidence: 0.95,
				Metadata: map[string]interface{}{
					"username":     parts[0],
					"domain":       parts[1],
					"display_name": addr.Name,
				},
				Hints: []string{
					fmt.Sprintf("Email domain: %s", parts[1]),
					"Can search for other employees",
					"Check domain registration",
				},
			}
		}
	}

	// Fallback to regex for simpler formats
	if c.patterns[TypeEmail].MatchString(input) {
		parts := strings.Split(input, "@")
		return &ClassifiedIdentifier{
			Raw:        input,
			Type:       TypeEmail,
			Value:      input,
			Confidence: 0.9,
			Metadata: map[string]interface{}{
				"username": parts[0],
				"domain":   parts[1],
			},
		}
	}

	return nil
}

// classifyIP checks if input is an IP address
func (c *IdentifierClassifier) classifyIP(input string) *ClassifiedIdentifier {
	// Try to parse as IP
	if ip := net.ParseIP(input); ip != nil {
		classified := &ClassifiedIdentifier{
			Raw:        input,
			Type:       TypeIP,
			Value:      ip.String(),
			Confidence: 1.0,
			Metadata: map[string]interface{}{
				"version":    "ipv4",
				"is_private": isPrivateIP(ip),
			},
		}

		// Determine IP version
		if ip.To4() == nil {
			classified.Metadata["version"] = "ipv6"
		}

		// Add hints based on IP type
		if isPrivateIP(ip) {
			classified.Hints = append(classified.Hints, "Private IP address - may need internal access")
		} else {
			classified.Hints = append(classified.Hints, "Public IP - can perform WHOIS lookup")
			classified.Hints = append(classified.Hints, "Check for reverse DNS")
			classified.Hints = append(classified.Hints, "Scan for open ports")
		}

		return classified
	}

	return nil
}

// classifyIPRange checks if input is an IP range in CIDR notation
func (c *IdentifierClassifier) classifyIPRange(input string) *ClassifiedIdentifier {
	if _, network, err := net.ParseCIDR(input); err == nil {
		// Calculate the number of hosts in the range
		ones, bits := network.Mask.Size()
		hostCount := 1 << (bits - ones)

		return &ClassifiedIdentifier{
			Raw:        input,
			Type:       TypeIPRange,
			Value:      network.String(),
			Confidence: 1.0,
			Metadata: map[string]interface{}{
				"network":    network.IP.String(),
				"mask_bits":  ones,
				"host_count": hostCount,
				"first_ip":   network.IP.String(),
				"last_ip":    lastIPInRange(network).String(),
			},
			Hints: []string{
				fmt.Sprintf("Range contains %d possible hosts", hostCount),
				"Can scan for live hosts",
				"Check WHOIS for network owner",
			},
		}
	}

	return nil
}

// classifyCertHash checks if input is a certificate hash
func (c *IdentifierClassifier) classifyCertHash(input string) *ClassifiedIdentifier {
	// Remove common separators from hashes
	cleaned := strings.ReplaceAll(input, ":", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")

	if c.patterns[TypeCertHash].MatchString(cleaned) {
		hashType := "unknown"
		switch len(cleaned) {
		case 32:
			hashType = "md5"
		case 40:
			hashType = "sha1"
		case 64:
			hashType = "sha256"
		}

		return &ClassifiedIdentifier{
			Raw:        input,
			Type:       TypeCertHash,
			Value:      strings.ToLower(cleaned),
			Confidence: 0.95,
			Metadata: map[string]interface{}{
				"hash_type":   hashType,
				"hash_length": len(cleaned),
			},
			Hints: []string{
				"Can search certificate transparency logs",
				"May find associated domains",
				"Check for certificate chain",
			},
		}
	}

	return nil
}

// classifyDomain checks if input is a domain name
func (c *IdentifierClassifier) classifyDomain(input string) *ClassifiedIdentifier {
	// First check if it's a valid domain pattern
	if !c.patterns[TypeDomain].MatchString(input) {
		return nil
	}

	// Must have at least one dot for a valid domain
	if !strings.Contains(input, ".") {
		return nil
	}

	// Try to parse as URL to ensure it's not a URL
	if strings.Contains(input, "://") {
		return nil
	}

	// Extract components
	parts := strings.Split(input, ".")

	classified := &ClassifiedIdentifier{
		Raw:        input,
		Type:       TypeDomain,
		Value:      strings.ToLower(input),
		Confidence: 0.85,
		Metadata: map[string]interface{}{
			"levels": len(parts),
			"tld":    parts[len(parts)-1],
		},
	}

	// Determine if it's a subdomain
	if len(parts) > 2 {
		// Likely a subdomain
		classified.Metadata["is_subdomain"] = true
		classified.Metadata["root_domain"] = strings.Join(parts[len(parts)-2:], ".")
		classified.Hints = append(classified.Hints, fmt.Sprintf("Subdomain of %s", classified.Metadata["root_domain"]))
	}

	// Add relevant hints
	classified.Hints = append(classified.Hints,
		"Perform DNS enumeration",
		"Check WHOIS records",
		"Search certificate transparency",
		"Look for related domains",
	)

	// Boost confidence if domain resolves
	if c.domainResolves(input) {
		classified.Confidence = 0.95
		classified.Metadata["resolves"] = true
	}

	return classified
}

// classifyURL checks if input is a URL
func (c *IdentifierClassifier) classifyURL(input string) *ClassifiedIdentifier {
	if parsed, err := url.Parse(input); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return &ClassifiedIdentifier{
			Raw:        input,
			Type:       TypeURL,
			Value:      input,
			Confidence: 1.0,
			Metadata: map[string]interface{}{
				"scheme": parsed.Scheme,
				"host":   parsed.Host,
				"path":   parsed.Path,
				"port":   parsed.Port(),
			},
			Hints: []string{
				fmt.Sprintf("Target host: %s", parsed.Host),
				"Can crawl for authentication endpoints",
				"Check for API documentation",
			},
		}
	}

	return nil
}

// classifyCompanyName treats remaining inputs as potential company names
func (c *IdentifierClassifier) classifyCompanyName(input string) *ClassifiedIdentifier {
	// This is our catch-all classifier
	// Apply some heuristics to determine if it's likely a company name

	confidence := 0.5 // Base confidence for company names

	// Boost confidence for certain patterns
	companyIndicators := []string{
		"inc", "corp", "corporation", "ltd", "llc", "limited",
		"company", "co", "group", "holdings", "partners",
	}

	lowerInput := strings.ToLower(input)
	for _, indicator := range companyIndicators {
		if strings.Contains(lowerInput, indicator) {
			confidence += 0.2
			break
		}
	}

	// Check if it's multiple words (common for company names)
	words := strings.Fields(input)
	if len(words) > 1 {
		confidence += 0.1
	}

	// Cap confidence
	if confidence > 0.8 {
		confidence = 0.8
	}

	return &ClassifiedIdentifier{
		Raw:        input,
		Type:       TypeCompanyName,
		Value:      input,
		Confidence: confidence,
		Metadata: map[string]interface{}{
			"word_count": len(words),
			"normalized": normalizeCompanyName(input),
		},
		Hints: []string{
			"Search for domains containing company name",
			"Check business registries",
			"Look for trademark records",
			"Search certificate transparency for organization",
		},
	}
}

// applyHeuristics applies additional heuristics for unknown inputs
func (c *IdentifierClassifier) applyHeuristics(input string) *ClassifiedIdentifier {
	// Last resort heuristics

	// Check if it looks like a hash of some kind
	if len(input) >= 32 && isHexString(input) {
		return &ClassifiedIdentifier{
			Raw:        input,
			Type:       TypeCertHash,
			Value:      input,
			Confidence: 0.6,
			Metadata: map[string]interface{}{
				"hash_type": "unknown",
			},
		}
	}

	// Default to company name with low confidence
	return c.classifyCompanyName(input)
}

// Helper functions
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func (c *IdentifierClassifier) domainResolves(domain string) bool {
	// Quick DNS check
	_, err := net.LookupHost(domain)
	return err == nil
}

func normalizeCompanyName(name string) string {
	// Remove common suffixes and normalize
	name = strings.TrimSpace(name)
	suffixes := []string{
		", inc.", ", inc", " inc.", " inc",
		", corp.", ", corp", " corp.", " corp",
		", llc", " llc", ", ltd", " ltd",
	}

	lower := strings.ToLower(name)
	for _, suffix := range suffixes {
		if strings.HasSuffix(lower, suffix) {
			name = name[:len(name)-len(suffix)]
			break
		}
	}

	return name
}

// lastIPInRange calculates the last IP address in a CIDR range
func lastIPInRange(network *net.IPNet) net.IP {
	// Make a copy of the IP to avoid modifying the original
	ip := make(net.IP, len(network.IP))
	copy(ip, network.IP)

	for i := range ip {
		ip[i] |= ^network.Mask[i]
	}
	return ip
}

// isHexString checks if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
