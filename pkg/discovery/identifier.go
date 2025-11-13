// pkg/discovery/identifier.go
package discovery

import (
	"fmt"
	"net"
	"net/mail"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// IdentifierType represents the type of identifier provided
type IdentifierType string

const (
	IdentifierTypeEmail       IdentifierType = "email"
	IdentifierTypeDomain      IdentifierType = "domain"
	IdentifierTypeIP          IdentifierType = "ip"
	IdentifierTypeIPRange     IdentifierType = "ip_range"
	IdentifierTypeCertHash    IdentifierType = "cert_hash"
	IdentifierTypeCompanyName IdentifierType = "company_name"
	IdentifierTypeURL         IdentifierType = "url"
	IdentifierTypeASN         IdentifierType = "asn"
	IdentifierTypeGitHub      IdentifierType = "github"
	IdentifierTypeAWSAccount  IdentifierType = "aws_account"
	IdentifierTypeUnknown     IdentifierType = "unknown"
)

// IdentifierClassification contains the classification result
type IdentifierClassification struct {
	Type       IdentifierType
	Value      string
	Normalized string
	Confidence float64
	Metadata   map[string]interface{}
}

// IdentifierClassifier classifies and processes various identifier types
type IdentifierClassifier struct {
	// Patterns for identification
	emailRegex      *regexp.Regexp
	domainRegex     *regexp.Regexp
	ipRegex         *regexp.Regexp
	ipRangeRegex    *regexp.Regexp
	urlRegex        *regexp.Regexp
	sha1Regex       *regexp.Regexp
	sha256Regex     *regexp.Regexp
	asnRegex        *regexp.Regexp
	awsAccountRegex *regexp.Regexp
	githubRegex     *regexp.Regexp
}

// NewIdentifierClassifier creates a new identifier classifier
func NewIdentifierClassifier() *IdentifierClassifier {
	return &IdentifierClassifier{
		emailRegex:      regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
		domainRegex:     regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`),
		ipRegex:         regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`),
		ipRangeRegex:    regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$`),
		urlRegex:        regexp.MustCompile(`^https?://`),
		sha1Regex:       regexp.MustCompile(`^[a-fA-F0-9]{40}$`),
		sha256Regex:     regexp.MustCompile(`^[a-fA-F0-9]{64}$`),
		asnRegex:        regexp.MustCompile(`^AS\d+$`),
		awsAccountRegex: regexp.MustCompile(`^\d{12}$`),
		githubRegex:     regexp.MustCompile(`^github\.com/[\w-]+(/[\w-]+)?$`),
	}
}

// Classify determines the type of identifier and returns classification
func (ic *IdentifierClassifier) Classify(identifier string) (*IdentifierClassification, error) {
	identifier = strings.TrimSpace(identifier)

	// Check URL first (most specific)
	if ic.urlRegex.MatchString(identifier) {
		return ic.classifyURL(identifier)
	}

	// Check email
	if ic.emailRegex.MatchString(identifier) {
		return ic.classifyEmail(identifier)
	}

	// Check IP range
	if ic.ipRangeRegex.MatchString(identifier) {
		return ic.classifyIPRange(identifier)
	}

	// Check IP address
	if ic.ipRegex.MatchString(identifier) && ic.isValidIP(identifier) {
		return ic.classifyIP(identifier)
	}

	// Check ASN
	if ic.asnRegex.MatchString(strings.ToUpper(identifier)) {
		return ic.classifyASN(identifier)
	}

	// Check AWS account ID
	if ic.awsAccountRegex.MatchString(identifier) {
		return ic.classifyAWSAccount(identifier)
	}

	// Check GitHub
	if strings.Contains(identifier, "github.com/") || ic.githubRegex.MatchString(identifier) {
		return ic.classifyGitHub(identifier)
	}

	// Check certificate hash
	if ic.sha1Regex.MatchString(identifier) || ic.sha256Regex.MatchString(identifier) {
		return ic.classifyCertHash(identifier)
	}

	// Check domain
	if ic.domainRegex.MatchString(identifier) && !strings.Contains(identifier, " ") {
		return ic.classifyDomain(identifier)
	}

	// Check if it's a simple domain without TLD
	if ic.looksLikeDomain(identifier) {
		return ic.classifyDomain(identifier)
	}

	// Default to company name
	return ic.classifyCompanyName(identifier)
}

// classifyEmail processes email identifiers
func (ic *IdentifierClassifier) classifyEmail(email string) (*IdentifierClassification, error) {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email format: %w", err)
	}

	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid email format")
	}

	return &IdentifierClassification{
		Type:       IdentifierTypeEmail,
		Value:      addr.Address,
		Normalized: strings.ToLower(addr.Address),
		Confidence: 1.0,
		Metadata: map[string]interface{}{
			"username": parts[0],
			"domain":   parts[1],
			"name":     addr.Name,
		},
	}, nil
}

// classifyDomain processes domain identifiers
func (ic *IdentifierClassifier) classifyDomain(domain string) (*IdentifierClassification, error) {
	normalized := strings.ToLower(strings.TrimSpace(domain))

	// Remove common prefixes
	normalized = strings.TrimPrefix(normalized, "www.")
	normalized = strings.TrimPrefix(normalized, "http://")
	normalized = strings.TrimPrefix(normalized, "https://")

	confidence := 1.0
	if !ic.domainRegex.MatchString(normalized) {
		confidence = 0.7 // Lower confidence for domains without TLD
	}

	return &IdentifierClassification{
		Type:       IdentifierTypeDomain,
		Value:      domain,
		Normalized: normalized,
		Confidence: confidence,
		Metadata: map[string]interface{}{
			"has_subdomain": strings.Count(normalized, ".") > 1,
		},
	}, nil
}

// classifyIP processes IP address identifiers
func (ic *IdentifierClassifier) classifyIP(ip string) (*IdentifierClassification, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("invalid IP address")
	}

	return &IdentifierClassification{
		Type:       IdentifierTypeIP,
		Value:      ip,
		Normalized: parsed.String(),
		Confidence: 1.0,
		Metadata: map[string]interface{}{
			"is_ipv4":    parsed.To4() != nil,
			"is_ipv6":    parsed.To4() == nil,
			"is_private": ic.isPrivateIP(parsed),
		},
	}, nil
}

// classifyIPRange processes IP range identifiers
func (ic *IdentifierClassifier) classifyIPRange(ipRange string) (*IdentifierClassification, error) {
	_, ipnet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return nil, fmt.Errorf("invalid IP range: %w", err)
	}

	ones, bits := ipnet.Mask.Size()

	return &IdentifierClassification{
		Type:       IdentifierTypeIPRange,
		Value:      ipRange,
		Normalized: ipnet.String(),
		Confidence: 1.0,
		Metadata: map[string]interface{}{
			"network":      ipnet.IP.String(),
			"mask_bits":    ones,
			"total_bits":   bits,
			"is_ipv4":      bits == 32,
			"is_ipv6":      bits == 128,
			"approx_hosts": ic.calculateHosts(ones, bits),
		},
	}, nil
}

// classifyCertHash processes certificate hash identifiers
func (ic *IdentifierClassifier) classifyCertHash(hash string) (*IdentifierClassification, error) {
	normalized := strings.ToLower(strings.TrimSpace(hash))

	hashType := "unknown"
	if len(normalized) == 40 {
		hashType = "sha1"
	} else if len(normalized) == 64 {
		hashType = "sha256"
	}

	return &IdentifierClassification{
		Type:       IdentifierTypeCertHash,
		Value:      hash,
		Normalized: normalized,
		Confidence: 0.9, // High confidence but could be other hash
		Metadata: map[string]interface{}{
			"hash_type":   hashType,
			"hash_length": len(normalized),
		},
	}, nil
}

// classifyCompanyName processes company name identifiers
func (ic *IdentifierClassifier) classifyCompanyName(name string) (*IdentifierClassification, error) {
	normalized := strings.TrimSpace(name)

	// Extract potential domains from company name
	potentialDomains := ic.generatePotentialDomains(normalized)

	return &IdentifierClassification{
		Type:       IdentifierTypeCompanyName,
		Value:      name,
		Normalized: normalized,
		Confidence: 0.8, // Default confidence for company names
		Metadata: map[string]interface{}{
			"potential_domains": potentialDomains,
			"word_count":        len(strings.Fields(normalized)),
		},
	}, nil
}

// classifyURL processes URL identifiers
func (ic *IdentifierClassifier) classifyURL(url string) (*IdentifierClassification, error) {
	// Extract domain from URL
	domain := ""
	if strings.HasPrefix(url, "http://") {
		domain = strings.TrimPrefix(url, "http://")
	} else if strings.HasPrefix(url, "https://") {
		domain = strings.TrimPrefix(url, "https://")
	}

	// Remove path
	if idx := strings.Index(domain, "/"); idx > 0 {
		domain = domain[:idx]
	}

	// Remove port
	if idx := strings.Index(domain, ":"); idx > 0 {
		domain = domain[:idx]
	}

	return &IdentifierClassification{
		Type:       IdentifierTypeURL,
		Value:      url,
		Normalized: strings.ToLower(url),
		Confidence: 1.0,
		Metadata: map[string]interface{}{
			"domain":   domain,
			"has_path": strings.Contains(url, "/") && strings.Count(url, "/") > 2,
			"scheme":   strings.Split(url, "://")[0],
		},
	}, nil
}

// classifyASN processes ASN identifiers
func (ic *IdentifierClassifier) classifyASN(asn string) (*IdentifierClassification, error) {
	normalized := strings.ToUpper(strings.TrimSpace(asn))

	// Extract ASN number
	asnNumber := strings.TrimPrefix(normalized, "AS")

	return &IdentifierClassification{
		Type:       IdentifierTypeASN,
		Value:      asn,
		Normalized: normalized,
		Confidence: 1.0,
		Metadata: map[string]interface{}{
			"asn_number": asnNumber,
		},
	}, nil
}

// classifyAWSAccount processes AWS account identifiers
func (ic *IdentifierClassifier) classifyAWSAccount(accountID string) (*IdentifierClassification, error) {
	return &IdentifierClassification{
		Type:       IdentifierTypeAWSAccount,
		Value:      accountID,
		Normalized: accountID,
		Confidence: 0.9, // Could be other 12-digit number
		Metadata: map[string]interface{}{
			"account_id": accountID,
		},
	}, nil
}

// classifyGitHub processes GitHub identifiers
func (ic *IdentifierClassifier) classifyGitHub(github string) (*IdentifierClassification, error) {
	normalized := strings.ToLower(strings.TrimSpace(github))
	normalized = strings.TrimPrefix(normalized, "https://")
	normalized = strings.TrimPrefix(normalized, "http://")
	normalized = strings.TrimSuffix(normalized, "/")

	parts := strings.Split(normalized, "/")

	metadata := map[string]interface{}{}
	if len(parts) >= 2 {
		metadata["organization"] = parts[1]
	}
	if len(parts) >= 3 {
		metadata["repository"] = parts[2]
	}

	return &IdentifierClassification{
		Type:       IdentifierTypeGitHub,
		Value:      github,
		Normalized: normalized,
		Confidence: 1.0,
		Metadata:   metadata,
	}, nil
}

// Helper methods

func (ic *IdentifierClassifier) isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func (ic *IdentifierClassifier) isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range privateRanges {
		_, ipnet, _ := net.ParseCIDR(cidr)
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (ic *IdentifierClassifier) looksLikeDomain(s string) bool {
	// Simple heuristic for domain-like strings
	s = strings.ToLower(s)

	// No spaces
	if strings.Contains(s, " ") {
		return false
	}

	// Contains only valid domain characters
	domainChars := regexp.MustCompile(`^[a-z0-9.-]+$`)
	if !domainChars.MatchString(s) {
		return false
	}

	// Has at least one dot or common domain pattern
	return strings.Contains(s, ".") || len(s) < 20
}

func (ic *IdentifierClassifier) generatePotentialDomains(companyName string) []string {
	// Normalize company name
	normalized := strings.ToLower(companyName)

	// Remove common suffixes
	suffixes := []string{
		" inc", " inc.", " incorporated",
		" corp", " corp.", " corporation",
		" llc", " ltd", " limited",
		" gmbh", " sa", " ag", " nv", " bv",
		" plc", " co", " company",
	}

	for _, suffix := range suffixes {
		normalized = strings.TrimSuffix(normalized, suffix)
	}

	// Remove special characters and create variations
	cleaned := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(normalized, "")
	hyphenated := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(normalized, "-")
	hyphenated = strings.Trim(hyphenated, "-")

	// Generate potential domains
	domains := []string{}
	tlds := []string{".com", ".net", ".org", ".io", ".co", ".ai", ".tech", ".cloud"}

	for _, base := range []string{cleaned, hyphenated} {
		if base == "" {
			continue
		}
		for _, tld := range tlds {
			domains = append(domains, base+tld)
		}
	}

	// Add first word only variations
	words := strings.Fields(normalized)
	if len(words) > 1 {
		firstWord := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(words[0], "")
		if firstWord != "" && firstWord != cleaned {
			for _, tld := range tlds[:4] { // Only common TLDs
				domains = append(domains, firstWord+tld)
			}
		}
	}

	return domains
}

func (ic *IdentifierClassifier) calculateHosts(maskBits, totalBits int) int64 {
	hostBits := totalBits - maskBits
	if hostBits <= 0 {
		return 1
	}
	if hostBits > 31 {
		return -1 // Too large to calculate
	}
	return (1 << hostBits) - 2 // Subtract network and broadcast
}

// ConvertToDiscoveryTarget converts classification to discovery target
func (ic *IdentifierClassifier) ConvertToDiscoveryTarget(classification *IdentifierClassification) *types.DiscoveryTarget {
	target := &types.DiscoveryTarget{
		Identifier: classification.Value,
		Type:       string(classification.Type),
		Confidence: classification.Confidence,
		Metadata:   classification.Metadata,
	}

	// Set primary value based on type
	switch classification.Type {
	case IdentifierTypeEmail:
		if domain, ok := classification.Metadata["domain"].(string); ok {
			target.PrimaryDomain = domain
		}
	case IdentifierTypeDomain, IdentifierTypeURL:
		target.PrimaryDomain = classification.Normalized
	case IdentifierTypeIP:
		target.PrimaryIP = classification.Normalized
	case IdentifierTypeIPRange:
		target.IPRange = classification.Normalized
	case IdentifierTypeCompanyName:
		target.CompanyName = classification.Normalized
		if domains, ok := classification.Metadata["potential_domains"].([]string); ok && len(domains) > 0 {
			target.PrimaryDomain = domains[0]
		}
	case IdentifierTypeASN:
		target.ASN = classification.Normalized
	case IdentifierTypeGitHub:
		if org, ok := classification.Metadata["organization"].(string); ok {
			target.GitHubOrg = org
		}
	case IdentifierTypeAWSAccount:
		target.AWSAccountID = classification.Value
	}

	return target
}
