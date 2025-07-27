// pkg/correlation/helpers.go
package correlation

import (
	"crypto/md5"
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"
)

// Helper functions used throughout the correlation system

func generateOrgID(seed string) string {
	hash := md5.Sum([]byte(seed))
	return fmt.Sprintf("org_%x", hash[:8])
}

func extractDomainFromEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return strings.ToLower(parts[1])
	}
	return ""
}

func extractDomainFromPattern(pattern string) string {
	// Handle patterns like *@example.com
	if strings.HasPrefix(pattern, "*@") {
		return strings.TrimPrefix(pattern, "*@")
	}
	return ""
}

func isDomainValid(domain string) bool {
	// Basic domain validation
	if domain == "" || len(domain) > 253 {
		return false
	}

	// Check for valid characters and structure
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(domain)
}

func isRelatedDomain(domain string, knownDomains []string) bool {
	// Check if domain is related to any known domains
	for _, known := range knownDomains {
		// Same second-level domain
		if extractSLD(domain) == extractSLD(known) {
			return true
		}

		// Subdomain of known domain
		if strings.HasSuffix(domain, "."+known) {
			return true
		}

		// Known domain is subdomain
		if strings.HasSuffix(known, "."+domain) {
			return true
		}
	}
	return false
}

func extractSLD(domain string) string {
	// Extract second-level domain (e.g., "example" from "www.example.com")
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return domain
}

func isLikelySubsidiary(companyName, parentName string) bool {
	// Simple heuristic for subsidiary detection
	normalized := normalizeCompanyName(companyName)
	parentNormalized := normalizeCompanyName(parentName)

	// Check if parent name is contained in company name
	if strings.Contains(normalized, parentNormalized) {
		return true
	}

	// Check common subsidiary patterns
	subsidiaryPatterns := []string{
		parentNormalized + "labs",
		parentNormalized + "research",
		parentNormalized + "ventures",
		parentNormalized + "capital",
		parentNormalized + "holdings",
		parentNormalized + "international",
		parentNormalized + "global",
	}

	for _, pattern := range subsidiaryPatterns {
		if strings.Contains(normalized, pattern) {
			return true
		}
	}

	return false
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsInt(slice []int, item int) bool {
	for _, i := range slice {
		if i == item {
			return true
		}
	}
	return false
}

func deduplicateStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

func deduplicateInts(slice []int) []int {
	seen := make(map[int]bool)
	result := []int{}

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

func isNumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return len(s) > 0
}

func getIPVersion(ip net.IP) string {
	if ip.To4() != nil {
		return "4"
	}
	if ip.To16() != nil {
		return "6"
	}
	return "unknown"
}

func extractLinkedInCompany(url string) string {
	// Extract company name from LinkedIn URL
	re := regexp.MustCompile(`linkedin\.com/company/([^/]+)`)
	matches := re.FindStringSubmatch(url)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func extractGitHubOrg(url string) string {
	// Extract organization from GitHub URL
	re := regexp.MustCompile(`github\.com/([^/]+)`)
	matches := re.FindStringSubmatch(url)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func expandIPRange(cidr string) ([]string, error) {
	// Expand CIDR to individual IPs (limited for large ranges)
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as single IP
		if net.ParseIP(cidr) != nil {
			return []string{cidr}, nil
		}
		return nil, err
	}

	var ips []string

	// Limit expansion to /24 or smaller to avoid memory issues
	ones, bits := ipnet.Mask.Size()
	if bits-ones > 8 {
		// Too large, just return the CIDR
		return []string{cidr}, nil
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
		if len(ips) > 256 {
			// Safety limit
			break
		}
	}

	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ipInRange(ip, cidr string) bool {
	// Check if IP is in CIDR range
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Not a CIDR, check exact match
		return ip == cidr
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return ipnet.Contains(parsedIP)
}
