package validation

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// TargetValidationResult contains the result of target validation
type TargetValidationResult struct {
	Valid          bool
	TargetType     string // "domain", "ip", "url", "ip_range", "email", "company"
	NormalizedURL  string
	Warnings       []string
	Error          error
}

// ValidateTarget performs comprehensive validation of scan targets
func ValidateTarget(target string) *TargetValidationResult {
	result := &TargetValidationResult{
		Valid:    false,
		Warnings: []string{},
	}

	// Empty check
	if strings.TrimSpace(target) == "" {
		result.Error = fmt.Errorf("target cannot be empty")
		return result
	}

	target = strings.TrimSpace(target)

	// Check for obvious local/private targets
	if isPrivateTarget(target) {
		result.Error = fmt.Errorf("scanning private/local targets is not allowed without explicit authorization")
		result.Warnings = append(result.Warnings, "Target appears to be localhost, private IP, or internal domain")
		return result
	}

	// Try to determine target type and validate
	if isEmail(target) {
		result.TargetType = "email"
		domain := extractDomainFromEmail(target)
		result.NormalizedURL = "https://" + domain
		result.Valid = true
		result.Warnings = append(result.Warnings, "Email provided - will discover assets from domain: "+domain)
		return result
	}

	if isIPRange(target) {
		result.TargetType = "ip_range"
		result.NormalizedURL = target
		result.Valid = true
		result.Warnings = append(result.Warnings, "IP range scanning can be intrusive - ensure you have authorization")
		return result
	}

	if isIP(target) {
		result.TargetType = "ip"
		result.NormalizedURL = "https://" + target
		result.Valid = true
		return result
	}

	// Try parsing as URL
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		parsedURL, err := url.Parse(target)
		if err != nil {
			result.Error = fmt.Errorf("invalid URL format: %w", err)
			return result
		}

		// Check if URL points to private network
		if isPrivateHost(parsedURL.Hostname()) {
			result.Error = fmt.Errorf("URL points to private/local network")
			return result
		}

		result.TargetType = "url"
		result.NormalizedURL = target
		result.Valid = true
		return result
	}

	// Try as domain name
	if isDomain(target) {
		result.TargetType = "domain"
		result.NormalizedURL = "https://" + target
		result.Valid = true
		return result
	}

	// Assume it's a company name if nothing else matches
	if len(target) > 3 && !strings.Contains(target, "/") {
		result.TargetType = "company"
		result.NormalizedURL = target
		result.Valid = true
		result.Warnings = append(result.Warnings, "Treating input as company name - will perform discovery")
		return result
	}

	result.Error = fmt.Errorf("unable to determine target type - expected URL, domain, IP, email, or company name")
	return result
}

// isPrivateTarget checks if target is localhost or private network
func isPrivateTarget(target string) bool {
	lower := strings.ToLower(target)

	// Check for localhost variations
	localhostPatterns := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"0.0.0.0",
	}

	for _, pattern := range localhostPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Check for private TLDs
	privateTLDs := []string{
		".local",
		".internal",
		".lan",
		".test",
		".localhost",
	}

	for _, tld := range privateTLDs {
		if strings.HasSuffix(lower, tld) {
			return true
		}
	}

	// Extract hostname from URL if present
	hostname := target
	if strings.HasPrefix(target, "http") {
		parsed, err := url.Parse(target)
		if err == nil {
			hostname = parsed.Hostname()
		}
	}

	return isPrivateHost(hostname)
}

// isPrivateHost checks if a hostname/IP is private
func isPrivateHost(host string) bool {
	// Try to parse as IP
	ip := net.ParseIP(host)
	if ip != nil {
		// Check private IP ranges
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return true
		}
		// Check for special ranges
		if ip.String() == "0.0.0.0" || ip.String() == "::" {
			return true
		}
	}

	return false
}

// isEmail checks if string matches email format
func isEmail(s string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(s)
}

// extractDomainFromEmail extracts domain from email address
func extractDomainFromEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// isIPRange checks if string is an IP range (CIDR notation)
func isIPRange(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// isIP checks if string is a valid IP address
func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

// isDomain checks if string looks like a valid domain name
func isDomain(s string) bool {
	// Basic domain validation
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(s)
}

// RequireAuthorization prompts user for authorization confirmation
func RequireAuthorization(target string) error {
	// This is a placeholder - in a real implementation, this might:
	// 1. Check for a scope file
	// 2. Prompt interactively
	// 3. Check environment variables
	// 4. Verify against a whitelist

	// For now, just return nil to allow scans
	// In production, you'd want actual authorization checks
	return nil
}
