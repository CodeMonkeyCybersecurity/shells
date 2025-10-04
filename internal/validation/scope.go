package validation

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

// ScopeFile represents a parsed scope file
type ScopeFile struct {
	InScope     []ScopeEntry
	OutOfScope  []ScopeEntry
	Description string
}

// ScopeEntry represents a single scope entry (domain, IP range, etc.)
type ScopeEntry struct {
	Value string
	Type  string // "domain", "ip", "ip_range", "wildcard"
}

// LoadScopeFile loads and parses a scope file
func LoadScopeFile(path string) (*ScopeFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open scope file: %w", err)
	}
	defer file.Close()

	scope := &ScopeFile{
		InScope:    []ScopeEntry{},
		OutOfScope: []ScopeEntry{},
	}

	scanner := bufio.NewScanner(file)
	inScopeSection := true // Default to in-scope

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			// Check for description comment
			if strings.HasPrefix(line, "# Description:") {
				scope.Description = strings.TrimPrefix(line, "# Description:")
				scope.Description = strings.TrimSpace(scope.Description)
			}
			continue
		}

		// Check for section headers
		if strings.ToLower(line) == "[in-scope]" || strings.ToLower(line) == "[inscope]" {
			inScopeSection = true
			continue
		}
		if strings.ToLower(line) == "[out-of-scope]" || strings.ToLower(line) == "[outofscope]" {
			inScopeSection = false
			continue
		}

		// Parse entry
		entry := parseScopeEntry(line)
		if entry == nil {
			continue // Skip invalid entries
		}

		if inScopeSection {
			scope.InScope = append(scope.InScope, *entry)
		} else {
			scope.OutOfScope = append(scope.OutOfScope, *entry)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading scope file: %w", err)
	}

	return scope, nil
}

// parseScopeEntry parses a single line into a ScopeEntry
func parseScopeEntry(line string) *ScopeEntry {
	line = strings.TrimSpace(line)

	// Check for IP range (CIDR)
	if strings.Contains(line, "/") {
		if _, _, err := net.ParseCIDR(line); err == nil {
			return &ScopeEntry{
				Value: line,
				Type:  "ip_range",
			}
		}
	}

	// Check for IP address
	if net.ParseIP(line) != nil {
		return &ScopeEntry{
			Value: line,
			Type:  "ip",
		}
	}

	// Check for wildcard domain (*.example.com)
	if strings.HasPrefix(line, "*.") {
		domain := strings.TrimPrefix(line, "*.")
		if isDomain(domain) {
			return &ScopeEntry{
				Value: line,
				Type:  "wildcard",
			}
		}
	}

	// Check for domain
	if isDomain(line) {
		return &ScopeEntry{
			Value: line,
			Type:  "domain",
		}
	}

	// Check for URL
	if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
		return &ScopeEntry{
			Value: line,
			Type:  "url",
		}
	}

	return nil
}

// IsInScope checks if a target is within the defined scope
func (sf *ScopeFile) IsInScope(target string) bool {
	// First check if explicitly out of scope
	if sf.matchesAnyEntry(target, sf.OutOfScope) {
		return false
	}

	// Then check if in scope
	return sf.matchesAnyEntry(target, sf.InScope)
}

// matchesAnyEntry checks if target matches any scope entry
func (sf *ScopeFile) matchesAnyEntry(target string, entries []ScopeEntry) bool {
	// Normalize target
	target = strings.ToLower(target)
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	target = strings.Split(target, "/")[0] // Remove path
	target = strings.Split(target, ":")[0] // Remove port

	for _, entry := range entries {
		if matchesScopeEntry(target, entry) {
			return true
		}
	}

	return false
}

// matchesScopeEntry checks if target matches a specific scope entry
func matchesScopeEntry(target string, entry ScopeEntry) bool {
	entryValue := strings.ToLower(entry.Value)

	switch entry.Type {
	case "domain":
		// Exact match or subdomain
		if target == entryValue {
			return true
		}
		// Check if target is subdomain of entry
		if strings.HasSuffix(target, "."+entryValue) {
			return true
		}

	case "wildcard":
		// *.example.com matches anything.example.com
		domain := strings.TrimPrefix(entryValue, "*.")
		if strings.HasSuffix(target, domain) {
			return true
		}

	case "ip":
		// Exact IP match
		return target == entryValue

	case "ip_range":
		// Check if target IP is within CIDR range
		targetIP := net.ParseIP(target)
		if targetIP == nil {
			return false
		}

		_, ipNet, err := net.ParseCIDR(entry.Value)
		if err != nil {
			return false
		}

		return ipNet.Contains(targetIP)

	case "url":
		// URL match (compare normalized URLs)
		normalizedEntry := strings.ToLower(entry.Value)
		normalizedEntry = strings.TrimPrefix(normalizedEntry, "http://")
		normalizedEntry = strings.TrimPrefix(normalizedEntry, "https://")

		return strings.HasPrefix(target, normalizedEntry)
	}

	return false
}

// ValidateWithScope validates a target against a scope file
func ValidateWithScope(target string, scopePath string) (*TargetValidationResult, error) {
	// First, do normal validation
	result := ValidateTarget(target)
	if !result.Valid {
		return result, nil
	}

	// If scope file doesn't exist, allow all valid targets
	if scopePath == "" {
		return result, nil
	}

	// Load scope file
	scope, err := LoadScopeFile(scopePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load scope file: %w", err)
	}

	// Check if target is in scope
	if !scope.IsInScope(target) {
		result.Valid = false
		result.Error = fmt.Errorf("target is not in scope")
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Target '%s' is not authorized in scope file '%s'", target, scopePath))
		return result, nil
	}

	return result, nil
}

// GenerateScopeFile creates a sample scope file
func GenerateScopeFile(path string, targets []string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create scope file: %w", err)
	}
	defer file.Close()

	// Write header
	fmt.Fprintln(file, "# Shells Scope File")
	fmt.Fprintln(file, "# Description: Define authorized scan targets")
	fmt.Fprintln(file, "#")
	fmt.Fprintln(file, "# Format:")
	fmt.Fprintln(file, "#   - Exact domains: example.com")
	fmt.Fprintln(file, "#   - Wildcard domains: *.example.com")
	fmt.Fprintln(file, "#   - IP addresses: 192.168.1.1")
	fmt.Fprintln(file, "#   - IP ranges: 192.168.1.0/24")
	fmt.Fprintln(file, "#   - URLs: https://api.example.com")
	fmt.Fprintln(file, "#")
	fmt.Fprintln(file, "# Lines starting with # are comments")
	fmt.Fprintln(file, "")
	fmt.Fprintln(file, "[in-scope]")

	// Write targets
	for _, target := range targets {
		fmt.Fprintln(file, target)
	}

	fmt.Fprintln(file, "")
	fmt.Fprintln(file, "[out-of-scope]")
	fmt.Fprintln(file, "# Example: *.internal.example.com")
	fmt.Fprintln(file, "")

	return nil
}

// isDomain is duplicated from target.go to avoid circular imports
func isDomainScope(s string) bool {
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(s)
}
