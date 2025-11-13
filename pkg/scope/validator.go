package scope

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

// Validator validates assets against scope
type Validator struct {
	manager *Manager
	logger  *logger.Logger
}

// NewValidator creates a new validator
func NewValidator(manager *Manager, logger *logger.Logger) *Validator {
	return &Validator{
		manager: manager,
		logger:  logger,
	}
}

// Validate checks if an asset is in scope
func (v *Validator) Validate(asset string) *ValidationResult {
	result := &ValidationResult{
		Asset:       asset,
		Status:      ScopeStatusUnknown,
		ValidatedAt: time.Now(),
	}

	// Normalize asset
	normalized := v.normalizeAsset(asset)
	assetType := v.detectAssetType(normalized)

	v.logger.Debug("Validating asset",
		"asset", asset,
		"normalized", normalized,
		"type", assetType)

	// Get all programs
	programs, err := v.manager.ListPrograms()
	if err != nil {
		result.Reason = fmt.Sprintf("Failed to load programs: %v", err)
		return result
	}

	// Check each program
	for _, program := range programs {
		if !program.Active {
			continue
		}

		// Check out of scope first (takes precedence)
		if match := v.checkScope(normalized, assetType, program.OutOfScope); match != nil {
			result.Status = ScopeStatusOutOfScope
			result.MatchedItem = match
			result.Program = program
			result.Reason = fmt.Sprintf("Explicitly out of scope for %s: %s",
				program.Name, match.Description)

			// Get applicable rules
			result.ApplicableRules = v.getApplicableRules(program, match)

			// If strict mode, return immediately on out of scope
			if v.manager.config.StrictMode {
				return result
			}
		}

		// Check in scope
		if match := v.checkScope(normalized, assetType, program.Scope); match != nil {
			// Only update if not already marked out of scope
			if result.Status != ScopeStatusOutOfScope {
				result.Status = ScopeStatusInScope
				result.MatchedItem = match
				result.Program = program
				result.Reason = fmt.Sprintf("In scope for %s", program.Name)
				result.Restrictions = match.Restrictions

				// Get applicable rules
				result.ApplicableRules = v.getApplicableRules(program, match)
			}
		}
	}

	// If no match found
	if result.Status == ScopeStatusUnknown {
		if v.manager.config.StrictMode {
			result.Status = ScopeStatusOutOfScope
			result.Reason = "No matching scope found (strict mode)"
		} else {
			result.Reason = "No matching scope found"
		}
	}

	return result
}

// normalizeAsset normalizes an asset for comparison
func (v *Validator) normalizeAsset(asset string) string {
	asset = strings.TrimSpace(strings.ToLower(asset))

	// Remove common prefixes
	asset = strings.TrimPrefix(asset, "http://")
	asset = strings.TrimPrefix(asset, "https://")
	asset = strings.TrimPrefix(asset, "www.")

	// Remove trailing slashes
	asset = strings.TrimSuffix(asset, "/")

	return asset
}

// detectAssetType determines the type of asset
func (v *Validator) detectAssetType(asset string) ScopeType {
	// Check if IP
	if ip := net.ParseIP(asset); ip != nil {
		return ScopeTypeIP
	}

	// Check if IP range
	if _, _, err := net.ParseCIDR(asset); err == nil {
		return ScopeTypeIPRange
	}

	// Check if URL (has path component)
	if strings.Contains(asset, "/") {
		return ScopeTypeURL
	}

	// Check if API endpoint
	if strings.Contains(asset, "api.") || strings.Contains(asset, "/api/") {
		return ScopeTypeAPI
	}

	// Default to domain
	return ScopeTypeDomain
}

// checkScope checks if asset matches any scope items
func (v *Validator) checkScope(asset string, assetType ScopeType, items []ScopeItem) *ScopeItem {
	for _, item := range items {
		if v.matchesScopeItem(asset, assetType, &item) {
			return &item
		}
	}
	return nil
}

// matchesScopeItem checks if asset matches a specific scope item
func (v *Validator) matchesScopeItem(asset string, assetType ScopeType, item *ScopeItem) bool {
	switch item.Type {
	case ScopeTypeWildcard:
		return v.matchesWildcard(asset, item)

	case ScopeTypeDomain:
		return v.matchesDomain(asset, item.Value)

	case ScopeTypeURL:
		return v.matchesURL(asset, item.Value)

	case ScopeTypeIP:
		return v.matchesIP(asset, item.Value)

	case ScopeTypeIPRange:
		return v.matchesIPRange(asset, item.Value)

	case ScopeTypeAPI:
		return v.matchesAPI(asset, item.Value)

	default:
		// Exact match for other types
		return asset == v.normalizeAsset(item.Value)
	}
}

// matchesWildcard checks wildcard patterns like *.example.com
func (v *Validator) matchesWildcard(asset string, item *ScopeItem) bool {
	if item.CompiledPattern != nil {
		return item.CompiledPattern.MatchString(asset)
	}

	pattern := item.Value

	// Handle *.domain.com pattern
	if strings.HasPrefix(pattern, "*.") {
		baseDomain := strings.TrimPrefix(pattern, "*.")
		return asset == baseDomain || strings.HasSuffix(asset, "."+baseDomain)
	}

	// Handle domain.* pattern
	if strings.HasSuffix(pattern, ".*") {
		basePattern := strings.TrimSuffix(pattern, ".*")
		return strings.HasPrefix(asset, basePattern+".")
	}

	// Handle *.domain.* pattern
	if strings.HasPrefix(pattern, "*.") && strings.HasSuffix(pattern, ".*") {
		middle := pattern[2 : len(pattern)-2]
		return strings.Contains(asset, middle)
	}

	return false
}

// matchesDomain checks if asset matches a domain
func (v *Validator) matchesDomain(asset, domain string) bool {
	domain = v.normalizeAsset(domain)

	// Exact match
	if asset == domain {
		return true
	}

	// Subdomain match
	if strings.HasSuffix(asset, "."+domain) {
		return true
	}

	// Check if asset is a URL on this domain
	if strings.HasPrefix(asset, domain+"/") {
		return true
	}

	return false
}

// matchesURL checks if asset matches a URL pattern
func (v *Validator) matchesURL(asset, urlPattern string) bool {
	// Parse the pattern
	parsedPattern, err := url.Parse(urlPattern)
	if err != nil {
		return false
	}

	// If asset is just a domain, check if it matches the host
	if !strings.Contains(asset, "/") {
		return v.matchesDomain(asset, parsedPattern.Host)
	}

	// For URL matching, check host and path prefix
	if !v.matchesDomain(asset, parsedPattern.Host) {
		return false
	}

	// Extract path from asset
	assetPath := "/"
	if idx := strings.Index(asset, "/"); idx > 0 {
		assetPath = asset[idx:]
	}

	// Check path prefix
	return strings.HasPrefix(assetPath, parsedPattern.Path)
}

// matchesIP checks if asset matches an IP
func (v *Validator) matchesIP(asset, ip string) bool {
	assetIP := net.ParseIP(asset)
	scopeIP := net.ParseIP(ip)

	if assetIP == nil || scopeIP == nil {
		return false
	}

	return assetIP.Equal(scopeIP)
}

// matchesIPRange checks if asset is within an IP range
func (v *Validator) matchesIPRange(asset, ipRange string) bool {
	assetIP := net.ParseIP(asset)
	if assetIP == nil {
		return false
	}

	_, network, err := net.ParseCIDR(ipRange)
	if err != nil {
		return false
	}

	return network.Contains(assetIP)
}

// matchesAPI checks if asset matches an API endpoint
func (v *Validator) matchesAPI(asset, api string) bool {
	// Normalize API endpoint
	api = v.normalizeAsset(api)

	// Check for exact match or prefix match
	return asset == api || strings.HasPrefix(asset, api+"/")
}

// getApplicableRules finds rules that apply to a scope item
func (v *Validator) getApplicableRules(program *Program, item *ScopeItem) []Rule {
	var applicable []Rule

	for _, rule := range program.Rules {
		// Check if rule applies to all items
		if len(rule.Applies) == 0 {
			applicable = append(applicable, rule)
			continue
		}

		// Check if rule applies to this specific item
		for _, appliesTo := range rule.Applies {
			if appliesTo == item.ID || appliesTo == item.Value {
				applicable = append(applicable, rule)
				break
			}
		}
	}

	return applicable
}
