// internal/discovery/organization_context.go
package discovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
)

// OrganizationContextBuilder builds organization context for discovery
type OrganizationContextBuilder struct {
	correlator *correlation.EnhancedOrganizationCorrelator
	logger     *logger.Logger
}

// NewOrganizationContextBuilder creates a new context builder
func NewOrganizationContextBuilder(correlator *correlation.EnhancedOrganizationCorrelator, logger *logger.Logger) *OrganizationContextBuilder {
	return &OrganizationContextBuilder{
		correlator: correlator,
		logger:     logger,
	}
}

// BuildContext builds organization context from an identifier
func (ocb *OrganizationContextBuilder) BuildContext(ctx context.Context, identifier string) (*OrganizationContext, error) {
	// Resolve identifier
	resolver := correlation.NewIdentifierResolver(ocb.logger)
	identInfo, err := resolver.ParseIdentifier(identifier)
	if err != nil {
		return nil, fmt.Errorf("failed to parse identifier: %w", err)
	}

	// Get organization
	org, err := resolver.ResolveToOrganization(ctx, identInfo, ocb.correlator)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve organization: %w", err)
	}

	// Extract email patterns from metadata
	emailPatterns := []string{}
	if patterns, ok := org.Metadata["email_patterns"].([]string); ok {
		emailPatterns = patterns
	}

	// Extract technologies as strings
	techStrings := make([]string, 0, len(org.Technologies))
	for _, tech := range org.Technologies {
		techStrings = append(techStrings, tech.Name)
	}

	// Build context matching the existing OrganizationContext structure
	orgContext := &OrganizationContext{
		OrgID:         generateOrgID(org.Name),
		OrgName:       org.Name,
		KnownDomains:  org.Domains,
		KnownIPRanges: org.IPRanges,
		EmailPatterns: emailPatterns,
		Subsidiaries:  org.Subsidiaries,
		Technologies:  techStrings,
		IndustryType:  getIndustryType(org),
	}

	ocb.logger.Infow("Built organization context",
		"org", org.Name,
		"domains", len(orgContext.KnownDomains),
		"ip_ranges", len(orgContext.KnownIPRanges),
		"subsidiaries", len(orgContext.Subsidiaries))

	return orgContext, nil
}

// Helper functions

func generateOrgID(name string) string {
	// Simple ID generation
	return fmt.Sprintf("org-%s", strings.ToLower(strings.ReplaceAll(name, " ", "-")))
}

func getIndustryType(org *correlation.Organization) string {
	// Try to extract industry from metadata
	if industry, ok := org.Metadata["industry"].(string); ok {
		return industry
	}
	// Default to unknown
	return "unknown"
}

// Update DiscoverySession in internal/discovery/engine.go
// Add this field to DiscoverySession struct:
// OrgContext *OrganizationContext `json:"org_context,omitempty"`
