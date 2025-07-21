// pkg/auth/discovery/org_correlation_module.go
package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
)

// OrgCorrelationModule discovers organization context early in the discovery process
type OrgCorrelationModule struct {
	logger     *logger.Logger
	correlator *correlation.OrganizationCorrelator
	config     *discovery.DiscoveryConfig
}

func NewOrgCorrelationModule(config *discovery.DiscoveryConfig, logger *logger.Logger) *OrgCorrelationModule {
	// Create a basic correlator config
	correlatorConfig := correlation.CorrelatorConfig{
		EnableWhois:     true,
		EnableCerts:     true,
		EnableASN:       true,
		EnableTrademark: true,
		EnableLinkedIn:  true,
		EnableGitHub:    true,
		EnableCloud:     true,
		CacheTTL:        30 * time.Minute,
		MaxWorkers:      10,
	}

	return &OrgCorrelationModule{
		logger:     logger,
		correlator: correlation.NewOrganizationCorrelator(correlatorConfig, logger),
		config:     config,
	}
}

func (o *OrgCorrelationModule) Name() string {
	return "organization_correlation"
}

func (o *OrgCorrelationModule) Priority() int {
	return 100 // Highest priority - runs first
}

func (o *OrgCorrelationModule) CanHandle(target *discovery.Target) bool {
	// Can handle any target type to extract organization context
	return true
}

func (o *OrgCorrelationModule) Discover(ctx context.Context, target *discovery.Target, session *discovery.DiscoverySession) (*discovery.DiscoveryResult, error) {
	o.logger.Info("Starting organization correlation",
		"target", target.Value,
		"type", target.Type)

	// Correlate to find organization
	// Use FindOrganizationAssets with the target value as seed data
	org, err := o.correlator.FindOrganizationAssets(ctx, target.Value)
	if err != nil {
		return nil, fmt.Errorf("organization correlation failed: %w", err)
	}

	// Store organization in session metadata
	if session.Metadata == nil {
		session.Metadata = make(map[string]interface{})
	}
	session.Metadata["organization"] = org

	// Generate org ID from name or use metadata if available
	orgID := ""
	if id, ok := org.Metadata["id"].(string); ok {
		orgID = id
	} else if org.Name != "" {
		// Create a deterministic ID from org name
		orgID = fmt.Sprintf("org-%s", strings.ReplaceAll(strings.ToLower(org.Name), " ", "-"))
	}

	session.Metadata["org_id"] = orgID
	session.Metadata["org_name"] = org.Name

	// Convert organization assets to discovery assets
	result := &discovery.DiscoveryResult{
		Assets:        o.convertOrgAssets(org),
		Relationships: []*discovery.Relationship{}, // TODO: implement extractOrgRelationships
		Source:        o.Name(),
	}

	// Add organization metadata to all assets
	for _, asset := range result.Assets {
		if asset.Metadata == nil {
			asset.Metadata = make(map[string]string)
		}
		asset.Metadata["org_id"] = orgID
		asset.Metadata["org_name"] = org.Name
		asset.Metadata["org_confidence"] = fmt.Sprintf("%.2f", org.Confidence)
	}

	o.logger.Info("Organization correlation completed",
		"org_name", org.Name,
		"domains", len(org.Domains),
		"ip_ranges", len(org.IPRanges),
		"confidence", org.Confidence)

	return result, nil
}

// convertOrgAssets converts organization data to discovery assets
func (o *OrgCorrelationModule) convertOrgAssets(org *correlation.Organization) []*discovery.Asset {
	var assets []*discovery.Asset

	// Convert domains
	for _, domain := range org.Domains {
		asset := &discovery.Asset{
			Type:       discovery.AssetTypeDomain,
			Value:      domain,
			Domain:     domain,
			Source:     "organization_correlation",
			Confidence: 0.9, // High confidence for org domains
			Metadata: map[string]string{
				"org_name": org.Name,
			},
			Priority: int(discovery.PriorityHigh),
			Tags:     []string{"organization_domain"},
		}

		assets = append(assets, asset)
	}

	// Convert IP ranges
	for _, ipRange := range org.IPRanges {
		asset := &discovery.Asset{
			Type:       discovery.AssetTypeIPRange,
			Value:      ipRange,
			Source:     "organization_correlation",
			Confidence: 0.8,
			Metadata: map[string]string{
				"org_name": org.Name,
			},
			Tags: []string{"organization_ip_range"},
		}
		assets = append(assets, asset)
	}

	// Convert ASNs
	for _, asn := range org.ASNs {
		asset := &discovery.Asset{
			Type:       discovery.AssetTypeASN,
			Value:      asn,
			Source:     "organization_correlation",
			Confidence: 0.9,
			Metadata: map[string]string{
				"org_name": org.Name,
			},
			Tags: []string{"organization_asn"},
		}
		assets = append(assets, asset)
	}

	// Convert GitHub organizations
	for _, gitOrg := range org.GitHubOrgs {
		asset := &discovery.Asset{
			Type:       discovery.AssetTypeRepository,
			Value:      gitOrg,
			Source:     "organization_correlation",
			Confidence: 0.8,
			Metadata: map[string]string{
				"org_name": org.Name,
				"platform": "github",
			},
			Tags: []string{"organization_repository"},
		}
		assets = append(assets, asset)
	}

	return assets
}
