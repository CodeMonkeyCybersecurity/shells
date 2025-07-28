// cmd/root_enhanced_simplified.go
// Enhanced root command with advanced infrastructure mapping

package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/infrastructure"
	"github.com/spf13/cobra"
)

// EnhanceRootCommand modifies the root command to include infrastructure mapping
func EnhanceRootCommand() {
	// Update the existing rootCmd with enhanced functionality
	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		// If no arguments provided, show help
		if len(args) == 0 {
			return cmd.Help()
		}

		// Enhanced point-and-click mode: comprehensive infrastructure discovery and testing
		return runEnhancedDiscovery(cmd, args, log, store)
	}
}

// runEnhancedDiscovery performs comprehensive infrastructure discovery and testing
func runEnhancedDiscovery(cmd *cobra.Command, args []string, log *logger.Logger, db core.ResultStore) error {
	target := args[0]
	ctx := context.Background()

	log.Infow("🚀 Starting enhanced infrastructure discovery and testing", "target", target)

	// Phase 1: Advanced Infrastructure Discovery
	log.Info("📡 Phase 1: Advanced Infrastructure Discovery")
	infraReport, err := runAdvancedInfrastructureDiscovery(ctx, target, log)
	if err != nil {
		log.Error("Infrastructure discovery failed", "error", err)
		return fmt.Errorf("infrastructure discovery failed: %w", err)
	}

	// Print infrastructure summary
	printInfrastructureSummary(infraReport)

	// Phase 2: Organization Context Building
	log.Info("🏢 Phase 2: Organization Context Analysis")
	orgContext := buildOrganizationContext(ctx, target, infraReport, log)
	if orgContext != nil {
		printOrganizationSummary(orgContext)
	}

	// Phase 3: Execute the existing comprehensive scanning from root.go
	log.Info("🔐 Phase 3: Running existing comprehensive scans")
	discoveredAssets := convertInfraToDiscoveryAssets(infraReport)

	// Use the existing executeComprehensiveScans function with a mock session
	session := createMockSession(target, discoveredAssets)
	if err := executeComprehensiveScans(session); err != nil {
		log.Error("Comprehensive scanning failed", "error", err)
		return fmt.Errorf("comprehensive scanning failed: %w", err)
	}

	log.Info("✅ Enhanced infrastructure discovery and testing completed successfully")
	return nil
}

// runAdvancedInfrastructureDiscovery performs advanced infrastructure discovery
func runAdvancedInfrastructureDiscovery(ctx context.Context, target string, log *logger.Logger) (*infrastructure.InfrastructureReport, error) {
	// Create infrastructure discovery configuration
	discoveryConfig := &infrastructure.DiscoveryConfig{
		MaxDepth:                  4,
		MaxAssets:                 2000,
		Timeout:                   45 * time.Minute,
		Workers:                   15,
		RateLimitPerSecond:        30,
		EnableDNSEnumeration:      true,
		EnableSubdomainBrute:      true,
		EnablePortScanning:        true,
		EnableSSLAnalysis:         true,
		EnableCloudDiscovery:      true,
		EnableCDNDetection:        true,
		EnableASNAnalysis:         true,
		EnableTechDetection:       true,
		EnableSupplyChainAnalysis: true,
		EnableThreatIntel:         false, // Requires API keys
		CustomPorts:               []int{80, 443, 8080, 8443, 3000, 5000, 8000, 9000, 8090, 9090},
	}

	// Initialize advanced infrastructure mapper
	mapper := infrastructure.NewAdvancedInfrastructureMapper(log, discoveryConfig)

	// Run infrastructure discovery
	infraReport, err := mapper.DiscoverInfrastructure(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("infrastructure discovery failed: %w", err)
	}

	return infraReport, nil
}

// buildOrganizationContext builds organization context using existing correlation
func buildOrganizationContext(ctx context.Context, target string, infraReport *infrastructure.InfrastructureReport, log *logger.Logger) *discovery.OrganizationContext {
	correlatorConfig := correlation.CorrelatorConfig{
		EnableWhois:     true,
		EnableCerts:     true,
		EnableASN:       true,
		EnableTrademark: true,
		EnableLinkedIn:  true,
		EnableGitHub:    true,
		EnableCloud:     true,
		CacheTTL:        24 * time.Hour,
		MaxWorkers:      5,
	}

	correlator := correlation.NewEnhancedOrganizationCorrelator(correlatorConfig, log)

	// Use existing organization context builder
	contextBuilder := discovery.NewOrganizationContextBuilder(correlator, log)
	orgContext, err := contextBuilder.BuildContext(ctx, target)
	if err != nil {
		log.Warn("Organization context building failed", "error", err)
		return nil
	}

	return orgContext
}

// convertInfraToDiscoveryAssets converts infrastructure assets to discovery assets
func convertInfraToDiscoveryAssets(infraReport *infrastructure.InfrastructureReport) []discovery.Asset {
	assets := make([]discovery.Asset, 0, len(infraReport.Assets))

	for _, infraAsset := range infraReport.Assets {
		asset := discovery.Asset{
			ID:           infraAsset.ID,
			Type:         convertToDiscoveryAssetType(infraAsset.Type),
			Value:        infraAsset.Value,
			Source:       infraAsset.Source,
			Confidence:   infraAsset.Confidence,
			Priority:     infraAsset.Priority,
			Metadata:     make(map[string]string),
			DiscoveredAt: infraAsset.DiscoveredAt,
		}

		// Convert metadata
		for k, v := range infraAsset.Metadata {
			if str, ok := v.(string); ok {
				asset.Metadata[k] = str
			} else {
				asset.Metadata[k] = fmt.Sprintf("%v", v)
			}
		}

		// Set domain and IP fields based on asset type
		if asset.Type == discovery.AssetTypeDomain || asset.Type == discovery.AssetTypeSubdomain {
			asset.Domain = infraAsset.Value
		} else if asset.Type == discovery.AssetTypeIP {
			asset.IP = infraAsset.Value
		}

		// Set technologies
		if len(infraAsset.Technologies) > 0 {
			techNames := make([]string, len(infraAsset.Technologies))
			for i, tech := range infraAsset.Technologies {
				techNames[i] = tech.Name
			}
			asset.Technology = techNames
		}

		assets = append(assets, asset)
	}

	return assets
}

// convertToDiscoveryAssetType converts infrastructure asset type to discovery asset type
func convertToDiscoveryAssetType(infraType infrastructure.AssetType) discovery.AssetType {
	switch infraType {
	case infrastructure.AssetTypeDomain:
		return discovery.AssetTypeDomain
	case infrastructure.AssetTypeSubdomain:
		return discovery.AssetTypeSubdomain
	case infrastructure.AssetTypeIP:
		return discovery.AssetTypeIP
	case infrastructure.AssetTypeURL:
		return discovery.AssetTypeURL
	case infrastructure.AssetTypeAPI:
		return discovery.AssetTypeAPI
	case infrastructure.AssetTypeDatabase:
		return discovery.AssetTypeAPI
	case infrastructure.AssetTypeEmail:
		return discovery.AssetTypeEmail
	default:
		return discovery.AssetTypeDomain
	}
}

// createMockSession creates a mock discovery session for the existing executeComprehensiveScans
func createMockSession(target string, assets []discovery.Asset) *discovery.DiscoverySession {
	return &discovery.DiscoverySession{
		ID:              fmt.Sprintf("enhanced-%d", time.Now().Unix()),
		Target:          discovery.Target{Raw: target, Type: discovery.TargetTypeDomain, Value: target},
		Status:          discovery.StatusCompleted,
		Progress:        1.0,
		Assets:          convertAssetsToMap(assets),
		TotalDiscovered: len(assets),
		HighValueAssets: countHighValueAssets(assets),
		Relationships:   make(map[string]*discovery.Relationship),
		StartedAt:       time.Now(),
		Errors:          []string{},
	}
}

// convertAssetsToMap converts asset slice to map as required by DiscoverySession
func convertAssetsToMap(assets []discovery.Asset) map[string]*discovery.Asset {
	assetMap := make(map[string]*discovery.Asset)
	for i := range assets {
		assetMap[assets[i].ID] = &assets[i]
	}
	return assetMap
}

// countHighValueAssets counts high-value assets
func countHighValueAssets(assets []discovery.Asset) int {
	count := 0
	for _, asset := range assets {
		if discovery.IsHighValueAsset(&asset) {
			count++
		}
	}
	return count
}

// printInfrastructureSummary prints a summary of the infrastructure discovery
func printInfrastructureSummary(report *infrastructure.InfrastructureReport) {
	fmt.Printf("\n📡 Enhanced Infrastructure Discovery Summary:\n")
	fmt.Printf("   Target: %s\n", report.Target)
	fmt.Printf("   Total Assets: %d\n", len(report.Assets))
	fmt.Printf("   Discovery Time: %v\n", report.DiscoveryTime)
	fmt.Printf("   Organizations: %d\n", len(report.Organizations))
	fmt.Printf("   Relationships: %d\n\n", len(report.Relationships))

	// Asset breakdown
	fmt.Printf("📊 Asset Breakdown:\n")
	for assetType, count := range report.Statistics.AssetsByType {
		fmt.Printf("   %s: %d\n", assetType, count)
	}

	// High-priority assets
	highPriorityAssets := 0
	criticalAssets := 0
	for _, asset := range report.Assets {
		if asset.Priority >= infrastructure.PriorityHigh {
			highPriorityAssets++
		}
		if asset.Priority >= infrastructure.PriorityCritical {
			criticalAssets++
		}
	}

	fmt.Printf("\n🎯 Priority Assets:\n")
	fmt.Printf("   High Priority: %d\n", highPriorityAssets)
	fmt.Printf("   Critical: %d\n", criticalAssets)
	fmt.Printf("   Cloud Assets: %d\n", report.Statistics.CloudAssets)
	fmt.Printf("   CDN Protected: %d\n", report.Statistics.CDNProtected)
	fmt.Printf("   SSL Certificates: %d\n\n", report.Statistics.SSLCertificates)

	// Show some example high-priority assets
	fmt.Printf("🔍 Notable High-Priority Assets:\n")
	count := 0
	for _, asset := range report.Assets {
		if asset.Priority >= infrastructure.PriorityHigh && count < 5 {
			fmt.Printf("   [%s] %s (confidence: %.2f)\n", asset.Type, asset.Value, asset.Confidence)
			count++
		}
	}
	fmt.Printf("\n")
}

// printOrganizationSummary prints organization context summary
func printOrganizationSummary(orgContext *discovery.OrganizationContext) {
	fmt.Printf("🏢 Organization Context:\n")
	fmt.Printf("   Name: %s\n", orgContext.OrgName)
	fmt.Printf("   Industry: %s\n", orgContext.IndustryType)
	fmt.Printf("   Domains: %d\n", len(orgContext.KnownDomains))
	fmt.Printf("   IP Ranges: %d\n", len(orgContext.KnownIPRanges))
	fmt.Printf("   Subsidiaries: %d\n", len(orgContext.Subsidiaries))
	fmt.Printf("   Technologies: %d\n\n", len(orgContext.Technologies))
}
