package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/spf13/cobra"
)

var (
	discoverOutput    string
	discoverVerbose   bool
	discoverMaxDepth  int
	discoverMaxAssets int
)

// discoverCmd represents the discover command
var discoverCmd = &cobra.Command{
	Use:   "discover [target]",
	Short: "Discover assets related to a target",
	Long: `Discover assets related to a target such as domains, subdomains, IPs, and services.

The target can be:
- Company name: "Acme Corporation" 
- Domain: example.com
- Email: admin@example.com
- IP address: 192.168.1.1
- IP range: 192.168.1.0/24
- URL: https://example.com

Examples:
  shells discover example.com
  shells discover "Acme Corporation"
  shells discover admin@example.com --verbose
  shells discover 192.168.1.0/24 --max-assets 500`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		return runDiscoveryOnly(target)
	},
}

func init() {
	rootCmd.AddCommand(discoverCmd)

	discoverCmd.Flags().StringVarP(&discoverOutput, "output", "o", "text", "Output format (text, json)")
	discoverCmd.Flags().BoolVarP(&discoverVerbose, "verbose", "v", false, "Verbose output")
	discoverCmd.Flags().IntVar(&discoverMaxDepth, "max-depth", 3, "Maximum discovery depth")
	discoverCmd.Flags().IntVar(&discoverMaxAssets, "max-assets", 1000, "Maximum assets to discover")
}

// runDiscoveryOnly runs discovery without testing
func runDiscoveryOnly(target string) error {
	fmt.Printf(" Starting asset discovery for: %s\n", target)

	// Create discovery configuration
	config := discovery.DefaultDiscoveryConfig()
	config.MaxDepth = discoverMaxDepth
	config.MaxAssets = discoverMaxAssets

	// Create discovery engine
	engine := discovery.NewEngine(config, log.WithComponent("discovery"))

	// Start discovery
	session, err := engine.StartDiscovery(target)
	if err != nil {
		return fmt.Errorf("failed to start discovery: %w", err)
	}

	if discoverVerbose {
		fmt.Printf("📋 Discovery session: %s\n", session.ID)
		fmt.Printf("🎯 Target type: %s\n", session.Target.Type)
		fmt.Printf("🎲 Confidence: %.0f%%\n", session.Target.Confidence*100)
	}

	// Monitor discovery progress
	fmt.Println("⏳ Discovery in progress...")

	for {
		session, err := engine.GetSession(session.ID)
		if err != nil {
			return fmt.Errorf("failed to get session: %w", err)
		}

		if discoverVerbose {
			fmt.Printf("\r🔄 Progress: %.0f%% | Assets: %d | High-Value: %d",
				session.Progress, session.TotalDiscovered, session.HighValueAssets)
		}

		if session.Status == discovery.StatusCompleted {
			if discoverVerbose {
				fmt.Println("\n Discovery completed!")
			}
			break
		} else if session.Status == discovery.StatusFailed {
			fmt.Println("\n❌ Discovery failed!")
			for _, errMsg := range session.Errors {
				fmt.Printf("   Error: %s\n", errMsg)
			}
			return fmt.Errorf("discovery failed")
		}

		time.Sleep(1 * time.Second)
	}

	// Get final results
	session, err = engine.GetSession(session.ID)
	if err != nil {
		return fmt.Errorf("failed to get final session: %w", err)
	}

	// Output results based on format
	switch discoverOutput {
	case "json":
		return outputDiscoveryJSON(session)
	default:
		return outputDiscoveryText(session)
	}
}

// outputDiscoveryText outputs discovery results in text format
func outputDiscoveryText(session *discovery.DiscoverySession) error {
	fmt.Printf("\n Discovery Results for: %s\n", session.Target.Value)
	fmt.Printf("%s\n\n", strings.Repeat("=", len(session.Target.Value)+25))

	fmt.Printf("🎯 Target Information:\n")
	fmt.Printf("   Type: %s\n", session.Target.Type)
	fmt.Printf("   Confidence: %.0f%%\n", session.Target.Confidence*100)
	if len(session.Target.Metadata) > 0 {
		fmt.Printf("   Metadata:\n")
		for key, value := range session.Target.Metadata {
			fmt.Printf("     %s: %s\n", key, value)
		}
	}

	fmt.Printf("\n📈 Summary:\n")
	fmt.Printf("   Total Assets: %d\n", session.TotalDiscovered)
	fmt.Printf("   High-Value Assets: %d\n", session.HighValueAssets)
	fmt.Printf("   Relationships: %d\n", len(session.Relationships))
	fmt.Printf("   Duration: %v\n", time.Since(session.StartedAt).Round(time.Second))

	// Group assets by type
	assetsByType := make(map[discovery.AssetType][]*discovery.Asset)
	for _, asset := range session.Assets {
		assetsByType[asset.Type] = append(assetsByType[asset.Type], asset)
	}

	// Display assets by type
	if len(session.Assets) > 0 {
		fmt.Printf("\n Discovered Assets:\n")

		// Order of asset types to display
		typeOrder := []discovery.AssetType{
			discovery.AssetTypeDomain,
			discovery.AssetTypeSubdomain,
			discovery.AssetTypeURL,
			discovery.AssetTypeIP,
			discovery.AssetTypeService,
			discovery.AssetTypeLogin,
			discovery.AssetTypeAdmin,
			discovery.AssetTypePayment,
			discovery.AssetTypeAPI,
		}

		for _, assetType := range typeOrder {
			assets := assetsByType[assetType]
			if len(assets) == 0 {
				continue
			}

			fmt.Printf("\n   %s (%d):\n", assetType, len(assets))
			for _, asset := range assets {
				priority := ""
				if discovery.IsHighValueAsset(asset) {
					priority = " 🔥"
				}

				confidence := ""
				if asset.Confidence < 0.8 {
					confidence = fmt.Sprintf(" (%.0f%%)", asset.Confidence*100)
				}

				fmt.Printf("     • %s%s%s\n", asset.Value, confidence, priority)

				if discoverVerbose {
					if asset.Title != "" {
						fmt.Printf("       Title: %s\n", asset.Title)
					}
					if len(asset.Technology) > 0 {
						fmt.Printf("       Tech: %v\n", asset.Technology)
					}
					if asset.IP != "" && asset.Type != discovery.AssetTypeIP {
						fmt.Printf("       IP: %s\n", asset.IP)
					}
					if asset.Port != 0 {
						fmt.Printf("       Port: %d\n", asset.Port)
					}
				}
			}
		}

		// Display remaining asset types
		for assetType, assets := range assetsByType {
			found := false
			for _, orderedType := range typeOrder {
				if assetType == orderedType {
					found = true
					break
				}
			}
			if !found && len(assets) > 0 {
				fmt.Printf("\n   %s (%d):\n", assetType, len(assets))
				for _, asset := range assets {
					priority := ""
					if discovery.IsHighValueAsset(asset) {
						priority = " 🔥"
					}
					fmt.Printf("     • %s%s\n", asset.Value, priority)
				}
			}
		}
	}

	// Display high-value assets summary
	if session.HighValueAssets > 0 {
		fmt.Printf("\n🎯 High-Value Assets:\n")
		for _, asset := range session.Assets {
			if discovery.IsHighValueAsset(asset) {
				fmt.Printf("   🔥 %s (%s)\n", asset.Value, asset.Type)
				if asset.Title != "" {
					fmt.Printf("      %s\n", asset.Title)
				}
			}
		}
	}

	// Display relationships if verbose
	if discoverVerbose && len(session.Relationships) > 0 {
		fmt.Printf("\n🔗 Asset Relationships:\n")
		for _, rel := range session.Relationships {
			sourceAsset := session.Assets[rel.Source]
			targetAsset := session.Assets[rel.Target]
			if sourceAsset != nil && targetAsset != nil {
				fmt.Printf("   %s → %s (%s)\n",
					sourceAsset.Value, targetAsset.Value, rel.Type)
			}
		}
	}

	fmt.Printf("\n💡 Next Steps:\n")
	fmt.Printf("   • Run security tests: shells %s\n", session.Target.Value)
	fmt.Printf("   • View specific assets: shells discover %s --verbose\n", session.Target.Value)
	if session.HighValueAssets > 0 {
		fmt.Printf("   • Focus on high-value assets for manual testing\n")
	}

	return nil
}

// outputDiscoveryJSON outputs discovery results in JSON format
func outputDiscoveryJSON(session *discovery.DiscoverySession) error {
	// Create a simplified JSON structure
	result := map[string]interface{}{
		"target": map[string]interface{}{
			"value":      session.Target.Value,
			"type":       session.Target.Type,
			"confidence": session.Target.Confidence,
			"metadata":   session.Target.Metadata,
		},
		"summary": map[string]interface{}{
			"total_assets":      session.TotalDiscovered,
			"high_value_assets": session.HighValueAssets,
			"relationships":     len(session.Relationships),
			"duration":          time.Since(session.StartedAt).Seconds(),
		},
		"assets":        session.Assets,
		"relationships": session.Relationships,
		"session_id":    session.ID,
		"started_at":    session.StartedAt,
		"completed_at":  session.CompletedAt,
	}

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(jsonData))
	return nil
}
