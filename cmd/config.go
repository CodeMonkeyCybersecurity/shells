package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/shells/internal/credentials"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage scan profiles, API keys, and tool configurations",
	Long:  `Create, update, and manage scan profiles, API credentials, and tool-specific configurations.`,
}

func init() {
	rootCmd.AddCommand(configCmd)

	configCmd.AddCommand(configProfileCmd)
	configCmd.AddCommand(configScopeCmd)
	configCmd.AddCommand(configToolCmd)
	configCmd.AddCommand(configAPIKeysCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configClearCmd)
}

var configProfileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage scan profiles",
}

var configProfileCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new scan profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		description, _ := cmd.Flags().GetString("description")

		log.Infow("Creating profile", "name", name, "description", description)

		return nil
	},
}

var configProfileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all scan profiles",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Info("Listing profiles")
		return nil
	},
}

var configScopeCmd = &cobra.Command{
	Use:   "scope",
	Short: "Manage scan scope",
}

var configScopeAddCmd = &cobra.Command{
	Use:   "add [pattern]",
	Short: "Add pattern to scan scope",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pattern := args[0]

		log.Infow("Adding to scope", "pattern", pattern)

		return nil
	},
}

var configScopeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List scope patterns",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Info("Listing scope")
		return nil
	},
}

var configToolCmd = &cobra.Command{
	Use:   "tool",
	Short: "Configure tool-specific settings",
}

func init() {
	configProfileCmd.AddCommand(configProfileCreateCmd)
	configProfileCmd.AddCommand(configProfileListCmd)

	configScopeCmd.AddCommand(configScopeAddCmd)
	configScopeCmd.AddCommand(configScopeListCmd)

	configProfileCreateCmd.Flags().String("description", "", "Profile description")
	configClearCmd.Flags().BoolP("force", "f", false, "Force clear without confirmation")
}

var configAPIKeysCmd = &cobra.Command{
	Use:   "api-keys",
	Short: "Configure API keys for external services",
	Long: `Configure API keys for external services like CIRCL, PassiveTotal, Shodan, etc.
These credentials are encrypted and stored locally in ~/.shells/credentials.enc`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Create credentials manager
		credManager, err := credentials.NewManager(log)
		if err != nil {
			return fmt.Errorf("failed to initialize credentials manager: %w", err)
		}

		// Run interactive configuration
		if err := credManager.PromptForAllAPIs(); err != nil {
			return fmt.Errorf("failed to configure API keys: %w", err)
		}

		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Long:  `Display the current configuration including which API keys are configured (keys are not shown).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Create credentials manager
		credManager, err := credentials.NewManager(log)
		if err != nil {
			return fmt.Errorf("failed to initialize credentials manager: %w", err)
		}

		// Load and display configured APIs
		keys := credManager.GetAPIKeys()
		
		fmt.Println("\n🔧 Current Configuration")
		fmt.Println("═══════════════════════")
		
		fmt.Println("\n📡 API Keys:")
		apis := map[string]string{
			"CirclUsername":        "CIRCL",
			"PassiveTotalUsername": "PassiveTotal",
			"Shodan":               "Shodan",
			"CensysID":             "Censys",
			"VirusTotal":           "VirusTotal",
			"SecurityTrails":       "SecurityTrails",
		}

		configured := 0
		for key, name := range apis {
			if val, exists := keys[key]; exists && val != "" {
				fmt.Printf("   ✅ %s: Configured\n", name)
				configured++
			} else {
				fmt.Printf("   ❌ %s: Not configured\n", name)
			}
		}

		fmt.Printf("\n📊 Total: %d/%d APIs configured\n", configured, len(apis))

		// Show config file location
		homeDir, _ := os.UserHomeDir()
		configDir := filepath.Join(homeDir, ".shells")
		fmt.Printf("\n📁 Config directory: %s\n", configDir)
		
		return nil
	},
}

var configClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear stored API credentials",
	Long:  `Clear all stored API credentials. This action cannot be undone.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		force, _ := cmd.Flags().GetBool("force")
		
		if !force {
			fmt.Println("⚠️  This will delete all stored API credentials.")
			fmt.Print("Are you sure? [y/N]: ")
			
			var response string
			fmt.Scanln(&response)
			response = strings.TrimSpace(strings.ToLower(response))
			
			if response != "y" && response != "yes" {
				fmt.Println("Cancelled.")
				return nil
			}
		}

		// Remove credentials file
		homeDir, _ := os.UserHomeDir()
		credFile := filepath.Join(homeDir, ".shells", "credentials.enc")
		keyFile := filepath.Join(homeDir, ".shells", ".key")
		
		os.Remove(credFile)
		os.Remove(keyFile)
		
		fmt.Println("✅ API credentials cleared")
		
		return nil
	},
}
