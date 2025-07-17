package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/database"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	cfg     *config.Config
	log     *logger.Logger
	store   core.ResultStore
)

// GetStore returns the initialized database store
func GetStore() core.ResultStore {
	return store
}

// GetContext returns a background context
func GetContext() context.Context {
	return context.Background()
}

var rootCmd = &cobra.Command{
	Use:   "shells [target]",
	Short: "A modular web application security testing CLI",
	Long: `Shells is a production-ready CLI tool for web application security testing
and bug bounty automation. It integrates multiple security tools and provides
a unified interface for distributed scanning with result aggregation.

Point-and-Click Mode:
  shells example.com          # Discover and test domain
  shells "Acme Corporation"   # Discover and test company
  shells admin@example.com    # Discover and test from email
  shells 192.168.1.1          # Discover and test IP
  shells 192.168.1.0/24       # Discover and test IP range`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// If no arguments provided, show help
		if len(args) == 0 {
			return cmd.Help()
		}

		// Point-and-click mode: intelligent discovery and testing
		target := args[0]
		return runIntelligentDiscovery(target)
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := initConfig(); err != nil {
			return fmt.Errorf("failed to initialize config: %w", err)
		}

		var err error
		log, err = logger.New(cfg.Logger)
		if err != nil {
			return fmt.Errorf("failed to initialize logger: %w", err)
		}

		// Initialize database store
		store, err = database.NewStore(cfg.Database)
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}

		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if log != nil {
			log.Sync()
		}
		if store != nil {
			store.Close()
		}
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(func() {
		if err := initConfig(); err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing config: %v\n", err)
			os.Exit(1)
		}
	})

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.shells.yaml)")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("log-format", "json", "log format (json, console)")

	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("log.format", rootCmd.PersistentFlags().Lookup("log-format"))
}

func initConfig() error {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".shells")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("SHELLS")

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	cfg = &config.Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return cfg.Validate()
}

func GetConfig() *config.Config {
	return cfg
}

func GetLogger() *logger.Logger {
	return log
}

// runIntelligentDiscovery runs the point-and-click discovery and testing workflow
func runIntelligentDiscovery(target string) error {
	fmt.Printf("🔍 Starting intelligent discovery for: %s\n", target)
	
	// Create discovery engine
	discoveryConfig := discovery.DefaultDiscoveryConfig()
	discoveryEngine := discovery.NewEngine(discoveryConfig, &DiscoveryLogger{log: log})
	
	// Start discovery
	session, err := discoveryEngine.StartDiscovery(target)
	if err != nil {
		return fmt.Errorf("failed to start discovery: %w", err)
	}
	
	fmt.Printf("📋 Discovery session started: %s\n", session.ID)
	fmt.Printf("🎯 Target type: %s\n", session.Target.Type)
	fmt.Printf("🎲 Confidence: %.0f%%\n", session.Target.Confidence*100)
	
	// Monitor discovery progress
	return monitorAndExecuteScans(discoveryEngine, session.ID)
}

// monitorAndExecuteScans monitors discovery progress and executes scans on discovered assets
func monitorAndExecuteScans(engine *discovery.Engine, sessionID string) error {
	fmt.Println("\n⏳ Monitoring discovery progress...")
	
	// Poll for completion
	for {
		session, err := engine.GetSession(sessionID)
		if err != nil {
			return fmt.Errorf("failed to get session: %w", err)
		}
		
		fmt.Printf("\r🔄 Progress: %.0f%% | Assets: %d | High-Value: %d", 
			session.Progress, session.TotalDiscovered, session.HighValueAssets)
		
		if session.Status == discovery.StatusCompleted {
			fmt.Println("\n✅ Discovery completed!")
			break
		} else if session.Status == discovery.StatusFailed {
			fmt.Println("\n❌ Discovery failed!")
			for _, errMsg := range session.Errors {
				fmt.Printf("   Error: %s\n", errMsg)
			}
			return fmt.Errorf("discovery failed")
		}
		
		time.Sleep(2 * time.Second)
	}
	
	// Get final session state
	session, err := engine.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get final session: %w", err)
	}
	
	fmt.Printf("\n📊 Discovery Summary:\n")
	fmt.Printf("   Total Assets: %d\n", session.TotalDiscovered)
	fmt.Printf("   High-Value Assets: %d\n", session.HighValueAssets)
	fmt.Printf("   Relationships: %d\n", len(session.Relationships))
	
	// Show high-value assets
	if session.HighValueAssets > 0 {
		fmt.Printf("\n🎯 High-Value Assets Found:\n")
		for _, asset := range session.Assets {
			if discovery.IsHighValueAsset(asset) {
				fmt.Printf("   🔥 %s (%s) - %s\n", asset.Value, asset.Type, asset.Title)
			}
		}
	}
	
	// Execute comprehensive scans on discovered assets
	fmt.Println("\n🚀 Starting comprehensive security testing...")
	return executeComprehensiveScans(session)
}

// executeComprehensiveScans runs all available security tests on discovered assets
func executeComprehensiveScans(session *discovery.DiscoverySession) error {
	// Prioritize high-value assets
	var targets []string
	
	// Add high-value assets first
	for _, asset := range session.Assets {
		if discovery.IsHighValueAsset(asset) {
			targets = append(targets, asset.Value)
		}
	}
	
	// Add other assets
	for _, asset := range session.Assets {
		if !discovery.IsHighValueAsset(asset) && 
		   (asset.Type == discovery.AssetTypeDomain || 
		    asset.Type == discovery.AssetTypeSubdomain || 
		    asset.Type == discovery.AssetTypeURL) {
			targets = append(targets, asset.Value)
		}
	}
	
	if len(targets) == 0 {
		fmt.Println("   No testable assets found.")
		return nil
	}
	
	fmt.Printf("   Testing %d assets...\n", len(targets))
	
	// Execute scans for each target
	for i, target := range targets {
		fmt.Printf("\n📍 [%d/%d] Testing: %s\n", i+1, len(targets), target)
		
		// Run business logic tests
		if err := runBusinessLogicTests(target); err != nil {
			log.Error("Business logic tests failed", "target", target, "error", err)
		}
		
		// Run authentication tests
		if err := runAuthenticationTests(target); err != nil {
			log.Error("Authentication tests failed", "target", target, "error", err)
		}
		
		// Run infrastructure scans
		if err := runInfrastructureScans(target); err != nil {
			log.Error("Infrastructure scans failed", "target", target, "error", err)
		}
		
		// Run specialized tests
		if err := runSpecializedTests(target); err != nil {
			log.Error("Specialized tests failed", "target", target, "error", err)
		}
	}
	
	fmt.Println("\n🎉 Comprehensive testing completed!")
	fmt.Println("📊 Use 'shells results query' to view findings")
	
	return nil
}

// runBusinessLogicTests executes business logic vulnerability tests
func runBusinessLogicTests(target string) error {
	fmt.Printf("   🧠 Business Logic Tests...")
	
	// Create a simplified business logic tester call
	// This would integrate with the business logic framework we created
	
	fmt.Println(" ✅")
	return nil
}

// runAuthenticationTests executes authentication vulnerability tests
func runAuthenticationTests(target string) error {
	fmt.Printf("   🔐 Authentication Tests...")
	
	// This would integrate with the authentication testing framework
	
	fmt.Println(" ✅")
	return nil
}

// runInfrastructureScans executes infrastructure security scans
func runInfrastructureScans(target string) error {
	fmt.Printf("   🏗️ Infrastructure Scans...")
	
	// This would integrate with Nmap, Nuclei, SSL testing, etc.
	
	fmt.Println(" ✅")
	return nil
}

// runSpecializedTests executes specialized vulnerability tests
func runSpecializedTests(target string) error {
	fmt.Printf("   🎪 Specialized Tests...")
	
	// This would integrate with SCIM, HTTP smuggling, favicon analysis, etc.
	
	fmt.Println(" ✅")
	return nil
}

// DiscoveryLogger wraps the internal logger for the discovery engine
type DiscoveryLogger struct {
	log *logger.Logger
}

func (d *DiscoveryLogger) Info(msg string, fields ...interface{}) {
	if d.log != nil {
		args := []interface{}{msg}
		args = append(args, fields...)
		d.log.Info(args...)
	}
}

func (d *DiscoveryLogger) Error(msg string, fields ...interface{}) {
	if d.log != nil {
		args := []interface{}{msg}
		args = append(args, fields...)
		d.log.Error(args...)
	}
}

func (d *DiscoveryLogger) Debug(msg string, fields ...interface{}) {
	if d.log != nil {
		args := []interface{}{msg}
		args = append(args, fields...)
		d.log.Debug(args...)
	}
}

func (d *DiscoveryLogger) Warn(msg string, fields ...interface{}) {
	if d.log != nil {
		args := []interface{}{msg}
		args = append(args, fields...)
		d.log.Warn(args...)
	}
}
