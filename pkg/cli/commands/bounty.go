// pkg/cli/commands/bounty.go - Bug Bounty Command Business Logic
//
// REFACTORED 2025-10-30: Extracted from cmd/orchestrator_main.go
// This contains the actual business logic for running bug bounty scans.
// cmd/orchestrator_main.go now only contains thin orchestration.

package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/internal/orchestrator"
	"github.com/CodeMonkeyCybersecurity/shells/internal/validation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/cli/display"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// BountyConfig contains configuration for bug bounty scanning
type BountyConfig struct {
	// Timeouts
	DiscoveryTimeout time.Duration
	ScanTimeout      time.Duration
	TotalTimeout     time.Duration

	// Discovery settings
	MaxAssets             int
	MaxDepth              int
	EnablePortScan        bool
	EnableWebCrawl        bool
	EnableDNS             bool
	SkipDiscovery         bool
	EnableSubdomainEnum   bool
	EnableCertTransparency bool

	// Testing settings
	EnableAuthTesting    bool
	EnableAPITesting     bool
	EnableLogicTesting   bool
	EnableSSRFTesting    bool
	EnableAccessControl  bool
	EnableSCIMTesting    bool
	EnableGraphQLTesting bool
	EnableIDORTesting    bool
	EnableSQLiTesting    bool
	EnableXSSTesting     bool
	EnableNucleiScan     bool

	// Scope settings
	ScopePath                      string
	EnableScopeValidation          bool
	EnableAssetRelationshipMapping bool
	BugBountyPlatform              string
	BugBountyProgram               string
	ScopeStrictMode                bool

	// Output settings
	ShowProgress bool
	Verbose      bool

	// Checkpointing
	EnableCheckpointing bool
	CheckpointInterval  time.Duration

	// Discovery configuration
	DiscoveryConfig *discovery.DiscoveryConfig
}

// RunBountyHunt executes a bug bounty hunt against the target
func RunBountyHunt(ctx context.Context, target string, config *BountyConfig, log *logger.Logger, store core.ResultStore) error {
	// Validate target (with scope if provided)
	var validationResult *validation.TargetValidationResult
	var err error

	if config.ScopePath != "" {
		validationResult, err = validation.ValidateWithScope(target, config.ScopePath)
		if err != nil {
			return fmt.Errorf("scope validation failed: %w", err)
		}
		color.Green("✓ Target authorized by scope file: %s\n\n", config.ScopePath)
	} else {
		validationResult = validation.ValidateTarget(target)
	}

	if !validationResult.Valid {
		return fmt.Errorf("target validation failed: %w", validationResult.Error)
	}

	// Display warnings if any
	if len(validationResult.Warnings) > 0 {
		color.Yellow("\n⚠️  Warnings:\n")
		for _, warning := range validationResult.Warnings {
			fmt.Printf("   • %s\n", warning)
		}
		fmt.Println()
	}

	// Use normalized target for scanning
	normalizedTarget := validationResult.NormalizedURL
	if normalizedTarget == "" {
		normalizedTarget = target
	}

	log.Infow("Target validated",
		"original_target", target,
		"normalized_target", normalizedTarget,
		"target_type", validationResult.TargetType,
	)

	// Print banner
	printBanner(normalizedTarget, config)

	// Create scan record to get scan ID
	scanID := fmt.Sprintf("bounty-%d-%x", time.Now().Unix(), time.Now().UnixNano()&0xFFFFFFFF)

	// Wrap logger with DBEventLogger to save events to database
	dbLogger := logger.NewDBEventLogger(log, store, scanID)

	// Convert to orchestrator config
	orchestratorConfig := convertToOrchestratorConfig(config)

	// Initialize orchestrator
	engine, err := orchestrator.NewBugBountyEngine(store, &NoopTelemetry{}, dbLogger.Logger, orchestratorConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize orchestrator: %w", err)
	}

	// Execute the full pipeline
	result, err := engine.Execute(ctx, normalizedTarget)
	if err != nil {
		return fmt.Errorf("orchestrator execution failed: %w", err)
	}

	// Display results
	displayResults(result)

	return nil
}

// BuildConfigFromFlags builds BountyConfig from cobra command flags
func BuildConfigFromFlags(cmd *cobra.Command) *BountyConfig {
	config := &BountyConfig{}

	// Parse timeouts
	if timeout, _ := cmd.Flags().GetDuration("timeout"); timeout > 0 {
		config.TotalTimeout = timeout
	} else {
		config.TotalTimeout = 30 * time.Minute
	}

	if discoveryTimeout, _ := cmd.Flags().GetDuration("discovery-timeout"); discoveryTimeout > 0 {
		config.DiscoveryTimeout = discoveryTimeout
	} else {
		config.DiscoveryTimeout = 5 * time.Minute
	}

	if scanTimeout, _ := cmd.Flags().GetDuration("scan-timeout"); scanTimeout > 0 {
		config.ScanTimeout = scanTimeout
	} else {
		config.ScanTimeout = 10 * time.Minute
	}

	// Parse discovery settings
	config.MaxAssets, _ = cmd.Flags().GetInt("max-assets")
	config.MaxDepth, _ = cmd.Flags().GetInt("max-depth")
	config.EnablePortScan, _ = cmd.Flags().GetBool("enable-port-scan")
	config.EnableWebCrawl, _ = cmd.Flags().GetBool("enable-web-crawl")
	config.EnableDNS, _ = cmd.Flags().GetBool("enable-dns")
	config.SkipDiscovery, _ = cmd.Flags().GetBool("skip-discovery")
	config.EnableSubdomainEnum, _ = cmd.Flags().GetBool("enable-subdomain-enum")
	config.EnableCertTransparency, _ = cmd.Flags().GetBool("enable-cert-transparency")

	// Parse testing settings
	config.EnableAuthTesting, _ = cmd.Flags().GetBool("enable-auth-testing")
	config.EnableAPITesting, _ = cmd.Flags().GetBool("enable-api-testing")
	config.EnableLogicTesting, _ = cmd.Flags().GetBool("enable-logic-testing")
	config.EnableSSRFTesting, _ = cmd.Flags().GetBool("enable-ssrf-testing")
	config.EnableAccessControl, _ = cmd.Flags().GetBool("enable-access-control")
	config.EnableSCIMTesting, _ = cmd.Flags().GetBool("enable-scim-testing")
	config.EnableGraphQLTesting, _ = cmd.Flags().GetBool("enable-graphql-testing")
	config.EnableIDORTesting, _ = cmd.Flags().GetBool("enable-idor-testing")
	config.EnableSQLiTesting, _ = cmd.Flags().GetBool("enable-sqli-testing")
	config.EnableXSSTesting, _ = cmd.Flags().GetBool("enable-xss-testing")
	config.EnableNucleiScan, _ = cmd.Flags().GetBool("enable-nuclei-scan")

	// Parse scope settings
	config.ScopePath, _ = cmd.Flags().GetString("scope")
	config.EnableScopeValidation, _ = cmd.Flags().GetBool("enable-scope-validation")
	config.BugBountyPlatform, _ = cmd.Flags().GetString("platform")
	config.BugBountyProgram, _ = cmd.Flags().GetString("program")
	config.ScopeStrictMode, _ = cmd.Flags().GetBool("scope-strict-mode")

	// Parse output settings
	config.ShowProgress, _ = cmd.Flags().GetBool("show-progress")
	config.Verbose, _ = cmd.Flags().GetBool("verbose")

	// Parse checkpointing settings
	config.EnableCheckpointing, _ = cmd.Flags().GetBool("enable-checkpointing")
	if interval, _ := cmd.Flags().GetDuration("checkpoint-interval"); interval > 0 {
		config.CheckpointInterval = interval
	} else {
		config.CheckpointInterval = 5 * time.Minute
	}

	return config
}

// Helper functions

func printBanner(target string, config *BountyConfig) {
	color.Cyan("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	color.Cyan("  SHELLS - Bug Bounty Hunting Mode\n")
	color.Cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("  Target: %s\n", color.GreenString(target))
	fmt.Printf("  Timeout: %s\n", config.TotalTimeout)
	if config.SkipDiscovery {
		fmt.Printf("  Mode: %s\n", color.YellowString("Direct Scan (skip discovery)"))
	} else {
		fmt.Printf("  Mode: %s\n", color.GreenString("Full Discovery + Testing"))
	}
	color.Cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
}

func convertToOrchestratorConfig(config *BountyConfig) orchestrator.BugBountyConfig {
	return orchestrator.BugBountyConfig{
		DiscoveryTimeout: config.DiscoveryTimeout,
		ScanTimeout:      config.ScanTimeout,
		TotalTimeout:     config.TotalTimeout,

		MaxAssets:             config.MaxAssets,
		MaxDepth:              config.MaxDepth,
		EnablePortScan:        config.EnablePortScan,
		EnableWebCrawl:        config.EnableWebCrawl,
		EnableDNS:             config.EnableDNS,
		SkipDiscovery:         config.SkipDiscovery,
		EnableSubdomainEnum:   config.EnableSubdomainEnum,
		EnableCertTransparency: config.EnableCertTransparency,

		EnableAuthTesting:    config.EnableAuthTesting,
		EnableAPITesting:     config.EnableAPITesting,
		EnableLogicTesting:   config.EnableLogicTesting,
		EnableSSRFTesting:    config.EnableSSRFTesting,
		EnableAccessControl:  config.EnableAccessControl,
		EnableSCIMTesting:    config.EnableSCIMTesting,
		EnableGraphQLTesting: config.EnableGraphQLTesting,
		EnableIDORTesting:    config.EnableIDORTesting,
		EnableSQLiTesting:    config.EnableSQLiTesting,
		EnableXSSTesting:     config.EnableXSSTesting,
		EnableNucleiScan:     config.EnableNucleiScan,

		EnableScopeValidation:          config.EnableScopeValidation,
		EnableAssetRelationshipMapping: config.EnableAssetRelationshipMapping,
		BugBountyPlatform:              config.BugBountyPlatform,
		BugBountyProgram:               config.BugBountyProgram,
		ScopeStrictMode:                config.ScopeStrictMode,

		ShowProgress: config.ShowProgress,
		Verbose:      config.Verbose,

		EnableCheckpointing: config.EnableCheckpointing,
		CheckpointInterval:  config.CheckpointInterval,

		DiscoveryConfig: config.DiscoveryConfig,
	}
}

func displayResults(result *orchestrator.BugBountyResult) {
	// Display organization footprinting results
	if result.OrganizationInfo != nil {
		displayOrganizationInfo(result.OrganizationInfo)
	}

	// Display asset discovery results
	if len(result.DiscoveredAssets) > 0 {
		displayAssetResults(result.DiscoveredAssets, result.DiscoverySession)
	}

	// Display findings summary
	if len(result.Findings) > 0 {
		display.DisplayTopFindings(result.Findings, 20)
	}

	// Display scan summary
	color.Cyan("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	color.Cyan("  Scan Summary\n")
	color.Cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("  Target: %s\n", result.Target)
	fmt.Printf("  Duration: %s\n", result.Duration)
	fmt.Printf("  Assets Discovered: %d\n", len(result.DiscoveredAssets))
	fmt.Printf("  Findings: %d\n", len(result.Findings))

	// Group by severity
	grouped := display.GroupFindingsBySeverity(result.Findings)
	fmt.Printf("    • Critical: %d\n", grouped["CRITICAL"])
	fmt.Printf("    • High: %d\n", grouped["HIGH"])
	fmt.Printf("    • Medium: %d\n", grouped["MEDIUM"])
	fmt.Printf("    • Low: %d\n", grouped["LOW"])
	fmt.Printf("    • Info: %d\n", grouped["INFO"])
	color.Cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
}

func displayOrganizationInfo(info interface{}) {
	// Simplified organization display
	// TODO: Properly type and implement OrganizationInfo display
	color.Cyan("\n🏢 Organization Footprinting\n")
	color.Cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("  Organization information available\n")
	color.Cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}

func displayAssetResults(assets []*discovery.Asset, session *discovery.DiscoverySession) {
	color.Cyan("\n🎯 Asset Discovery\n")
	color.Cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("  Total Assets: %d\n", len(assets))
	if session != nil {
		fmt.Printf("  High Value Assets: %d\n", session.HighValueAssets)
		fmt.Printf("  Discovery Status: %s\n", display.ColorStatus(string(session.Status)))
	}
	color.Cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}

// NoopTelemetry is a no-op implementation for testing
// TODO: Move to pkg/telemetry/noop.go
type NoopTelemetry struct{}

func (n *NoopTelemetry) RecordScan(scanType types.ScanType, duration float64, success bool) {}
func (n *NoopTelemetry) RecordFinding(severity types.Severity)                              {}
func (n *NoopTelemetry) RecordWorkerMetrics(status *types.WorkerStatus)                     {}
func (n *NoopTelemetry) Close() error                                                       { return nil }
