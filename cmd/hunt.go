// cmd/hunt.go - Clean CLI wrapper for bug bounty orchestrator
package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/database"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/internal/orchestrator"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var huntCmd = &cobra.Command{
	Use:   "hunt [target]",
	Short: "[DEPRECATED] Run optimized bug bounty hunting pipeline - use 'shells [target]' instead",
	Long: `[DEPRECATED] This command is deprecated. Use the main command instead:
  shells example.com

The hunt command is now redundant with the main shells command, which provides
the same intelligent orchestration pipeline.

RECOMMENDATION: Use 'shells [target]' directly for bug bounty hunting.

Legacy documentation:
  1. Smart asset discovery (time-boxed to 30s)
  2. Asset prioritization (auth endpoints, APIs, admin panels)
  3. Parallel vulnerability testing (SAML, OAuth2, WebAuthn, SCIM, etc.)
  4. Structured results storage and reporting`,
	Args:       cobra.ExactArgs(1),
	RunE:       runHuntCommand,
	Deprecated: "use the main command 'shells [target]' instead, which provides the same functionality",
}

func init() {
	rootCmd.AddCommand(huntCmd)

	// Timeout configurations
	huntCmd.Flags().Duration("discovery-timeout", 30*time.Second, "Max time for asset discovery")
	huntCmd.Flags().Duration("scan-timeout", 5*time.Minute, "Max time for vulnerability scanning")
	huntCmd.Flags().Duration("total-timeout", 10*time.Minute, "Max time for entire pipeline")

	// Discovery settings
	huntCmd.Flags().Int("max-assets", 50, "Maximum number of assets to discover")
	huntCmd.Flags().Int("max-depth", 1, "Maximum crawl depth for discovery")
	huntCmd.Flags().Bool("enable-port-scan", true, "Enable port scanning during discovery")
	huntCmd.Flags().Bool("enable-web-crawl", true, "Enable web crawling during discovery")
	huntCmd.Flags().Bool("enable-dns", false, "Enable DNS enumeration (slow)")

	// Testing toggles
	huntCmd.Flags().Bool("enable-auth-testing", true, "Enable authentication vulnerability testing")
	huntCmd.Flags().Bool("enable-api-testing", true, "Enable API security testing")
	huntCmd.Flags().Bool("enable-logic-testing", true, "Enable business logic testing")
	huntCmd.Flags().Bool("enable-ssrf-testing", true, "Enable SSRF testing")
	huntCmd.Flags().Bool("enable-access-control", true, "Enable access control testing")
	huntCmd.Flags().Bool("enable-scim-testing", true, "Enable SCIM vulnerability testing")

	// Output settings
	huntCmd.Flags().Bool("show-progress", true, "Show real-time progress indicators")
	huntCmd.Flags().Bool("verbose", false, "Enable verbose output")
	huntCmd.Flags().String("output", "", "Save detailed report to file (JSON)")
}

func runHuntCommand(cmd *cobra.Command, args []string) error {
	// Display deprecation warning
	color.Yellow("\n⚠️  DEPRECATION WARNING: The 'hunt' command is deprecated.\n")
	color.White("   Use 'shells %s' instead for the same functionality.\n\n", args[0])

	target := args[0]

	// Parse flags
	discoveryTimeout, _ := cmd.Flags().GetDuration("discovery-timeout")
	scanTimeout, _ := cmd.Flags().GetDuration("scan-timeout")
	totalTimeout, _ := cmd.Flags().GetDuration("total-timeout")
	maxAssets, _ := cmd.Flags().GetInt("max-assets")
	maxDepth, _ := cmd.Flags().GetInt("max-depth")
	enablePortScan, _ := cmd.Flags().GetBool("enable-port-scan")
	enableWebCrawl, _ := cmd.Flags().GetBool("enable-web-crawl")
	enableDNS, _ := cmd.Flags().GetBool("enable-dns")
	enableAuthTesting, _ := cmd.Flags().GetBool("enable-auth-testing")
	enableAPITesting, _ := cmd.Flags().GetBool("enable-api-testing")
	enableLogicTesting, _ := cmd.Flags().GetBool("enable-logic-testing")
	enableSSRFTesting, _ := cmd.Flags().GetBool("enable-ssrf-testing")
	enableAccessControl, _ := cmd.Flags().GetBool("enable-access-control")
	enableSCIMTesting, _ := cmd.Flags().GetBool("enable-scim-testing")
	showProgress, _ := cmd.Flags().GetBool("show-progress")
	verbose, _ := cmd.Flags().GetBool("verbose")
	outputFile, _ := cmd.Flags().GetString("output")

	// Initialize logger
	logLevel := "error"
	if verbose {
		logLevel = "debug"
	}
	log, err := logger.New(config.LoggerConfig{
		Level:  logLevel,
		Format: "console",
	})
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Initialize database
	dbConfig := config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    "shells.db",
	}
	store, err := database.NewStore(dbConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer store.Close()

	// Initialize telemetry (no-op for now)
	telemetry := &noopTelemetry{}

	// Create bug bounty configuration
	bountyConfig := orchestrator.BugBountyConfig{
		DiscoveryTimeout:    discoveryTimeout,
		ScanTimeout:         scanTimeout,
		TotalTimeout:        totalTimeout,
		MaxAssets:           maxAssets,
		MaxDepth:            maxDepth,
		EnablePortScan:      enablePortScan,
		EnableWebCrawl:      enableWebCrawl,
		EnableDNS:           enableDNS,
		EnableAuthTesting:   enableAuthTesting,
		EnableAPITesting:    enableAPITesting,
		EnableLogicTesting:  enableLogicTesting,
		EnableSSRFTesting:   enableSSRFTesting,
		EnableAccessControl: enableAccessControl,
		EnableSCIMTesting:   enableSCIMTesting,
		ShowProgress:        showProgress,
		Verbose:             verbose,
	}

	// Initialize orchestrator
	engine, err := orchestrator.NewBugBountyEngine(store, telemetry, log, bountyConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize bug bounty engine: %w", err)
	}

	// Print banner
	printHuntBanner(target)

	// Execute bug bounty pipeline
	ctx := context.Background()
	result, err := engine.Execute(ctx, target)
	if err != nil {
		return fmt.Errorf("bug bounty scan failed: %w", err)
	}

	// Display results
	displayHuntResults(result)

	// Save detailed output if requested
	if outputFile != "" {
		if err := saveHuntReport(result, outputFile); err != nil {
			log.Errorw("Failed to save report", "error", err, "file", outputFile)
		} else {
			fmt.Printf("\n✓ Detailed report saved to: %s\n", outputFile)
		}
	}

	return nil
}

func printHuntBanner(target string) {
	blue := color.New(color.FgCyan, color.Bold)
	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════════════════")
	blue.Println("🎯 Shells Bug Bounty Hunter")
	fmt.Printf("   Target: %s\n", target)
	fmt.Printf("   Time: %s\n", time.Now().Format("15:04:05"))
	fmt.Println("══════════════════════════════════════════════════════════════════════")
	fmt.Println()
}

func displayHuntResults(result *orchestrator.BugBountyResult) {
	fmt.Println()
	fmt.Println("═══ Scan Summary ═══")
	fmt.Printf("Status: %s\n", colorStatus(result.Status))
	fmt.Printf("Duration: %s\n", result.Duration.Round(time.Second))
	fmt.Printf("Assets Discovered: %d\n", result.DiscoveredAt)
	fmt.Printf("Assets Tested: %d\n", result.TestedAssets)
	fmt.Printf("Total Findings: %d\n", result.TotalFindings)
	fmt.Println()

	// Display phase results
	if len(result.PhaseResults) > 0 {
		fmt.Println("═══ Phase Results ═══")
		for phase, pr := range result.PhaseResults {
			status := colorPhaseStatus(pr.Status)
			fmt.Printf("[%s] %s - %s (%d findings, %s)\n",
				status,
				phase,
				pr.Status,
				pr.Findings,
				pr.Duration.Round(time.Second),
			)
			if pr.Error != "" {
				color.New(color.FgRed).Printf("    Error: %s\n", pr.Error)
			}
		}
		fmt.Println()
	}

	// Display findings by severity
	if len(result.Findings) > 0 {
		fmt.Println("═══ Findings by Severity ═══")
		bySeverity := groupFindingsBySeverity(result.Findings)
		for _, severity := range []types.Severity{
			types.SeverityCritical,
			types.SeverityHigh,
			types.SeverityMedium,
			types.SeverityLow,
			types.SeverityInfo,
		} {
			count := bySeverity[severity]
			if count > 0 {
				fmt.Printf("%s: %d\n", colorSeverity(severity), count)
			}
		}
		fmt.Println()

		// Display top findings
		fmt.Println("═══ Top Findings ═══")
		displayTopFindings(result.Findings, 5)
	} else {
		color.New(color.FgGreen).Println("✓ No vulnerabilities found")
	}

	fmt.Println()
	fmt.Printf("✓ Scan complete in %s\n", result.Duration.Round(time.Second))
	fmt.Printf("  Scan ID: %s\n", result.ScanID)
}

func saveHuntReport(result *orchestrator.BugBountyResult, filename string) error {
	// TODO: Implement JSON export
	return fmt.Errorf("report export not yet implemented")
}

// Note: Helper functions (colorStatus, colorSeverity, displayTopFindings, noopTelemetry, etc.)
// are now in display_helpers.go to avoid duplication across commands
