// cmd/orchestrator_main.go - Unified intelligent orchestrator for main command
package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/internal/orchestrator"
	"github.com/CodeMonkeyCybersecurity/shells/internal/validation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// runIntelligentOrchestrator is the main entry point that wires the orchestrator to the root command
func runIntelligentOrchestrator(ctx context.Context, target string, cmd *cobra.Command, log *logger.Logger, store core.ResultStore) error {
	// Check for scope file
	scopePath, _ := cmd.Flags().GetString("scope")

	// Validate target (with scope if provided)
	var validationResult *validation.TargetValidationResult
	var err error

	if scopePath != "" {
		validationResult, err = validation.ValidateWithScope(target, scopePath)
		if err != nil {
			return fmt.Errorf("scope validation failed: %w", err)
		}
		color.Green("✓ Target authorized by scope file: %s\n\n", scopePath)
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

	// Parse configuration from flags
	config := buildOrchestratorConfig(cmd)

	// Print banner
	printOrchestratorBanner(normalizedTarget, config)

	// Initialize orchestrator with real scanners
	engine, err := orchestrator.NewBugBountyEngine(store, &noopTelemetry{}, log, config)
	if err != nil {
		return fmt.Errorf("failed to initialize orchestrator: %w", err)
	}

	// Execute the full pipeline with normalized target
	result, err := engine.Execute(ctx, normalizedTarget)
	if err != nil {
		return fmt.Errorf("orchestrator execution failed: %w", err)
	}

	// Display results
	displayOrchestratorResults(result, config)

	// Save report if requested
	if outputFile := getOutputFile(cmd); outputFile != "" {
		if err := saveOrchestratorReport(result, outputFile); err != nil {
			log.Errorw("Failed to save report", "error", err, "file", outputFile)
		} else {
			fmt.Printf("\n✓ Detailed report saved to: %s\n", outputFile)
		}
	}

	return nil
}

// buildOrchestratorConfig builds orchestrator configuration from command flags
func buildOrchestratorConfig(cmd *cobra.Command) orchestrator.BugBountyConfig {
	// Check for quick/deep mode flags
	quick, _ := cmd.Flags().GetBool("quick")
	deep, _ := cmd.Flags().GetBool("deep")

	// Base configuration optimized for bug bounty
	config := orchestrator.DefaultBugBountyConfig()

	// Apply mode-specific settings
	if quick {
		// Quick mode: Faster, less comprehensive
		config.DiscoveryTimeout = 15 * time.Second
		config.ScanTimeout = 2 * time.Minute
		config.TotalTimeout = 5 * time.Minute
		config.MaxAssets = 20
		config.MaxDepth = 1
		config.EnableDNS = false
		config.EnablePortScan = false
		config.EnableWebCrawl = true
	} else if deep {
		// Deep mode: Comprehensive, slower
		config.DiscoveryTimeout = 2 * time.Minute
		config.ScanTimeout = 15 * time.Minute
		config.TotalTimeout = 30 * time.Minute
		config.MaxAssets = 200
		config.MaxDepth = 3
		config.EnableDNS = true
		config.EnablePortScan = true
		config.EnableWebCrawl = true
	}

	// Apply custom timeout if provided
	if timeout, _ := cmd.Flags().GetDuration("timeout"); timeout > 0 {
		config.TotalTimeout = timeout
	}

	// Always enable progress for main command
	config.ShowProgress = true
	config.Verbose = false

	return config
}

// printOrchestratorBanner displays the orchestrator banner
func printOrchestratorBanner(target string, config orchestrator.BugBountyConfig) {
	cyan := color.New(color.FgCyan, color.Bold)

	mode := "Standard"
	if config.TotalTimeout < 10*time.Minute {
		mode = "Quick"
	} else if config.TotalTimeout > 20*time.Minute {
		mode = "Deep"
	}

	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════════════════")
	cyan.Println("🎯 Shells - Intelligent Bug Bounty Automation")
	fmt.Printf("   Target: %s\n", target)
	fmt.Printf("   Mode: %s\n", mode)
	fmt.Printf("   Time: %s\n", time.Now().Format("15:04:05"))
	fmt.Println("══════════════════════════════════════════════════════════════════════")
	fmt.Println()
}

// displayOrchestratorResults displays results from the orchestrator
func displayOrchestratorResults(result *orchestrator.BugBountyResult, config orchestrator.BugBountyConfig) {
	fmt.Println()
	fmt.Println("═══ Orchestrator Summary ═══")
	fmt.Printf("Status: %s\n", colorStatus(result.Status))
	fmt.Printf("Duration: %s\n", result.Duration.Round(time.Second))
	fmt.Printf("Assets Discovered: %d\n", result.DiscoveredAt)
	fmt.Printf("Assets Tested: %d\n", result.TestedAssets)
	fmt.Printf("Total Findings: %d\n", result.TotalFindings)
	fmt.Println()

	// Display phase results
	if len(result.PhaseResults) > 0 {
		fmt.Println("═══ Pipeline Phases ═══")

		// Display in order: discovery, prioritization, testing phases
		phaseOrder := []string{"discovery", "auth", "scim", "api"}
		for _, phaseName := range phaseOrder {
			if pr, ok := result.PhaseResults[phaseName]; ok {
				status := colorPhaseStatus(pr.Status)
				phaseLine := fmt.Sprintf("[%s] %s", status, pr.Phase)

				if pr.Status == "completed" {
					phaseLine += color.GreenString(" ✓")
				} else if pr.Status == "failed" {
					phaseLine += color.RedString(" ✗")
				}

				phaseLine += fmt.Sprintf(" - %d findings in %s",
					pr.Findings,
					pr.Duration.Round(time.Second),
				)

				fmt.Println(phaseLine)

				if pr.Error != "" {
					color.New(color.FgRed).Printf("    Error: %s\n", pr.Error)
				}
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
		displayTopFindings(result.Findings, 10)

		if len(result.Findings) > 10 {
			fmt.Printf("\n... and %d more findings\n", len(result.Findings)-10)
			fmt.Println("\nUse 'shells results query' to see all findings")
		}
	} else {
		color.New(color.FgYellow).Println("ℹ No high-severity vulnerabilities found")
		fmt.Println("  The target appears to have good security posture,")
		fmt.Println("  or may require authenticated testing.")
	}

	fmt.Println()
	fmt.Printf("✓ Scan complete in %s\n", result.Duration.Round(time.Second))
	fmt.Printf("  Scan ID: %s\n", result.ScanID)

	// Print results location
	dbPath := "~/.shells/shells.db" // Default database path
	fmt.Printf("\n📊 Results saved to: %s\n", color.CyanString(dbPath))
	fmt.Printf("\nQuery results with:\n")
	fmt.Printf("  shells results query --scan-id %s\n", result.ScanID)
	fmt.Printf("  shells results stats\n")
	fmt.Printf("  shells results recent --limit 10\n")
}

// Helper functions

func getOutputFile(cmd *cobra.Command) string {
	// Check if output flag exists in root command
	if cmd.Flags().Lookup("output") != nil {
		output, _ := cmd.Flags().GetString("output")
		return output
	}
	return ""
}

func saveOrchestratorReport(result *orchestrator.BugBountyResult, filename string) error {
	// TODO: Implement JSON/HTML export
	return fmt.Errorf("report export not yet implemented")
}

// Note: Helper functions (colorStatus, colorSeverity, displayTopFindings, etc.)
// are now in display_helpers.go to avoid duplication across commands
