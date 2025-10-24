package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/internal/orchestrator"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/checkpoint"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var resumeCmd = &cobra.Command{
	Use:   "resume [scan-id]",
	Short: "Resume a previous scan from checkpoint",
	Long: `Resume a previously interrupted scan from its last checkpoint.

When a scan is interrupted (Ctrl+C, timeout, etc.), a checkpoint is saved
containing all progress made so far. This command loads that checkpoint and
continues the scan from where it left off.

Examples:
  # Resume by full scan ID
  shells resume bounty-1234567890-abc123

  # Resume by short ID suffix
  shells resume abc123

  # List available checkpoints
  shells resume --list

The resume command will:
  1. Load the checkpoint file
  2. Skip completed discovery phase
  3. Skip completed vulnerability tests
  4. Continue from the last phase that was running
  5. Preserve all findings collected so far`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check for --list flag
		listCheckpoints, _ := cmd.Flags().GetBool("list")
		if listCheckpoints {
			return listAvailableCheckpoints(cmd)
		}

		// Require scan ID if not listing
		if len(args) == 0 {
			return fmt.Errorf("scan ID required (use --list to see available checkpoints)")
		}

		scanID := args[0]
		return resumeFromCheckpoint(cmd, scanID)
	},
}

func init() {
	rootCmd.AddCommand(resumeCmd)

	resumeCmd.Flags().BoolP("list", "l", false, "List all available checkpoints")
	resumeCmd.Flags().Bool("force", false, "Force resume even if checkpoint seems corrupted")
}

// listAvailableCheckpoints displays all saved checkpoints
func listAvailableCheckpoints(cmd *cobra.Command) error {
	ctx := context.Background()

	// Initialize checkpoint manager
	manager, err := checkpoint.NewManager()
	if err != nil {
		return fmt.Errorf("failed to initialize checkpoint manager: %w", err)
	}

	// List checkpoints
	states, err := manager.List(ctx)
	if err != nil {
		return fmt.Errorf("failed to list checkpoints: %w", err)
	}

	if len(states) == 0 {
		color.Yellow("No saved checkpoints found\n")
		fmt.Println("\nCheckpoints are automatically saved when scans are interrupted.")
		fmt.Println("Run a scan with: shells example.com")
		return nil
	}

	// Display checkpoints
	fmt.Println()
	color.New(color.FgCyan, color.Bold).Println("Available Checkpoints")
	fmt.Println()

	for i, state := range states {
		// Calculate age
		age := time.Since(state.UpdatedAt)
		ageStr := formatDuration(age)

		// Format status
		status := fmt.Sprintf("%.0f%% complete", state.Progress)
		if state.CurrentPhase != "" {
			status = fmt.Sprintf("%s (%s phase)", status, state.CurrentPhase)
		}

		// Display checkpoint info
		fmt.Printf("%d. Scan ID: %s\n", i+1, color.CyanString(state.ScanID))
		fmt.Printf("   Target:   %s\n", state.Target)
		fmt.Printf("   Status:   %s\n", status)
		fmt.Printf("   Findings: %d\n", len(state.Findings))
		fmt.Printf("   Updated:  %s ago\n", ageStr)
		fmt.Printf("   Resume:   shells resume %s\n", state.ScanID)
		fmt.Println()
	}

	return nil
}

// resumeFromCheckpoint loads a checkpoint and continues the scan
func resumeFromCheckpoint(cmd *cobra.Command, scanID string) error {
	ctx := context.Background()

	color.New(color.FgCyan, color.Bold).Printf("\nResuming scan: %s\n\n", scanID)

	// Initialize checkpoint manager
	manager, err := checkpoint.NewManager()
	if err != nil {
		return fmt.Errorf("failed to initialize checkpoint manager: %w", err)
	}

	// Load checkpoint
	state, err := manager.Load(ctx, scanID)
	if err != nil {
		color.Red("Failed to load checkpoint: %v\n", err)
		fmt.Println("\nTip: Use 'shells resume --list' to see available checkpoints")
		return err
	}

	// Display checkpoint info
	fmt.Printf("Loaded checkpoint:\n")
	fmt.Printf("  Target:          %s\n", state.Target)
	fmt.Printf("  Progress:        %.0f%%\n", state.Progress)
	fmt.Printf("  Current Phase:   %s\n", state.CurrentPhase)
	fmt.Printf("  Completed Tests: %v\n", state.CompletedTests)
	fmt.Printf("  Findings So Far: %d\n", len(state.Findings))
	fmt.Printf("  Last Updated:    %s\n", state.UpdatedAt.Format(time.RFC3339))
	fmt.Println()

	// Warn if checkpoint is old
	age := time.Since(state.UpdatedAt)
	if age > 24*time.Hour {
		color.Yellow("Warning: Checkpoint is %s old. Target may have changed.\n\n", formatDuration(age))
	}

	// Restore configuration from metadata
	_ = buildOrchestratorConfigFromCheckpoint(cmd, state)

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Resume the scan with checkpoint state
	color.Green("✓ Resuming scan from checkpoint\n")
	color.Cyan("  Completed: %v\n", state.CompletedTests)
	color.Cyan("  Progress: %.0f%%\n\n", state.Progress)

	// Call orchestrator with resume
	return runOrchestratorWithResume(ctx, state, cmd, log, store)
}

// buildOrchestratorConfigFromCheckpoint extracts config from checkpoint metadata
func buildOrchestratorConfigFromCheckpoint(cmd *cobra.Command, state *checkpoint.State) interface{} {
	// Extract saved configuration from metadata
	// This preserves the original scan's settings (quick mode, timeout, etc.)

	if state.Metadata == nil {
		// No metadata, use default config
		return buildOrchestratorConfig(cmd)
	}

	// TODO: Properly restore orchestrator config from checkpoint metadata
	// For now, use default config
	return buildOrchestratorConfig(cmd)
}

// formatDuration formats a duration in human-readable form
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	days := int(d.Hours() / 24)
	return fmt.Sprintf("%dd", days)
}

// runOrchestratorWithResume runs the orchestrator in resume mode
func runOrchestratorWithResume(ctx context.Context, state *checkpoint.State, cmd *cobra.Command, log *logger.Logger, store core.ResultStore) error {
	// Parse configuration from flags (or restore from checkpoint metadata)
	config := buildOrchestratorConfig(cmd)
	
	// Print banner
	fmt.Println()
	color.New(color.FgCyan, color.Bold).Println("═══ Shells - Bug Bounty Automation (RESUME MODE) ═══")
	fmt.Printf("  Target: %s\n", state.Target)
	fmt.Printf("  Scan ID: %s\n", state.ScanID)
	fmt.Printf("  Checkpoint from: %s\n", state.UpdatedAt.Format(time.RFC1123))
	fmt.Println()
	
	// Initialize orchestrator
	engine, err := orchestrator.NewBugBountyEngine(store, &noopTelemetry{}, log, config)
	if err != nil {
		return fmt.Errorf("failed to initialize orchestrator: %w", err)
	}
	
	// Resume from checkpoint
	result, err := engine.ResumeFromCheckpoint(ctx, state)
	if err != nil {
		return fmt.Errorf("resume failed: %w", err)
	}
	
	// Display results (same as normal scan)
	if result.OrganizationInfo != nil {
		displayOrganizationFootprinting(result.OrganizationInfo)
	}
	
	if len(result.DiscoveredAssets) > 0 {
		displayAssetDiscoveryResults(result.DiscoveredAssets, result.DiscoverySession)
	}
	
	displayOrchestratorResults(result, config)
	
	fmt.Println()
	color.Green("✓ Resumed scan completed successfully\n")
	
	return nil
}
