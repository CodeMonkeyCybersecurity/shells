// cmd/self.go
package cmd

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/self"
	"github.com/spf13/cobra"
)

var selfCmd = &cobra.Command{
	Use:   "self",
	Short: "Self-management commands for Shells",
	Long: `The self command provides utilities for managing the Shells installation itself,
including updates, version checks, and configuration management.`,
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update Shells to the latest version",
	Long: `Safely update Shells to the latest version from the git repository.

This command will:
  1. Create a backup of your current binary
  2. Pull the latest code from the main branch
  3. Build the new binary
  4. Validate it works correctly
  5. Install it in place of the old version

Your database and configuration are NOT affected by updates.`,
	RunE: runUpdate,
}

var (
	updateBranch       string
	updateSkipBackup   bool
	updateSkipValidate bool
	updateSourceDir    string
)

func init() {
	// Add flags to update command
	updateCmd.Flags().StringVar(&updateBranch, "branch", "main", "Git branch to update from")
	updateCmd.Flags().BoolVar(&updateSkipBackup, "skip-backup", false, "Skip backing up current binary")
	updateCmd.Flags().BoolVar(&updateSkipValidate, "skip-validation", false, "Skip validating new binary (not recommended)")
	updateCmd.Flags().StringVar(&updateSourceDir, "source", "/opt/shells", "Path to shells git repository")

	// Add subcommands
	selfCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(selfCmd)
}

func runUpdate(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

	// Initialize logger
	logCfg := config.LoggerConfig{
		Level:  "info",
		Format: "console",
	}
	logger, err := logger.New(logCfg)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	logger.Infow("Starting Shells self-update",
		"branch", updateBranch,
		"source_dir", updateSourceDir,
	)

	// Create updater configuration
	updateConfig := &self.UpdateConfig{
		SourceDir:      updateSourceDir,
		BinaryPath:     "/usr/local/bin/shells",
		BackupDir:      "/usr/local/bin",
		MaxBackups:     5,
		GitBranch:      updateBranch,
		SkipBackup:     updateSkipBackup,
		SkipValidation: updateSkipValidate,
	}

	// Create updater
	updater := self.NewShellsUpdater(logger, updateConfig)

	// Execute update
	if err := updater.Update(); err != nil {
		logger.Errorw("Self-update failed", "error", err)
		return fmt.Errorf("self-update failed: %w", err)
	}

	duration := time.Since(startTime)
	logger.Infow("Self-update completed successfully",
		"duration", duration.String(),
	)

	// Run database migrations
	logger.Infow("Running database migrations",
		"component", "self_update",
	)
	fmt.Println()
	fmt.Println(" Running database migrations...")

	if err := runDatabaseMigrations(); err != nil {
		logger.Warnw("Database migration failed - you may need to run migrations manually",
			"component", "self_update",
			"error", err,
		)
		fmt.Printf("⚠️  Warning: Database migration failed: %v\n", err)
		fmt.Printf("   You can run migrations manually with: shells db migrate\n")
	} else {
		logger.Infow("Database migrations completed successfully",
			"component", "self_update",
		)
		fmt.Println(" Database migrations completed successfully!")
	}

	fmt.Println()
	log.Info(" Shells updated successfully!", "component", "self")
	fmt.Printf("   Duration: %s\n", duration.Round(time.Second))
	fmt.Println()
	log.Info("Run 'shells --version' to verify the new version", "component", "self")

	return nil
}
