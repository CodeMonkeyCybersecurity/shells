// cmd/self.go
package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	updateDryRun       bool
)

func init() {
	// Add flags to update command
	updateCmd.Flags().StringVar(&updateBranch, "branch", "main", "Git branch to update from")
	updateCmd.Flags().BoolVar(&updateSkipBackup, "skip-backup", false, "Skip backing up current binary")
	updateCmd.Flags().BoolVar(&updateSkipValidate, "skip-validation", false, "Skip validating new binary (not recommended)")
	updateCmd.Flags().StringVar(&updateSourceDir, "source", "/opt/shells", "Path to shells git repository")
	updateCmd.Flags().BoolVar(&updateDryRun, "dry-run", false, "Check for updates without installing")

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
		"dry_run", updateDryRun,
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

	// Dry run: just assess and report
	if updateDryRun {
		logger.Infow("Dry-run mode: assessing update availability")
		state, err := updater.Assess()
		if err != nil {
			return fmt.Errorf("assessment failed: %w", err)
		}

		fmt.Println()
		fmt.Println("Dry-run Assessment:")
		fmt.Println("===================")
		fmt.Printf("Source directory:  %s (exists: %v)\n", updateSourceDir, state.SourceExists)
		fmt.Printf("Git repository:    %v\n", state.GitRepository)
		fmt.Printf("Current version:   %s\n", state.CurrentVersion)
		fmt.Printf("Binary path:       %s (exists: %v)\n", updateConfig.BinaryPath, state.BinaryExists)
		fmt.Printf("Backup count:      %d\n", len(state.BackupPaths))
		fmt.Println()
		fmt.Println("Run without --dry-run to perform the actual update")
		return nil
	}

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
		fmt.Printf("Warning: Database migration failed: %v\n", err)
		fmt.Printf("   You can run migrations manually with: shells db migrate\n")
	} else {
		logger.Infow("Database migrations completed successfully",
			"component", "self_update",
		)
		fmt.Println(" Database migrations completed successfully!")
	}

	// Install/update Nuclei scanner
	logger.Infow("Checking Nuclei installation",
		"component", "self_update",
	)
	fmt.Println()
	fmt.Println(" Checking Nuclei scanner...")

	if err := ensureNucleiInstalled(logger); err != nil {
		logger.Warnw("Nuclei installation/update failed",
			"component", "self_update",
			"error", err,
		)
		fmt.Printf("Warning: Nuclei installation failed: %v\n", err)
		fmt.Printf("   Nuclei scanning will be disabled until installed\n")
		fmt.Printf("   You can install manually with: %s/scripts/install-nuclei.sh\n", updateSourceDir)
	} else {
		logger.Infow("Nuclei scanner ready",
			"component", "self_update",
		)
		fmt.Println(" Nuclei scanner ready!")
	}

	fmt.Println()
	log.Info(" Shells updated successfully!", "component", "self")
	fmt.Printf("   Duration: %s\n", duration.Round(time.Second))
	fmt.Println()
	log.Info("Run 'shells --version' to verify the new version", "component", "self")

	return nil
}

// ensureNucleiInstalled checks if Nuclei is installed and installs/updates it if needed
func ensureNucleiInstalled(logger *logger.Logger) error {
	// Check if nuclei is already in PATH
	nucleiPath, err := exec.LookPath("nuclei")
	if err == nil {
		// Nuclei found, check version and update templates
		logger.Infow("Nuclei already installed",
			"path", nucleiPath,
			"component", "nuclei_setup",
		)

		// Update templates
		cmd := exec.Command("nuclei", "-update-templates", "-silent")
		if err := cmd.Run(); err != nil {
			logger.Warnw("Failed to update Nuclei templates",
				"error", err,
				"component", "nuclei_setup",
			)
			// Don't fail if template update fails
		} else {
			logger.Infow("Nuclei templates updated",
				"component", "nuclei_setup",
			)
		}

		return nil
	}

	// Nuclei not found, need to install
	logger.Infow("Nuclei not found, installing from GitHub",
		"component", "nuclei_setup",
	)
	fmt.Println("   Installing Nuclei scanner...")

	// Install using go install
	installCmd := exec.Command("go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
	installCmd.Stdout = nil // Suppress output
	installCmd.Stderr = nil

	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("failed to install nuclei: %w", err)
	}

	// Verify installation
	nucleiPath, err = exec.LookPath("nuclei")
	if err != nil {
		// Try in Go bin directory
		goPath := os.Getenv("GOPATH")
		if goPath == "" {
			homeDir, _ := os.UserHomeDir()
			goPath = filepath.Join(homeDir, "go")
		}
		nucleiPath = filepath.Join(goPath, "bin", "nuclei")

		if _, err := os.Stat(nucleiPath); err != nil {
			return fmt.Errorf("nuclei installed but not found in PATH. Please add %s/bin to your PATH", goPath)
		}
	}

	logger.Infow("Nuclei installed successfully",
		"path", nucleiPath,
		"component", "nuclei_setup",
	)

	// Update templates
	fmt.Println("   Updating Nuclei templates...")
	templatesCmd := exec.Command(nucleiPath, "-update-templates", "-silent")
	if err := templatesCmd.Run(); err != nil {
		logger.Warnw("Failed to update Nuclei templates",
			"error", err,
			"component", "nuclei_setup",
		)
		// Don't fail - templates will update on first run
	} else {
		logger.Infow("Nuclei templates updated",
			"component", "nuclei_setup",
		)
	}

	fmt.Println("   Nuclei scanner installed successfully!")

	return nil
}
