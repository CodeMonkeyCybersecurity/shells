// pkg/self/update.go - Shells self-update functionality following Assess→Intervene→Evaluate pattern
package self

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// UpdateConfig holds configuration for Shells self-update
type UpdateConfig struct {
	SourceDir      string // Path to shells git repository (default: /opt/shells)
	BinaryPath     string // Path to shells binary (default: /usr/local/bin/shells)
	BackupDir      string // Directory for backups (default: /usr/local/bin)
	MaxBackups     int    // Maximum number of backups to keep (default: 5)
	GitBranch      string // Git branch to update from (default: main)
	SkipBackup     bool   // Skip creating backup before update
	SkipValidation bool   // Skip validating new binary (not recommended)
}

// UpdateState represents the state of the Shells installation
type UpdateState struct {
	SourceExists   bool     // Whether source directory exists
	BinaryExists   bool     // Whether current binary exists
	GitRepository  bool     // Whether source is a git repository
	CurrentVersion string   // Current version/commit
	SourcePath     string   // Absolute path to source
	BinaryPath     string   // Absolute path to binary
	BackupPaths    []string // Paths to existing backups
}

// ShellsUpdater handles Shells self-update following Assess→Intervene→Evaluate pattern
type ShellsUpdater struct {
	logger *logger.Logger
	config *UpdateConfig
	state  *UpdateState
}

// NewShellsUpdater creates a new Shells updater
func NewShellsUpdater(log *logger.Logger, config *UpdateConfig) *ShellsUpdater {
	// Set defaults if not provided
	if config.SourceDir == "" {
		config.SourceDir = "/opt/shells"
	}
	if config.BinaryPath == "" {
		config.BinaryPath = "/usr/local/bin/shells"
	}
	if config.BackupDir == "" {
		config.BackupDir = "/usr/local/bin"
	}
	if config.MaxBackups == 0 {
		config.MaxBackups = 5
	}
	if config.GitBranch == "" {
		config.GitBranch = "main"
	}

	return &ShellsUpdater{
		logger: log,
		config: config,
		state:  &UpdateState{},
	}
}

// Assess checks the current state of the Shells installation
func (su *ShellsUpdater) Assess() (*UpdateState, error) {
	su.logger.Info("Assessing Shells installation state")

	// Check if source directory exists and is a git repository
	gitDir := filepath.Join(su.config.SourceDir, ".git")
	if _, err := os.Stat(gitDir); err == nil {
		su.state.SourceExists = true
		su.state.GitRepository = true
		su.state.SourcePath = su.config.SourceDir

		// Get current git commit
		cmd := exec.Command("git", "-C", su.config.SourceDir, "rev-parse", "--short", "HEAD")
		if output, err := cmd.Output(); err == nil {
			su.state.CurrentVersion = strings.TrimSpace(string(output))
		}
	} else if os.IsNotExist(err) {
		return nil, fmt.Errorf("shells source directory not found at %s - cannot self-update\n"+
			"Clone the repository first: git clone https://github.com/CodeMonkeyCybersecurity/shells %s",
			su.config.SourceDir, su.config.SourceDir)
	}

	// Check if binary exists
	if _, err := os.Stat(su.config.BinaryPath); err == nil {
		su.state.BinaryExists = true
		su.state.BinaryPath = su.config.BinaryPath
	}

	// Find existing backups
	backupPattern := filepath.Join(su.config.BackupDir, "shells.backup.*")
	if backups, err := filepath.Glob(backupPattern); err == nil {
		su.state.BackupPaths = backups
	}

	su.logger.Infow("Assessment complete",
		"source_exists", su.state.SourceExists,
		"git_repository", su.state.GitRepository,
		"binary_exists", su.state.BinaryExists,
		"current_version", su.state.CurrentVersion,
		"backup_count", len(su.state.BackupPaths),
	)

	return su.state, nil
}

// Update performs the complete Shells self-update following Assess→Intervene→Evaluate
func (su *ShellsUpdater) Update() error {
	su.logger.Info("Starting Shells self-update")

	// ASSESS - Check current state
	if _, err := su.Assess(); err != nil {
		return fmt.Errorf("assessment failed: %w", err)
	}

	// Create backup of current binary
	if !su.config.SkipBackup && su.state.BinaryExists {
		if err := su.CreateBackup(); err != nil {
			su.logger.Warnw("Failed to create backup", "error", err)
		} else {
			su.CleanupOldBackups()
		}
	}

	// INTERVENE - Pull latest code
	if err := su.PullLatestCode(); err != nil {
		return fmt.Errorf("failed to pull latest code: %w", err)
	}

	// Build new binary to temporary location
	tempBinary, err := su.BuildBinary()
	if err != nil {
		return fmt.Errorf("failed to build binary: %w", err)
	}
	defer os.Remove(tempBinary)

	// EVALUATE - Validate new binary
	if !su.config.SkipValidation {
		if err := su.ValidateBinary(tempBinary); err != nil {
			return fmt.Errorf("binary validation failed: %w", err)
		}
	}

	// Install new binary
	if err := su.InstallBinary(tempBinary); err != nil {
		return fmt.Errorf("failed to install new binary: %w", err)
	}

	// Final verification
	if err := su.Verify(); err != nil {
		su.logger.Warnw("Post-install verification failed", "error", err)
	}

	su.logger.Info(" Shells self-update completed successfully!")
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println(" Shells Updated Successfully!")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()
	fmt.Println(" Quick Start:")
	fmt.Println()
	fmt.Println("   shells serve")
	fmt.Println()
	fmt.Println("   This automatically:")
	fmt.Println("    Connects to PostgreSQL and creates tables")
	fmt.Println("    Starts web dashboard at http://localhost:8080")
	fmt.Println("    Starts worker service for scanning")
	fmt.Println("    Exposes REST API at /api/v1/*")
	fmt.Println()
	fmt.Println(" Dashboard: http://localhost:8080")
	fmt.Println()
	fmt.Println(" Run Scans:")
	fmt.Println("   shells example.com          # Full bug bounty pipeline")
	fmt.Println("   shells \"Acme Corp\"          # Discover company assets")
	fmt.Println()
	fmt.Println("  Configuration (No YAML files!):")
	fmt.Println("   shells serve --port 9000 --workers 5")
	fmt.Println("   export SHELLS_DATABASE_DSN=\"postgres://...\"")
	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()
	return nil
}

// CreateBackup creates a backup of the current binary
func (su *ShellsUpdater) CreateBackup() error {
	backupPath := fmt.Sprintf("%s/shells.backup.%d", su.config.BackupDir, time.Now().Unix())

	su.logger.Infow("Creating backup of current binary", "backup_path", backupPath)

	currentBinary, err := os.ReadFile(su.config.BinaryPath)
	if err != nil {
		return fmt.Errorf("failed to read current binary: %w", err)
	}

	if err := os.WriteFile(backupPath, currentBinary, 0755); err != nil {
		return fmt.Errorf("failed to write backup: %w", err)
	}

	su.logger.Infow("Backup created successfully",
		"backup_path", backupPath,
		"size_bytes", len(currentBinary),
	)

	return nil
}

// CleanupOldBackups removes old backup files, keeping only the most recent N
func (su *ShellsUpdater) CleanupOldBackups() {
	backupFiles, err := filepath.Glob(filepath.Join(su.config.BackupDir, "shells.backup.*"))
	if err != nil || len(backupFiles) <= su.config.MaxBackups {
		return
	}

	// Sort by name (which includes timestamp)
	sort.Strings(backupFiles)

	// Remove all but the last N
	for i := 0; i < len(backupFiles)-su.config.MaxBackups; i++ {
		if err := os.Remove(backupFiles[i]); err == nil {
			su.logger.Debugw("Removed old backup", "file", backupFiles[i])
		}
	}

	su.logger.Infow("Cleaned up old backups",
		"removed", len(backupFiles)-su.config.MaxBackups,
		"kept", su.config.MaxBackups,
	)
}

// PullLatestCode pulls the latest code from git
func (su *ShellsUpdater) PullLatestCode() error {
	su.logger.Infow("Pulling latest changes from git repository",
		"branch", su.config.GitBranch,
		"source_dir", su.config.SourceDir,
	)

	// First, fetch to see if there are updates
	fetchCmd := exec.Command("git", "-C", su.config.SourceDir, "fetch", "origin", su.config.GitBranch)
	if output, err := fetchCmd.CombinedOutput(); err != nil {
		su.logger.Errorw("Git fetch failed",
			"error", err,
			"output", string(output),
		)
		return fmt.Errorf("git fetch failed: %w", err)
	}

	// Check if we're behind
	cmd := exec.Command("git", "-C", su.config.SourceDir, "rev-list", "--count", "HEAD..origin/"+su.config.GitBranch)
	output, err := cmd.Output()
	if err == nil {
		behind := strings.TrimSpace(string(output))
		if behind == "0" {
			su.logger.Info("Already up to date - no updates available")
			return fmt.Errorf("already up to date")
		}
		su.logger.Infow("Updates available", "commits_behind", behind)
	}

	// Pull the changes
	pullCmd := exec.Command("git", "-C", su.config.SourceDir, "pull", "origin", su.config.GitBranch)
	pullOutput, err := pullCmd.CombinedOutput()
	if err != nil {
		su.logger.Errorw("Git pull failed",
			"error", err,
			"output", string(pullOutput),
		)
		return fmt.Errorf("git pull failed: %w", err)
	}

	su.logger.Infow("Git pull completed",
		"output", strings.TrimSpace(string(pullOutput)),
	)
	return nil
}

// BuildBinary builds the new Shells binary to a temporary location
func (su *ShellsUpdater) BuildBinary() (string, error) {
	tempBinary := fmt.Sprintf("/tmp/shells-update-%d", time.Now().Unix())

	su.logger.Infow("Building Shells binary",
		"temp_path", tempBinary,
		"source_dir", su.config.SourceDir,
	)

	// Run go mod tidy first to ensure dependencies are up to date
	tidyCmd := exec.Command("go", "mod", "tidy")
	tidyCmd.Dir = su.config.SourceDir
	if tidyOutput, err := tidyCmd.CombinedOutput(); err != nil {
		su.logger.Warnw("go mod tidy failed (continuing anyway)",
			"error", err,
			"output", string(tidyOutput),
		)
	}

	// Build command
	buildArgs := []string{"build", "-o", tempBinary, "."}
	buildCmd := exec.Command("go", buildArgs...)
	buildCmd.Dir = su.config.SourceDir

	// Set build environment
	buildCmd.Env = append(os.Environ(),
		"CGO_ENABLED=0", // Shells doesn't need CGO
		"GO111MODULE=on",
	)

	// Log build architecture
	if detectCmd := exec.Command("go", "env", "GOOS", "GOARCH"); detectCmd != nil {
		if detectOutput, err := detectCmd.Output(); err == nil {
			parts := strings.Split(strings.TrimSpace(string(detectOutput)), "\n")
			if len(parts) >= 2 {
				su.logger.Infow("Building for architecture",
					"os", strings.TrimSpace(parts[0]),
					"arch", strings.TrimSpace(parts[1]),
				)
			}
		}
	}

	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		su.logger.Errorw("Build failed",
			"error", err,
			"output", string(buildOutput),
		)
		os.Remove(tempBinary)
		return "", fmt.Errorf("build failed: %w\nOutput: %s", err, string(buildOutput))
	}

	// Validate the binary was created and is valid
	binaryInfo, err := os.Stat(tempBinary)
	if err != nil {
		return "", fmt.Errorf("built binary does not exist at %s: %w", tempBinary, err)
	}

	// Check the file size is reasonable (at least 10MB for shells binary with all features)
	const minBinarySize = 10 * 1024 * 1024 // 10MB
	if binaryInfo.Size() < minBinarySize {
		os.Remove(tempBinary)
		return "", fmt.Errorf("built binary is too small (%d bytes), expected at least %d bytes - build may have failed",
			binaryInfo.Size(), minBinarySize)
	}

	su.logger.Infow("Binary built successfully",
		"size_bytes", binaryInfo.Size(),
		"size_mb", fmt.Sprintf("%.2f MB", float64(binaryInfo.Size())/(1024*1024)),
	)

	// Set execute permissions
	if err := os.Chmod(tempBinary, 0755); err != nil {
		os.Remove(tempBinary)
		return "", fmt.Errorf("failed to set execute permissions: %w", err)
	}

	return tempBinary, nil
}

// ValidateBinary validates that the binary is executable and works correctly
func (su *ShellsUpdater) ValidateBinary(binaryPath string) error {
	su.logger.Info("Validating new binary")

	// Check if it's a valid executable binary
	fileCmd := exec.Command("file", binaryPath)
	if fileOutput, err := fileCmd.Output(); err == nil {
		fileType := strings.TrimSpace(string(fileOutput))
		su.logger.Infow("Binary file analysis", "file_type", fileType)

		if !strings.Contains(fileType, "executable") &&
			!strings.Contains(fileType, "ELF") &&
			!strings.Contains(fileType, "Mach-O") {
			return fmt.Errorf("built file is not an executable binary: %s", fileType)
		}
	}

	// Test the binary with --version flag
	testCmd := exec.Command(binaryPath, "--version")
	testOutput, err := testCmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(testOutput))

	if err != nil {
		// Try --help as fallback
		testCmd = exec.Command(binaryPath, "--help")
		testOutput, err = testCmd.CombinedOutput()
		outputStr = strings.TrimSpace(string(testOutput))

		if err != nil {
			su.logger.Errorw("Binary execution failed",
				"error", err,
				"binary", binaryPath,
				"output", outputStr,
			)

			// Provide helpful error message
			if strings.Contains(outputStr, "permission denied") {
				return fmt.Errorf("new binary cannot be executed (permission denied)")
			} else if strings.Contains(outputStr, "not found") {
				return fmt.Errorf("new binary has missing dependencies")
			} else if outputStr == "" {
				return fmt.Errorf("new binary crashed with no output: %w", err)
			}
			return fmt.Errorf("binary validation failed: %w", err)
		}
	}

	// Check that the output contains expected text (shells or cobra CLI markers)
	validMarkers := []string{
		"shells",
		"Shells",
		"Available Commands",
		"Usage:",
		"security scanning",
		"bug bounty",
	}

	hasValidMarker := false
	for _, marker := range validMarkers {
		if strings.Contains(outputStr, marker) {
			hasValidMarker = true
			break
		}
	}

	if !hasValidMarker {
		su.logger.Errorw("Binary produced unexpected output", "output", outputStr)
		return fmt.Errorf("new binary output doesn't look like Shells CLI")
	}

	su.logger.Infow("Binary validation successful",
		"has_shells_marker", strings.Contains(strings.ToLower(outputStr), "shells"),
		"has_commands", strings.Contains(outputStr, "Available Commands"),
		"has_usage", strings.Contains(outputStr, "Usage:"),
	)

	return nil
}

// InstallBinary atomically replaces the old binary with the new one
func (su *ShellsUpdater) InstallBinary(sourcePath string) error {
	su.logger.Infow("Installing new binary", "destination", su.config.BinaryPath)

	// Try atomic rename first (works if source and destination are on same filesystem)
	if err := os.Rename(sourcePath, su.config.BinaryPath); err != nil {
		// If rename fails, try copy (might be across filesystems)
		su.logger.Debugw("Rename failed, trying copy instead", "error", err)

		input, err := os.ReadFile(sourcePath)
		if err != nil {
			return fmt.Errorf("failed to read temp binary for copy: %w", err)
		}

		if err := os.WriteFile(su.config.BinaryPath, input, 0755); err != nil {
			return fmt.Errorf("failed to copy new binary to destination: %w", err)
		}

		// Remove the temporary file after successful copy
		os.Remove(sourcePath)
	}

	su.logger.Info("Binary installation completed successfully")
	return nil
}

// Verify verifies the installed binary works correctly
func (su *ShellsUpdater) Verify() error {
	su.logger.Info("Verifying installed Shells binary")

	// Test with --version
	versionCmd := exec.Command(su.config.BinaryPath, "--version")
	verifyOutput, err := versionCmd.CombinedOutput()

	if err != nil {
		// Try --help as fallback
		versionCmd = exec.Command(su.config.BinaryPath, "--help")
		verifyOutput, err = versionCmd.CombinedOutput()

		if err != nil {
			su.logger.Warnw("Could not verify Shells after update",
				"error", err,
				"output", string(verifyOutput),
			)
			return fmt.Errorf("verification failed: %w", err)
		}
	}

	outputStr := string(verifyOutput)
	if strings.Contains(strings.ToLower(outputStr), "shells") ||
		strings.Contains(outputStr, "Available Commands:") {
		su.logger.Info("Shells binary verified successfully")
		return nil
	}

	su.logger.Warnw("Shells binary verification produced unexpected output",
		"output", outputStr,
	)
	return fmt.Errorf("unexpected output from installed binary")
}
