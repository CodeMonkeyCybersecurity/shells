package cmd

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	dryRun bool
)

var selfUpdateCmd = &cobra.Command{
	Use:   "self-update",
	Short: "Update shells to the latest version from GitHub",
	Long: `Update shells to the latest version by pulling from the GitHub repository,
rebuilding the binary, and verifying the update with SHA256 checksums.

This command will:
1. Pull the latest code from the GitHub repository
2. Run ./install.sh to rebuild and install the binary
3. Compare SHA256 hashes to verify the update
4. Report the size of the new binary

The binary is always rebuilt after pulling to ensure you have the latest version,
even if no new commits were pulled.

Use --dry-run to preview the update without installing.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Initialize config but skip database for self-update
		return initConfig()
	},
	RunE: runSelfUpdate,
}

func init() {
	rootCmd.AddCommand(selfUpdateCmd)
	selfUpdateCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Check for updates without installing")
}

func runSelfUpdate(cmd *cobra.Command, args []string) error {
	fmt.Println("🔄 Starting shells self-update...")

	// Get current binary path
	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current binary path: %w", err)
	}

	fmt.Printf("📍 Current binary: %s\n", currentBinary)

	// Get current binary SHA256
	currentHash, err := calculateSHA256(currentBinary)
	if err != nil {
		return fmt.Errorf("failed to calculate current binary hash: %w", err)
	}

	fmt.Printf("🔐 Current SHA256: %s\n", currentHash)

	// Find the source directory (assume we're in a git repo)
	sourceDir, err := findGitRoot(currentBinary)
	if err != nil {
		return fmt.Errorf("failed to find git repository: %w", err)
	}

	fmt.Printf("📂 Source directory: %s\n", sourceDir)

	// Change to source directory
	originalDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	if err := os.Chdir(sourceDir); err != nil {
		return fmt.Errorf("failed to change to source directory: %w", err)
	}
	defer os.Chdir(originalDir)

	// Check if we have a clean working directory
	fmt.Println("🔍 Checking git status...")
	if err := checkGitStatus(); err != nil {
		return fmt.Errorf("git repository has uncommitted changes: %w", err)
	}

	// Pull latest changes
	fmt.Println("⬇️  Pulling latest changes from GitHub...")
	if err := pullLatestChanges(); err != nil {
		return fmt.Errorf("failed to pull latest changes: %w", err)
	}

	// Always rebuild after pulling latest changes to ensure binary is up to date
	fmt.Println("🔍 Building latest version...")

	if dryRun {
		fmt.Println("   (dry-run mode: would rebuild and install binary)")
		fmt.Println("🎯 Run without --dry-run to perform the actual update.")
		return nil
	}

	fmt.Println("   Building and installing new binary...")

	// Check if install.sh exists
	installScript := "./install.sh"
	if _, err := os.Stat(installScript); os.IsNotExist(err) {
		return fmt.Errorf("install.sh not found in repository root")
	}

	// Make install.sh executable
	if err := os.Chmod(installScript, 0755); err != nil {
		return fmt.Errorf("failed to make install.sh executable: %w", err)
	}

	// Run install script
	fmt.Println("🔨 Running install script...")
	fmt.Println("   Note: This may require sudo privileges...")
	installCmd := exec.Command("bash", "./install.sh")
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	installCmd.Stdin = os.Stdin // Allow for sudo password input
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("install script failed: %w", err)
	}

	// Calculate new binary hash
	newHash, err := calculateSHA256(currentBinary)
	if err != nil {
		return fmt.Errorf("failed to calculate new binary hash: %w", err)
	}

	// Compare hashes
	if currentHash == newHash {
		fmt.Println("ℹ️  Binary hash unchanged - no code changes affected the compiled binary.")
	} else {
		fmt.Printf("✅ Update successful!\n")
		fmt.Printf("   Old SHA256: %s\n", currentHash)
		fmt.Printf("   New SHA256: %s\n", newHash)
	}

	// Get binary size
	fileInfo, err := os.Stat(currentBinary)
	if err != nil {
		return fmt.Errorf("failed to get binary info: %w", err)
	}

	sizeMB := float64(fileInfo.Size()) / (1024 * 1024)
	fmt.Printf("📏 New binary size: %.2f MB\n", sizeMB)

	fmt.Println("🎉 Self-update completed successfully!")
	return nil
}

// calculateSHA256 calculates the SHA256 hash of a file
func calculateSHA256(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Log but don't fail - hash was already calculated
			fmt.Fprintf(os.Stderr, "Warning: failed to close file after hashing: %v\n", err)
		}
	}()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// findGitRoot finds the git repository root starting from the binary location
func findGitRoot(binaryPath string) (string, error) {
	dir := filepath.Dir(binaryPath)

	// Walk up the directory tree looking for .git
	for {
		gitDir := filepath.Join(dir, ".git")
		if _, err := os.Stat(gitDir); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached root
		}
		dir = parent
	}

	// If not found relative to binary, try current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("no git repository found")
	}

	dir = currentDir
	for {
		gitDir := filepath.Join(dir, ".git")
		if _, err := os.Stat(gitDir); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached root
		}
		dir = parent
	}

	return "", fmt.Errorf("no git repository found")
}

// checkGitStatus checks if the working directory is clean
func checkGitStatus() error {
	cmd := exec.Command("git", "status", "--porcelain")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check git status: %w", err)
	}

	if len(strings.TrimSpace(string(output))) > 0 {
		return fmt.Errorf("working directory has uncommitted changes. Please commit or stash them first")
	}

	return nil
}

// pullLatestChanges pulls the latest changes from the remote repository
func pullLatestChanges() error {
	// Fetch latest changes
	fetchCmd := exec.Command("git", "fetch", "origin")
	if err := fetchCmd.Run(); err != nil {
		return fmt.Errorf("failed to fetch from origin: %w", err)
	}

	// Get current branch
	branchCmd := exec.Command("git", "branch", "--show-current")
	branchOutput, err := branchCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get current branch: %w", err)
	}

	currentBranch := strings.TrimSpace(string(branchOutput))
	if currentBranch == "" {
		currentBranch = "main" // fallback to main
	}

	// Pull latest changes
	pullCmd := exec.Command("git", "pull", "origin", currentBranch)
	output, err := pullCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to pull changes: %w\nOutput: %s", err, string(output))
	}

	fmt.Printf("Git output: %s\n", string(output))
	return nil
}
