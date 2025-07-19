package security

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CommandExecutor provides secure command execution
type CommandExecutor struct {
	AllowedCommands map[string]bool
	Timeout         time.Duration
}

// NewCommandExecutor creates a new secure command executor
func NewCommandExecutor() *CommandExecutor {
	return &CommandExecutor{
		AllowedCommands: map[string]bool{
			"nmap":     true,
			"openssl":  true,
			"nslookup": true,
			"dig":      true,
			"httpx":    true,
			"nuclei":   true,
			"curl":     true,
			"wget":     true,
		},
		Timeout: 5 * time.Minute,
	}
}

// ExecuteCommand executes a command with security checks
func (ce *CommandExecutor) ExecuteCommand(ctx context.Context, command string, args ...string) ([]byte, error) {
	// Validate command is allowed
	if !ce.AllowedCommands[command] {
		return nil, fmt.Errorf("command not allowed: %s", command)
	}

	// Sanitize arguments
	sanitizedArgs := SanitizeCommand(args)

	// Create context with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, ce.Timeout)
	defer cancel()

	// Execute command
	cmd := exec.CommandContext(cmdCtx, command, sanitizedArgs...)

	// Set environment variables to prevent shell injection
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"SHELL=/bin/sh",
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("command execution failed: %w", err)
	}

	return output, nil
}

// ExecuteNmapScan executes nmap scan with validation
func (ce *CommandExecutor) ExecuteNmapScan(ctx context.Context, target, ports string) ([]byte, error) {
	// Validate inputs
	validTarget, err := ValidateTarget(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	validPorts, err := ValidatePortRange(ports)
	if err != nil {
		return nil, fmt.Errorf("invalid port range: %w", err)
	}

	// Create secure temporary file for output
	tempFile, err := os.CreateTemp("", "nmap_*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Execute nmap with safe arguments
	args := []string{
		"-oJ", tempFile.Name(),
		"-p", validPorts,
		validTarget,
	}

	_, err = ce.ExecuteCommand(ctx, "nmap", args...)
	if err != nil {
		return nil, err
	}

	// Read results from temp file
	return os.ReadFile(tempFile.Name())
}

// ExecuteSSLScan executes OpenSSL scan with validation
func (ce *CommandExecutor) ExecuteSSLScan(ctx context.Context, target string, port int) ([]byte, error) {
	// Validate inputs
	validTarget, err := ValidateTarget(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", port)
	}

	// Execute OpenSSL s_client with safe arguments
	connectStr := fmt.Sprintf("%s:%d", validTarget, port)
	args := []string{
		"s_client",
		"-connect", connectStr,
		"-servername", validTarget,
		"-verify_return_error",
		"-brief",
	}

	return ce.ExecuteCommand(ctx, "openssl", args...)
}

// ExecuteDNSLookup executes DNS lookup with validation
func (ce *CommandExecutor) ExecuteDNSLookup(ctx context.Context, target string) ([]byte, error) {
	// Validate target
	validTarget, err := ValidateTarget(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	// Use dig instead of nslookup for better security
	args := []string{
		"+short",
		validTarget,
	}

	return ce.ExecuteCommand(ctx, "dig", args...)
}

// CreateSecureTempFile creates a secure temporary file
func CreateSecureTempFile(prefix, suffix string) (*os.File, error) {
	// Create temp file with secure permissions
	tempFile, err := os.CreateTemp("", prefix+"_*"+suffix)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	// Set secure permissions (600 - owner read/write only)
	if err := tempFile.Chmod(0600); err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		return nil, fmt.Errorf("failed to set secure permissions: %w", err)
	}

	return tempFile, nil
}

// CreateSecureTempDir creates a secure temporary directory
func CreateSecureTempDir(prefix string) (string, error) {
	// Create temp directory with secure permissions
	tempDir, err := os.MkdirTemp("", prefix+"_*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Set secure permissions (700 - owner read/write/execute only)
	if err := os.Chmod(tempDir, 0700); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to set secure permissions: %w", err)
	}

	return tempDir, nil
}

// ValidateAndSanitizePath validates and sanitizes file paths
func ValidateAndSanitizePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path cannot be empty")
	}

	// Clean the path
	cleanPath := filepath.Clean(path)

	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("path traversal detected")
	}

	// Ensure path is within allowed directories
	allowedDirs := []string{"/tmp", "/var/tmp", "temp", "reports", "output"}
	allowed := false
	for _, dir := range allowedDirs {
		if strings.HasPrefix(cleanPath, dir) || strings.HasPrefix(cleanPath, "./"+dir) {
			allowed = true
			break
		}
	}

	if !allowed {
		return "", fmt.Errorf("path not in allowed directories")
	}

	return cleanPath, nil
}
