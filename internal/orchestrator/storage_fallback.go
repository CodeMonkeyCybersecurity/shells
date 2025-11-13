package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// FallbackStorage handles saving findings to JSON when database fails
type FallbackStorage struct {
	fallbackDir string
	logger      *logger.Logger
}

// NewFallbackStorage creates a fallback storage handler
func NewFallbackStorage(log *logger.Logger) *FallbackStorage {
	// Use /tmp by default, create subdirectory for shells
	fallbackDir := filepath.Join(os.TempDir(), "shells-fallback")
	os.MkdirAll(fallbackDir, 0700) // Owner only

	return &FallbackStorage{
		fallbackDir: fallbackDir,
		logger:      log,
	}
}

// SaveFindingsWithFallback attempts to save findings to database, falls back to JSON on failure
// Returns error only if BOTH database AND fallback fail
func (fs *FallbackStorage) SaveFindingsWithFallback(
	ctx context.Context,
	store interface{ SaveFindings(context.Context, []types.Finding) error },
	scanID string,
	findings []types.Finding,
) error {
	// Try database first with background context (survive Ctrl+C)
	// P0-1 FIX: Use background context for storage operations
	saveCtx, saveCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer saveCancel()

	err := store.SaveFindings(saveCtx, findings)
	if err == nil {
		// Success - no fallback needed
		return nil
	}

	// Database failed - use fallback
	fs.logger.Warnw("Database save failed - attempting fallback to JSON",
		"error", err,
		"findings_count", len(findings),
		"scan_id", scanID,
	)

	// Save to JSON file
	fallbackPath := filepath.Join(fs.fallbackDir, fmt.Sprintf("findings-%s.json", scanID))

	if fallbackErr := fs.saveToJSON(fallbackPath, findings); fallbackErr != nil {
		// Both failed - critical data loss
		return fmt.Errorf("CRITICAL: database save failed AND fallback failed - data may be lost:\n"+
			"  Database error: %v\n"+
			"  Fallback error: %v\n"+
			"  Findings count: %d",
			err, fallbackErr, len(findings))
	}

	// Fallback succeeded
	return fmt.Errorf("database save failed - findings saved to fallback location:\n"+
		"  Path: %s\n"+
		"  Findings: %d\n"+
		"  Original error: %v\n\n"+
		"ACTION REQUIRED: Import findings manually:\n"+
		"  shells import-findings %s",
		fallbackPath, len(findings), err, fallbackPath)
}

// saveToJSON writes findings to JSON file with atomic write
func (fs *FallbackStorage) saveToJSON(path string, findings []types.Finding) error {
	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal findings to JSON: %w", err)
	}

	// Atomic write: temp file + rename
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		os.Remove(tempPath) // Cleanup
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	fs.logger.Infow("Findings saved to fallback JSON",
		"path", path,
		"findings_count", len(findings),
		"file_size_bytes", len(data),
	)

	return nil
}

// GetFallbackPath returns the path where findings would be saved
func (fs *FallbackStorage) GetFallbackPath(scanID string) string {
	return filepath.Join(fs.fallbackDir, fmt.Sprintf("findings-%s.json", scanID))
}
