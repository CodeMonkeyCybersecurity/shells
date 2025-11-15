// Package checkpoint provides graceful shutdown and resume capability for long-running scans.
//
// CHECKPOINT SYSTEM ARCHITECTURE:
//
// The checkpoint system enables shells to save scan progress at regular intervals and on
// graceful shutdown (Ctrl+C, SIGTERM). This allows users to resume interrupted scans from
// their last checkpoint, preserving all discovered assets, completed tests, and findings.
//
// KEY FEATURES:
//
// 1. Automatic Checkpoint Saves:
//   - After each major phase (discovery, prioritization, testing, storage)
//   - Every 5 minutes during long-running operations (configurable)
//   - On graceful shutdown (Ctrl+C, SIGTERM)
//
// 2. Resume Capability:
//   - Load checkpoint by full scan ID or short suffix
//   - Skip completed phases and tests
//   - Preserve all findings collected so far
//   - Continue from exact point of interruption
//
// 3. Storage Format:
//   - Human-readable JSON files in ~/.shells/checkpoints/
//   - Each checkpoint file named: {scan_id}.json
//   - Includes: progress, current phase, completed tests, findings, metadata
//
// 4. Automatic Cleanup:
//   - Old checkpoints (>7 days) automatically cleaned up
//   - Successful scan completion deletes checkpoint
//   - Manual cleanup via shells resume --cleanup
//
// USAGE EXAMPLES:
//
//	// Basic scan (automatically saves checkpoints)
//	shells example.com
//	// ... press Ctrl+C during scan ...
//	// Progress saved to checkpoint: bounty-1234567890-abc123
//	// Resume with: shells resume abc123
//
//	// Resume interrupted scan
//	shells resume abc123
//
//	// List available checkpoints
//	shells resume --list
//
// INTEGRATION POINTS:
//
// 1. cmd/root.go: Initializes shutdown handler, registers checkpoint save on Ctrl+C
// 2. internal/orchestrator/bounty_engine.go: Saves checkpoints after each phase
// 3. cmd/resume.go: Loads checkpoint and resumes scan from last phase
// 4. pkg/shutdown/graceful.go: Coordinates graceful shutdown with checkpoint save
//
// CHECKPOINT STATE STRUCTURE:
//
// State contains:
//   - ScanID: Unique identifier for resume
//   - Target: Original target being scanned
//   - Progress: Percentage complete (0-100)
//   - CurrentPhase: discovery, prioritization, testing, storage
//   - DiscoveredAssets: All assets found during discovery phase
//   - CompletedTests: List of completed test suites (auth, scim, nmap, etc.)
//   - Findings: All vulnerabilities found so far
//   - Metadata: Scan configuration (quick mode, timeout, flags, etc.)
//
// CHECKPOINT LIFECYCLE:
//
// 1. Scan Start:
//   - Initialize checkpoint state with scan ID and target
//   - Save initial checkpoint (0% complete)
//
// 2. During Scan:
//   - Save checkpoint after each major phase (25%, 35%, 85%, 95%)
//   - Save periodic checkpoints every 5 minutes
//   - Update progress, current phase, completed tests, findings
//
// 3. Graceful Shutdown (Ctrl+C):
//   - Shutdown handler triggers checkpoint save
//   - Save current progress with all accumulated data
//   - Display resume command to user
//
// 4. Scan Completion:
//   - Save final checkpoint (100% complete)
//   - Optionally delete checkpoint (scan complete, no need to resume)
//
// 5. Resume:
//   - Load checkpoint state from disk
//   - Skip completed phases (discovery if already done)
//   - Skip completed tests (auth, scim, etc. if already run)
//   - Continue from current phase with preserved findings
//
// CHECKPOINT FILE FORMAT (JSON):
//
//	{
//	  "scan_id": "bounty-1234567890-abc123",
//	  "target": "example.com",
//	  "progress": 50.0,
//	  "current_phase": "testing",
//	  "created_at": "2025-10-06T10:00:00Z",
//	  "updated_at": "2025-10-06T10:15:00Z",
//	  "discovered_assets": [...],
//	  "completed_tests": ["auth", "scim"],
//	  "findings": [...],
//	  "metadata": {
//	    "quick_mode": false,
//	    "timeout": "30m",
//	    "enable_dns": true
//	  }
//	}
//
// IMPLEMENTATION STATUS:
//
// ✓ Checkpoint data structures (State, Asset, Manager)
// ✓ Save/Load/List/Delete checkpoint operations
// ✓ Automatic cleanup of old checkpoints
// ✓ Resume command (shells resume [scan-id])
// ✓ Integration with shutdown handler
// ○ Full orchestrator resume integration (skipping completed phases)
// ○ Periodic checkpoint saves during long operations
// ○ Checkpoint save in orchestrator after each phase
//
// FUTURE ENHANCEMENTS:
//
// - Checkpoint compression for large scans (gzip)
// - Remote checkpoint storage (S3, database)
// - Checkpoint diff/comparison between runs
// - Checkpoint repair/recovery for corrupted files
// - Checkpoint export/import for scan migration
package checkpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// State represents a saved checkpoint of a scan's progress
// This allows resuming long-running scans after interruption (Ctrl+C, crashes, etc.)
type State struct {
	// Core identifiers
	ScanID    string    `json:"scan_id"`
	Target    string    `json:"target"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Progress tracking
	Progress     float64 `json:"progress"`      // 0-100 percentage complete
	CurrentPhase string  `json:"current_phase"` // discovery, prioritization, testing, storage

	// Discovery results (to avoid re-running discovery)
	DiscoveredAssets []Asset `json:"discovered_assets,omitempty"`

	// Testing progress (which tests have been completed)
	CompletedTests []string `json:"completed_tests"` // e.g., ["auth", "scim", "nmap"]

	// Findings accumulated so far
	Findings []types.Finding `json:"findings,omitempty"`

	// Configuration and metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate checks if checkpoint state is valid and safe to use
// P0-11/12/25 FIX: Validate all required fields before resume
func (s *State) Validate() error {
	// P0-11: Check required string fields
	if s.ScanID == "" {
		return fmt.Errorf("invalid checkpoint: empty scan_id")
	}
	if s.Target == "" {
		return fmt.Errorf("invalid checkpoint: empty target")
	}
	if s.CurrentPhase == "" {
		return fmt.Errorf("invalid checkpoint: empty current_phase")
	}

	// P0-25: Check timestamps
	if s.CreatedAt.IsZero() {
		return fmt.Errorf("invalid checkpoint: zero created_at timestamp")
	}
	if s.UpdatedAt.IsZero() {
		return fmt.Errorf("invalid checkpoint: zero updated_at timestamp")
	}
	if s.UpdatedAt.Before(s.CreatedAt) {
		return fmt.Errorf("invalid checkpoint: updated_at before created_at")
	}

	// P0-12: Validate progress percentage
	if s.Progress < 0 || s.Progress > 100 {
		return fmt.Errorf("invalid checkpoint: progress %.2f out of range [0, 100]", s.Progress)
	}

	// Validate current phase value
	validPhases := map[string]bool{
		"initialized":    true,
		"footprinting":   true,
		"scope_import":   true,
		"discovery":      true,
		"prioritization": true,
		"testing":        true,
		"storage":        true,
		"completed":      true,
	}
	if !validPhases[s.CurrentPhase] {
		return fmt.Errorf("invalid checkpoint: unknown phase '%s'", s.CurrentPhase)
	}

	return nil
}

// Asset is a simplified version of discovery.Asset for checkpoint serialization
// P0-16 FIX: Added missing fields (Priority, Source, Confidence, DiscoveredAt, LastSeen)
type Asset struct {
	ID           string            `json:"id"`
	Type         string            `json:"type"`
	Value        string            `json:"value"`
	Domain       string            `json:"domain,omitempty"`
	IP           string            `json:"ip,omitempty"`
	Port         int               `json:"port,omitempty"`
	Protocol     string            `json:"protocol,omitempty"`
	Title        string            `json:"title,omitempty"`
	Technology   []string          `json:"technology,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Priority     int               `json:"priority"`            // P0-16: Asset testing priority
	Source       string            `json:"source,omitempty"`    // P0-16: Discovery source (crt.sh, dns, etc.)
	Confidence   float64           `json:"confidence"`          // P0-16: Reliability score
	DiscoveredAt time.Time         `json:"discovered_at"`       // P0-16: When first found
	LastSeen     time.Time         `json:"last_seen,omitempty"` // P0-16: When last confirmed
}

// Manager handles checkpoint storage and retrieval
type Manager struct {
	checkpointDir string
}

// NewManager creates a new checkpoint manager
// Checkpoints are stored in ~/.shells/checkpoints/ by default
func NewManager() (*Manager, error) {
	// Get user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	checkpointDir := filepath.Join(homeDir, ".shells", "checkpoints")

	// Create checkpoint directory if it doesn't exist
	if err := os.MkdirAll(checkpointDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create checkpoint directory: %w", err)
	}

	return &Manager{
		checkpointDir: checkpointDir,
	}, nil
}

// Save writes a checkpoint state to disk
// Checkpoint files are named: {scan_id}.json
// Returns the absolute path to the saved checkpoint file
func (m *Manager) Save(ctx context.Context, state *State) error {
	if state.ScanID == "" {
		return fmt.Errorf("checkpoint state must have a scan_id")
	}

	// Update timestamp
	state.UpdatedAt = time.Now()

	// Marshal to JSON with indentation for human readability
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint state: %w", err)
	}

	// P0-13 FIX: Atomic write using temp file + rename
	// This ensures that if the process crashes during write, we don't leave a
	// corrupted checkpoint file. The rename operation is atomic on POSIX systems.

	finalFilename := filepath.Join(m.checkpointDir, fmt.Sprintf("%s.json", state.ScanID))
	tempFilename := filepath.Join(m.checkpointDir, fmt.Sprintf(".%s.json.tmp", state.ScanID))

	// P1-19 FIX: Write with 0600 permissions (owner read/write only) for security
	// Checkpoints may contain sensitive scan targets and vulnerability findings
	if err := os.WriteFile(tempFilename, data, 0600); err != nil {
		return fmt.Errorf("failed to write temp checkpoint file: %w", err)
	}

	// Atomic rename: if this fails, temp file remains and final file is unchanged
	if err := os.Rename(tempFilename, finalFilename); err != nil {
		// Cleanup temp file on failure
		os.Remove(tempFilename)
		return fmt.Errorf("failed to atomically save checkpoint: %w", err)
	}

	return nil
}

// Load reads a checkpoint state from disk
// scanID can be the full scan ID or just the short suffix (e.g., "abc123" for "bounty-1234567890-abc123")
func (m *Manager) Load(ctx context.Context, scanID string) (*State, error) {
	// Try exact match first
	filename := filepath.Join(m.checkpointDir, fmt.Sprintf("%s.json", scanID))

	// If exact match doesn't exist, try to find by suffix
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		found, err := m.findBySuffix(scanID)
		if err != nil {
			return nil, err
		}
		if found != "" {
			filename = found
		} else {
			return nil, fmt.Errorf("checkpoint not found for scan ID: %s", scanID)
		}
	}

	// Read file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read checkpoint file: %w", err)
	}

	// Unmarshal JSON
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal checkpoint: %w (file may be corrupted)", err)
	}

	// P0-11/12/25 FIX: Validate checkpoint before returning
	// This catches corrupt files, invalid progress values, zero timestamps, etc.
	if err := state.Validate(); err != nil {
		return nil, fmt.Errorf("checkpoint validation failed: %w", err)
	}

	return &state, nil
}

// findBySuffix finds a checkpoint file by scanning ID suffix
func (m *Manager) findBySuffix(suffix string) (string, error) {
	files, err := os.ReadDir(m.checkpointDir)
	if err != nil {
		return "", fmt.Errorf("failed to read checkpoint directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Check if filename contains suffix (before .json extension)
		name := file.Name()
		if len(name) < 5 || name[len(name)-5:] != ".json" {
			continue
		}

		// Remove .json extension
		nameWithoutExt := name[:len(name)-5]

		// Check if scan ID ends with suffix
		if len(nameWithoutExt) >= len(suffix) && nameWithoutExt[len(nameWithoutExt)-len(suffix):] == suffix {
			return filepath.Join(m.checkpointDir, name), nil
		}
	}

	return "", nil
}

// List returns all available checkpoints, sorted by most recent first
func (m *Manager) List(ctx context.Context) ([]State, error) {
	files, err := os.ReadDir(m.checkpointDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read checkpoint directory: %w", err)
	}

	var states []State
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		// Load checkpoint
		scanID := file.Name()[:len(file.Name())-5] // Remove .json extension
		state, err := m.Load(ctx, scanID)
		if err != nil {
			// Skip corrupted checkpoints
			continue
		}

		states = append(states, *state)
	}

	// Sort by UpdatedAt (most recent first)
	sort.Slice(states, func(i, j int) bool {
		return states[i].UpdatedAt.After(states[j].UpdatedAt)
	})

	return states, nil
}

// Delete removes a checkpoint from disk
func (m *Manager) Delete(ctx context.Context, scanID string) error {
	filename := filepath.Join(m.checkpointDir, fmt.Sprintf("%s.json", scanID))

	if err := os.Remove(filename); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("checkpoint not found: %s", scanID)
		}
		return fmt.Errorf("failed to delete checkpoint: %w", err)
	}

	return nil
}

// CleanupOld removes checkpoints older than the specified duration
// This helps keep the checkpoint directory clean of stale/abandoned scans
func (m *Manager) CleanupOld(ctx context.Context, maxAge time.Duration) (int, error) {
	states, err := m.List(ctx)
	if err != nil {
		return 0, err
	}

	deleted := 0
	cutoff := time.Now().Add(-maxAge)

	for _, state := range states {
		if state.UpdatedAt.Before(cutoff) {
			if err := m.Delete(ctx, state.ScanID); err != nil {
				// Log but continue
				continue
			}
			deleted++
		}
	}

	return deleted, nil
}

// ConvertDiscoveryAssets converts discovery.Asset slice to checkpoint.Asset slice
func ConvertDiscoveryAssets(assets []*discovery.Asset) []Asset {
	converted := make([]Asset, len(assets))
	for i, asset := range assets {
		converted[i] = Asset{
			ID:           asset.ID,
			Type:         string(asset.Type),
			Value:        asset.Value,
			Domain:       asset.Domain,
			IP:           asset.IP,
			Port:         asset.Port,
			Protocol:     asset.Protocol,
			Title:        asset.Title,
			Technology:   asset.Technology,
			Metadata:     asset.Metadata,
			Priority:     asset.Priority,     // P0-16: Preserve priority
			Source:       asset.Source,       // P0-16: Preserve source
			Confidence:   asset.Confidence,   // P0-16: Preserve confidence
			DiscoveredAt: asset.DiscoveredAt, // P0-16: Preserve timestamps
			LastSeen:     asset.LastSeen,     // P0-16: Preserve last seen
		}
	}
	return converted
}

// ConvertToDiscoveryAssets converts checkpoint.Asset slice back to discovery.Asset slice
func ConvertToDiscoveryAssets(assets []Asset) []*discovery.Asset {
	converted := make([]*discovery.Asset, len(assets))
	for i, asset := range assets {
		converted[i] = &discovery.Asset{
			ID:           asset.ID,
			Type:         discovery.AssetType(asset.Type),
			Value:        asset.Value,
			Domain:       asset.Domain,
			IP:           asset.IP,
			Port:         asset.Port,
			Protocol:     asset.Protocol,
			Title:        asset.Title,
			Technology:   asset.Technology,
			Metadata:     asset.Metadata,
			Priority:     asset.Priority,     // P0-16: Restore priority
			Source:       asset.Source,       // P0-16: Restore source
			Confidence:   asset.Confidence,   // P0-16: Restore confidence
			DiscoveredAt: asset.DiscoveredAt, // P0-16: Restore timestamps
			LastSeen:     asset.LastSeen,     // P0-16: Restore last seen
		}
	}
	return converted
}
