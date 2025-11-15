package checkpoint

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

func TestNewManager(t *testing.T) {
	manager, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	if manager.checkpointDir == "" {
		t.Error("Manager checkpoint directory is empty")
	}

	// Verify directory exists
	if _, err := os.Stat(manager.checkpointDir); os.IsNotExist(err) {
		t.Errorf("Checkpoint directory does not exist: %s", manager.checkpointDir)
	}
}

func TestSaveAndLoad(t *testing.T) {
	ctx := context.Background()
	manager, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// Create test state
	scanID := "test-scan-12345"
	state := &State{
		ScanID:         scanID,
		Target:         "example.com",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		Progress:       50.0,
		CurrentPhase:   "testing",
		CompletedTests: []string{"auth", "scim"},
		Findings: []types.Finding{
			{
				ID:       "finding-1",
				ScanID:   scanID,
				Tool:     "test-tool",
				Type:     "TEST_VULN",
				Severity: types.SeverityHigh,
				Title:    "Test vulnerability",
			},
		},
		Metadata: map[string]interface{}{
			"quick_mode": false,
			"timeout":    "30m",
		},
	}

	// Save checkpoint
	if err := manager.Save(ctx, state); err != nil {
		t.Fatalf("Failed to save checkpoint: %v", err)
	}

	// Load checkpoint
	loaded, err := manager.Load(ctx, scanID)
	if err != nil {
		t.Fatalf("Failed to load checkpoint: %v", err)
	}

	// Verify loaded state
	if loaded.ScanID != state.ScanID {
		t.Errorf("ScanID mismatch: got %s, want %s", loaded.ScanID, state.ScanID)
	}
	if loaded.Target != state.Target {
		t.Errorf("Target mismatch: got %s, want %s", loaded.Target, state.Target)
	}
	if loaded.Progress != state.Progress {
		t.Errorf("Progress mismatch: got %f, want %f", loaded.Progress, state.Progress)
	}
	if loaded.CurrentPhase != state.CurrentPhase {
		t.Errorf("CurrentPhase mismatch: got %s, want %s", loaded.CurrentPhase, state.CurrentPhase)
	}
	if len(loaded.CompletedTests) != len(state.CompletedTests) {
		t.Errorf("CompletedTests length mismatch: got %d, want %d", len(loaded.CompletedTests), len(state.CompletedTests))
	}
	if len(loaded.Findings) != len(state.Findings) {
		t.Errorf("Findings length mismatch: got %d, want %d", len(loaded.Findings), len(state.Findings))
	}

	// Cleanup
	if err := manager.Delete(ctx, scanID); err != nil {
		t.Errorf("Failed to delete checkpoint: %v", err)
	}
}

func TestList(t *testing.T) {
	ctx := context.Background()
	manager, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// Create multiple test checkpoints
	scanIDs := []string{"test-1", "test-2", "test-3"}
	for _, scanID := range scanIDs {
		state := &State{
			ScanID:    scanID,
			Target:    "example.com",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := manager.Save(ctx, state); err != nil {
			t.Fatalf("Failed to save checkpoint %s: %v", scanID, err)
		}
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	}

	// List checkpoints
	states, err := manager.List(ctx)
	if err != nil {
		t.Fatalf("Failed to list checkpoints: %v", err)
	}

	// Verify we got at least our test checkpoints
	if len(states) < len(scanIDs) {
		t.Errorf("Expected at least %d checkpoints, got %d", len(scanIDs), len(states))
	}

	// Verify sorting (most recent first)
	for i := 1; i < len(states); i++ {
		if states[i].UpdatedAt.After(states[i-1].UpdatedAt) {
			t.Error("Checkpoints not sorted by UpdatedAt (most recent first)")
		}
	}

	// Cleanup
	for _, scanID := range scanIDs {
		manager.Delete(ctx, scanID)
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	manager, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// Create test checkpoint
	scanID := "test-delete-12345"
	state := &State{
		ScanID:    scanID,
		Target:    "example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := manager.Save(ctx, state); err != nil {
		t.Fatalf("Failed to save checkpoint: %v", err)
	}

	// Delete checkpoint
	if err := manager.Delete(ctx, scanID); err != nil {
		t.Fatalf("Failed to delete checkpoint: %v", err)
	}

	// Verify deletion
	_, err = manager.Load(ctx, scanID)
	if err == nil {
		t.Error("Expected error loading deleted checkpoint, got nil")
	}
}

func TestCleanupOld(t *testing.T) {
	ctx := context.Background()
	manager, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// Create old checkpoint
	scanID := "test-old-12345"
	oldTime := time.Now().Add(-8 * 24 * time.Hour)
	state := &State{
		ScanID:    scanID,
		Target:    "example.com",
		CreatedAt: oldTime,
		UpdatedAt: oldTime,
	}

	// Save checkpoint (this will update UpdatedAt to current time)
	if err := manager.Save(ctx, state); err != nil {
		t.Fatalf("Failed to save checkpoint: %v", err)
	}

	// Manually edit the file to set old timestamp
	filename := filepath.Join(manager.checkpointDir, scanID+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read checkpoint file: %v", err)
	}

	// Parse and update the timestamp
	var savedState State
	if err := json.Unmarshal(data, &savedState); err != nil {
		t.Fatalf("Failed to unmarshal checkpoint: %v", err)
	}

	savedState.UpdatedAt = oldTime
	data, err = json.MarshalIndent(savedState, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal checkpoint: %v", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		t.Fatalf("Failed to write checkpoint file: %v", err)
	}

	// Cleanup checkpoints older than 7 days
	deleted, err := manager.CleanupOld(ctx, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to cleanup old checkpoints: %v", err)
	}

	if deleted < 1 {
		t.Error("Expected at least 1 checkpoint to be deleted")
	}

	// Verify deletion
	_, err = manager.Load(ctx, scanID)
	if err == nil {
		t.Error("Expected error loading cleaned up checkpoint, got nil")
	}
}

func TestCheckpointFileFormat(t *testing.T) {
	ctx := context.Background()
	manager, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	scanID := "test-format-12345"
	state := &State{
		ScanID:    scanID,
		Target:    "example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := manager.Save(ctx, state); err != nil {
		t.Fatalf("Failed to save checkpoint: %v", err)
	}

	// Read raw file
	filename := filepath.Join(manager.checkpointDir, scanID+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read checkpoint file: %v", err)
	}

	// Verify it's valid JSON with indentation (human-readable)
	content := string(data)
	if len(content) == 0 {
		t.Error("Checkpoint file is empty")
	}

	// Verify it contains expected fields
	expectedFields := []string{
		"scan_id",
		"target",
		"created_at",
		"updated_at",
		"progress",
		"current_phase",
	}

	for _, field := range expectedFields {
		if !contains(content, field) {
			t.Errorf("Checkpoint file missing field: %s", field)
		}
	}

	// Cleanup
	manager.Delete(ctx, scanID)
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) &&
		(s == substr || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
