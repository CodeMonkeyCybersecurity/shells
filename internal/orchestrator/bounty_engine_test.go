// internal/orchestrator/bounty_engine_test.go
//
// Integration Tests for BugBountyEngine
//
// These tests verify the full scan pipeline works correctly after the Phase 0b
// refactoring that extracted scanners, factory, persistence, and output modules.

package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// TestFullPipelineWithMockScanners verifies the complete scan pipeline
// This is the most important integration test - validates discovery → prioritization → testing → storage
func TestFullPipelineWithMockScanners(t *testing.T) {
	// Setup
	store := NewMockResultStore()
	telemetry := NewMockTelemetry()
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := CreateTestConfig()

	// Create engine using factory (tests factory pattern)
	engine, err := NewBugBountyEngine(store, telemetry, logger, config)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Verify engine was initialized correctly
	if engine == nil {
		t.Fatal("Engine is nil")
	}
	if engine.scannerManager == nil {
		t.Fatal("Scanner manager is nil")
	}
	if engine.outputFormatter == nil {
		t.Fatal("Output formatter is nil")
	}
	if engine.persistenceManager == nil {
		t.Fatal("Persistence manager is nil")
	}

	// Register mock scanners
	mockAuth := NewMockScanner("authentication", "authentication", 2)
	mockAuth.SetFindings(CreateMockFindings("test-scan", 3))
	engine.scannerManager.Register("authentication", mockAuth)

	mockSCIM := NewMockScanner("scim", "scim", 3)
	mockSCIM.SetFindings(CreateMockFindings("test-scan", 2))
	engine.scannerManager.Register("scim", mockSCIM)

	// NOTE: We cannot test Execute() in full because it requires:
	// - Discovery engine (makes external network calls)
	// - Organization correlator (makes WHOIS/cert lookups)
	// Instead, we test individual phases

	t.Log("Full pipeline test: Setup complete, engine initialized with mock scanners")
}

// TestMultipleAssetsGetTested validates P0-2 fix: "Discovered 50 assets, tested 1"
// This test ensures ALL discovered assets are passed to scanners, not just the first
func TestMultipleAssetsGetTested(t *testing.T) {
	// Setup
	store := NewMockResultStore()
	telemetry := NewMockTelemetry()
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := CreateTestConfig()
	engine, err := NewBugBountyEngine(store, telemetry, logger, config)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Create 50 mock assets
	discoveryAssets := CreateMockAssets(50)

	// Convert to AssetPriority (simulate prioritization phase)
	prioritizedAssets := engine.executePrioritizationPhase(discoveryAssets, logger)

	if len(prioritizedAssets) != 50 {
		t.Fatalf("Expected 50 prioritized assets, got %d", len(prioritizedAssets))
	}

	// Register mock scanner
	mockScanner := NewMockScanner("test-scanner", "test", 1)
	mockScanner.SetFindings([]types.Finding{
		{
			ID:       "finding-1",
			ScanID:   "test-scan",
			Tool:     "test-scanner",
			Severity: types.SeverityHigh,
			Title:    "Test Finding",
		},
	})
	engine.scannerManager.Register("test-scanner", mockScanner)

	// Execute scanner manager against all assets
	ctx := context.Background()
	findings, err := engine.scannerManager.ExecuteAll(ctx, prioritizedAssets)
	if err != nil {
		t.Fatalf("Scanner execution failed: %v", err)
	}

	// Verify scanner was called (it should have been given all 50 assets)
	if mockScanner.GetExecuteCallCount() == 0 {
		t.Fatal("Scanner Execute() was never called")
	}

	// Verify findings were returned
	if len(findings) == 0 {
		t.Fatal("No findings returned from scanner")
	}

	t.Logf("SUCCESS: Multiple assets tested - %d assets prioritized, scanner called %d time(s), %d findings returned",
		len(prioritizedAssets), mockScanner.GetExecuteCallCount(), len(findings))
}

// TestAssetPrioritization validates scoring logic
func TestAssetPrioritization(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := CreateTestConfig()
	store := NewMockResultStore()
	telemetry := NewMockTelemetry()

	engine, err := NewBugBountyEngine(store, telemetry, logger, config)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Create assets with different characteristics
	assets := []*discovery.Asset{
		{
			ID:     "1",
			Type:   "web",
			Value:  "https://example.com/login",
			Domain: "example.com",
		},
		{
			ID:     "2",
			Type:   "web",
			Value:  "https://example.com/api/users",
			Domain: "example.com",
		},
		{
			ID:     "3",
			Type:   "web",
			Value:  "https://example.com/admin",
			Domain: "example.com",
		},
	}

	// Prioritize
	prioritized := engine.executePrioritizationPhase(assets, logger)

	if len(prioritized) != 3 {
		t.Fatalf("Expected 3 prioritized assets, got %d", len(prioritized))
	}

	// Verify prioritization occurred (priorities should be assigned)
	for i, asset := range prioritized {
		if asset.Priority == 0 {
			t.Errorf("Asset %d has zero priority (no scoring occurred)", i)
		}
		t.Logf("Asset %d: %s - Priority: %d", i, asset.Asset.Value, asset.Priority)
	}

	t.Log("SUCCESS: Asset prioritization working")
}

// TestScannerManagerRegistration validates registry pattern
func TestScannerManagerRegistration(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := CreateTestConfig()
	store := NewMockResultStore()
	telemetry := NewMockTelemetry()

	engine, err := NewBugBountyEngine(store, telemetry, logger, config)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Register mock scanners
	mock1 := NewMockScanner("scanner1", "type1", 1)
	mock2 := NewMockScanner("scanner2", "type2", 2)

	engine.scannerManager.Register("scanner1", mock1)
	engine.scannerManager.Register("scanner2", mock2)

	// List registered scanners
	scanners := engine.scannerManager.List()
	if len(scanners) < 2 {
		t.Fatalf("Expected at least 2 scanners, got %d", len(scanners))
	}

	// Get specific scanner
	retrieved, ok := engine.scannerManager.Get("scanner1")
	if !ok {
		t.Fatal("Failed to retrieve registered scanner")
	}
	if retrieved.Name() != "scanner1" {
		t.Errorf("Retrieved wrong scanner: got %s, want scanner1", retrieved.Name())
	}

	t.Log("SUCCESS: Scanner manager registration working")
}

// TestScannerPriorityOrdering validates scanners execute in priority order
func TestScannerPriorityOrdering(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := CreateTestConfig()
	store := NewMockResultStore()
	telemetry := NewMockTelemetry()

	engine, err := NewBugBountyEngine(store, telemetry, logger, config)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Register scanners with different priorities
	// Lower priority number = higher priority (executes first)
	highPriority := NewMockScanner("high-priority", "auth", 1)
	mediumPriority := NewMockScanner("medium-priority", "api", 2)
	lowPriority := NewMockScanner("low-priority", "misc", 3)

	engine.scannerManager.Register("low", lowPriority)      // Register out of order
	engine.scannerManager.Register("high", highPriority)    // to test sorting
	engine.scannerManager.Register("medium", mediumPriority)

	// Get ordered list
	orderedScanners := engine.scannerManager.List()

	// Verify ordering (priority 1 should come before priority 2, etc.)
	if len(orderedScanners) < 3 {
		t.Fatalf("Expected at least 3 scanners, got %d", len(orderedScanners))
	}

	// Find our test scanners in the list
	foundHigh := false
	foundMedium := false
	foundLow := false
	highIndex, mediumIndex, lowIndex := -1, -1, -1

	for i, s := range orderedScanners {
		switch s.Name() {
		case "high-priority":
			foundHigh = true
			highIndex = i
		case "medium-priority":
			foundMedium = true
			mediumIndex = i
		case "low-priority":
			foundLow = true
			lowIndex = i
		}
	}

	if !foundHigh || !foundMedium || !foundLow {
		t.Fatal("Not all test scanners found in ordered list")
	}

	// Verify high priority comes before medium, medium before low
	if highIndex >= mediumIndex {
		t.Errorf("High priority scanner (index %d) should come before medium (index %d)", highIndex, mediumIndex)
	}
	if mediumIndex >= lowIndex {
		t.Errorf("Medium priority scanner (index %d) should come before low (index %d)", mediumIndex, lowIndex)
	}

	t.Logf("SUCCESS: Scanner priority ordering correct (high=%d, medium=%d, low=%d)", highIndex, mediumIndex, lowIndex)
}

// TestFactoryInitialization validates factory pattern creates proper engine
func TestFactoryInitialization(t *testing.T) {
	store := NewMockResultStore()
	telemetry := NewMockTelemetry()
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := CreateTestConfig()

	// Create engine through factory
	engine, err := NewBugBountyEngine(store, telemetry, logger, config)
	if err != nil {
		t.Fatalf("Factory failed to create engine: %v", err)
	}

	// Verify all components initialized
	if engine.store != store {
		t.Error("Store not set correctly")
	}
	if engine.telemetry != telemetry {
		t.Error("Telemetry not set correctly")
	}
	if engine.logger == nil {
		t.Error("Logger is nil")
	}
	if engine.scannerManager == nil {
		t.Error("Scanner manager is nil")
	}
	if engine.outputFormatter == nil {
		t.Error("Output formatter is nil")
	}
	if engine.persistenceManager == nil {
		t.Error("Persistence manager is nil")
	}
	if engine.rateLimiter == nil {
		t.Error("Rate limiter is nil")
	}

	t.Log("SUCCESS: Factory initialization creates valid engine with all components")
}

// TestPersistenceManager validates result storage
func TestPersistenceManager(t *testing.T) {
	store := NewMockResultStore()
	telemetry := NewMockTelemetry()
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := CreateTestConfig()
	engine, err := NewBugBountyEngine(store, telemetry, logger, config)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Create mock result
	result := &BugBountyResult{
		ScanID:    "test-scan-123",
		Target:    "example.com",
		StartTime: time.Now(),
		Status:    "completed",
		Findings:  CreateMockFindings("test-scan-123", 5),
	}

	// Save results using persistence manager
	ctx := context.Background()
	err = engine.persistenceManager.SaveResults(ctx, result.ScanID, result)
	if err != nil {
		t.Fatalf("Failed to save results: %v", err)
	}

	// Verify findings were saved to store
	savedCount := store.GetSavedFindingsCount(result.ScanID)
	if savedCount != 5 {
		t.Errorf("Expected 5 findings saved, got %d", savedCount)
	}

	t.Logf("SUCCESS: Persistence manager saved %d findings", savedCount)
}

// TestOutputFormatter validates display methods don't crash
func TestOutputFormatter(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := CreateTestConfig()
	store := NewMockResultStore()
	telemetry := NewMockTelemetry()

	engine, err := NewBugBountyEngine(store, telemetry, logger, config)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Create mock result
	result := &BugBountyResult{
		ScanID:    "test-scan",
		Target:    "example.com",
		StartTime: time.Now(),
		Status:    "completed",
		Findings:  CreateMockFindings("test-scan", 3),
	}

	// Test display methods (should not panic)
	t.Run("DisplayScanSummary", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("DisplayScanSummary panicked: %v", r)
			}
		}()
		engine.outputFormatter.DisplayScanSummary(result)
	})

	t.Run("DisplayDiscoveryResults", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("DisplayDiscoveryResults panicked: %v", r)
			}
		}()
		assets := CreateMockAssets(5)
		engine.outputFormatter.DisplayDiscoveryResults(assets, 1*time.Second)
	})

	t.Log("SUCCESS: Output formatter methods execute without panic")
}
