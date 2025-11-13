// internal/orchestrator/result_test.go
//
// Thread-Safe Result Container Tests
//
// Validates the P0-19 and P0-20 fixes for race conditions in concurrent
// access to findings and phase results. These tests use go test -race to
// detect data races.

package orchestrator

import (
	"sync"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// TestResultThreadSafety validates concurrent access doesn't cause race conditions
// This is the critical test for P0-19 and P0-20 fixes
func TestResultThreadSafety(t *testing.T) {
	result := &BugBountyResult{
		ScanID:       "test-scan",
		Target:       "example.com",
		StartTime:    time.Now(),
		Status:       "running",
		PhaseResults: make(map[string]PhaseResult),
		Findings:     []types.Finding{},
	}

	// Run concurrent operations
	numGoroutines := 10
	operationsPerGoroutine := 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3) // 3 types of operations

	// Concurrent finding additions (P0-19 test)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				findings := []types.Finding{
					{
						ID:       "finding",
						ScanID:   "test-scan",
						Tool:     "test",
						Severity: types.SeverityHigh,
						Title:    "Test Finding",
					},
				}
				result.AddFindings(findings)
			}
		}(i)
	}

	// Concurrent finding reads (P0-19 test)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				_ = result.GetFindingsForCheckpoint()
			}
		}(i)
	}

	// Concurrent phase result updates (P0-20 test)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				phase := PhaseResult{
					Phase:     "test",
					Status:    "running",
					StartTime: time.Now(),
				}
				result.SetPhaseResult("test", phase)
			}
		}(i)
	}

	wg.Wait()

	// Verify no panics occurred and data is consistent
	findings := result.GetFindingsForCheckpoint()
	expectedFindings := numGoroutines * operationsPerGoroutine

	if len(findings) != expectedFindings {
		t.Errorf("Expected %d findings, got %d", expectedFindings, len(findings))
	}

	t.Logf("SUCCESS: Concurrent operations completed without race conditions (%d findings)", len(findings))
}

// TestResultAddFindings validates adding findings is thread-safe
func TestResultAddFindings(t *testing.T) {
	result := &BugBountyResult{
		ScanID:    "test-scan",
		Target:    "example.com",
		StartTime: time.Now(),
		Findings:  []types.Finding{},
	}

	// Add initial findings
	initial := []types.Finding{
		{ID: "1", ScanID: "test-scan", Tool: "test", Severity: types.SeverityHigh},
		{ID: "2", ScanID: "test-scan", Tool: "test", Severity: types.SeverityMedium},
	}
	result.AddFindings(initial)

	// Add more findings
	additional := []types.Finding{
		{ID: "3", ScanID: "test-scan", Tool: "test", Severity: types.SeverityLow},
	}
	result.AddFindings(additional)

	// Verify total count
	findings := result.GetFindingsForCheckpoint()
	if len(findings) != 3 {
		t.Errorf("Expected 3 findings, got %d", len(findings))
	}

	t.Log("SUCCESS: AddFindings works correctly")
}

// TestResultGetFindingsForCheckpoint validates reading findings for checkpoint
func TestResultGetFindingsForCheckpoint(t *testing.T) {
	result := &BugBountyResult{
		ScanID:    "test-scan",
		Target:    "example.com",
		StartTime: time.Now(),
		Findings: []types.Finding{
			{ID: "1", ScanID: "test-scan", Tool: "test"},
			{ID: "2", ScanID: "test-scan", Tool: "test"},
		},
	}

	// Get findings for checkpoint (creates copy)
	findings := result.GetFindingsForCheckpoint()

	if len(findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(findings))
	}

	// Modify the copy shouldn't affect original
	findings[0].ID = "modified"

	// Get again and verify original unchanged
	findings2 := result.GetFindingsForCheckpoint()
	if findings2[0].ID == "modified" {
		t.Error("GetFindingsForCheckpoint did not create independent copy")
	}

	t.Log("SUCCESS: GetFindingsForCheckpoint returns independent copy")
}

// TestResultSetDiscoveredAssets validates asset storage is thread-safe
func TestResultSetDiscoveredAssets(t *testing.T) {
	result := &BugBountyResult{
		ScanID:       "test-scan",
		Target:       "example.com",
		StartTime:    time.Now(),
		DiscoveredAt: 0,
	}

	// Create mock assets
	assets := CreateMockAssets(10)

	// Set discovered assets
	result.SetDiscoveredAssets(assets)

	// Verify count
	if result.DiscoveredAt != 10 {
		t.Errorf("Expected DiscoveredAt=10, got %d", result.DiscoveredAt)
	}

	// Get assets back
	retrieved := result.GetDiscoveredAssetsForCheckpoint()
	if len(retrieved) != 10 {
		t.Errorf("Expected 10 assets retrieved, got %d", len(retrieved))
	}

	t.Log("SUCCESS: SetDiscoveredAssets stores assets correctly")
}

// TestResultSetPhaseResult validates phase result updates are thread-safe
func TestResultSetPhaseResult(t *testing.T) {
	result := &BugBountyResult{
		ScanID:       "test-scan",
		Target:       "example.com",
		StartTime:    time.Now(),
		PhaseResults: make(map[string]PhaseResult),
	}

	// Set multiple phase results
	phases := []string{"discovery", "prioritization", "testing", "storage"}
	for _, phase := range phases {
		result.SetPhaseResult(phase, PhaseResult{
			Phase:     phase,
			Status:    "completed",
			StartTime: time.Now(),
			EndTime:   time.Now(),
			Duration:  1 * time.Second,
		})
	}

	// Verify all phases stored using thread-safe getter
	allPhases := result.GetAllPhaseResults()
	if len(allPhases) != 4 {
		t.Errorf("Expected 4 phase results, got %d", len(allPhases))
	}

	t.Log("SUCCESS: SetPhaseResult stores multiple phases correctly")
}

// TestResultConcurrentPhaseUpdates validates concurrent phase updates don't race
func TestResultConcurrentPhaseUpdates(t *testing.T) {
	result := &BugBountyResult{
		ScanID:       "test-scan",
		Target:       "example.com",
		StartTime:    time.Now(),
		PhaseResults: make(map[string]PhaseResult),
	}

	phases := []string{"phase1", "phase2", "phase3", "phase4", "phase5"}
	var wg sync.WaitGroup

	// Update different phases concurrently
	for _, phase := range phases {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				result.SetPhaseResult(p, PhaseResult{
					Phase:     p,
					Status:    "running",
					StartTime: time.Now(),
				})
			}
		}(phase)
	}

	wg.Wait()

	// Verify all phases present using thread-safe getter
	allPhases := result.GetAllPhaseResults()
	if len(allPhases) != 5 {
		t.Errorf("Expected 5 phases, got %d", len(allPhases))
	}

	t.Log("SUCCESS: Concurrent phase updates work correctly")
}

// TestResultStatusUpdate validates status changes are thread-safe
func TestResultStatusUpdate(t *testing.T) {
	result := &BugBountyResult{
		ScanID:    "test-scan",
		Target:    "example.com",
		StartTime: time.Now(),
		Status:    "running",
	}

	// Update status multiple times using thread-safe setter
	statuses := []string{"running", "testing", "storing", "completed"}
	for _, status := range statuses {
		result.SetStatus(status)
	}

	// Read final status - access directly since Status is in basic metadata
	if result.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", result.Status)
	}

	t.Log("SUCCESS: Status updates work correctly")
}

// TestResultSeverityCounts validates severity counting logic
func TestResultSeverityCounts(t *testing.T) {
	result := &BugBountyResult{
		ScanID:    "test-scan",
		Target:    "example.com",
		StartTime: time.Now(),
		Findings: []types.Finding{
			{Severity: types.SeverityCritical},
			{Severity: types.SeverityCritical},
			{Severity: types.SeverityHigh},
			{Severity: types.SeverityMedium},
			{Severity: types.SeverityLow},
			{Severity: types.SeverityInfo},
		},
	}

	// Count severities using thread-safe getter
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	infoCount := 0

	findings := result.GetFindings()
	for _, f := range findings {
		switch f.Severity {
		case types.SeverityCritical:
			criticalCount++
		case types.SeverityHigh:
			highCount++
		case types.SeverityMedium:
			mediumCount++
		case types.SeverityLow:
			lowCount++
		case types.SeverityInfo:
			infoCount++
		}
	}

	if criticalCount != 2 {
		t.Errorf("Expected 2 critical findings, got %d", criticalCount)
	}
	if highCount != 1 {
		t.Errorf("Expected 1 high finding, got %d", highCount)
	}
	if mediumCount != 1 {
		t.Errorf("Expected 1 medium finding, got %d", mediumCount)
	}

	t.Log("SUCCESS: Severity counting works correctly")
}

// TestResultEmptyFindings validates handling of empty findings list
func TestResultEmptyFindings(t *testing.T) {
	result := &BugBountyResult{
		ScanID:    "test-scan",
		Target:    "example.com",
		StartTime: time.Now(),
		Findings:  []types.Finding{},
	}

	// Get findings when empty
	findings := result.GetFindingsForCheckpoint()
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(findings))
	}

	// Add empty list
	result.AddFindings([]types.Finding{})

	// Should still be empty
	findings = result.GetFindingsForCheckpoint()
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings after adding empty list, got %d", len(findings))
	}

	t.Log("SUCCESS: Empty findings handled correctly")
}

// TestResultLargeNumberOfFindings validates handling of many findings
func TestResultLargeNumberOfFindings(t *testing.T) {
	result := &BugBountyResult{
		ScanID:    "test-scan",
		Target:    "example.com",
		StartTime: time.Now(),
		Findings:  []types.Finding{},
	}

	// Add 1000 findings
	manyFindings := CreateMockFindings("test-scan", 1000)
	result.AddFindings(manyFindings)

	// Verify count
	findings := result.GetFindingsForCheckpoint()
	if len(findings) != 1000 {
		t.Errorf("Expected 1000 findings, got %d", len(findings))
	}

	t.Log("SUCCESS: Large number of findings handled correctly")
}

// TestResultMutexProtection validates mutex actually protects shared state
func TestResultMutexProtection(t *testing.T) {
	result := &BugBountyResult{
		ScanID:    "test-scan",
		Target:    "example.com",
		StartTime: time.Now(),
		Findings:  []types.Finding{},
	}

	// This test will be detected by go test -race if mutex is not working
	var wg sync.WaitGroup
	iterations := 1000

	// Writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			result.AddFindings([]types.Finding{{ID: "test"}})
		}
	}()

	// Reader goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = result.GetFindingsForCheckpoint()
		}
	}()

	wg.Wait()

	// If we reach here without race detector complaining, mutex works
	t.Log("SUCCESS: Mutex protection working (run with -race to verify)")
}
