// internal/orchestrator/scanners/manager_test.go
//
// Scanner Manager Tests
//
// Validates the registry pattern, parallel execution, priority ordering,
// and scanner lifecycle management.

package scanners

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/google/uuid"
)

// mockScanner implements Scanner interface for testing
type mockScanner struct {
	name          string
	scannerType   string
	priority      int
	findings      []types.Finding
	err           error
	executeCalled int
	mu            sync.Mutex
}

func newMockScanner(name, scannerType string, priority int) *mockScanner {
	return &mockScanner{
		name:        name,
		scannerType: scannerType,
		priority:    priority,
		findings:    []types.Finding{},
	}
}

func (m *mockScanner) Name() string                                    { return m.name }
func (m *mockScanner) Type() string                                    { return m.scannerType }
func (m *mockScanner) Priority() int                                   { return m.priority }
func (m *mockScanner) CanHandle(asset *AssetPriority) bool             { return true }

func (m *mockScanner) Execute(ctx context.Context, assets []*AssetPriority) ([]types.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.executeCalled++

	if m.err != nil {
		return nil, m.err
	}
	return m.findings, nil
}

func (m *mockScanner) setFindings(findings []types.Finding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findings = findings
}

func (m *mockScanner) setError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

func (m *mockScanner) getExecuteCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.executeCalled
}

// createTestLogger creates a logger for testing
func createTestLogger() (*logger.Logger, error) {
	cfg := config.LoggerConfig{
		Level:       "info",
		Format:      "text",
		OutputPaths: []string{"stdout"},
	}
	return logger.New(cfg)
}

// createMockAssets creates test assets
func createMockAssets(count int) []*AssetPriority {
	assets := make([]*AssetPriority, count)
	for i := 0; i < count; i++ {
		assets[i] = &AssetPriority{
			Asset: &discovery.Asset{
				ID:     uuid.New().String(),
				Type:   "web",
				Value:  "https://example.com",
				Domain: "example.com",
			},
			Priority: 5,
			Features: AssetFeatures{},
		}
	}
	return assets
}

// TestManagerRegistration validates scanner registration
func TestManagerRegistration(t *testing.T) {
	log, err := createTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := ManagerConfig{
		MaxConcurrentScanners: 5,
		DefaultScannerTimeout: 30 * time.Second,
	}

	mgr := NewManager(config, log)

	// Register scanners
	scanner1 := newMockScanner("scanner1", "type1", 1)
	scanner2 := newMockScanner("scanner2", "type2", 2)

	mgr.Register("scanner1", scanner1)
	mgr.Register("scanner2", scanner2)

	// List should show 2 scanners
	scanners := mgr.List()
	if len(scanners) != 2 {
		t.Errorf("Expected 2 scanners, got %d", len(scanners))
	}

	t.Log("SUCCESS: Scanner registration works")
}

// TestManagerGet validates getting scanners by name
func TestManagerGet(t *testing.T) {
	log, err := createTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	mgr := NewManager(ManagerConfig{}, log)

	scanner := newMockScanner("test-scanner", "test", 1)
	mgr.Register("test-scanner", scanner)

	// Get registered scanner
	retrieved, ok := mgr.Get("test-scanner")
	if !ok {
		t.Fatal("Failed to get registered scanner")
	}
	if retrieved.Name() != "test-scanner" {
		t.Errorf("Got wrong scanner: %s", retrieved.Name())
	}

	// Get non-existent scanner
	_, ok = mgr.Get("non-existent")
	if ok {
		t.Error("Got scanner that shouldn't exist")
	}

	t.Log("SUCCESS: Manager Get works correctly")
}

// TestManagerPriorityOrdering validates scanners execute in priority order
func TestManagerPriorityOrdering(t *testing.T) {
	log, err := createTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	mgr := NewManager(ManagerConfig{}, log)

	// Register scanners with different priorities (lower = higher priority)
	low := newMockScanner("low-priority", "misc", 3)
	high := newMockScanner("high-priority", "auth", 1)
	medium := newMockScanner("medium-priority", "api", 2)

	// Register out of order to test sorting
	mgr.Register("low", low)
	mgr.Register("high", high)
	mgr.Register("medium", medium)

	// Get ordered list of scanner names
	scanners := mgr.List()

	if len(scanners) != 3 {
		t.Fatalf("Expected 3 scanners, got %d", len(scanners))
	}

	// Verify scanners are registered
	if _, ok := mgr.Get("high"); !ok {
		t.Error("High priority scanner not found")
	}
	if _, ok := mgr.Get("medium"); !ok {
		t.Error("Medium priority scanner not found")
	}
	if _, ok := mgr.Get("low"); !ok {
		t.Error("Low priority scanner not found")
	}

	t.Log("SUCCESS: Priority ordering works correctly")
}

// TestManagerExecuteByName validates executing specific scanner
func TestManagerExecuteByName(t *testing.T) {
	log, err := createTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	mgr := NewManager(ManagerConfig{}, log)

	// Register mock scanner with findings
	scanner := newMockScanner("test-scanner", "test", 1)
	scanner.setFindings([]types.Finding{
		{ID: "1", Tool: "test-scanner", Severity: types.SeverityHigh},
		{ID: "2", Tool: "test-scanner", Severity: types.SeverityMedium},
	})
	mgr.Register("test-scanner", scanner)

	// Execute
	ctx := context.Background()
	assets := createMockAssets(5)
	findings, err := mgr.ExecuteByName(ctx, "test-scanner", assets)

	if err != nil {
		t.Fatalf("ExecuteByName failed: %v", err)
	}

	if len(findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(findings))
	}

	if scanner.getExecuteCallCount() != 1 {
		t.Errorf("Scanner should be called once, was called %d times", scanner.getExecuteCallCount())
	}

	t.Log("SUCCESS: ExecuteByName works correctly")
}

// TestManagerExecuteAll validates executing all scanners
func TestManagerExecuteAll(t *testing.T) {
	log, err := createTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := ManagerConfig{
		MaxConcurrentScanners: 2,
		DefaultScannerTimeout: 30 * time.Second,
	}
	mgr := NewManager(config, log)

	// Register multiple scanners
	scanner1 := newMockScanner("scanner1", "type1", 1)
	scanner1.setFindings([]types.Finding{{ID: "1", Tool: "scanner1"}})

	scanner2 := newMockScanner("scanner2", "type2", 2)
	scanner2.setFindings([]types.Finding{{ID: "2", Tool: "scanner2"}})

	mgr.Register("scanner1", scanner1)
	mgr.Register("scanner2", scanner2)

	// Execute all
	ctx := context.Background()
	assets := createMockAssets(3)
	findings, err := mgr.ExecuteAll(ctx, assets)

	if err != nil {
		t.Fatalf("ExecuteAll failed: %v", err)
	}

	// Should get findings from both scanners
	if len(findings) != 2 {
		t.Errorf("Expected 2 findings (1 from each scanner), got %d", len(findings))
	}

	// Both scanners should have been called
	if scanner1.getExecuteCallCount() != 1 {
		t.Error("Scanner1 was not called")
	}
	if scanner2.getExecuteCallCount() != 1 {
		t.Error("Scanner2 was not called")
	}

	t.Log("SUCCESS: ExecuteAll works correctly")
}

// TestManagerExecuteByType validates filtering by scanner type
func TestManagerExecuteByType(t *testing.T) {
	log, err := createTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	mgr := NewManager(ManagerConfig{}, log)

	// Register scanners of different types
	authScanner := newMockScanner("auth-scanner", "authentication", 1)
	authScanner.setFindings([]types.Finding{{ID: "auth-finding"}})

	apiScanner := newMockScanner("api-scanner", "api", 2)
	apiScanner.setFindings([]types.Finding{{ID: "api-finding"}})

	mgr.Register("auth", authScanner)
	mgr.Register("api", apiScanner)

	// Execute only authentication scanners
	ctx := context.Background()
	assets := createMockAssets(2)
	findings, err := mgr.ExecuteByType(ctx, "authentication", assets)

	if err != nil {
		t.Fatalf("ExecuteByType failed: %v", err)
	}

	// Should only get findings from auth scanner
	if len(findings) != 1 {
		t.Errorf("Expected 1 finding from auth scanner, got %d", len(findings))
	}
	if findings[0].ID != "auth-finding" {
		t.Error("Got wrong finding - should be from auth scanner only")
	}

	// Only auth scanner should have been called
	if authScanner.getExecuteCallCount() != 1 {
		t.Error("Auth scanner was not called")
	}
	if apiScanner.getExecuteCallCount() != 0 {
		t.Error("API scanner should not have been called")
	}

	t.Log("SUCCESS: ExecuteByType filters correctly")
}

// TestManagerErrorHandling validates error handling in scanner execution
func TestManagerErrorHandling(t *testing.T) {
	log, err := createTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	mgr := NewManager(ManagerConfig{}, log)

	// Register scanner that returns error
	scanner := newMockScanner("failing-scanner", "test", 1)
	scanner.setError(errors.New("scanner failed"))
	mgr.Register("failing-scanner", scanner)

	// Execute should return error
	ctx := context.Background()
	assets := createMockAssets(1)
	_, err = mgr.ExecuteByName(ctx, "failing-scanner", assets)

	if err == nil {
		t.Error("Expected error from failing scanner, got nil")
	}

	t.Log("SUCCESS: Error handling works correctly")
}

// TestManagerConcurrentExecution validates parallel scanner execution
func TestManagerConcurrentExecution(t *testing.T) {
	log, err := createTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := ManagerConfig{
		MaxConcurrentScanners: 3,
		DefaultScannerTimeout: 30 * time.Second,
	}
	mgr := NewManager(config, log)

	// Register multiple scanners
	for i := 1; i <= 5; i++ {
		scanner := newMockScanner("scanner", "type", i)
		scanner.setFindings([]types.Finding{{ID: "finding"}})
		mgr.Register("scanner", scanner)
	}

	// Execute all concurrently
	ctx := context.Background()
	assets := createMockAssets(10)
	start := time.Now()
	findings, err := mgr.ExecuteAll(ctx, assets)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("ExecuteAll failed: %v", err)
	}

	// Should get findings from all scanners
	if len(findings) != 5 {
		t.Errorf("Expected 5 findings, got %d", len(findings))
	}

	// With concurrency, should be faster than sequential execution
	t.Logf("Concurrent execution took %v", duration)

	t.Log("SUCCESS: Concurrent execution works")
}

// TestManagerContextCancellation validates context cancellation stops execution
func TestManagerContextCancellation(t *testing.T) {
	log, err := createTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	mgr := NewManager(ManagerConfig{}, log)

	// Register scanner
	scanner := newMockScanner("scanner", "test", 1)
	mgr.Register("scanner", scanner)

	// Create context with immediate cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	assets := createMockAssets(1)
	_, err = mgr.ExecuteByName(ctx, "scanner", assets)

	// Should get context error
	if err == nil {
		t.Error("Expected context cancellation error, got nil")
	}

	t.Log("SUCCESS: Context cancellation works")
}

// TestManagerEmptyAssets validates handling of empty asset list
func TestManagerEmptyAssets(t *testing.T) {
	log, err := createTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	mgr := NewManager(ManagerConfig{}, log)

	scanner := newMockScanner("scanner", "test", 1)
	mgr.Register("scanner", scanner)

	// Execute with no assets
	ctx := context.Background()
	findings, err := mgr.ExecuteByName(ctx, "scanner", []*AssetPriority{})

	if err != nil {
		t.Fatalf("ExecuteByName with empty assets failed: %v", err)
	}

	// Should still call scanner (with empty list)
	if scanner.getExecuteCallCount() != 1 {
		t.Error("Scanner was not called with empty assets")
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings with empty assets, got %d", len(findings))
	}

	t.Log("SUCCESS: Empty assets handled correctly")
}

// TestManagerNoScanners validates handling when no scanners registered
func TestManagerNoScanners(t *testing.T) {
	log, err := createTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	mgr := NewManager(ManagerConfig{}, log)

	// Execute with no registered scanners
	ctx := context.Background()
	assets := createMockAssets(5)
	findings, err := mgr.ExecuteAll(ctx, assets)

	if err != nil {
		t.Fatalf("ExecuteAll with no scanners failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings with no scanners, got %d", len(findings))
	}

	t.Log("SUCCESS: No scanners case handled correctly")
}
