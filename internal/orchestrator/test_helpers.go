// internal/orchestrator/test_helpers.go
//
// Test Helpers - Mock implementations for testing
//
// This file provides mock implementations of key interfaces to enable
// comprehensive integration and unit testing of the orchestrator.

package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/internal/orchestrator/scanners"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/google/uuid"
)

// MockScanner implements scanners.Scanner interface for testing
type MockScanner struct {
	name          string
	scannerType   string
	priority      int
	findings      []types.Finding
	err           error
	executeCalled int
	mu            sync.Mutex
}

// NewMockScanner creates a mock scanner with configurable behavior
func NewMockScanner(name, scannerType string, priority int) *MockScanner {
	return &MockScanner{
		name:        name,
		scannerType: scannerType,
		priority:    priority,
		findings:    []types.Finding{},
	}
}

// SetFindings configures what findings the mock should return
func (m *MockScanner) SetFindings(findings []types.Finding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findings = findings
}

// SetError configures what error the mock should return
func (m *MockScanner) SetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

// GetExecuteCallCount returns how many times Execute was called
func (m *MockScanner) GetExecuteCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.executeCalled
}

func (m *MockScanner) Name() string {
	return m.name
}

func (m *MockScanner) Type() string {
	return m.scannerType
}

func (m *MockScanner) Priority() int {
	return m.priority
}

func (m *MockScanner) CanHandle(asset *scanners.AssetPriority) bool {
	// Mock handles all assets
	return true
}

func (m *MockScanner) Execute(ctx context.Context, assets []*scanners.AssetPriority) ([]types.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.executeCalled++

	if m.err != nil {
		return nil, m.err
	}

	// Return configured findings
	return m.findings, nil
}

// MockResultStore implements core.ResultStore interface for testing
type MockResultStore struct {
	savedScans    map[string]*types.ScanRequest
	savedFindings map[string][]types.Finding
	savedEvents   map[string][]types.Event
	mu            sync.RWMutex
}

// NewMockResultStore creates a mock result store
func NewMockResultStore() *MockResultStore {
	return &MockResultStore{
		savedScans:    make(map[string]*types.ScanRequest),
		savedFindings: make(map[string][]types.Finding),
		savedEvents:   make(map[string][]types.Event),
	}
}

func (m *MockResultStore) SaveScan(ctx context.Context, scan *types.ScanRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.savedScans[scan.ID] = scan
	return nil
}

func (m *MockResultStore) GetScan(ctx context.Context, scanID string) (*types.ScanRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	scan, ok := m.savedScans[scanID]
	if !ok {
		return nil, fmt.Errorf("scan not found: %s", scanID)
	}
	return scan, nil
}

func (m *MockResultStore) UpdateScan(ctx context.Context, scan *types.ScanRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.savedScans[scan.ID] = scan
	return nil
}

func (m *MockResultStore) SaveFindings(ctx context.Context, findings []types.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(findings) == 0 {
		return nil
	}
	scanID := findings[0].ScanID
	m.savedFindings[scanID] = append(m.savedFindings[scanID], findings...)
	return nil
}

func (m *MockResultStore) GetFindings(ctx context.Context, scanID string) ([]types.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	findings, ok := m.savedFindings[scanID]
	if !ok {
		return []types.Finding{}, nil
	}
	return findings, nil
}

func (m *MockResultStore) SaveEvent(ctx context.Context, event *types.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.savedEvents[event.ScanID] = append(m.savedEvents[event.ScanID], *event)
	return nil
}

func (m *MockResultStore) GetEvents(ctx context.Context, scanID string) ([]types.Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	events, ok := m.savedEvents[scanID]
	if !ok {
		return []types.Event{}, nil
	}
	return events, nil
}

// GetSavedFindingsCount returns count of findings saved for a scan
func (m *MockResultStore) GetSavedFindingsCount(scanID string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.savedFindings[scanID])
}

// MockTelemetry implements core.Telemetry interface for testing
type MockTelemetry struct {
	events []string
	mu     sync.Mutex
}

// NewMockTelemetry creates a mock telemetry client
func NewMockTelemetry() *MockTelemetry {
	return &MockTelemetry{
		events: []string{},
	}
}

func (m *MockTelemetry) TrackEvent(ctx context.Context, event string, properties map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *MockTelemetry) TrackError(ctx context.Context, err error, properties map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, fmt.Sprintf("error: %v", err))
	return nil
}

// GetEventCount returns how many events were tracked
func (m *MockTelemetry) GetEventCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

// CreateMockAssets creates a set of mock discovery assets for testing
func CreateMockAssets(count int) []*discovery.Asset {
	assets := make([]*discovery.Asset, count)
	for i := 0; i < count; i++ {
		assets[i] = &discovery.Asset{
			ID:           uuid.New().String(),
			Type:         "web",
			Value:        fmt.Sprintf("https://example%d.com", i),
			Domain:       fmt.Sprintf("example%d.com", i),
			Confidence:   0.9,
			Priority:     5,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
			Tags:         []string{"test", "mock"},
			Metadata:     map[string]string{"source": "mock"},
		}
	}
	return assets
}

// CreateMockFindings creates mock findings with various severities
func CreateMockFindings(scanID string, count int) []types.Finding {
	findings := make([]types.Finding, count)
	severities := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}

	for i := 0; i < count; i++ {
		findings[i] = types.Finding{
			ID:          uuid.New().String(),
			ScanID:      scanID,
			Tool:        "mock-scanner",
			Type:        fmt.Sprintf("MOCK_VULN_%d", i),
			Severity:    severities[i%len(severities)],
			Title:       fmt.Sprintf("Mock Vulnerability %d", i),
			Description: fmt.Sprintf("This is a mock finding for testing purposes (index %d)", i),
			Evidence:    fmt.Sprintf("Mock evidence %d", i),
			Solution:    "Fix the mock issue",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
	}
	return findings
}

// CreateTestLogger creates a logger for testing with appropriate config
func CreateTestLogger() (*logger.Logger, error) {
	cfg := logger.Config{
		Level:  "info",
		Format: "text",
		Output: "stdout",
	}
	return logger.New(cfg)
}

// CreateTestConfig creates a minimal config for testing
func CreateTestConfig() BugBountyConfig {
	return BugBountyConfig{
		MaxAssets:                100,
		MaxDepth:                 2,
		DiscoveryTimeout:         30 * time.Second,
		ScanTimeout:              30 * time.Second,
		TotalTimeout:             2 * time.Minute,
		EnableDNS:                false, // Disable to avoid external calls in tests
		EnablePortScan:           false,
		EnableWebCrawl:           false,
		EnableAuthTesting:        true,
		EnableSCIMTesting:        true,
		EnableAPITesting:         true,
		EnableIDORTesting:        true,
		EnableGraphQLTesting:     true,
		EnableServiceFingerprint: false, // Requires nmap binary
		EnableNucleiScan:         false, // Requires nuclei binary
		RateLimitPerSecond:       10.0,
		RateLimitBurst:           20,
		ShowProgress:             false, // Disable for cleaner test output
		EnableCheckpointing:      false, // Disable for unit tests
		CheckpointInterval:       1 * time.Minute,
		EnableEnrichment:         false, // Disable to avoid external API calls
	}
}
