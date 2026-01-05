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

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
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
	savedScans        map[string]*types.ScanRequest
	savedFindings     map[string][]types.Finding
	correlation       map[string][]types.CorrelationResult
	correlationByType map[string][]types.CorrelationResult
	scanEvents        []storedScanEvent
	SaveScanCalled    bool // Track if SaveScan was called (for integration tests)
	mu                sync.RWMutex
}

// NewMockResultStore creates a mock result store
func NewMockResultStore() *MockResultStore {
	return &MockResultStore{
		savedScans:        make(map[string]*types.ScanRequest),
		savedFindings:     make(map[string][]types.Finding),
		correlation:       make(map[string][]types.CorrelationResult),
		correlationByType: make(map[string][]types.CorrelationResult),
	}
}

type storedScanEvent struct {
	scanID    string
	eventType string
	component string
	message   string
	metadata  map[string]interface{}
}

func (m *MockResultStore) SaveScan(ctx context.Context, scan *types.ScanRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.savedScans[scan.ID] = scan
	m.SaveScanCalled = true
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

// Additional methods to satisfy core.ResultStore interface
func (m *MockResultStore) ListScans(ctx context.Context, filter core.ScanFilter) ([]*types.ScanRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var scans []*types.ScanRequest
	for _, scan := range m.savedScans {
		scans = append(scans, scan)
	}
	return scans, nil
}

func (m *MockResultStore) GetFindingsBySeverity(ctx context.Context, severity types.Severity) ([]types.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var findings []types.Finding
	for _, scanFindings := range m.savedFindings {
		for _, finding := range scanFindings {
			if finding.Severity == severity {
				findings = append(findings, finding)
			}
		}
	}
	return findings, nil
}

func (m *MockResultStore) QueryFindings(ctx context.Context, query core.FindingQuery) ([]types.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var findings []types.Finding
	for _, scanFindings := range m.savedFindings {
		findings = append(findings, scanFindings...)
	}
	return findings, nil
}

func (m *MockResultStore) GetFindingStats(ctx context.Context) (*core.FindingStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	stats := &core.FindingStats{
		Total:      0,
		BySeverity: make(map[types.Severity]int),
		ByTool:     make(map[string]int),
		ByType:     make(map[string]int),
		ByTarget:   make(map[string]int),
	}
	for _, scanFindings := range m.savedFindings {
		stats.Total += len(scanFindings)
		for _, finding := range scanFindings {
			stats.BySeverity[finding.Severity]++
			stats.ByTool[finding.Tool]++
			stats.ByType[finding.Type]++
		}
	}
	return stats, nil
}

func (m *MockResultStore) GetRecentCriticalFindings(ctx context.Context, limit int) ([]types.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var findings []types.Finding
	for _, scanFindings := range m.savedFindings {
		for _, finding := range scanFindings {
			if finding.Severity == types.SeverityCritical {
				findings = append(findings, finding)
			}
		}
	}
	if len(findings) > limit {
		findings = findings[:limit]
	}
	return findings, nil
}

func (m *MockResultStore) SearchFindings(ctx context.Context, searchTerm string, limit int) ([]types.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var findings []types.Finding
	for _, scanFindings := range m.savedFindings {
		findings = append(findings, scanFindings...)
	}
	if len(findings) > limit {
		findings = findings[:limit]
	}
	return findings, nil
}

func (m *MockResultStore) SaveScanEvent(ctx context.Context, scanID string, eventType string, component string, message string, metadata map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanEvents = append(m.scanEvents, storedScanEvent{
		scanID:    scanID,
		eventType: eventType,
		component: component,
		message:   message,
		metadata:  metadata,
	})
	return nil
}

func (m *MockResultStore) GetSummary(ctx context.Context, scanID string) (*types.Summary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	findings := m.savedFindings[scanID]
	severityCounts := make(map[types.Severity]int)
	toolCounts := make(map[string]int)
	for _, finding := range findings {
		severityCounts[finding.Severity]++
		toolCounts[finding.Tool]++
	}
	return &types.Summary{
		Total:      len(findings),
		BySeverity: severityCounts,
		ByTool:     toolCounts,
	}, nil
}

func (m *MockResultStore) Close() error {
	return nil
}

func (m *MockResultStore) UpdateFindingStatus(ctx context.Context, findingID string, status types.FindingStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for scanID, findings := range m.savedFindings {
		for i, finding := range findings {
			if finding.ID == findingID {
				finding.Status = status
				m.savedFindings[scanID][i] = finding
				return nil
			}
		}
	}
	return nil
}

func (m *MockResultStore) MarkFindingVerified(ctx context.Context, findingID string, verified bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for scanID, findings := range m.savedFindings {
		for i, finding := range findings {
			if finding.ID == findingID {
				finding.Verified = verified
				m.savedFindings[scanID][i] = finding
				return nil
			}
		}
	}
	return nil
}

func (m *MockResultStore) MarkFindingFalsePositive(ctx context.Context, findingID string, falsePositive bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for scanID, findings := range m.savedFindings {
		for i, finding := range findings {
			if finding.ID == findingID {
				finding.FalsePositive = falsePositive
				m.savedFindings[scanID][i] = finding
				return nil
			}
		}
	}
	return nil
}

func (m *MockResultStore) GetRegressions(ctx context.Context, limit int) ([]types.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	results := make([]types.Finding, 0)
	for _, findings := range m.savedFindings {
		for _, finding := range findings {
			if finding.Status == types.FindingStatusReopened {
				results = append(results, finding)
			}
		}
	}
	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func (m *MockResultStore) GetVulnerabilityTimeline(ctx context.Context, fingerprint string) ([]types.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	results := make([]types.Finding, 0)
	for _, findings := range m.savedFindings {
		for _, finding := range findings {
			if finding.Fingerprint == fingerprint {
				results = append(results, finding)
			}
		}
	}
	return results, nil
}

func (m *MockResultStore) GetFindingsByFingerprint(ctx context.Context, fingerprint string) ([]types.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	results := make([]types.Finding, 0)
	for _, findings := range m.savedFindings {
		for _, finding := range findings {
			if finding.Fingerprint == fingerprint {
				results = append(results, finding)
			}
		}
	}
	return results, nil
}

func (m *MockResultStore) GetNewFindings(ctx context.Context, sinceDate time.Time) ([]types.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	results := make([]types.Finding, 0)
	for _, findings := range m.savedFindings {
		for _, finding := range findings {
			if finding.CreatedAt.After(sinceDate) {
				results = append(results, finding)
			}
		}
	}
	return results, nil
}

func (m *MockResultStore) GetFixedFindings(ctx context.Context, limit int) ([]types.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	results := make([]types.Finding, 0)
	for _, findings := range m.savedFindings {
		for _, finding := range findings {
			if finding.Status == types.FindingStatusFixed {
				results = append(results, finding)
			}
		}
	}
	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func (m *MockResultStore) SaveCorrelationResults(ctx context.Context, results []types.CorrelationResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(results) == 0 {
		return nil
	}
	scanID := results[0].ScanID
	m.correlation[scanID] = append(m.correlation[scanID], results...)
	for _, res := range results {
		m.correlationByType[res.InsightType] = append(m.correlationByType[res.InsightType], res)
	}
	return nil
}

func (m *MockResultStore) GetCorrelationResults(ctx context.Context, scanID string) ([]types.CorrelationResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]types.CorrelationResult(nil), m.correlation[scanID]...), nil
}

func (m *MockResultStore) GetCorrelationResultsByType(ctx context.Context, insightType string) ([]types.CorrelationResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]types.CorrelationResult(nil), m.correlationByType[insightType]...), nil
}

// GetSavedFindingsCount returns count of findings saved for a scan
func (m *MockResultStore) GetSavedFindingsCount(scanID string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.savedFindings[scanID])
}

// MockTelemetry implements core.Telemetry interface for testing
type MockTelemetry struct {
	scanCount     int
	findingCount  int
	workerMetrics int
	mu            sync.Mutex
}

// NewMockTelemetry creates a mock telemetry client
func NewMockTelemetry() *MockTelemetry {
	return &MockTelemetry{}
}

func (m *MockTelemetry) RecordScan(scanType types.ScanType, duration float64, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanCount++
}

func (m *MockTelemetry) RecordFinding(severity types.Severity) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findingCount++
}

func (m *MockTelemetry) RecordWorkerMetrics(status *types.WorkerStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workerMetrics++
}

func (m *MockTelemetry) Close() error {
	return nil
}

// GetScanCount returns how many scans were recorded
func (m *MockTelemetry) GetScanCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.scanCount
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
	cfg := config.LoggerConfig{
		Level:       "info",
		Format:      "text",
		OutputPaths: []string{"stdout"},
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
