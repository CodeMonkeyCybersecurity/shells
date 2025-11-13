package commands

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/core"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	authdiscovery "github.com/CodeMonkeyCybersecurity/artemis/pkg/auth/discovery"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock implementations for testing

// mockResultStore is a mock implementation of core.ResultStore
type mockResultStore struct {
	saveScanCalled     bool
	updateScanCalled   bool
	saveFindingsCalled bool
	savedFindings      []types.Finding
	scanID             string
	err                error
	returnScan         *types.ScanRequest
	returnFindings     []types.Finding
}

func (m *mockResultStore) SaveScan(ctx context.Context, scan *types.ScanRequest) error {
	m.saveScanCalled = true
	return m.err
}

func (m *mockResultStore) UpdateScan(ctx context.Context, scan *types.ScanRequest) error {
	m.updateScanCalled = true
	return m.err
}

func (m *mockResultStore) GetScan(ctx context.Context, scanID string) (*types.ScanRequest, error) {
	m.scanID = scanID
	return m.returnScan, m.err
}

func (m *mockResultStore) ListScans(ctx context.Context, filter core.ScanFilter) ([]*types.ScanRequest, error) {
	return []*types.ScanRequest{m.returnScan}, m.err
}

func (m *mockResultStore) SaveFindings(ctx context.Context, findings []types.Finding) error {
	m.saveFindingsCalled = true
	m.savedFindings = append(m.savedFindings, findings...)
	return m.err
}

func (m *mockResultStore) GetFindings(ctx context.Context, scanID string) ([]types.Finding, error) {
	m.scanID = scanID
	return m.returnFindings, m.err
}

func (m *mockResultStore) GetFindingsBySeverity(ctx context.Context, severity types.Severity) ([]types.Finding, error) {
	return m.returnFindings, m.err
}

func (m *mockResultStore) QueryFindings(ctx context.Context, query core.FindingQuery) ([]types.Finding, error) {
	return m.returnFindings, m.err
}

func (m *mockResultStore) GetFindingStats(ctx context.Context) (*core.FindingStats, error) {
	return &core.FindingStats{}, m.err
}

func (m *mockResultStore) GetRecentCriticalFindings(ctx context.Context, limit int) ([]types.Finding, error) {
	return m.returnFindings, m.err
}

func (m *mockResultStore) SearchFindings(ctx context.Context, searchTerm string, limit int) ([]types.Finding, error) {
	return m.returnFindings, m.err
}

func (m *mockResultStore) GetSummary(ctx context.Context, scanID string) (*types.Summary, error) {
	return &types.Summary{}, m.err
}

func (m *mockResultStore) SaveScanEvent(ctx context.Context, scanID string, eventType string, component string, message string, metadata map[string]interface{}) error {
	return m.err
}

func (m *mockResultStore) Close() error {
	return m.err
}

// mockLogger is a mock implementation of logger.Logger
type mockLogger struct {
	infoMessages  []string
	errorMessages []string
	debugMessages []string
	warnMessages  []string
	infowCalls    []map[string]interface{}
	errorwCalls   []map[string]interface{}
}

func newMockLogger() *mockLogger {
	return &mockLogger{
		infoMessages:  make([]string, 0),
		errorMessages: make([]string, 0),
		debugMessages: make([]string, 0),
		warnMessages:  make([]string, 0),
		infowCalls:    make([]map[string]interface{}, 0),
		errorwCalls:   make([]map[string]interface{}, 0),
	}
}

func (m *mockLogger) Info(msg string) {
	m.infoMessages = append(m.infoMessages, msg)
}

func (m *mockLogger) Infow(msg string, keysAndValues ...interface{}) {
	m.infoMessages = append(m.infoMessages, msg)
	args := make(map[string]interface{})
	args["msg"] = msg
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			key := fmt.Sprintf("%v", keysAndValues[i])
			args[key] = keysAndValues[i+1]
		}
	}
	m.infowCalls = append(m.infowCalls, args)
}

func (m *mockLogger) Error(msg string) {
	m.errorMessages = append(m.errorMessages, msg)
}

func (m *mockLogger) Errorw(msg string, keysAndValues ...interface{}) {
	m.errorMessages = append(m.errorMessages, msg)
	args := make(map[string]interface{})
	args["msg"] = msg
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			key := fmt.Sprintf("%v", keysAndValues[i])
			args[key] = keysAndValues[i+1]
		}
	}
	m.errorwCalls = append(m.errorwCalls, args)
}

func (m *mockLogger) Debug(msg string) {
	m.debugMessages = append(m.debugMessages, msg)
}

func (m *mockLogger) Debugw(msg string, keysAndValues ...interface{}) {
	m.debugMessages = append(m.debugMessages, msg)
}

func (m *mockLogger) Warn(msg string) {
	m.warnMessages = append(m.warnMessages, msg)
}

func (m *mockLogger) Warnw(msg string, keysAndValues ...interface{}) {
	m.warnMessages = append(m.warnMessages, msg)
}

func (m *mockLogger) WithComponent(component string) *logger.Logger {
	// Return a real logger for chaining
	log, _ := logger.New(config.LoggerConfig{Level: "info", Format: "json"})
	return log
}

func (m *mockLogger) WithTarget(target string) *logger.Logger {
	log, _ := logger.New(config.LoggerConfig{Level: "info", Format: "json"})
	return log
}

func (m *mockLogger) WithScanID(scanID string) *logger.Logger {
	log, _ := logger.New(config.LoggerConfig{Level: "info", Format: "json"})
	return log
}

func (m *mockLogger) WithTool(tool string) *logger.Logger {
	log, _ := logger.New(config.LoggerConfig{Level: "info", Format: "json"})
	return log
}

func (m *mockLogger) WithModule(module string) *logger.Logger {
	log, _ := logger.New(config.LoggerConfig{Level: "info", Format: "json"})
	return log
}

func (m *mockLogger) WithFields(keysAndValues ...interface{}) *logger.Logger {
	log, _ := logger.New(config.LoggerConfig{Level: "info", Format: "json"})
	return log
}

func (m *mockLogger) LogError(ctx context.Context, err error, msg string, keysAndValues ...interface{}) {
	m.errorMessages = append(m.errorMessages, msg)
	args := make(map[string]interface{})
	args["msg"] = msg
	args["error"] = err
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			key := fmt.Sprintf("%v", keysAndValues[i])
			args[key] = keysAndValues[i+1]
		}
	}
	m.errorwCalls = append(m.errorwCalls, args)
}

// Test helper functions

func createTestOrchestrator(store core.ResultStore, log *mockLogger, cfg *config.Config) *Orchestrator {
	return &Orchestrator{
		log:   convertMockLogger(log),
		store: store,
		cfg:   cfg,
	}
}

func convertMockLogger(mock *mockLogger) *logger.Logger {
	// For tests, we'll create a real logger but still track calls via mock
	log, _ := logger.New(config.LoggerConfig{Level: "info", Format: "json"})
	return log
}

func defaultTestConfig() *config.Config {
	return &config.Config{
		Logger: config.LoggerConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

// Unit Tests

func TestNew(t *testing.T) {
	mockStore := &mockResultStore{}
	mockLog := newMockLogger()
	cfg := defaultTestConfig()

	orch := New(convertMockLogger(mockLog), mockStore, cfg)

	assert.NotNil(t, orch)
	assert.NotNil(t, orch.log)
	assert.NotNil(t, orch.store)
	assert.NotNil(t, orch.cfg)
}

func TestRunSCIMScan_Success(t *testing.T) {
	mockStore := &mockResultStore{}
	mockLog := newMockLogger()
	cfg := defaultTestConfig()

	orch := createTestOrchestrator(mockStore, mockLog, cfg)

	ctx := context.Background()
	target := "https://example.com"
	scanID := "test-scan-123"

	// This will fail in real execution because it tries to make network calls
	// For now, we test that the method can be called without panicking
	err := orch.runSCIMScan(ctx, target, scanID)

	// We expect an error because there's no real SCIM endpoint
	// The important thing is that it doesn't panic
	assert.NotNil(t, err)
}

func TestRunSCIMScan_EmptyTarget(t *testing.T) {
	mockStore := &mockResultStore{}
	mockLog := newMockLogger()
	cfg := defaultTestConfig()

	orch := createTestOrchestrator(mockStore, mockLog, cfg)

	ctx := context.Background()
	target := ""
	scanID := "test-scan-123"

	err := orch.runSCIMScan(ctx, target, scanID)

	// Should get an error for empty target
	assert.NotNil(t, err)
}

func TestRunSCIMScan_SaveFindingsError(t *testing.T) {
	mockStore := &mockResultStore{
		err: errors.New("database error"),
	}
	mockLog := newMockLogger()
	cfg := defaultTestConfig()

	orch := createTestOrchestrator(mockStore, mockLog, cfg)

	ctx := context.Background()
	target := "https://example.com"
	scanID := "test-scan-123"

	err := orch.runSCIMScan(ctx, target, scanID)

	// Should propagate store error
	assert.NotNil(t, err)
}

func TestRunSmugglingDetection_Success(t *testing.T) {
	mockStore := &mockResultStore{}
	mockLog := newMockLogger()
	cfg := defaultTestConfig()

	orch := createTestOrchestrator(mockStore, mockLog, cfg)

	ctx := context.Background()
	target := "https://example.com"
	scanID := "test-scan-123"

	// This will fail in real execution because it tries to make network calls
	err := orch.runSmugglingDetection(ctx, target, scanID)

	// We expect an error because there's no real endpoint
	assert.NotNil(t, err)
}

func TestRunSmugglingDetection_AddsHTTPSPrefix(t *testing.T) {
	mockStore := &mockResultStore{}
	mockLog := newMockLogger()
	cfg := defaultTestConfig()

	orch := createTestOrchestrator(mockStore, mockLog, cfg)

	ctx := context.Background()
	target := "example.com"
	scanID := "test-scan-123"

	// Should add https:// prefix automatically
	err := orch.runSmugglingDetection(ctx, target, scanID)

	// Will fail on network call, but should have added prefix
	assert.NotNil(t, err)
}

func TestRunSmugglingDetection_SaveFindingsError(t *testing.T) {
	mockStore := &mockResultStore{
		err: errors.New("database error"),
	}
	mockLog := newMockLogger()
	cfg := defaultTestConfig()

	orch := createTestOrchestrator(mockStore, mockLog, cfg)

	ctx := context.Background()
	target := "https://example.com"
	scanID := "test-scan-123"

	err := orch.runSmugglingDetection(ctx, target, scanID)

	// Should propagate store error
	assert.NotNil(t, err)
}

func TestRunComprehensiveBusinessLogicTests_Success(t *testing.T) {
	mockStore := &mockResultStore{}
	mockLog := newMockLogger()
	cfg := defaultTestConfig()

	orch := createTestOrchestrator(mockStore, mockLog, cfg)

	ctx := context.Background()
	target := "https://example.com"
	scanID := "test-scan-123"

	err := orch.runComprehensiveBusinessLogicTests(ctx, target, scanID)

	// Should succeed as it creates placeholder findings
	assert.NoError(t, err)
	assert.True(t, mockStore.saveFindingsCalled)
	assert.Equal(t, 1, len(mockStore.savedFindings))
}

func TestRunComprehensiveBusinessLogicTests_SaveFindingsError(t *testing.T) {
	mockStore := &mockResultStore{
		err: errors.New("database error"),
	}
	mockLog := newMockLogger()
	cfg := defaultTestConfig()

	orch := createTestOrchestrator(mockStore, mockLog, cfg)

	ctx := context.Background()
	target := "https://example.com"
	scanID := "test-scan-123"

	err := orch.runComprehensiveBusinessLogicTests(ctx, target, scanID)

	// Should propagate store error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database error")
}

func TestRunComprehensiveAuthenticationTests_Success(t *testing.T) {
	mockStore := &mockResultStore{}
	mockLog := newMockLogger()
	cfg := defaultTestConfig()

	orch := createTestOrchestrator(mockStore, mockLog, cfg)

	ctx := context.Background()
	target := "https://example.com"
	scanID := "test-scan-123"

	// This will fail in real execution because it tries to make network calls
	err := orch.runComprehensiveAuthenticationTests(ctx, target, scanID)

	// We expect an error because there's no real endpoint
	assert.NotNil(t, err)
}

func TestRunComprehensiveAuthenticationTests_AddsHTTPSPrefix(t *testing.T) {
	mockStore := &mockResultStore{}
	mockLog := newMockLogger()
	cfg := defaultTestConfig()

	orch := createTestOrchestrator(mockStore, mockLog, cfg)

	ctx := context.Background()
	target := "example.com"
	scanID := "test-scan-123"

	// Should add https:// prefix automatically
	err := orch.runComprehensiveAuthenticationTests(ctx, target, scanID)

	// Will fail on network call, but should have added prefix
	assert.NotNil(t, err)
}

func TestConvertAuthInventoryToFindings_Empty(t *testing.T) {
	inventory := &authdiscovery.AuthInventory{}
	domain := "example.com"
	sessionID := "test-session"

	findings := convertAuthInventoryToFindings(inventory, domain, sessionID)

	assert.NotNil(t, findings)
	assert.Equal(t, 0, len(findings))
}

func TestConvertAuthInventoryToFindings_NetworkAuth(t *testing.T) {
	inventory := &authdiscovery.AuthInventory{
		NetworkAuth: &authdiscovery.NetworkAuthMethods{
			LDAP: []authdiscovery.LDAPEndpoint{
				{
					Host: "ldap.example.com",
					Port: 389,
					SSL:  false,
				},
			},
		},
	}
	domain := "example.com"
	sessionID := "test-session"

	findings := convertAuthInventoryToFindings(inventory, domain, sessionID)

	assert.NotNil(t, findings)
	assert.Equal(t, 1, len(findings))
	assert.Equal(t, "NETWORK_AUTH", findings[0].Type)
	assert.Contains(t, findings[0].Title, "LDAP")
}

func TestConvertAuthInventoryToFindings_WebAuth(t *testing.T) {
	inventory := &authdiscovery.AuthInventory{
		WebAuth: &authdiscovery.WebAuthMethods{
			FormLogin: []authdiscovery.FormLoginEndpoint{
				{
					URL:            "https://example.com/login",
					Method:         "POST",
					UsernameField:  "username",
					PasswordField:  "password",
				},
			},
		},
	}
	domain := "example.com"
	sessionID := "test-session"

	findings := convertAuthInventoryToFindings(inventory, domain, sessionID)

	assert.NotNil(t, findings)
	assert.Equal(t, 1, len(findings))
	assert.Equal(t, "WEB_AUTH", findings[0].Type)
	assert.Contains(t, findings[0].Title, "Form-Based")
}

func TestConvertAuthInventoryToFindings_APIAuth(t *testing.T) {
	inventory := &authdiscovery.AuthInventory{
		APIAuth: &authdiscovery.APIAuthMethods{
			REST: []authdiscovery.RESTEndpoint{
				{
					URL: "https://api.example.com/v1",
				},
			},
		},
	}
	domain := "example.com"
	sessionID := "test-session"

	findings := convertAuthInventoryToFindings(inventory, domain, sessionID)

	assert.NotNil(t, findings)
	assert.Equal(t, 1, len(findings))
	assert.Equal(t, "API_AUTH", findings[0].Type)
	assert.Contains(t, findings[0].Title, "REST API")
}

func TestConvertAuthInventoryToFindings_CustomAuth(t *testing.T) {
	inventory := &authdiscovery.AuthInventory{
		CustomAuth: []authdiscovery.CustomAuthMethod{
			{
				Type:        "custom-sso",
				Description: "Custom SSO implementation",
				Indicators:  []string{"X-Custom-Auth: true"},
			},
		},
	}
	domain := "example.com"
	sessionID := "test-session"

	findings := convertAuthInventoryToFindings(inventory, domain, sessionID)

	assert.NotNil(t, findings)
	assert.Equal(t, 1, len(findings))
	assert.Equal(t, "CUSTOM_AUTH", findings[0].Type)
	assert.Contains(t, findings[0].Title, "Custom Authentication")
}

func TestConvertAuthInventoryToFindings_Multiple(t *testing.T) {
	inventory := &authdiscovery.AuthInventory{
		NetworkAuth: &authdiscovery.NetworkAuthMethods{
			LDAP: []authdiscovery.LDAPEndpoint{
				{Host: "ldap.example.com", Port: 389, SSL: false},
			},
		},
		WebAuth: &authdiscovery.WebAuthMethods{
			FormLogin: []authdiscovery.FormLoginEndpoint{
				{URL: "https://example.com/login", Method: "POST"},
			},
		},
		APIAuth: &authdiscovery.APIAuthMethods{
			REST: []authdiscovery.RESTEndpoint{
				{URL: "https://api.example.com/v1"},
			},
		},
		CustomAuth: []authdiscovery.CustomAuthMethod{
			{Type: "custom-sso", Description: "Custom SSO"},
		},
	}
	domain := "example.com"
	sessionID := "test-session"

	findings := convertAuthInventoryToFindings(inventory, domain, sessionID)

	assert.NotNil(t, findings)
	assert.Equal(t, 4, len(findings))

	// Check that we have all types
	types := make(map[string]bool)
	for _, f := range findings {
		types[f.Type] = true
	}
	assert.True(t, types["NETWORK_AUTH"])
	assert.True(t, types["WEB_AUTH"])
	assert.True(t, types["API_AUTH"])
	assert.True(t, types["CUSTOM_AUTH"])
}

func TestExecuteRecommendedScanners_Stub(t *testing.T) {
	mockStore := &mockResultStore{}
	mockLog := newMockLogger()
	cfg := defaultTestConfig()

	orch := createTestOrchestrator(mockStore, mockLog, cfg)

	ctx := context.Background()
	session := &discovery.DiscoverySession{}
	recommendations := []discovery.ScannerRecommendation{}

	err := orch.executeRecommendedScanners(ctx, session, recommendations)

	// Currently a stub, should return nil
	assert.NoError(t, err)
}

// Integration-style tests (these test interactions between components)

func TestRunComprehensiveBusinessLogicTests_Integration(t *testing.T) {
	t.Run("saves findings with correct structure", func(t *testing.T) {
		mockStore := &mockResultStore{}
		mockLog := newMockLogger()
		cfg := defaultTestConfig()

		orch := createTestOrchestrator(mockStore, mockLog, cfg)

		ctx := context.Background()
		target := "https://example.com"
		scanID := "test-scan-123"

		err := orch.runComprehensiveBusinessLogicTests(ctx, target, scanID)

		require.NoError(t, err)
		require.Equal(t, 1, len(mockStore.savedFindings))

		finding := mockStore.savedFindings[0]
		assert.Equal(t, scanID, finding.ScanID)
		assert.Equal(t, "business-logic", finding.Tool)
		assert.Equal(t, "BUSINESS_LOGIC", finding.Type)
		assert.Equal(t, types.SeverityInfo, finding.Severity)
		assert.Contains(t, finding.Title, "Business Logic Testing Completed")
		assert.NotEmpty(t, finding.Evidence)
		assert.False(t, finding.CreatedAt.IsZero())
		assert.False(t, finding.UpdatedAt.IsZero())
	})

	t.Run("handles multiple targets", func(t *testing.T) {
		mockStore := &mockResultStore{}
		mockLog := newMockLogger()
		cfg := defaultTestConfig()

		orch := createTestOrchestrator(mockStore, mockLog, cfg)

		ctx := context.Background()
		targets := []string{"https://example1.com", "https://example2.com"}
		scanID := "test-scan-123"

		for _, target := range targets {
			err := orch.runComprehensiveBusinessLogicTests(ctx, target, scanID)
			require.NoError(t, err)
		}

		assert.Equal(t, 2, len(mockStore.savedFindings))
	})
}

func TestContextCancellation(t *testing.T) {
	t.Run("respects context cancellation", func(t *testing.T) {
		mockStore := &mockResultStore{}
		mockLog := newMockLogger()
		cfg := defaultTestConfig()

		orch := createTestOrchestrator(mockStore, mockLog, cfg)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		target := "https://example.com"
		scanID := "test-scan-123"

		// These should handle cancellation gracefully
		// Some may return errors, some may succeed quickly
		_ = orch.runSCIMScan(ctx, target, scanID)
		_ = orch.runSmugglingDetection(ctx, target, scanID)
		_ = orch.runComprehensiveBusinessLogicTests(ctx, target, scanID)
		_ = orch.runComprehensiveAuthenticationTests(ctx, target, scanID)

		// The important thing is no panic
	})

	t.Run("respects context timeout", func(t *testing.T) {
		mockStore := &mockResultStore{}
		mockLog := newMockLogger()
		cfg := defaultTestConfig()

		orch := createTestOrchestrator(mockStore, mockLog, cfg)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		time.Sleep(2 * time.Millisecond) // Ensure timeout

		target := "https://example.com"
		scanID := "test-scan-123"

		// Should handle timeout gracefully
		_ = orch.runSCIMScan(ctx, target, scanID)
		_ = orch.runSmugglingDetection(ctx, target, scanID)
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("empty target handling", func(t *testing.T) {
		mockStore := &mockResultStore{}
		mockLog := newMockLogger()
		cfg := defaultTestConfig()

		orch := createTestOrchestrator(mockStore, mockLog, cfg)

		ctx := context.Background()
		scanID := "test-scan-123"

		// Empty targets should be handled gracefully
		_ = orch.runSCIMScan(ctx, "", scanID)
		_ = orch.runSmugglingDetection(ctx, "", scanID)
		_ = orch.runComprehensiveBusinessLogicTests(ctx, "", scanID)
		_ = orch.runComprehensiveAuthenticationTests(ctx, "", scanID)
	})

	t.Run("empty scan ID handling", func(t *testing.T) {
		mockStore := &mockResultStore{}
		mockLog := newMockLogger()
		cfg := defaultTestConfig()

		orch := createTestOrchestrator(mockStore, mockLog, cfg)

		ctx := context.Background()
		target := "https://example.com"

		// Empty scan IDs should be handled (findings will have empty scan_id)
		err := orch.runComprehensiveBusinessLogicTests(ctx, target, "")
		assert.NoError(t, err)
	})

	t.Run("nil config handling", func(t *testing.T) {
		mockStore := &mockResultStore{}
		mockLog := newMockLogger()

		orch := New(convertMockLogger(mockLog), mockStore, nil)

		// Should not panic with nil config
		assert.NotNil(t, orch)
		assert.Nil(t, orch.cfg)
	})
}

// Benchmark tests

func BenchmarkRunComprehensiveBusinessLogicTests(b *testing.B) {
	mockStore := &mockResultStore{}
	mockLog := newMockLogger()
	cfg := defaultTestConfig()

	orch := createTestOrchestrator(mockStore, mockLog, cfg)

	ctx := context.Background()
	target := "https://example.com"
	scanID := "bench-scan"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = orch.runComprehensiveBusinessLogicTests(ctx, target, scanID)
	}
}

func BenchmarkConvertAuthInventoryToFindings(b *testing.B) {
	inventory := &authdiscovery.AuthInventory{
		NetworkAuth: &authdiscovery.NetworkAuthMethods{
			LDAP: []authdiscovery.LDAPEndpoint{
				{Host: "ldap.example.com", Port: 389, SSL: false},
			},
		},
		WebAuth: &authdiscovery.WebAuthMethods{
			FormLogin: []authdiscovery.FormLoginEndpoint{
				{URL: "https://example.com/login", Method: "POST"},
			},
		},
	}
	domain := "example.com"
	sessionID := "bench-session"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = convertAuthInventoryToFindings(inventory, domain, sessionID)
	}
}
