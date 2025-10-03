package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/database"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBugBountyWorkflow tests the basic bug bounty workflow
func TestBugBountyWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create test logger
	log, err := logger.New(config.LoggerConfig{
		Level:  "error", // Quiet for tests
		Format: "console",
	})
	require.NoError(t, err)

	// Create in-memory database for testing
	store, err := database.NewStore(config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	})
	require.NoError(t, err)
	defer store.Close()

	// Test with a simple target
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Run workflow with example.com (should timeout gracefully)
	err = runBugBountyWorkflow(ctx, "example.com", log, store)

	// Should not error even if discovery times out
	assert.NoError(t, err)
}

// TestBugBountyWorkflowTimeout tests that workflow respects timeout
func TestBugBountyWorkflowTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log, err := logger.New(config.LoggerConfig{
		Level:  "error",
		Format: "console",
	})
	require.NoError(t, err)

	store, err := database.NewStore(config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	})
	require.NoError(t, err)
	defer store.Close()

	// Very short timeout to test timeout handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	err = runBugBountyWorkflow(ctx, "example.com", log, store)
	duration := time.Since(start)

	// Should complete within timeout + small buffer
	assert.Less(t, duration, 10*time.Second)

	// Should not error on timeout
	assert.NoError(t, err)
}

// TestTimedDiscovery tests the timed discovery function
func TestTimedDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log, err := logger.New(config.LoggerConfig{
		Level:  "error",
		Format: "console",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	assets, err := runTimedDiscovery(ctx, "example.com", log)

	// Should not error even if discovery times out
	assert.NoError(t, err)

	// Should return at least the target asset
	assert.NotNil(t, assets)
}

// TestVulnerabilityTests tests individual vulnerability test functions
func TestVulnerabilityTests(t *testing.T) {
	log, err := logger.New(config.LoggerConfig{
		Level:  "error",
		Format: "console",
	})
	require.NoError(t, err)

	ctx := context.Background()
	assets := []*BugBountyAssetPriority{}

	// Test each vulnerability function doesn't panic
	t.Run("Authentication", func(t *testing.T) {
		findings := testAuthentication(ctx, assets, "example.com", log)
		assert.NotNil(t, findings)
	})

	t.Run("API Security", func(t *testing.T) {
		findings := testAPISecurity(ctx, assets, "example.com", log)
		assert.NotNil(t, findings)
	})

	t.Run("Business Logic", func(t *testing.T) {
		findings := testBusinessLogic(ctx, assets, "example.com", log)
		assert.NotNil(t, findings)
	})

	t.Run("SSRF", func(t *testing.T) {
		findings := testSSRF(ctx, assets, "example.com", log)
		assert.NotNil(t, findings)
	})

	t.Run("Access Control", func(t *testing.T) {
		findings := testAccessControl(ctx, assets, "example.com", log)
		assert.NotNil(t, findings)
	})
}

// TestPrioritizeAssets tests asset prioritization
func TestPrioritizeAssets(t *testing.T) {
	log, err := logger.New(config.LoggerConfig{
		Level:  "error",
		Format: "console",
	})
	require.NoError(t, err)

	assets := []*BugBountyAssetPriority{
		{Score: 50},
		{Score: 100},
		{Score: 75},
	}

	// Test display doesn't panic
	displayTopTargets(assets, 3)

	// Verify top target has highest score
	assert.Equal(t, 100, assets[0].Score)
}

// Mock implementation of core.ResultStore for testing
type mockStore struct{}

func (m *mockStore) SaveScan(ctx context.Context, scan interface{}) error      { return nil }
func (m *mockStore) UpdateScan(ctx context.Context, scan interface{}) error    { return nil }
func (m *mockStore) GetScan(ctx context.Context, scanID string) (interface{}, error) { return nil, nil }
func (m *mockStore) ListScans(ctx context.Context, filter interface{}) ([]interface{}, error) {
	return nil, nil
}
func (m *mockStore) SaveFindings(ctx context.Context, findings interface{}) error { return nil }
func (m *mockStore) GetFindings(ctx context.Context, scanID string) (interface{}, error) {
	return nil, nil
}
func (m *mockStore) GetFindingsBySeverity(ctx context.Context, severity interface{}) (interface{}, error) {
	return nil, nil
}
func (m *mockStore) GetSummary(ctx context.Context, scanID string) (interface{}, error) {
	return nil, nil
}
func (m *mockStore) Close() error { return nil }
func (m *mockStore) DB() interface{} { return nil }
func (m *mockStore) QueryFindings(ctx context.Context, query core.FindingQuery) (interface{}, error) {
	return nil, nil
}
func (m *mockStore) GetFindingStats(ctx context.Context) (*core.FindingStats, error) {
	return &core.FindingStats{}, nil
}
func (m *mockStore) GetRecentCriticalFindings(ctx context.Context, limit int) (interface{}, error) {
	return nil, nil
}
func (m *mockStore) SearchFindings(ctx context.Context, searchTerm string, limit int) (interface{}, error) {
	return nil, nil
}
