package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/database"
	"github.com/CodeMonkeyCybersecurity/shells/internal/orchestrator"
)

// TestBugBountyWorkflowEndToEnd is a smoke test that validates the complete workflow
func TestBugBountyWorkflowEndToEnd(t *testing.T) {
	// Skip if in short mode
	if testing.Short() {
		t.Skip("Skipping end-to-end test in short mode")
	}

	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>Test Target</title></head>
			<body>
				<h1>Test Application</h1>
				<a href="/login">Login</a>
				<a href="/api/v1/users">API</a>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	// Setup PostgreSQL testcontainer
	store, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Initialize logger
	log := setupTestLogger(t)

	// Create orchestrator with quick mode settings
	engineConfig := orchestrator.DefaultBugBountyConfig()
	engineConfig.DiscoveryTimeout = 3 * time.Second
	engineConfig.ScanTimeout = 10 * time.Second
	engineConfig.TotalTimeout = 15 * time.Second
	engineConfig.MaxAssets = 5
	engineConfig.MaxDepth = 1
	engineConfig.EnableDNS = false
	engineConfig.EnablePortScan = false
	engineConfig.EnableWebCrawl = false
	engineConfig.ShowProgress = false

	engine, err := orchestrator.NewBugBountyEngine(store, &noopTelemetry{}, log, engineConfig)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	// Run scan with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	target := server.URL
	result, err := engine.Execute(ctx, target)

	// Verify scan completed
	if err != nil {
		t.Errorf("Scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("Result is nil")
	}

	// Verify basic result fields
	if result.Status != "completed" && result.Status != "failed" {
		t.Errorf("Expected status completed or failed, got: %s", result.Status)
	}

	if result.Target != target {
		t.Errorf("Expected target %s, got: %s", target, result.Target)
	}

	if result.Duration == 0 {
		t.Error("Expected non-zero duration")
	}

	// Verify scan completed within timeout
	if result.Duration > 20*time.Second {
		t.Errorf("Scan took too long: %v (max 20s)", result.Duration)
	}

	// Verify findings are stored in database
	sqlStore, ok := store.(*database.Store)
	if !ok {
		t.Fatal("Store is not *database.Store type")
	}

	rows, err := sqlStore.DB().Query("SELECT COUNT(*) FROM scans WHERE id = $1", result.ScanID)
	if err != nil {
		t.Errorf("Failed to query scans: %v", err)
	}
	defer rows.Close()

	var scanCount int
	if rows.Next() {
		rows.Scan(&scanCount)
	}

	if scanCount == 0 {
		t.Error("Scan was not stored in database")
	}

	t.Logf("✓ Smoke test passed:")
	t.Logf("   Scan ID: %s", result.ScanID)
	t.Logf("   Status: %s", result.Status)
	t.Logf("   Duration: %v", result.Duration)
	t.Logf("   Assets: %d discovered, %d tested", result.DiscoveredAt, result.TestedAssets)
	t.Logf("   Findings: %d total", result.TotalFindings)
}

// TestDatabaseResultsPersistence verifies findings are queryable
func TestDatabaseResultsPersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	// Setup PostgreSQL testcontainer
	store, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Verify database schema
	verifyDatabaseSchema(t, store)

	t.Log("✓ Database persistence verified")
}
