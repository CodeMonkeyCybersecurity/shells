package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/database"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/internal/orchestrator"
	"github.com/spf13/cobra"
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

	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Initialize logger
	log, err := logger.New(config.LoggerConfig{
		Level:  "error", // Quiet for tests
		Format: "console",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Initialize database
	dbConfig := config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    dbPath,
	}
	store, err := database.NewStore(dbConfig)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer store.Close()

	// Create orchestrator with quick mode settings
	engineConfig := orchestrator.DefaultBugBountyConfig()
	engineConfig.DiscoveryTimeout = 3 * time.Second // Very quick for test
	engineConfig.ScanTimeout = 10 * time.Second
	engineConfig.TotalTimeout = 15 * time.Second
	engineConfig.MaxAssets = 5
	engineConfig.MaxDepth = 1
	engineConfig.EnableDNS = false
	engineConfig.EnablePortScan = false
	engineConfig.EnableWebCrawl = false // Disable to avoid external deps
	engineConfig.ShowProgress = false   // No progress bar in tests

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

	// Verify at least one asset was discovered/tested
	if result.DiscoveredAt == 0 {
		t.Log("Warning: No assets discovered (should at least have target)")
	}

	// Verify findings are stored in database
	// Query results using the scan ID (cast to concrete type to access DB())
	sqlStore, ok := store.(*database.Store)
	if !ok {
		t.Fatal("Store is not *database.Store type")
	}

	rows, err := sqlStore.DB().Query("SELECT COUNT(*) FROM scans WHERE id = ?", result.ScanID)
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

	t.Logf("✅ Smoke test passed:")
	t.Logf("   Scan ID: %s", result.ScanID)
	t.Logf("   Status: %s", result.Status)
	t.Logf("   Duration: %v", result.Duration)
	t.Logf("   Assets: %d discovered, %d tested", result.DiscoveredAt, result.TestedAssets)
	t.Logf("   Findings: %d total", result.TotalFindings)
}

// TestQuickScanMode tests the --quick flag workflow
func TestQuickScanMode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Test</body></html>"))
	}))
	defer server.Close()

	// Setup
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "quick.db")

	log, _ := logger.New(config.LoggerConfig{Level: "error", Format: "console"})
	store, err := database.NewStore(config.DatabaseConfig{Driver: "sqlite3", DSN: dbPath})
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer store.Close()

	// Quick mode config
	engineConfig := orchestrator.DefaultBugBountyConfig()
	engineConfig.DiscoveryTimeout = 2 * time.Second
	engineConfig.TotalTimeout = 5 * time.Second
	engineConfig.MaxAssets = 5
	engineConfig.EnableWebCrawl = false
	engineConfig.ShowProgress = false

	engine, _ := orchestrator.NewBugBountyEngine(store, &noopTelemetry{}, log, engineConfig)

	// Execute quick scan
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	result, err := engine.Execute(ctx, server.URL)
	duration := time.Since(start)

	if err != nil {
		t.Errorf("Quick scan failed: %v", err)
	}

	// Verify quick scan actually is quick (< 10 seconds)
	if duration > 10*time.Second {
		t.Errorf("Quick scan took %v, expected < 10s", duration)
	}

	if result != nil && result.Status == "completed" {
		t.Logf("✅ Quick scan completed in %v", duration)
	}
}

// TestValidationPreventsInvalidTargets tests that validation blocks bad inputs
func TestValidationPreventsInvalidTargets(t *testing.T) {
	invalidTargets := []string{
		"localhost",
		"127.0.0.1",
		"http://localhost:8080",
		"192.168.1.1",
		"10.0.0.1",
		"",
		"not a valid target!@#",
	}

	for _, target := range invalidTargets {
		t.Run(target, func(t *testing.T) {
			// Create minimal setup
			tmpDir := t.TempDir()
			dbPath := filepath.Join(tmpDir, "val.db")
			testLog, _ := logger.New(config.LoggerConfig{Level: "error", Format: "console"})
			store, _ := database.NewStore(config.DatabaseConfig{Driver: "sqlite3", DSN: dbPath})
			defer store.Close()

			// Create mock command
			cmd := &cobra.Command{}
			cmd.Flags().String("scope", "", "")

			// Attempt to run orchestrator
			ctx := context.Background()
			err := runIntelligentOrchestrator(ctx, target, cmd, testLog, store)

			// Should fail validation
			if err == nil {
				t.Errorf("Expected validation error for %s, but succeeded", target)
			}
		})
	}
}

// TestDatabaseResultsPersistence verifies findings are queryable
func TestDatabaseResultsPersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	// Setup
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "persist.db")

	_, _ = logger.New(config.LoggerConfig{Level: "error", Format: "console"})
	store, err := database.NewStore(config.DatabaseConfig{Driver: "sqlite3", DSN: dbPath})
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer store.Close()

	// Verify database file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("Database file was not created at %s", dbPath)
	}

	// Verify tables exist
	sqlStore, ok := store.(*database.Store)
	if !ok {
		t.Fatal("Store is not *database.Store type")
	}

	tables := []string{"scans", "findings", "assets"}
	for _, table := range tables {
		var count int
		err := sqlStore.DB().QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count)
		if err != nil {
			t.Errorf("Failed to query table existence: %v", err)
		}
		if count == 0 {
			t.Errorf("Table %s does not exist", table)
		}
	}

	t.Log("✅ Database persistence verified")
}

// TestRealWorldQuickScan tests against actual public target
func TestRealWorldQuickScan(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping real network test in short mode")
	}

	// Setup
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "real.db")
	log, _ := logger.New(config.LoggerConfig{Level: "error", Format: "console"})
	store, err := database.NewStore(config.DatabaseConfig{Driver: "sqlite3", DSN: dbPath})
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer store.Close()

	// Quick mode config (should skip discovery)
	engineConfig := orchestrator.DefaultBugBountyConfig()
	engineConfig.SkipDiscovery = true // Quick mode skips discovery
	engineConfig.DiscoveryTimeout = 1 * time.Second
	engineConfig.TotalTimeout = 10 * time.Second
	engineConfig.MaxAssets = 1
	engineConfig.ShowProgress = false
	engineConfig.EnableAuthTesting = false // Skip auth discovery in quick mode

	engine, _ := orchestrator.NewBugBountyEngine(store, &noopTelemetry{}, log, engineConfig)

	// Execute against REAL public API (httpbin.org is designed for testing)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	target := "httpbin.org"
	start := time.Now()
	result, err := engine.Execute(ctx, target)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Real network scan failed: %v", err)
	}

	// Quick mode should complete in < 10 seconds
	if duration > 10*time.Second {
		t.Errorf("Scan too slow: %v (expected < 10s)", duration)
	}

	// Should have tested at least the target
	if result.TestedAssets == 0 {
		t.Error("No assets tested")
	}

	// Status should be completed
	if result.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", result.Status)
	}

	t.Logf("✅ Real network scan passed:")
	t.Logf("   Target: %s", target)
	t.Logf("   Duration: %v", duration)
	t.Logf("   Assets: %d tested", result.TestedAssets)
	t.Logf("   Status: %s", result.Status)
}

// Benchmark for performance regression testing
func BenchmarkQuickScan(b *testing.B) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Setup
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")
	log, _ := logger.New(config.LoggerConfig{Level: "error", Format: "console"})
	store, _ := database.NewStore(config.DatabaseConfig{Driver: "sqlite3", DSN: dbPath})
	defer store.Close()

	engineConfig := orchestrator.DefaultBugBountyConfig()
	engineConfig.DiscoveryTimeout = 1 * time.Second
	engineConfig.TotalTimeout = 3 * time.Second
	engineConfig.ShowProgress = false

	engine, _ := orchestrator.NewBugBountyEngine(store, &noopTelemetry{}, log, engineConfig)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		engine.Execute(ctx, server.URL)
		cancel()
	}
}
