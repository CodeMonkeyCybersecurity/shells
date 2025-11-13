package cmd

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/core"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/database"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// setupTestDatabase creates a PostgreSQL testcontainer and returns the configured store
func setupTestDatabase(t *testing.T) (core.ResultStore, func()) {
	ctx := context.Background()

	// Create PostgreSQL container
	postgresContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("shells_test"),
		postgres.WithUsername("shells_test"),
		postgres.WithPassword("shells_test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		t.Fatalf("Failed to start PostgreSQL container: %v", err)
	}

	// Get connection string
	connStr, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		postgresContainer.Terminate(ctx)
		t.Fatalf("Failed to get connection string: %v", err)
	}

	// Create database store
	dbConfig := config.DatabaseConfig{
		Driver: "postgres",
		DSN:    connStr,
	}
	store, err := database.NewStore(dbConfig)
	if err != nil {
		postgresContainer.Terminate(ctx)
		t.Fatalf("Failed to create database: %v", err)
	}

	// Cleanup function
	cleanup := func() {
		if store != nil {
			store.Close()
		}
		if err := postgresContainer.Terminate(ctx); err != nil {
			t.Logf("Warning: failed to terminate container: %v", err)
		}
	}

	t.Logf("✓ PostgreSQL testcontainer ready at: %s", connStr)
	return store, cleanup
}

// setupTestLogger creates a test logger with error level (quiet)
func setupTestLogger(t *testing.T) *logger.Logger {
	log, err := logger.New(config.LoggerConfig{
		Level:  "error",
		Format: "console",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	return log
}

// verifyDatabaseSchema checks that required tables exist
func verifyDatabaseSchema(t *testing.T, store core.ResultStore) {
	sqlStore, ok := store.(*database.Store)
	if !ok {
		t.Fatal("Store is not *database.Store type")
	}

	// Check for required tables
	tables := []string{"scans", "findings"}
	for _, table := range tables {
		var exists bool
		query := fmt.Sprintf("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = '%s')", table)
		err := sqlStore.DB().QueryRow(query).Scan(&exists)
		if err != nil {
			t.Errorf("Failed to check table %s: %v", table, err)
		}
		if !exists {
			t.Errorf("Required table %s does not exist", table)
		}
	}
}
