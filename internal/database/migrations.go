package database

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/jmoiron/sqlx"
)

// Migration represents a single database migration
type Migration struct {
	Version     int
	Description string
	Up          string // SQL to apply migration
	Down        string // SQL to rollback migration (optional)
}

// MigrationRunner handles database migrations
type MigrationRunner struct {
	db  *sqlx.DB
	log *logger.Logger
}

// NewMigrationRunner creates a new migration runner
func NewMigrationRunner(db *sqlx.DB, log *logger.Logger) *MigrationRunner {
	return &MigrationRunner{
		db:  db,
		log: log,
	}
}

// GetAllMigrations returns all available migrations in order
func GetAllMigrations() []Migration {
	return []Migration{
		{
			Version:     1,
			Description: "Add config, result, checkpoint columns to scans table",
			Up: `
				ALTER TABLE scans
				ADD COLUMN IF NOT EXISTS config JSONB,
				ADD COLUMN IF NOT EXISTS result JSONB,
				ADD COLUMN IF NOT EXISTS checkpoint JSONB;
			`,
			Down: `
				ALTER TABLE scans
				DROP COLUMN IF EXISTS config,
				DROP COLUMN IF EXISTS result,
				DROP COLUMN IF EXISTS checkpoint;
			`,
		},
		{
			Version:     2,
			Description: "Create scan_events table if not exists",
			Up: `
				CREATE TABLE IF NOT EXISTS scan_events (
					id SERIAL PRIMARY KEY,
					scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
					event_type TEXT NOT NULL,
					component TEXT NOT NULL,
					message TEXT NOT NULL,
					metadata JSONB,
					created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
				);
				CREATE INDEX IF NOT EXISTS idx_scan_events_scan_id ON scan_events(scan_id);
				CREATE INDEX IF NOT EXISTS idx_scan_events_created_at ON scan_events(created_at);
			`,
			Down: `
				DROP TABLE IF EXISTS scan_events CASCADE;
			`,
		},
	}
}

// ensureMigrationsTable creates the migrations tracking table if it doesn't exist
func (mr *MigrationRunner) ensureMigrationsTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			description TEXT NOT NULL,
			applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			checksum TEXT NOT NULL
		);
	`

	if _, err := mr.db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	return nil
}

// getAppliedMigrations returns a map of applied migration versions
func (mr *MigrationRunner) getAppliedMigrations(ctx context.Context) (map[int]bool, error) {
	applied := make(map[int]bool)

	rows, err := mr.db.QueryContext(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("failed to scan migration version: %w", err)
		}
		applied[version] = true
	}

	return applied, nil
}

// RunMigrations applies all pending migrations
func (mr *MigrationRunner) RunMigrations(ctx context.Context) error {
	mr.log.Infow("Starting database migration check",
		"component", "migrations",
	)

	// Ensure migrations table exists
	if err := mr.ensureMigrationsTable(ctx); err != nil {
		return err
	}

	// Get applied migrations
	appliedMigrations, err := mr.getAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	// Get all migrations and sort by version
	allMigrations := GetAllMigrations()
	sort.Slice(allMigrations, func(i, j int) bool {
		return allMigrations[i].Version < allMigrations[j].Version
	})

	pendingCount := 0
	for _, migration := range allMigrations {
		if !appliedMigrations[migration.Version] {
			pendingCount++
		}
	}

	if pendingCount == 0 {
		mr.log.Infow("Database schema is up to date",
			"component", "migrations",
			"latest_version", allMigrations[len(allMigrations)-1].Version,
		)
		return nil
	}

	mr.log.Infow("Found pending migrations",
		"component", "migrations",
		"pending_count", pendingCount,
	)

	// Apply pending migrations
	for _, migration := range allMigrations {
		if appliedMigrations[migration.Version] {
			continue
		}

		if err := mr.applyMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
		}
	}

	mr.log.Infow("All migrations applied successfully",
		"component", "migrations",
		"migrations_applied", pendingCount,
	)

	return nil
}

// applyMigration applies a single migration
func (mr *MigrationRunner) applyMigration(ctx context.Context, migration Migration) error {
	mr.log.Infow("Applying migration",
		"component", "migrations",
		"version", migration.Version,
		"description", migration.Description,
	)

	// Start transaction
	tx, err := mr.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Apply migration
	if _, err := tx.ExecContext(ctx, migration.Up); err != nil {
		mr.log.Errorw("Migration failed",
			"component", "migrations",
			"version", migration.Version,
			"error", err,
		)
		return fmt.Errorf("failed to execute migration SQL: %w", err)
	}

	// Record migration
	checksum := fmt.Sprintf("%x", migration.Version) // Simple checksum for now
	recordQuery := `
		INSERT INTO schema_migrations (version, description, applied_at, checksum)
		VALUES ($1, $2, $3, $4)
	`
	if _, err := tx.ExecContext(ctx, recordQuery, migration.Version, migration.Description, time.Now(), checksum); err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration: %w", err)
	}

	mr.log.Infow("Migration applied successfully",
		"component", "migrations",
		"version", migration.Version,
	)

	return nil
}

// GetMigrationStatus returns the current migration status
func (mr *MigrationRunner) GetMigrationStatus(ctx context.Context) (map[string]interface{}, error) {
	if err := mr.ensureMigrationsTable(ctx); err != nil {
		return nil, err
	}

	appliedMigrations, err := mr.getAppliedMigrations(ctx)
	if err != nil {
		return nil, err
	}

	allMigrations := GetAllMigrations()
	latestVersion := 0
	if len(allMigrations) > 0 {
		latestVersion = allMigrations[len(allMigrations)-1].Version
	}

	appliedVersion := 0
	for version := range appliedMigrations {
		if version > appliedVersion {
			appliedVersion = version
		}
	}

	pendingCount := 0
	for _, migration := range allMigrations {
		if !appliedMigrations[migration.Version] {
			pendingCount++
		}
	}

	return map[string]interface{}{
		"current_version":  appliedVersion,
		"latest_version":   latestVersion,
		"pending_count":    pendingCount,
		"is_up_to_date":    pendingCount == 0,
		"applied_count":    len(appliedMigrations),
		"available_count":  len(allMigrations),
	}, nil
}

// RollbackMigration rolls back the last applied migration
func (mr *MigrationRunner) RollbackMigration(ctx context.Context, version int) error {
	mr.log.Warnw("Rolling back migration",
		"component", "migrations",
		"version", version,
	)

	// Find migration
	var migration *Migration
	for _, m := range GetAllMigrations() {
		if m.Version == version {
			migration = &m
			break
		}
	}

	if migration == nil {
		return fmt.Errorf("migration version %d not found", version)
	}

	if migration.Down == "" {
		return fmt.Errorf("migration version %d has no rollback SQL", version)
	}

	// Start transaction
	tx, err := mr.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Apply rollback
	if _, err := tx.ExecContext(ctx, migration.Down); err != nil {
		return fmt.Errorf("failed to execute rollback SQL: %w", err)
	}

	// Remove migration record
	if _, err := tx.ExecContext(ctx, "DELETE FROM schema_migrations WHERE version = $1", version); err != nil {
		return fmt.Errorf("failed to remove migration record: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit rollback: %w", err)
	}

	mr.log.Infow("Migration rolled back successfully",
		"component", "migrations",
		"version", version,
	)

	return nil
}

// CheckColumnExists checks if a column exists in a table (helper for conditional migrations)
func CheckColumnExists(ctx context.Context, db *sqlx.DB, tableName, columnName string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.columns
			WHERE table_name = $1 AND column_name = $2
		)
	`

	var exists bool
	err := db.QueryRowContext(ctx, query, tableName, columnName).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check column existence: %w", err)
	}

	return exists, nil
}

// CheckTableExists checks if a table exists (helper for conditional migrations)
func CheckTableExists(ctx context.Context, db *sqlx.DB, tableName string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.tables
			WHERE table_name = $1
		)
	`

	var exists bool
	err := db.QueryRowContext(ctx, query, tableName).Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		return false, fmt.Errorf("failed to check table existence: %w", err)
	}

	return exists, nil
}
