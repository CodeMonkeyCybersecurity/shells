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
		{
			Version:     3,
			Description: "Add temporal tracking columns to findings table",
			Up: `
				ALTER TABLE findings
				ADD COLUMN IF NOT EXISTS fingerprint TEXT,
				ADD COLUMN IF NOT EXISTS first_scan_id TEXT,
				ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'new',
				ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT false,
				ADD COLUMN IF NOT EXISTS false_positive BOOLEAN DEFAULT false;

				CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
				CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
				CREATE INDEX IF NOT EXISTS idx_findings_first_scan_id ON findings(first_scan_id);

				COMMENT ON COLUMN findings.fingerprint IS 'Hash for deduplication across scans';
				COMMENT ON COLUMN findings.first_scan_id IS 'Scan ID where this vulnerability was first detected';
				COMMENT ON COLUMN findings.status IS 'Lifecycle status: new, active, fixed, duplicate, reopened';
				COMMENT ON COLUMN findings.verified IS 'Whether finding has been manually verified';
				COMMENT ON COLUMN findings.false_positive IS 'Whether finding is marked as false positive';
			`,
			Down: `
				DROP INDEX IF EXISTS idx_findings_fingerprint;
				DROP INDEX IF EXISTS idx_findings_status;
				DROP INDEX IF EXISTS idx_findings_first_scan_id;

				ALTER TABLE findings
				DROP COLUMN IF EXISTS fingerprint,
				DROP COLUMN IF EXISTS first_scan_id,
				DROP COLUMN IF EXISTS status,
				DROP COLUMN IF EXISTS verified,
				DROP COLUMN IF EXISTS false_positive;
			`,
		},
		{
			Version:     4,
			Description: "Create correlation_results table for attack chains and insights",
			Up: `
				CREATE TABLE IF NOT EXISTS correlation_results (
					id TEXT PRIMARY KEY,
					scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
					insight_type TEXT NOT NULL,
					severity TEXT NOT NULL,
					title TEXT NOT NULL,
					description TEXT,
					confidence FLOAT NOT NULL,
					related_findings JSONB,
					attack_path JSONB,
					metadata JSONB,
					created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
					updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
				);

				CREATE INDEX IF NOT EXISTS idx_correlation_scan_id ON correlation_results(scan_id);
				CREATE INDEX IF NOT EXISTS idx_correlation_severity ON correlation_results(severity);
				CREATE INDEX IF NOT EXISTS idx_correlation_type ON correlation_results(insight_type);
				CREATE INDEX IF NOT EXISTS idx_correlation_created_at ON correlation_results(created_at);

				COMMENT ON TABLE correlation_results IS 'Stores correlation insights, attack chains, and vulnerability relationships';
				COMMENT ON COLUMN correlation_results.insight_type IS 'Type: attack_chain, infrastructure_correlation, temporal_pattern, technology_vulnerability';
				COMMENT ON COLUMN correlation_results.confidence IS 'Confidence score 0.0-1.0';
				COMMENT ON COLUMN correlation_results.related_findings IS 'Array of finding IDs that contribute to this insight';
				COMMENT ON COLUMN correlation_results.attack_path IS 'Step-by-step attack chain with exploitability scores';
			`,
			Down: `
				DROP TABLE IF EXISTS correlation_results CASCADE;
			`,
		},
		{
			Version:     5,
			Description: "Backfill fingerprints and status for existing findings",
			Up: `
				-- Update existing findings to set status='active' where NULL
				-- (New findings after migration v3 will have status='new' by default)
				UPDATE findings
				SET status = 'active'
				WHERE status IS NULL;

				-- Set first_scan_id to scan_id for existing findings where not set
				-- (This establishes baseline for temporal tracking)
				UPDATE findings
				SET first_scan_id = scan_id
				WHERE first_scan_id IS NULL;

				-- Note: Fingerprint backfill cannot be done in SQL because it requires
				-- complex logic to extract target from metadata or evidence.
				-- The application will regenerate fingerprints on next scan using the
				-- enhanced generateFindingFingerprint() function.
				-- Old findings without fingerprints will be treated as new occurrences
				-- until they are rescanned.

				COMMENT ON COLUMN findings.status IS 'Migration v5: Backfilled existing findings with status=active';
			`,
			Down: `
				-- Rollback: Reset backfilled data
				UPDATE findings
				SET status = NULL
				WHERE status = 'active' AND created_at < (
					SELECT applied_at FROM schema_migrations WHERE version = 5
				);

				UPDATE findings
				SET first_scan_id = NULL
				WHERE first_scan_id = scan_id AND created_at < (
					SELECT applied_at FROM schema_migrations WHERE version = 5
				);
			`,
		},
		{
			Version:     6,
			Description: "Add database constraints and GIN indexes for performance and data integrity",
			Up: `
				-- Add foreign key constraint for first_scan_id (ensures referential integrity)
				-- Note: This assumes first_scan_id references scans(id)
				-- Skip if constraint already exists
				DO $$
				BEGIN
					IF NOT EXISTS (
						SELECT 1 FROM pg_constraint
						WHERE conname = 'fk_findings_first_scan_id'
					) THEN
						ALTER TABLE findings
						ADD CONSTRAINT fk_findings_first_scan_id
						FOREIGN KEY (first_scan_id) REFERENCES scans(id) ON DELETE SET NULL;
					END IF;
				END $$;

				-- Add check constraint for status enum (prevents invalid status values)
				DO $$
				BEGIN
					IF NOT EXISTS (
						SELECT 1 FROM pg_constraint
						WHERE conname = 'chk_findings_status'
					) THEN
						ALTER TABLE findings
						ADD CONSTRAINT chk_findings_status
						CHECK (status IN ('new', 'active', 'fixed', 'duplicate', 'reopened'));
					END IF;
				END $$;

				-- Add check constraint for severity enum
				DO $$
				BEGIN
					IF NOT EXISTS (
						SELECT 1 FROM pg_constraint
						WHERE conname = 'chk_findings_severity'
					) THEN
						ALTER TABLE findings
						ADD CONSTRAINT chk_findings_severity
						CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'));
					END IF;
				END $$;

				-- Add NOT NULL constraints for critical fields
				ALTER TABLE findings ALTER COLUMN fingerprint SET NOT NULL;
				ALTER TABLE findings ALTER COLUMN first_scan_id SET NOT NULL;
				ALTER TABLE findings ALTER COLUMN status SET NOT NULL;

				-- Add GIN indexes for JSONB columns (PostgreSQL only, enables fast JSONB queries)
				-- These indexes dramatically improve queries like: metadata @> '{"key": "value"}'
				CREATE INDEX IF NOT EXISTS idx_findings_metadata_gin ON findings USING GIN (metadata);
				CREATE INDEX IF NOT EXISTS idx_correlation_related_findings_gin ON correlation_results USING GIN (related_findings);
				CREATE INDEX IF NOT EXISTS idx_correlation_attack_path_gin ON correlation_results USING GIN (attack_path);
				CREATE INDEX IF NOT EXISTS idx_correlation_metadata_gin ON correlation_results USING GIN (metadata);

				-- Add composite indexes for common query patterns
				-- Regression queries: WHERE status = 'reopened' ORDER BY created_at DESC
				CREATE INDEX IF NOT EXISTS idx_findings_status_created ON findings(status, created_at DESC);

				-- Timeline queries: WHERE fingerprint = ? ORDER BY created_at ASC
				CREATE INDEX IF NOT EXISTS idx_findings_fingerprint_created ON findings(fingerprint, created_at ASC);

				-- Fixed findings: WHERE status = 'fixed' ORDER BY updated_at DESC
				CREATE INDEX IF NOT EXISTS idx_findings_status_updated ON findings(status, updated_at DESC);

				-- Add unique constraint on fingerprint + scan_id (prevents exact duplicates within same scan)
				CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint_scan_unique ON findings(fingerprint, scan_id);

				-- Add comments for documentation
				COMMENT ON CONSTRAINT fk_findings_first_scan_id ON findings IS 'Ensures first_scan_id references valid scan';
				COMMENT ON CONSTRAINT chk_findings_status ON findings IS 'Enforces valid status enum values';
				COMMENT ON CONSTRAINT chk_findings_severity ON findings IS 'Enforces valid severity enum values';
			`,
			Down: `
				-- Remove composite indexes
				DROP INDEX IF EXISTS idx_findings_status_created;
				DROP INDEX IF EXISTS idx_findings_fingerprint_created;
				DROP INDEX IF EXISTS idx_findings_status_updated;
				DROP INDEX IF EXISTS idx_findings_fingerprint_scan_unique;

				-- Remove GIN indexes
				DROP INDEX IF EXISTS idx_findings_metadata_gin;
				DROP INDEX IF EXISTS idx_correlation_related_findings_gin;
				DROP INDEX IF EXISTS idx_correlation_attack_path_gin;
				DROP INDEX IF EXISTS idx_correlation_metadata_gin;

				-- Remove NOT NULL constraints
				ALTER TABLE findings ALTER COLUMN fingerprint DROP NOT NULL;
				ALTER TABLE findings ALTER COLUMN first_scan_id DROP NOT NULL;
				ALTER TABLE findings ALTER COLUMN status DROP NOT NULL;

				-- Remove check constraints
				ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_status;
				ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_severity;

				-- Remove foreign key constraint
				ALTER TABLE findings DROP CONSTRAINT IF EXISTS fk_findings_first_scan_id;
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
		"current_version": appliedVersion,
		"latest_version":  latestVersion,
		"pending_count":   pendingCount,
		"is_up_to_date":   pendingCount == 0,
		"applied_count":   len(appliedMigrations),
		"available_count": len(allMigrations),
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
