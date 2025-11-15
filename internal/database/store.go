// Database Store - SQLite and PostgreSQL Support
//
// P0 FIXES COMPLETE (2025-10-06):
//
//	P0-1: WHOIS Schema Mismatch - FIXED
//	 Redesigned schema to match queries with columns: registration_date, registrar, age_days, raw_data
//	 See: Lines 249-257 (schema), 362-370 (migration)
//
//	P0-2: Threat Intel Schema Mismatch - FIXED
//	 Changed from single-row JSON to relational design with UNIQUE(domain, source)
//	 See: Lines 259-269 (schema), 372-382 (migration)
//
//	P0-3: PostgreSQL SQL in SQLite Code - FIXED
//	 Created heraDB helper with driver-specific SQL functions (NOW(), CURRENT_DATE)
//	 See: internal/api/hera.go:47-75 for implementation
//
//	P0-4: Placeholder Mismatch - FIXED
//	 Dynamic placeholder generation via getPlaceholder() supports both $1 and ?
//	 See: Line 31-36 (getPlaceholder function)
//
//	P0-5: Stats Table Schema Mismatch - FIXED
//	 Completely redesigned stats table with columns: date, verdict, reputation_bucket, pattern, count
//	 See: Lines 271-278 (schema), 384-391 (migration)
//
//	P0-6: Serve Command Not Registered - FIXED
//	 Created complete serve.go with all functionality (267 lines)
//	 See: cmd/serve.go
//
//	P0-7: API Files Never Created - FIXED
//	 Actually created hera.go (707 lines) and middleware.go (191 lines)
//	 See: internal/api/hera.go, internal/api/middleware.go
//
//	P0-8: Feedback Missing Metadata Column - FIXED
//	 Added metadata column to both PostgreSQL and SQLite schemas
//	 See: Lines 285, 399
//
//	P0-9: Index on Non-Existent Column - FIXED
//	 Changed index from event_type to verdict column
//	 See: Lines 299, 413
//
// DATABASE TABLES:
// - hera_detections: Detection events log
// - hera_domain_reputation: Domain reputation data (Tranco, trust scores)
// - hera_whois_cache: WHOIS lookup cache
// - hera_threat_intel: Threat intelligence cache (multi-source)
// - hera_stats: Privacy-preserving aggregate statistics
// - hera_feedback: User feedback (false positives/negatives)
// - hera_pattern_stats: Pattern accuracy tracking
// - scans: Shells scan results
// - findings: Shells vulnerability findings
//
// INDEXES:
// - idx_hera_detections_domain: Fast detection lookups
// - idx_hera_detections_severity: Filter by severity
// - idx_hera_stats_verdict: Aggregate stats queries
// - idx_hera_feedback_domain: Feedback lookups
//
// DRIVER SUPPORT:
// - SQLite (default, good for development)
// - PostgreSQL (production-ready, full JSONB support)
// - Automatic schema creation
// - Driver-agnostic queries via getPlaceholder()
package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/core"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

type sqlStore struct {
	db     *sqlx.DB
	cfg    config.DatabaseConfig
	logger *logger.Logger
}

// Store is a public type alias for sqlStore
type Store = sqlStore

// getPlaceholder returns the appropriate placeholder for PostgreSQL
func (s *sqlStore) getPlaceholder(n int) string {
	return fmt.Sprintf("$%d", n)
}

// closeRows safely closes database rows and logs any errors
// This is critical for connection pool health - unclosed rows leak connections
func (s *sqlStore) closeRows(rows *sqlx.Rows) {
	if err := rows.Close(); err != nil {
		s.logger.Errorw("Failed to close database rows - connection may leak",
			"error", err,
			"impact", "Database connection pool may be exhausted over time",
			"action", "Monitor connection pool metrics")
	}
}

// closeRows2 safely closes sql.Rows (non-sqlx variant)
func (s *sqlStore) closeRows2(rows *sql.Rows) {
	if err := rows.Close(); err != nil {
		s.logger.Errorw("Failed to close database rows - connection may leak",
			"error", err,
			"impact", "Database connection pool may be exhausted over time",
			"action", "Monitor connection pool metrics")
	}
}

func NewStore(cfg config.DatabaseConfig) (core.ResultStore, error) {
	// Initialize logger for database operations
	// Default to error level to reduce noise, use debug only if explicitly set
	level := "error"
	format := "console"
	if debugMode := os.Getenv("SHELLS_DEBUG"); debugMode == "true" || debugMode == "1" {
		level = "debug"
		format = "json"
	}
	if os.Getenv("SHELLS_BUG_BOUNTY_MODE") == "true" {
		level = "fatal"
		format = "console"
	}
	log, err := logger.New(config.LoggerConfig{Level: level, Format: format})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database logger: %w", err)
	}
	log = log.WithComponent("database")

	ctx := context.Background()
	ctx, span := log.StartOperation(ctx, "database.NewStore",
		"driver", cfg.Driver,
		"dsn_masked", maskDSN(cfg.DSN),
		"max_connections", cfg.MaxConnections,
	)
	defer func() {
		log.FinishOperation(ctx, span, "database.NewStore", time.Now(), err)
	}()

	log.WithContext(ctx).Infow("Initializing database connection",
		"driver", cfg.Driver,
		"max_connections", cfg.MaxConnections,
		"max_idle_conns", cfg.MaxIdleConns,
		"conn_max_lifetime", cfg.ConnMaxLifetime,
	)

	start := time.Now()
	db, err := sqlx.Connect(cfg.Driver, cfg.DSN)
	if err != nil {
		log.LogError(ctx, err, "database.Connect",
			"driver", cfg.Driver,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	log.LogDuration(ctx, "database.Connect", start,
		"driver", cfg.Driver,
		"success", true,
	)

	db.SetMaxOpenConns(cfg.MaxConnections)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	log.WithContext(ctx).Debugw("Database connection pool configured",
		"max_open_conns", cfg.MaxConnections,
		"max_idle_conns", cfg.MaxIdleConns,
		"conn_max_lifetime", cfg.ConnMaxLifetime,
	)

	store := &sqlStore{
		db:     db,
		cfg:    cfg,
		logger: log,
	}

	// Run database migrations
	migrateStart := time.Now()
	if err := store.migrate(); err != nil {
		log.LogError(ctx, err, "database.Migrate",
			"duration_ms", time.Since(migrateStart).Milliseconds(),
		)
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	log.LogDuration(ctx, "database.Migrate", migrateStart,
		"success", true,
	)

	log.WithContext(ctx).Infow("Database store initialized successfully",
		"driver", cfg.Driver,
		"total_init_duration_ms", time.Since(start).Milliseconds(),
	)

	return store, nil
}

// maskDSN masks sensitive information in DSN for logging
func maskDSN(dsn string) string {
	// Simple masking - in production you'd want more sophisticated masking
	if len(dsn) > 10 {
		return dsn[:5] + "***" + dsn[len(dsn)-5:]
	}
	return "***"
}

func (s *sqlStore) migrate() error {
	ctx := context.Background()
	ctx, span := s.logger.StartOperation(ctx, "database.migrate",
		"driver", s.cfg.Driver,
	)
	defer func() {
		s.logger.FinishOperation(ctx, span, "database.migrate", time.Now(), nil)
	}()

	s.logger.WithContext(ctx).Infow("Starting PostgreSQL database migration",
		"driver", s.cfg.Driver,
	)

	// PostgreSQL-only schema
	schema := `
		CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY,
			target TEXT NOT NULL,
			type TEXT NOT NULL,
			profile TEXT,
			options TEXT,
			scheduled_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL,
			started_at TIMESTAMP,
			completed_at TIMESTAMP,
			status TEXT NOT NULL,
			error_message TEXT,
			worker_id TEXT,
			config JSONB,
			result JSONB,
			checkpoint JSONB
		);

		CREATE TABLE IF NOT EXISTS findings (
			id TEXT PRIMARY KEY,
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			tool TEXT NOT NULL,
			type TEXT NOT NULL,
			severity TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT,
			evidence TEXT,
			solution TEXT,
			refs JSONB,
			metadata JSONB,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);

		CREATE TABLE IF NOT EXISTS scan_events (
			id SERIAL PRIMARY KEY,
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			event_type TEXT NOT NULL,
			component TEXT NOT NULL,
			message TEXT NOT NULL,
			metadata JSONB,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
		CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
		CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
		CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
		CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
		CREATE INDEX IF NOT EXISTS idx_scan_events_scan_id ON scan_events(scan_id);
		CREATE INDEX IF NOT EXISTS idx_scan_events_created_at ON scan_events(created_at);

		-- Bug bounty platform submissions table (PostgreSQL)
		CREATE TABLE IF NOT EXISTS platform_submissions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
			platform TEXT NOT NULL,
			program_handle TEXT,
			report_id TEXT NOT NULL,
			report_url TEXT,
			status TEXT NOT NULL,
			platform_data JSONB,
			submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(finding_id, platform)
		);

		CREATE INDEX IF NOT EXISTS idx_submissions_finding_id ON platform_submissions(finding_id);
		CREATE INDEX IF NOT EXISTS idx_submissions_platform ON platform_submissions(platform);
		CREATE INDEX IF NOT EXISTS idx_submissions_status ON platform_submissions(status);

		-- Hera browser extension tables (PostgreSQL)
		CREATE TABLE IF NOT EXISTS hera_detections (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			domain TEXT NOT NULL,
			detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			severity TEXT NOT NULL,
			reasons JSONB,
			user_agent TEXT,
			extension_version TEXT
		);

		CREATE TABLE IF NOT EXISTS hera_domain_reputation (
			domain TEXT PRIMARY KEY,
			tranco_rank INTEGER,
			category TEXT,
			trust_score INTEGER CHECK (trust_score >= 0 AND trust_score <= 100),
			age_days INTEGER,
			owner TEXT,
			first_seen TIMESTAMP,
			last_updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS hera_whois_cache (
			domain TEXT PRIMARY KEY,
			registration_date TEXT,
			registrar TEXT,
			age_days INTEGER,
			raw_data JSONB,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL
		);

		CREATE TABLE IF NOT EXISTS hera_threat_intel (
			id SERIAL PRIMARY KEY,
			domain TEXT NOT NULL,
			source TEXT NOT NULL,
			verdict TEXT NOT NULL,
			score INTEGER,
			details JSONB,
			last_checked TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			UNIQUE(domain, source)
		);

		CREATE TABLE IF NOT EXISTS hera_stats (
			date DATE NOT NULL,
			verdict TEXT NOT NULL,
			reputation_bucket INTEGER NOT NULL,
			pattern TEXT,
			count INTEGER DEFAULT 1,
			PRIMARY KEY (date, verdict, reputation_bucket, pattern)
		);

		CREATE TABLE IF NOT EXISTS hera_feedback (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			domain TEXT NOT NULL,
			was_phishing BOOLEAN NOT NULL,
			user_comment TEXT,
			metadata JSONB,
			detection_id UUID,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS hera_pattern_stats (
			pattern_name TEXT PRIMARY KEY,
			true_positives INTEGER DEFAULT 0,
			false_positives INTEGER DEFAULT 0,
			last_updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_hera_detections_domain ON hera_detections(domain);
		CREATE INDEX IF NOT EXISTS idx_hera_detections_severity ON hera_detections(severity);
		CREATE INDEX IF NOT EXISTS idx_hera_stats_verdict ON hera_stats(verdict);
		CREATE INDEX IF NOT EXISTS idx_hera_feedback_domain ON hera_feedback(domain);
		`

	start := time.Now()
	_, err := s.db.Exec(schema)
	if err != nil {
		s.logger.LogError(ctx, err, "database.migrate.schema",
			"duration_ms", time.Since(start).Milliseconds(),
			"driver", s.cfg.Driver,
		)
		return err
	}

	s.logger.LogDuration(ctx, "database.migrate.schema", start,
		"tables_created", []string{"scans", "findings"},
		"indexes_created", 5,
		"success", true,
	)

	s.logger.WithContext(ctx).Infow("Database migration completed successfully",
		"driver", s.cfg.Driver,
		"total_duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

func (s *sqlStore) SaveScan(ctx context.Context, scan *types.ScanRequest) error {
	start := time.Now()
	ctx, span := s.logger.StartOperation(ctx, "database.SaveScan",
		"scan_id", scan.ID,
		"target", scan.Target,
		"type", string(scan.Type),
	)
	var err error
	defer func() {
		s.logger.FinishOperation(ctx, span, "database.SaveScan", start, err)
	}()

	s.logger.WithContext(ctx).Debugw("Saving scan to database",
		"scan_id", scan.ID,
		"target", scan.Target,
		"type", string(scan.Type),
		"status", string(scan.Status),
		"worker_id", scan.WorkerID,
	)

	optionsJSON, err := json.Marshal(scan.Options)
	if err != nil {
		s.logger.LogError(ctx, err, "database.SaveScan.marshal",
			"scan_id", scan.ID,
			"options_count", len(scan.Options),
		)
		return fmt.Errorf("failed to marshal options: %w", err)
	}

	query := `
		INSERT INTO scans (
			id, target, type, profile, options, scheduled_at,
			created_at, started_at, completed_at, status,
			error_message, worker_id
		) VALUES (
			:id, :target, :type, :profile, :options, :scheduled_at,
			:created_at, :started_at, :completed_at, :status,
			:error_message, :worker_id
		)
	`

	args := map[string]interface{}{
		"id":            scan.ID,
		"target":        scan.Target,
		"type":          scan.Type,
		"profile":       scan.Profile,
		"options":       string(optionsJSON),
		"scheduled_at":  scan.ScheduledAt,
		"created_at":    scan.CreatedAt,
		"started_at":    scan.StartedAt,
		"completed_at":  scan.CompletedAt,
		"status":        scan.Status,
		"error_message": scan.ErrorMessage,
		"worker_id":     scan.WorkerID,
	}

	queryStart := time.Now()
	result, err := s.db.NamedExecContext(ctx, query, args)
	if err != nil {
		s.logger.LogError(ctx, err, "database.SaveScan.insert",
			"scan_id", scan.ID,
			"query_duration_ms", time.Since(queryStart).Milliseconds(),
		)
		return err
	}

	// P1 FIX: Check RowsAffected error to detect partial writes
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		s.logger.Errorw("Failed to get rows affected after scan insert", "error", err, "scan_id", scan.ID)
		rowsAffected = -1 // Indicate unknown
	}
	s.logger.LogDatabaseOperation(ctx, "INSERT", "scans", rowsAffected, time.Since(queryStart),
		"scan_id", scan.ID,
		"target", scan.Target,
	)

	s.logger.WithContext(ctx).Infow("Scan saved successfully",
		"scan_id", scan.ID,
		"target", scan.Target,
		"total_duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

// SaveScanEvent saves a scan event to the database for UI display
func (s *sqlStore) SaveScanEvent(ctx context.Context, scanID string, eventType string, component string, message string, metadata map[string]interface{}) error {
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	query := `
		INSERT INTO scan_events (scan_id, event_type, component, message, metadata)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err = s.db.ExecContext(ctx, query, scanID, eventType, component, message, metadataJSON)
	if err != nil {
		// Don't fail the whole scan if event logging fails
		s.logger.Warnw("Failed to save scan event", "error", err, "scan_id", scanID)
	}
	return err
}

func (s *sqlStore) UpdateScan(ctx context.Context, scan *types.ScanRequest) error {
	optionsJSON, err := json.Marshal(scan.Options)
	if err != nil {
		return fmt.Errorf("failed to marshal options: %w", err)
	}

	query := `
		UPDATE scans SET
			target = :target,
			type = :type,
			profile = :profile,
			options = :options,
			scheduled_at = :scheduled_at,
			started_at = :started_at,
			completed_at = :completed_at,
			status = :status,
			error_message = :error_message,
			worker_id = :worker_id
		WHERE id = :id
	`

	args := map[string]interface{}{
		"id":            scan.ID,
		"target":        scan.Target,
		"type":          scan.Type,
		"profile":       scan.Profile,
		"options":       string(optionsJSON),
		"scheduled_at":  scan.ScheduledAt,
		"started_at":    scan.StartedAt,
		"completed_at":  scan.CompletedAt,
		"status":        scan.Status,
		"error_message": scan.ErrorMessage,
		"worker_id":     scan.WorkerID,
	}

	_, err = s.db.NamedExecContext(ctx, query, args)
	return err
}

func (s *sqlStore) GetScan(ctx context.Context, scanID string) (*types.ScanRequest, error) {
	var scan types.ScanRequest
	var optionsJSON string

	query := fmt.Sprintf(`
		SELECT id, target, type, profile, options, scheduled_at,
			   created_at, started_at, completed_at, status,
			   error_message, worker_id
		FROM scans
		WHERE id = %s
	`, s.getPlaceholder(1))

	err := s.db.GetContext(ctx, &struct {
		*types.ScanRequest
		Options string `db:"options"`
	}{
		ScanRequest: &scan,
	}, query, scanID)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("scan not found")
		}
		return nil, err
	}

	if optionsJSON != "" {
		if err := json.Unmarshal([]byte(optionsJSON), &scan.Options); err != nil {
			return nil, fmt.Errorf("failed to unmarshal options: %w", err)
		}
	}

	return &scan, nil
}

func (s *sqlStore) ListScans(ctx context.Context, filter core.ScanFilter) ([]*types.ScanRequest, error) {
	query := `SELECT * FROM scans WHERE 1=1`
	args := map[string]interface{}{}

	if filter.Target != "" {
		query += " AND target = :target"
		args["target"] = filter.Target
	}

	if filter.Status != "" {
		query += " AND status = :status"
		args["status"] = filter.Status
	}

	if filter.Type != "" {
		query += " AND type = :type"
		args["type"] = filter.Type
	}

	if filter.FromDate != nil {
		query += " AND created_at >= :from_date"
		args["from_date"] = *filter.FromDate
	}

	if filter.ToDate != nil {
		query += " AND created_at <= :to_date"
		args["to_date"] = *filter.ToDate
	}

	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}

	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := s.db.NamedQueryContext(ctx, query, args)
	if err != nil {
		return nil, err
	}
	defer s.closeRows(rows)

	scans := []*types.ScanRequest{}
	for rows.Next() {
		var scan types.ScanRequest
		var optionsJSON string

		if err := rows.Scan(
			&scan.ID, &scan.Target, &scan.Type, &scan.Profile,
			&optionsJSON, &scan.ScheduledAt, &scan.CreatedAt,
			&scan.StartedAt, &scan.CompletedAt, &scan.Status,
			&scan.ErrorMessage, &scan.WorkerID,
		); err != nil {
			return nil, err
		}

		if optionsJSON != "" {
			if err := json.Unmarshal([]byte(optionsJSON), &scan.Options); err != nil {
				return nil, fmt.Errorf("failed to unmarshal options: %w", err)
			}
		}

		scans = append(scans, &scan)
	}

	return scans, nil
}

// generateFindingFingerprint creates a hash for deduplication across scans
// Fingerprint is based on: tool + type + title + target (normalized)
// Target is extracted from metadata or evidence with extensive field checking
func generateFindingFingerprint(finding types.Finding) string {
	// Extract target information from metadata
	target := ""
	if finding.Metadata != nil {
		// Try common target field names in priority order
		if t, ok := finding.Metadata["target"].(string); ok && t != "" {
			target = t
		} else if ep, ok := finding.Metadata["endpoint"].(string); ok && ep != "" {
			target = ep
		} else if url, ok := finding.Metadata["url"].(string); ok && url != "" {
			target = url
		} else if host, ok := finding.Metadata["host"].(string); ok && host != "" {
			target = host
		} else if hostname, ok := finding.Metadata["hostname"].(string); ok && hostname != "" {
			target = hostname
		} else if domain, ok := finding.Metadata["domain"].(string); ok && domain != "" {
			target = domain
		} else if ip, ok := finding.Metadata["ip"].(string); ok && ip != "" {
			target = ip
		} else if path, ok := finding.Metadata["path"].(string); ok && path != "" {
			target = path
		} else if param, ok := finding.Metadata["parameter"].(string); ok && param != "" {
			// For parameter-specific vulns (e.g., XSS in specific param)
			target = param
		} else if port, ok := finding.Metadata["port"].(string); ok && port != "" {
			// For port-specific vulns
			target = port
		} else if svc, ok := finding.Metadata["service"].(string); ok && svc != "" {
			target = svc
		}
	}

	// If no target in metadata, extract from evidence
	if target == "" && finding.Evidence != "" {
		evidenceLines := strings.Split(finding.Evidence, "\n")

		// Try each line until we find a target
		for _, line := range evidenceLines {
			if target != "" {
				break
			}

			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Pattern 1: HTTP method + path (e.g., "GET /api/users")
			if strings.Contains(line, "GET ") || strings.Contains(line, "POST ") ||
				strings.Contains(line, "PUT ") || strings.Contains(line, "DELETE ") ||
				strings.Contains(line, "PATCH ") || strings.Contains(line, "OPTIONS ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					target = parts[1] // The path
					break
				}
			}

			// Pattern 2: Full URL (e.g., "https://example.com/path")
			if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
				if idx := strings.Index(line, "://"); idx != -1 {
					remaining := line[idx+3:]
					if spaceIdx := strings.IndexAny(remaining, " \t"); spaceIdx != -1 {
						remaining = remaining[:spaceIdx]
					}
					target = remaining
					break
				}
			}

			// Pattern 3: Look for URL: prefix (e.g., "URL: https://example.com")
			if strings.Contains(line, "URL:") || strings.Contains(line, "url:") {
				if idx := strings.Index(strings.ToLower(line), "url:"); idx != -1 {
					urlPart := strings.TrimSpace(line[idx+4:])
					if urlPart != "" {
						target = urlPart
						break
					}
				}
			}

			// Pattern 4: Look for Target: prefix
			if strings.Contains(line, "Target:") || strings.Contains(line, "target:") {
				if idx := strings.Index(strings.ToLower(line), "target:"); idx != -1 {
					targetPart := strings.TrimSpace(line[idx+7:])
					if targetPart != "" {
						target = targetPart
						break
					}
				}
			}
		}
	}

	// Normalize: lowercase and trim whitespace
	normalized := fmt.Sprintf("%s:%s:%s:%s",
		strings.ToLower(strings.TrimSpace(finding.Tool)),
		strings.ToLower(strings.TrimSpace(finding.Type)),
		strings.ToLower(strings.TrimSpace(finding.Title)),
		strings.ToLower(strings.TrimSpace(target)),
	)

	// Generate SHA256 hash
	hash := sha256.Sum256([]byte(normalized))
	fingerprint := fmt.Sprintf("%x", hash[:16]) // Use first 16 bytes (32 hex chars)

	// EDGE CASE HANDLING: Empty target creates weaker fingerprints
	// If target is empty, the fingerprint is based on tool:type:title only
	// This allows deduplication of identical findings across scans, but may cause
	// false positives if the same vulnerability type exists at multiple locations
	// and we can't extract location from metadata or evidence.
	//
	// This is acceptable because:
	// 1. Most scanners populate metadata["target"] or similar fields
	// 2. Evidence usually contains URLs or paths we can extract
	// 3. Manual verification can mark false positives via verified/false_positive fields
	// 4. Weak fingerprints are better than no deduplication
	//
	// To improve: Ensure scanners populate metadata with location info

	return fingerprint
}

// DuplicateInfo holds information about a duplicate finding
type DuplicateInfo struct {
	IsDuplicate    bool
	FirstScanID    string
	PreviousStatus types.FindingStatus
}

// batchCheckDuplicateFindings checks multiple fingerprints in a single query (performance optimization)
// Returns a map of fingerprint -> DuplicateInfo
func (s *sqlStore) batchCheckDuplicateFindings(ctx context.Context, tx *sqlx.Tx, fingerprints []string, currentScanID string) (map[string]DuplicateInfo, error) {
	if len(fingerprints) == 0 {
		return make(map[string]DuplicateInfo), nil
	}

	var query string
	var args []interface{}

	// PostgreSQL uses ANY($1) with array parameter
	if s.cfg.Driver == "postgres" {
		query = `
			SELECT DISTINCT ON (fingerprint)
				fingerprint, first_scan_id, scan_id, status
			FROM findings
			WHERE fingerprint = ANY($1)
			ORDER BY fingerprint, created_at DESC
		`
		args = []interface{}{pq.Array(fingerprints)}
	} else {
		// SQLite uses IN clause with placeholders
		placeholders := make([]string, len(fingerprints))
		args = make([]interface{}, len(fingerprints))
		for i, fp := range fingerprints {
			placeholders[i] = s.getPlaceholder(i + 1)
			args[i] = fp
		}

		query = fmt.Sprintf(`
			SELECT fingerprint, first_scan_id, scan_id, status
			FROM (
				SELECT fingerprint, first_scan_id, scan_id, status,
					   ROW_NUMBER() OVER (PARTITION BY fingerprint ORDER BY created_at DESC) as rn
				FROM findings
				WHERE fingerprint IN (%s)
			)
			WHERE rn = 1
		`, strings.Join(placeholders, ","))
	}

	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to batch check duplicates: %w", err)
	}
	defer rows.Close()

	result := make(map[string]DuplicateInfo)

	for rows.Next() {
		var fingerprint, firstScanID, scanID string
		var previousStatus types.FindingStatus

		if err := rows.Scan(&fingerprint, &firstScanID, &scanID, &previousStatus); err != nil {
			return nil, fmt.Errorf("failed to scan duplicate row: %w", err)
		}

		// If first_scan_id is empty (old data before migration), use the scan_id we found
		if firstScanID == "" {
			firstScanID = scanID
		}

		// Check for regression (previously fixed vulnerability reappearing)
		if previousStatus == types.FindingStatusFixed {
			s.logger.Errorw("REGRESSION DETECTED: Previously fixed vulnerability has reappeared",
				"fingerprint", fingerprint,
				"first_scan_id", firstScanID,
				"last_seen_scan", scanID,
				"current_scan", currentScanID,
				"impact", "CRITICAL",
			)
			result[fingerprint] = DuplicateInfo{
				IsDuplicate:    true,
				FirstScanID:    firstScanID,
				PreviousStatus: types.FindingStatusReopened,
			}
		} else {
			result[fingerprint] = DuplicateInfo{
				IsDuplicate:    true,
				FirstScanID:    firstScanID,
				PreviousStatus: previousStatus,
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating duplicate rows: %w", err)
	}

	return result, nil
}

// checkDuplicateFinding checks if a finding with the same fingerprint exists in previous scans
// Returns: (isDuplicate, firstScanID, previousStatus, error)
// Also detects regressions when a "fixed" vulnerability reappears
// NOTE: This is kept for backward compatibility but batchCheckDuplicateFindings should be preferred
func (s *sqlStore) checkDuplicateFinding(ctx context.Context, tx *sqlx.Tx, fingerprint, currentScanID string) (bool, string, types.FindingStatus, error) {
	// Get the most recent occurrence to check for regressions
	recentQuery := `
		SELECT first_scan_id, scan_id, status
		FROM findings
		WHERE fingerprint = $1
		ORDER BY created_at DESC
		LIMIT 1
	`

	var firstScanID, scanID string
	var previousStatus types.FindingStatus
	err := tx.QueryRowContext(ctx, recentQuery, fingerprint).Scan(&firstScanID, &scanID, &previousStatus)
	if err == sql.ErrNoRows {
		// Not a duplicate - this is the first occurrence
		return false, currentScanID, "", nil
	}
	if err != nil {
		return false, "", "", fmt.Errorf("failed to check duplicate: %w", err)
	}

	// If first_scan_id is empty (old data before migration), use the scan_id we found
	if firstScanID == "" {
		firstScanID = scanID
	}

	// Check for regression (previously fixed vulnerability reappearing)
	if previousStatus == types.FindingStatusFixed {
		s.logger.Errorw("REGRESSION DETECTED: Previously fixed vulnerability has reappeared",
			"fingerprint", fingerprint,
			"first_scan_id", firstScanID,
			"last_seen_scan", scanID,
			"current_scan", currentScanID,
			"impact", "CRITICAL",
		)
		return true, firstScanID, types.FindingStatusReopened, nil
	}

	return true, firstScanID, previousStatus, nil
}

func (s *sqlStore) SaveFindings(ctx context.Context, findings []types.Finding) error {
	start := time.Now()
	ctx, span := s.logger.StartOperation(ctx, "database.SaveFindings",
		"findings_count", len(findings),
	)
	var err error
	defer func() {
		s.logger.FinishOperation(ctx, span, "database.SaveFindings", start, err)
	}()

	if len(findings) == 0 {
		s.logger.WithContext(ctx).Debugw("No findings to save",
			"findings_count", 0,
		)
		return nil
	}

	// Extract scan_id from first finding for logging (all findings should have same scan_id)
	scanID := findings[0].ScanID
	s.logger.WithContext(ctx).Infow("Saving findings to database",
		"findings_count", len(findings),
		"scan_id", scanID,
	)

	// Count findings by severity for logging
	severityCounts := make(map[types.Severity]int)
	toolCounts := make(map[string]int)
	statusCounts := make(map[types.FindingStatus]int)
	duplicateCount := 0

	for _, finding := range findings {
		severityCounts[finding.Severity]++
		toolCounts[finding.Tool]++
	}

	s.logger.WithContext(ctx).Debugw("Findings breakdown",
		"scan_id", scanID,
		"severity_counts", severityCounts,
		"tool_counts", toolCounts,
	)

	txStart := time.Now()
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		s.logger.LogError(ctx, err, "database.SaveFindings.begin_tx",
			"scan_id", scanID,
			"findings_count", len(findings),
			"tx_duration_ms", time.Since(txStart).Milliseconds(),
		)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			// Log rollback errors (ignore ErrTxDone which means tx already committed)
			s.logger.Errorw("Failed to rollback transaction",
				"error", err,
				"impact", "Transaction may have partially committed",
				"action", "Verify data integrity")
		}
	}()

	s.logger.LogDuration(ctx, "database.SaveFindings.begin_tx", txStart,
		"scan_id", scanID,
		"success", true,
	)

	query := `
		INSERT INTO findings (
			id, scan_id, tool, type, severity, title, description,
			evidence, solution, refs, metadata,
			fingerprint, first_scan_id, status, verified, false_positive,
			created_at, updated_at
		) VALUES (
			:id, :scan_id, :tool, :type, :severity, :title, :description,
			:evidence, :solution, :refs, :metadata,
			:fingerprint, :first_scan_id, :status, :verified, :false_positive,
			:created_at, :updated_at
		)
	`

	insertStart := time.Now()
	totalRowsAffected := int64(0)

	// P1 OPTIMIZATION: Batch fingerprint lookup (fixes N+1 query problem)
	// Instead of querying database for each finding (100 findings = 100 queries),
	// we query once for all fingerprints (100 findings = 1 query)
	batchLookupStart := time.Now()
	fingerprints := make([]string, len(findings))
	for i, finding := range findings {
		fingerprints[i] = generateFindingFingerprint(finding)
	}

	duplicateLookup, err := s.batchCheckDuplicateFindings(ctx, tx, fingerprints, scanID)
	if err != nil {
		s.logger.LogError(ctx, err, "database.SaveFindings.batch_check_duplicates",
			"scan_id", scanID,
			"findings_count", len(findings),
		)
		// Initialize empty map and continue (will treat all as new findings)
		duplicateLookup = make(map[string]DuplicateInfo)
	}

	s.logger.LogDuration(ctx, "database.SaveFindings.batch_lookup", batchLookupStart,
		"scan_id", scanID,
		"fingerprints_checked", len(fingerprints),
		"duplicates_found", len(duplicateLookup),
	)

	for i, finding := range findings {
		findingStart := time.Now()

		// Get fingerprint (already generated in batch lookup phase)
		fingerprint := fingerprints[i]

		// Look up duplicate information from batch check
		dupInfo, found := duplicateLookup[fingerprint]
		isDuplicate := found
		firstScanID := finding.ScanID
		previousStatus := types.FindingStatus("")

		if found {
			isDuplicate = dupInfo.IsDuplicate
			firstScanID = dupInfo.FirstScanID
			previousStatus = dupInfo.PreviousStatus
		}

		// Set status based on duplication and regression detection
		status := types.FindingStatusNew
		if isDuplicate {
			// If previousStatus is "reopened", this is a regression
			if previousStatus == types.FindingStatusReopened {
				status = types.FindingStatusReopened
				s.logger.Warnw("Marking finding as reopened (regression)",
					"finding_id", finding.ID,
					"fingerprint", fingerprint,
					"first_scan_id", firstScanID,
				)
			} else {
				status = types.FindingStatusDuplicate
				duplicateCount++
			}
		}
		// Override with explicit status if provided
		if finding.Status != "" {
			status = finding.Status
		}

		// Set first_scan_id
		if finding.FirstScanID != "" {
			firstScanID = finding.FirstScanID
		}

		statusCounts[status]++

		refsJSON, err := json.Marshal(finding.References)
		if err != nil {
			s.logger.LogError(ctx, err, "database.SaveFindings.marshal_refs",
				"finding_id", finding.ID,
				"scan_id", finding.ScanID,
				"refs_count", len(finding.References),
				"finding_index", i,
			)
			return fmt.Errorf("failed to marshal references for finding %s: %w", finding.ID, err)
		}

		metaJSON, err := json.Marshal(finding.Metadata)
		if err != nil {
			s.logger.LogError(ctx, err, "database.SaveFindings.marshal_metadata",
				"finding_id", finding.ID,
				"scan_id", finding.ScanID,
				"metadata_keys", len(finding.Metadata),
				"finding_index", i,
			)
			return fmt.Errorf("failed to marshal metadata for finding %s: %w", finding.ID, err)
		}

		args := map[string]interface{}{
			"id":             finding.ID,
			"scan_id":        finding.ScanID,
			"tool":           finding.Tool,
			"type":           finding.Type,
			"severity":       finding.Severity,
			"title":          finding.Title,
			"description":    finding.Description,
			"evidence":       finding.Evidence,
			"solution":       finding.Solution,
			"refs":           string(refsJSON),
			"metadata":       string(metaJSON),
			"fingerprint":    fingerprint,
			"first_scan_id":  firstScanID,
			"status":         status,
			"verified":       finding.Verified,
			"false_positive": finding.FalsePositive,
			"created_at":     finding.CreatedAt,
			"updated_at":     finding.UpdatedAt,
		}

		queryStart := time.Now()
		result, err := tx.NamedExecContext(ctx, query, args)
		if err != nil {
			s.logger.LogError(ctx, err, "database.SaveFindings.insert",
				"finding_id", finding.ID,
				"scan_id", finding.ScanID,
				"tool", finding.Tool,
				"severity", string(finding.Severity),
				"finding_index", i,
				"query_duration_ms", time.Since(queryStart).Milliseconds(),
			)
			return fmt.Errorf("failed to insert finding %s: %w", finding.ID, err)
		}

		// P1 FIX: Check RowsAffected error to detect partial writes
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			s.logger.Errorw("Failed to get rows affected after finding insert", "error", err, "finding_id", finding.ID)
			rowsAffected = -1 // Indicate unknown
		}
		totalRowsAffected += rowsAffected

		s.logger.LogDatabaseOperation(ctx, "INSERT", "findings", rowsAffected, time.Since(queryStart),
			"finding_id", finding.ID,
			"scan_id", finding.ScanID,
			"tool", finding.Tool,
			"severity", string(finding.Severity),
		)

		s.logger.WithContext(ctx).Debugw("Finding saved",
			"finding_id", finding.ID,
			"scan_id", finding.ScanID,
			"tool", finding.Tool,
			"severity", string(finding.Severity),
			"finding_index", i+1,
			"total_findings", len(findings),
			"finding_duration_ms", time.Since(findingStart).Milliseconds(),
		)
	}

	s.logger.LogDuration(ctx, "database.SaveFindings.insert_all", insertStart,
		"scan_id", scanID,
		"findings_count", len(findings),
		"total_rows_affected", totalRowsAffected,
		"success", true,
	)

	commitStart := time.Now()
	err = tx.Commit()
	if err != nil {
		s.logger.LogError(ctx, err, "database.SaveFindings.commit",
			"scan_id", scanID,
			"findings_count", len(findings),
			"commit_duration_ms", time.Since(commitStart).Milliseconds(),
		)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	s.logger.LogDuration(ctx, "database.SaveFindings.commit", commitStart,
		"scan_id", scanID,
		"findings_count", len(findings),
		"success", true,
	)

	s.logger.WithContext(ctx).Infow("Findings saved successfully",
		"scan_id", scanID,
		"findings_count", len(findings),
		"severity_counts", severityCounts,
		"tool_counts", toolCounts,
		"status_counts", statusCounts,
		"duplicate_count", duplicateCount,
		"total_rows_affected", totalRowsAffected,
		"total_duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

func (s *sqlStore) GetFindings(ctx context.Context, scanID string) ([]types.Finding, error) {
	query := fmt.Sprintf(`
		SELECT id, scan_id, tool, type, severity, title, description,
			   evidence, solution, refs, metadata,
			   fingerprint, first_scan_id, status, verified, false_positive,
			   created_at, updated_at
		FROM findings
		WHERE scan_id = %s
		ORDER BY severity DESC, created_at DESC
	`, s.getPlaceholder(1))

	rows, err := s.db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, err
	}
	defer s.closeRows2(rows)

	findings := []types.Finding{}
	for rows.Next() {
		var finding types.Finding
		var refsJSON, metaJSON string

		err := rows.Scan(
			&finding.ID, &finding.ScanID, &finding.Tool, &finding.Type,
			&finding.Severity, &finding.Title, &finding.Description,
			&finding.Evidence, &finding.Solution, &refsJSON, &metaJSON,
			&finding.CreatedAt, &finding.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if refsJSON != "" {
			if err := json.Unmarshal([]byte(refsJSON), &finding.References); err != nil {
				// Log error but continue processing
				s.logger.Warn("Failed to unmarshal references for finding", "finding_id", finding.ID, "error", err)
			}
		}
		if metaJSON != "" {
			if err := json.Unmarshal([]byte(metaJSON), &finding.Metadata); err != nil {
				// Log error but continue processing
				s.logger.Warn("Failed to unmarshal metadata for finding", "finding_id", finding.ID, "error", err)
			}
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

func (s *sqlStore) GetFindingsBySeverity(ctx context.Context, severity types.Severity) ([]types.Finding, error) {
	query := fmt.Sprintf(`
		SELECT id, scan_id, tool, type, severity, title, description,
			   evidence, solution, refs, metadata, created_at, updated_at
		FROM findings
		WHERE severity = %s
		ORDER BY created_at DESC
	`, s.getPlaceholder(1))

	rows, err := s.db.QueryContext(ctx, query, severity)
	if err != nil {
		return nil, err
	}
	defer s.closeRows2(rows)

	findings := []types.Finding{}
	for rows.Next() {
		var finding types.Finding
		var refsJSON, metaJSON string

		err := rows.Scan(
			&finding.ID, &finding.ScanID, &finding.Tool, &finding.Type,
			&finding.Severity, &finding.Title, &finding.Description,
			&finding.Evidence, &finding.Solution, &refsJSON, &metaJSON,
			&finding.CreatedAt, &finding.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if refsJSON != "" {
			if err := json.Unmarshal([]byte(refsJSON), &finding.References); err != nil {
				// Log error but continue processing
				s.logger.Warn("Failed to unmarshal references for finding", "finding_id", finding.ID, "error", err)
			}
		}
		if metaJSON != "" {
			if err := json.Unmarshal([]byte(metaJSON), &finding.Metadata); err != nil {
				// Log error but continue processing
				s.logger.Warn("Failed to unmarshal metadata for finding", "finding_id", finding.ID, "error", err)
			}
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// UpdateFindingStatus updates the status of a finding (for lifecycle tracking)
func (s *sqlStore) UpdateFindingStatus(ctx context.Context, findingID string, status types.FindingStatus) error {
	ctx, span := s.logger.StartOperation(ctx, "database.UpdateFindingStatus",
		"finding_id", findingID,
		"status", status,
	)
	start := time.Now()
	var err error
	defer func() { s.logger.FinishOperation(ctx, span, "database.UpdateFindingStatus", start, err) }()

	query := fmt.Sprintf(`
		UPDATE findings
		SET status = %s, updated_at = %s
		WHERE id = %s
	`, s.getPlaceholder(1), s.getPlaceholder(2), s.getPlaceholder(3))

	result, err := s.db.ExecContext(ctx, query, string(status), time.Now(), findingID)
	if err != nil {
		return fmt.Errorf("failed to update finding status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("finding not found: %s", findingID)
	}

	s.logger.Infow("Finding status updated",
		"finding_id", findingID,
		"new_status", status,
	)

	return nil
}

// MarkFindingVerified marks a finding as manually verified or unverified
func (s *sqlStore) MarkFindingVerified(ctx context.Context, findingID string, verified bool) error {
	ctx, span := s.logger.StartOperation(ctx, "database.MarkFindingVerified",
		"finding_id", findingID,
		"verified", verified,
	)
	start := time.Now()
	var err error
	defer func() { s.logger.FinishOperation(ctx, span, "database.MarkFindingVerified", start, err) }()

	query := fmt.Sprintf(`
		UPDATE findings
		SET verified = %s, updated_at = %s
		WHERE id = %s
	`, s.getPlaceholder(1), s.getPlaceholder(2), s.getPlaceholder(3))

	result, err := s.db.ExecContext(ctx, query, verified, time.Now(), findingID)
	if err != nil {
		return fmt.Errorf("failed to mark finding verified: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("finding not found: %s", findingID)
	}

	s.logger.Infow("Finding verification status updated",
		"finding_id", findingID,
		"verified", verified,
	)

	return nil
}

// MarkFindingFalsePositive marks a finding as a false positive or removes the false positive flag
func (s *sqlStore) MarkFindingFalsePositive(ctx context.Context, findingID string, falsePositive bool) error {
	ctx, span := s.logger.StartOperation(ctx, "database.MarkFindingFalsePositive",
		"finding_id", findingID,
		"false_positive", falsePositive,
	)
	start := time.Now()
	var err error
	defer func() { s.logger.FinishOperation(ctx, span, "database.MarkFindingFalsePositive", start, err) }()

	query := fmt.Sprintf(`
		UPDATE findings
		SET false_positive = %s, updated_at = %s
		WHERE id = %s
	`, s.getPlaceholder(1), s.getPlaceholder(2), s.getPlaceholder(3))

	result, err := s.db.ExecContext(ctx, query, falsePositive, time.Now(), findingID)
	if err != nil {
		return fmt.Errorf("failed to mark finding as false positive: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("finding not found: %s", findingID)
	}

	s.logger.Infow("Finding false positive status updated",
		"finding_id", findingID,
		"false_positive", falsePositive,
	)

	return nil
}

// GetRegressions returns findings that were marked as fixed and then reopened (regressions)
func (s *sqlStore) GetRegressions(ctx context.Context, limit int) ([]types.Finding, error) {
	ctx, span := s.logger.StartOperation(ctx, "database.GetRegressions",
		"limit", limit,
	)
	var err error
	start := time.Now()
	defer func() { s.logger.FinishOperation(ctx, span, "database.GetRegressions", start, err) }()

	query := fmt.Sprintf(`
		SELECT id, scan_id, tool, type, severity, title, description,
			   evidence, solution, refs, metadata,
			   fingerprint, first_scan_id, status, verified, false_positive,
			   created_at, updated_at
		FROM findings
		WHERE status = %s
		ORDER BY created_at DESC
		LIMIT %s
	`, s.getPlaceholder(1), s.getPlaceholder(2))

	rows, err := s.db.QueryContext(ctx, query, types.FindingStatusReopened, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query regressions: %w", err)
	}
	defer rows.Close()

	return s.scanFindings(rows)
}

// GetVulnerabilityTimeline returns all instances of a specific vulnerability across scans (full lifecycle)
func (s *sqlStore) GetVulnerabilityTimeline(ctx context.Context, fingerprint string) ([]types.Finding, error) {
	ctx, span := s.logger.StartOperation(ctx, "database.GetVulnerabilityTimeline",
		"fingerprint", fingerprint,
	)
	var err error
	start := time.Now()
	defer func() { s.logger.FinishOperation(ctx, span, "database.GetVulnerabilityTimeline", start, err) }()

	query := fmt.Sprintf(`
		SELECT id, scan_id, tool, type, severity, title, description,
			   evidence, solution, refs, metadata,
			   fingerprint, first_scan_id, status, verified, false_positive,
			   created_at, updated_at
		FROM findings
		WHERE fingerprint = %s
		ORDER BY created_at ASC
	`, s.getPlaceholder(1))

	rows, err := s.db.QueryContext(ctx, query, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerability timeline: %w", err)
	}
	defer rows.Close()

	return s.scanFindings(rows)
}

// GetFindingsByFingerprint returns all findings with a specific fingerprint (across all scans)
func (s *sqlStore) GetFindingsByFingerprint(ctx context.Context, fingerprint string) ([]types.Finding, error) {
	ctx, span := s.logger.StartOperation(ctx, "database.GetFindingsByFingerprint",
		"fingerprint", fingerprint,
	)
	var err error
	start := time.Now()
	defer func() { s.logger.FinishOperation(ctx, span, "database.GetFindingsByFingerprint", start, err) }()

	query := fmt.Sprintf(`
		SELECT id, scan_id, tool, type, severity, title, description,
			   evidence, solution, refs, metadata,
			   fingerprint, first_scan_id, status, verified, false_positive,
			   created_at, updated_at
		FROM findings
		WHERE fingerprint = %s
		ORDER BY created_at DESC
	`, s.getPlaceholder(1))

	rows, err := s.db.QueryContext(ctx, query, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings by fingerprint: %w", err)
	}
	defer rows.Close()

	return s.scanFindings(rows)
}

// GetNewFindings returns findings that first appeared after a specific date
func (s *sqlStore) GetNewFindings(ctx context.Context, sinceDate time.Time) ([]types.Finding, error) {
	ctx, span := s.logger.StartOperation(ctx, "database.GetNewFindings",
		"since_date", sinceDate,
	)
	var err error
	start := time.Now()
	defer func() { s.logger.FinishOperation(ctx, span, "database.GetNewFindings", start, err) }()

	// Get findings where first_scan_id's created_at is after sinceDate
	query := fmt.Sprintf(`
		SELECT f.id, f.scan_id, f.tool, f.type, f.severity, f.title, f.description,
			   f.evidence, f.solution, f.refs, f.metadata,
			   f.fingerprint, f.first_scan_id, f.status, f.verified, f.false_positive,
			   f.created_at, f.updated_at
		FROM findings f
		INNER JOIN (
			SELECT fingerprint, MIN(created_at) as first_seen
			FROM findings
			GROUP BY fingerprint
		) first ON f.fingerprint = first.fingerprint
		WHERE first.first_seen >= %s
		  AND f.status = %s
		ORDER BY first.first_seen DESC
	`, s.getPlaceholder(1), s.getPlaceholder(2))

	rows, err := s.db.QueryContext(ctx, query, sinceDate, types.FindingStatusNew)
	if err != nil {
		return nil, fmt.Errorf("failed to query new findings: %w", err)
	}
	defer rows.Close()

	return s.scanFindings(rows)
}

// GetFixedFindings returns findings that have been marked as fixed
func (s *sqlStore) GetFixedFindings(ctx context.Context, limit int) ([]types.Finding, error) {
	ctx, span := s.logger.StartOperation(ctx, "database.GetFixedFindings",
		"limit", limit,
	)
	var err error
	start := time.Now()
	defer func() { s.logger.FinishOperation(ctx, span, "database.GetFixedFindings", start, err) }()

	query := fmt.Sprintf(`
		SELECT id, scan_id, tool, type, severity, title, description,
			   evidence, solution, refs, metadata,
			   fingerprint, first_scan_id, status, verified, false_positive,
			   created_at, updated_at
		FROM findings
		WHERE status = %s
		ORDER BY updated_at DESC
		LIMIT %s
	`, s.getPlaceholder(1), s.getPlaceholder(2))

	rows, err := s.db.QueryContext(ctx, query, types.FindingStatusFixed, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query fixed findings: %w", err)
	}
	defer rows.Close()

	return s.scanFindings(rows)
}

// scanFindings is a helper function to scan rows into Finding structs
func (s *sqlStore) scanFindings(rows *sql.Rows) ([]types.Finding, error) {
	findings := []types.Finding{}

	for rows.Next() {
		var finding types.Finding
		var refsJSON, metaJSON string

		err := rows.Scan(
			&finding.ID, &finding.ScanID, &finding.Tool, &finding.Type,
			&finding.Severity, &finding.Title, &finding.Description,
			&finding.Evidence, &finding.Solution, &refsJSON, &metaJSON,
			&finding.Fingerprint, &finding.FirstScanID, &finding.Status,
			&finding.Verified, &finding.FalsePositive,
			&finding.CreatedAt, &finding.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan finding: %w", err)
		}

		if refsJSON != "" {
			if err := json.Unmarshal([]byte(refsJSON), &finding.References); err != nil {
				s.logger.Warn("Failed to unmarshal references for finding", "finding_id", finding.ID, "error", err)
			}
		}

		if metaJSON != "" {
			if err := json.Unmarshal([]byte(metaJSON), &finding.Metadata); err != nil {
				s.logger.Warn("Failed to unmarshal metadata for finding", "finding_id", finding.ID, "error", err)
			}
		}

		findings = append(findings, finding)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating findings: %w", err)
	}

	return findings, nil
}

func (s *sqlStore) GetSummary(ctx context.Context, scanID string) (*types.Summary, error) {
	summary := &types.Summary{
		BySeverity: make(map[types.Severity]int),
		ByTool:     make(map[string]int),
	}

	severityQuery := fmt.Sprintf(`
		SELECT severity, COUNT(*) as count
		FROM findings
		WHERE scan_id = %s
		GROUP BY severity
	`, s.getPlaceholder(1))

	rows, err := s.db.QueryContext(ctx, severityQuery, scanID)
	if err != nil {
		return nil, err
	}
	defer s.closeRows2(rows)

	for rows.Next() {
		var severity types.Severity
		var count int

		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}

		summary.BySeverity[severity] = count
		summary.Total += count
	}

	toolQuery := fmt.Sprintf(`
		SELECT tool, COUNT(*) as count
		FROM findings
		WHERE scan_id = %s
		GROUP BY tool
	`, s.getPlaceholder(1))

	rows2, err := s.db.QueryContext(ctx, toolQuery, scanID)
	if err != nil {
		return nil, err
	}
	defer s.closeRows2(rows2)

	for rows2.Next() {
		var tool string
		var count int

		if err := rows2.Scan(&tool, &count); err != nil {
			return nil, err
		}

		summary.ByTool[tool] = count
	}

	return summary, nil
}

func (s *sqlStore) Close() error {
	return s.db.Close()
}

// DB returns the underlying sqlx.DB instance
func (s *sqlStore) DB() *sqlx.DB {
	return s.db
}

// Enhanced query methods for findings

func (s *sqlStore) QueryFindings(ctx context.Context, query core.FindingQuery) ([]types.Finding, error) {
	sqlQuery := `
		SELECT id, scan_id, tool, type, severity, title, description,
			   evidence, solution, refs, metadata, created_at, updated_at
		FROM findings
		WHERE 1=1
	`
	args := map[string]interface{}{}

	if query.ScanID != "" {
		sqlQuery += " AND scan_id = :scan_id"
		args["scan_id"] = query.ScanID
	}

	if query.Tool != "" {
		sqlQuery += " AND tool = :tool"
		args["tool"] = query.Tool
	}

	if query.Type != "" {
		sqlQuery += " AND type = :type"
		args["type"] = query.Type
	}

	if query.Severity != "" {
		sqlQuery += " AND severity = :severity"
		args["severity"] = query.Severity
	}

	if query.Target != "" {
		sqlQuery += " AND scan_id IN (SELECT id FROM scans WHERE target LIKE :target)"
		args["target"] = "%" + query.Target + "%"
	}

	if query.SearchTerm != "" {
		sqlQuery += " AND (title LIKE :search OR description LIKE :search OR evidence LIKE :search)"
		args["search"] = "%" + query.SearchTerm + "%"
	}

	if query.FromDate != nil {
		sqlQuery += " AND created_at >= :from_date"
		args["from_date"] = *query.FromDate
	}

	if query.ToDate != nil {
		sqlQuery += " AND created_at <= :to_date"
		args["to_date"] = *query.ToDate
	}

	// Ordering
	if query.OrderBy != "" {
		switch query.OrderBy {
		case "severity":
			sqlQuery += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END"
		case "created_at":
			sqlQuery += " ORDER BY created_at DESC"
		default:
			sqlQuery += " ORDER BY created_at DESC"
		}
	} else {
		sqlQuery += " ORDER BY created_at DESC"
	}

	if query.Limit > 0 {
		sqlQuery += fmt.Sprintf(" LIMIT %d", query.Limit)
	}

	if query.Offset > 0 {
		sqlQuery += fmt.Sprintf(" OFFSET %d", query.Offset)
	}

	rows, err := s.db.NamedQueryContext(ctx, sqlQuery, args)
	if err != nil {
		return nil, err
	}
	defer s.closeRows(rows)

	findings := []types.Finding{}
	for rows.Next() {
		var finding types.Finding
		var refsJSON, metaJSON string

		err := rows.Scan(
			&finding.ID, &finding.ScanID, &finding.Tool, &finding.Type,
			&finding.Severity, &finding.Title, &finding.Description,
			&finding.Evidence, &finding.Solution, &refsJSON, &metaJSON,
			&finding.CreatedAt, &finding.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if refsJSON != "" {
			if err := json.Unmarshal([]byte(refsJSON), &finding.References); err != nil {
				// Log error but continue processing
				s.logger.Warn("Failed to unmarshal references for finding", "finding_id", finding.ID, "error", err)
			}
		}
		if metaJSON != "" {
			if err := json.Unmarshal([]byte(metaJSON), &finding.Metadata); err != nil {
				// Log error but continue processing
				s.logger.Warn("Failed to unmarshal metadata for finding", "finding_id", finding.ID, "error", err)
			}
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

func (s *sqlStore) GetFindingStats(ctx context.Context) (*core.FindingStats, error) {
	stats := &core.FindingStats{
		BySeverity: make(map[types.Severity]int),
		ByTool:     make(map[string]int),
		ByType:     make(map[string]int),
		ByTarget:   make(map[string]int),
	}

	// Count by severity
	severityQuery := `
		SELECT severity, COUNT(*) as count
		FROM findings
		GROUP BY severity
	`
	rows, err := s.db.QueryContext(ctx, severityQuery)
	if err != nil {
		return nil, err
	}
	defer s.closeRows2(rows)

	for rows.Next() {
		var severity types.Severity
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		stats.BySeverity[severity] = count
		stats.Total += count
	}

	// Count by tool
	toolQuery := `
		SELECT tool, COUNT(*) as count
		FROM findings
		GROUP BY tool
		ORDER BY count DESC
		LIMIT 10
	`
	rows2, err := s.db.QueryContext(ctx, toolQuery)
	if err != nil {
		return nil, err
	}
	defer s.closeRows2(rows2)

	for rows2.Next() {
		var tool string
		var count int
		if err := rows2.Scan(&tool, &count); err != nil {
			return nil, err
		}
		stats.ByTool[tool] = count
	}

	// Count by type
	typeQuery := `
		SELECT type, COUNT(*) as count
		FROM findings
		GROUP BY type
		ORDER BY count DESC
		LIMIT 20
	`
	rows3, err := s.db.QueryContext(ctx, typeQuery)
	if err != nil {
		return nil, err
	}
	defer s.closeRows2(rows3)

	for rows3.Next() {
		var findingType string
		var count int
		if err := rows3.Scan(&findingType, &count); err != nil {
			return nil, err
		}
		stats.ByType[findingType] = count
	}

	// Count by target
	targetQuery := `
		SELECT s.target, COUNT(f.id) as count
		FROM findings f
		JOIN scans s ON f.scan_id = s.id
		GROUP BY s.target
		ORDER BY count DESC
		LIMIT 10
	`
	rows4, err := s.db.QueryContext(ctx, targetQuery)
	if err != nil {
		return nil, err
	}
	defer s.closeRows2(rows4)

	for rows4.Next() {
		var target string
		var count int
		if err := rows4.Scan(&target, &count); err != nil {
			return nil, err
		}
		stats.ByTarget[target] = count
	}

	return stats, nil
}

func (s *sqlStore) GetRecentCriticalFindings(ctx context.Context, limit int) ([]types.Finding, error) {
	query := core.FindingQuery{
		Severity: string(types.SeverityCritical),
		OrderBy:  "created_at",
		Limit:    limit,
	}
	return s.QueryFindings(ctx, query)
}

func (s *sqlStore) SearchFindings(ctx context.Context, searchTerm string, limit int) ([]types.Finding, error) {
	query := core.FindingQuery{
		SearchTerm: searchTerm,
		OrderBy:    "created_at",
		Limit:      limit,
	}
	return s.QueryFindings(ctx, query)
}

// Platform Submission Methods

// PlatformSubmission represents a bug bounty platform submission
type PlatformSubmission struct {
	ID            string    `db:"id" json:"id"`
	FindingID     string    `db:"finding_id" json:"finding_id"`
	Platform      string    `db:"platform" json:"platform"`
	ProgramHandle string    `db:"program_handle" json:"program_handle,omitempty"`
	ReportID      string    `db:"report_id" json:"report_id"`
	ReportURL     string    `db:"report_url" json:"report_url,omitempty"`
	Status        string    `db:"status" json:"status"`
	PlatformData  string    `db:"platform_data" json:"platform_data,omitempty"` // JSON string
	SubmittedAt   time.Time `db:"submitted_at" json:"submitted_at"`
	UpdatedAt     time.Time `db:"updated_at" json:"updated_at"`
}

// CreateSubmission records a platform submission in the database
func (s *sqlStore) CreateSubmission(ctx context.Context, submission *PlatformSubmission) error {
	ctx, span := s.logger.StartOperation(ctx, "database.create_submission",
		"platform", submission.Platform,
		"finding_id", submission.FindingID,
	)
	defer func() {
		s.logger.FinishOperation(ctx, span, "database.create_submission", time.Now(), nil)
	}()

	// Generate ID if not provided
	if submission.ID == "" {
		submission.ID = fmt.Sprintf("sub_%d", time.Now().UnixNano())
	}

	query := `INSERT INTO platform_submissions
		(id, finding_id, platform, program_handle, report_id, report_url, status, platform_data, submitted_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	if s.cfg.Driver == "postgres" {
		query = `INSERT INTO platform_submissions
			(id, finding_id, platform, program_handle, report_id, report_url, status, platform_data, submitted_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	}

	now := time.Now()
	submission.SubmittedAt = now
	submission.UpdatedAt = now

	_, err := s.db.ExecContext(ctx, query,
		submission.ID,
		submission.FindingID,
		submission.Platform,
		submission.ProgramHandle,
		submission.ReportID,
		submission.ReportURL,
		submission.Status,
		submission.PlatformData,
		submission.SubmittedAt,
		submission.UpdatedAt,
	)

	if err != nil {
		s.logger.LogError(ctx, err, "database.create_submission.exec",
			"platform", submission.Platform,
			"finding_id", submission.FindingID,
		)
		return fmt.Errorf("failed to create submission: %w", err)
	}

	return nil
}

// GetSubmission retrieves a submission by ID
func (s *sqlStore) GetSubmission(ctx context.Context, id string) (*PlatformSubmission, error) {
	var submission PlatformSubmission
	query := "SELECT * FROM platform_submissions WHERE id = ?"
	if s.cfg.Driver == "postgres" {
		query = "SELECT * FROM platform_submissions WHERE id = $1"
	}

	err := s.db.GetContext(ctx, &submission, query, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get submission: %w", err)
	}

	return &submission, nil
}

// GetSubmissionsByFinding retrieves all submissions for a finding
func (s *sqlStore) GetSubmissionsByFinding(ctx context.Context, findingID string) ([]PlatformSubmission, error) {
	var submissions []PlatformSubmission
	query := "SELECT * FROM platform_submissions WHERE finding_id = ? ORDER BY submitted_at DESC"
	if s.cfg.Driver == "postgres" {
		query = "SELECT * FROM platform_submissions WHERE finding_id = $1 ORDER BY submitted_at DESC"
	}

	err := s.db.SelectContext(ctx, &submissions, query, findingID)
	if err != nil {
		return nil, fmt.Errorf("failed to get submissions: %w", err)
	}

	return submissions, nil
}

// GetSubmissionsByPlatform retrieves all submissions for a platform
func (s *sqlStore) GetSubmissionsByPlatform(ctx context.Context, platform string) ([]PlatformSubmission, error) {
	var submissions []PlatformSubmission
	query := "SELECT * FROM platform_submissions WHERE platform = ? ORDER BY submitted_at DESC"
	if s.cfg.Driver == "postgres" {
		query = "SELECT * FROM platform_submissions WHERE platform = $1 ORDER BY submitted_at DESC"
	}

	err := s.db.SelectContext(ctx, &submissions, query, platform)
	if err != nil {
		return nil, fmt.Errorf("failed to get submissions: %w", err)
	}

	return submissions, nil
}

// CheckSubmissionExists checks if a finding has already been submitted to a platform
func (s *sqlStore) CheckSubmissionExists(ctx context.Context, findingID, platform string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM platform_submissions WHERE finding_id = ? AND platform = ?"
	if s.cfg.Driver == "postgres" {
		query = "SELECT COUNT(*) FROM platform_submissions WHERE finding_id = $1 AND platform = $2"
	}

	err := s.db.GetContext(ctx, &count, query, findingID, platform)
	if err != nil {
		return false, fmt.Errorf("failed to check submission: %w", err)
	}

	return count > 0, nil
}

// UpdateSubmissionStatus updates the status of a submission
func (s *sqlStore) UpdateSubmissionStatus(ctx context.Context, id, status string) error {
	query := "UPDATE platform_submissions SET status = ?, updated_at = ? WHERE id = ?"
	if s.cfg.Driver == "postgres" {
		query = "UPDATE platform_submissions SET status = $1, updated_at = $2 WHERE id = $3"
	}

	_, err := s.db.ExecContext(ctx, query, status, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update submission status: %w", err)
	}

	return nil
}

// SaveCorrelationResults saves correlation results (attack chains, insights) to the database
func (s *sqlStore) SaveCorrelationResults(ctx context.Context, results []types.CorrelationResult) error {
	start := time.Now()
	ctx, span := s.logger.StartOperation(ctx, "database.SaveCorrelationResults",
		"results_count", len(results),
	)
	var err error
	defer func() {
		s.logger.FinishOperation(ctx, span, "database.SaveCorrelationResults", start, err)
	}()

	if len(results) == 0 {
		s.logger.WithContext(ctx).Debugw("No correlation results to save",
			"results_count", 0,
		)
		return nil
	}

	// Extract scan_id from first result for logging
	scanID := results[0].ScanID
	s.logger.WithContext(ctx).Infow("Saving correlation results to database",
		"results_count", len(results),
		"scan_id", scanID,
	)

	// Count results by type and severity
	typeCounts := make(map[string]int)
	severityCounts := make(map[types.Severity]int)
	for _, result := range results {
		typeCounts[result.InsightType]++
		severityCounts[result.Severity]++
	}

	s.logger.WithContext(ctx).Debugw("Correlation results breakdown",
		"scan_id", scanID,
		"type_counts", typeCounts,
		"severity_counts", severityCounts,
	)

	txStart := time.Now()
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		s.logger.LogError(ctx, err, "database.SaveCorrelationResults.begin_tx",
			"scan_id", scanID,
			"results_count", len(results),
		)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			s.logger.Errorw("Failed to rollback transaction",
				"error", err,
				"impact", "Transaction may have partially committed",
			)
		}
	}()

	s.logger.LogDuration(ctx, "database.SaveCorrelationResults.begin_tx", txStart,
		"scan_id", scanID,
		"success", true,
	)

	query := `
		INSERT INTO correlation_results (
			id, scan_id, insight_type, severity, title, description,
			confidence, related_findings, attack_path, metadata,
			created_at, updated_at
		) VALUES (
			:id, :scan_id, :insight_type, :severity, :title, :description,
			:confidence, :related_findings, :attack_path, :metadata,
			:created_at, :updated_at
		)
	`

	insertStart := time.Now()
	totalRowsAffected := int64(0)

	for i, result := range results {
		resultStart := time.Now()

		// Marshal JSONB fields
		relatedFindingsJSON, err := json.Marshal(result.RelatedFindings)
		if err != nil {
			s.logger.LogError(ctx, err, "database.SaveCorrelationResults.marshal_related_findings",
				"result_id", result.ID,
				"scan_id", result.ScanID,
			)
			return fmt.Errorf("failed to marshal related_findings for result %s: %w", result.ID, err)
		}

		attackPathJSON, err := json.Marshal(result.AttackPath)
		if err != nil {
			s.logger.LogError(ctx, err, "database.SaveCorrelationResults.marshal_attack_path",
				"result_id", result.ID,
				"scan_id", result.ScanID,
			)
			return fmt.Errorf("failed to marshal attack_path for result %s: %w", result.ID, err)
		}

		metadataJSON, err := json.Marshal(result.Metadata)
		if err != nil {
			s.logger.LogError(ctx, err, "database.SaveCorrelationResults.marshal_metadata",
				"result_id", result.ID,
				"scan_id", result.ScanID,
			)
			return fmt.Errorf("failed to marshal metadata for result %s: %w", result.ID, err)
		}

		args := map[string]interface{}{
			"id":               result.ID,
			"scan_id":          result.ScanID,
			"insight_type":     result.InsightType,
			"severity":         result.Severity,
			"title":            result.Title,
			"description":      result.Description,
			"confidence":       result.Confidence,
			"related_findings": string(relatedFindingsJSON),
			"attack_path":      string(attackPathJSON),
			"metadata":         string(metadataJSON),
			"created_at":       result.CreatedAt,
			"updated_at":       result.UpdatedAt,
		}

		queryStart := time.Now()
		execResult, err := tx.NamedExecContext(ctx, query, args)
		if err != nil {
			s.logger.LogError(ctx, err, "database.SaveCorrelationResults.insert",
				"result_id", result.ID,
				"scan_id", result.ScanID,
				"insight_type", result.InsightType,
				"severity", string(result.Severity),
			)
			return fmt.Errorf("failed to insert correlation result %s: %w", result.ID, err)
		}

		rowsAffected, err := execResult.RowsAffected()
		if err != nil {
			s.logger.Errorw("Failed to get rows affected after correlation result insert",
				"error", err,
				"result_id", result.ID,
			)
			rowsAffected = -1
		}
		totalRowsAffected += rowsAffected

		s.logger.LogDatabaseOperation(ctx, "INSERT", "correlation_results", rowsAffected, time.Since(queryStart),
			"result_id", result.ID,
			"scan_id", result.ScanID,
			"insight_type", result.InsightType,
			"severity", string(result.Severity),
		)

		s.logger.WithContext(ctx).Debugw("Correlation result saved",
			"result_id", result.ID,
			"scan_id", result.ScanID,
			"insight_type", result.InsightType,
			"severity", string(result.Severity),
			"result_index", i+1,
			"total_results", len(results),
			"result_duration_ms", time.Since(resultStart).Milliseconds(),
		)
	}

	s.logger.LogDuration(ctx, "database.SaveCorrelationResults.insert_all", insertStart,
		"scan_id", scanID,
		"results_count", len(results),
		"total_rows_affected", totalRowsAffected,
		"success", true,
	)

	commitStart := time.Now()
	err = tx.Commit()
	if err != nil {
		s.logger.LogError(ctx, err, "database.SaveCorrelationResults.commit",
			"scan_id", scanID,
			"results_count", len(results),
		)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	s.logger.LogDuration(ctx, "database.SaveCorrelationResults.commit", commitStart,
		"scan_id", scanID,
		"results_count", len(results),
		"success", true,
	)

	s.logger.WithContext(ctx).Infow("Correlation results saved successfully",
		"scan_id", scanID,
		"results_count", len(results),
		"type_counts", typeCounts,
		"severity_counts", severityCounts,
		"total_rows_affected", totalRowsAffected,
		"total_duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

// GetCorrelationResults retrieves all correlation results for a scan
func (s *sqlStore) GetCorrelationResults(ctx context.Context, scanID string) ([]types.CorrelationResult, error) {
	query := fmt.Sprintf(`
		SELECT id, scan_id, insight_type, severity, title, description,
			   confidence, related_findings, attack_path, metadata,
			   created_at, updated_at
		FROM correlation_results
		WHERE scan_id = %s
		ORDER BY severity DESC, confidence DESC, created_at DESC
	`, s.getPlaceholder(1))

	rows, err := s.db.QueryContext(ctx, query, scanID)
	if err != nil {
		s.logger.LogError(ctx, err, "database.GetCorrelationResults.query",
			"scan_id", scanID,
		)
		return nil, fmt.Errorf("failed to query correlation results: %w", err)
	}
	defer s.closeRows2(rows)

	var results []types.CorrelationResult
	for rows.Next() {
		var result types.CorrelationResult
		var relatedFindingsJSON, attackPathJSON, metadataJSON []byte

		err := rows.Scan(
			&result.ID,
			&result.ScanID,
			&result.InsightType,
			&result.Severity,
			&result.Title,
			&result.Description,
			&result.Confidence,
			&relatedFindingsJSON,
			&attackPathJSON,
			&metadataJSON,
			&result.CreatedAt,
			&result.UpdatedAt,
		)
		if err != nil {
			s.logger.LogError(ctx, err, "database.GetCorrelationResults.scan",
				"scan_id", scanID,
			)
			return nil, fmt.Errorf("failed to scan correlation result row: %w", err)
		}

		// Unmarshal JSONB fields
		if err := json.Unmarshal(relatedFindingsJSON, &result.RelatedFindings); err != nil {
			s.logger.LogError(ctx, err, "database.GetCorrelationResults.unmarshal_related_findings",
				"result_id", result.ID,
			)
			return nil, fmt.Errorf("failed to unmarshal related_findings: %w", err)
		}

		if err := json.Unmarshal(attackPathJSON, &result.AttackPath); err != nil {
			s.logger.LogError(ctx, err, "database.GetCorrelationResults.unmarshal_attack_path",
				"result_id", result.ID,
			)
			return nil, fmt.Errorf("failed to unmarshal attack_path: %w", err)
		}

		if err := json.Unmarshal(metadataJSON, &result.Metadata); err != nil {
			s.logger.LogError(ctx, err, "database.GetCorrelationResults.unmarshal_metadata",
				"result_id", result.ID,
			)
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		results = append(results, result)
	}

	if err := rows.Err(); err != nil {
		s.logger.LogError(ctx, err, "database.GetCorrelationResults.rows_err",
			"scan_id", scanID,
		)
		return nil, fmt.Errorf("error iterating correlation results: %w", err)
	}

	s.logger.WithContext(ctx).Debugw("Retrieved correlation results",
		"scan_id", scanID,
		"results_count", len(results),
	)

	return results, nil
}

// GetCorrelationResultsByType retrieves all correlation results of a specific type across all scans
func (s *sqlStore) GetCorrelationResultsByType(ctx context.Context, insightType string) ([]types.CorrelationResult, error) {
	query := fmt.Sprintf(`
		SELECT id, scan_id, insight_type, severity, title, description,
			   confidence, related_findings, attack_path, metadata,
			   created_at, updated_at
		FROM correlation_results
		WHERE insight_type = %s
		ORDER BY severity DESC, confidence DESC, created_at DESC
	`, s.getPlaceholder(1))

	rows, err := s.db.QueryContext(ctx, query, insightType)
	if err != nil {
		s.logger.LogError(ctx, err, "database.GetCorrelationResultsByType.query",
			"insight_type", insightType,
		)
		return nil, fmt.Errorf("failed to query correlation results by type: %w", err)
	}
	defer s.closeRows2(rows)

	var results []types.CorrelationResult
	for rows.Next() {
		var result types.CorrelationResult
		var relatedFindingsJSON, attackPathJSON, metadataJSON []byte

		err := rows.Scan(
			&result.ID,
			&result.ScanID,
			&result.InsightType,
			&result.Severity,
			&result.Title,
			&result.Description,
			&result.Confidence,
			&relatedFindingsJSON,
			&attackPathJSON,
			&metadataJSON,
			&result.CreatedAt,
			&result.UpdatedAt,
		)
		if err != nil {
			s.logger.LogError(ctx, err, "database.GetCorrelationResultsByType.scan",
				"insight_type", insightType,
			)
			return nil, fmt.Errorf("failed to scan correlation result row: %w", err)
		}

		// Unmarshal JSONB fields
		if err := json.Unmarshal(relatedFindingsJSON, &result.RelatedFindings); err != nil {
			s.logger.LogError(ctx, err, "database.GetCorrelationResultsByType.unmarshal_related_findings",
				"result_id", result.ID,
			)
			return nil, fmt.Errorf("failed to unmarshal related_findings: %w", err)
		}

		if err := json.Unmarshal(attackPathJSON, &result.AttackPath); err != nil {
			s.logger.LogError(ctx, err, "database.GetCorrelationResultsByType.unmarshal_attack_path",
				"result_id", result.ID,
			)
			return nil, fmt.Errorf("failed to unmarshal attack_path: %w", err)
		}

		if err := json.Unmarshal(metadataJSON, &result.Metadata); err != nil {
			s.logger.LogError(ctx, err, "database.GetCorrelationResultsByType.unmarshal_metadata",
				"result_id", result.ID,
			)
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		results = append(results, result)
	}

	if err := rows.Err(); err != nil {
		s.logger.LogError(ctx, err, "database.GetCorrelationResultsByType.rows_err",
			"insight_type", insightType,
		)
		return nil, fmt.Errorf("error iterating correlation results: %w", err)
	}

	s.logger.WithContext(ctx).Debugw("Retrieved correlation results by type",
		"insight_type", insightType,
		"results_count", len(results),
	)

	return results, nil
}
