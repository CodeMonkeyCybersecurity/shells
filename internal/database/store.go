package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

type sqlStore struct {
	db     *sqlx.DB
	cfg    config.DatabaseConfig
	logger *logger.Logger
}

// getPlaceholder returns the appropriate placeholder for the database driver
func (s *sqlStore) getPlaceholder(n int) string {
	if s.cfg.Driver == "postgres" {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func NewStore(cfg config.DatabaseConfig) (core.ResultStore, error) {
	// Initialize logger for database operations
	log, err := logger.New(config.LoggerConfig{Level: "debug", Format: "json"})
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

	s.logger.WithContext(ctx).Infow("Starting database migration",
		"driver", s.cfg.Driver,
	)

	// Enable foreign keys for SQLite
	if s.cfg.Driver == "sqlite3" {
		start := time.Now()
		_, err := s.db.Exec("PRAGMA foreign_keys = ON;")
		if err != nil {
			s.logger.LogError(ctx, err, "database.migrate.pragma",
				"driver", s.cfg.Driver,
				"duration_ms", time.Since(start).Milliseconds(),
			)
			return fmt.Errorf("failed to enable foreign keys: %w", err)
		}
		s.logger.LogDuration(ctx, "database.migrate.pragma", start,
			"pragma", "foreign_keys",
			"enabled", true,
		)
	}

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
		worker_id TEXT
	);

	CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL,
		tool TEXT NOT NULL,
		type TEXT NOT NULL,
		severity TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT,
		evidence TEXT,
		solution TEXT,
		refs TEXT,
		metadata TEXT,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
	CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
	CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
	CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
	CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
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

	rowsAffected, _ := result.RowsAffected()
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
	defer rows.Close()

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
	defer tx.Rollback()

	s.logger.LogDuration(ctx, "database.SaveFindings.begin_tx", txStart,
		"scan_id", scanID,
		"success", true,
	)

	query := `
		INSERT INTO findings (
			id, scan_id, tool, type, severity, title, description,
			evidence, solution, refs, metadata, created_at, updated_at
		) VALUES (
			:id, :scan_id, :tool, :type, :severity, :title, :description,
			:evidence, :solution, :refs, :metadata, :created_at, :updated_at
		)
	`

	insertStart := time.Now()
	totalRowsAffected := int64(0)

	for i, finding := range findings {
		findingStart := time.Now()

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
			"id":          finding.ID,
			"scan_id":     finding.ScanID,
			"tool":        finding.Tool,
			"type":        finding.Type,
			"severity":    finding.Severity,
			"title":       finding.Title,
			"description": finding.Description,
			"evidence":    finding.Evidence,
			"solution":    finding.Solution,
			"refs":        string(refsJSON),
			"metadata":    string(metaJSON),
			"created_at":  finding.CreatedAt,
			"updated_at":  finding.UpdatedAt,
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

		rowsAffected, _ := result.RowsAffected()
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
		"total_rows_affected", totalRowsAffected,
		"total_duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

func (s *sqlStore) GetFindings(ctx context.Context, scanID string) ([]types.Finding, error) {
	query := fmt.Sprintf(`
		SELECT id, scan_id, tool, type, severity, title, description,
			   evidence, solution, refs, metadata, created_at, updated_at
		FROM findings
		WHERE scan_id = %s
		ORDER BY severity DESC, created_at DESC
	`, s.getPlaceholder(1))

	rows, err := s.db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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
				fmt.Printf("Warning: failed to unmarshal references for finding %s: %v\n", finding.ID, err)
			}
		}
		if metaJSON != "" {
			if err := json.Unmarshal([]byte(metaJSON), &finding.Metadata); err != nil {
				// Log error but continue processing
				fmt.Printf("Warning: failed to unmarshal metadata for finding %s: %v\n", finding.ID, err)
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
	defer rows.Close()

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
				fmt.Printf("Warning: failed to unmarshal references for finding %s: %v\n", finding.ID, err)
			}
		}
		if metaJSON != "" {
			if err := json.Unmarshal([]byte(metaJSON), &finding.Metadata); err != nil {
				// Log error but continue processing
				fmt.Printf("Warning: failed to unmarshal metadata for finding %s: %v\n", finding.ID, err)
			}
		}

		findings = append(findings, finding)
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
	defer rows.Close()

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
	defer rows2.Close()

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
	defer rows.Close()

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
				fmt.Printf("Warning: failed to unmarshal references for finding %s: %v\n", finding.ID, err)
			}
		}
		if metaJSON != "" {
			if err := json.Unmarshal([]byte(metaJSON), &finding.Metadata); err != nil {
				// Log error but continue processing
				fmt.Printf("Warning: failed to unmarshal metadata for finding %s: %v\n", finding.ID, err)
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
	defer rows.Close()

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
	defer rows2.Close()

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
	defer rows3.Close()

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
	defer rows4.Close()

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
