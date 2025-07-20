// pkg/monitoring/storage.go
package monitoring

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// SQLiteStorage implements MonitoringStorage using SQLite3
type SQLiteStorage struct {
	db     *sqlx.DB
	logger *logger.Logger
}

// NewSQLiteStorage creates a new SQLite storage backend for monitoring
func NewSQLiteStorage(dsn string) (*SQLiteStorage, error) {
	// Initialize logger
	log, err := logger.New(config.LoggerConfig{Level: "debug", Format: "json"})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize monitoring storage logger: %w", err)
	}
	log = log.WithComponent("monitoring-storage")

	// Connect to SQLite database
	db, err := sqlx.Connect("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SQLite database: %w", err)
	}

	storage := &SQLiteStorage{
		db:     db,
		logger: log,
	}

	// Initialize schema
	if err := storage.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return storage, nil
}

// initSchema creates the necessary tables for monitoring data
func (s *SQLiteStorage) initSchema() error {
	ctx := context.Background()

	// Enable foreign keys
	if _, err := s.db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		return fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Create certificates table
	certSchema := `
	CREATE TABLE IF NOT EXISTS monitoring_certificates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		subject_cn TEXT NOT NULL,
		sans TEXT,
		issuer TEXT,
		not_before TIMESTAMP,
		not_after TIMESTAMP,
		serial_number TEXT,
		fingerprint TEXT UNIQUE,
		source TEXT,
		seen_at TIMESTAMP NOT NULL,
		metadata TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_cert_domain ON monitoring_certificates(domain);
	CREATE INDEX IF NOT EXISTS idx_cert_fingerprint ON monitoring_certificates(fingerprint);
	CREATE INDEX IF NOT EXISTS idx_cert_seen_at ON monitoring_certificates(seen_at);
	`

	// Create DNS records table
	dnsSchema := `
	CREATE TABLE IF NOT EXISTS monitoring_dns_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		record_type TEXT NOT NULL,
		value TEXT NOT NULL,
		hash TEXT,
		last_checked TIMESTAMP NOT NULL,
		last_modified TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(domain, record_type, value)
	);
	CREATE INDEX IF NOT EXISTS idx_dns_domain ON monitoring_dns_records(domain);
	CREATE INDEX IF NOT EXISTS idx_dns_hash ON monitoring_dns_records(hash);
	`

	// Create DNS changes table
	dnsChangeSchema := `
	CREATE TABLE IF NOT EXISTS monitoring_dns_changes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		change_type TEXT NOT NULL,
		record_type TEXT NOT NULL,
		old_records TEXT,
		new_records TEXT,
		detected_at TIMESTAMP NOT NULL,
		metadata TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_dns_change_domain ON monitoring_dns_changes(domain);
	CREATE INDEX IF NOT EXISTS idx_dns_change_detected ON monitoring_dns_changes(detected_at);
	`

	// Create git changes table
	gitSchema := `
	CREATE TABLE IF NOT EXISTS monitoring_git_changes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		repository TEXT NOT NULL,
		commit_hash TEXT NOT NULL,
		author TEXT,
		message TEXT,
		files TEXT,
		secrets TEXT,
		detected_at TIMESTAMP NOT NULL,
		metadata TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(repository, commit_hash)
	);
	CREATE INDEX IF NOT EXISTS idx_git_repo ON monitoring_git_changes(repository);
	CREATE INDEX IF NOT EXISTS idx_git_detected ON monitoring_git_changes(detected_at);
	`

	// Create alerts table
	alertSchema := `
	CREATE TABLE IF NOT EXISTS monitoring_alerts (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		severity TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT,
		source TEXT,
		target TEXT,
		timestamp TIMESTAMP NOT NULL,
		data TEXT,
		sent_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_alert_type ON monitoring_alerts(type);
	CREATE INDEX IF NOT EXISTS idx_alert_severity ON monitoring_alerts(severity);
	CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON monitoring_alerts(timestamp);
	CREATE INDEX IF NOT EXISTS idx_alert_target ON monitoring_alerts(target);
	`

	// Execute schemas
	schemas := []string{certSchema, dnsSchema, dnsChangeSchema, gitSchema, alertSchema}
	for i, schema := range schemas {
		if _, err := s.db.ExecContext(ctx, schema); err != nil {
			return fmt.Errorf("failed to create schema %d: %w", i, err)
		}
	}

	s.logger.Info("Monitoring database schema initialized successfully")
	return nil
}

// StoreCertificate stores a certificate from CT logs
func (s *SQLiteStorage) StoreCertificate(cert *Certificate) error {
	ctx := context.Background()

	// Convert SANs to JSON
	sansJSON, err := json.Marshal(cert.SANs)
	if err != nil {
		return fmt.Errorf("failed to marshal SANs: %w", err)
	}

	// Convert metadata to JSON
	metadataJSON, err := json.Marshal(cert.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT OR IGNORE INTO monitoring_certificates (
			domain, subject_cn, sans, issuer, not_before, not_after,
			serial_number, fingerprint, source, seen_at, metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = s.db.ExecContext(ctx, query,
		cert.Domain, cert.SubjectCN, string(sansJSON), cert.Issuer,
		cert.NotBefore, cert.NotAfter, cert.SerialNumber, cert.Fingerprint,
		cert.Source, cert.SeenAt, string(metadataJSON),
	)

	if err != nil {
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	s.logger.Debug("Stored certificate", "domain", cert.Domain, "fingerprint", cert.Fingerprint)
	return nil
}

// StoreIPRecord stores DNS record information
func (s *SQLiteStorage) StoreIPRecord(record *DNSRecordSet) error {
	ctx := context.Background()

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete existing records for this domain
	_, err = tx.ExecContext(ctx, "DELETE FROM monitoring_dns_records WHERE domain = ?", record.Domain)
	if err != nil {
		return fmt.Errorf("failed to delete old records: %w", err)
	}

	// Insert new records
	for recordType, values := range record.Records {
		for _, value := range values {
			query := `
				INSERT INTO monitoring_dns_records (
					domain, record_type, value, hash, last_checked, last_modified
				) VALUES (?, ?, ?, ?, ?, ?)
			`
			_, err = tx.ExecContext(ctx, query,
				record.Domain, recordType, value, record.Hash,
				record.LastChecked, record.LastModified,
			)
			if err != nil {
				return fmt.Errorf("failed to insert DNS record: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	s.logger.Debug("Stored DNS records", "domain", record.Domain, "hash", record.Hash)
	return nil
}

// StoreGitChange stores a git repository change
func (s *SQLiteStorage) StoreGitChange(change *GitChange) error {
	ctx := context.Background()

	// Convert files to JSON
	filesJSON, err := json.Marshal(change.Files)
	if err != nil {
		return fmt.Errorf("failed to marshal files: %w", err)
	}

	// Convert secrets to JSON
	secretsJSON, err := json.Marshal(change.Secrets)
	if err != nil {
		return fmt.Errorf("failed to marshal secrets: %w", err)
	}

	// Convert metadata to JSON
	metadataJSON, err := json.Marshal(change.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT OR IGNORE INTO monitoring_git_changes (
			repository, commit_hash, author, message, files,
			secrets, detected_at, metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = s.db.ExecContext(ctx, query,
		change.Repository, change.CommitHash, change.Author, change.Message,
		string(filesJSON), string(secretsJSON), change.DetectedAt, string(metadataJSON),
	)

	if err != nil {
		return fmt.Errorf("failed to store git change: %w", err)
	}

	s.logger.Debug("Stored git change", "repository", change.Repository, "commit", change.CommitHash)
	return nil
}

// GetLastSeen gets the last time a domain was seen in CT logs
func (s *SQLiteStorage) GetLastSeen(domain string) (time.Time, error) {
	ctx := context.Background()

	var lastSeen time.Time
	query := `
		SELECT MAX(seen_at) FROM monitoring_certificates 
		WHERE domain = ? OR subject_cn = ?
	`

	err := s.db.GetContext(ctx, &lastSeen, query, domain, domain)
	if err != nil {
		if err == sql.ErrNoRows {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("failed to get last seen: %w", err)
	}

	return lastSeen, nil
}

// GetHistoricalData retrieves historical monitoring data
func (s *SQLiteStorage) GetHistoricalData(target string, dataType string, since time.Time) ([]interface{}, error) {
	ctx := context.Background()
	results := make([]interface{}, 0)

	switch dataType {
	case "certificates":
		var certs []Certificate
		query := `
			SELECT domain, subject_cn, sans, issuer, not_before, not_after,
			       serial_number, fingerprint, source, seen_at, metadata
			FROM monitoring_certificates
			WHERE (domain = ? OR subject_cn = ?) AND seen_at >= ?
			ORDER BY seen_at DESC
		`
		err := s.db.SelectContext(ctx, &certs, query, target, target, since)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificate history: %w", err)
		}
		for _, cert := range certs {
			results = append(results, cert)
		}

	case "dns":
		// var records []DNSRecordSet // Not needed, using recordMap instead
		query := `
			SELECT domain, record_type, value, hash, last_checked, last_modified
			FROM monitoring_dns_records
			WHERE domain = ? AND last_modified >= ?
			ORDER BY last_modified DESC
		`
		rows, err := s.db.QueryContext(ctx, query, target, since)
		if err != nil {
			return nil, fmt.Errorf("failed to get DNS history: %w", err)
		}
		defer rows.Close()

		// Group records by timestamp
		recordMap := make(map[string]*DNSRecordSet)
		for rows.Next() {
			var domain, recordType, value, hash string
			var lastChecked, lastModified time.Time

			err := rows.Scan(&domain, &recordType, &value, &hash, &lastChecked, &lastModified)
			if err != nil {
				continue
			}

			key := fmt.Sprintf("%s-%s", domain, lastModified.Format(time.RFC3339))
			if _, exists := recordMap[key]; !exists {
				recordMap[key] = &DNSRecordSet{
					Domain:       domain,
					Records:      make(map[string][]string),
					LastChecked:  lastChecked,
					LastModified: lastModified,
					Hash:         hash,
				}
			}

			recordMap[key].Records[recordType] = append(recordMap[key].Records[recordType], value)
		}

		for _, record := range recordMap {
			results = append(results, record)
		}

	case "git":
		// Process git changes
		query := `
			SELECT repository, commit_hash, author, message, files,
			       secrets, detected_at, metadata
			FROM monitoring_git_changes
			WHERE repository = ? AND detected_at >= ?
			ORDER BY detected_at DESC
		`
		rows, err := s.db.QueryContext(ctx, query, target, since)
		if err != nil {
			return nil, fmt.Errorf("failed to get git history: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var change GitChange
			var filesJSON, secretsJSON, metadataJSON string

			err := rows.Scan(&change.Repository, &change.CommitHash, &change.Author,
				&change.Message, &filesJSON, &secretsJSON, &change.DetectedAt, &metadataJSON)
			if err != nil {
				continue
			}

			// Unmarshal JSON fields
			json.Unmarshal([]byte(filesJSON), &change.Files)
			json.Unmarshal([]byte(secretsJSON), &change.Secrets)
			json.Unmarshal([]byte(metadataJSON), &change.Metadata)

			results = append(results, change)
		}
	}

	return results, nil
}

// StoreDNSChange stores a DNS change event
func (s *SQLiteStorage) StoreDNSChange(change *DNSChange) error {
	ctx := context.Background()

	// Convert old/new records to JSON
	oldRecordsJSON, _ := json.Marshal(change.OldRecords)
	newRecordsJSON, _ := json.Marshal(change.NewRecords)
	metadataJSON, _ := json.Marshal(change.Metadata)

	query := `
		INSERT INTO monitoring_dns_changes (
			domain, change_type, record_type, old_records, new_records,
			detected_at, metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.ExecContext(ctx, query,
		change.Domain, change.ChangeType, change.RecordType,
		string(oldRecordsJSON), string(newRecordsJSON),
		change.DetectedAt, string(metadataJSON),
	)

	if err != nil {
		return fmt.Errorf("failed to store DNS change: %w", err)
	}

	s.logger.Debug("Stored DNS change", "domain", change.Domain, "type", change.ChangeType)
	return nil
}

// StoreAlert stores a monitoring alert
func (s *SQLiteStorage) StoreAlert(alert *Alert) error {
	ctx := context.Background()

	// Convert data to JSON
	dataJSON, err := json.Marshal(alert.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal alert data: %w", err)
	}

	query := `
		INSERT INTO monitoring_alerts (
			id, type, severity, title, description, source,
			target, timestamp, data, sent_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = s.db.ExecContext(ctx, query,
		alert.ID, alert.Type, alert.Severity, alert.Title, alert.Description,
		alert.Source, alert.Target, alert.Timestamp, string(dataJSON), time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to store alert: %w", err)
	}

	s.logger.Info("Stored monitoring alert",
		"id", alert.ID, "type", alert.Type, "severity", alert.Severity, "target", alert.Target)
	return nil
}

// Close closes the database connection
func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}
