package scope

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/jmoiron/sqlx"
)

// Manager implements comprehensive scope management
type Manager struct {
	db              *sqlx.DB
	logger          *logger.Logger
	platformClients map[Platform]PlatformClient
	validator       *Validator
	cache           *ScopeCache
	monitor         *ScopeMonitor
	mu              sync.RWMutex
	config          *Config
}

// Config contains scope manager configuration
type Config struct {
	AutoSync         bool          `yaml:"auto_sync"`
	SyncInterval     time.Duration `yaml:"sync_interval"`
	CacheTTL         time.Duration `yaml:"cache_ttl"`
	ValidateWorkers  int           `yaml:"validate_workers"`
	StrictMode       bool          `yaml:"strict_mode"` // Fail closed on ambiguous cases
	EnableMonitoring bool          `yaml:"enable_monitoring"`
	MonitorInterval  time.Duration `yaml:"monitor_interval"`
}

// NewManager creates a new scope manager
func NewManager(db *sqlx.DB, logger *logger.Logger, config *Config) *Manager {
	if config == nil {
		config = &Config{
			AutoSync:         true,
			SyncInterval:     30 * time.Minute,
			CacheTTL:         1 * time.Hour,
			ValidateWorkers:  10,
			StrictMode:       false,
			EnableMonitoring: true,
			MonitorInterval:  30 * time.Minute,
		}
	}

	m := &Manager{
		db:              db,
		logger:          logger,
		platformClients: make(map[Platform]PlatformClient),
		cache:           NewScopeCache(config.CacheTTL),
		config:          config,
	}

	m.validator = NewValidator(m, logger)
	m.monitor = NewScopeMonitor(m, logger, config.MonitorInterval)

	// Initialize platform clients
	m.initializePlatformClients()

	// Create database tables if needed
	if err := m.createTables(); err != nil {
		logger.Error("Failed to create scope tables", "error", err)
	}

	return m
}

// initializePlatformClients sets up platform API clients
func (m *Manager) initializePlatformClients() {
	// These will be initialized based on config
	m.platformClients[PlatformHackerOne] = NewHackerOneClient(m.logger)
	m.platformClients[PlatformBugcrowd] = NewBugcrowdClient(m.logger)
}

// GetPlatformClient returns a platform client
func (m *Manager) GetPlatformClient(platform Platform) PlatformClient {
	return m.platformClients[platform]
}

// SetMonitorInterval sets the monitoring interval
func (m *Manager) SetMonitorInterval(interval time.Duration) {
	m.config.MonitorInterval = interval
	if m.monitor != nil {
		m.monitor.SetInterval(interval)
	}
}

// createTables creates the necessary database tables
func (m *Manager) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS scope_programs (
            id TEXT PRIMARY KEY,
            platform TEXT NOT NULL,
            name TEXT NOT NULL,
            handle TEXT NOT NULL,
            url TEXT,
            testing_guidelines TEXT,
            vpn_required BOOLEAN DEFAULT FALSE,
            max_bounty REAL,
            last_synced TIMESTAMP,
            active BOOLEAN DEFAULT TRUE,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,

		`CREATE TABLE IF NOT EXISTS scope_items (
            id TEXT PRIMARY KEY,
            program_id TEXT NOT NULL,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            status TEXT NOT NULL,
            description TEXT,
            severity TEXT,
            environment_type TEXT,
            max_severity TEXT,
            restrictions TEXT,
            instructions TEXT,
            metadata TEXT,
            last_updated TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (program_id) REFERENCES scope_programs(id)
        )`,

		`CREATE TABLE IF NOT EXISTS scope_rules (
            id TEXT PRIMARY KEY,
            program_id TEXT NOT NULL,
            type TEXT NOT NULL,
            description TEXT,
            value TEXT,
            applies_to TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (program_id) REFERENCES scope_programs(id)
        )`,

		`CREATE TABLE IF NOT EXISTS scope_validations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset TEXT NOT NULL,
            status TEXT NOT NULL,
            program_id TEXT,
            scope_item_id TEXT,
            reason TEXT,
            restrictions TEXT,
            validated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (program_id) REFERENCES scope_programs(id),
            FOREIGN KEY (scope_item_id) REFERENCES scope_items(id)
        )`,

		`CREATE INDEX IF NOT EXISTS idx_scope_items_value ON scope_items(value)`,
		`CREATE INDEX IF NOT EXISTS idx_scope_items_program ON scope_items(program_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scope_validations_asset ON scope_validations(asset)`,
		`CREATE INDEX IF NOT EXISTS idx_scope_validations_time ON scope_validations(validated_at)`,
	}

	for _, query := range queries {
		if _, err := m.db.ExecContext(context.Background(), query); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	return nil
}

// AddProgram adds a new bug bounty program
func (m *Manager) AddProgram(program *Program) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("Adding bug bounty program",
		"name", program.Name,
		"platform", program.Platform)

	// Store program
	tx, err := m.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Insert program
	metadata, _ := json.Marshal(program.Metadata)
	_, err = tx.Exec(`
        INSERT OR REPLACE INTO scope_programs 
        (id, platform, name, handle, url, testing_guidelines, vpn_required, 
         max_bounty, last_synced, active, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		program.ID, program.Platform, program.Name, program.Handle,
		program.URL, program.TestingGuidelines, program.VPNRequired,
		program.MaxBounty, program.LastSynced, program.Active, string(metadata))
	if err != nil {
		return err
	}

	// Insert scope items
	for _, item := range program.Scope {
		if err := m.insertScopeItem(tx, program.ID, &item); err != nil {
			return err
		}
	}

	// Insert out of scope items
	for _, item := range program.OutOfScope {
		if err := m.insertScopeItem(tx, program.ID, &item); err != nil {
			return err
		}
	}

	// Insert rules
	for _, rule := range program.Rules {
		applies, _ := json.Marshal(rule.Applies)
		_, err = tx.Exec(`
            INSERT OR REPLACE INTO scope_rules 
            (id, program_id, type, description, value, applies_to)
            VALUES (?, ?, ?, ?, ?, ?)`,
			rule.ID, program.ID, rule.Type, rule.Description,
			rule.Value, string(applies))
		if err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// Clear cache
	m.cache.Clear()

	m.logger.Info("Successfully added program",
		"program", program.Name,
		"in_scope", len(program.Scope),
		"out_of_scope", len(program.OutOfScope))

	return nil
}

// RemoveProgram removes a program
func (m *Manager) RemoveProgram(programID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	tx, err := m.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete in order due to foreign key constraints
	_, err = tx.Exec("DELETE FROM scope_validations WHERE program_id = ?", programID)
	if err != nil {
		return err
	}

	_, err = tx.Exec("DELETE FROM scope_rules WHERE program_id = ?", programID)
	if err != nil {
		return err
	}

	_, err = tx.Exec("DELETE FROM scope_items WHERE program_id = ?", programID)
	if err != nil {
		return err
	}

	_, err = tx.Exec("DELETE FROM scope_programs WHERE id = ?", programID)
	if err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// Clear cache
	m.cache.Clear()

	m.logger.Info("Successfully removed program", "program_id", programID)
	return nil
}

// insertScopeItem inserts a single scope item
func (m *Manager) insertScopeItem(tx *sqlx.Tx, programID string, item *ScopeItem) error {
	restrictions, _ := json.Marshal(item.Restrictions)
	metadata, _ := json.Marshal(item.Metadata)

	_, err := tx.Exec(`
        INSERT OR REPLACE INTO scope_items 
        (id, program_id, type, value, status, description, severity,
         environment_type, max_severity, restrictions, instructions, 
         metadata, last_updated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID, programID, item.Type, item.Value, item.Status,
		item.Description, item.Severity, item.EnvironmentType,
		item.MaxSeverity, string(restrictions), item.Instructions,
		string(metadata), item.LastUpdated)

	return err
}

// SyncProgram syncs a program's scope from the platform
func (m *Manager) SyncProgram(programID string) error {
	m.logger.Info("Syncing program scope", "program_id", programID)

	// Get program
	program, err := m.GetProgram(programID)
	if err != nil {
		return err
	}

	// Get platform client
	client, exists := m.platformClients[program.Platform]
	if !exists {
		return fmt.Errorf("no client for platform %s", program.Platform)
	}

	// Fetch latest scope
	ctx := context.Background()
	updatedProgram, err := client.GetProgram(ctx, program.Handle)
	if err != nil {
		return fmt.Errorf("failed to fetch program: %w", err)
	}

	// Update program
	updatedProgram.ID = program.ID // Preserve our ID
	return m.AddProgram(updatedProgram)
}

// SyncAllPrograms syncs all active programs
func (m *Manager) SyncAllPrograms() error {
	programs, err := m.ListPrograms()
	if err != nil {
		return err
	}

	var errors []error
	for _, program := range programs {
		if !program.Active {
			continue
		}

		if err := m.SyncProgram(program.ID); err != nil {
			m.logger.Error("Failed to sync program",
				"program", program.Name,
				"error", err)
			errors = append(errors, err)
		}

		// Rate limit between syncs
		time.Sleep(2 * time.Second)
	}

	if len(errors) > 0 {
		return fmt.Errorf("sync completed with %d errors", len(errors))
	}

	return nil
}

// ValidateAsset validates if an asset is in scope
func (m *Manager) ValidateAsset(asset string) (*ValidationResult, error) {
	// Check cache first
	if cached := m.cache.GetValidation(asset); cached != nil {
		return cached, nil
	}

	result := m.validator.Validate(asset)

	// Store validation result
	if err := m.storeValidation(result); err != nil {
		m.logger.Error("Failed to store validation", "error", err)
	}

	// Cache result
	m.cache.StoreValidation(asset, result)

	return result, nil
}

// ValidateBatch validates multiple assets
func (m *Manager) ValidateBatch(assets []string) ([]*ValidationResult, error) {
	results := make([]*ValidationResult, len(assets))

	// Use worker pool for parallel validation
	workers := m.config.ValidateWorkers
	if workers <= 0 {
		workers = 10
	}

	type job struct {
		index int
		asset string
	}

	jobs := make(chan job, len(assets))
	resultsChan := make(chan struct {
		index  int
		result *ValidationResult
		err    error
	}, len(assets))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				result, err := m.ValidateAsset(j.asset)
				resultsChan <- struct {
					index  int
					result *ValidationResult
					err    error
				}{j.index, result, err}
			}
		}()
	}

	// Send jobs
	for i, asset := range assets {
		jobs <- job{i, asset}
	}
	close(jobs)

	// Wait for completion
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	var firstErr error
	for r := range resultsChan {
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		results[r.index] = r.result
	}

	return results, firstErr
}

// IsInScope is a simple helper to check if asset is in scope
func (m *Manager) IsInScope(asset string) (bool, error) {
	result, err := m.ValidateAsset(asset)
	if err != nil {
		return false, err
	}
	return result.Status == ScopeStatusInScope, nil
}

// GetProgram retrieves a program by ID
func (m *Manager) GetProgram(programID string) (*Program, error) {
	var program Program

	row := m.db.QueryRowxContext(context.Background(), `
        SELECT id, platform, name, handle, url, testing_guidelines,
               vpn_required, max_bounty, last_synced, active, metadata
        FROM scope_programs WHERE id = ?`, programID)

	var metadata sql.NullString
	err := row.Scan(&program.ID, &program.Platform, &program.Name,
		&program.Handle, &program.URL, &program.TestingGuidelines,
		&program.VPNRequired, &program.MaxBounty, &program.LastSynced,
		&program.Active, &metadata)
	if err != nil {
		return nil, err
	}

	if metadata.Valid && metadata.String != "" {
		json.Unmarshal([]byte(metadata.String), &program.Metadata)
	}

	// Load scope items
	program.Scope, err = m.getScopeItems(programID, ScopeStatusInScope)
	if err != nil {
		return nil, err
	}

	program.OutOfScope, err = m.getScopeItems(programID, ScopeStatusOutOfScope)
	if err != nil {
		return nil, err
	}

	// Load rules
	program.Rules, err = m.getRules(programID)
	if err != nil {
		return nil, err
	}

	return &program, nil
}

// getScopeItems retrieves scope items for a program
func (m *Manager) getScopeItems(programID string, status ScopeStatus) ([]ScopeItem, error) {
	rows, err := m.db.QueryxContext(context.Background(), `
        SELECT id, type, value, status, description, severity,
               environment_type, max_severity, restrictions, instructions,
               metadata, last_updated
        FROM scope_items 
        WHERE program_id = ? AND status = ?`, programID, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []ScopeItem
	for rows.Next() {
		var item ScopeItem
		var restrictions, metadata sql.NullString

		err := rows.Scan(&item.ID, &item.Type, &item.Value, &item.Status,
			&item.Description, &item.Severity, &item.EnvironmentType,
			&item.MaxSeverity, &restrictions, &item.Instructions,
			&metadata, &item.LastUpdated)
		if err != nil {
			return nil, err
		}

		if restrictions.Valid && restrictions.String != "" {
			json.Unmarshal([]byte(restrictions.String), &item.Restrictions)
		}
		if metadata.Valid && metadata.String != "" {
			json.Unmarshal([]byte(metadata.String), &item.Metadata)
		}

		// Compile regex patterns for wildcards
		if item.Type == ScopeTypeWildcard {
			item.CompiledPattern = compileWildcardPattern(item.Value)
		}

		items = append(items, item)
	}

	return items, nil
}

// getRules retrieves rules for a program
func (m *Manager) getRules(programID string) ([]Rule, error) {
	rows, err := m.db.QueryxContext(context.Background(), `
        SELECT id, type, description, value, applies_to
        FROM scope_rules WHERE program_id = ?`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var rule Rule
		var appliesTo sql.NullString

		err := rows.Scan(&rule.ID, &rule.Type, &rule.Description,
			&rule.Value, &appliesTo)
		if err != nil {
			return nil, err
		}

		if appliesTo.Valid && appliesTo.String != "" {
			json.Unmarshal([]byte(appliesTo.String), &rule.Applies)
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// ListPrograms lists all programs
func (m *Manager) ListPrograms() ([]*Program, error) {
	rows, err := m.db.QueryxContext(context.Background(), `
        SELECT id FROM scope_programs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var programs []*Program
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}

		program, err := m.GetProgram(id)
		if err != nil {
			return nil, err
		}

		programs = append(programs, program)
	}

	return programs, nil
}

// GetScopeForProgram returns scope items for a program
func (m *Manager) GetScopeForProgram(programID string) ([]ScopeItem, error) {
	return m.getScopeItems(programID, ScopeStatusInScope)
}

// GetAllInScopeItems returns all in-scope items
func (m *Manager) GetAllInScopeItems() ([]ScopeItem, error) {
	rows, err := m.db.QueryxContext(context.Background(), `
        SELECT id, program_id, type, value, status, description, severity,
               environment_type, max_severity, restrictions, instructions,
               metadata, last_updated
        FROM scope_items 
        WHERE status = ?`, ScopeStatusInScope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []ScopeItem
	for rows.Next() {
		var item ScopeItem
		var programID string
		var restrictions, metadata sql.NullString

		err := rows.Scan(&item.ID, &programID, &item.Type, &item.Value, &item.Status,
			&item.Description, &item.Severity, &item.EnvironmentType,
			&item.MaxSeverity, &restrictions, &item.Instructions,
			&metadata, &item.LastUpdated)
		if err != nil {
			return nil, err
		}

		if restrictions.Valid && restrictions.String != "" {
			json.Unmarshal([]byte(restrictions.String), &item.Restrictions)
		}
		if metadata.Valid && metadata.String != "" {
			json.Unmarshal([]byte(metadata.String), &item.Metadata)
		}

		// Compile regex patterns for wildcards
		if item.Type == ScopeTypeWildcard {
			item.CompiledPattern = compileWildcardPattern(item.Value)
		}

		items = append(items, item)
	}

	return items, nil
}

// SearchScope searches for scope items matching a query
func (m *Manager) SearchScope(query string) ([]ScopeItem, error) {
	rows, err := m.db.QueryxContext(context.Background(), `
        SELECT id, program_id, type, value, status, description, severity,
               environment_type, max_severity, restrictions, instructions,
               metadata, last_updated
        FROM scope_items 
        WHERE value LIKE ? OR description LIKE ?`,
		"%"+query+"%", "%"+query+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []ScopeItem
	for rows.Next() {
		var item ScopeItem
		var programID string
		var restrictions, metadata sql.NullString

		err := rows.Scan(&item.ID, &programID, &item.Type, &item.Value, &item.Status,
			&item.Description, &item.Severity, &item.EnvironmentType,
			&item.MaxSeverity, &restrictions, &item.Instructions,
			&metadata, &item.LastUpdated)
		if err != nil {
			return nil, err
		}

		if restrictions.Valid && restrictions.String != "" {
			json.Unmarshal([]byte(restrictions.String), &item.Restrictions)
		}
		if metadata.Valid && metadata.String != "" {
			json.Unmarshal([]byte(metadata.String), &item.Metadata)
		}

		// Compile regex patterns for wildcards
		if item.Type == ScopeTypeWildcard {
			item.CompiledPattern = compileWildcardPattern(item.Value)
		}

		items = append(items, item)
	}

	return items, nil
}

// storeValidation stores a validation result
func (m *Manager) storeValidation(result *ValidationResult) error {
	restrictions, _ := json.Marshal(result.Restrictions)

	var programID, scopeItemID sql.NullString
	if result.Program != nil {
		programID = sql.NullString{String: result.Program.ID, Valid: true}
	}
	if result.MatchedItem != nil {
		scopeItemID = sql.NullString{String: result.MatchedItem.ID, Valid: true}
	}

	_, err := m.db.ExecContext(context.Background(), `
        INSERT INTO scope_validations 
        (asset, status, program_id, scope_item_id, reason, restrictions, validated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		result.Asset, result.Status, programID, scopeItemID,
		result.Reason, string(restrictions), result.ValidatedAt)

	return err
}

// StartMonitoring starts the scope monitoring service
func (m *Manager) StartMonitoring() error {
	if !m.config.EnableMonitoring {
		return nil
	}
	return m.monitor.Start()
}

// StopMonitoring stops the scope monitoring service
func (m *Manager) StopMonitoring() error {
	return m.monitor.Stop()
}

// compileWildcardPattern compiles a wildcard pattern to regex
func compileWildcardPattern(pattern string) *regexp.Regexp {
	// Escape special regex characters except *
	escaped := strings.ReplaceAll(pattern, ".", `\.`)
	escaped = strings.ReplaceAll(escaped, "*", ".*")
	// Anchor the pattern
	escaped = "^" + escaped + "$"

	compiled, err := regexp.Compile(escaped)
	if err != nil {
		return nil
	}

	return compiled
}