// internal/orchestrator/scanners/manager.go
//
// Scanner Manager - Unified orchestration for all vulnerability scanners
//
// REFACTORING CONTEXT:
// This file extracts scanner orchestration from bounty_engine.go (4,118 lines).
// Previously, each scanner had its own run* method (runAuthenticationTests,
// runSCIMTests, etc.) directly on BugBountyEngine - 990 lines of unmaintainable code.
//
// NEW ARCHITECTURE:
// - Scanner interface: Unified abstraction for all scanners
// - Manager: Registry-based orchestration with parallel execution
// - Extensibility: Add new scanners without modifying engine
//
// PHILOSOPHY ALIGNMENT:
// - Sustainable: Clear separation of concerns, each scanner self-contained
// - Evidence-based: Scanners report findings with structured evidence
// - Human-centric: Transparent execution with progress tracking

package scanners

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// Scanner represents a unified vulnerability scanner interface
// All scanners (Auth, SCIM, API, Nmap, Nuclei, GraphQL, IDOR) implement this
type Scanner interface {
	// Name returns the scanner's display name
	Name() string

	// Type returns the scanner category (auth, api, infrastructure, etc.)
	Type() string

	// Execute runs the scanner against prioritized assets
	Execute(ctx context.Context, assets []*AssetPriority) ([]types.Finding, error)

	// CanHandle determines if this scanner can test the given asset
	CanHandle(asset *AssetPriority) bool

	// Priority returns execution priority (1-10, lower = earlier)
	// Used for dependency-aware ordering (e.g., auth scanners run before API scanners)
	Priority() int
}

// AssetPriority represents a prioritized asset for testing
// This type is used throughout the orchestrator to track asset importance
type AssetPriority struct {
	Asset      *discovery.Asset
	Priority   int
	Reasoning  string
	Features   AssetFeatures
	ScopeMatch string // "in-scope", "out-of-scope", "unknown"
}

// AssetFeatures represents detected features of an asset
// Used for intelligent scanner selection
type AssetFeatures struct {
	HasAuthentication bool     // Login pages, auth endpoints
	HasAPIEndpoints   bool     // REST, GraphQL, SOAP APIs
	HasAdminPanel     bool     // Admin interfaces
	HasFileUpload     bool     // File upload capabilities
	HasPaymentFlow    bool     // Payment/transaction endpoints
	HasSCIMEndpoint   bool     // SCIM provisioning
	TechStack         []string // Detected technologies
	OpenPorts         []int    // Open ports from port scan
	Services          []string // Detected services
}

// Manager orchestrates execution of all registered scanners
type Manager struct {
	registry map[string]Scanner
	logger   *logger.Logger
	config   ManagerConfig
	mu       sync.RWMutex
}

// ManagerConfig contains scanner manager configuration
type ManagerConfig struct {
	// Parallel execution settings
	MaxConcurrentScanners int // Max scanners running in parallel (0 = unlimited)

	// Timeout settings
	DefaultScannerTimeout time.Duration

	// Filtering
	EnabledScanners  []string // Empty = all enabled
	DisabledScanners []string // Scanners to skip

	// Execution strategy
	RespectPriority bool // If true, execute in priority order; if false, parallel
	FailFast        bool // Stop on first scanner error
}

// DefaultManagerConfig returns sensible defaults
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		MaxConcurrentScanners: 5, // Run up to 5 scanners in parallel
		DefaultScannerTimeout: 15 * time.Minute,
		RespectPriority:       true,  // Dependency-aware execution
		FailFast:              false, // Continue testing even if one scanner fails
	}
}

// NewManager creates a new scanner manager
func NewManager(config ManagerConfig, logger *logger.Logger) *Manager {
	return &Manager{
		registry: make(map[string]Scanner),
		logger:   logger.WithComponent("scanner-manager"),
		config:   config,
	}
}

// Register adds a scanner to the registry
func (m *Manager) Register(name string, scanner Scanner) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.registry[name]; exists {
		return fmt.Errorf("scanner %s already registered", name)
	}

	m.registry[name] = scanner
	m.logger.Debugw("Scanner registered",
		"name", name,
		"type", scanner.Type(),
		"priority", scanner.Priority(),
	)
	return nil
}

// Unregister removes a scanner from the registry
func (m *Manager) Unregister(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.registry, name)
}

// Get retrieves a scanner by name
func (m *Manager) Get(name string) (Scanner, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	scanner, ok := m.registry[name]
	return scanner, ok
}

// List returns all registered scanner names
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.registry))
	for name := range m.registry {
		names = append(names, name)
	}
	return names
}

// ExecuteAll runs all registered scanners against the provided assets
// Respects priority ordering and parallel execution settings
func (m *Manager) ExecuteAll(ctx context.Context, assets []*AssetPriority) ([]types.Finding, error) {
	m.mu.RLock()
	scanners := m.getEnabledScanners()
	m.mu.RUnlock()

	if len(scanners) == 0 {
		m.logger.Warnw("No scanners registered or enabled")
		return []types.Finding{}, nil
	}

	m.logger.Infow("Executing scanners",
		"total_scanners", len(scanners),
		"total_assets", len(assets),
		"respect_priority", m.config.RespectPriority,
	)

	if m.config.RespectPriority {
		return m.executeSequential(ctx, scanners, assets)
	}
	return m.executeParallel(ctx, scanners, assets)
}

// ExecuteByName runs a specific scanner by name
func (m *Manager) ExecuteByName(ctx context.Context, name string, assets []*AssetPriority) ([]types.Finding, error) {
	scanner, ok := m.Get(name)
	if !ok {
		return nil, fmt.Errorf("scanner %s not found", name)
	}

	if !m.isScannerEnabled(name) {
		m.logger.Warnw("Scanner is disabled",
			"scanner", name,
		)
		return []types.Finding{}, nil
	}

	m.logger.Infow("Executing scanner",
		"scanner", name,
		"type", scanner.Type(),
		"assets", len(assets),
	)

	return m.executeSingleScanner(ctx, scanner, assets)
}

// ExecuteByType runs all scanners of a specific type (e.g., "auth", "api")
func (m *Manager) ExecuteByType(ctx context.Context, scannerType string, assets []*AssetPriority) ([]types.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matchingScanners []Scanner
	for name, scanner := range m.registry {
		if scanner.Type() == scannerType && m.isScannerEnabled(name) {
			matchingScanners = append(matchingScanners, scanner)
		}
	}

	if len(matchingScanners) == 0 {
		m.logger.Warnw("No scanners found for type",
			"type", scannerType,
		)
		return []types.Finding{}, nil
	}

	m.logger.Infow("Executing scanners by type",
		"type", scannerType,
		"scanner_count", len(matchingScanners),
		"assets", len(assets),
	)

	return m.executeParallel(ctx, matchingScanners, assets)
}

// getEnabledScanners returns scanners that should be executed
func (m *Manager) getEnabledScanners() []Scanner {
	var enabled []Scanner
	for name, scanner := range m.registry {
		if m.isScannerEnabled(name) {
			enabled = append(enabled, scanner)
		}
	}

	// Sort by priority if needed
	if m.config.RespectPriority {
		sortScannersByPriority(enabled)
	}

	return enabled
}

// isScannerEnabled checks if a scanner should be executed
func (m *Manager) isScannerEnabled(name string) bool {
	// Check if explicitly disabled
	for _, disabled := range m.config.DisabledScanners {
		if disabled == name {
			return false
		}
	}

	// If EnabledScanners is specified, only run those
	if len(m.config.EnabledScanners) > 0 {
		for _, enabled := range m.config.EnabledScanners {
			if enabled == name {
				return true
			}
		}
		return false
	}

	return true
}

// executeSequential runs scanners one at a time in priority order
func (m *Manager) executeSequential(ctx context.Context, scanners []Scanner, assets []*AssetPriority) ([]types.Finding, error) {
	allFindings := []types.Finding{}

	for _, scanner := range scanners {
		select {
		case <-ctx.Done():
			return allFindings, ctx.Err()
		default:
		}

		findings, err := m.executeSingleScanner(ctx, scanner, assets)
		if err != nil {
			m.logger.Errorw("Scanner execution failed",
				"scanner", scanner.Name(),
				"error", err,
			)
			if m.config.FailFast {
				return allFindings, err
			}
			continue
		}

		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// executeParallel runs scanners concurrently with concurrency limit
func (m *Manager) executeParallel(ctx context.Context, scanners []Scanner, assets []*AssetPriority) ([]types.Finding, error) {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		findings []types.Finding
		firstErr error
	)

	// Semaphore for concurrency control
	maxConcurrent := m.config.MaxConcurrentScanners
	if maxConcurrent <= 0 {
		maxConcurrent = len(scanners) // Unlimited
	}
	sem := make(chan struct{}, maxConcurrent)

	for _, scanner := range scanners {
		scanner := scanner // Capture for goroutine

		wg.Add(1)
		go func() {
			defer wg.Done()

			// Acquire semaphore
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			// Execute scanner
			scannerFindings, err := m.executeSingleScanner(ctx, scanner, assets)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				m.logger.Errorw("Scanner execution failed",
					"scanner", scanner.Name(),
					"error", err,
				)
				if firstErr == nil {
					firstErr = err
				}
				return
			}

			findings = append(findings, scannerFindings...)
		}()
	}

	wg.Wait()

	if m.config.FailFast && firstErr != nil {
		return findings, firstErr
	}

	return findings, nil
}

// executeSingleScanner executes one scanner with timeout and filtering
func (m *Manager) executeSingleScanner(ctx context.Context, scanner Scanner, assets []*AssetPriority) ([]types.Finding, error) {
	start := time.Now()

	// Filter assets that this scanner can handle
	relevantAssets := m.filterAssetsForScanner(scanner, assets)
	if len(relevantAssets) == 0 {
		m.logger.Debugw("Scanner skipped - no relevant assets",
			"scanner", scanner.Name(),
		)
		return []types.Finding{}, nil
	}

	m.logger.Infow("Starting scanner",
		"scanner", scanner.Name(),
		"type", scanner.Type(),
		"relevant_assets", len(relevantAssets),
		"total_assets", len(assets),
	)

	// Apply timeout
	scanCtx, cancel := context.WithTimeout(ctx, m.config.DefaultScannerTimeout)
	defer cancel()

	// Execute scanner
	findings, err := scanner.Execute(scanCtx, relevantAssets)
	duration := time.Since(start)

	if err != nil {
		m.logger.Errorw("Scanner failed",
			"scanner", scanner.Name(),
			"duration", duration.String(),
			"error", err,
		)
		return nil, fmt.Errorf("scanner %s failed: %w", scanner.Name(), err)
	}

	m.logger.Infow("Scanner completed",
		"scanner", scanner.Name(),
		"duration", duration.String(),
		"findings", len(findings),
	)

	return findings, nil
}

// filterAssetsForScanner returns assets that the scanner can handle
func (m *Manager) filterAssetsForScanner(scanner Scanner, assets []*AssetPriority) []*AssetPriority {
	var relevant []*AssetPriority
	for _, asset := range assets {
		if scanner.CanHandle(asset) {
			relevant = append(relevant, asset)
		}
	}
	return relevant
}

// sortScannersByPriority sorts scanners by priority (lower number = higher priority)
func sortScannersByPriority(scanners []Scanner) {
	// Simple bubble sort (fine for small number of scanners)
	n := len(scanners)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if scanners[j].Priority() > scanners[j+1].Priority() {
				scanners[j], scanners[j+1] = scanners[j+1], scanners[j]
			}
		}
	}
}

// ScannerStats returns execution statistics
type ScannerStats struct {
	TotalScanners    int
	EnabledScanners  int
	DisabledScanners int
	RegisteredTypes  map[string]int // Type -> count
}

// GetStats returns scanner registry statistics
func (m *Manager) GetStats() ScannerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := ScannerStats{
		TotalScanners:   len(m.registry),
		RegisteredTypes: make(map[string]int),
	}

	for name, scanner := range m.registry {
		if m.isScannerEnabled(name) {
			stats.EnabledScanners++
		} else {
			stats.DisabledScanners++
		}
		stats.RegisteredTypes[scanner.Type()]++
	}

	return stats
}
