// internal/orchestrator/bounty_engine.go
package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/internal/orchestrator/scanners"
	"github.com/CodeMonkeyCybersecurity/shells/internal/progress"
	"github.com/CodeMonkeyCybersecurity/shells/internal/ratelimit"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/oauth2"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/saml"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/webauthn"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/checkpoint"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/enrichment"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/intel/certs"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scope"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/workers"
	"github.com/google/uuid"
)

// BugBountyEngine orchestrates the full bug bounty scanning pipeline
//
// REFACTORED (2025-10-28): Simplified from god object to orchestrator
// - BEFORE: 14 individual scanner fields (samlScanner, oauth2Scanner, etc.)
// - AFTER: 1 scannerManager field (registry-based)
// - ELIMINATED: 350+ lines of scanner initialization code (moved to factory.go)
type BugBountyEngine struct {
	// Core services
	store       core.ResultStore
	telemetry   core.Telemetry
	logger      *logger.Logger
	rateLimiter *ratelimit.Limiter

	// Discovery
	discoveryEngine *discovery.Engine
	orgCorrelator   *correlation.OrganizationCorrelator
	certIntel       *certs.CertIntel
	scopeManager    *scope.Manager // Bug bounty program scope management
	authDiscovery   *auth.AuthDiscoveryEngine

	// Scanners (REFACTORED: unified manager replaces 14 individual scanner fields)
	scannerManager *scanners.Manager

	// DEPRECATED: Individual scanner fields kept temporarily for backward compatibility
	// These will be removed once all references are migrated to scannerManager
	// TODO: Remove after migration complete
	samlScanner     *saml.SAMLScanner         // DEPRECATED: Use scannerManager.Get("authentication")
	oauth2Scanner   *oauth2.OAuth2Scanner     // DEPRECATED: Use scannerManager.Get("authentication")
	webauthnScanner *webauthn.WebAuthnScanner // DEPRECATED: Use scannerManager.Get("authentication")
	scimScanner     core.Scanner              // DEPRECATED: Use scannerManager.Get("scim")
	nmapScanner     core.Scanner              // DEPRECATED: Use scannerManager.Get("nmap")
	nucleiScanner   core.Scanner              // DEPRECATED: Use scannerManager.Get("nuclei")
	graphqlScanner  core.Scanner              // DEPRECATED: Use scannerManager.Get("graphql")
	idorScanner     core.Scanner              // DEPRECATED: Use scannerManager.Get("idor")
	restapiScanner  core.Scanner              // DEPRECATED: Use scannerManager.Get("api")

	// Python worker client (optional - for GraphCrawler)
	pythonWorkers *workers.Client

	// Enrichment
	enricher *enrichment.ResultEnricher

	// Checkpointing
	checkpointEnabled  bool
	checkpointInterval time.Duration
	checkpointManager  CheckpointManager

	// Output and Persistence (REFACTORED: extracted from bounty_engine.go)
	outputFormatter           *OutputFormatter
	persistenceManager        *PersistenceManager
	platformIntegration       *PlatformIntegration
	organizationFootprinting  *OrganizationFootprinting
	scopeValidator            *ScopeValidator

	// Configuration
	config BugBountyConfig
}

// CheckpointManager defines the interface for checkpoint operations
// This allows mocking in tests and alternative storage backends
type CheckpointManager interface {
	Save(ctx context.Context, state interface{}) error
	Load(ctx context.Context, scanID string) (interface{}, error)
	Delete(ctx context.Context, scanID string) error
}

// BugBountyConfig contains configuration for comprehensive bug bounty scans
type BugBountyConfig struct {
	// Timeouts
	DiscoveryTimeout time.Duration
	ScanTimeout      time.Duration
	TotalTimeout     time.Duration

	// Comprehensive discovery settings
	MaxAssets      int
	MaxDepth       int
	EnablePortScan bool
	EnableWebCrawl bool
	EnableDNS      bool
	SkipDiscovery  bool // If true, use target directly without discovery

	// Advanced discovery features
	EnableSubdomainEnum      bool // Subdomain enumeration via DNS, certs, search engines
	EnableCertTransparency   bool // Certificate transparency logs for related domains
	EnableAdjacentIPScan     bool // Scan neighboring IPs in same subnet
	EnableRelatedDomainDisc  bool // Find related domains (same org, same cert, same email)
	EnableWHOISAnalysis      bool // WHOIS data for organization footprinting
	EnableServiceFingerprint bool // Deep service version detection on open ports

	// Comprehensive testing settings
	EnableAuthTesting    bool // SAML, OAuth2, WebAuthn, JWT
	EnableAPITesting     bool // REST API security
	EnableLogicTesting   bool // Business logic flaws
	EnableSSRFTesting    bool // Server-side request forgery
	EnableAccessControl  bool // IDOR, broken access control
	EnableSCIMTesting    bool // SCIM provisioning vulnerabilities
	EnableGraphQLTesting bool // GraphQL introspection, injection, DoS
	EnableIDORTesting    bool // Insecure Direct Object Reference testing
	EnableSQLiTesting    bool // SQL injection detection
	EnableXSSTesting     bool // Cross-site scripting detection
	EnableNucleiScan     bool // Nuclei vulnerability templates (CVEs, misconfigurations)

	// Database and persistence
	EnableTemporalSnapshots bool          // Track changes over time (historical comparison)
	SnapshotInterval        time.Duration // How often to snapshot (for repeated scans)

	// Enrichment settings (TASK 14)
	EnableEnrichment bool   // Enable finding enrichment (CVSS, exploits, remediation)
	EnrichmentLevel  string // "basic", "standard", "comprehensive"

	// Rate limiting settings
	RateLimitPerSecond float64
	RateLimitBurst     int

	// Output settings
	ShowProgress bool
	Verbose      bool

	// Checkpointing settings
	EnableCheckpointing bool          // Enable automatic checkpoint saves
	CheckpointInterval  time.Duration // How often to save checkpoints (default: 5 minutes)

	// Scope management settings (Bug Bounty Platform Integration)
	EnableScopeValidation bool   // Validate assets against bug bounty program scope before testing
	BugBountyPlatform     string // Platform to import scope from (hackerone, bugcrowd, intigriti, yeswehack)
	BugBountyProgram      string // Program handle/slug to import scope from
	ScopeStrictMode       bool   // Fail closed on ambiguous scope decisions (default: fail open)

	// Platform API credentials (read from environment variables)
	PlatformCredentials map[string]PlatformCredential // Platform name -> credentials
}

// PlatformCredential stores API credentials for bug bounty platforms
type PlatformCredential struct {
	Username string
	APIKey   string
}

// DefaultBugBountyConfig returns comprehensive configuration for full asset discovery and testing
// This is the "point and click" mode - discover everything, test everything, save everything
func DefaultBugBountyConfig() BugBountyConfig {
	return BugBountyConfig{
		// Generous timeouts for comprehensive scanning
		DiscoveryTimeout: 5 * time.Minute,  // DNS, subdomain enum, cert transparency takes time
		ScanTimeout:      15 * time.Minute, // Deep testing of all discovered assets
		TotalTimeout:     30 * time.Minute, // Full comprehensive scan

		// Comprehensive discovery settings
		MaxAssets:      500,  // Discover and test up to 500 assets (subdomains, IPs, APIs)
		MaxDepth:       3,    // Deep crawl for login pages, API endpoints, admin panels
		EnablePortScan: true, // Find all exposed services
		EnableWebCrawl: true, // Deep crawl to find auth endpoints, APIs, admin panels
		EnableDNS:      true, // CRITICAL: Subdomain enum, related domains, cert transparency, WHOIS

		// Advanced discovery features - ENABLE EVERYTHING
		EnableSubdomainEnum:      true, // Subdomain brute force, DNS records, search engines
		EnableCertTransparency:   true, // Certificate transparency logs (crt.sh, etc.)
		EnableAdjacentIPScan:     true, // Scan neighboring IPs in /24 subnet
		EnableRelatedDomainDisc:  true, // Find domains: same org, same cert issuer, same registrant email
		EnableWHOISAnalysis:      true, // WHOIS for org name, registrant, admin contact, tech contact
		EnableServiceFingerprint: true, // Nmap service version detection on all open ports

		// Enable ALL vulnerability testing
		EnableAuthTesting:    true, // SAML, OAuth2, WebAuthn, JWT, session handling
		EnableAPITesting:     true, // REST API security, rate limiting, auth bypass
		EnableLogicTesting:   true, // Business logic flaws, privilege escalation
		EnableSSRFTesting:    true, // Server-side request forgery, cloud metadata access
		EnableAccessControl:  true, // Horizontal/vertical privilege escalation
		EnableSCIMTesting:    true, // SCIM provisioning vulnerabilities
		EnableGraphQLTesting: true, // GraphQL introspection, injection, DoS, batching attacks
		EnableIDORTesting:    true, // Insecure Direct Object Reference (sequential IDs, UUIDs)
		EnableSQLiTesting:    true, // SQL injection detection and exploitation
		EnableXSSTesting:     true, // Reflected, stored, DOM-based XSS
		EnableNucleiScan:     true, // Nuclei vulnerability scanner (CVEs, misconfigurations, exposures)

		// Database and persistence - track everything over time
		EnableTemporalSnapshots: true,           // Save snapshots for historical comparison
		SnapshotInterval:        24 * time.Hour, // Daily snapshots for repeated scans

		// Enrichment - add context to findings (TASK 14)
		EnableEnrichment: true,            // Enrich findings with CVSS, exploits, remediation
		EnrichmentLevel:  "comprehensive", // Full enrichment with business impact, compliance

		// Respectful rate limiting (won't trigger WAFs but still comprehensive)
		RateLimitPerSecond: 10.0, // 10 requests per second
		RateLimitBurst:     20,   // Allow bursts of 20 for parallel operations

		// User experience
		ShowProgress: true,  // Show real-time progress updates
		Verbose:      false, // Concise output (use --log-level debug for verbose)

		// Checkpointing (enabled by default for graceful shutdown)
		EnableCheckpointing: true,            // Save checkpoints automatically
		CheckpointInterval:  5 * time.Minute, // Save every 5 minutes during long scans
	}
}

// NewBugBountyEngine creates a new bug bounty orchestration engine
//
// REFACTORED (2025-10-28): Delegates to EngineFactory for clean initialization
// Previously this was a 349-line constructor - now it's a simple factory delegation.
//
// See factory.go for the actual initialization logic.
func NewBugBountyEngine(
	store core.ResultStore,
	telemetry core.Telemetry,
	logger *logger.Logger,
	config BugBountyConfig,
) (*BugBountyEngine, error) {
	factory := NewEngineFactory(store, telemetry, logger, config)
	return factory.Build()
}

// BugBountyResult and PhaseResult moved to result.go for better organization
// See result.go for thread-safe result container with mutex-protected operations

// Execute runs the full bug bounty pipeline
func (e *BugBountyEngine) Execute(ctx context.Context, target string) (*BugBountyResult, error) {
	execStart := time.Now()

	// Create scan record with UUID to prevent collisions (must be early for DB logger)
	scanID := fmt.Sprintf("bounty-%d-%s", time.Now().Unix(), uuid.New().String()[:8])

	// Wrap logger with database event logger to save all scan events to database for UI
	// DBEventLogger intercepts ALL logging methods (Info/Infow/Debug/Debugw/Warn/Warnw/Error/Errorw)
	// and saves them to database asynchronously while also logging to stdout.
	// We use dbLogger throughout this function and pass it to all child components.
	dbLogger := logger.NewDBEventLogger(e.logger, e.store, scanID)

	dbLogger.Infow(" Starting bug bounty scan",
		"target", target,
		"config_discovery_timeout", e.config.DiscoveryTimeout.String(),
		"config_scan_timeout", e.config.ScanTimeout.String(),
		"config_total_timeout", e.config.TotalTimeout.String(),
		"max_assets", e.config.MaxAssets,
		"max_depth", e.config.MaxDepth,
		"enable_dns", e.config.EnableDNS,
		"enable_port_scan", e.config.EnablePortScan,
		"enable_web_crawl", e.config.EnableWebCrawl,
	)

	// Initialize progress tracker (needs the underlying Logger, not DBEventLogger wrapper)
	tracker := progress.New(e.config.ShowProgress, dbLogger.Logger)
	tracker.AddPhase("discovery", "Discovering assets")
	tracker.AddPhase("prioritization", "Prioritizing targets")
	tracker.AddPhase("testing", "Testing for vulnerabilities")
	tracker.AddPhase("storage", "Storing results")

	result := &BugBountyResult{
		ScanID:       scanID,
		Target:       target,
		StartTime:    time.Now(),
		Status:       "running",
		PhaseResults: make(map[string]PhaseResult),
		Findings:     []types.Finding{},
	}

	// P0-3 FIX: Test database connectivity BEFORE starting expensive scan
	dbLogger.Infow("Testing database connectivity",
		"component", "orchestrator",
	)
	healthCtx, healthCancel := context.WithTimeout(ctx, 5*time.Second)
	defer healthCancel()

	testScan := &types.ScanRequest{
		ID:     scanID + "-health-check",
		Target: "health-check",
		Type:   types.ScanTypeAuth,
		Status: types.ScanStatusRunning,
	}
	if err := e.store.SaveScan(healthCtx, testScan); err != nil {
		return nil, fmt.Errorf("database health check failed - scan aborted to prevent data loss:\n"+
			"  Error: %v\n"+
			"  Check: 1) Database running 2) Connection string correct 3) Network connectivity",
			err)
	}
	// TODO: Clean up test scan record if needed
	dbLogger.Infow("Database health check passed", "component", "orchestrator")

	// Create initial scan record in database so events can reference it via foreign key
	initialScan := &types.ScanRequest{
		ID:        scanID,
		Target:    target,
		Type:      types.ScanTypeAuth,
		Status:    types.ScanStatusRunning,
		CreatedAt: result.StartTime,
	}
	if err := e.store.SaveScan(ctx, initialScan); err != nil {
		// Log but don't fail - scan can continue even if DB save fails
		dbLogger.Warnw("Failed to save initial scan record",
			"error", err,
			"scan_id", scanID,
		)
	}

	dbLogger.Infow(" Scan initialized",
		"scan_id", scanID,
		"start_time", result.StartTime.Format(time.RFC3339),
	)

	// Helper function to save checkpoint
	// FIXED: Actually saves checkpoint state to disk for resume capability
	saveCheckpoint := func(phase string, progress float64, completedTests []string, findings []types.Finding) {
		if !e.checkpointEnabled || e.checkpointManager == nil {
			return
		}

		// P0-2/19/20 FIX: Use thread-safe methods to prevent race conditions
		// GetDiscoveredAssetsForCheckpoint() holds read lock internally
		assets := result.GetDiscoveredAssetsForCheckpoint()
		checkpointAssets := checkpoint.ConvertDiscoveryAssets(assets)

		// Build checkpoint state
		state := &checkpoint.State{
			ScanID:           scanID,
			Target:           target,
			CreatedAt:        result.StartTime,
			UpdatedAt:        time.Now(),
			Progress:         progress,
			CurrentPhase:     phase,
			DiscoveredAssets: checkpointAssets,
			CompletedTests:   completedTests,
			Findings:         findings,
			Metadata: map[string]interface{}{
				// P1-3 FIX: Save COMPLETE config so resume behaves identically to original scan
				"quick_mode":                 e.config.SkipDiscovery,
				"total_timeout":              e.config.TotalTimeout.String(),
				"scan_timeout":               e.config.ScanTimeout.String(),
				"discovery_timeout":          e.config.DiscoveryTimeout.String(),
				"enable_dns":                 e.config.EnableDNS,
				"enable_port_scan":           e.config.EnablePortScan,
				"enable_web_crawl":           e.config.EnableWebCrawl,
				"enable_auth_testing":        e.config.EnableAuthTesting,
				"enable_api_testing":         e.config.EnableAPITesting,
				"enable_scim_testing":        e.config.EnableSCIMTesting,
				"enable_graphql_testing":     e.config.EnableGraphQLTesting,
				"enable_idor_testing":        e.config.EnableIDORTesting,
				"enable_service_fingerprint": e.config.EnableServiceFingerprint,
				"enable_nuclei_scan":         e.config.EnableNucleiScan,
				"max_assets":                 e.config.MaxAssets,
				"max_depth":                  e.config.MaxDepth,
				"show_progress":              e.config.ShowProgress,
				"rate_limit_per_second":      e.config.RateLimitPerSecond,
				"rate_limit_burst":           e.config.RateLimitBurst,
				"enable_checkpointing":       e.config.EnableCheckpointing,
				"checkpoint_interval":        e.config.CheckpointInterval.String(),
				"enable_enrichment":          e.config.EnableEnrichment,
				"enrichment_level":           e.config.EnrichmentLevel,
				"enable_whois_analysis":      e.config.EnableWHOISAnalysis,
				"enable_cert_transparency":   e.config.EnableCertTransparency,
				"enable_related_domain_disc": e.config.EnableRelatedDomainDisc,
				"bug_bounty_platform":        e.config.BugBountyPlatform,
				"bug_bounty_program":         e.config.BugBountyProgram,
			},
		}

		// P0-1 FIX: Use background context for checkpoint save to survive Ctrl+C
		// The parent ctx may be cancelled when user presses Ctrl+C, but we MUST save the checkpoint
		// so the scan can be resumed later. Use a separate timeout context derived from Background.
		saveCtx, saveCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer saveCancel()

		// Save checkpoint to disk with isolated context
		if err := e.checkpointManager.Save(saveCtx, state); err != nil {
			dbLogger.Errorw("Failed to save checkpoint",
				"error", err,
				"scan_id", scanID,
				"phase", phase,
				"progress", progress,
				"context_error", ctx.Err(), // Log if parent was cancelled
			)
			// Log but don't fail the scan - checkpointing is best-effort
		} else {
			dbLogger.Infow("Checkpoint saved successfully",
				"scan_id", scanID,
				"phase", phase,
				"progress", progress,
				"completed_tests", completedTests,
				"findings_count", len(findings),
				"assets_discovered", len(checkpointAssets),
			)
		}
	}

	// Checkpoint after scan initialization
	saveCheckpoint("initialized", 0.0, []string{}, []types.Finding{})

	// Apply total timeout
	ctx, cancel := context.WithTimeout(ctx, e.config.TotalTimeout)
	defer cancel()

	// Log initial context state
	if deadline, ok := ctx.Deadline(); ok {
		dbLogger.Infow(" Total timeout context created",
			"total_timeout", e.config.TotalTimeout.String(),
			"deadline", deadline.Format(time.RFC3339),
			"deadline_unix", deadline.Unix(),
			"time_until_deadline", time.Until(deadline).String(),
		)
	} else {
		dbLogger.Warnw("  No deadline on parent context - unexpected!")
	}

	// P0-21 FIX: Start periodic checkpoint saver in background
	// This ensures checkpoints are saved during long-running phases (discovery, testing)
	// Without this, a 60-minute discovery phase that crashes at minute 59 has NO checkpoint
	var checkpointTicker *time.Ticker
	checkpointDone := make(chan bool)
	currentPhase := "initialized"
	currentProgress := 0.0
	var currentCompletedTests []string
	var progressMutex sync.RWMutex

	if e.checkpointEnabled && e.checkpointManager != nil && e.config.CheckpointInterval > 0 {
		checkpointTicker = time.NewTicker(e.config.CheckpointInterval)
		go func() {
			defer checkpointTicker.Stop()
			for {
				select {
				case <-checkpointTicker.C:
					// Save checkpoint with current progress
					progressMutex.RLock()
					phase := currentPhase
					progress := currentProgress
					tests := currentCompletedTests
					progressMutex.RUnlock()

					dbLogger.Debugw("Periodic checkpoint save triggered",
						"interval", e.config.CheckpointInterval,
						"phase", phase,
						"progress", progress,
					)
					// P0-19 FIX: Use thread-safe method to get findings
					findings := result.GetFindingsForCheckpoint()
					saveCheckpoint(phase, progress, tests, findings)

				case <-checkpointDone:
					// Scan complete or context cancelled, stop ticker
					return

				case <-ctx.Done():
					// Context cancelled (timeout or Ctrl+C), stop ticker
					return
				}
			}
		}()
		defer func() {
			close(checkpointDone) // Signal goroutine to stop
		}()

		dbLogger.Infow("Periodic checkpoint saver started",
			"interval", e.config.CheckpointInterval,
			"component", "checkpoint",
		)
	}

	// Helper to update current progress (for periodic saver)
	updateProgress := func(phase string, progress float64, tests []string) {
		progressMutex.Lock()
		currentPhase = phase
		currentProgress = progress
		currentCompletedTests = tests
		progressMutex.Unlock()
	}

	// Pre-Phase: Bug Bounty Platform Scope Import (if enabled)
	if e.platformIntegration != nil {
		scopeImported := e.platformIntegration.ImportScope(ctx, updateProgress, saveCheckpoint)
		if !scopeImported {
			// Scope import failed or disabled - disable scope validation
			e.scopeManager = nil
		} else {
			// Scope imported successfully - update scopeManager reference
			e.scopeManager = e.platformIntegration.GetScopeManager()
		}
	}

	// Phase 0: Organization Footprinting (if enabled)
	var orgDomains []string
	if e.organizationFootprinting != nil && e.organizationFootprinting.IsEnabled() {
		footprintResult := e.organizationFootprinting.CorrelateOrganization(ctx, target, updateProgress, saveCheckpoint)
		if footprintResult != nil {
			// Store organization info and domains
			if footprintResult.Organization != nil {
				result.OrganizationInfo = footprintResult.Organization
			}
			orgDomains = footprintResult.Domains

			// Store phase result
			if result.PhaseResults == nil {
				result.PhaseResults = make(map[string]PhaseResult)
			}
			result.PhaseResults["footprinting"] = footprintResult.PhaseResult
		}
	}

	// Phase 1: Asset Discovery (or skip if configured)
	var assets []*discovery.Asset
	var phaseResult PhaseResult

	if e.config.SkipDiscovery {
		// Quick mode: Use target directly without discovery
		dbLogger.Infow("⏭️  Skipping discovery (quick mode)",
			"target", target,
			"reason", "quick mode enabled - testing target directly",
		)
		tracker.StartPhase("discovery")

		// Normalize target to URL
		normalizedTarget := target
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			normalizedTarget = "https://" + target
		}

		assets = []*discovery.Asset{
			{
				Type:  discovery.AssetTypeURL,
				Value: normalizedTarget,
			},
		}

		phaseResult = PhaseResult{
			Phase:     "discovery",
			Status:    "skipped",
			StartTime: time.Now(),
			EndTime:   time.Now(),
			Duration:  0,
			Findings:  0,
		}
		result.PhaseResults["discovery"] = phaseResult
		result.DiscoveredAt = 1
		tracker.CompletePhase("discovery")
	} else {
		// Normal/Deep mode: Run full discovery
		discoveryStart := time.Now()

		// Determine targets to scan: original target + any org-related domains
		targetsToScan := []string{target}
		if len(orgDomains) > 0 {
			targetsToScan = orgDomains
			dbLogger.Infow(" Phase 1: Starting parallel discovery for organization domains",
				"organization_domains", len(orgDomains),
				"domains", orgDomains,
				"discovery_timeout", e.config.DiscoveryTimeout.String(),
				"enable_dns", e.config.EnableDNS,
				"enable_subdomain_enum", e.config.EnableSubdomainEnum,
				"enable_cert_transparency", e.config.EnableCertTransparency,
				"elapsed_since_scan_start", time.Since(execStart).String(),
			)
		} else {
			dbLogger.Infow(" Phase 1: Starting full discovery",
				"target", target,
				"discovery_timeout", e.config.DiscoveryTimeout.String(),
				"enable_dns", e.config.EnableDNS,
				"enable_subdomain_enum", e.config.EnableSubdomainEnum,
				"enable_cert_transparency", e.config.EnableCertTransparency,
				"elapsed_since_scan_start", time.Since(execStart).String(),
			)
		}

		tracker.StartPhase("discovery")

		// Run discovery in parallel for all targets
		allAssets := []*discovery.Asset{}
		var mu sync.Mutex
		var wg sync.WaitGroup

		// Track last successful session for display
		var lastSession *discovery.DiscoverySession

		for _, scanTarget := range targetsToScan {
			wg.Add(1)
			go func(t string) {
				defer wg.Done()
				targetAssets, targetSession, _ := e.executeDiscoveryPhase(ctx, t, tracker, dbLogger)
				mu.Lock()
				allAssets = append(allAssets, targetAssets...)
				if targetSession != nil {
					lastSession = targetSession // Store for display
				}
				mu.Unlock()
			}(scanTarget)
		}

		wg.Wait()
		assets = allAssets

		// Store session and assets in result for display
		if lastSession != nil {
			result.DiscoverySession = lastSession
		}
		// P0-2 FIX: Use thread-safe method to set assets
		result.SetDiscoveredAssets(assets)

		phaseResult = PhaseResult{
			Phase:     "discovery",
			Status:    "completed",
			StartTime: discoveryStart,
			EndTime:   time.Now(),
			Duration:  time.Since(discoveryStart),
			Findings:  len(assets),
		}

		discoveryDuration := time.Since(discoveryStart)
		dbLogger.Infow(" Discovery phase completed",
			"status", phaseResult.Status,
			"assets_discovered", len(assets),
			"discovery_duration", discoveryDuration.String(),
			"elapsed_since_scan_start", time.Since(execStart).String(),
		)

		// USER-FRIENDLY CLI DISPLAY
		if len(assets) > 0 {
			e.outputFormatter.DisplayDiscoveryResults(assets, discoveryDuration)
		}

		result.PhaseResults["discovery"] = phaseResult
		result.DiscoveredAt = len(assets)

		// Checkpoint after discovery
		updateProgress("discovery", 25.0, []string{"discovery"})
		saveCheckpoint("discovery", 25.0, []string{"discovery"}, []types.Finding{})

		if phaseResult.Status == "failed" {
			dbLogger.Errorw(" Discovery phase failed",
				"error", phaseResult.Error,
				"duration", discoveryDuration.String(),
			)
			tracker.FailPhase("discovery", fmt.Errorf("%s", phaseResult.Error))
			result.Status = "failed"
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime)
			return result, fmt.Errorf("discovery phase failed: %s", phaseResult.Error)
		}
		tracker.CompletePhase("discovery")
	}

	// Log context status after discovery
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		dbLogger.Infow(" Context status after discovery",
			"remaining_time", remaining.String(),
			"remaining_seconds", remaining.Seconds(),
			"elapsed_since_scan_start", time.Since(execStart).String(),
			"context_healthy", remaining > 0,
		)
		if remaining <= 0 {
			dbLogger.Errorw(" CRITICAL: Context already expired after discovery!",
				"expired_by", (-remaining).String(),
			)
		}
	}

	// Phase 2: Asset Prioritization
	prioritizationStart := time.Now()
	dbLogger.Infow(" Phase 2: Starting asset prioritization",
		"total_assets", len(assets),
		"elapsed_since_scan_start", time.Since(execStart).String(),
	)

	tracker.StartPhase("prioritization")
	prioritized := e.executePrioritizationPhase(assets, dbLogger)

	dbLogger.Infow(" Prioritization completed",
		"high_priority_assets", len(prioritized),
		"prioritization_duration", time.Since(prioritizationStart).String(),
		"elapsed_since_scan_start", time.Since(execStart).String(),
	)
	tracker.CompletePhase("prioritization")

	// Checkpoint after prioritization
	updateProgress("prioritization", 35.0, []string{"discovery", "prioritization"})
	saveCheckpoint("prioritization", 35.0, []string{"discovery", "prioritization"}, []types.Finding{})

	// Phase 2.5: Scope Validation (if enabled)
	if e.scopeValidator != nil && e.scopeValidator.IsEnabled() {
		validationResult := e.scopeValidator.FilterAssets(prioritized)

		// Update prioritized list to only include in-scope assets
		prioritized = validationResult.InScope

		if len(prioritized) == 0 {
			dbLogger.Warnw("No in-scope assets to test after scope validation",
				"component", "orchestrator",
			)
			fmt.Println("   ⚠️  No in-scope assets found - scan complete")
			fmt.Println()

			result.Status = "completed"
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime)
			return result, nil
		}
	}

	// Phase 3: Vulnerability Testing (parallel)
	testingStart := time.Now()

	// Log enabled scanners
	enabledScanners := []string{}
	if e.config.EnableAuthTesting {
		enabledScanners = append(enabledScanners, "auth")
	}
	if e.config.EnableServiceFingerprint && e.nmapScanner != nil {
		enabledScanners = append(enabledScanners, "nmap")
	}
	if e.config.EnableNucleiScan && e.nucleiScanner != nil {
		enabledScanners = append(enabledScanners, "nuclei")
	}
	if e.config.EnableGraphQLTesting && e.graphqlScanner != nil {
		enabledScanners = append(enabledScanners, "graphql")
	}
	if e.config.EnableSCIMTesting {
		enabledScanners = append(enabledScanners, "scim")
	}

	// IMMEDIATE CLI FEEDBACK - Show user what's happening
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println(" Phase 3: Vulnerability Testing")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("   Assets to test: %d\n", len(prioritized))
	fmt.Printf("   Enabled scanners: %s\n", strings.Join(enabledScanners, ", "))
	fmt.Printf("   Scan timeout: %s\n", e.config.ScanTimeout)
	fmt.Println()
	if e.config.EnableAuthTesting {
		fmt.Printf("   • Authentication testing (SAML, OAuth2, WebAuthn, JWT)...\n")
	}
	if e.config.EnableSCIMTesting {
		fmt.Printf("   • SCIM provisioning vulnerabilities...\n")
	}
	if e.config.EnableGraphQLTesting && e.graphqlScanner != nil {
		fmt.Printf("   • GraphQL introspection and injection...\n")
	}
	if e.config.EnableAPITesting {
		fmt.Printf("   • REST API security testing...\n")
	}
	if e.config.EnableIDORTesting {
		fmt.Printf("   • IDOR (Insecure Direct Object Reference) testing...\n")
	}
	if e.config.EnableServiceFingerprint && e.nmapScanner != nil {
		fmt.Printf("   • Nmap service fingerprinting...\n")
	}
	if e.config.EnableNucleiScan && e.nucleiScanner != nil {
		fmt.Printf("   • Nuclei CVE scanning...\n")
	}
	fmt.Println()

	dbLogger.Infow(" Phase 3: Starting vulnerability testing",
		"assets_to_test", len(prioritized),
		"enabled_scanners", enabledScanners,
		"scanner_count", len(enabledScanners),
		"scan_timeout", e.config.ScanTimeout.String(),
		"elapsed_since_scan_start", time.Since(execStart).String(),
	)

	// Check context status before testing
	select {
	case <-ctx.Done():
		dbLogger.Errorw(" CRITICAL: Context already cancelled before testing phase",
			"error", ctx.Err(),
			"elapsed_time", time.Since(execStart).String(),
		)
	default:
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			dbLogger.Infow(" Context valid before testing",
				"remaining_time", remaining.String(),
				"remaining_seconds", remaining.Seconds(),
				"elapsed_time", time.Since(execStart).String(),
			)
		}
	}

	tracker.StartPhase("testing")
	// Normal run: no tests to skip (empty slice)
	findings, phaseResults := e.executeTestingPhase(ctx, target, prioritized, tracker, dbLogger, []string{})

	testingDuration := time.Since(testingStart)
	dbLogger.Infow(" Testing phase completed",
		"total_findings", len(findings),
		"testing_duration", testingDuration.String(),
		"elapsed_since_scan_start", time.Since(execStart).String(),
	)

	for phase, pr := range phaseResults {
		result.PhaseResults[phase] = pr
	}
	result.Findings = append(result.Findings, findings...)
	result.TestedAssets = len(prioritized)
	tracker.CompletePhase("testing")

	// Checkpoint after testing (major phase)
	completedTestsList := []string{"discovery", "prioritization"}
	for testName := range phaseResults {
		completedTestsList = append(completedTestsList, testName)
	}
	updateProgress("testing", 85.0, completedTestsList)
	saveCheckpoint("testing", 85.0, completedTestsList, result.Findings)

	// Phase 4: Store results
	storageStart := time.Now()
	dbLogger.Infow(" Phase 4: Storing results to database",
		"scan_id", scanID,
		"findings_count", len(result.Findings),
		"elapsed_since_scan_start", time.Since(execStart).String(),
	)

	// Check context status before storage
	select {
	case <-ctx.Done():
		dbLogger.Errorw(" CRITICAL: Context already cancelled before storage phase",
			"error", ctx.Err(),
			"elapsed_time", time.Since(execStart).String(),
		)
	default:
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			dbLogger.Infow(" Context valid before storage",
				"remaining_time", remaining.String(),
				"remaining_seconds", remaining.Seconds(),
				"elapsed_time", time.Since(execStart).String(),
			)
		}
	}

	tracker.StartPhase("storage")
	if err := e.persistenceManager.SaveResults(ctx, scanID, result); err != nil {
		dbLogger.Errorw(" Failed to store results",
			"error", err,
			"scan_id", scanID,
			"storage_duration", time.Since(storageStart).String(),
			"elapsed_since_scan_start", time.Since(execStart).String(),
		)
		tracker.FailPhase("storage", err)
	} else {
		dbLogger.Infow(" Results stored successfully",
			"scan_id", scanID,
			"storage_duration", time.Since(storageStart).String(),
			"elapsed_since_scan_start", time.Since(execStart).String(),
		)
		tracker.CompletePhase("storage")
	}

	result.Status = "completed"
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.TotalFindings = len(result.Findings)

	// Show final summary
	tracker.Complete()

	// Count findings by severity for final report
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	infoCount := 0

	for _, finding := range result.Findings {
		switch strings.ToUpper(string(finding.Severity)) {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		default:
			infoCount++
		}
	}

	dbLogger.Infow(" Bug bounty scan completed successfully",
		"target", target,
		"scan_id", scanID,
		"total_findings", result.TotalFindings,
		"critical", criticalCount,
		"high", highCount,
		"medium", mediumCount,
		"low", lowCount,
		"info", infoCount,
		"assets_discovered", result.DiscoveredAt,
		"assets_tested", result.TestedAssets,
		"total_duration", result.Duration.String(),
		"scan_start", result.StartTime.Format(time.RFC3339),
		"scan_end", result.EndTime.Format(time.RFC3339),
		"phases_completed", "discovery,prioritization,testing,storage",
	)

	// USER-FRIENDLY CLI SUMMARY DISPLAY
	e.outputFormatter.DisplayScanSummary(result)

	return result, nil
}

// ResumeFromCheckpoint resumes a scan from a saved checkpoint
// This method loads the checkpoint state and continues execution from where it left off,
// skipping completed phases and preserving all findings collected so far.
func (e *BugBountyEngine) ResumeFromCheckpoint(ctx context.Context, state *checkpoint.State) (*BugBountyResult, error) {
	execStart := time.Now()

	// Use checkpoint scan ID
	scanID := state.ScanID
	target := state.Target

	// Wrap logger with database event logger
	dbLogger := logger.NewDBEventLogger(e.logger, e.store, scanID)

	dbLogger.Infow("Resuming scan from checkpoint",
		"scan_id", scanID,
		"target", target,
		"progress", state.Progress,
		"current_phase", state.CurrentPhase,
		"completed_tests", state.CompletedTests,
		"findings_so_far", len(state.Findings),
		"assets_discovered", len(state.DiscoveredAssets),
	)

	// Initialize progress tracker
	tracker := progress.New(e.config.ShowProgress, dbLogger.Logger)
	tracker.AddPhase("discovery", "Discovering assets")
	tracker.AddPhase("prioritization", "Prioritizing targets")
	tracker.AddPhase("testing", "Testing for vulnerabilities")
	tracker.AddPhase("storage", "Storing results")

	// Rebuild result from checkpoint
	result := &BugBountyResult{
		ScanID:           scanID,
		Target:           target,
		StartTime:        state.CreatedAt, // Original start time
		Status:           "running",
		PhaseResults:     make(map[string]PhaseResult),
		Findings:         state.Findings, // Preserve existing findings
		DiscoveredAssets: checkpoint.ConvertToDiscoveryAssets(state.DiscoveredAssets),
	}

	// P0-6 FIX: Calculate timeout based on work remaining, not elapsed time
	// The old logic gave all resumed scans only 5 minutes if they were interrupted >30min ago.
	// Instead, we estimate remaining work from progress percentage and allocate proportional time.

	workCompleted := state.Progress / 100.0
	workRemaining := 1.0 - workCompleted

	// Estimate time needed = (total timeout) * (fraction of work remaining)
	estimatedTimeNeeded := time.Duration(float64(e.config.TotalTimeout) * workRemaining)

	// Apply reasonable bounds:
	// - Minimum 5 minutes (even if 99% complete, give time for cleanup)
	// - Maximum is the original total timeout (don't exceed configured limit)
	remainingTimeout := estimatedTimeNeeded
	if remainingTimeout < 5*time.Minute {
		remainingTimeout = 5 * time.Minute
	}
	if remainingTimeout > e.config.TotalTimeout {
		remainingTimeout = e.config.TotalTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, remainingTimeout)
	defer cancel()

	dbLogger.Infow("Resume context configured",
		"progress_completed_pct", state.Progress,
		"work_remaining_pct", workRemaining*100,
		"estimated_time_needed", estimatedTimeNeeded,
		"remaining_timeout_granted", remainingTimeout,
		"original_timeout", e.config.TotalTimeout,
		"elapsed_since_start", time.Since(state.CreatedAt),
	)

	// Declare all variables upfront to avoid goto issues
	var assets []*discovery.Asset
	var session *discovery.DiscoverySession
	var discoveryPhaseResult PhaseResult
	var prioritizedAssets []*scanners.AssetPriority
	var newFindings []types.Finding
	var phaseResults map[string]PhaseResult

	// Determine where to resume from based on current phase
	switch state.CurrentPhase {
	case "initialized", "footprinting":
		// Start from discovery
		dbLogger.Infow("Resuming from discovery phase (checkpoint was early)")
		goto discoveryPhase

	case "discovery", "prioritization":
		// Discovery complete, start testing
		dbLogger.Infow("Skipping discovery phase (already completed)",
			"assets_discovered", len(result.DiscoveredAssets),
		)
		tracker.CompletePhase("discovery")
		tracker.CompletePhase("prioritization")
		goto testingPhase

	case "testing":
		// P0-18 FIX: goto testingPhase (not continueTesting which is empty and falls through)
		// Testing in progress, continue from completed tests
		dbLogger.Infow("Resuming testing phase",
			"completed_tests", state.CompletedTests,
			"findings_so_far", len(result.Findings),
		)
		tracker.CompletePhase("discovery")
		tracker.CompletePhase("prioritization")
		goto testingPhase

	case "storage":
		// Nearly complete, just save and finish
		dbLogger.Infow("Resuming storage phase (scan nearly complete)")
		tracker.CompletePhase("discovery")
		tracker.CompletePhase("prioritization")
		tracker.CompletePhase("testing")
		goto storagePhase

	default:
		dbLogger.Warnw("Unknown checkpoint phase, starting from beginning",
			"phase", state.CurrentPhase,
		)
		goto discoveryPhase
	}

discoveryPhase:
	// Run full discovery if not completed
	tracker.StartPhase("discovery")

	if e.config.SkipDiscovery {
		// Quick mode: use target directly
		normalizedTarget := target
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			normalizedTarget = "https://" + target
		}
		assets = []*discovery.Asset{
			{Type: discovery.AssetTypeURL, Value: normalizedTarget, Priority: 100},
		}
		discoveryPhaseResult = PhaseResult{
			Phase:    "discovery",
			Status:   "skipped",
			Duration: 0,
		}
	} else {
		assets, session, discoveryPhaseResult = e.executeDiscoveryPhase(ctx, target, tracker, dbLogger)
		result.DiscoverySession = session
	}

	// P0-2 FIX: Use thread-safe methods
	result.SetDiscoveredAssets(assets)
	result.SetPhaseResult("discovery", discoveryPhaseResult)
	tracker.CompletePhase("discovery")

testingPhase:
	// Run vulnerability testing
	tracker.StartPhase("testing")

	// Prioritize assets for testing
	prioritizedAssets = e.executePrioritizationPhase(result.DiscoveredAssets, dbLogger)

	// P0-24 FIX: Removed dead code (completedTests map was built but never used)
	// P0-7 FIX: Pass state.CompletedTests to skip already-run tests on resume
	// Run testing on all assets (use existing testing phase but skip completed tests)
	newFindings, phaseResults = e.executeTestingPhase(ctx, target, prioritizedAssets, tracker, dbLogger, state.CompletedTests)
	// P0-19/20 FIX: Use thread-safe methods
	result.AddFindings(newFindings)
	for phase, pr := range phaseResults {
		result.SetPhaseResult(phase, pr)
	}

	tracker.CompletePhase("testing")

storagePhase:
	// Save all findings to database
	tracker.StartPhase("storage")

	// Set scan ID for all findings
	for i := range result.Findings {
		result.Findings[i].ScanID = scanID
	}

	// Save all findings at once
	if err := e.store.SaveFindings(ctx, result.Findings); err != nil {
		dbLogger.Errorw("Failed to save findings", "error", err, "count", len(result.Findings))
	}

	tracker.CompletePhase("storage")

	// Update scan record with final status
	result.Status = "completed"
	result.Duration = time.Since(execStart)
	result.EndTime = time.Now()
	result.TestedAssets = len(result.DiscoveredAssets)
	result.TotalFindings = len(result.Findings)

	// Save final scan record
	finalScan := &types.ScanRequest{
		ID:          scanID,
		Target:      target,
		Type:        types.ScanTypeAuth,
		Status:      types.ScanStatusCompleted,
		CreatedAt:   state.CreatedAt,
		CompletedAt: &result.EndTime,
	}
	if err := e.store.SaveScan(ctx, finalScan); err != nil {
		dbLogger.Warnw("Failed to save final scan record", "error", err)
	}

	dbLogger.Infow("Scan resumed and completed successfully",
		"scan_id", scanID,
		"total_duration", result.Duration,
		"total_findings", result.TotalFindings,
		"tested_assets", result.TestedAssets,
	)

	return result, nil
}

// executeDiscoveryPhase runs asset discovery with timeout
func (e *BugBountyEngine) executeDiscoveryPhase(ctx context.Context, target string, tracker *progress.Tracker, dbLogger *logger.DBEventLogger) ([]*discovery.Asset, *discovery.DiscoverySession, PhaseResult) {
	phaseStart := time.Now()
	phase := PhaseResult{
		Phase:     "discovery",
		Status:    "running",
		StartTime: phaseStart,
	}

	// Log parent context status
	if deadline, ok := ctx.Deadline(); ok {
		dbLogger.Infow(" Parent context status before discovery phase",
			"target", target,
			"parent_deadline", deadline.Format(time.RFC3339),
			"time_until_parent_deadline", time.Until(deadline).String(),
			"parent_deadline_seconds", time.Until(deadline).Seconds(),
		)
	} else {
		dbLogger.Warnw("  No parent context deadline - unexpected!",
			"target", target,
		)
	}

	// IMMEDIATE CLI FEEDBACK - Show user what's happening
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println(" Phase 1: Asset Discovery")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("   Target: %s\n", target)
	if e.config.EnableDNS {
		fmt.Printf("   • Subdomain enumeration (DNS, certs, search engines)...\n")
	}
	if e.config.EnablePortScan {
		fmt.Printf("   • Port scanning for exposed services...\n")
	}
	if e.config.EnableWebCrawl {
		fmt.Printf("   • Web crawling for endpoints and APIs...\n")
	}
	fmt.Printf("   • Timeout: %s\n", e.config.DiscoveryTimeout)
	fmt.Println()

	dbLogger.Infow(" Phase 1: Starting Asset Discovery",
		"target", target,
		"discovery_timeout", e.config.DiscoveryTimeout.String(),
	)
	tracker.UpdateProgress("discovery", 10)

	// Start discovery session (passing context for timeout propagation)
	sessionStart := time.Now()
	session, err := e.discoveryEngine.StartDiscovery(ctx, target)
	if err != nil {
		phase.Status = "failed"
		phase.Error = fmt.Sprintf("failed to start discovery: %v", err)
		phase.EndTime = time.Now()
		phase.Duration = phase.EndTime.Sub(phase.StartTime)
		dbLogger.Errorw(" Discovery failed to start",
			"error", err,
			"target", target,
			"elapsed_time", time.Since(phaseStart).String(),
		)
		return nil, nil, phase
	}

	dbLogger.Infow(" Discovery session started",
		"target", target,
		"session_id", session.ID,
		"session_start_duration", time.Since(sessionStart).String(),
	)

	// Create discovery timeout context from PARENT context
	discoveryCtx, discoveryCancel := context.WithTimeout(ctx, e.config.DiscoveryTimeout)
	defer discoveryCancel()

	// Log discovery context deadline
	if deadline, ok := discoveryCtx.Deadline(); ok {
		parentDeadline, hasParent := ctx.Deadline()
		dbLogger.Infow(" Discovery context created FROM PARENT",
			"target", target,
			"session_id", session.ID,
			"discovery_deadline", deadline.Format(time.RFC3339),
			"discovery_timeout", e.config.DiscoveryTimeout.String(),
			"time_until_discovery_deadline", time.Until(deadline).String(),
			"has_parent_deadline", hasParent,
			"parent_deadline", func() string {
				if hasParent {
					return parentDeadline.Format(time.RFC3339)
				}
				return "NONE"
			}(),
		)
	}

	// Wait for discovery to complete or timeout
	discoveryComplete := make(chan bool, 1)
	go func() {
		progress := 20
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				currentSession, err := e.discoveryEngine.GetSession(session.ID)
				if err != nil || currentSession == nil {
					select {
					case discoveryComplete <- false:
					default:
					}
					return
				}

				// Update progress incrementally
				if progress < 90 {
					progress += 5
					tracker.UpdateProgress("discovery", progress)
				}

				if currentSession.Status == discovery.StatusCompleted || currentSession.Status == discovery.StatusFailed {
					select {
					case discoveryComplete <- true:
					default:
					}
					return
				}
			case <-discoveryCtx.Done():
				// Discovery timeout
				select {
				case discoveryComplete <- false:
				default:
				}
				return
			}
		}
	}()

	// Wait for completion or timeout
	select {
	case success := <-discoveryComplete:
		if success {
			// Discovery completed
			tracker.UpdateProgress("discovery", 95)
			session, err = e.discoveryEngine.GetSession(session.ID)
			if err != nil {
				dbLogger.Warnw("Failed to get session after completion, using partial results", "error", err)
			}
		} else {
			dbLogger.Warnw("Discovery failed or stopped, using partial results")
			session, _ = e.discoveryEngine.GetSession(session.ID)
		}
	case <-discoveryCtx.Done():
		// Discovery timeout
		dbLogger.Warnw("Discovery timed out, using partial results", "timeout", e.config.DiscoveryTimeout)
		session, _ = e.discoveryEngine.GetSession(session.ID)
	}

	// Get discovered assets from session
	var assets []*discovery.Asset
	if session != nil {
		// Convert map to slice
		for _, asset := range session.Assets {
			assets = append(assets, asset)
		}
	}

	// If no assets discovered, create one from the target
	if len(assets) == 0 {
		dbLogger.Warnw("No assets discovered, using target as single asset", "target", target)
		assets = []*discovery.Asset{
			{
				Type:  discovery.AssetTypeURL,
				Value: target,
			},
		}
	}

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(phase.StartTime)
	phase.Status = "completed"
	dbLogger.Infow("Discovery completed", "assets", len(assets), "duration", phase.Duration)

	return assets, session, phase
}

// AssetPriority represents a prioritized asset for testing

// executePrioritizationPhase prioritizes assets for testing
func (e *BugBountyEngine) executePrioritizationPhase(assets []*discovery.Asset, dbLogger *logger.DBEventLogger) []*scanners.AssetPriority {
	dbLogger.Infow("Phase 2: Asset Prioritization", "assets", len(assets))

	var prioritized []*scanners.AssetPriority

	for _, asset := range assets {
		priority := &scanners.AssetPriority{
			Asset:    asset,
			Priority:    0,
			Features: e.analyzeAssetFeatures(asset),
		}

		// Score based on features
		if priority.Features.HasAuthentication {
			priority.Priority += 100
		}
		if priority.Features.HasAPIEndpoints {
			priority.Priority += 90
		}
		if priority.Features.HasAdminPanel {
			priority.Priority += 85
		}
		if priority.Features.HasPaymentFlow {
			priority.Priority += 85
		}
		if priority.Features.HasSCIMEndpoint {
			priority.Priority += 95 // SCIM is high value
		}
		if priority.Features.HasFileUpload {
			priority.Priority += 75
		}
		if priority.Features.HasFileUpload {
			priority.Priority += 70
		}

		prioritized = append(prioritized, priority)
	}

	// Sort by score (highest first) - critical for targeting high-value endpoints
	sort.Slice(prioritized, func(i, j int) bool {
		return prioritized[i].Priority > prioritized[j].Priority
	})

	// Log top priorities for visibility
	topCount := min(5, len(prioritized))
	dbLogger.Infow("Asset prioritization completed",
		"total_assets", len(prioritized),
		"top_priorities", topCount,
	)

	for i := 0; i < topCount; i++ {
		p := prioritized[i]
		dbLogger.Debugw("High priority target",
			"rank", i+1,
			"score", p.Priority,
			"url", p.Asset.Value,
			"auth", p.Features.HasAuthentication,
			"api", p.Features.HasAPIEndpoints,
			"admin", p.Features.HasAdminPanel,
			"scim", p.Features.HasSCIMEndpoint,
		)
	}

	return prioritized
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// analyzeAssetFeatures analyzes an asset to identify important features
func (e *BugBountyEngine) analyzeAssetFeatures(asset *discovery.Asset) scanners.AssetFeatures {
	features := scanners.AssetFeatures{}

	value := strings.ToLower(asset.Value)

	// Authentication endpoints - highest priority
	authPatterns := []string{
		"login", "signin", "sign-in", "auth", "authenticate",
		"sso", "oauth", "saml", "oidc", "openid",
		"session", "token", "jwt", "webauthn", "fido",
	}
	if containsAny(value, authPatterns) {
		features.HasAuthentication = true
	}

	// API endpoints - very high value
	apiPatterns := []string{
		"/api/", "/v1/", "/v2/", "/v3/",
		"/graphql", "/rest", "/swagger", "/openapi",
		"api.", "/endpoints", "/.well-known",
	}
	if containsAny(value, apiPatterns) {
		features.HasAPIEndpoints = true
	}

	// SCIM endpoints - critical for enterprise targets
	scimPatterns := []string{
		"/scim/", "/scim/v2/", "/scim2/",
		"/provisioning", "/identity/scim",
	}
	if containsAny(value, scimPatterns) {
		features.HasSCIMEndpoint = true
	}

	// Admin/privileged endpoints
	adminPatterns := []string{
		"admin", "administrator", "dashboard", "panel",
		"management", "console", "control", "config",
	}
	if containsAny(value, adminPatterns) {
		features.HasAdminPanel = true
	}

	// Payment/financial endpoints
	paymentPatterns := []string{
		"payment", "checkout", "billing", "invoice",
		"pay", "subscription", "pricing", "stripe",
		"paypal", "credit", "card",
	}
	if containsAny(value, paymentPatterns) {
		features.HasPaymentFlow = true
	}

	// File upload endpoints - common vuln vector
	uploadPatterns := []string{
		"upload", "file", "attachment", "media",
		"image", "document", "import",
	}
	if containsAny(value, uploadPatterns) {
		features.HasFileUpload = true
	}

	// User data endpoints
	userDataPatterns := []string{
		"user", "profile", "account", "settings",
		"preferences", "personal", "data",
	}
	if containsAny(value, userDataPatterns) {
		features.HasFileUpload = true
	}

	return features
}

// executeTestingPhase runs all vulnerability tests in parallel
// P0-7 FIX: Add skipTests parameter to avoid re-running completed tests on resume
func (e *BugBountyEngine) executeTestingPhase(ctx context.Context, target string, assets []*scanners.AssetPriority, tracker *progress.Tracker, dbLogger *logger.DBEventLogger, skipTests []string) ([]types.Finding, map[string]PhaseResult) {
	// Helper to check if test should be skipped
	shouldSkip := func(testName string) bool {
		for _, skip := range skipTests {
			if skip == testName {
				dbLogger.Infow("Skipping already-completed test",
					"test", testName,
					"component", "orchestrator",
				)
				return true
			}
		}
		return false
	}

	dbLogger.Infow(" Phase 3: Starting vulnerability testing",
		"assets", len(assets),
		"skipping_tests", skipTests,
		"component", "orchestrator",
	)

	phaseResults := make(map[string]PhaseResult)
	allFindings := []types.Finding{}
	var mu sync.Mutex

	// Track test progress
	totalTests := 0
	completedTests := 0
	if e.config.EnableAuthTesting {
		totalTests++
	}
	if e.config.EnableSCIMTesting {
		totalTests++
	}
	if e.config.EnableAPITesting {
		totalTests++
	}
	if e.config.EnableServiceFingerprint && e.nmapScanner != nil {
		totalTests++
	}
	if e.config.EnableNucleiScan && e.nucleiScanner != nil {
		totalTests++
	}
	if e.config.EnableGraphQLTesting && e.graphqlScanner != nil {
		totalTests++
	}
	if e.config.EnableIDORTesting && e.idorScanner != nil {
		totalTests++
	}

	updateTestProgress := func() {
		mu.Lock()
		defer mu.Unlock()
		completedTests++
		progress := (completedTests * 100) / totalTests
		tracker.UpdateProgress("testing", progress)
	}

	// Run tests in parallel
	var wg sync.WaitGroup

	// Authentication Testing
	if e.config.EnableAuthTesting && !shouldSkip("auth") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, result := e.runAuthenticationTests(ctx, target, assets, dbLogger)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			phaseResults["auth"] = result
			mu.Unlock()
			updateTestProgress()
		}()
	} else if shouldSkip("auth") {
		updateTestProgress() // Count as completed
	}

	// SCIM Testing
	if e.config.EnableSCIMTesting && !shouldSkip("scim") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, result := e.runSCIMTests(ctx, assets, dbLogger)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			phaseResults["scim"] = result
			mu.Unlock()
			updateTestProgress()
		}()
	} else if shouldSkip("scim") {
		updateTestProgress()
	}

	// API Testing
	if e.config.EnableAPITesting && !shouldSkip("api") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, result := e.runAPITests(ctx, assets, dbLogger)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			phaseResults["api"] = result
			mu.Unlock()
			updateTestProgress()
		}()
	} else if shouldSkip("api") {
		updateTestProgress()
	}

	// Nmap Service Fingerprinting
	if e.config.EnableServiceFingerprint && e.nmapScanner != nil && !shouldSkip("nmap") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, result := e.runNmapScans(ctx, assets, dbLogger)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			phaseResults["nmap"] = result
			mu.Unlock()
			updateTestProgress()
		}()
	} else if shouldSkip("nmap") {
		updateTestProgress()
	}

	// Nuclei Vulnerability Scanning
	if e.config.EnableNucleiScan && e.nucleiScanner != nil && !shouldSkip("nuclei") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, result := e.runNucleiScans(ctx, assets, dbLogger)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			phaseResults["nuclei"] = result
			mu.Unlock()
			updateTestProgress()
		}()
	} else if shouldSkip("nuclei") {
		updateTestProgress()
	}

	// GraphQL Testing (Go scanner + optional Python GraphCrawler)
	if e.config.EnableGraphQLTesting && e.graphqlScanner != nil && !shouldSkip("graphql") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, result := e.runGraphQLTests(ctx, assets, dbLogger)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			phaseResults["graphql"] = result
			mu.Unlock()
			updateTestProgress()
		}()
	} else if shouldSkip("graphql") {
		updateTestProgress()
	}

	// IDOR Testing (Go scanner)
	if e.config.EnableIDORTesting && e.idorScanner != nil && !shouldSkip("idor") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, result := e.runIDORTests(ctx, assets, dbLogger)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			phaseResults["idor"] = result
			mu.Unlock()
			updateTestProgress()
		}()
	} else if shouldSkip("idor") {
		updateTestProgress()
	}

	// Wait for all tests to complete
	wg.Wait()

	return allFindings, phaseResults
}

// GetRateLimiter returns the rate limiter for use by scanners
// Scanners should call rateLimiter.Wait(ctx) before making HTTP requests
func (e *BugBountyEngine) GetRateLimiter() *ratelimit.Limiter {
	return e.rateLimiter
}


// ExecuteWithPipeline runs the bug bounty scan using the Kill Chain aligned pipeline
//
// ADVERSARIAL REVIEW: P0 FIX #3 - Feedback Loop Implementation
// - This is the NEW execution path that uses the Kill Chain aligned pipeline
// - Replaces the old Execute() method's chaotic scanning
// - Implements iterative reconnaissance (findings → new assets → re-scan)
// - Clear phase boundaries with checkpointing
//
// USAGE:
//
//	Old way: engine.Execute(ctx, target) // Chaotic, no clear phases
//	New way: engine.ExecuteWithPipeline(ctx, target) // Kill Chain aligned, iterative
//
// MIGRATION PATH:
//  1. Update cmd/root.go to call ExecuteWithPipeline instead of Execute
//  2. Test with: shells example.com --use-pipeline
//  3. Once stable, make ExecuteWithPipeline the default
//  4. Deprecate old Execute() method
func (e *BugBountyEngine) ExecuteWithPipeline(ctx context.Context, target string) (*PipelineResult, error) {
	e.logger.Infow("Starting Kill Chain aligned pipeline execution",
		"target", target,
		"total_timeout", e.config.TotalTimeout.String(),
	)

	// Apply total timeout to context
	ctx, cancel := context.WithTimeout(ctx, e.config.TotalTimeout)
	defer cancel()

	// Create pipeline with all necessary engines
	pipeline, err := NewPipeline(
		target,
		e.config,
		e.logger,
		e.store,
		e.discoveryEngine,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create pipeline: %w", err)
	}

	// Initialize phase engines
	pipeline.weaponizationEngine = NewWeaponizationEngine(e.config, e.logger)
	pipeline.exploitationEngine = NewExploitationEngine(e.config, e.logger)

	// Initialize correlation engine with existing correlator and enricher
	var exploitChainer *correlation.ExploitChainer
	if e.config.EnableEnrichment {
		// Create vulnerability correlator (was unused before P1 FIX #6)
		exploitChainer = correlation.NewExploitChainer()
	}

	pipeline.correlationEngine = NewCorrelationEngine(
		e.config,
		e.logger,
		exploitChainer,
		e.enricher,
	)

	// Execute pipeline (includes feedback loop)
	result, err := pipeline.Execute(ctx)
	if err != nil {
		return nil, fmt.Errorf("pipeline execution failed: %w", err)
	}

	e.logger.Infow("Pipeline execution completed successfully",
		"scan_id", result.ScanID,
		"duration", result.Duration.String(),
		"iterations", result.Iterations,
		"total_findings", result.TotalFindings,
		"exploit_chains", result.ExploitChains,
	)

	return result, nil
}

// DEPRECATED STUB METHODS: These delegate to scannerManager for backward compatibility
// TODO: Refactor executeTestingPhase to use scannerManager directly

func (e *BugBountyEngine) runAuthenticationTests(ctx context.Context, target string, assets []*scanners.AssetPriority, dbLogger *logger.DBEventLogger) ([]types.Finding, PhaseResult) {
	phaseStart := time.Now()
	scanner, _ := e.scannerManager.Get("authentication")
	if scanner == nil {
		return []types.Finding{}, PhaseResult{Phase: "auth", Status: "skipped", StartTime: phaseStart, EndTime: time.Now()}
	}
	findings, err := scanner.Execute(ctx, assets)
	status := "completed"
	errMsg := ""
	if err != nil {
		status = "failed"
		errMsg = err.Error()
	}
	return findings, PhaseResult{
		Phase:     "auth",
		Status:    status,
		Error:     errMsg,
		Findings:  len(findings),
		StartTime: phaseStart,
		EndTime:   time.Now(),
		Duration:  time.Since(phaseStart),
	}
}

func (e *BugBountyEngine) runSCIMTests(ctx context.Context, assets []*scanners.AssetPriority, dbLogger *logger.DBEventLogger) ([]types.Finding, PhaseResult) {
	phaseStart := time.Now()
	scanner, _ := e.scannerManager.Get("scim")
	if scanner == nil {
		return []types.Finding{}, PhaseResult{Phase: "scim", Status: "skipped", StartTime: phaseStart, EndTime: time.Now()}
	}
	findings, err := scanner.Execute(ctx, assets)
	status := "completed"
	errMsg := ""
	if err != nil {
		status = "failed"
		errMsg = err.Error()
	}
	return findings, PhaseResult{
		Phase:     "scim",
		Status:    status,
		Error:     errMsg,
		Findings:  len(findings),
		StartTime: phaseStart,
		EndTime:   time.Now(),
		Duration:  time.Since(phaseStart),
	}
}

func (e *BugBountyEngine) runAPITests(ctx context.Context, assets []*scanners.AssetPriority, dbLogger *logger.DBEventLogger) ([]types.Finding, PhaseResult) {
	phaseStart := time.Now()
	scanner, _ := e.scannerManager.Get("api")
	if scanner == nil {
		return []types.Finding{}, PhaseResult{Phase: "api", Status: "skipped", StartTime: phaseStart, EndTime: time.Now()}
	}
	findings, err := scanner.Execute(ctx, assets)
	status := "completed"
	errMsg := ""
	if err != nil {
		status = "failed"
		errMsg = err.Error()
	}
	return findings, PhaseResult{
		Phase:     "api",
		Status:    status,
		Error:     errMsg,
		Findings:  len(findings),
		StartTime: phaseStart,
		EndTime:   time.Now(),
		Duration:  time.Since(phaseStart),
	}
}

func (e *BugBountyEngine) runNmapScans(ctx context.Context, assets []*scanners.AssetPriority, dbLogger *logger.DBEventLogger) ([]types.Finding, PhaseResult) {
	phaseStart := time.Now()
	scanner, _ := e.scannerManager.Get("nmap")
	if scanner == nil {
		return []types.Finding{}, PhaseResult{Phase: "nmap", Status: "skipped", StartTime: phaseStart, EndTime: time.Now()}
	}
	findings, err := scanner.Execute(ctx, assets)
	status := "completed"
	errMsg := ""
	if err != nil {
		status = "failed"
		errMsg = err.Error()
	}
	return findings, PhaseResult{
		Phase:     "nmap",
		Status:    status,
		Error:     errMsg,
		Findings:  len(findings),
		StartTime: phaseStart,
		EndTime:   time.Now(),
		Duration:  time.Since(phaseStart),
	}
}

func (e *BugBountyEngine) runNucleiScans(ctx context.Context, assets []*scanners.AssetPriority, dbLogger *logger.DBEventLogger) ([]types.Finding, PhaseResult) {
	phaseStart := time.Now()
	scanner, _ := e.scannerManager.Get("nuclei")
	if scanner == nil {
		return []types.Finding{}, PhaseResult{Phase: "nuclei", Status: "skipped", StartTime: phaseStart, EndTime: time.Now()}
	}
	findings, err := scanner.Execute(ctx, assets)
	status := "completed"
	errMsg := ""
	if err != nil {
		status = "failed"
		errMsg = err.Error()
	}
	return findings, PhaseResult{
		Phase:     "nuclei",
		Status:    status,
		Error:     errMsg,
		Findings:  len(findings),
		StartTime: phaseStart,
		EndTime:   time.Now(),
		Duration:  time.Since(phaseStart),
	}
}

func (e *BugBountyEngine) runGraphQLTests(ctx context.Context, assets []*scanners.AssetPriority, dbLogger *logger.DBEventLogger) ([]types.Finding, PhaseResult) {
	phaseStart := time.Now()
	scanner, _ := e.scannerManager.Get("graphql")
	if scanner == nil {
		return []types.Finding{}, PhaseResult{Phase: "graphql", Status: "skipped", StartTime: phaseStart, EndTime: time.Now()}
	}
	findings, err := scanner.Execute(ctx, assets)
	status := "completed"
	errMsg := ""
	if err != nil {
		status = "failed"
		errMsg = err.Error()
	}
	return findings, PhaseResult{
		Phase:     "graphql",
		Status:    status,
		Error:     errMsg,
		Findings:  len(findings),
		StartTime: phaseStart,
		EndTime:   time.Now(),
		Duration:  time.Since(phaseStart),
	}
}

func (e *BugBountyEngine) runIDORTests(ctx context.Context, assets []*scanners.AssetPriority, dbLogger *logger.DBEventLogger) ([]types.Finding, PhaseResult) {
	phaseStart := time.Now()
	scanner, _ := e.scannerManager.Get("idor")
	if scanner == nil {
		return []types.Finding{}, PhaseResult{Phase: "idor", Status: "skipped", StartTime: phaseStart, EndTime: time.Now()}
	}
	findings, err := scanner.Execute(ctx, assets)
	status := "completed"
	errMsg := ""
	if err != nil {
		status = "failed"
		errMsg = err.Error()
	}
	return findings, PhaseResult{
		Phase:     "idor",
		Status:    status,
		Error:     errMsg,
		Findings:  len(findings),
		StartTime: phaseStart,
		EndTime:   time.Now(),
		Duration:  time.Since(phaseStart),
	}
}
