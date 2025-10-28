// internal/orchestrator/bounty_engine.go
package orchestrator

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	configpkg "github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/internal/plugins/api"
	"github.com/CodeMonkeyCybersecurity/shells/internal/plugins/nmap"
	"github.com/CodeMonkeyCybersecurity/shells/internal/plugins/nuclei"
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
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scanners/idor"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scanners/restapi"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scim"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scope"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/workers"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// BugBountyEngine orchestrates the full bug bounty scanning pipeline
type BugBountyEngine struct {
	// Core services
	store       core.ResultStore
	telemetry   core.Telemetry
	logger      *logger.Logger
	rateLimiter *ratelimit.Limiter

	// Discovery
	discoveryEngine     *discovery.Engine
	orgCorrelator       *correlation.OrganizationCorrelator
	certIntel           *certs.CertIntel
	scopeManager        *scope.Manager // Bug bounty program scope management

	// Scanners
	samlScanner     *saml.SAMLScanner
	oauth2Scanner   *oauth2.OAuth2Scanner
	webauthnScanner *webauthn.WebAuthnScanner
	scimScanner     core.Scanner
	authDiscovery   *auth.AuthDiscoveryEngine

	// Additional scanners
	nmapScanner    core.Scanner // Nmap port scanning and service fingerprinting
	nucleiScanner  core.Scanner // Nuclei vulnerability scanning
	graphqlScanner core.Scanner // GraphQL introspection and testing
	idorScanner    core.Scanner // IDOR (Insecure Direct Object Reference) testing
	restapiScanner core.Scanner // REST API vulnerability scanning

	// Python worker client (optional - for GraphCrawler)
	pythonWorkers *workers.Client

	// Enrichment (TASK 14: Add result enrichment)
	enricher *enrichment.ResultEnricher

	// Checkpointing
	checkpointEnabled  bool
	checkpointInterval time.Duration
	checkpointManager  CheckpointManager

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
		EnableEnrichment: true,          // Enrich findings with CVSS, exploits, remediation
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
func NewBugBountyEngine(
	store core.ResultStore,
	telemetry core.Telemetry,
	logger *logger.Logger,
	config BugBountyConfig,
) (*BugBountyEngine, error) {
	// Initialize SAML scanner with proper logger adapter
	samlLogger := &loggerAdapter{logger: logger}
	samlScanner := saml.NewSAMLScanner(samlLogger)

	// Initialize OAuth2 scanner
	oauth2Scanner := oauth2.NewOAuth2Scanner(samlLogger)

	// Initialize WebAuthn scanner
	webauthnScanner := webauthn.NewWebAuthnScanner(samlLogger)

	// Initialize SCIM scanner (implements core.Scanner interface)
	var scimScanner core.Scanner = scim.NewScanner()

	// Initialize Nmap scanner for service fingerprinting (if enabled)
	var nmapScanner core.Scanner
	if config.EnableServiceFingerprint {
		nmapCfg := configpkg.NmapConfig{
			BinaryPath: "nmap", // Use system nmap
			Timeout:    2 * time.Minute,
			Profiles: map[string]string{
				"default": "-sV --version-intensity 2 -T4", // Quick service detection
				"quick":   "-sV --version-intensity 2 -T4",
				"full":    "-sV --version-all -T4",
			},
		}
		nmapScanner = nmap.NewScanner(nmapCfg, samlLogger)
		logger.Infow("Nmap scanner initialized", "component", "orchestrator")
	}

	// Initialize Nuclei scanner (if enabled and binary exists)
	var nucleiScanner core.Scanner
	if config.EnableNucleiScan {
		// Check if nuclei binary is available
		nucleiBinaryPath := "nuclei"
		if _, err := exec.LookPath(nucleiBinaryPath); err != nil {
			logger.Warnw("Nuclei scanner disabled - binary not found in PATH",
				"error", err,
				"binary", nucleiBinaryPath,
				"install_instructions", "Run: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
				"component", "orchestrator",
			)
		} else {
			nucleiConfig := nuclei.NucleiConfig{
				BinaryPath:    nucleiBinaryPath,
				TemplatesPath: "", // Use default
				Timeout:       config.ScanTimeout,
				RateLimit:     int(config.RateLimitPerSecond),
				BulkSize:      25,
				Concurrency:   25,
				Retries:       2,
			}
			nucleiScanner = nuclei.NewScanner(nucleiConfig, samlLogger)
			logger.Infow("Nuclei scanner initialized",
				"binary_path", nucleiBinaryPath,
				"component", "orchestrator",
			)
		}
	}

	// Initialize GraphQL scanner (if enabled)
	var graphqlScanner core.Scanner
	if config.EnableGraphQLTesting {
		graphqlScanner = api.NewGraphQLScanner(samlLogger)
		logger.Infow("GraphQL scanner initialized", "component", "orchestrator")
	}

	// Initialize IDOR scanner (if enabled)
	// TASK 6 COMPLETED: Go-based IDOR scanner fully integrated with adapter pattern
	// - IDORScannerAdapter bridges idor.IDORScanner to core.Scanner interface
	// - Scanner tests sequential IDs, UUIDs, horizontal privilege escalation
	// - Wired into executeTestingPhase() and runIDORTests()
	// - Results displayed in displayTestCoverage() under Access Control Testing
	var idorScanner core.Scanner
	if config.EnableIDORTesting {
		idorConfig := idor.IDORConfig{
			MaxSequentialRange:    1000,  // Test up to 1000 sequential IDs
			ParallelWorkers:       10,    // 10 parallel workers
			Timeout:               config.ScanTimeout,
			RateLimit:             int(config.RateLimitPerSecond),
			EnableSequentialID:    true,  // Test sequential IDs
			EnableUUIDAnalysis:    true,  // Test UUID patterns
			EnableHorizontalTest:  true,  // Test horizontal privilege escalation
			EnableVerticalTest:    false, // Vertical requires admin creds
			EnablePatternLearning: true,  // Learn ID patterns
			SmartRangeDetection:   true,  // Auto-detect valid ranges
			SmartStopOnConsecutive: 50,   // Stop after 50 consecutive 404s
			StatusCodeFilters:     []int{200, 201, 202, 204},
			MinResponseSize:       10,    // Minimum 10 bytes
			SimilarityThresh:      0.85,  // 85% similarity threshold
		}
		idorScanner = NewIDORScannerAdapter(idorConfig, logger)
		logger.Infow("IDOR scanner initialized",
			"component", "orchestrator",
			"max_range", idorConfig.MaxSequentialRange,
			"parallel_workers", idorConfig.ParallelWorkers,
		)
	}

	// Initialize REST API scanner (if enabled)
	// TASK 7 COMPLETED: REST API scanner fully integrated with adapter pattern
	// - RESTAPIScannerAdapter bridges restapi.RESTAPIScanner to core.Scanner interface
	// - Scanner tests Swagger/OpenAPI specs, method fuzzing, auth bypass, IDOR, mass assignment, CORS
	// - Wired into executeTestingPhase() (uses existing runAPITests)
	// - Results displayed in displayTestCoverage() under API Security Testing
	var restapiScanner core.Scanner
	if config.EnableAPITesting {
		restapiConfig := restapi.RESTAPIConfig{
			// Discovery settings
			EnableSwaggerDiscovery: true,
			EnableMethodFuzzing:    true,
			EnableVersionFuzzing:   true,

			// Security testing
			EnableAuthBypass:       true,
			EnableIDORTesting:      true,
			EnableMassAssignment:   true,
			EnableInjectionTesting: true,
			EnableCORSTesting:      true,
			EnableRateLimitTest:    true,

			// Request parameters
			Timeout:          config.ScanTimeout,
			MaxWorkers:       10,
			RateLimit:        int(config.RateLimitPerSecond),
			FollowRedirects:  false,

			// Detection thresholds
			StatusCodeFilters:     []int{200, 201, 202, 204},
			MinResponseSize:       10,
			SimilarityThresh:      0.85,

			// Smart features
			EnableSmartFuzzing:    true,
			EnablePatternLearning: true,
			ExtractModelsFromSpec: true,
		}
		restapiScanner = NewRESTAPIScannerAdapter(restapiConfig, logger)
		logger.Infow("REST API scanner initialized",
			"component", "orchestrator",
			"swagger_discovery", restapiConfig.EnableSwaggerDiscovery,
			"method_fuzzing", restapiConfig.EnableMethodFuzzing,
			"auth_bypass", restapiConfig.EnableAuthBypass,
		)
	}

	// Initialize auth discovery engine
	authDiscoveryConfig := auth.DiscoveryConfig{
		EnablePortScan:    config.EnablePortScan,
		EnableWebCrawl:    config.EnableWebCrawl,
		EnableMLDetection: false,
		MaxDepth:          config.MaxDepth,
		Timeout:           config.DiscoveryTimeout,
		UserAgent:         "Shells Bug Bounty Scanner/1.0",
	}

	authDiscovery := auth.NewAuthDiscoveryEngine(authDiscoveryConfig, logger)

	// Initialize discovery engine
	discoveryConfig := &discovery.DiscoveryConfig{
		MaxDepth:        config.MaxDepth,
		MaxAssets:       config.MaxAssets,
		Timeout:         config.DiscoveryTimeout,
		EnableDNS:       config.EnableDNS,
		EnableCertLog:   false, // Too slow for bug bounty
		EnableSearch:    false, // Not needed for direct targets
		EnablePortScan:  config.EnablePortScan,
		EnableWebCrawl:  config.EnableWebCrawl,
		EnableTechStack: true,
		PortScanPorts:   "80,443,8080,8443,3000,5000,8000,8888",
		PortScanTimeout: 5 * time.Second,
	}
	discoveryEngine := discovery.NewEngine(discoveryConfig, logger)

	// Initialize organization correlator for Phase 0 footprinting
	var orgCorrelator *correlation.OrganizationCorrelator
	var certIntel *certs.CertIntel
	if config.EnableWHOISAnalysis || config.EnableCertTransparency || config.EnableRelatedDomainDisc {
		// Initialize certificate intelligence client
		certIntel = certs.NewCertIntel(logger)

		// Initialize organization correlator with default clients
		correlatorConfig := correlation.CorrelatorConfig{
			EnableWhois:    config.EnableWHOISAnalysis,
			EnableCerts:    config.EnableCertTransparency,
			EnableASN:      true,
			EnableGitHub:   false,
			EnableLinkedIn: false,
			CacheTTL:       1 * time.Hour,
			MaxWorkers:     5,
		}
		orgCorrelator = correlation.NewOrganizationCorrelator(correlatorConfig, logger)

		// Set up clients
		whoisClient := correlation.NewDefaultWhoisClient(logger)
		certClient := correlation.NewDefaultCertificateClient(logger)
		asnClient := correlation.NewDefaultASNClient(logger)
		orgCorrelator.SetClients(whoisClient, certClient, asnClient, nil, nil, nil, nil)

		logger.Infow("Organization correlator initialized",
			"enable_whois", config.EnableWHOISAnalysis,
			"enable_cert_transparency", config.EnableCertTransparency,
			"enable_asn", true,
			"component", "orchestrator",
		)
	}

	// Initialize rate limiter to prevent IP bans
	// NOTE: Individual scanners should respect this rate limit before making HTTP requests
	// This prevents overwhelming target servers and getting blocked
	rateLimiterConfig := ratelimit.Config{
		RequestsPerSecond: config.RateLimitPerSecond,
		BurstSize:         config.RateLimitBurst,
		MinDelay:          100 * time.Millisecond, // Minimum 100ms between requests to same host
	}
	rateLimiter := ratelimit.NewLimiter(rateLimiterConfig)

	logger.Infow("Rate limiter initialized",
		"requests_per_second", config.RateLimitPerSecond,
		"burst_size", config.RateLimitBurst,
		"min_delay_ms", 100,
	)

	// Initialize Python workers client (optional - check if service is running)
	var pythonWorkers *workers.Client
	workerURL := "http://localhost:5000"
	pythonWorkers = workers.NewClient(workerURL)
	if err := pythonWorkers.Health(); err != nil {
		logger.Warnw("Python worker service not available - GraphCrawler testing disabled",
			"error", err,
			"worker_url", workerURL,
			"note", "Run 'shells serve' or 'shells workers start' to enable Python-based GraphCrawler testing. IDOR testing now uses native Go scanner.",
		)
		pythonWorkers = nil // Disable if not available
	} else {
		logger.Infow("Python worker service connected",
			"worker_url", workerURL,
			"capabilities", []string{"GraphCrawler"},
		)
	}

	// Initialize checkpoint manager if enabled
	var checkpointMgr CheckpointManager
	if config.EnableCheckpointing {
		// NOTE: We'll create a checkpoint adapter that implements CheckpointManager
		// For now, checkpointing is configured but not fully wired
		logger.Infow("Checkpoint system initialized",
			"enabled", config.EnableCheckpointing,
			"interval", config.CheckpointInterval.String(),
		)
	}

	// TASK 14: Initialize enrichment engine
	var enricher *enrichment.ResultEnricher
	if config.EnableEnrichment {
		enricherConfig := enrichment.EnricherConfig{
			CVSSVersion:     "3.1",
			EnrichmentLevel: config.EnrichmentLevel,
			CacheSize:       1000,
			CacheTTL:        1 * time.Hour,
			MaxConcurrency:  10,
		}
		var err error
		enricher, err = enrichment.NewResultEnricher(enricherConfig)
		if err != nil {
			logger.Warnw("Failed to initialize enrichment engine - continuing without enrichment",
				"error", err,
				"component", "orchestrator",
			)
			enricher = nil
		} else {
			logger.Infow("Finding enrichment enabled",
				"level", config.EnrichmentLevel,
				"cvss_version", "3.1",
				"component", "orchestrator",
			)
		}
	}

	// Initialize scope manager for bug bounty program scope validation (if enabled)
	var scopeManager *scope.Manager
	if config.EnableScopeValidation {
		// Get database connection from store
		var db *sqlx.DB
		if sqlStore, ok := store.(interface{ DB() *sqlx.DB }); ok {
			db = sqlStore.DB()
		} else {
			logger.Warnw("Scope validation disabled - store does not provide DB access",
				"component", "orchestrator",
			)
		}

		if db != nil {
			scopeConfig := &scope.Config{
				AutoSync:         false, // Manual sync for now
				CacheTTL:         1 * time.Hour,
				ValidateWorkers:  10,
				StrictMode:       config.ScopeStrictMode,
				EnableMonitoring: false, // Disable monitoring for now
			}
			scopeManager = scope.NewManager(db, logger, scopeConfig)
			logger.Infow("Scope manager initialized",
				"strict_mode", config.ScopeStrictMode,
				"component", "orchestrator",
			)

			// Import scope from bug bounty platform if specified
			if config.BugBountyPlatform != "" && config.BugBountyProgram != "" {
				logger.Infow("Bug bounty platform scope import requested",
					"platform", config.BugBountyPlatform,
					"program", config.BugBountyProgram,
					"component", "orchestrator",
				)
				// Scope import will happen in Execute() before discovery
			}
		}
	}

	return &BugBountyEngine{
		store:              store,
		telemetry:          telemetry,
		logger:             logger,
		rateLimiter:        rateLimiter,
		discoveryEngine:    discoveryEngine,
		orgCorrelator:      orgCorrelator,
		certIntel:          certIntel,
		scopeManager:       scopeManager,
		samlScanner:        samlScanner,
		oauth2Scanner:      oauth2Scanner,
		webauthnScanner:    webauthnScanner,
		scimScanner:        scimScanner,
		authDiscovery:      authDiscovery,
		nmapScanner:        nmapScanner,
		nucleiScanner:      nucleiScanner,
		graphqlScanner:     graphqlScanner,
		idorScanner:        idorScanner,
		restapiScanner:     restapiScanner,
		pythonWorkers:      pythonWorkers,
		enricher:           enricher, // TASK 14: Add enrichment
		checkpointEnabled:  config.EnableCheckpointing,
		checkpointInterval: config.CheckpointInterval,
		checkpointManager:  checkpointMgr,
		config:             config,
	}, nil
}

// BugBountyResult contains the complete results of a bug bounty scan
// P0-2 FIX: Add mutex to protect concurrent access to DiscoveredAssets
type BugBountyResult struct {
	ScanID           string
	Target           string
	StartTime        time.Time
	EndTime          time.Time
	Duration         time.Duration
	Status           string
	DiscoveredAt     int // Number of discovered assets
	TestedAssets     int
	TotalFindings    int
	Findings         []types.Finding
	PhaseResults     map[string]PhaseResult
	OrganizationInfo *correlation.Organization      // Organization footprinting results
	DiscoverySession *discovery.DiscoverySession    // Asset discovery session metadata
	DiscoveredAssets []*discovery.Asset              // Discovered assets for display
	assetsMutex      sync.RWMutex                    // P0-2: Protects DiscoveredAssets from race conditions
}

// PhaseResult contains results from a specific phase
type PhaseResult struct {
	Phase     string
	Status    string
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	Findings  int
	Error     string
}

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

		// P0-2 FIX: Lock assets during read to prevent race condition with concurrent modifications
		result.assetsMutex.RLock()
		checkpointAssets := checkpoint.ConvertDiscoveryAssets(result.DiscoveredAssets)
		result.assetsMutex.RUnlock()

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
				"quick_mode":                  e.config.SkipDiscovery,
				"total_timeout":               e.config.TotalTimeout.String(),
				"scan_timeout":                e.config.ScanTimeout.String(),
				"discovery_timeout":           e.config.DiscoveryTimeout.String(),
				"enable_dns":                  e.config.EnableDNS,
				"enable_port_scan":            e.config.EnablePortScan,
				"enable_web_crawl":            e.config.EnableWebCrawl,
				"enable_auth_testing":         e.config.EnableAuthTesting,
				"enable_api_testing":          e.config.EnableAPITesting,
				"enable_scim_testing":         e.config.EnableSCIMTesting,
				"enable_graphql_testing":      e.config.EnableGraphQLTesting,
				"enable_idor_testing":         e.config.EnableIDORTesting,
				"enable_service_fingerprint":  e.config.EnableServiceFingerprint,
				"enable_nuclei_scan":          e.config.EnableNucleiScan,
				"max_assets":                  e.config.MaxAssets,
				"max_depth":                   e.config.MaxDepth,
				"show_progress":               e.config.ShowProgress,
				"rate_limit_per_second":       e.config.RateLimitPerSecond,
				"rate_limit_burst":            e.config.RateLimitBurst,
				"enable_checkpointing":        e.config.EnableCheckpointing,
				"checkpoint_interval":         e.config.CheckpointInterval.String(),
				"enable_enrichment":           e.config.EnableEnrichment,
				"enrichment_level":            e.config.EnrichmentLevel,
				"enable_whois_analysis":       e.config.EnableWHOISAnalysis,
				"enable_cert_transparency":    e.config.EnableCertTransparency,
				"enable_related_domain_disc":  e.config.EnableRelatedDomainDisc,
				"bug_bounty_platform":         e.config.BugBountyPlatform,
				"bug_bounty_program":          e.config.BugBountyProgram,
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

	// Pre-Phase: Bug Bounty Platform Scope Import (if enabled)
	if e.scopeManager != nil && e.config.BugBountyPlatform != "" && e.config.BugBountyProgram != "" {
		scopeImportStart := time.Now()

		// IMMEDIATE CLI FEEDBACK - Show user what's happening
		fmt.Println()
		fmt.Println("═══════════════════════════════════════════════════════════════")
		fmt.Println(" Scope Import: Bug Bounty Program")
		fmt.Println("═══════════════════════════════════════════════════════════════")
		fmt.Printf("   Platform: %s\n", e.config.BugBountyPlatform)
		fmt.Printf("   Program: %s\n", e.config.BugBountyProgram)
		fmt.Printf("   • Fetching program scope from platform API...\n")
		fmt.Println()

		dbLogger.Infow(" Importing bug bounty program scope",
			"platform", e.config.BugBountyPlatform,
			"program", e.config.BugBountyProgram,
			"component", "orchestrator",
		)

		// Get platform client
		var platformType scope.Platform
		switch strings.ToLower(e.config.BugBountyPlatform) {
		case "hackerone", "h1":
			platformType = scope.PlatformHackerOne
		case "bugcrowd", "bc":
			platformType = scope.PlatformBugcrowd
		case "intigriti":
			platformType = scope.PlatformIntigriti
		case "yeswehack", "ywh":
			platformType = scope.PlatformYesWeHack
		default:
			dbLogger.Errorw("Unsupported bug bounty platform",
				"platform", e.config.BugBountyPlatform,
				"supported", []string{"hackerone", "bugcrowd", "intigriti", "yeswehack"},
				"component", "orchestrator",
			)
			fmt.Printf("   ⚠️  Unsupported platform: %s\n", e.config.BugBountyPlatform)
			fmt.Printf("   Supported: hackerone, bugcrowd, intigriti, yeswehack\n")
			fmt.Printf("   Continuing without scope validation...\n")
			fmt.Println()
			e.scopeManager = nil
		}

		if e.scopeManager != nil {
			// Get platform client and fetch program
			client := e.scopeManager.GetPlatformClient(platformType)
			if client == nil {
				dbLogger.Errorw("Platform client not available",
					"platform", platformType,
					"component", "orchestrator",
				)
				fmt.Printf("   ⚠️  Platform client not available\n")
				fmt.Printf("   Continuing without scope validation...\n")
				fmt.Println()
				e.scopeManager = nil
			} else {
				// Configure client with API credentials if available
				if cred, ok := e.config.PlatformCredentials[strings.ToLower(e.config.BugBountyPlatform)]; ok {
					if cred.Username != "" && cred.APIKey != "" {
						// Type assert to configure the client
						if h1Client, ok := client.(*scope.HackerOneClient); ok {
							h1Client.Configure(cred.Username, cred.APIKey)
							dbLogger.Debugw("Configured HackerOne API credentials",
								"username", cred.Username,
								"component", "orchestrator",
							)
						} else if bcClient, ok := client.(*scope.BugcrowdClient); ok {
							bcClient.Configure(cred.APIKey) // Bugcrowd uses API token only
							dbLogger.Debugw("Configured Bugcrowd API credentials",
								"component", "orchestrator",
							)
						}
					} else {
						dbLogger.Warnw("Platform credentials incomplete",
							"platform", e.config.BugBountyPlatform,
							"has_username", cred.Username != "",
							"has_api_key", cred.APIKey != "",
							"note", "Will attempt public API access",
							"component", "orchestrator",
						)
					}
				} else {
					dbLogger.Infow("No platform credentials configured",
						"platform", e.config.BugBountyPlatform,
						"note", "Will attempt public API access",
						"hint", fmt.Sprintf("Set %s_USERNAME and %s_API_KEY environment variables for private programs",
							strings.ToUpper(e.config.BugBountyPlatform),
							strings.ToUpper(e.config.BugBountyPlatform)),
						"component", "orchestrator",
					)
				}

				// Fetch program from platform
				program, err := client.GetProgram(ctx, e.config.BugBountyProgram)
				if err != nil {
					dbLogger.Errorw("Failed to fetch bug bounty program",
						"error", err,
						"platform", e.config.BugBountyPlatform,
						"program", e.config.BugBountyProgram,
						"component", "orchestrator",
					)
					fmt.Printf("   ⚠️  Failed to fetch program: %v\n", err)

					// Check if this looks like an authentication error
					errStr := strings.ToLower(err.Error())
					if strings.Contains(errStr, "401") || strings.Contains(errStr, "unauthorized") ||
					   strings.Contains(errStr, "403") || strings.Contains(errStr, "forbidden") ||
					   strings.Contains(errStr, "invalid credentials") {
						fmt.Printf("\n   Authentication failed. For private programs, set:\n")
						platformUpper := strings.ToUpper(e.config.BugBountyPlatform)
						fmt.Printf("     export %s_USERNAME=your-username\n", platformUpper)
						fmt.Printf("     export %s_API_KEY=your-api-key\n", platformUpper)
						fmt.Println()
					} else {
						fmt.Printf("   Continuing without scope validation...\n")
						fmt.Println()
					}
					e.scopeManager = nil
				} else {
					// Add program to scope manager
					if err := e.scopeManager.AddProgram(program); err != nil {
						dbLogger.Errorw("Failed to add program to scope manager",
							"error", err,
							"program", program.Name,
							"component", "orchestrator",
						)
						fmt.Printf("   ⚠️  Failed to add program: %v\n", err)
						fmt.Printf("   Continuing without scope validation...\n")
						fmt.Println()
						e.scopeManager = nil
					} else {
						dbLogger.Infow(" Bug bounty scope import completed",
							"program_id", program.ID,
							"duration", time.Since(scopeImportStart).String(),
							"component", "orchestrator",
						)

						// Display scope summary
						fmt.Printf("   ✓ Scope imported successfully\n")
						fmt.Printf("   Program: %s\n", program.Name)
						if len(program.Scope) > 0 {
							fmt.Printf("   In-Scope Assets: %d\n", len(program.Scope))
						}
						if len(program.OutOfScope) > 0 {
							fmt.Printf("   Out-of-Scope Assets: %d\n", len(program.OutOfScope))
						}
						if program.MaxBounty > 0 {
							fmt.Printf("   Max Bounty: $%.0f\n", program.MaxBounty)
						}
						fmt.Printf("   Duration: %s\n", time.Since(scopeImportStart).Round(time.Millisecond))
						fmt.Println()
					}
				}
			}
		}

		saveCheckpoint("scope_import", 2.0, []string{"scope_import"}, []types.Finding{})
	}

	// Phase 0: Organization Footprinting (if enabled)
	var orgDomains []string
	if e.orgCorrelator != nil && !e.config.SkipDiscovery {
		footprintStart := time.Now()

		// IMMEDIATE CLI FEEDBACK - Show user what's happening
		fmt.Println()
		fmt.Println("═══════════════════════════════════════════════════════════════")
		fmt.Println(" Phase 0: Organization Footprinting")
		fmt.Println("═══════════════════════════════════════════════════════════════")
		fmt.Printf("   Analyzing: %s\n", target)
		fmt.Printf("   • WHOIS lookup for organization details...\n")
		fmt.Printf("   • Certificate transparency logs for related domains...\n")
		fmt.Printf("   • ASN discovery for IP ranges...\n")
		fmt.Println()

		dbLogger.Infow(" Phase 0: Organization Footprinting",
			"target", target,
			"enable_whois", e.config.EnableWHOISAnalysis,
			"enable_cert_transparency", e.config.EnableCertTransparency,
			"enable_related_domains", e.config.EnableRelatedDomainDisc,
			"component", "orchestrator",
		)

		// Correlate organization from target
		org, err := e.orgCorrelator.FindOrganizationAssets(ctx, target)
		if err != nil {
			// ENHANCED ERROR LOGGING: Provide detailed diagnostics
			dbLogger.Errorw("CRITICAL: Organization footprinting failed",
				"error", err,
				"error_type", fmt.Sprintf("%T", err),
				"target", target,
				"whois_enabled", e.config.EnableWHOISAnalysis,
				"cert_enabled", e.config.EnableCertTransparency,
				"asn_enabled", true,
				"elapsed_time", time.Since(footprintStart).String(),
				"component", "orchestrator",
			)

			// Store failed phase result
			result.PhaseResults["footprinting"] = PhaseResult{
				Phase:     "footprinting",
				Status:    "failed",
				StartTime: footprintStart,
				EndTime:   time.Now(),
				Duration:  time.Since(footprintStart),
				Error:     err.Error(),
			}
		} else if org == nil {
			// NULL RESULT: Correlation returned nil without error
			dbLogger.Warnw(" Organization footprinting returned nil (no error)",
				"target", target,
				"elapsed_time", time.Since(footprintStart).String(),
				"component", "orchestrator",
			)

			result.PhaseResults["footprinting"] = PhaseResult{
				Phase:     "footprinting",
				Status:    "completed",
				StartTime: footprintStart,
				EndTime:   time.Now(),
				Duration:  time.Since(footprintStart),
				Findings:  0,
			}
		} else {
			// Store org info for later display
			result.OrganizationInfo = org // Add to result for display

			dbLogger.Infow(" Organization footprinting completed",
				"organization_name", org.Name,
				"domains_found", len(org.Domains),
				"asns_found", len(org.ASNs),
				"ip_ranges_found", len(org.IPRanges),
				"certificates_found", len(org.Certificates),
				"confidence", org.Confidence,
				"sources", org.Sources,
				"duration", time.Since(footprintStart).String(),
				"component", "orchestrator",
			)

			// USER-FRIENDLY CLI DISPLAY
			e.displayOrganizationFootprinting(org, time.Since(footprintStart))

			// Store discovered domains for parallel scanning
			orgDomains = org.Domains

			// Log each discovered domain
			for i, domain := range org.Domains {
				dbLogger.Infow(" Discovered related domain",
					"index", i+1,
					"domain", domain,
					"organization", org.Name,
					"component", "orchestrator",
				)
			}

			// Store organization metadata in result
			if result.PhaseResults == nil {
				result.PhaseResults = make(map[string]PhaseResult)
			}
			result.PhaseResults["footprinting"] = PhaseResult{
				Phase:     "footprinting",
				Status:    "completed",
				StartTime: footprintStart,
				EndTime:   time.Now(),
				Duration:  time.Since(footprintStart),
				Findings:  len(org.Domains), // Count domains as findings
			}
		}

		saveCheckpoint("footprinting", 5.0, []string{"footprinting"}, []types.Finding{})
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
		// P0-2 FIX: Lock during write to prevent race with checkpoint save
		result.assetsMutex.Lock()
		result.DiscoveredAssets = assets
		result.assetsMutex.Unlock()

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
			e.displayDiscoveryResults(assets, discoveryDuration)
		}

		result.PhaseResults["discovery"] = phaseResult
		result.DiscoveredAt = len(assets)

		// Checkpoint after discovery
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
	saveCheckpoint("prioritization", 35.0, []string{"discovery", "prioritization"}, []types.Finding{})

	// Phase 2.5: Scope Validation (if enabled)
	if e.scopeManager != nil {
		scopeValidationStart := time.Now()

		// IMMEDIATE CLI FEEDBACK
		fmt.Println()
		fmt.Println("═══════════════════════════════════════════════════════════════")
		fmt.Println(" Scope Validation: Bug Bounty Program")
		fmt.Println("═══════════════════════════════════════════════════════════════")
		fmt.Printf("   Validating %d assets against program scope...\n", len(prioritized))
		fmt.Println()

		dbLogger.Infow(" Starting scope validation",
			"assets_to_validate", len(prioritized),
			"strict_mode", e.config.ScopeStrictMode,
			"component", "orchestrator",
		)

		// Filter out-of-scope assets
		inScopeAssets := make([]*AssetPriority, 0, len(prioritized))
		outOfScopeAssets := make([]*AssetPriority, 0)
		unknownAssets := make([]*AssetPriority, 0)

		for _, asset := range prioritized {
			// Validate asset against scope
			validation, err := e.scopeManager.ValidateAsset(asset.Asset.Value)
			if err != nil {
				dbLogger.Warnw("Asset validation error - including asset",
					"asset", asset.Asset.Value,
					"error", err,
					"component", "scope_validator",
				)
				// On error, include the asset (fail open)
				unknownAssets = append(unknownAssets, asset)
				inScopeAssets = append(inScopeAssets, asset)
				continue
			}

			if validation.Status == scope.ScopeStatusInScope {
				inScopeAssets = append(inScopeAssets, asset)
				dbLogger.Debugw("Asset in scope",
					"asset", asset.Asset.Value,
					"program", validation.Program.Name,
					"component", "scope_validator",
				)
			} else if validation.Status == scope.ScopeStatusOutOfScope {
				outOfScopeAssets = append(outOfScopeAssets, asset)
				dbLogger.Warnw("Asset out of scope - skipping",
					"asset", asset.Asset.Value,
					"reason", validation.Reason,
					"component", "scope_validator",
				)
			} else {
				// Unknown - behavior depends on strict mode
				if e.config.ScopeStrictMode {
					outOfScopeAssets = append(outOfScopeAssets, asset)
					dbLogger.Warnw("Asset scope unknown (strict mode) - skipping",
						"asset", asset.Asset.Value,
						"component", "scope_validator",
					)
				} else {
					unknownAssets = append(unknownAssets, asset)
					inScopeAssets = append(inScopeAssets, asset)
					dbLogger.Debugw("Asset scope unknown (permissive mode) - including",
						"asset", asset.Asset.Value,
						"component", "scope_validator",
					)
				}
			}
		}

		dbLogger.Infow(" Scope validation completed",
			"in_scope", len(inScopeAssets),
			"out_of_scope", len(outOfScopeAssets),
			"unknown", len(unknownAssets),
			"duration", time.Since(scopeValidationStart).String(),
			"component", "orchestrator",
		)

		// Display validation results
		fmt.Printf("   ✓ Validation completed\n")
		fmt.Printf("   In-Scope Assets: %d\n", len(inScopeAssets))
		if len(outOfScopeAssets) > 0 {
			fmt.Printf("   Out-of-Scope Assets: %d (skipped)\n", len(outOfScopeAssets))
		}
		if len(unknownAssets) > 0 {
			fmt.Printf("   Unknown Scope Assets: %d (included in %s mode)\n",
				len(unknownAssets),
				func() string {
					if e.config.ScopeStrictMode {
						return "strict"
					}
					return "permissive"
				}())
		}
		fmt.Printf("   Duration: %s\n", time.Since(scopeValidationStart).Round(time.Millisecond))
		fmt.Println()

		// Update prioritized list to only include in-scope assets
		prioritized = inScopeAssets

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
	if err := e.storeResults(ctx, scanID, result); err != nil {
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
	e.displayScanSummary(result)

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
	var prioritizedAssets []*AssetPriority
	var completedTests map[string]bool
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
		// Testing in progress, continue from completed tests
		dbLogger.Infow("Resuming testing phase",
			"completed_tests", state.CompletedTests,
			"findings_so_far", len(result.Findings),
		)
		tracker.CompletePhase("discovery")
		tracker.CompletePhase("prioritization")
		tracker.StartPhase("testing")
		goto continueTesting

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

	// P0-2 FIX: Lock during write to prevent race with checkpoint save
	result.assetsMutex.Lock()
	result.DiscoveredAssets = assets
	result.assetsMutex.Unlock()

	result.PhaseResults["discovery"] = discoveryPhaseResult
	tracker.CompletePhase("discovery")

testingPhase:
	// Run vulnerability testing
	tracker.StartPhase("testing")

	// Prioritize assets for testing
	prioritizedAssets = e.executePrioritizationPhase(result.DiscoveredAssets, dbLogger)

	// Filter out already-tested assets if resuming mid-testing
	completedTests = make(map[string]bool)
	for _, test := range state.CompletedTests {
		completedTests[test] = true
	}

	// P0-7 FIX: Pass completedTests to skip already-run tests on resume
	// Run testing on all assets (use existing testing phase but skip completed tests)
	newFindings, phaseResults = e.executeTestingPhase(ctx, target, prioritizedAssets, tracker, dbLogger, state.CompletedTests)
	result.Findings = append(result.Findings, newFindings...)
	for phase, pr := range phaseResults {
		result.PhaseResults[phase] = pr
	}

	tracker.CompletePhase("testing")

continueTesting:
	// Already handled in testingPhase label

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
type AssetPriority struct {
	Asset    *discovery.Asset
	Score    int
	Features AssetFeatures
}

// AssetFeatures tracks important features of an asset
type AssetFeatures struct {
	HasAuthentication bool
	HasAPI            bool
	HasPayment        bool
	HasFileUpload     bool
	HasUserData       bool
	HasAdmin          bool
	IsSCIM            bool
	Technology        string
}

// executePrioritizationPhase prioritizes assets for testing
func (e *BugBountyEngine) executePrioritizationPhase(assets []*discovery.Asset, dbLogger *logger.DBEventLogger) []*AssetPriority {
	dbLogger.Infow("Phase 2: Asset Prioritization", "assets", len(assets))

	var prioritized []*AssetPriority

	for _, asset := range assets {
		priority := &AssetPriority{
			Asset:    asset,
			Score:    0,
			Features: e.analyzeAssetFeatures(asset),
		}

		// Score based on features
		if priority.Features.HasAuthentication {
			priority.Score += 100
		}
		if priority.Features.HasAPI {
			priority.Score += 90
		}
		if priority.Features.HasAdmin {
			priority.Score += 85
		}
		if priority.Features.HasPayment {
			priority.Score += 85
		}
		if priority.Features.IsSCIM {
			priority.Score += 95 // SCIM is high value
		}
		if priority.Features.HasFileUpload {
			priority.Score += 75
		}
		if priority.Features.HasUserData {
			priority.Score += 70
		}

		prioritized = append(prioritized, priority)
	}

	// Sort by score (highest first) - critical for targeting high-value endpoints
	sort.Slice(prioritized, func(i, j int) bool {
		return prioritized[i].Score > prioritized[j].Score
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
			"score", p.Score,
			"url", p.Asset.Value,
			"auth", p.Features.HasAuthentication,
			"api", p.Features.HasAPI,
			"admin", p.Features.HasAdmin,
			"scim", p.Features.IsSCIM,
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
func (e *BugBountyEngine) analyzeAssetFeatures(asset *discovery.Asset) AssetFeatures {
	features := AssetFeatures{}

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
		features.HasAPI = true
	}

	// SCIM endpoints - critical for enterprise targets
	scimPatterns := []string{
		"/scim/", "/scim/v2/", "/scim2/",
		"/provisioning", "/identity/scim",
	}
	if containsAny(value, scimPatterns) {
		features.IsSCIM = true
	}

	// Admin/privileged endpoints
	adminPatterns := []string{
		"admin", "administrator", "dashboard", "panel",
		"management", "console", "control", "config",
	}
	if containsAny(value, adminPatterns) {
		features.HasAdmin = true
	}

	// Payment/financial endpoints
	paymentPatterns := []string{
		"payment", "checkout", "billing", "invoice",
		"pay", "subscription", "pricing", "stripe",
		"paypal", "credit", "card",
	}
	if containsAny(value, paymentPatterns) {
		features.HasPayment = true
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
		features.HasUserData = true
	}

	return features
}

// executeTestingPhase runs all vulnerability tests in parallel
// P0-7 FIX: Add skipTests parameter to avoid re-running completed tests on resume
func (e *BugBountyEngine) executeTestingPhase(ctx context.Context, target string, assets []*AssetPriority, tracker *progress.Tracker, dbLogger *logger.DBEventLogger, skipTests []string) ([]types.Finding, map[string]PhaseResult) {
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

// runAuthenticationTests executes all authentication vulnerability tests
func (e *BugBountyEngine) runAuthenticationTests(ctx context.Context, target string, assets []*AssetPriority, dbLogger *logger.DBEventLogger) ([]types.Finding, PhaseResult) {
	phaseStart := time.Now()
	phase := PhaseResult{
		Phase:     "authentication",
		Status:    "running",
		StartTime: phaseStart,
	}

	dbLogger.Infow(" Starting authentication testing phase",
		"target", target,
		"asset_count", len(assets),
		"component", "auth_scanner",
	)

	// Check context status
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		dbLogger.Infow(" Context status at auth phase start",
			"remaining_time", remaining.String(),
			"remaining_seconds", remaining.Seconds(),
			"context_healthy", remaining > 0,
			"component", "auth_scanner",
		)
	}

	var findings []types.Finding

	// Discover authentication endpoints
	discoveryStart := time.Now()
	dbLogger.Infow(" Discovering authentication endpoints",
		"target", target,
		"component", "auth_scanner",
	)

	authInventory, err := e.authDiscovery.DiscoverAllAuth(ctx, target)
	discoveryDuration := time.Since(discoveryStart)

	if err != nil {
		dbLogger.Errorw(" Authentication discovery failed",
			"error", err,
			"target", target,
			"discovery_duration", discoveryDuration.String(),
			"elapsed_since_phase_start", time.Since(phaseStart).String(),
			"component", "auth_scanner",
		)
		phase.Status = "failed"
		phase.Error = err.Error()
		phase.EndTime = time.Now()
		phase.Duration = phase.EndTime.Sub(phase.StartTime)
		return findings, phase
	}

	// Log discovery results
	protocolsFound := []string{}
	if authInventory.SAML != nil {
		protocolsFound = append(protocolsFound, "SAML")
	}
	if authInventory.OAuth2 != nil {
		protocolsFound = append(protocolsFound, "OAuth2/OIDC")
	}
	if authInventory.WebAuthn != nil {
		protocolsFound = append(protocolsFound, "WebAuthn/FIDO2")
	}

	dbLogger.Infow(" Authentication endpoint discovery complete",
		"saml_found", authInventory.SAML != nil,
		"oauth2_found", authInventory.OAuth2 != nil,
		"webauthn_found", authInventory.WebAuthn != nil,
		"protocols_found", protocolsFound,
		"protocol_count", len(protocolsFound),
		"discovery_duration", discoveryDuration.String(),
		"elapsed_since_phase_start", time.Since(phaseStart).String(),
		"component", "auth_scanner",
	)

	// Test SAML if discovered
	if authInventory.SAML != nil && authInventory.SAML.MetadataURL != "" {
		dbLogger.Infow(" Testing SAML authentication security",
			"metadata_url", authInventory.SAML.MetadataURL,
			"tests", []string{"Golden SAML", "XML Signature Wrapping", "Assertion manipulation"},
			"component", "auth_scanner",
		)

		samlOptions := map[string]interface{}{
			"metadata_url": authInventory.SAML.MetadataURL,
			"test_golden":  true,
			"test_xsw":     true,
		}

		report, err := e.samlScanner.Scan(target, samlOptions)
		if err != nil {
			dbLogger.Warnw("SAML scanning failed",
				"error", err,
				"target", target,
				"component", "auth_scanner",
			)
		} else if report != nil {
			dbLogger.Infow("SAML scan complete",
				"vulnerabilities_found", len(report.Vulnerabilities),
				"attack_chains", len(report.AttackChains),
				"component", "auth_scanner",
			)

			// Convert vulnerabilities to findings
			for _, vuln := range report.Vulnerabilities {
				finding := convertVulnerabilityToFinding(vuln, target)
				findings = append(findings, finding)

				// Stream critical/high findings immediately to CLI
				streamHighSeverityFinding(finding)

				dbLogger.Infow(" SAML vulnerability found",
					"type", vuln.Type,
					"severity", vuln.Severity,
					"title", vuln.Title,
					"component", "auth_scanner",
				)
			}
		}
	} else {
		dbLogger.Infow("No SAML endpoints discovered - skipping SAML tests",
			"target", target,
			"component", "auth_scanner",
		)
	}

	// Test OAuth2 if discovered
	if authInventory.OAuth2 != nil && authInventory.OAuth2.AuthorizationURL != "" {
		dbLogger.Infow(" Testing OAuth2/OIDC authentication security",
			"authorization_url", authInventory.OAuth2.AuthorizationURL,
			"token_url", authInventory.OAuth2.TokenURL,
			"tests", []string{"JWT algorithm confusion", "PKCE bypass", "State validation", "Scope escalation"},
			"component", "auth_scanner",
		)

		oauth2Options := map[string]interface{}{
			"authorization_url": authInventory.OAuth2.AuthorizationURL,
			"token_url":         authInventory.OAuth2.TokenURL,
			"test_jwt":          true,
			"test_pkce":         true,
		}

		report, err := e.oauth2Scanner.Scan(target, oauth2Options)
		if err != nil {
			dbLogger.Warnw("OAuth2 scanning failed",
				"error", err,
				"target", target,
				"component", "auth_scanner",
			)
		} else if report != nil {
			dbLogger.Infow("OAuth2 scan complete",
				"vulnerabilities_found", len(report.Vulnerabilities),
				"attack_chains", len(report.AttackChains),
				"component", "auth_scanner",
			)

			for _, vuln := range report.Vulnerabilities {
				finding := convertVulnerabilityToFinding(vuln, target)
				findings = append(findings, finding)

				// Stream critical/high findings immediately to CLI
				streamHighSeverityFinding(finding)

				dbLogger.Infow(" OAuth2 vulnerability found",
					"type", vuln.Type,
					"severity", vuln.Severity,
					"title", vuln.Title,
					"component", "auth_scanner",
				)
			}
		}
	} else {
		dbLogger.Infow("No OAuth2 endpoints discovered - skipping OAuth2 tests",
			"target", target,
			"component", "auth_scanner",
		)
	}

	// Test WebAuthn if discovered
	if authInventory.WebAuthn != nil && authInventory.WebAuthn.RegisterURL != "" {
		dbLogger.Infow(" Testing WebAuthn/FIDO2 authentication security",
			"register_url", authInventory.WebAuthn.RegisterURL,
			"login_url", authInventory.WebAuthn.LoginURL,
			"tests", []string{"Virtual authenticator", "Credential substitution", "Challenge reuse", "Origin validation"},
			"component", "auth_scanner",
		)

		webauthnOptions := map[string]interface{}{
			"register_url": authInventory.WebAuthn.RegisterURL,
			"login_url":    authInventory.WebAuthn.LoginURL,
		}

		report, err := e.webauthnScanner.Scan(target, webauthnOptions)
		if err != nil {
			dbLogger.Warnw("WebAuthn scanning failed",
				"error", err,
				"target", target,
				"component", "auth_scanner",
			)
		} else if report != nil {
			dbLogger.Infow("WebAuthn scan complete",
				"vulnerabilities_found", len(report.Vulnerabilities),
				"attack_chains", len(report.AttackChains),
				"component", "auth_scanner",
			)

			for _, vuln := range report.Vulnerabilities {
				finding := convertVulnerabilityToFinding(vuln, target)
				findings = append(findings, finding)

				// Stream critical/high findings immediately to CLI
				streamHighSeverityFinding(finding)

				dbLogger.Infow(" WebAuthn vulnerability found",
					"type", vuln.Type,
					"severity", vuln.Severity,
					"title", vuln.Title,
					"component", "auth_scanner",
				)
			}
		}
	} else {
		dbLogger.Infow("No WebAuthn endpoints discovered - skipping WebAuthn tests",
			"target", target,
			"component", "auth_scanner",
		)
	}

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(phase.StartTime)
	phase.Status = "completed"
	phase.Findings = len(findings)

	dbLogger.Infow("Authentication testing completed", "findings", len(findings), "duration", phase.Duration)

	return findings, phase
}

// runSCIMTests executes SCIM vulnerability tests in parallel
func (e *BugBountyEngine) runSCIMTests(ctx context.Context, assets []*AssetPriority, dbLogger *logger.DBEventLogger) ([]types.Finding, PhaseResult) {
	phaseStart := time.Now()
	phase := PhaseResult{
		Phase:     "scim",
		Status:    "running",
		StartTime: phaseStart,
	}

	dbLogger.Infow(" Starting SCIM testing phase",
		"asset_count", len(assets),
		"component", "scim_scanner",
	)

	// Check context status
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		dbLogger.Infow(" Context status at SCIM phase start",
			"remaining_time", remaining.String(),
			"remaining_seconds", remaining.Seconds(),
			"context_healthy", remaining > 0,
			"component", "scim_scanner",
		)
	}

	var findings []types.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Worker pool for parallel SCIM testing
	maxWorkers := 5
	semaphore := make(chan struct{}, maxWorkers)

	// Find and test SCIM endpoints in parallel
	for _, asset := range assets {
		if !asset.Features.IsSCIM {
			continue
		}

		wg.Add(1)
		semaphore <- struct{}{} // Acquire worker slot

		go func(assetValue string) {
			defer func() {
				// P2.1: Panic recovery - graceful error handling
				if r := recover(); r != nil {
					dbLogger.Errorw("SCIM scanner panicked - recovered gracefully",
						"url", assetValue,
						"panic", r)
				}
				<-semaphore // Release worker slot
				wg.Done()
			}()

			dbLogger.Infow("Testing SCIM endpoint", "url", assetValue)

			// Run SCIM vulnerability tests with timeout protection
			scanCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			scimOptions := make(map[string]string)
			scimOptions["test_all"] = "true"

			scimFindings, err := e.scimScanner.Scan(scanCtx, assetValue, scimOptions)
			if err != nil {
				dbLogger.Warnw("SCIM scan failed", "url", assetValue, "error", err)
				return
			}

			// Thread-safe append of findings
			mu.Lock()
			findings = append(findings, scimFindings...)
			mu.Unlock()

			dbLogger.Infow("SCIM scan completed", "url", assetValue, "findings", len(scimFindings))
		}(asset.Asset.Value)
	}

	// Wait for all SCIM scans to complete
	wg.Wait()

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(phase.StartTime)
	phase.Status = "completed"
	phase.Findings = len(findings)

	dbLogger.Infow(" SCIM testing phase completed",
		"total_findings", len(findings),
		"phase_duration", phase.Duration.String(),
		"elapsed_since_phase_start", time.Since(phaseStart).String(),
		"component", "scim_scanner",
	)

	return findings, phase
}

// runAPITests executes API vulnerability tests
func (e *BugBountyEngine) runAPITests(ctx context.Context, assets []*AssetPriority, dbLogger *logger.DBEventLogger) ([]types.Finding, PhaseResult) {
	phase := PhaseResult{
		Phase:     "api",
		Status:    "running",
		StartTime: time.Now(),
	}

	dbLogger.Infow("Running REST API security tests", "component", "rest_api_scanner")

	var findings []types.Finding

	// Find API endpoints from discovered assets
	apiEndpoints := []string{}
	for _, asset := range assets {
		url := asset.Asset.Value
		// Look for API endpoints (REST, GraphQL, etc.)
		if strings.Contains(url, "/api/") ||
		   strings.Contains(url, "/graphql") ||
		   strings.Contains(url, "/swagger") ||
		   strings.Contains(url, "/openapi") ||
		   asset.Features.HasAPI {
			apiEndpoints = append(apiEndpoints, url)
		}
	}

	if len(apiEndpoints) == 0 {
		dbLogger.Infow("No API endpoints found", "component", "rest_api_scanner")
		phase.EndTime = time.Now()
		phase.Duration = phase.EndTime.Sub(phase.StartTime)
		phase.Status = "completed"
		phase.Findings = 0
		return findings, phase
	}

	dbLogger.Infow("API endpoints identified",
		"count", len(apiEndpoints),
		"component", "rest_api_scanner",
	)

	// Run REST API scans using Go scanner
	if e.restapiScanner != nil {
		for _, endpoint := range apiEndpoints {
			dbLogger.Debugw("Testing REST API endpoint",
				"endpoint", endpoint,
				"component", "rest_api_scanner",
			)

			apiFindings, err := e.restapiScanner.Scan(ctx, endpoint, nil)
			if err != nil {
				dbLogger.Errorw("REST API scan failed",
					"error", err,
					"endpoint", endpoint,
					"component", "rest_api_scanner",
				)
				continue
			}

			if len(apiFindings) > 0 {
				findings = append(findings, apiFindings...)
				dbLogger.Infow("REST API scan completed",
					"endpoint", endpoint,
					"findings", len(apiFindings),
					"component", "rest_api_scanner",
				)
			} else {
				dbLogger.Debugw("REST API scan completed - no findings",
					"endpoint", endpoint,
					"component", "rest_api_scanner",
				)
			}
		}
	} else {
		dbLogger.Warnw("REST API scanner not initialized - skipping",
			"component", "rest_api_scanner",
		)
	}

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(phase.StartTime)
	phase.Status = "completed"
	phase.Findings = len(findings)

	dbLogger.Infow("REST API testing completed",
		"findings", len(findings),
		"duration", phase.Duration,
		"endpoints_tested", len(apiEndpoints),
		"component", "rest_api_scanner",
	)

	return findings, phase
}

// runNmapScans performs service fingerprinting and port scanning
func (e *BugBountyEngine) runNmapScans(ctx context.Context, assets []*AssetPriority, dbLogger *logger.DBEventLogger) ([]types.Finding, PhaseResult) {
	phaseStart := time.Now()
	phase := PhaseResult{
		Phase:     "nmap",
		Status:    "running",
		StartTime: phaseStart,
	}

	dbLogger.Infow(" Starting Nmap service fingerprinting phase",
		"asset_count", len(assets),
		"component", "nmap_scanner",
	)

	// DIAGNOSTIC: Check context before Nmap execution
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		dbLogger.Infow(" Context status at Nmap phase start",
			"deadline", deadline.Format(time.RFC3339),
			"deadline_unix", deadline.Unix(),
			"remaining_seconds", remaining.Seconds(),
			"remaining_duration", remaining.String(),
			"context_healthy", remaining > 0,
			"component", "nmap_scanner",
		)
		if remaining <= 0 {
			dbLogger.Errorw(" CRITICAL: Context already expired before Nmap phase!",
				"expired_by", (-remaining).String(),
				"component", "nmap_scanner",
			)
		}
	} else {
		dbLogger.Warnw("  No deadline on context before Nmap - unexpected!",
			"component", "nmap_scanner",
		)
	}

	var findings []types.Finding

	// Scan each asset's host
	scannedHosts := make(map[string]bool) // Deduplicate hosts
	totalHosts := 0
	for _, asset := range assets {
		host := extractHost(asset.Asset.Value)
		if host != "" && !scannedHosts[host] {
			totalHosts++
			scannedHosts[host] = true
		}
	}

	dbLogger.Infow(" Nmap scan targets prepared",
		"total_assets", len(assets),
		"unique_hosts", totalHosts,
		"component", "nmap_scanner",
	)

	scannedCount := 0
	for host := range scannedHosts {
		scannedCount++
		scanStart := time.Now()

		dbLogger.Infow(" Scanning host with Nmap",
			"host", host,
			"progress", fmt.Sprintf("%d/%d", scannedCount, totalHosts),
			"elapsed_since_phase_start", time.Since(phaseStart).String(),
			"component", "nmap_scanner",
		)

		// DIAGNOSTIC: Check context status immediately before each Nmap call
		select {
		case <-ctx.Done():
			dbLogger.Errorw(" CRITICAL: Context cancelled before Nmap.Scan()",
				"error", ctx.Err(),
				"host", host,
				"scanned_count", scannedCount,
				"total_hosts", totalHosts,
				"elapsed_since_phase_start", time.Since(phaseStart).String(),
				"component", "nmap_scanner",
			)
			phase.Status = "failed"
			phase.Error = fmt.Sprintf("context cancelled: %v", ctx.Err())
			return findings, phase
		default:
			if deadline, ok := ctx.Deadline(); ok {
				remaining := time.Until(deadline)
				dbLogger.Infow(" Context valid before Nmap.Scan()",
					"host", host,
					"remaining_time", remaining.String(),
					"remaining_seconds", remaining.Seconds(),
					"component", "nmap_scanner",
				)
			}
		}

		// Run Nmap scan
		results, err := e.nmapScanner.Scan(ctx, host, nil)
		scanDuration := time.Since(scanStart)

		if err != nil {
			dbLogger.Errorw(" Nmap scan failed",
				"error", err,
				"host", host,
				"scan_duration", scanDuration.String(),
				"elapsed_since_phase_start", time.Since(phaseStart).String(),
				"component", "nmap_scanner",
			)

			// Check if error was due to context cancellation
			if ctx.Err() != nil {
				dbLogger.Errorw(" Nmap scan failed due to context cancellation",
					"context_error", ctx.Err(),
					"scan_error", err,
					"host", host,
					"component", "nmap_scanner",
				)
			}
			continue
		}

		// Convert results to findings
		findings = append(findings, results...)

		dbLogger.Infow(" Nmap scan completed",
			"host", host,
			"findings", len(results),
			"scan_duration", scanDuration.String(),
			"progress", fmt.Sprintf("%d/%d", scannedCount, totalHosts),
			"elapsed_since_phase_start", time.Since(phaseStart).String(),
			"component", "nmap_scanner",
		)
	}

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(phase.StartTime)
	phase.Status = "completed"
	phase.Findings = len(findings)

	dbLogger.Infow(" Nmap scanning phase completed",
		"total_findings", len(findings),
		"phase_duration", phase.Duration.String(),
		"hosts_scanned", scannedCount,
		"total_hosts", totalHosts,
		"avg_scan_time", fmt.Sprintf("%.2fs", phase.Duration.Seconds()/float64(scannedCount)),
		"component", "nmap_scanner",
	)

	return findings, phase
}

// runNucleiScans performs vulnerability scanning with Nuclei templates
func (e *BugBountyEngine) runNucleiScans(ctx context.Context, assets []*AssetPriority, dbLogger *logger.DBEventLogger) ([]types.Finding, PhaseResult) {
	phaseStart := time.Now()
	phase := PhaseResult{
		Phase:     "nuclei",
		Status:    "running",
		StartTime: phaseStart,
	}

	dbLogger.Infow(" Starting Nuclei vulnerability scanning phase",
		"asset_count", len(assets),
		"component", "nuclei_scanner",
	)

	// Check context status at phase start
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		dbLogger.Infow(" Context status at Nuclei phase start",
			"remaining_time", remaining.String(),
			"remaining_seconds", remaining.Seconds(),
			"context_healthy", remaining > 0,
			"component", "nuclei_scanner",
		)
		if remaining <= 0 {
			dbLogger.Errorw(" CRITICAL: Context already expired before Nuclei phase!",
				"expired_by", (-remaining).String(),
				"component", "nuclei_scanner",
			)
		}
	}

	var findings []types.Finding
	totalAssets := len(assets)

	// Scan high-priority assets
	for idx, asset := range assets {
		scanStart := time.Now()
		progress := fmt.Sprintf("%d/%d", idx+1, totalAssets)

		dbLogger.Infow(" Scanning target with Nuclei",
			"target", asset.Asset.Value,
			"priority_score", asset.Score,
			"progress", progress,
			"elapsed_since_phase_start", time.Since(phaseStart).String(),
			"component", "nuclei_scanner",
		)

		// Check context status before each scan
		select {
		case <-ctx.Done():
			dbLogger.Errorw(" CRITICAL: Context cancelled before Nuclei scan",
				"error", ctx.Err(),
				"target", asset.Asset.Value,
				"progress", progress,
				"elapsed_since_phase_start", time.Since(phaseStart).String(),
				"component", "nuclei_scanner",
			)
			phase.Status = "failed"
			phase.Error = fmt.Sprintf("context cancelled: %v", ctx.Err())
			return findings, phase
		default:
			if deadline, ok := ctx.Deadline(); ok {
				remaining := time.Until(deadline)
				dbLogger.Debugw(" Context valid before Nuclei scan",
					"target", asset.Asset.Value,
					"remaining_time", remaining.String(),
					"component", "nuclei_scanner",
				)
			}
		}

		// Run Nuclei scan
		results, err := e.nucleiScanner.Scan(ctx, asset.Asset.Value, nil)
		scanDuration := time.Since(scanStart)

		if err != nil {
			dbLogger.Errorw(" Nuclei scan failed",
				"error", err,
				"target", asset.Asset.Value,
				"scan_duration", scanDuration.String(),
				"elapsed_since_phase_start", time.Since(phaseStart).String(),
				"component", "nuclei_scanner",
			)

			// Check if error was due to context cancellation
			if ctx.Err() != nil {
				dbLogger.Errorw(" Nuclei scan failed due to context cancellation",
					"context_error", ctx.Err(),
					"scan_error", err,
					"target", asset.Asset.Value,
					"component", "nuclei_scanner",
				)
			}
			continue
		}

		// Convert results to findings
		findings = append(findings, results...)

		dbLogger.Infow(" Nuclei scan completed",
			"target", asset.Asset.Value,
			"findings", len(results),
			"scan_duration", scanDuration.String(),
			"progress", progress,
			"elapsed_since_phase_start", time.Since(phaseStart).String(),
			"component", "nuclei_scanner",
		)
	}

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(phase.StartTime)
	phase.Status = "completed"
	phase.Findings = len(findings)

	avgScanTime := "N/A"
	if totalAssets > 0 {
		avgScanTime = fmt.Sprintf("%.2fs", phase.Duration.Seconds()/float64(totalAssets))
	}

	dbLogger.Infow(" Nuclei scanning phase completed",
		"total_findings", len(findings),
		"phase_duration", phase.Duration.String(),
		"targets_scanned", totalAssets,
		"avg_scan_time", avgScanTime,
		"component", "nuclei_scanner",
	)

	return findings, phase
}

// runGraphQLTests performs GraphQL security testing
func (e *BugBountyEngine) runGraphQLTests(ctx context.Context, assets []*AssetPriority, dbLogger *logger.DBEventLogger) ([]types.Finding, PhaseResult) {
	phase := PhaseResult{
		Phase:     "graphql",
		Status:    "running",
		StartTime: time.Now(),
	}

	dbLogger.Infow(" Running GraphQL security tests",
		"component", "graphql_scanner",
	)

	var findings []types.Finding

	// Extract unique base URLs from assets for GraphQL testing
	// The GraphQL scanner will test common paths like /graphql, /gql, /api/graphql, etc.
	baseURLs := make(map[string]bool)
	for _, asset := range assets {
		// Parse URL to extract base (scheme + host)
		if strings.HasPrefix(asset.Asset.Value, "http://") || strings.HasPrefix(asset.Asset.Value, "https://") {
			// Find the base URL (up to the first path separator after the host)
			parts := strings.SplitN(asset.Asset.Value, "/", 4) // ["https:", "", "example.com", "path..."]
			if len(parts) >= 3 {
				baseURL := parts[0] + "//" + parts[2] // "https://example.com"
				baseURLs[baseURL] = true
			}
		}
	}

	dbLogger.Infow(" Extracted base URLs for GraphQL testing",
		"total_assets", len(assets),
		"unique_base_urls", len(baseURLs),
		"component", "graphql_scanner",
	)

	// Test each base URL - GraphQL scanner will discover endpoints automatically
	graphqlCount := 0
	for baseURL := range baseURLs {
		graphqlCount++
		dbLogger.Infow(" Testing base URL for GraphQL endpoints",
			"url", baseURL,
			"testing_count", fmt.Sprintf("%d/%d", graphqlCount, len(baseURLs)),
			"component", "graphql_scanner",
		)

		// Run Go GraphQL scanner - it will test multiple common GraphQL paths
		results, err := e.graphqlScanner.Scan(ctx, baseURL, nil)
		if err != nil {
			dbLogger.Errorw(" GraphQL scan failed",
				"error", err,
				"url", baseURL,
				"component", "graphql_scanner",
			)
			continue
		}

		// Convert results to findings
		findings = append(findings, results...)

		dbLogger.Infow(" Go GraphQL scan completed",
			"url", baseURL,
			"findings", len(results),
			"component", "graphql_scanner",
		)

		// Also run Python GraphCrawler if available
		if e.pythonWorkers != nil {
			dbLogger.Infow(" Running Python GraphCrawler",
				"url", baseURL,
				"component", "graphcrawler",
			)

			jobStatus, err := e.pythonWorkers.ScanGraphQLSync(ctx, baseURL, nil)
			if err != nil {
				dbLogger.Errorw(" GraphCrawler scan failed",
					"error", err,
					"url", baseURL,
					"component", "graphcrawler",
				)
			} else if jobStatus.Status == "completed" && jobStatus.Result != nil {
				// Convert Python worker results to findings
				pythonFindings := convertPythonGraphQLToFindings(jobStatus.Result, baseURL)
				findings = append(findings, pythonFindings...)

				dbLogger.Infow(" GraphCrawler scan completed",
					"url", baseURL,
					"findings", len(pythonFindings),
					"component", "graphcrawler",
				)
			}
		}
	}

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(phase.StartTime)
	phase.Status = "completed"
	phase.Findings = len(findings)

	dbLogger.Infow(" GraphQL testing completed",
		"findings", len(findings),
		"duration", phase.Duration.String(),
		"endpoints_tested", graphqlCount,
		"component", "graphql_scanner",
	)

	return findings, phase
}

// runIDORTests performs IDOR vulnerability testing using Python workers
func (e *BugBountyEngine) runIDORTests(ctx context.Context, assets []*AssetPriority, dbLogger *logger.DBEventLogger) ([]types.Finding, PhaseResult) {
	phase := PhaseResult{
		Phase:     "idor",
		Status:    "running",
		StartTime: time.Now(),
	}

	dbLogger.Infow("Running IDOR vulnerability tests", "component", "idor_scanner")

	var findings []types.Finding

	// Find potential IDOR endpoints (those with IDs in URL or query params)
	idorEndpoints := []string{}
	for _, asset := range assets {
		url := asset.Asset.Value
		// Look for numeric IDs, UUIDs, or query parameters in URLs
		if containsPattern(url, `\/\d+`) ||
		   containsPattern(url, `[a-f0-9-]{36}`) ||
		   strings.Contains(url, "id=") ||
		   strings.Contains(url, "user_id=") ||
		   strings.Contains(url, "userId=") {
			idorEndpoints = append(idorEndpoints, url)
		}
	}

	if len(idorEndpoints) == 0 {
		dbLogger.Infow("No IDOR candidates found", "component", "idor_scanner")
		phase.EndTime = time.Now()
		phase.Duration = phase.EndTime.Sub(phase.StartTime)
		phase.Status = "completed"
		phase.Findings = 0
		return findings, phase
	}

	dbLogger.Infow("IDOR candidates identified",
		"count", len(idorEndpoints),
		"component", "idor_scanner",
	)

	// Run IDOR scans using Go scanner
	for _, endpoint := range idorEndpoints {
		dbLogger.Debugw("Testing IDOR endpoint",
			"endpoint", endpoint,
			"component", "idor_scanner",
		)

		// Use Go IDOR scanner
		idorFindings, err := e.idorScanner.Scan(ctx, endpoint, nil)
		if err != nil {
			dbLogger.Errorw("IDOR scan failed",
				"error", err,
				"endpoint", endpoint,
				"component", "idor_scanner",
			)
			continue
		}

		if len(idorFindings) > 0 {
			findings = append(findings, idorFindings...)
			dbLogger.Infow("IDOR scan completed",
				"endpoint", endpoint,
				"findings", len(idorFindings),
				"component", "idor_scanner",
			)
		} else {
			dbLogger.Debugw("IDOR scan completed - no findings",
				"endpoint", endpoint,
				"component", "idor_scanner",
			)
		}
	}

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(phase.StartTime)
	phase.Status = "completed"
	phase.Findings = len(findings)

	dbLogger.Infow("IDOR testing completed",
		"findings", len(findings),
		"duration", phase.Duration,
		"endpoints_tested", len(idorEndpoints),
		"component", "idor_scanner",
	)

	return findings, phase
}

// convertPythonGraphQLToFindings converts GraphCrawler results to findings
func convertPythonGraphQLToFindings(result map[string]interface{}, target string) []types.Finding {
	var findings []types.Finding

	// Extract findings from GraphCrawler result
	if rawOutput, ok := result["raw_output"].(string); ok && rawOutput != "" {
		// GraphCrawler found something
		findings = append(findings, types.Finding{
			ID:          uuid.New().String(),
			Tool:        "graphcrawler",
			Type:        "GraphQL Introspection",
			Severity:    types.SeverityMedium,
			Title:       "GraphQL Schema Exposed via Introspection",
			Description: "GraphQL introspection is enabled, exposing the complete schema including queries, mutations, and types. Target: " + target,
			Evidence:    rawOutput,
			Solution:    "Disable GraphQL introspection in production environments",
			CreatedAt:   time.Now(),
		})
	}

	return findings
}

// convertPythonIDORToFindings converts IDOR scanner results to findings
func convertPythonIDORToFindings(result map[string]interface{}, target string) []types.Finding {
	var findings []types.Finding

	// Extract IDOR findings
	if findingsData, ok := result["findings"].([]interface{}); ok {
		for _, item := range findingsData {
			if f, ok := item.(map[string]interface{}); ok {
				// Parse severity
				severity := types.SeverityMedium // default
				if sev, ok := f["severity"].(string); ok {
					switch strings.ToUpper(sev) {
					case "CRITICAL":
						severity = types.SeverityCritical
					case "HIGH":
						severity = types.SeverityHigh
					case "MEDIUM":
						severity = types.SeverityMedium
					case "LOW":
						severity = types.SeverityLow
					}
				}

				finding := types.Finding{
					ID:          uuid.New().String(),
					Tool:        "idor-scanner",
					Type:        "IDOR",
					Severity:    severity,
					Title:       "Insecure Direct Object Reference Vulnerability",
					Description: fmt.Sprintf("%v. Target: %v", f["description"], f["url"]),
					Evidence:    fmt.Sprintf("User ID: %v", f["user_id"]),
					Solution:    "Implement proper authorization checks to ensure users can only access their own resources",
					CreatedAt:   time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// containsPattern checks if string matches regex pattern
func containsPattern(s, pattern string) bool {
	// Simple pattern matching - in production use proper regex
	return strings.Contains(s, pattern)
}

// extractHost extracts the host from a URL
func extractHost(urlStr string) string {
	// Simple extraction - just get the host part
	if !strings.Contains(urlStr, "://") {
		urlStr = "http://" + urlStr
	}

	// Parse URL
	parts := strings.Split(urlStr, "://")
	if len(parts) < 2 {
		return ""
	}

	hostPort := strings.Split(parts[1], "/")[0]
	host := strings.Split(hostPort, ":")[0]

	return host
}

// storeResults saves scan results to the database
func (e *BugBountyEngine) storeResults(ctx context.Context, scanID string, result *BugBountyResult) error {
	// Prepare scan configuration for storage
	configJSON := map[string]interface{}{
		"discovery_timeout":          e.config.DiscoveryTimeout.String(),
		"scan_timeout":               e.config.ScanTimeout.String(),
		"total_timeout":              e.config.TotalTimeout.String(),
		"max_assets":                 e.config.MaxAssets,
		"max_depth":                  e.config.MaxDepth,
		"enable_port_scan":           e.config.EnablePortScan,
		"enable_web_crawl":           e.config.EnableWebCrawl,
		"enable_dns":                 e.config.EnableDNS,
		"enable_subdomain_enum":      e.config.EnableSubdomainEnum,
		"enable_cert_transparency":   e.config.EnableCertTransparency,
		"enable_whois_analysis":      e.config.EnableWHOISAnalysis,
		"enable_related_domain_disc": e.config.EnableRelatedDomainDisc,
		"enable_auth_testing":        e.config.EnableAuthTesting,
		"enable_api_testing":         e.config.EnableAPITesting,
		"enable_scim_testing":        e.config.EnableSCIMTesting,
		"enable_graphql_testing":     e.config.EnableGraphQLTesting,
		"enable_nuclei_scan":         e.config.EnableNucleiScan,
		"enable_service_fingerprint": e.config.EnableServiceFingerprint,
	}

	// Prepare results summary for storage
	resultJSON := map[string]interface{}{
		"scan_id":         result.ScanID,
		"target":          result.Target,
		"start_time":      result.StartTime,
		"end_time":        result.EndTime,
		"duration":        result.Duration.String(),
		"status":          result.Status,
		"discovered_at":   result.DiscoveredAt,
		"tested_assets":   result.TestedAssets,
		"total_findings":  result.TotalFindings,
		"phase_results":   result.PhaseResults,
		"findings_by_severity": map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
			"info":     0,
		},
	}

	// Count findings by severity
	severityCounts := resultJSON["findings_by_severity"].(map[string]int)
	for _, finding := range result.Findings {
		switch strings.ToUpper(string(finding.Severity)) {
		case "CRITICAL":
			severityCounts["critical"]++
		case "HIGH":
			severityCounts["high"]++
		case "MEDIUM":
			severityCounts["medium"]++
		case "LOW":
			severityCounts["low"]++
		default:
			severityCounts["info"]++
		}
	}

	// Save scan metadata with config and results
	startedAt := result.StartTime
	completedAt := result.EndTime
	scan := &types.ScanRequest{
		ID:          scanID,
		Target:      result.Target,
		Type:        types.ScanTypeAuth, // Using ScanTypeAuth for now
		Status:      types.ScanStatusCompleted,
		CreatedAt:   result.StartTime,
		StartedAt:   &startedAt, // Set started time for duration calculation
		CompletedAt: &completedAt,
		Config:      configJSON, // Store scan configuration
		Result:      resultJSON, // Store scan results summary
	}

	if err := e.store.SaveScan(ctx, scan); err != nil {
		return fmt.Errorf("failed to save scan: %w", err)
	}

	// TASK 14: Enrich findings before saving
	if len(result.Findings) > 0 {
		if e.enricher != nil {
			e.logger.Infow("Enriching findings with CVSS, exploits, and remediation guidance...",
				"findings_count", len(result.Findings),
				"enrichment_level", e.config.EnrichmentLevel,
			)

			enrichedFindings, err := e.enricher.EnrichFindings(ctx, result.Findings)
			if err != nil {
				e.logger.Warnw("Enrichment failed - saving findings without enrichment",
					"error", err,
					"findings_count", len(result.Findings),
				)
			} else {
				// Convert enriched findings back to types.Finding with metadata
				for i := range result.Findings {
					if enrichedFindings[i].CVSSScore != nil {
						if result.Findings[i].Metadata == nil {
							result.Findings[i].Metadata = make(map[string]interface{})
						}
						result.Findings[i].Metadata["cvss_score"] = enrichedFindings[i].CVSSScore.BaseScore
						result.Findings[i].Metadata["cvss_vector"] = enrichedFindings[i].CVSSScore.Vector
						result.Findings[i].Metadata["cvss_severity"] = enrichedFindings[i].CVSSScore.Severity
					}

					if enrichedFindings[i].ExploitInfo != nil && enrichedFindings[i].ExploitInfo.ExploitAvailable {
						if result.Findings[i].Metadata == nil {
							result.Findings[i].Metadata = make(map[string]interface{})
						}
						result.Findings[i].Metadata["exploit_available"] = true
						result.Findings[i].Metadata["exploit_count"] = enrichedFindings[i].ExploitInfo.ExploitCount
					}

					if enrichedFindings[i].Remediation != nil {
						// Update solution with enhanced remediation guidance
						if enrichedFindings[i].Remediation.Summary != "" {
							result.Findings[i].Solution = enrichedFindings[i].Remediation.Summary
						}
						if result.Findings[i].Metadata == nil {
							result.Findings[i].Metadata = make(map[string]interface{})
						}
						result.Findings[i].Metadata["remediation_priority"] = enrichedFindings[i].Remediation.Priority
						result.Findings[i].Metadata["estimated_effort"] = enrichedFindings[i].Remediation.EstimatedEffort
					}
				}

				e.logger.Infow("Findings enriched successfully",
					"enriched_count", len(enrichedFindings),
				)
			}
		}

		// Set scan ID for all findings
		for i := range result.Findings {
			result.Findings[i].ScanID = scanID
		}

		if err := e.store.SaveFindings(ctx, result.Findings); err != nil {
			return fmt.Errorf("failed to save findings: %w", err)
		}
	}

	return nil
}

// Helper functions

func containsAny(s string, substrs []string) bool {
	s = strings.ToLower(s)
	for _, substr := range substrs {
		if strings.Contains(s, strings.ToLower(substr)) {
			return true
		}
	}
	return false
}

// convertVulnerabilityToFinding converts auth.common.Vulnerability to types.Finding
func convertVulnerabilityToFinding(vuln interface{}, target string) types.Finding {
	// Type assertion to access actual vulnerability fields
	v, ok := vuln.(struct {
		ID          string
		Type        string
		Protocol    string
		Severity    string
		Title       string
		Description string
		Impact      string
		Evidence    []interface{}
		References  []string
		CVSS        float64
		CWE         string
	})

	if !ok {
		// Fallback if type assertion fails
		return types.Finding{
			ID:          fmt.Sprintf("finding-%d", time.Now().UnixNano()),
			ScanID:      "current-scan",
			Type:        "UNKNOWN_VULNERABILITY",
			Severity:    types.SeverityMedium,
			Title:       "Vulnerability detected",
			Description: fmt.Sprintf("Vulnerability found in %s", target),
			Tool:        "auth-scanner",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
	}

	// Map severity string to types.Severity
	severity := mapSeverity(v.Severity)

	// Build evidence string from array
	evidenceStr := ""
	if len(v.Evidence) > 0 {
		evidenceStr = fmt.Sprintf("%v", v.Evidence)
	}

	// Build metadata map
	metadata := map[string]interface{}{
		"cvss":     v.CVSS,
		"cwe":      v.CWE,
		"protocol": v.Protocol,
		"impact":   v.Impact,
	}

	return types.Finding{
		ID:          v.ID,
		ScanID:      "current-scan",
		Type:        v.Type,
		Severity:    severity,
		Title:       v.Title,
		Description: v.Description,
		Evidence:    evidenceStr,
		Solution:    "", // Auth vulnerabilities don't have solution field, would come from Remediation
		References:  v.References,
		Metadata:    metadata,
		Tool:        fmt.Sprintf("auth-%s", strings.ToLower(v.Protocol)),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// mapSeverity maps severity strings to types.Severity constants
func mapSeverity(severityStr string) types.Severity {
	switch strings.ToUpper(severityStr) {
	case "CRITICAL":
		return types.SeverityCritical
	case "HIGH":
		return types.SeverityHigh
	case "MEDIUM":
		return types.SeverityMedium
	case "LOW":
		return types.SeverityLow
	case "INFO", "INFORMATIONAL":
		return types.SeverityInfo
	default:
		// Default to medium if unknown
		return types.SeverityMedium
	}
}

// GetRateLimiter returns the rate limiter for use by scanners
// Scanners should call rateLimiter.Wait(ctx) before making HTTP requests
func (e *BugBountyEngine) GetRateLimiter() *ratelimit.Limiter {
	return e.rateLimiter
}

// loggerAdapter adapts internal logger to auth package logger interface
type loggerAdapter struct {
	logger *logger.Logger
}

func (l *loggerAdapter) Debug(msg string, keysAndValues ...interface{}) {
	l.logger.Debugw(msg, keysAndValues...)
}

func (l *loggerAdapter) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Infow(msg, keysAndValues...)
}

func (l *loggerAdapter) Warn(msg string, keysAndValues ...interface{}) {
	l.logger.Warnw(msg, keysAndValues...)
}

func (l *loggerAdapter) Error(msg string, keysAndValues ...interface{}) {
	l.logger.Errorw(msg, keysAndValues...)
}

// IDORScannerAdapter adapts the IDOR scanner to core.Scanner interface
type IDORScannerAdapter struct {
	scanner *idor.IDORScanner
	logger  *logger.Logger
}

// NewIDORScannerAdapter creates a new IDOR scanner adapter
func NewIDORScannerAdapter(config idor.IDORConfig, log *logger.Logger) *IDORScannerAdapter {
	// Create adapter for IDOR scanner logger
	idorLogger := &idorLoggerAdapter{logger: log}
	scanner := idor.NewIDORScanner(config, idorLogger)
	return &IDORScannerAdapter{
		scanner: scanner,
		logger:  log,
	}
}

func (a *IDORScannerAdapter) Name() string {
	return "IDOR Scanner"
}

func (a *IDORScannerAdapter) Type() types.ScanType {
	return types.ScanTypeAuth
}

func (a *IDORScannerAdapter) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	idorFindings, err := a.scanner.Scan(ctx, target)
	if err != nil {
		return nil, err
	}

	findings := make([]types.Finding, 0, len(idorFindings))
	for _, idorFinding := range idorFindings {
		finding := types.Finding{
			ID:          fmt.Sprintf("idor-%s", uuid.New().String()[:8]),
			Tool:        "idor",
			Type:        idorFinding.FindingType,
			Severity:    idorFinding.Severity,
			Title:       fmt.Sprintf("IDOR: %s", idorFinding.Description),
			Description: fmt.Sprintf("%s\n\nImpact: %s", idorFinding.Evidence, idorFinding.Impact),
			Evidence:    idorFinding.Evidence,
			Solution:    idorFinding.Remediation,
			Metadata: map[string]interface{}{
				"url":           idorFinding.URL,
				"method":        idorFinding.Method,
				"original_id":   idorFinding.OriginalID,
				"accessible_id": idorFinding.AccessibleID,
				"status_code":   idorFinding.StatusCode,
				"response_size": idorFinding.ResponseSize,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func (a *IDORScannerAdapter) Validate(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	return nil
}

// idorLoggerAdapter adapts internal logger to IDOR scanner logger interface
type idorLoggerAdapter struct {
	logger *logger.Logger
}

func (l *idorLoggerAdapter) Debug(msg string, keysAndValues ...interface{}) {
	l.logger.Debugw(msg, keysAndValues...)
}

func (l *idorLoggerAdapter) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Infow(msg, keysAndValues...)
}

func (l *idorLoggerAdapter) Warn(msg string, keysAndValues ...interface{}) {
	l.logger.Warnw(msg, keysAndValues...)
}

func (l *idorLoggerAdapter) Error(msg string, keysAndValues ...interface{}) {
	l.logger.Errorw(msg, keysAndValues...)
}

// RESTAPIScannerAdapter adapts restapi.RESTAPIScanner to core.Scanner interface
type RESTAPIScannerAdapter struct {
	scanner *restapi.RESTAPIScanner
	logger  *logger.Logger
}

func NewRESTAPIScannerAdapter(config restapi.RESTAPIConfig, log *logger.Logger) *RESTAPIScannerAdapter {
	restapiLogger := &restapiLoggerAdapter{logger: log}
	scanner := restapi.NewRESTAPIScanner(config, restapiLogger)
	return &RESTAPIScannerAdapter{scanner: scanner, logger: log}
}

func (a *RESTAPIScannerAdapter) Name() string {
	return "rest_api"
}

func (a *RESTAPIScannerAdapter) Type() types.ScanType {
	return types.ScanTypeWeb
}

func (a *RESTAPIScannerAdapter) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	apiFindings, err := a.scanner.Scan(ctx, target)
	if err != nil {
		return nil, err
	}

	findings := make([]types.Finding, 0, len(apiFindings))
	for _, apiFinding := range apiFindings {
		finding := types.Finding{
			ID:          fmt.Sprintf("restapi-%s", uuid.New().String()[:8]),
			Tool:        "rest_api",
			Type:        apiFinding.FindingType,
			Severity:    apiFinding.Severity,
			Title:       fmt.Sprintf("REST API: %s", apiFinding.Description),
			Description: fmt.Sprintf("%s\n\nImpact: %s", apiFinding.Evidence, apiFinding.Impact),
			Evidence:    apiFinding.Evidence,
			Solution:    apiFinding.Remediation,
			Metadata: map[string]interface{}{
				"url":              apiFinding.URL,
				"method":           apiFinding.Method,
				"endpoint":         apiFinding.Endpoint,
				"status_code":      apiFinding.StatusCode,
				"payload":          apiFinding.Payload,
				"response":         apiFinding.Response,
				"confidence_score": apiFinding.ConfidenceScore,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func (a *RESTAPIScannerAdapter) Validate(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	return nil
}

// restapiLoggerAdapter adapts internal logger to REST API scanner logger interface
type restapiLoggerAdapter struct {
	logger *logger.Logger
}

func (l *restapiLoggerAdapter) Debug(msg string, keysAndValues ...interface{}) {
	l.logger.Debugw(msg, keysAndValues...)
}

func (l *restapiLoggerAdapter) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Infow(msg, keysAndValues...)
}

func (l *restapiLoggerAdapter) Warn(msg string, keysAndValues ...interface{}) {
	l.logger.Warnw(msg, keysAndValues...)
}

func (l *restapiLoggerAdapter) Error(msg string, keysAndValues ...interface{}) {
	l.logger.Errorw(msg, keysAndValues...)
}

// ResumeFromCheckpoint resumes a scan from a saved checkpoint, skipping completed phases
// TASK 10: Implements intelligent resume that skips already-completed work

// displayOrganizationFootprinting displays user-friendly organization footprinting results to CLI
func (e *BugBountyEngine) displayOrganizationFootprinting(org *correlation.Organization, duration time.Duration) {
	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("  Organization Footprinting Results")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	if org.Name != "" {
		fmt.Printf("✓ Organization: %s\n", org.Name)
	} else {
		fmt.Println("⚠  Organization name not found")
	}

	fmt.Printf("✓ Confidence Score: %.0f%%\n", org.Confidence*100)
	fmt.Printf("✓ Duration: %s\n", duration.Round(time.Millisecond))

	if len(org.Domains) > 0 {
		fmt.Printf("\n  Related Domains (%d found):\n", len(org.Domains))
		// Show max 10 domains to avoid cluttering output
		maxDisplay := len(org.Domains)
		if maxDisplay > 10 {
			maxDisplay = 10
		}
		for i := 0; i < maxDisplay; i++ {
			if i == 0 {
				fmt.Printf("    • %s (primary)\n", org.Domains[i])
			} else {
				fmt.Printf("    • %s\n", org.Domains[i])
			}
		}
		if len(org.Domains) > 10 {
			fmt.Printf("    ... and %d more domains\n", len(org.Domains)-10)
		}
	} else {
		fmt.Println("\n  Related Domains: None discovered")
	}

	if len(org.Certificates) > 0 {
		fmt.Printf("\n  SSL/TLS Certificates: %d found\n", len(org.Certificates))
		// Show first certificate details
		cert := org.Certificates[0]
		fmt.Printf("    • Subject: %s\n", cert.Subject)
		fmt.Printf("    • Issuer: %s\n", cert.Issuer)
		if len(cert.SANs) > 0 {
			fmt.Printf("    • SANs: %d domains\n", len(cert.SANs))
		}
		if len(org.Certificates) > 1 {
			fmt.Printf("    ... and %d more certificates\n", len(org.Certificates)-1)
		}
	}

	if len(org.ASNs) > 0 {
		fmt.Printf("\n  Autonomous Systems: %d found\n", len(org.ASNs))
		for _, asn := range org.ASNs {
			fmt.Printf("    • %s\n", asn)
		}
	}

	if len(org.IPRanges) > 0 {
		fmt.Printf("\n  IP Ranges: %d found\n", len(org.IPRanges))
		for _, ipRange := range org.IPRanges {
			fmt.Printf("    • %s\n", ipRange)
		}
	}

	fmt.Printf("\n  Data Sources: %s\n", strings.Join(org.Sources, ", "))
	fmt.Println("═══════════════════════════════════════════════════════════════\n")
}

// displayDiscoveryResults displays user-friendly asset discovery results to CLI
func (e *BugBountyEngine) displayDiscoveryResults(assets []*discovery.Asset, duration time.Duration) {
	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("  Asset Discovery Results")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	fmt.Printf("✓ Total Assets: %d\n", len(assets))
	fmt.Printf("✓ Duration: %s\n", duration.Round(time.Millisecond))

	// Group assets by type
	assetsByType := make(map[discovery.AssetType][]*discovery.Asset)
	for _, asset := range assets {
		assetsByType[asset.Type] = append(assetsByType[asset.Type], asset)
	}

	// Display URLs/Endpoints
	if urls, ok := assetsByType[discovery.AssetTypeURL]; ok && len(urls) > 0 {
		fmt.Printf("\n  Web Endpoints (%d):\n", len(urls))
		maxDisplay := len(urls)
		if maxDisplay > 10 {
			maxDisplay = 10
		}
		for i := 0; i < maxDisplay; i++ {
			fmt.Printf("    • %s\n", urls[i].Value)
		}
		if len(urls) > 10 {
			fmt.Printf("    ... and %d more endpoints\n", len(urls)-10)
		}
	}

	// Display domains
	if domains, ok := assetsByType[discovery.AssetTypeDomain]; ok && len(domains) > 0 {
		fmt.Printf("\n  Domains (%d):\n", len(domains))
		maxDisplay := len(domains)
		if maxDisplay > 10 {
			maxDisplay = 10
		}
		for i := 0; i < maxDisplay; i++ {
			fmt.Printf("    • %s\n", domains[i].Value)
		}
		if len(domains) > 10 {
			fmt.Printf("    ... and %d more domains\n", len(domains)-10)
		}
	}

	// Display IPs
	if ips, ok := assetsByType[discovery.AssetTypeIP]; ok && len(ips) > 0 {
		fmt.Printf("\n  IP Addresses (%d):\n", len(ips))
		maxDisplay := len(ips)
		if maxDisplay > 5 {
			maxDisplay = 5
		}
		for i := 0; i < maxDisplay; i++ {
			fmt.Printf("    • %s\n", ips[i].Value)
		}
		if len(ips) > 5 {
			fmt.Printf("    ... and %d more IPs\n", len(ips)-5)
		}
	}

	// Display services
	if services, ok := assetsByType[discovery.AssetTypeService]; ok && len(services) > 0 {
		fmt.Printf("\n  Services (%d):\n", len(services))
		maxDisplay := len(services)
		if maxDisplay > 10 {
			maxDisplay = 10
		}
		for i := 0; i < maxDisplay; i++ {
			service := services[i]
			if service.Port > 0 && service.Protocol != "" {
				fmt.Printf("    • %s:%d (%s)\n", service.Value, service.Port, service.Protocol)
			} else if service.Port > 0 {
				fmt.Printf("    • %s:%d\n", service.Value, service.Port)
			} else {
				fmt.Printf("    • %s\n", service.Value)
			}
		}
		if len(services) > 10 {
			fmt.Printf("    ... and %d more services\n", len(services)-10)
		}
	}

	fmt.Println("═══════════════════════════════════════════════════════════════\n")
}

// displayScanSummary displays final scan results summary to CLI
func (e *BugBountyEngine) displayScanSummary(result *BugBountyResult) {
	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("  Scan Complete!")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	fmt.Printf("  Scan ID: %s\n", result.ScanID)
	fmt.Printf("  Target: %s\n", result.Target)
	fmt.Printf("  Duration: %s\n", result.Duration.Round(time.Millisecond))

	// Group findings by severity
	severityCounts := make(map[string]int)
	for _, finding := range result.Findings {
		severityCounts[string(finding.Severity)]++
	}

	fmt.Printf("\n  Findings: %d total\n", len(result.Findings))
	if critical, ok := severityCounts["CRITICAL"]; ok && critical > 0 {
		fmt.Printf("    • CRITICAL: %d\n", critical)
	}
	if high, ok := severityCounts["HIGH"]; ok && high > 0 {
		fmt.Printf("    • HIGH: %d\n", high)
	}
	if medium, ok := severityCounts["MEDIUM"]; ok && medium > 0 {
		fmt.Printf("    • MEDIUM: %d\n", medium)
	}
	if low, ok := severityCounts["LOW"]; ok && low > 0 {
		fmt.Printf("    • LOW: %d\n", low)
	}
	if len(result.Findings) == 0 {
		fmt.Println("    • No vulnerabilities found")
	}

	// Show sample findings
	if len(result.Findings) > 0 {
		fmt.Println("\n  Top Findings:")
		maxDisplay := len(result.Findings)
		if maxDisplay > 5 {
			maxDisplay = 5
		}
		for i := 0; i < maxDisplay; i++ {
			finding := result.Findings[i]
			fmt.Printf("\n    [%s] %s\n", finding.Severity, finding.Title)
			fmt.Printf("      Tool: %s | Type: %s\n", finding.Tool, finding.Type)
			if finding.Description != "" && len(finding.Description) < 100 {
				fmt.Printf("      %s\n", finding.Description)
			}
		}
		if len(result.Findings) > 5 {
			fmt.Printf("\n    ... and %d more findings\n", len(result.Findings)-5)
		}
	}

	fmt.Println("\n  Next Steps:")
	fmt.Printf("    • View detailed results: shells results show %s\n", result.ScanID)
	fmt.Printf("    • Export report: shells results export %s --format html\n", result.ScanID)
	fmt.Printf("    • Web dashboard: http://localhost:8080 (if server running)\n")

	fmt.Println("═══════════════════════════════════════════════════════════════\n")
}

// streamHighSeverityFinding displays critical/high findings immediately to CLI
// This provides real-time feedback during scans instead of waiting until the end
func streamHighSeverityFinding(finding types.Finding) {
	// Only stream CRITICAL and HIGH severity findings
	if finding.Severity != types.SeverityCritical && finding.Severity != types.SeverityHigh {
		return
	}

	// Color coding for severity
	severityStr := fmt.Sprintf("[%s]", finding.Severity)
	if finding.Severity == types.SeverityCritical {
		severityStr = fmt.Sprintf("\033[1;31m[CRITICAL]\033[0m") // Bold Red
	} else if finding.Severity == types.SeverityHigh {
		severityStr = fmt.Sprintf("\033[1;33m[HIGH]\033[0m") // Bold Yellow
	}

	// Immediate CLI output
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf(" %s VULNERABILITY FOUND\n", severityStr)
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("   Title: %s\n", finding.Title)
	fmt.Printf("   Type: %s\n", finding.Type)
	fmt.Printf("   Tool: %s\n", finding.Tool)
	fmt.Printf("   Severity: %s\n", finding.Severity)
	if finding.Description != "" {
		// Truncate long descriptions
		desc := finding.Description
		if len(desc) > 200 {
			desc = desc[:197] + "..."
		}
		fmt.Printf("   Description: %s\n", desc)
	}
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()
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
//   Old way: engine.Execute(ctx, target) // Chaotic, no clear phases
//   New way: engine.ExecuteWithPipeline(ctx, target) // Kill Chain aligned, iterative
//
// MIGRATION PATH:
//   1. Update cmd/root.go to call ExecuteWithPipeline instead of Execute
//   2. Test with: shells example.com --use-pipeline
//   3. Once stable, make ExecuteWithPipeline the default
//   4. Deprecate old Execute() method
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
