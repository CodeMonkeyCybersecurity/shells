// internal/orchestrator/bounty_engine.go
package orchestrator

import (
	"context"
	"fmt"
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
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scim"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/workers"
	"github.com/google/uuid"
)

// BugBountyEngine orchestrates the full bug bounty scanning pipeline
type BugBountyEngine struct {
	// Core services
	store       core.ResultStore
	telemetry   core.Telemetry
	logger      *logger.Logger
	rateLimiter *ratelimit.Limiter

	// Discovery
	discoveryEngine *discovery.Engine

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

	// Python worker client (optional - for GraphCrawler and IDOR)
	pythonWorkers *workers.Client

	// Configuration
	config BugBountyConfig
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

	// Rate limiting settings
	RateLimitPerSecond float64
	RateLimitBurst     int

	// Output settings
	ShowProgress bool
	Verbose      bool
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

		// Respectful rate limiting (won't trigger WAFs but still comprehensive)
		RateLimitPerSecond: 10.0, // 10 requests per second
		RateLimitBurst:     20,   // Allow bursts of 20 for parallel operations

		// User experience
		ShowProgress: true,  // Show real-time progress updates
		Verbose:      false, // Concise output (use --log-level debug for verbose)
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

	// Initialize Nuclei scanner (if enabled)
	var nucleiScanner core.Scanner
	if config.EnableNucleiScan {
		nucleiConfig := nuclei.NucleiConfig{
			BinaryPath:    "nuclei",
			TemplatesPath: "", // Use default
			Timeout:       config.ScanTimeout,
			RateLimit:     int(config.RateLimitPerSecond),
			BulkSize:      25,
			Concurrency:   25,
			Retries:       2,
		}
		nucleiScanner = nuclei.NewScanner(nucleiConfig, samlLogger)
		logger.Infow("Nuclei scanner initialized", "component", "orchestrator")
	}

	// Initialize GraphQL scanner (if enabled)
	var graphqlScanner core.Scanner
	if config.EnableGraphQLTesting {
		graphqlScanner = api.NewGraphQLScanner(samlLogger)
		logger.Infow("GraphQL scanner initialized", "component", "orchestrator")
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
		logger.Warnw("Python worker service not available - IDOR and GraphCrawler testing disabled",
			"error", err,
			"worker_url", workerURL,
			"note", "Run 'shells serve' or 'shells workers start' to enable Python-based testing",
		)
		pythonWorkers = nil // Disable if not available
	} else {
		logger.Infow("Python worker service connected",
			"worker_url", workerURL,
			"capabilities", []string{"GraphCrawler", "IDOR"},
		)
	}

	return &BugBountyEngine{
		store:           store,
		telemetry:       telemetry,
		logger:          logger,
		rateLimiter:     rateLimiter,
		discoveryEngine: discoveryEngine,
		samlScanner:     samlScanner,
		oauth2Scanner:   oauth2Scanner,
		webauthnScanner: webauthnScanner,
		scimScanner:     scimScanner,
		authDiscovery:   authDiscovery,
		nmapScanner:     nmapScanner,
		nucleiScanner:   nucleiScanner,
		graphqlScanner:  graphqlScanner,
		pythonWorkers:   pythonWorkers,
		config:          config,
	}, nil
}

// BugBountyResult contains the complete results of a bug bounty scan
type BugBountyResult struct {
	ScanID        string
	Target        string
	StartTime     time.Time
	EndTime       time.Time
	Duration      time.Duration
	Status        string
	DiscoveredAt  int // Number of discovered assets
	TestedAssets  int
	TotalFindings int
	Findings      []types.Finding
	PhaseResults  map[string]PhaseResult
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

	e.logger.Infow("🎯 Starting bug bounty scan",
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

	// Initialize progress tracker
	tracker := progress.New(e.config.ShowProgress, e.logger)
	tracker.AddPhase("discovery", "Discovering assets")
	tracker.AddPhase("prioritization", "Prioritizing targets")
	tracker.AddPhase("testing", "Testing for vulnerabilities")
	tracker.AddPhase("storage", "Storing results")

	// Create scan record with UUID to prevent collisions
	scanID := fmt.Sprintf("bounty-%d-%s", time.Now().Unix(), uuid.New().String()[:8])
	result := &BugBountyResult{
		ScanID:       scanID,
		Target:       target,
		StartTime:    time.Now(),
		Status:       "running",
		PhaseResults: make(map[string]PhaseResult),
		Findings:     []types.Finding{},
	}

	e.logger.Infow("📋 Scan initialized",
		"scan_id", scanID,
		"start_time", result.StartTime.Format(time.RFC3339),
	)

	// Apply total timeout
	ctx, cancel := context.WithTimeout(ctx, e.config.TotalTimeout)
	defer cancel()

	// Log initial context state
	if deadline, ok := ctx.Deadline(); ok {
		e.logger.Infow(" Total timeout context created",
			"total_timeout", e.config.TotalTimeout.String(),
			"deadline", deadline.Format(time.RFC3339),
			"deadline_unix", deadline.Unix(),
			"time_until_deadline", time.Until(deadline).String(),
		)
	} else {
		e.logger.Warnw("⚠️  No deadline on parent context - unexpected!")
	}

	// Phase 1: Asset Discovery (or skip if configured)
	var assets []*discovery.Asset
	var phaseResult PhaseResult

	if e.config.SkipDiscovery {
		// Quick mode: Use target directly without discovery
		e.logger.Infow("⏭️  Skipping discovery (quick mode)",
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
		e.logger.Infow(" Phase 1: Starting full discovery",
			"target", target,
			"discovery_timeout", e.config.DiscoveryTimeout.String(),
			"enable_dns", e.config.EnableDNS,
			"enable_subdomain_enum", e.config.EnableSubdomainEnum,
			"enable_cert_transparency", e.config.EnableCertTransparency,
			"elapsed_since_scan_start", time.Since(execStart).String(),
		)

		tracker.StartPhase("discovery")
		assets, phaseResult = e.executeDiscoveryPhase(ctx, target, tracker)

		discoveryDuration := time.Since(discoveryStart)
		e.logger.Infow(" Discovery phase completed",
			"status", phaseResult.Status,
			"assets_discovered", len(assets),
			"discovery_duration", discoveryDuration.String(),
			"elapsed_since_scan_start", time.Since(execStart).String(),
		)

		result.PhaseResults["discovery"] = phaseResult
		result.DiscoveredAt = len(assets)

		if phaseResult.Status == "failed" {
			e.logger.Errorw("❌ Discovery phase failed",
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
		e.logger.Infow(" Context status after discovery",
			"remaining_time", remaining.String(),
			"remaining_seconds", remaining.Seconds(),
			"elapsed_since_scan_start", time.Since(execStart).String(),
			"context_healthy", remaining > 0,
		)
		if remaining <= 0 {
			e.logger.Errorw(" CRITICAL: Context already expired after discovery!",
				"expired_by", (-remaining).String(),
			)
		}
	}

	// Phase 2: Asset Prioritization
	prioritizationStart := time.Now()
	e.logger.Infow("🎯 Phase 2: Starting asset prioritization",
		"total_assets", len(assets),
		"elapsed_since_scan_start", time.Since(execStart).String(),
	)

	tracker.StartPhase("prioritization")
	prioritized := e.executePrioritizationPhase(assets)

	e.logger.Infow(" Prioritization completed",
		"high_priority_assets", len(prioritized),
		"prioritization_duration", time.Since(prioritizationStart).String(),
		"elapsed_since_scan_start", time.Since(execStart).String(),
	)
	tracker.CompletePhase("prioritization")

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

	e.logger.Infow("🔬 Phase 3: Starting vulnerability testing",
		"assets_to_test", len(prioritized),
		"enabled_scanners", enabledScanners,
		"scanner_count", len(enabledScanners),
		"scan_timeout", e.config.ScanTimeout.String(),
		"elapsed_since_scan_start", time.Since(execStart).String(),
	)

	// Check context status before testing
	select {
	case <-ctx.Done():
		e.logger.Errorw(" CRITICAL: Context already cancelled before testing phase",
			"error", ctx.Err(),
			"elapsed_time", time.Since(execStart).String(),
		)
	default:
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			e.logger.Infow(" Context valid before testing",
				"remaining_time", remaining.String(),
				"remaining_seconds", remaining.Seconds(),
				"elapsed_time", time.Since(execStart).String(),
			)
		}
	}

	tracker.StartPhase("testing")
	findings, phaseResults := e.executeTestingPhase(ctx, target, prioritized, tracker)

	testingDuration := time.Since(testingStart)
	e.logger.Infow(" Testing phase completed",
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

	// Phase 4: Store results
	storageStart := time.Now()
	e.logger.Infow("💾 Phase 4: Storing results to database",
		"scan_id", scanID,
		"findings_count", len(result.Findings),
		"elapsed_since_scan_start", time.Since(execStart).String(),
	)

	// Check context status before storage
	select {
	case <-ctx.Done():
		e.logger.Errorw(" CRITICAL: Context already cancelled before storage phase",
			"error", ctx.Err(),
			"elapsed_time", time.Since(execStart).String(),
		)
	default:
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			e.logger.Infow(" Context valid before storage",
				"remaining_time", remaining.String(),
				"remaining_seconds", remaining.Seconds(),
				"elapsed_time", time.Since(execStart).String(),
			)
		}
	}

	tracker.StartPhase("storage")
	if err := e.storeResults(ctx, scanID, result); err != nil {
		e.logger.Errorw("❌ Failed to store results",
			"error", err,
			"scan_id", scanID,
			"storage_duration", time.Since(storageStart).String(),
			"elapsed_since_scan_start", time.Since(execStart).String(),
		)
		tracker.FailPhase("storage", err)
	} else {
		e.logger.Infow("✅ Results stored successfully",
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

	e.logger.Infow("🎉 Bug bounty scan completed successfully",
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

	return result, nil
}

// executeDiscoveryPhase runs asset discovery with timeout
func (e *BugBountyEngine) executeDiscoveryPhase(ctx context.Context, target string, tracker *progress.Tracker) ([]*discovery.Asset, PhaseResult) {
	phaseStart := time.Now()
	phase := PhaseResult{
		Phase:     "discovery",
		Status:    "running",
		StartTime: phaseStart,
	}

	// Log parent context status
	if deadline, ok := ctx.Deadline(); ok {
		e.logger.Infow("⏰ Parent context status before discovery phase",
			"target", target,
			"parent_deadline", deadline.Format(time.RFC3339),
			"time_until_parent_deadline", time.Until(deadline).String(),
			"parent_deadline_seconds", time.Until(deadline).Seconds(),
		)
	} else {
		e.logger.Warnw("⚠️  No parent context deadline - unexpected!",
			"target", target,
		)
	}

	e.logger.Infow("🔍 Phase 1: Starting Asset Discovery",
		"target", target,
		"discovery_timeout", e.config.DiscoveryTimeout.String(),
	)
	tracker.UpdateProgress("discovery", 10)

	// Start discovery session
	sessionStart := time.Now()
	session, err := e.discoveryEngine.StartDiscovery(target)
	if err != nil {
		phase.Status = "failed"
		phase.Error = fmt.Sprintf("failed to start discovery: %v", err)
		phase.EndTime = time.Now()
		phase.Duration = phase.EndTime.Sub(phase.StartTime)
		e.logger.Errorw("❌ Discovery failed to start",
			"error", err,
			"target", target,
			"elapsed_time", time.Since(phaseStart).String(),
		)
		return nil, phase
	}

	e.logger.Infow("✅ Discovery session started",
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
		e.logger.Infow("⏰ Discovery context created FROM PARENT",
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
				e.logger.Warnw("Failed to get session after completion, using partial results", "error", err)
			}
		} else {
			e.logger.Warnw("Discovery failed or stopped, using partial results")
			session, _ = e.discoveryEngine.GetSession(session.ID)
		}
	case <-discoveryCtx.Done():
		// Discovery timeout
		e.logger.Warnw("Discovery timed out, using partial results", "timeout", e.config.DiscoveryTimeout)
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
		e.logger.Warnw("No assets discovered, using target as single asset", "target", target)
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
	e.logger.Infow("Discovery completed", "assets", len(assets), "duration", phase.Duration)

	return assets, phase
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
func (e *BugBountyEngine) executePrioritizationPhase(assets []*discovery.Asset) []*AssetPriority {
	e.logger.Infow("Phase 2: Asset Prioritization", "assets", len(assets))

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
	e.logger.Infow("Asset prioritization completed",
		"total_assets", len(prioritized),
		"top_priorities", topCount,
	)

	for i := 0; i < topCount; i++ {
		p := prioritized[i]
		e.logger.Debugw("High priority target",
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
func (e *BugBountyEngine) executeTestingPhase(ctx context.Context, target string, assets []*AssetPriority, tracker *progress.Tracker) ([]types.Finding, map[string]PhaseResult) {
	e.logger.Infow("Phase 3: Vulnerability Testing", "assets", len(assets))

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
	if e.config.EnableIDORTesting && e.pythonWorkers != nil {
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
	if e.config.EnableAuthTesting {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, result := e.runAuthenticationTests(ctx, target, assets)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			phaseResults["auth"] = result
			mu.Unlock()
			updateTestProgress()
		}()
	}

	// SCIM Testing
	if e.config.EnableSCIMTesting {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, result := e.runSCIMTests(ctx, assets)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			phaseResults["scim"] = result
			mu.Unlock()
			updateTestProgress()
		}()
	}

	// API Testing
	if e.config.EnableAPITesting {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, result := e.runAPITests(ctx, assets)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			phaseResults["api"] = result
			mu.Unlock()
			updateTestProgress()
		}()
	}

	// Nmap Service Fingerprinting
	if e.config.EnableServiceFingerprint && e.nmapScanner != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, result := e.runNmapScans(ctx, assets)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			phaseResults["nmap"] = result
			mu.Unlock()
			updateTestProgress()
		}()
	}

	// Nuclei Vulnerability Scanning
	if e.config.EnableNucleiScan && e.nucleiScanner != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, result := e.runNucleiScans(ctx, assets)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			phaseResults["nuclei"] = result
			mu.Unlock()
			updateTestProgress()
		}()
	}

	// GraphQL Testing (Go scanner + optional Python GraphCrawler)
	if e.config.EnableGraphQLTesting && e.graphqlScanner != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, result := e.runGraphQLTests(ctx, assets)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			phaseResults["graphql"] = result
			mu.Unlock()
			updateTestProgress()
		}()
	}

	// IDOR Testing (Python workers only)
	if e.config.EnableIDORTesting && e.pythonWorkers != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, result := e.runIDORTests(ctx, assets)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			phaseResults["idor"] = result
			mu.Unlock()
			updateTestProgress()
		}()
	}

	// Wait for all tests to complete
	wg.Wait()

	return allFindings, phaseResults
}

// runAuthenticationTests executes all authentication vulnerability tests
func (e *BugBountyEngine) runAuthenticationTests(ctx context.Context, target string, assets []*AssetPriority) ([]types.Finding, PhaseResult) {
	phase := PhaseResult{
		Phase:     "authentication",
		Status:    "running",
		StartTime: time.Now(),
	}

	e.logger.Infow("Testing authentication vulnerabilities", "target", target)

	var findings []types.Finding

	// Discover authentication endpoints
	e.logger.Infow(" Discovering authentication endpoints",
		"target", target,
		"component", "auth_scanner",
	)

	authInventory, err := e.authDiscovery.DiscoverAllAuth(ctx, target)
	if err != nil {
		e.logger.Errorw("Authentication discovery failed",
			"error", err,
			"target", target,
			"component", "auth_scanner",
		)
		phase.Status = "failed"
		phase.Error = err.Error()
		phase.EndTime = time.Now()
		phase.Duration = phase.EndTime.Sub(phase.StartTime)
		return findings, phase
	}

	// Log discovery results
	e.logger.Infow("Authentication endpoint discovery complete",
		"saml_found", authInventory.SAML != nil,
		"oauth2_found", authInventory.OAuth2 != nil,
		"webauthn_found", authInventory.WebAuthn != nil,
		"component", "auth_scanner",
	)

	// Test SAML if discovered
	if authInventory.SAML != nil && authInventory.SAML.MetadataURL != "" {
		e.logger.Infow("🔐 Testing SAML authentication security",
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
			e.logger.Warnw("SAML scanning failed",
				"error", err,
				"target", target,
				"component", "auth_scanner",
			)
		} else if report != nil {
			e.logger.Infow("SAML scan complete",
				"vulnerabilities_found", len(report.Vulnerabilities),
				"attack_chains", len(report.AttackChains),
				"component", "auth_scanner",
			)

			// Convert vulnerabilities to findings
			for _, vuln := range report.Vulnerabilities {
				finding := convertVulnerabilityToFinding(vuln, target)
				findings = append(findings, finding)

				e.logger.Infow(" SAML vulnerability found",
					"type", vuln.Type,
					"severity", vuln.Severity,
					"title", vuln.Title,
					"component", "auth_scanner",
				)
			}
		}
	} else {
		e.logger.Infow("No SAML endpoints discovered - skipping SAML tests",
			"target", target,
			"component", "auth_scanner",
		)
	}

	// Test OAuth2 if discovered
	if authInventory.OAuth2 != nil && authInventory.OAuth2.AuthorizationURL != "" {
		e.logger.Infow("🔐 Testing OAuth2/OIDC authentication security",
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
			e.logger.Warnw("OAuth2 scanning failed",
				"error", err,
				"target", target,
				"component", "auth_scanner",
			)
		} else if report != nil {
			e.logger.Infow("OAuth2 scan complete",
				"vulnerabilities_found", len(report.Vulnerabilities),
				"attack_chains", len(report.AttackChains),
				"component", "auth_scanner",
			)

			for _, vuln := range report.Vulnerabilities {
				finding := convertVulnerabilityToFinding(vuln, target)
				findings = append(findings, finding)

				e.logger.Infow(" OAuth2 vulnerability found",
					"type", vuln.Type,
					"severity", vuln.Severity,
					"title", vuln.Title,
					"component", "auth_scanner",
				)
			}
		}
	} else {
		e.logger.Infow("No OAuth2 endpoints discovered - skipping OAuth2 tests",
			"target", target,
			"component", "auth_scanner",
		)
	}

	// Test WebAuthn if discovered
	if authInventory.WebAuthn != nil && authInventory.WebAuthn.RegisterURL != "" {
		e.logger.Infow("🔐 Testing WebAuthn/FIDO2 authentication security",
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
			e.logger.Warnw("WebAuthn scanning failed",
				"error", err,
				"target", target,
				"component", "auth_scanner",
			)
		} else if report != nil {
			e.logger.Infow("WebAuthn scan complete",
				"vulnerabilities_found", len(report.Vulnerabilities),
				"attack_chains", len(report.AttackChains),
				"component", "auth_scanner",
			)

			for _, vuln := range report.Vulnerabilities {
				finding := convertVulnerabilityToFinding(vuln, target)
				findings = append(findings, finding)

				e.logger.Infow(" WebAuthn vulnerability found",
					"type", vuln.Type,
					"severity", vuln.Severity,
					"title", vuln.Title,
					"component", "auth_scanner",
				)
			}
		}
	} else {
		e.logger.Infow("No WebAuthn endpoints discovered - skipping WebAuthn tests",
			"target", target,
			"component", "auth_scanner",
		)
	}

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(phase.StartTime)
	phase.Status = "completed"
	phase.Findings = len(findings)

	e.logger.Infow("Authentication testing completed", "findings", len(findings), "duration", phase.Duration)

	return findings, phase
}

// runSCIMTests executes SCIM vulnerability tests in parallel
func (e *BugBountyEngine) runSCIMTests(ctx context.Context, assets []*AssetPriority) ([]types.Finding, PhaseResult) {
	phase := PhaseResult{
		Phase:     "scim",
		Status:    "running",
		StartTime: time.Now(),
	}

	e.logger.Infow("Testing SCIM endpoints")

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
					e.logger.Errorw("SCIM scanner panicked - recovered gracefully",
						"url", assetValue,
						"panic", r)
				}
				<-semaphore // Release worker slot
				wg.Done()
			}()

			e.logger.Infow("Testing SCIM endpoint", "url", assetValue)

			// Run SCIM vulnerability tests with timeout protection
			scanCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			scimOptions := make(map[string]string)
			scimOptions["test_all"] = "true"

			scimFindings, err := e.scimScanner.Scan(scanCtx, assetValue, scimOptions)
			if err != nil {
				e.logger.Warnw("SCIM scan failed", "url", assetValue, "error", err)
				return
			}

			// Thread-safe append of findings
			mu.Lock()
			findings = append(findings, scimFindings...)
			mu.Unlock()

			e.logger.Infow("SCIM scan completed", "url", assetValue, "findings", len(scimFindings))
		}(asset.Asset.Value)
	}

	// Wait for all SCIM scans to complete
	wg.Wait()

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(phase.StartTime)
	phase.Status = "completed"
	phase.Findings = len(findings)

	e.logger.Infow("SCIM testing completed", "findings", len(findings), "duration", phase.Duration)

	return findings, phase
}

// runAPITests executes API vulnerability tests
func (e *BugBountyEngine) runAPITests(ctx context.Context, assets []*AssetPriority) ([]types.Finding, PhaseResult) {
	phase := PhaseResult{
		Phase:     "api",
		Status:    "running",
		StartTime: time.Now(),
	}

	e.logger.Infow("Testing API endpoints")

	var findings []types.Finding

	// TODO: Implement real API testing with actual vulnerability checks:
	// - GraphQL introspection and injection
	// - REST authorization bypass (IDOR, broken access control)
	// - API rate limiting bypass
	// - Mass assignment vulnerabilities
	// - JWT token manipulation
	// - API versioning issues
	//
	// For now, API testing is DISABLED to avoid fake findings.
	// Use dedicated `shells api` command for API-specific testing when implemented.

	apiCount := 0
	for _, asset := range assets {
		if asset.Features.HasAPI {
			apiCount++
			e.logger.Debugw("API endpoint identified (testing not yet implemented)",
				"url", asset.Asset.Value,
				"note", "use shells api command for dedicated API testing",
			)
		}
	}

	if apiCount > 0 {
		e.logger.Infow("API endpoints detected but not tested",
			"count", apiCount,
			"reason", "real API testing not yet implemented",
			"recommendation", "use dedicated API testing tools or shells api command",
		)
	}

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(phase.StartTime)
	phase.Status = "completed"
	phase.Findings = len(findings)

	e.logger.Infow("API testing completed", "findings", len(findings), "duration", phase.Duration)

	return findings, phase
}

// runNmapScans performs service fingerprinting and port scanning
func (e *BugBountyEngine) runNmapScans(ctx context.Context, assets []*AssetPriority) ([]types.Finding, PhaseResult) {
	phaseStart := time.Now()
	phase := PhaseResult{
		Phase:     "nmap",
		Status:    "running",
		StartTime: phaseStart,
	}

	e.logger.Infow(" Starting Nmap service fingerprinting phase",
		"asset_count", len(assets),
		"component", "nmap_scanner",
	)

	// DIAGNOSTIC: Check context before Nmap execution
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		e.logger.Infow(" Context status at Nmap phase start",
			"deadline", deadline.Format(time.RFC3339),
			"deadline_unix", deadline.Unix(),
			"remaining_seconds", remaining.Seconds(),
			"remaining_duration", remaining.String(),
			"context_healthy", remaining > 0,
			"component", "nmap_scanner",
		)
		if remaining <= 0 {
			e.logger.Errorw(" CRITICAL: Context already expired before Nmap phase!",
				"expired_by", (-remaining).String(),
				"component", "nmap_scanner",
			)
		}
	} else {
		e.logger.Warnw("⚠️  No deadline on context before Nmap - unexpected!",
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

	e.logger.Infow("📋 Nmap scan targets prepared",
		"total_assets", len(assets),
		"unique_hosts", totalHosts,
		"component", "nmap_scanner",
	)

	scannedCount := 0
	for host := range scannedHosts {
		scannedCount++
		scanStart := time.Now()

		e.logger.Infow("🎯 Scanning host with Nmap",
			"host", host,
			"progress", fmt.Sprintf("%d/%d", scannedCount, totalHosts),
			"elapsed_since_phase_start", time.Since(phaseStart).String(),
			"component", "nmap_scanner",
		)

		// DIAGNOSTIC: Check context status immediately before each Nmap call
		select {
		case <-ctx.Done():
			e.logger.Errorw(" CRITICAL: Context cancelled before Nmap.Scan()",
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
				e.logger.Infow(" Context valid before Nmap.Scan()",
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
			e.logger.Errorw("❌ Nmap scan failed",
				"error", err,
				"host", host,
				"scan_duration", scanDuration.String(),
				"elapsed_since_phase_start", time.Since(phaseStart).String(),
				"component", "nmap_scanner",
			)

			// Check if error was due to context cancellation
			if ctx.Err() != nil {
				e.logger.Errorw(" Nmap scan failed due to context cancellation",
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

		e.logger.Infow("✅ Nmap scan completed",
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

	e.logger.Infow("🎉 Nmap scanning phase completed",
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
func (e *BugBountyEngine) runNucleiScans(ctx context.Context, assets []*AssetPriority) ([]types.Finding, PhaseResult) {
	phaseStart := time.Now()
	phase := PhaseResult{
		Phase:     "nuclei",
		Status:    "running",
		StartTime: phaseStart,
	}

	e.logger.Infow(" Starting Nuclei vulnerability scanning phase",
		"asset_count", len(assets),
		"component", "nuclei_scanner",
	)

	// Check context status at phase start
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		e.logger.Infow(" Context status at Nuclei phase start",
			"remaining_time", remaining.String(),
			"remaining_seconds", remaining.Seconds(),
			"context_healthy", remaining > 0,
			"component", "nuclei_scanner",
		)
		if remaining <= 0 {
			e.logger.Errorw(" CRITICAL: Context already expired before Nuclei phase!",
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

		e.logger.Infow("🎯 Scanning target with Nuclei",
			"target", asset.Asset.Value,
			"priority_score", asset.Score,
			"progress", progress,
			"elapsed_since_phase_start", time.Since(phaseStart).String(),
			"component", "nuclei_scanner",
		)

		// Check context status before each scan
		select {
		case <-ctx.Done():
			e.logger.Errorw(" CRITICAL: Context cancelled before Nuclei scan",
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
				e.logger.Debugw(" Context valid before Nuclei scan",
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
			e.logger.Errorw("❌ Nuclei scan failed",
				"error", err,
				"target", asset.Asset.Value,
				"scan_duration", scanDuration.String(),
				"elapsed_since_phase_start", time.Since(phaseStart).String(),
				"component", "nuclei_scanner",
			)

			// Check if error was due to context cancellation
			if ctx.Err() != nil {
				e.logger.Errorw(" Nuclei scan failed due to context cancellation",
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

		e.logger.Infow("✅ Nuclei scan completed",
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

	e.logger.Infow("🎉 Nuclei scanning phase completed",
		"total_findings", len(findings),
		"phase_duration", phase.Duration.String(),
		"targets_scanned", totalAssets,
		"avg_scan_time", avgScanTime,
		"component", "nuclei_scanner",
	)

	return findings, phase
}

// runGraphQLTests performs GraphQL security testing
func (e *BugBountyEngine) runGraphQLTests(ctx context.Context, assets []*AssetPriority) ([]types.Finding, PhaseResult) {
	phase := PhaseResult{
		Phase:     "graphql",
		Status:    "running",
		StartTime: time.Now(),
	}

	e.logger.Infow("Running GraphQL security tests")

	var findings []types.Finding

	// Find GraphQL endpoints
	graphqlCount := 0
	for _, asset := range assets {
		url := asset.Asset.Value
		// Check if URL likely contains GraphQL endpoint
		if !strings.Contains(strings.ToLower(url), "graphql") &&
			!strings.Contains(strings.ToLower(url), "/api") {
			continue
		}

		graphqlCount++
		e.logger.Debugw("Testing GraphQL endpoint",
			"url", url,
			"component", "graphql_scanner",
		)

		// Run Go GraphQL scanner
		results, err := e.graphqlScanner.Scan(ctx, url, nil)
		if err != nil {
			e.logger.Errorw("GraphQL scan failed",
				"error", err,
				"url", url,
				"component", "graphql_scanner",
			)
			continue
		}

		// Convert results to findings
		findings = append(findings, results...)

		e.logger.Infow("Go GraphQL scan completed",
			"url", url,
			"findings", len(results),
			"component", "graphql_scanner",
		)

		// Also run Python GraphCrawler if available
		if e.pythonWorkers != nil {
			e.logger.Infow("Running Python GraphCrawler",
				"url", url,
				"component", "graphcrawler",
			)

			jobStatus, err := e.pythonWorkers.ScanGraphQLSync(ctx, url, nil)
			if err != nil {
				e.logger.Errorw("GraphCrawler scan failed",
					"error", err,
					"url", url,
					"component", "graphcrawler",
				)
			} else if jobStatus.Status == "completed" && jobStatus.Result != nil {
				// Convert Python worker results to findings
				pythonFindings := convertPythonGraphQLToFindings(jobStatus.Result, url)
				findings = append(findings, pythonFindings...)

				e.logger.Infow("GraphCrawler scan completed",
					"url", url,
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

	e.logger.Infow("GraphQL testing completed",
		"findings", len(findings),
		"duration", phase.Duration,
		"endpoints_tested", graphqlCount,
	)

	return findings, phase
}

// runIDORTests performs IDOR vulnerability testing using Python workers
func (e *BugBountyEngine) runIDORTests(ctx context.Context, assets []*AssetPriority) ([]types.Finding, PhaseResult) {
	phase := PhaseResult{
		Phase:     "idor",
		Status:    "running",
		StartTime: time.Now(),
	}

	e.logger.Infow("Running IDOR vulnerability tests")

	var findings []types.Finding

	// Find potential IDOR endpoints (those with IDs in URL)
	idorEndpoints := []string{}
	for _, asset := range assets {
		url := asset.Asset.Value
		// Look for numeric IDs or UUIDs in URLs
		if strings.Contains(url, "/api/") && (containsPattern(url, `\/\d+`) || containsPattern(url, `[a-f0-9-]{36}`)) {
			idorEndpoints = append(idorEndpoints, url)
		}
	}

	if len(idorEndpoints) == 0 {
		e.logger.Infow("No IDOR candidates found", "component", "idor_scanner")
		phase.EndTime = time.Now()
		phase.Duration = phase.EndTime.Sub(phase.StartTime)
		phase.Status = "completed"
		phase.Findings = 0
		return findings, phase
	}

	e.logger.Infow("IDOR candidates identified",
		"count", len(idorEndpoints),
		"component", "idor_scanner",
	)

	// Run IDOR scans
	for _, endpoint := range idorEndpoints {
		e.logger.Debugw("Testing IDOR endpoint",
			"endpoint", endpoint,
			"component", "idor_scanner",
		)

		// Use Python IDOR scanner
		// Note: In production, you'd need to extract auth tokens from somewhere
		tokens := []string{} // TODO: Extract from credential manager or user input
		jobStatus, err := e.pythonWorkers.ScanIDORSync(ctx, endpoint, tokens, 1, 100)
		if err != nil {
			e.logger.Errorw("IDOR scan failed",
				"error", err,
				"endpoint", endpoint,
				"component", "idor_scanner",
			)
			continue
		}

		if jobStatus.Status == "completed" && jobStatus.Result != nil {
			// Convert Python worker results to findings
			idorFindings := convertPythonIDORToFindings(jobStatus.Result, endpoint)
			findings = append(findings, idorFindings...)

			e.logger.Infow("IDOR scan completed",
				"endpoint", endpoint,
				"findings", len(idorFindings),
				"component", "idor_scanner",
			)
		}
	}

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(phase.StartTime)
	phase.Status = "completed"
	phase.Findings = len(findings)

	e.logger.Infow("IDOR testing completed",
		"findings", len(findings),
		"duration", phase.Duration,
		"endpoints_tested", len(idorEndpoints),
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
	// Save scan metadata
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
	}

	if err := e.store.SaveScan(ctx, scan); err != nil {
		return fmt.Errorf("failed to save scan: %w", err)
	}

	// Save findings
	if len(result.Findings) > 0 {
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
