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
	e.logger.Infow("Starting bug bounty scan", "target", target)

	// Initialize progress tracker
	tracker := progress.New(e.config.ShowProgress, e.logger)
	tracker.AddPhase("discovery", "Discovering assets")
	tracker.AddPhase("prioritization", "Prioritizing targets")
	tracker.AddPhase("testing", "Testing for vulnerabilities")
	tracker.AddPhase("storage", "Storing results")

	// Create scan record
	scanID := fmt.Sprintf("bounty-%d", time.Now().Unix())
	result := &BugBountyResult{
		ScanID:       scanID,
		Target:       target,
		StartTime:    time.Now(),
		Status:       "running",
		PhaseResults: make(map[string]PhaseResult),
		Findings:     []types.Finding{},
	}

	// Apply total timeout
	ctx, cancel := context.WithTimeout(ctx, e.config.TotalTimeout)
	defer cancel()

	// Phase 1: Asset Discovery (or skip if configured)
	var assets []*discovery.Asset
	var phaseResult PhaseResult

	if e.config.SkipDiscovery {
		// Quick mode: Use target directly without discovery
		e.logger.Infow("Skipping discovery (quick mode)", "target", target)
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
		tracker.StartPhase("discovery")
		assets, phaseResult = e.executeDiscoveryPhase(ctx, target, tracker)
		result.PhaseResults["discovery"] = phaseResult
		result.DiscoveredAt = len(assets)

		if phaseResult.Status == "failed" {
			tracker.FailPhase("discovery", fmt.Errorf("%s", phaseResult.Error))
			result.Status = "failed"
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime)
			return result, fmt.Errorf("discovery phase failed: %s", phaseResult.Error)
		}
		tracker.CompletePhase("discovery")
	}

	// Phase 2: Asset Prioritization
	tracker.StartPhase("prioritization")
	prioritized := e.executePrioritizationPhase(assets)
	e.logger.Infow("Prioritized assets", "count", len(prioritized), "target", target)
	tracker.CompletePhase("prioritization")

	// Phase 3: Vulnerability Testing (parallel)
	tracker.StartPhase("testing")
	findings, phaseResults := e.executeTestingPhase(ctx, target, prioritized, tracker)
	for phase, pr := range phaseResults {
		result.PhaseResults[phase] = pr
	}
	result.Findings = append(result.Findings, findings...)
	result.TestedAssets = len(prioritized)
	tracker.CompletePhase("testing")

	// Phase 4: Store results
	tracker.StartPhase("storage")
	if err := e.storeResults(ctx, scanID, result); err != nil {
		e.logger.Errorw("Failed to store results", "error", err, "scan_id", scanID)
		tracker.FailPhase("storage", err)
	} else {
		tracker.CompletePhase("storage")
	}

	result.Status = "completed"
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.TotalFindings = len(result.Findings)

	// Show final summary
	tracker.Complete()

	e.logger.Infow("Bug bounty scan completed",
		"target", target,
		"scan_id", scanID,
		"findings", result.TotalFindings,
		"duration", result.Duration,
	)

	return result, nil
}

// executeDiscoveryPhase runs asset discovery with timeout
func (e *BugBountyEngine) executeDiscoveryPhase(ctx context.Context, target string, tracker *progress.Tracker) ([]*discovery.Asset, PhaseResult) {
	phase := PhaseResult{
		Phase:     "discovery",
		Status:    "running",
		StartTime: time.Now(),
	}

	e.logger.Infow("Phase 1: Asset Discovery", "target", target, "timeout", e.config.DiscoveryTimeout)
	tracker.UpdateProgress("discovery", 10)

	// Start discovery session
	session, err := e.discoveryEngine.StartDiscovery(target)
	if err != nil {
		phase.Status = "failed"
		phase.Error = fmt.Sprintf("failed to start discovery: %v", err)
		phase.EndTime = time.Now()
		phase.Duration = phase.EndTime.Sub(phase.StartTime)
		e.logger.Errorw("Discovery failed to start", "error", err, "target", target)
		return nil, phase
	}

	// Create discovery timeout context
	discoveryCtx, discoveryCancel := context.WithTimeout(ctx, e.config.DiscoveryTimeout)
	defer discoveryCancel()

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

	// GraphQL Testing
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
	e.logger.Infow("🔍 Discovering authentication endpoints",
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

				e.logger.Infow("🚨 SAML vulnerability found",
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

				e.logger.Infow("🚨 OAuth2 vulnerability found",
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

				e.logger.Infow("🚨 WebAuthn vulnerability found",
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
	phase := PhaseResult{
		Phase:     "nmap",
		Status:    "running",
		StartTime: time.Now(),
	}

	e.logger.Infow("Running Nmap service fingerprinting")

	var findings []types.Finding

	// Scan each asset's host
	scannedHosts := make(map[string]bool) // Deduplicate hosts
	for _, asset := range assets {
		// Extract host from URL
		host := extractHost(asset.Asset.Value)
		if host == "" || scannedHosts[host] {
			continue
		}
		scannedHosts[host] = true

		e.logger.Debugw("Scanning host with Nmap",
			"host", host,
			"component", "nmap_scanner",
		)

		// Run Nmap scan
		results, err := e.nmapScanner.Scan(ctx, host, nil)
		if err != nil {
			e.logger.Errorw("Nmap scan failed",
				"error", err,
				"host", host,
				"component", "nmap_scanner",
			)
			continue
		}

		// Convert results to findings
		findings = append(findings, results...)

		e.logger.Infow("Nmap scan completed",
			"host", host,
			"findings", len(results),
			"component", "nmap_scanner",
		)
	}

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(phase.StartTime)
	phase.Status = "completed"
	phase.Findings = len(findings)

	e.logger.Infow("Nmap scanning completed",
		"findings", len(findings),
		"duration", phase.Duration,
		"hosts_scanned", len(scannedHosts),
	)

	return findings, phase
}

// runNucleiScans performs vulnerability scanning with Nuclei templates
func (e *BugBountyEngine) runNucleiScans(ctx context.Context, assets []*AssetPriority) ([]types.Finding, PhaseResult) {
	phase := PhaseResult{
		Phase:     "nuclei",
		Status:    "running",
		StartTime: time.Now(),
	}

	e.logger.Infow("Running Nuclei vulnerability scanner")

	var findings []types.Finding

	// Scan high-priority assets
	for _, asset := range assets {
		e.logger.Debugw("Scanning with Nuclei",
			"target", asset.Asset.Value,
			"score", asset.Score,
			"component", "nuclei_scanner",
		)

		// Run Nuclei scan
		results, err := e.nucleiScanner.Scan(ctx, asset.Asset.Value, nil)
		if err != nil {
			e.logger.Errorw("Nuclei scan failed",
				"error", err,
				"target", asset.Asset.Value,
				"component", "nuclei_scanner",
			)
			continue
		}

		// Convert results to findings
		findings = append(findings, results...)

		e.logger.Infow("Nuclei scan completed",
			"target", asset.Asset.Value,
			"findings", len(results),
			"component", "nuclei_scanner",
		)
	}

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(phase.StartTime)
	phase.Status = "completed"
	phase.Findings = len(findings)

	e.logger.Infow("Nuclei scanning completed",
		"findings", len(findings),
		"duration", phase.Duration,
		"targets_scanned", len(assets),
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

		// Run GraphQL scan
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

		e.logger.Infow("GraphQL scan completed",
			"url", url,
			"findings", len(results),
			"component", "graphql_scanner",
		)
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
	completedAt := result.EndTime
	scan := &types.ScanRequest{
		ID:          scanID,
		Target:      result.Target,
		Type:        types.ScanTypeAuth, // Using ScanTypeAuth for now
		Status:      types.ScanStatusCompleted,
		CreatedAt:   result.StartTime,
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
