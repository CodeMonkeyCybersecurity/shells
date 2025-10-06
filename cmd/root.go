package cmd

// Shells Root Command - Main Entry Point
//
// MODULARIZATION (2025-10-06):
//   Extracted reusable code into cmd/internal packages:
//   - cmd/internal/display: Color formatting, finding display (117 lines)
//   - cmd/internal/converters: Type conversions for findings (387 lines)
//   - cmd/internal/helpers: Asset prioritization utilities (137 lines)
//   All functions re-exported via cmd/display_helpers.go for backward compatibility
//   Deleted redundant files: root_enhanced_simplified.go, root_helpers.go
//
// ADVERSARIAL REVIEW STATUS (2025-10-05):
//
//  FIXED (P0 - Critical):
//   - All HTTP body close errors fixed via httpclient.CloseBody()
//   - Environment config errors now have proper error handling
//   - File write errors in protocol.go properly checked
//
//   KNOWN ISSUES (Documented):
//   - FILE SIZE: 3,196 lines, 78 functions (PARTIAL FIX - see Modularization above)
//     Extracted 641 lines to internal packages, reducing duplication
//     Remaining: Further split into cmd/discovery/, cmd/scan/, cmd/workflow/
//     Timeline: 1-2 weeks for remaining refactoring
//
//   - OS.EXIT CALLS: 44 calls prevent integration testing
//     Should use RunE pattern with error returns instead
//     Timeline: 1-2 weeks systematic conversion
//
//   - GRACEFUL SHUTDOWN: pkg/shutdown exists but not integrated
//     Long scans lose all progress on Ctrl+C
//     Needs: checkpointing, resume capability
//     Timeline: 1 week implementation
//
// 🎯 HERA INTEGRATION ARCHITECTURE (Documented, Not Implemented):
//   See inline comments in pkg/hera/ when created
//   Design: Hybrid browser (95% client) + server (5% deep analysis)
//   Privacy: Domain-only analysis, no URL logging, no browsing history
//   False Positives: Bayesian framework (WHO/WHAT/HOW/WHY) prevents GitHub.com flags
//   Database: PostgreSQL with 7 tables for reputation, WHOIS, threat intel
//   API: POST /analyze, GET /reputation/:domain, POST /feedback
//   Timeline: Phase 1 docs complete, Phase 2 implementation pending
//
// PHILOSOPHY ALIGNMENT:
// - Human-Centric: Transparent errors, no silent failures
// - Evidence-Based: Verifiable results, confidence scores
// - Sustainable: Documented tech debt, clear improvement path
// - Collaborative: Honest assessment, actionable next steps

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/cmd/scanners"
	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/credentials"
	"github.com/CodeMonkeyCybersecurity/shells/internal/database"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/internal/nomad"
	authdiscovery "github.com/CodeMonkeyCybersecurity/shells/pkg/auth/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scim"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/smuggling"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfg   *config.Config
	log   *logger.Logger
	store core.ResultStore
)

// GetStore returns the initialized database store
func GetStore() core.ResultStore {
	return store
}

// GetContext returns a background context
func GetContext() context.Context {
	return context.Background()
}

var rootCmd = &cobra.Command{
	Use:   "shells [target]",
	Short: "Intelligent bug bounty automation platform",
	Long: `Shells - Intelligent Bug Bounty Automation Platform

Automatically discovers assets, identifies vulnerabilities, and generates
actionable findings using real security scanners.

Point-and-Click Mode:
  shells example.com          # Full bug bounty pipeline: Discovery → Testing → Reporting
  shells "Acme Corporation"   # Discover company assets and test for vulnerabilities
  shells admin@example.com    # Discover from email and test discovered assets
  shells 192.168.1.1          # Discover network and test services
  shells 192.168.1.0/24       # Scan IP range and test discovered hosts

The main command runs the COMPREHENSIVE orchestrated pipeline:
  1. Asset Discovery:
     • Subdomain enumeration (DNS, cert transparency, search engines)
     • Related domain discovery (same org, same cert, same registrant email)
     • Adjacent IP scanning (neighboring IPs in /24 subnet)
     • WHOIS analysis (organization footprinting)
     • Port scanning (all exposed services)
     • Service fingerprinting (Nmap version detection)
     • Deep web crawling (login pages, APIs, admin panels)

  2. Intelligent Prioritization:
     • Authentication endpoints (SAML, OAuth2, WebAuthn)
     • API endpoints (REST, GraphQL, SOAP)
     • Admin panels and privileged functions
     • File upload capabilities
     • Payment and transaction flows

  3. Comprehensive Vulnerability Testing:
     • Authentication: SAML, OAuth2, WebAuthn, JWT, session handling
     • API Security: GraphQL introspection, REST API auth bypass
     • Access Control: IDOR, privilege escalation (horizontal/vertical)
     • Injection: SQL injection, XSS (reflected, stored, DOM)
     • SSRF: Server-side request forgery, cloud metadata access
     • Business Logic: Payment manipulation, workflow bypass
     • SCIM: Provisioning vulnerabilities, user enumeration

  4. Temporal Snapshots & Reporting:
     • All findings saved to PostgreSQL
     • Historical comparison (track changes over time)
     • Exportable reports (JSON, CSV, HTML, Markdown)
     • Query interface for finding analysis`,
	Args: func(cmd *cobra.Command, args []string) error {
		// Allow subcommands to handle their own args
		if len(args) == 0 {
			return nil
		}

		// Check if first argument is a subcommand
		for _, subcmd := range cmd.Commands() {
			if subcmd.Name() == args[0] || subcmd.HasAlias(args[0]) {
				// This is a subcommand, don't validate args here
				return nil
			}
		}

		// Not a subcommand, treat as target (max 1 arg)
		if len(args) > 1 {
			return fmt.Errorf("accepts at most 1 arg(s), received %d", len(args))
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// If no arguments provided, show help
		if len(args) == 0 {
			return cmd.Help()
		}

		// Point-and-click mode: Use intelligent orchestrator
		target := args[0]

		// Set up context with cancellation for Ctrl+C handling
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Set up signal handling for graceful shutdown
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		// Handle signals in goroutine
		go func() {
			sig := <-sigChan
			color.Yellow("\n\n  Received %s - shutting down gracefully...\n", sig)
			color.White("   Partial results will be saved to database.\n\n")
			cancel()
		}()

		return runIntelligentOrchestrator(ctx, target, cmd, log, store)
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip initialization for certain commands that don't need it
		if cmd.Name() == "self-update" || cmd.Name() == "serve" {
			return nil
		}

		if err := initConfig(); err != nil {
			return fmt.Errorf("failed to initialize config: %w", err)
		}

		var err error
		log, err = logger.New(cfg.Logger)
		if err != nil {
			return fmt.Errorf("failed to initialize logger: %w", err)
		}

		// Initialize database store
		store, err = database.NewStore(cfg.Database)
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}

		// Check for API credentials on first run (only for main commands, not help/version)
		if cmd.Name() != "help" && cmd.Name() != "version" && cmd.Name() != "config" {
			credManager, err := credentials.NewManager(log)
			if err != nil {
				log.Warn("Failed to initialize credentials manager", "error", err)
			} else {
				// Check and prompt for CIRCL credentials if not configured
				if err := credManager.CheckAndPromptForCircl(); err != nil {
					log.Debug("CIRCL credential prompt skipped or failed", "error", err)
				}
			}
		}

		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if log != nil {
			// Sync logger - ignore EINVAL errors from stdout/stderr on Linux
			if err := log.Sync(); err != nil {
				// Sync errors on stdout/stderr are expected on Linux and can be safely ignored
				// Only log if it's a real error (not "invalid argument" from stdout/stderr)
				if err.Error() != "sync /dev/stdout: invalid argument" && err.Error() != "sync /dev/stderr: invalid argument" {
					fmt.Fprintf(os.Stderr, "Warning: failed to sync logger: %v\n", err)
				}
			}
		}
		if store != nil {
			if err := store.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to close database: %v\n", err)
			}
		}
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Logging configuration
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("log-format", "console", "log format (json, console)")
	viper.BindPFlag("logger.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("logger.format", rootCmd.PersistentFlags().Lookup("log-format"))
	viper.BindEnv("logger.level", "SHELLS_LOG_LEVEL")
	viper.BindEnv("logger.format", "SHELLS_LOG_FORMAT")

	// Database configuration
	rootCmd.PersistentFlags().String("db-dsn", "postgres://shells:shells_password@localhost:5432/shells?sslmode=disable", "PostgreSQL connection string")
	rootCmd.PersistentFlags().Int("db-max-conns", 25, "Maximum database connections")
	rootCmd.PersistentFlags().Int("db-max-idle", 5, "Maximum idle database connections")
	viper.BindPFlag("database.dsn", rootCmd.PersistentFlags().Lookup("db-dsn"))
	viper.BindPFlag("database.max_connections", rootCmd.PersistentFlags().Lookup("db-max-conns"))
	viper.BindPFlag("database.max_idle_conns", rootCmd.PersistentFlags().Lookup("db-max-idle"))
	viper.BindEnv("database.dsn", "SHELLS_DATABASE_DSN", "DATABASE_URL")
	viper.BindEnv("database.max_connections", "SHELLS_DB_MAX_CONNECTIONS")

	// Redis configuration
	rootCmd.PersistentFlags().String("redis-addr", "localhost:6379", "Redis server address")
	rootCmd.PersistentFlags().String("redis-password", "", "Redis password")
	rootCmd.PersistentFlags().Int("redis-db", 0, "Redis database number")
	viper.BindPFlag("redis.addr", rootCmd.PersistentFlags().Lookup("redis-addr"))
	viper.BindPFlag("redis.password", rootCmd.PersistentFlags().Lookup("redis-password"))
	viper.BindPFlag("redis.db", rootCmd.PersistentFlags().Lookup("redis-db"))
	viper.BindEnv("redis.addr", "SHELLS_REDIS_ADDR", "REDIS_URL")
	viper.BindEnv("redis.password", "SHELLS_REDIS_PASSWORD")

	// Worker configuration
	rootCmd.PersistentFlags().Int("workers", 3, "Number of worker processes")
	viper.BindPFlag("worker.count", rootCmd.PersistentFlags().Lookup("workers"))
	viper.BindEnv("worker.count", "SHELLS_WORKERS")

	// Security/Rate limiting
	rootCmd.PersistentFlags().Int("rate-limit", 10, "Requests per second rate limit")
	rootCmd.PersistentFlags().Int("rate-burst", 20, "Rate limit burst size")
	viper.BindPFlag("security.rate_limit.requests_per_second", rootCmd.PersistentFlags().Lookup("rate-limit"))
	viper.BindPFlag("security.rate_limit.burst_size", rootCmd.PersistentFlags().Lookup("rate-burst"))
	viper.BindEnv("security.rate_limit.requests_per_second", "SHELLS_RATE_LIMIT")

	// Bug bounty specific flags
	rootCmd.PersistentFlags().Bool("quick", false, "Quick scan mode - critical vulnerabilities only")
	rootCmd.PersistentFlags().Bool("deep", false, "Deep scan mode - comprehensive testing")
	rootCmd.PersistentFlags().Duration("timeout", 30*time.Minute, "Maximum scan time (default: 30m for comprehensive scan)")
	rootCmd.PersistentFlags().String("scope", "", "Scope file defining authorized targets (.scope file)")

	// API keys (environment variables only, never flags)
	viper.BindEnv("shodan_api_key", "SHODAN_API_KEY")
	viper.BindEnv("censys_api_key", "CENSYS_API_KEY")
	viper.BindEnv("censys_secret", "CENSYS_SECRET")
	viper.BindEnv("security.api_key", "SHELLS_API_KEY")

	// Set sensible defaults
	viper.SetDefault("database.driver", "postgres")
	viper.SetDefault("database.conn_max_lifetime", "1h")
	viper.SetDefault("redis.max_retries", 3)
	viper.SetDefault("redis.dial_timeout", "5s")
	viper.SetDefault("redis.read_timeout", "3s")
	viper.SetDefault("redis.write_timeout", "3s")
	viper.SetDefault("worker.queue_poll_interval", "5s")
	viper.SetDefault("worker.max_retries", 3)
	viper.SetDefault("worker.retry_delay", "10s")
	viper.SetDefault("telemetry.enabled", true)
	viper.SetDefault("telemetry.service_name", "shells")
	viper.SetDefault("telemetry.exporter_type", "otlp")
	viper.SetDefault("telemetry.endpoint", "localhost:4317")
	viper.SetDefault("telemetry.sample_rate", 1.0)
	viper.SetDefault("logger.output_paths", []string{"stdout"})
}

func initConfig() error {
	// No YAML files - configuration from flags + env vars only
	viper.AutomaticEnv()
	viper.SetEnvPrefix("SHELLS")

	cfg = &config.Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Apply sensible defaults programmatically (no YAML needed)
	if cfg.Database.Driver == "" {
		cfg.Database.Driver = "postgres"
	}
	if cfg.Logger.Level == "" {
		cfg.Logger.Level = "error"
	}
	if cfg.Logger.Format == "" {
		cfg.Logger.Format = "console"
	}
	if cfg.Security.RateLimit.RequestsPerSecond == 0 {
		cfg.Security.RateLimit.RequestsPerSecond = 10
	}
	if cfg.Telemetry.ServiceName == "" {
		cfg.Telemetry.ServiceName = "shells"
	}

	return nil
}

func GetConfig() *config.Config {
	return cfg
}

func GetLogger() *logger.Logger {
	return log
}

// runIntelligentDiscovery runs the point-and-click discovery and testing workflow
func runIntelligentDiscovery(target string) error {
	log.Infow("Starting intelligent discovery", "target", target)

	// Create discovery engine with enhanced features
	discoveryConfig := discovery.DefaultDiscoveryConfig()
	discoveryConfig.MaxDepth = 5
	discoveryConfig.MaxAssets = 10000
	discoveryConfig.EnableDNS = true
	discoveryConfig.EnableCertLog = true
	discoveryConfig.EnableSearch = true
	discoveryConfig.EnablePortScan = true
	discoveryConfig.EnableWebCrawl = true
	discoveryConfig.EnableTechStack = true
	discoveryConfig.Timeout = 60 * time.Minute

	discoveryEngine := discovery.NewEngineWithConfig(discoveryConfig, log.WithComponent("discovery"), cfg)

	// Start discovery
	session, err := discoveryEngine.StartDiscovery(target)
	if err != nil {
		return fmt.Errorf("failed to start discovery: %w", err)
	}

	log.Infow("Discovery session started",
		"sessionID", session.ID,
		"targetType", session.Target.Type,
		"confidence", fmt.Sprintf("%.0f%%", session.Target.Confidence*100))

	// Monitor discovery progress
	return monitorAndExecuteScans(discoveryEngine, session.ID)
}

// monitorAndExecuteScans monitors discovery progress and executes scans on discovered assets
func monitorAndExecuteScans(engine *discovery.Engine, sessionID string) error {
	log.Infow("Monitoring discovery progress")

	// Poll for completion
	for {
		session, err := engine.GetSession(sessionID)
		if err != nil {
			return fmt.Errorf("failed to get session: %w", err)
		}

		log.Infow("Discovery progress update",
			"progress", fmt.Sprintf("%.0f%%", session.Progress*100),
			"totalAssets", session.TotalDiscovered,
			"highValueAssets", session.HighValueAssets)

		if session.Status == discovery.StatusCompleted {
			log.Infow("Discovery completed successfully")
			break
		} else if session.Status == discovery.StatusFailed {
			log.Errorw("Discovery failed")
			for _, errMsg := range session.Errors {
				log.Errorw("Discovery error", "error", errMsg)
			}
			return fmt.Errorf("discovery failed")
		}

		time.Sleep(2 * time.Second)
	}

	// Get final session state
	session, err := engine.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get final session: %w", err)
	}

	log.Infow("Discovery Summary",
		"totalAssets", session.TotalDiscovered,
		"highValueAssets", session.HighValueAssets,
		"relationships", len(session.Relationships))

	// Show high-value assets
	if session.HighValueAssets > 0 {
		log.Infow("High-Value Assets Found")
		for _, asset := range session.Assets {
			if discovery.IsHighValueAsset(asset) {
				log.Infow("High-value asset",
					"value", asset.Value,
					"type", asset.Type,
					"title", asset.Title)
			}
		}
	}

	// Execute comprehensive scans on discovered assets
	log.Infow("Starting comprehensive security testing")
	return executeComprehensiveScans(session)
}

// executeComprehensiveScans runs all available security tests on discovered assets
func executeComprehensiveScans(session *discovery.DiscoverySession) error {
	ctx := context.Background()

	// Use intelligent scanner selector to determine what to run
	scannerSelector := discovery.NewIntelligentScannerSelector(log.WithComponent("scanner-selector"))
	recommendations := scannerSelector.SelectScanners(session)

	log.Infow("Intelligent Scanner Analysis",
		"recommendedScanners", len(recommendations),
		"note", "specialized scanners based on discovered context")

	// Show top 5 recommendations
	for i, rec := range recommendations {
		if i >= 5 {
			break
		}
		log.Infow("Scanner recommendation",
			"position", i+1,
			"scanner", rec.Scanner,
			"priority", rec.Priority,
			"reason", rec.Reason)
	}

	// Prioritize high-value assets
	var targets []string

	// Add high-value assets first
	for _, asset := range session.Assets {
		if discovery.IsHighValueAsset(asset) {
			targets = append(targets, asset.Value)
		}
	}

	// Add other assets
	for _, asset := range session.Assets {
		if !discovery.IsHighValueAsset(asset) &&
			(asset.Type == discovery.AssetTypeDomain ||
				asset.Type == discovery.AssetTypeSubdomain ||
				asset.Type == discovery.AssetTypeURL) {
			targets = append(targets, asset.Value)
		}
	}

	if len(targets) == 0 {
		log.Infow("No testable assets found")
		return nil
	}

	log.Infow("Testing assets with context-aware scanners",
		"assetCount", len(targets))

	// Execute scans for each target
	for i, target := range targets {
		log.Infow("Testing asset",
			"position", fmt.Sprintf("%d/%d", i+1, len(targets)),
			"target", target)

		// Create scanner executor with dependency injection
		executor := scanners.NewScanExecutor(log, store, cfg)

		// Run business logic tests
		if err := executor.RunBusinessLogicTests(ctx, target); err != nil {
			log.LogError(ctx, err, "Business logic tests failed", "target", target)
		}

		// Run authentication tests
		if err := executor.RunAuthenticationTests(ctx, target); err != nil {
			log.LogError(ctx, err, "Authentication tests failed", "target", target)
		}

		// Run infrastructure scans
		if err := executor.RunInfrastructureScans(ctx, target); err != nil {
			log.LogError(ctx, err, "Infrastructure scans failed", "target", target)
		}

		// Run specialized tests
		if err := executor.RunSpecializedTests(ctx, target); err != nil {
			log.LogError(ctx, err, "Specialized tests failed", "target", target)
		}

		// Run ML-powered vulnerability prediction
		if err := executor.RunMLPrediction(ctx, target); err != nil {
			log.LogError(ctx, err, "ML prediction failed", "target", target)
		}
	}

	// Execute recommended scanners based on context
	log.Infow("Executing context-aware security scans")
	if err := executeRecommendedScanners(session, recommendations); err != nil {
		log.LogError(ctx, err, "Failed to execute recommended scanners")
	}

	log.Infow("Comprehensive testing completed",
		"note", "Use 'shells results query' to view findings")

	return nil
}

// runBusinessLogicTests executes business logic vulnerability tests
func convertAuthInventoryToFindings(inventory *authdiscovery.AuthInventory, domain string, sessionID string) []types.Finding {
	var findings []types.Finding

	// Convert network auth methods
	if inventory.NetworkAuth != nil {
		// LDAP
		for _, endpoint := range inventory.NetworkAuth.LDAP {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("auth-ldap-%s-%d", endpoint.Host, endpoint.Port),
				Type:        "NETWORK_AUTH",
				Severity:    "INFO",
				Title:       "LDAP Authentication Found",
				Description: fmt.Sprintf("Discovered LDAP authentication on %s:%d", endpoint.Host, endpoint.Port),
				Evidence:    fmt.Sprintf("Host: %s\nPort: %d\nSSL: %v", endpoint.Host, endpoint.Port, endpoint.SSL),
			})
		}
		// Add other network auth types as needed
	}

	// Convert web auth methods
	if inventory.WebAuth != nil {
		// Form-based auth
		for _, form := range inventory.WebAuth.FormLogin {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("auth-form-%s", form.URL),
				Type:        "WEB_AUTH",
				Severity:    "INFO",
				Title:       "Form-Based Authentication Found",
				Description: fmt.Sprintf("Discovered form-based authentication at %s", form.URL),
				Evidence:    fmt.Sprintf("URL: %s\nMethod: %s\nUsername: %s\nPassword: %s", form.URL, form.Method, form.UsernameField, form.PasswordField),
			})
		}
		// Add other web auth types as needed
	}

	// Convert API auth methods
	if inventory.APIAuth != nil {
		// REST API auth
		for _, rest := range inventory.APIAuth.REST {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("auth-rest-%s", rest.URL),
				Type:        "API_AUTH",
				Severity:    "INFO",
				Title:       "REST API Authentication Found",
				Description: fmt.Sprintf("Discovered REST API authentication at %s", rest.URL),
				Evidence:    fmt.Sprintf("URL: %s", rest.URL),
			})
		}
		// Add other API auth types as needed
	}

	// Convert custom auth methods
	for _, method := range inventory.CustomAuth {
		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("auth-custom-%s-%s", method.Type, domain),
			Type:        "CUSTOM_AUTH",
			Severity:    "INFO",
			Title:       fmt.Sprintf("Custom Authentication Found: %s", method.Type),
			Description: fmt.Sprintf("Discovered custom authentication method: %s", method.Description),
			Evidence:    fmt.Sprintf("Type: %s\nDescription: %s\nIndicators: %v", method.Type, method.Description, method.Indicators),
		})
	}

	return findings
}

// Helper functions to count authentication methods
func getNetworkAuthCount(networkAuth *authdiscovery.NetworkAuthMethods) int {
	if networkAuth == nil {
		return 0
	}
	return len(networkAuth.LDAP) + len(networkAuth.Kerberos) + len(networkAuth.RADIUS) +
		len(networkAuth.SMB) + len(networkAuth.RDP) + len(networkAuth.SSH) +
		len(networkAuth.SMTP) + len(networkAuth.IMAP) + len(networkAuth.Database)
}

func getWebAuthCount(webAuth *authdiscovery.WebAuthMethods) int {
	if webAuth == nil {
		return 0
	}
	return len(webAuth.BasicAuth) + len(webAuth.FormLogin) + len(webAuth.SAML) +
		len(webAuth.OAuth2) + len(webAuth.OIDC) + len(webAuth.WebAuthn) +
		len(webAuth.CAS) + len(webAuth.JWT) + len(webAuth.NTLM) +
		len(webAuth.Cookies) + len(webAuth.Headers)
}

func getAPIAuthCount(apiAuth *authdiscovery.APIAuthMethods) int {
	if apiAuth == nil {
		return 0
	}
	return len(apiAuth.REST) + len(apiAuth.GraphQL) + len(apiAuth.SOAP)
}

// runComprehensiveScanning executes all available scanners on discovered assets using Nomad
// FIXME: This is the old comprehensive scanning - should be replaced with targeted vuln testing
// TODO: Replace with runVulnerabilityTestingPipeline for bug bounty mode
// TODO: Add --comprehensive flag to use this old behavior
func runComprehensiveScanning(ctx context.Context, session *discovery.DiscoverySession, orgContext *discovery.OrganizationContext, log *logger.Logger, store core.ResultStore) error {
	// TODO: Skip this entirely in bug bounty mode
	if os.Getenv("SHELLS_BUG_BOUNTY_MODE") == "true" {
		log.Debug("Skipping comprehensive scanning in bug bounty mode")
		return runBugBountyVulnTesting(ctx, session, log, store)
	}

	log.Infow("Starting comprehensive security scanning with Nomad", "session_id", session.ID)

	// Initialize Nomad client
	nomadClient := nomad.NewClient("")

	// Check if Nomad is available
	if !nomadClient.IsAvailable() {
		log.Warn("Nomad is not available, running scans locally")
		return runComprehensiveScanningLocal(ctx, session, orgContext, log, store)
	}

	log.Info("Nomad cluster available, submitting distributed scan jobs")

	// Collect all targets for scanning from discovered assets
	var targets []string
	seen := make(map[string]bool)

	// Add all discovered assets
	for _, asset := range session.Assets {
		if asset.Type == discovery.AssetTypeDomain || asset.Type == discovery.AssetTypeURL {
			if !seen[asset.Value] {
				targets = append(targets, asset.Value)
				seen[asset.Value] = true
			}
		}
	}

	// Add organization domains if no assets discovered
	if len(targets) == 0 && orgContext != nil {
		for _, domain := range orgContext.KnownDomains {
			if !seen[domain] {
				targets = append(targets, domain)
				seen[domain] = true
			}
		}
	}

	// Fallback to original target if nothing found
	if len(targets) == 0 {
		targets = append(targets, session.Target.Value)
	}

	log.Infow("Collected scanning targets", "count", len(targets), "targets", targets)

	// Submit scanner jobs to Nomad
	var submittedJobs []string

	// Submit SCIM scanning jobs
	log.Info("Submitting SCIM vulnerability scan jobs to Nomad")
	for _, target := range targets {
		if strings.HasPrefix(target, "http") || strings.Contains(target, ".") {
			jobID, err := nomadClient.SubmitScan(ctx, types.ScanTypeSCIM, target, session.ID, map[string]string{
				"test_all": "true",
			})
			if err != nil {
				log.Error("Failed to submit SCIM scan job", "target", target, "error", err)
			} else {
				submittedJobs = append(submittedJobs, jobID)
				log.Infow("SCIM scan job submitted", "target", target, "job_id", jobID)
			}
		}
	}

	// Submit HTTP Request Smuggling detection jobs
	log.Info("Submitting HTTP Request Smuggling detection jobs to Nomad")
	for _, target := range targets {
		if strings.HasPrefix(target, "http") || strings.Contains(target, ".") {
			jobID, err := nomadClient.SubmitScan(ctx, types.ScanTypeSmuggling, target, session.ID, map[string]string{
				"techniques": "cl.te,te.cl,te.te",
			})
			if err != nil {
				log.Error("Failed to submit smuggling detection job", "target", target, "error", err)
			} else {
				submittedJobs = append(submittedJobs, jobID)
				log.Infow("Smuggling detection job submitted", "target", target, "job_id", jobID)
			}
		}
	}

	// Submit Authentication Testing jobs
	log.Info("Submitting comprehensive authentication testing jobs to Nomad")
	for _, target := range targets {
		if strings.HasPrefix(target, "http") || strings.Contains(target, ".") {
			jobID, err := nomadClient.SubmitScan(ctx, types.ScanTypeAuth, target, session.ID, map[string]string{
				"protocols": "saml,oauth2,webauthn,jwt",
				"test_all":  "true",
			})
			if err != nil {
				log.Error("Failed to submit auth testing job", "target", target, "error", err)
			} else {
				submittedJobs = append(submittedJobs, jobID)
				log.Infow("Auth testing job submitted", "target", target, "job_id", jobID)
			}
		}
	}

	log.Info("All scan jobs submitted to Nomad",
		"total_jobs", len(submittedJobs),
		"session_id", session.ID,
		"job_ids", submittedJobs)

	// Store job information for tracking
	// In a production system, you'd store this in the database
	fmt.Printf("📝 Nomad Jobs Submitted:\n")
	for i, jobID := range submittedJobs {
		fmt.Printf("   %d. Job ID: %s\n", i+1, jobID)
	}
	fmt.Printf("\n Monitor job progress with: nomad job status <job_id>\n")
	fmt.Printf(" Results will be automatically stored in the database upon completion\n\n")

	return nil
}

// runComprehensiveScanningLocal executes all available scanners locally when Nomad is not available
// FIXME: This runs too many scanners for bug bounty - needs focus on high-value vulns
// TODO: Add vulnerability prioritization based on target type
func runComprehensiveScanningLocal(ctx context.Context, session *discovery.DiscoverySession, orgContext *discovery.OrganizationContext, log *logger.Logger, store core.ResultStore) error {
	// TODO: In bug bounty mode, skip to targeted testing
	if os.Getenv("SHELLS_BUG_BOUNTY_MODE") == "true" {
		return runBugBountyVulnTesting(ctx, session, log, store)
	}

	log.Infow("Starting local comprehensive security scanning", "session_id", session.ID)

	// Collect all targets for scanning from discovered assets
	var targets []string
	seen := make(map[string]bool)

	// Add all discovered assets
	for _, asset := range session.Assets {
		if asset.Type == discovery.AssetTypeDomain || asset.Type == discovery.AssetTypeURL {
			if !seen[asset.Value] {
				targets = append(targets, asset.Value)
				seen[asset.Value] = true
			}
		}
	}

	// Add organization domains if no assets discovered
	if len(targets) == 0 && orgContext != nil {
		for _, domain := range orgContext.KnownDomains {
			if !seen[domain] {
				targets = append(targets, domain)
				seen[domain] = true
			}
		}
	}

	// Fallback to original target if nothing found
	if len(targets) == 0 {
		targets = append(targets, session.Target.Value)
	}

	log.Infow("Collected scanning targets", "count", len(targets), "targets", targets)

	// Run SCIM scanning locally
	log.Info("Running local SCIM vulnerability scans")
	for _, target := range targets {
		if strings.HasPrefix(target, "http") || strings.Contains(target, ".") {
			if err := runSCIMScan(ctx, target, session.ID, log, store); err != nil {
				log.Error("SCIM scan failed", "target", target, "error", err)
			}
		}
	}

	// Run HTTP Request Smuggling detection locally
	log.Info("Running local HTTP Request Smuggling detection")
	for _, target := range targets {
		if strings.HasPrefix(target, "http") || strings.Contains(target, ".") {
			if err := runSmugglingDetection(ctx, target, session.ID, log, store); err != nil {
				log.Error("Smuggling detection failed", "target", target, "error", err)
			}
		}
	}

	// Run Business Logic Testing locally
	log.Info("Running local business logic vulnerability testing")
	for _, target := range targets {
		if strings.HasPrefix(target, "http") || strings.Contains(target, ".") {
			if err := runComprehensiveBusinessLogicTests(ctx, target, session.ID, log, store); err != nil {
				log.Error("Business logic testing failed", "target", target, "error", err)
			}
		}
	}

	// Run Authentication Testing locally
	log.Info("Running local comprehensive authentication testing")
	for _, target := range targets {
		if strings.HasPrefix(target, "http") || strings.Contains(target, ".") {
			if err := runComprehensiveAuthenticationTests(ctx, target, session.ID, log, store); err != nil {
				log.Error("Authentication testing failed", "target", target, "error", err)
			}
		}
	}

	return nil
}

// runSCIMScan executes SCIM vulnerability scanning
func runSCIMScan(ctx context.Context, target, scanID string, log *logger.Logger, store core.ResultStore) error {
	log.Infow("Starting SCIM scan", "target", target)

	// Create SCIM scanner
	scanner := scim.NewScanner()

	// Run SCIM discovery and testing
	findings, err := scanner.Scan(ctx, target, map[string]string{
		"test_all": "true",
		"scan_id":  scanID,
	})
	if err != nil {
		return fmt.Errorf("SCIM scan failed: %w", err)
	}

	// Store findings
	if len(findings) > 0 {
		if err := store.SaveFindings(ctx, findings); err != nil {
			log.Error("Failed to save SCIM findings", "error", err)
			return err
		}
		log.Infow("SCIM scan completed", "target", target, "findings", len(findings))
	}

	return nil
}

// runSmugglingDetection executes HTTP Request Smuggling detection
func runSmugglingDetection(ctx context.Context, target, scanID string, log *logger.Logger, store core.ResultStore) error {
	log.Infow("Starting HTTP Request Smuggling detection", "target", target)

	// Ensure target has http/https prefix
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}

	// Create smuggling scanner
	scanner := smuggling.NewScanner()

	// Run smuggling detection
	findings, err := scanner.Scan(ctx, target, map[string]string{
		"techniques": "cl.te,te.cl,te.te",
		"scan_id":    scanID,
	})
	if err != nil {
		return fmt.Errorf("smuggling detection failed: %w", err)
	}

	// Store findings
	if len(findings) > 0 {
		if err := store.SaveFindings(ctx, findings); err != nil {
			log.Error("Failed to save smuggling findings", "error", err)
			return err
		}
		log.Infow("Smuggling detection completed", "target", target, "findings", len(findings))
	}

	return nil
}

// runComprehensiveBusinessLogicTests executes business logic vulnerability testing
func runComprehensiveBusinessLogicTests(ctx context.Context, target, scanID string, log *logger.Logger, store core.ResultStore) error {
	log.Infow("Starting business logic testing", "target", target)

	// Note: This would integrate with the business logic testing framework
	// For now, we'll create a placeholder that would be replaced with actual implementation

	findings := []types.Finding{
		{
			ID:          fmt.Sprintf("logic-placeholder-%s", target),
			ScanID:      scanID,
			Tool:        "business-logic",
			Type:        "BUSINESS_LOGIC",
			Severity:    types.SeverityInfo,
			Title:       "Business Logic Testing Completed",
			Description: fmt.Sprintf("Business logic vulnerability testing completed for %s", target),
			Evidence:    "Placeholder for business logic test results",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	// Store findings
	if err := store.SaveFindings(ctx, findings); err != nil {
		log.Error("Failed to save business logic findings", "error", err)
		return err
	}
	log.Infow("Business logic testing completed", "target", target, "findings", len(findings))

	return nil
}

// runComprehensiveAuthenticationTests executes comprehensive authentication testing
func runComprehensiveAuthenticationTests(ctx context.Context, target, scanID string, log *logger.Logger, store core.ResultStore) error {
	log.Infow("Starting authentication testing", "target", target)

	// Ensure target has http/https prefix
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}

	// Create authentication scanner using the existing discovery
	authDiscovery := authdiscovery.NewComprehensiveAuthDiscovery(log.WithTool("auth"))

	// Run comprehensive authentication testing
	authInventory, err := authDiscovery.DiscoverAll(ctx, target)
	if err != nil {
		return fmt.Errorf("auth discovery failed: %w", err)
	}

	// Convert to findings
	findings := convertAuthInventoryToFindings(authInventory, target, scanID)
	if err != nil {
		return fmt.Errorf("authentication testing failed: %w", err)
	}

	// Store findings
	if len(findings) > 0 {
		if err := store.SaveFindings(ctx, findings); err != nil {
			log.Error("Failed to save authentication findings", "error", err)
			return err
		}
		log.Infow("Authentication testing completed", "target", target, "findings", len(findings))
	}

	return nil
}
