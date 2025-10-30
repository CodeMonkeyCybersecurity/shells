// internal/orchestrator/factory.go
//
// Engine Factory - Builds BugBountyEngine with all dependencies
//
// REFACTORING CONTEXT:
// Extracted from bounty_engine.go NewBugBountyEngine() (lines 223-572, ~349 lines)
// This factory handles initialization of all scanners, discovery engines, correlators,
// and other dependencies using builder pattern for clean dependency injection.
//
// PHILOSOPHY ALIGNMENT:
// - Sustainable: Clear initialization logic, easy to modify scanner configuration
// - Human-centric: Explicit error handling with actionable messages
// - Evidence-based: Validates dependencies exist before proceeding

package orchestrator

import (
	"fmt"
	"os/exec"
	"time"

	configpkg "github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/internal/orchestrator/scanners"
	"github.com/CodeMonkeyCybersecurity/shells/internal/plugins/api"
	"github.com/CodeMonkeyCybersecurity/shells/internal/plugins/nmap"
	"github.com/CodeMonkeyCybersecurity/shells/internal/plugins/nuclei"
	"github.com/CodeMonkeyCybersecurity/shells/internal/ratelimit"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/oauth2"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/saml"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/webauthn"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/enrichment"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/intel/certs"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scanners/idor"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scanners/restapi"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scim"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scope"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/workers"
	"github.com/jmoiron/sqlx"
)

// EngineFactory builds BugBountyEngine instances with all dependencies
type EngineFactory struct {
	store     core.ResultStore
	telemetry core.Telemetry
	logger    *logger.Logger
	config    BugBountyConfig
}

// NewEngineFactory creates a new factory for building engines
func NewEngineFactory(
	store core.ResultStore,
	telemetry core.Telemetry,
	logger *logger.Logger,
	config BugBountyConfig,
) *EngineFactory {
	return &EngineFactory{
		store:     store,
		telemetry: telemetry,
		logger:    logger,
		config:    config,
	}
}

// Build constructs a fully initialized BugBountyEngine
func (f *EngineFactory) Build() (*BugBountyEngine, error) {
	f.logger.Infow("Building BugBountyEngine",
		"component", "factory",
	)

	// Build components in dependency order
	logAdapter := f.buildLoggerAdapter()
	rateLimiter := f.buildRateLimiter()
	discoveryEngine := f.buildDiscoveryEngine()
	authDiscovery := f.buildAuthDiscovery()
	orgCorrelator, certIntel := f.buildOrganizationCorrelator()
	scopeManager := f.buildScopeManager()
	enricher := f.buildEnricher()
	scannerMgr, err := f.buildScannerManager(logAdapter, authDiscovery)
	if err != nil {
		return nil, fmt.Errorf("failed to build scanner manager: %w", err)
	}
	pythonWorkers := f.buildPythonWorkers()
	checkpointMgr := f.buildCheckpointManager()
	outputFormatter := f.buildOutputFormatter()
	persistenceMgr := f.buildPersistenceManager(enricher, checkpointMgr)
	platformIntegration := f.buildPlatformIntegration(scopeManager)

	engine := &BugBountyEngine{
		store:               f.store,
		telemetry:           f.telemetry,
		logger:              f.logger,
		rateLimiter:         rateLimiter,
		discoveryEngine:     discoveryEngine,
		orgCorrelator:       orgCorrelator,
		certIntel:           certIntel,
		scopeManager:        scopeManager,
		authDiscovery:       authDiscovery,
		scannerManager:      scannerMgr,
		pythonWorkers:       pythonWorkers,
		enricher:            enricher,
		checkpointEnabled:   f.config.EnableCheckpointing,
		checkpointInterval:  f.config.CheckpointInterval,
		checkpointManager:   checkpointMgr,
		outputFormatter:     outputFormatter,
		persistenceManager:  persistenceMgr,
		platformIntegration: platformIntegration,
		config:              f.config,
	}

	f.logger.Infow("BugBountyEngine built successfully",
		"scanners_registered", len(scannerMgr.List()),
		"component", "factory",
	)

	return engine, nil
}

// buildLoggerAdapter creates unified logger adapter for all scanners
func (f *EngineFactory) buildLoggerAdapter() *loggerAdapter {
	return &loggerAdapter{logger: f.logger}
}

// buildRateLimiter creates rate limiter for request throttling
func (f *EngineFactory) buildRateLimiter() *ratelimit.Limiter {
	rateLimiterConfig := ratelimit.Config{
		RequestsPerSecond: f.config.RateLimitPerSecond,
		BurstSize:         f.config.RateLimitBurst,
		MinDelay:          100 * time.Millisecond,
	}
	limiter := ratelimit.NewLimiter(rateLimiterConfig)

	f.logger.Infow("Rate limiter initialized",
		"requests_per_second", f.config.RateLimitPerSecond,
		"burst_size", f.config.RateLimitBurst,
		"component", "factory",
	)

	return limiter
}

// buildDiscoveryEngine creates asset discovery engine
func (f *EngineFactory) buildDiscoveryEngine() *discovery.Engine {
	discoveryConfig := &discovery.DiscoveryConfig{
		MaxDepth:        f.config.MaxDepth,
		MaxAssets:       f.config.MaxAssets,
		Timeout:         f.config.DiscoveryTimeout,
		EnableDNS:       f.config.EnableDNS,
		EnableCertLog:   false,
		EnableSearch:    false,
		EnablePortScan:  f.config.EnablePortScan,
		EnableWebCrawl:  f.config.EnableWebCrawl,
		EnableTechStack: true,
		PortScanPorts:   "80,443,8080,8443,3000,5000,8000,8888",
		PortScanTimeout: 5 * time.Second,
	}

	return discovery.NewEngine(discoveryConfig, f.logger)
}

// buildAuthDiscovery creates authentication endpoint discovery engine
func (f *EngineFactory) buildAuthDiscovery() *auth.AuthDiscoveryEngine {
	authDiscoveryConfig := auth.DiscoveryConfig{
		EnablePortScan:    f.config.EnablePortScan,
		EnableWebCrawl:    f.config.EnableWebCrawl,
		EnableMLDetection: false,
		MaxDepth:          f.config.MaxDepth,
		Timeout:           f.config.DiscoveryTimeout,
		UserAgent:         "Shells Bug Bounty Scanner/1.0",
	}

	return auth.NewAuthDiscoveryEngine(authDiscoveryConfig, f.logger)
}

// buildOrganizationCorrelator creates organization footprinting correlator
func (f *EngineFactory) buildOrganizationCorrelator() (*correlation.OrganizationCorrelator, *certs.CertIntel) {
	if !f.config.EnableWHOISAnalysis && !f.config.EnableCertTransparency && !f.config.EnableRelatedDomainDisc {
		return nil, nil
	}

	// Initialize certificate intelligence client
	certIntel := certs.NewCertIntel(f.logger)

	// Initialize organization correlator
	correlatorConfig := correlation.CorrelatorConfig{
		EnableWhois:    f.config.EnableWHOISAnalysis,
		EnableCerts:    f.config.EnableCertTransparency,
		EnableASN:      true,
		EnableGitHub:   false,
		EnableLinkedIn: false,
		CacheTTL:       1 * time.Hour,
		MaxWorkers:     5,
	}
	orgCorrelator := correlation.NewOrganizationCorrelator(correlatorConfig, f.logger)

	// Set up clients
	whoisClient := correlation.NewDefaultWhoisClient(f.logger)
	certClient := correlation.NewDefaultCertificateClient(f.logger)
	asnClient := correlation.NewDefaultASNClient(f.logger)
	orgCorrelator.SetClients(whoisClient, certClient, asnClient, nil, nil, nil, nil)

	f.logger.Infow("Organization correlator initialized",
		"enable_whois", f.config.EnableWHOISAnalysis,
		"enable_cert_transparency", f.config.EnableCertTransparency,
		"component", "factory",
	)

	return orgCorrelator, certIntel
}

// buildScopeManager creates bug bounty scope manager
func (f *EngineFactory) buildScopeManager() *scope.Manager {
	if !f.config.EnableScopeValidation {
		return nil
	}

	// Get database connection from store
	var db *sqlx.DB
	if sqlStore, ok := f.store.(interface{ DB() *sqlx.DB }); ok {
		db = sqlStore.DB()
	} else {
		f.logger.Warnw("Scope validation disabled - store does not provide DB access",
			"component", "factory",
		)
		return nil
	}

	if db == nil {
		return nil
	}

	scopeConfig := &scope.Config{
		AutoSync:         false,
		CacheTTL:         1 * time.Hour,
		ValidateWorkers:  10,
		StrictMode:       f.config.ScopeStrictMode,
		EnableMonitoring: false,
	}
	scopeManager := scope.NewManager(db, f.logger, scopeConfig)

	f.logger.Infow("Scope manager initialized",
		"strict_mode", f.config.ScopeStrictMode,
		"component", "factory",
	)

	// Log platform scope import if specified
	if f.config.BugBountyPlatform != "" && f.config.BugBountyProgram != "" {
		f.logger.Infow("Bug bounty platform scope import requested",
			"platform", f.config.BugBountyPlatform,
			"program", f.config.BugBountyProgram,
			"component", "factory",
		)
	}

	return scopeManager
}

// buildEnricher creates result enrichment engine
func (f *EngineFactory) buildEnricher() *enrichment.ResultEnricher {
	if !f.config.EnableEnrichment {
		return nil
	}

	enricherConfig := enrichment.EnricherConfig{
		CVSSVersion:     "3.1",
		EnrichmentLevel: f.config.EnrichmentLevel,
		CacheSize:       1000,
		CacheTTL:        1 * time.Hour,
		MaxConcurrency:  10,
	}

	enricher, err := enrichment.NewResultEnricher(enricherConfig)
	if err != nil {
		f.logger.Warnw("Failed to initialize enrichment engine",
			"error", err,
			"component", "factory",
		)
		return nil
	}

	f.logger.Infow("Finding enrichment enabled",
		"level", f.config.EnrichmentLevel,
		"cvss_version", "3.1",
		"component", "factory",
	)

	return enricher
}

// buildScannerManager creates and registers all vulnerability scanners
func (f *EngineFactory) buildScannerManager(logAdapter *loggerAdapter, authDiscovery *auth.AuthDiscoveryEngine) (*scanners.Manager, error) {
	// Create scanner manager
	managerConfig := scanners.DefaultManagerConfig()
	managerConfig.RespectPriority = true
	managerConfig.MaxConcurrentScanners = 5

	mgr := scanners.NewManager(managerConfig, f.logger)

	// Register authentication scanner
	if f.config.EnableAuthTesting {
		samlScanner := saml.NewSAMLScanner(logAdapter)
		oauth2Scanner := oauth2.NewOAuth2Scanner(logAdapter)
		webauthnScanner := webauthn.NewWebAuthnScanner(logAdapter)

		authScanner := scanners.NewAuthenticationScanner(
			samlScanner,
			oauth2Scanner,
			webauthnScanner,
			authDiscovery,
			f.logger,
		)
		if err := mgr.Register("authentication", authScanner); err != nil {
			return nil, err
		}
		f.logger.Infow("Authentication scanner registered", "component", "factory")
	}

	// Register SCIM scanner
	if f.config.EnableSCIMTesting {
		scimCoreScanner := scim.NewScanner()
		scimScanner := scanners.NewSCIMScanner(
			scimCoreScanner,
			f.logger,
			scanners.SCIMConfig{},
		)
		if err := mgr.Register("scim", scimScanner); err != nil {
			return nil, err
		}
		f.logger.Infow("SCIM scanner registered", "component", "factory")
	}

	// Register API scanner
	if f.config.EnableAPITesting {
		restapiConfig := restapi.RESTAPIConfig{
			EnableSwaggerDiscovery: true,
			EnableMethodFuzzing:    true,
			EnableAuthBypass:       true,
			EnableIDORTesting:      true,
			Timeout:                f.config.ScanTimeout,
			MaxWorkers:             10,
			RateLimit:              int(f.config.RateLimitPerSecond),
		}
		restapiCoreScanner := NewRESTAPIScannerAdapter(restapiConfig, f.logger)
		apiScanner := scanners.NewAPIScanner(restapiCoreScanner, f.logger)
		if err := mgr.Register("api", apiScanner); err != nil {
			return nil, err
		}
		f.logger.Infow("API scanner registered", "component", "factory")
	}

	// Register Nmap scanner
	if f.config.EnableServiceFingerprint {
		nmapCfg := configpkg.NmapConfig{
			BinaryPath: "nmap",
			Timeout:    2 * time.Minute,
			Profiles: map[string]string{
				"default": "-sV --version-intensity 2 -T4",
			},
		}
		nmapCoreScanner := nmap.NewScanner(nmapCfg, logAdapter)
		nmapScanner := scanners.NewNmapScanner(
			nmapCoreScanner,
			f.logger,
			scanners.NmapConfig{},
		)
		if err := mgr.Register("nmap", nmapScanner); err != nil {
			return nil, err
		}
		f.logger.Infow("Nmap scanner registered", "component", "factory")
	}

	// Register Nuclei scanner
	if f.config.EnableNucleiScan {
		nucleiBinaryPath := "nuclei"
		if _, err := exec.LookPath(nucleiBinaryPath); err != nil {
			f.logger.Warnw("Nuclei scanner disabled - binary not found",
				"error", err,
				"component", "factory",
			)
		} else {
			nucleiConfig := nuclei.NucleiConfig{
				BinaryPath:  nucleiBinaryPath,
				Timeout:     f.config.ScanTimeout,
				RateLimit:   int(f.config.RateLimitPerSecond),
				Concurrency: 25,
			}
			nucleiCoreScanner := nuclei.NewScanner(nucleiConfig, logAdapter)
			nucleiScanner := scanners.NewNucleiScanner(
				nucleiCoreScanner,
				f.logger,
				scanners.NucleiConfig{},
			)
			if err := mgr.Register("nuclei", nucleiScanner); err != nil {
				return nil, err
			}
			f.logger.Infow("Nuclei scanner registered", "component", "factory")
		}
	}

	// Register GraphQL scanner
	if f.config.EnableGraphQLTesting {
		graphqlCoreScanner := api.NewGraphQLScanner(logAdapter)
		graphqlScanner := scanners.NewGraphQLScanner(graphqlCoreScanner, f.logger)
		if err := mgr.Register("graphql", graphqlScanner); err != nil {
			return nil, err
		}
		f.logger.Infow("GraphQL scanner registered", "component", "factory")
	}

	// Register IDOR scanner
	if f.config.EnableIDORTesting {
		idorConfig := idor.IDORConfig{
			MaxSequentialRange:     1000,
			ParallelWorkers:        10,
			Timeout:                f.config.ScanTimeout,
			RateLimit:              int(f.config.RateLimitPerSecond),
			EnableSequentialID:     true,
			EnableUUIDAnalysis:     true,
			EnableHorizontalTest:   true,
			EnablePatternLearning:  true,
			SmartRangeDetection:    true,
			SmartStopOnConsecutive: 50,
		}
		idorCoreScanner := NewIDORScannerAdapter(idorConfig, f.logger)
		idorScanner := scanners.NewIDORScanner(
			idorCoreScanner,
			f.logger,
			scanners.IDORConfig{},
		)
		if err := mgr.Register("idor", idorScanner); err != nil {
			return nil, err
		}
		f.logger.Infow("IDOR scanner registered", "component", "factory")
	}

	stats := mgr.GetStats()
	f.logger.Infow("Scanner manager built",
		"total_scanners", stats.TotalScanners,
		"enabled_scanners", stats.EnabledScanners,
		"component", "factory",
	)

	return mgr, nil
}

// buildPythonWorkers connects to Python worker service (optional)
func (f *EngineFactory) buildPythonWorkers() *workers.Client {
	workerURL := "http://localhost:5000"
	pythonWorkers := workers.NewClient(workerURL)

	if err := pythonWorkers.Health(); err != nil {
		f.logger.Warnw("Python worker service not available",
			"error", err,
			"worker_url", workerURL,
			"component", "factory",
		)
		return nil
	}

	f.logger.Infow("Python worker service connected",
		"worker_url", workerURL,
		"component", "factory",
	)

	return pythonWorkers
}

// buildCheckpointManager creates checkpoint manager if enabled
func (f *EngineFactory) buildCheckpointManager() CheckpointManager {
	if !f.config.EnableCheckpointing {
		return nil
	}

	f.logger.Infow("Checkpoint system initialized",
		"enabled", f.config.EnableCheckpointing,
		"interval", f.config.CheckpointInterval.String(),
		"component", "factory",
	)

	// TODO: Implement checkpoint manager adapter
	return nil
}

// buildOutputFormatter creates the output formatter for CLI display
func (f *EngineFactory) buildOutputFormatter() *OutputFormatter {
	return &OutputFormatter{
		logger: f.logger,
		config: f.config,
	}
}

// buildPersistenceManager creates the persistence manager for storing results
func (f *EngineFactory) buildPersistenceManager(enricher *enrichment.ResultEnricher, checkpointMgr CheckpointManager) *PersistenceManager {
	return &PersistenceManager{
		store:             f.store,
		enricher:          enricher,
		checkpointManager: checkpointMgr,
		logger:            f.logger,
		config:            f.config,
	}
}

// buildPlatformIntegration creates platform integration manager for bug bounty scope import
func (f *EngineFactory) buildPlatformIntegration(scopeManager *scope.Manager) *PlatformIntegration {
	return NewPlatformIntegration(scopeManager, f.logger, f.config)
}

