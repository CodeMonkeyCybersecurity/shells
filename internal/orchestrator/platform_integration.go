// internal/orchestrator/platform_integration.go
//
// Platform Integration - Bug Bounty Platform Scope Import
//
// REFACTORING CONTEXT:
// Extracted from bounty_engine.go Execute() method (lines 494-653, ~160 lines)
// Isolates bug bounty platform API integration from core execution logic.
//
// PHILOSOPHY ALIGNMENT:
// - Human-centric: Clear CLI feedback during scope import operations
// - Evidence-based: Validates scope from authoritative platform APIs
// - Sustainable: Isolated module for platform-specific logic
// - Safe: Comprehensive error handling, fails gracefully
//
// SUPPORTED PLATFORMS:
// - HackerOne (h1)
// - Bugcrowd (bc)
// - Intigriti
// - YesWeHack (ywh)

package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scope"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// PlatformIntegration handles bug bounty platform scope import
type PlatformIntegration struct {
	scopeManager *scope.Manager
	logger       *logger.Logger
	config       BugBountyConfig
}

// NewPlatformIntegration creates a new platform integration manager
func NewPlatformIntegration(
	scopeManager *scope.Manager,
	logger *logger.Logger,
	config BugBountyConfig,
) *PlatformIntegration {
	return &PlatformIntegration{
		scopeManager: scopeManager,
		logger:       logger.WithComponent("platform-integration"),
		config:       config,
	}
}

// ImportScope imports bug bounty program scope from the configured platform
// Returns true if scope was successfully imported, false if disabled or failed
func (p *PlatformIntegration) ImportScope(
	ctx context.Context,
	updateProgress func(phase string, pct float64, completed []string),
	saveCheckpoint func(phase string, pct float64, completed []string, findings []types.Finding),
) bool {
	// Check if scope import is enabled and configured
	if p.scopeManager == nil {
		return false
	}

	if p.config.BugBountyPlatform == "" || p.config.BugBountyProgram == "" {
		return false
	}

	scopeImportStart := time.Now()

	// IMMEDIATE CLI FEEDBACK - Show user what's happening
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Scope Import: Bug Bounty Program")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("   Platform: %s\n", p.config.BugBountyPlatform)
	fmt.Printf("   Program: %s\n", p.config.BugBountyProgram)
	fmt.Printf("   • Fetching program scope from platform API...\n")
	fmt.Println()

	p.logger.Infow("  Importing bug bounty program scope",
		"platform", p.config.BugBountyPlatform,
		"program", p.config.BugBountyProgram,
	)

	// Get platform type
	platformType, err := p.resolvePlatformType(p.config.BugBountyPlatform)
	if err != nil {
		p.logger.Errorw("Unsupported bug bounty platform",
			"platform", p.config.BugBountyPlatform,
			"supported", []string{"hackerone", "bugcrowd", "intigriti", "yeswehack"},
		)
		fmt.Printf("   ⚠️  Unsupported platform: %s\n", p.config.BugBountyPlatform)
		fmt.Printf("   Supported: hackerone, bugcrowd, intigriti, yeswehack\n")
		fmt.Printf("   Continuing without scope validation...\n")
		fmt.Println()
		return false
	}

	// Get platform client
	client := p.scopeManager.GetPlatformClient(platformType)
	if client == nil {
		p.logger.Errorw("Platform client not available", "platform", platformType)
		fmt.Printf("   ⚠️  Platform client not available\n")
		fmt.Printf("   Continuing without scope validation...\n")
		fmt.Println()
		return false
	}

	// Configure client with API credentials
	if !p.configureClient(client, platformType) {
		// Warning already logged, continue with public API access
	}

	// Fetch program from platform
	program, err := client.GetProgram(ctx, p.config.BugBountyProgram)
	if err != nil {
		p.handleFetchError(err)
		return false
	}

	// Add program to scope manager
	if err := p.scopeManager.AddProgram(program); err != nil {
		p.logger.Errorw("Failed to add program to scope manager",
			"error", err,
			"program", program.Name,
		)
		fmt.Printf("   ⚠️  Failed to add program: %v\n", err)
		fmt.Printf("   Continuing without scope validation...\n")
		fmt.Println()
		return false
	}

	// Success - display summary
	p.displayScopeSummary(program, time.Since(scopeImportStart))

	// Update progress tracking
	if updateProgress != nil {
		updateProgress("scope_import", 2.0, []string{"scope_import"})
	}
	if saveCheckpoint != nil {
		saveCheckpoint("scope_import", 2.0, []string{"scope_import"}, []types.Finding{})
	}

	return true
}

// resolvePlatformType converts platform name to scope.Platform enum
func (p *PlatformIntegration) resolvePlatformType(platformName string) (scope.Platform, error) {
	switch strings.ToLower(platformName) {
	case "hackerone", "h1":
		return scope.PlatformHackerOne, nil
	case "bugcrowd", "bc":
		return scope.PlatformBugcrowd, nil
	case "intigriti":
		return scope.PlatformIntigriti, nil
	case "yeswehack", "ywh":
		return scope.PlatformYesWeHack, nil
	default:
		return "", fmt.Errorf("unsupported platform: %s", platformName)
	}
}

// configureClient configures the platform client with API credentials
// Returns true if credentials were configured, false if not available
func (p *PlatformIntegration) configureClient(client scope.PlatformClient, platformType scope.Platform) bool {
	platformKey := strings.ToLower(p.config.BugBountyPlatform)

	cred, hasCredential := p.config.PlatformCredentials[platformKey]
	if !hasCredential {
		p.logger.Infow("No platform credentials configured",
			"platform", p.config.BugBountyPlatform,
			"note", "Will attempt public API access",
			"hint", fmt.Sprintf("Set %s_USERNAME and %s_API_KEY environment variables for private programs",
				strings.ToUpper(p.config.BugBountyPlatform),
				strings.ToUpper(p.config.BugBountyPlatform)),
		)
		return false
	}

	if cred.Username == "" || cred.APIKey == "" {
		p.logger.Warnw("Platform credentials incomplete",
			"platform", p.config.BugBountyPlatform,
			"has_username", cred.Username != "",
			"has_api_key", cred.APIKey != "",
			"note", "Will attempt public API access",
		)
		return false
	}

	// Configure client based on platform type
	switch client := client.(type) {
	case *scope.HackerOneClient:
		client.Configure(cred.Username, cred.APIKey)
		p.logger.Debugw("Configured HackerOne API credentials", "username", cred.Username)
		return true
	case *scope.BugcrowdClient:
		client.Configure(cred.APIKey) // Bugcrowd uses API token only
		p.logger.Debugw("Configured Bugcrowd API credentials")
		return true
	default:
		p.logger.Warnw("Unknown client type, credentials not configured", "platform", platformType)
		return false
	}
}

// handleFetchError handles errors during program fetch and provides helpful CLI feedback
func (p *PlatformIntegration) handleFetchError(err error) {
	p.logger.Errorw("Failed to fetch bug bounty program",
		"error", err,
		"platform", p.config.BugBountyPlatform,
		"program", p.config.BugBountyProgram,
	)
	fmt.Printf("   ⚠️  Failed to fetch program: %v\n", err)

	// Check if this looks like an authentication error
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "401") || strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "403") || strings.Contains(errStr, "forbidden") ||
		strings.Contains(errStr, "invalid credentials") {
		fmt.Printf("\n   Authentication failed. For private programs, set:\n")
		platformUpper := strings.ToUpper(p.config.BugBountyPlatform)
		fmt.Printf("     export %s_USERNAME=your-username\n", platformUpper)
		fmt.Printf("     export %s_API_KEY=your-api-key\n", platformUpper)
		fmt.Println()
	} else {
		fmt.Printf("   Continuing without scope validation...\n")
		fmt.Println()
	}
}

// displayScopeSummary displays the imported scope summary to the user
func (p *PlatformIntegration) displayScopeSummary(program *scope.Program, duration time.Duration) {
	p.logger.Infow("  Bug bounty scope import completed",
		"program_id", program.ID,
		"duration", duration.String(),
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
	fmt.Printf("   Duration: %s\n", duration.Round(time.Millisecond))
	fmt.Println()
}

// GetScopeManager returns the scope manager (nil if scope import failed)
func (p *PlatformIntegration) GetScopeManager() *scope.Manager {
	return p.scopeManager
}

// DisableScopeValidation disables the scope manager (used after import failure)
func (p *PlatformIntegration) DisableScopeValidation() {
	p.scopeManager = nil
}
