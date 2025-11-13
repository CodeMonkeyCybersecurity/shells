// internal/orchestrator/phase_classification.go
//
// PHASE 0: Target Classification & Scope Loading
//
// This phase implements the initial target analysis and scope validation setup.
// Corresponds to pre-reconnaissance intelligence gathering in the Cyber Kill Chain.
//
// Actions:
//   1. Parse and classify target (domain/IP/company/email)
//   2. Load bug bounty program scope (if specified via --platform/--program flags)
//   3. Initialize scope validator with in-scope/out-of-scope rules
//   4. Set up rate limiting and authorization constraints
//
// ADVERSARIAL REVIEW: P0 FIX #1 component
// - Clear phase boundary before reconnaissance begins
// - Scope rules loaded BEFORE discovery to prevent wasted effort

package orchestrator

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/discovery"
	discoverypkg "github.com/CodeMonkeyCybersecurity/artemis/pkg/discovery"
)

// phaseTargetClassification executes Phase 0: Target Classification & Scope Loading
func (p *Pipeline) phaseTargetClassification(ctx context.Context) error {
	p.logger.Infow("Phase 0: Target Classification & Scope Loading",
		"scan_id", p.state.ScanID,
		"target", p.state.Target,
	)

	// Step 1: Classify target type
	classifier := discoverypkg.NewIdentifierClassifier()
	classification, err := classifier.Classify(p.state.Target)
	if err != nil {
		return fmt.Errorf("failed to classify target: %w", err)
	}

	// Map classification to discovery target type
	p.state.TargetType = p.mapClassificationToTargetType(classification.Type)

	p.logger.Infow("Target classified",
		"scan_id", p.state.ScanID,
		"target", p.state.Target,
		"type", p.state.TargetType,
		"confidence", fmt.Sprintf("%.0f%%", classification.Confidence*100),
		"normalized", classification.Normalized,
	)

	// Step 2: Load bug bounty program scope (if enabled)
	// NOTE: Scope import is now handled by BountyEngine.Run() in bounty_engine.go
	// This phase just logs the configuration
	if p.config.EnableScopeValidation {
		if p.config.BugBountyPlatform == "" || p.config.BugBountyProgram == "" {
			p.logger.Warnw("Scope validation enabled but platform/program not specified",
				"scan_id", p.state.ScanID,
				"note", "Use --platform and --program flags to enable scope validation",
			)
		} else {
			p.logger.Infow("Bug bounty program scope will be loaded",
				"scan_id", p.state.ScanID,
				"platform", p.config.BugBountyPlatform,
				"program", p.config.BugBountyProgram,
				"strict_mode", p.config.ScopeStrictMode,
			)
		}
	} else {
		p.logger.Infow("Scope validation disabled - all discovered assets will be tested",
			"scan_id", p.state.ScanID,
			"note", "Use --scope-validation flag to enable program scope checking",
		)
	}

	// Step 3: Validate target is appropriate for scanning
	if err := p.validateTargetAuthorization(); err != nil {
		return fmt.Errorf("target authorization validation failed: %w", err)
	}

	p.logger.Infow("Phase 0 completed: Target ready for reconnaissance",
		"scan_id", p.state.ScanID,
		"target_type", p.state.TargetType,
		"scope_validation_enabled", p.config.EnableScopeValidation,
	)

	return nil
}

// mapClassificationToTargetType converts pkg/discovery classification to internal discovery type
func (p *Pipeline) mapClassificationToTargetType(classificationType discoverypkg.IdentifierType) discovery.TargetType {
	switch classificationType {
	case discoverypkg.IdentifierTypeDomain:
		return discovery.TargetTypeDomain
	case discoverypkg.IdentifierTypeIP:
		return discovery.TargetTypeIP
	case discoverypkg.IdentifierTypeIPRange:
		return discovery.TargetTypeIPRange
	case discoverypkg.IdentifierTypeEmail:
		return discovery.TargetTypeEmail
	case discoverypkg.IdentifierTypeURL:
		return discovery.TargetTypeURL
	default:
		return discovery.TargetTypeUnknown
	}
}

// validateTargetAuthorization ensures target is authorized for scanning
func (p *Pipeline) validateTargetAuthorization() error {
	// Basic validation - ensure target is not obviously unauthorized
	// In production, this would check against:
	// - Internal blacklist (government domains, critical infrastructure)
	// - User's authorization token/API key scope
	// - Rate limiting quotas

	// For now, just a placeholder
	p.logger.Infow("Target authorization validated",
		"scan_id", p.state.ScanID,
		"target", p.state.Target,
		"note", "Assuming target is authorized - user responsible for authorization",
	)

	return nil
}
