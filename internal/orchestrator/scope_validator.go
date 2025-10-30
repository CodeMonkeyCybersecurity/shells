// internal/orchestrator/scope_validator.go
//
// Scope Validator - Bug Bounty Program Scope Validation
//
// REFACTORING CONTEXT:
// Extracted from bounty_engine.go Execute() method (lines 705-818, ~113 lines)
// Isolates scope validation logic from core execution flow.
//
// PHILOSOPHY ALIGNMENT:
// - Human-centric: Clear CLI feedback showing validation results
// - Evidence-based: Validates against authoritative bug bounty program scope
// - Sustainable: Isolated module for scope filtering logic
// - Safe: Fail open on errors (include asset), strict mode for paranoid users
//
// CAPABILITIES:
// - Validate discovered assets against bug bounty program scope
// - Filter out-of-scope assets before testing (prevent legal issues)
// - Support strict mode (fail closed) and permissive mode (fail open)
// - Handle unknown scope ambiguity gracefully

package orchestrator

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/internal/orchestrator/scanners"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scope"
)

// ScopeValidator handles bug bounty program scope validation
type ScopeValidator struct {
	scopeManager *scope.Manager
	logger       *logger.Logger
	config       BugBountyConfig
}

// NewScopeValidator creates a new scope validator
func NewScopeValidator(
	scopeManager *scope.Manager,
	logger *logger.Logger,
	config BugBountyConfig,
) *ScopeValidator {
	return &ScopeValidator{
		scopeManager: scopeManager,
		logger:       logger.WithComponent("scope-validator"),
		config:       config,
	}
}

// ValidationResult contains the results of scope validation
type ValidationResult struct {
	InScope      []*scanners.AssetPriority
	OutOfScope   []*scanners.AssetPriority
	Unknown      []*scanners.AssetPriority
	Duration     time.Duration
}

// FilterAssets validates assets against bug bounty program scope
// Returns in-scope assets, out-of-scope assets, and unknown assets
func (s *ScopeValidator) FilterAssets(assets []*scanners.AssetPriority) *ValidationResult {
	// Check if scope validation is enabled
	if s.scopeManager == nil {
		// No scope manager - return all assets as in-scope
		return &ValidationResult{
			InScope:    assets,
			OutOfScope: []*scanners.AssetPriority{},
			Unknown:    []*scanners.AssetPriority{},
		}
	}

	startTime := time.Now()

	// IMMEDIATE CLI FEEDBACK
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Scope Validation: Bug Bounty Program")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("   Validating %d assets against program scope...\n", len(assets))
	fmt.Println()

	s.logger.Infow("  Starting scope validation",
		"assets_to_validate", len(assets),
		"strict_mode", s.config.ScopeStrictMode,
	)

	// Filter out-of-scope assets
	inScopeAssets := make([]*scanners.AssetPriority, 0, len(assets))
	outOfScopeAssets := make([]*scanners.AssetPriority, 0)
	unknownAssets := make([]*scanners.AssetPriority, 0)

	for _, asset := range assets {
		// Validate asset against scope
		validation, err := s.scopeManager.ValidateAsset(asset.Asset.Value)
		if err != nil {
			s.logger.Warnw("Asset validation error - including asset",
				"asset", asset.Asset.Value,
				"error", err,
			)
			// On error, include the asset (fail open)
			unknownAssets = append(unknownAssets, asset)
			inScopeAssets = append(inScopeAssets, asset)
			continue
		}

		if validation.Status == scope.ScopeStatusInScope {
			inScopeAssets = append(inScopeAssets, asset)
			s.logger.Debugw("Asset in scope",
				"asset", asset.Asset.Value,
				"program", validation.Program.Name,
			)
		} else if validation.Status == scope.ScopeStatusOutOfScope {
			outOfScopeAssets = append(outOfScopeAssets, asset)
			s.logger.Warnw("Asset out of scope - skipping",
				"asset", asset.Asset.Value,
				"reason", validation.Reason,
			)
		} else {
			// Unknown - behavior depends on strict mode
			if s.config.ScopeStrictMode {
				outOfScopeAssets = append(outOfScopeAssets, asset)
				s.logger.Warnw("Asset scope unknown (strict mode) - skipping",
					"asset", asset.Asset.Value,
				)
			} else {
				unknownAssets = append(unknownAssets, asset)
				inScopeAssets = append(inScopeAssets, asset)
				s.logger.Debugw("Asset scope unknown (permissive mode) - including",
					"asset", asset.Asset.Value,
				)
			}
		}
	}

	duration := time.Since(startTime)

	s.logger.Infow("  Scope validation completed",
		"in_scope", len(inScopeAssets),
		"out_of_scope", len(outOfScopeAssets),
		"unknown", len(unknownAssets),
		"duration", duration.String(),
	)

	// Display validation results
	s.displayResults(len(inScopeAssets), len(outOfScopeAssets), len(unknownAssets), duration)

	return &ValidationResult{
		InScope:    inScopeAssets,
		OutOfScope: outOfScopeAssets,
		Unknown:    unknownAssets,
		Duration:   duration,
	}
}

// displayResults shows validation results to user
func (s *ScopeValidator) displayResults(inScope, outOfScope, unknown int, duration time.Duration) {
	fmt.Printf("   ✓ Validation completed\n")
	fmt.Printf("   In-Scope Assets: %d\n", inScope)
	if outOfScope > 0 {
		fmt.Printf("   Out-of-Scope Assets: %d (skipped)\n", outOfScope)
	}
	if unknown > 0 {
		mode := "permissive"
		if s.config.ScopeStrictMode {
			mode = "strict"
		}
		fmt.Printf("   Unknown Scope Assets: %d (included in %s mode)\n", unknown, mode)
	}
	fmt.Printf("   Duration: %s\n", duration.Round(time.Millisecond))
	fmt.Println()
}

// IsEnabled checks if scope validation is enabled
func (s *ScopeValidator) IsEnabled() bool {
	return s.scopeManager != nil
}
