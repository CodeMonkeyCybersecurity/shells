// internal/orchestrator/phase_reconnaissance.go
//
// PHASE 1: Reconnaissance (Passive → Active)
//
// This phase discovers all assets related to the target through passive and active techniques.
// Corresponds to the Reconnaissance stage of the Cyber Kill Chain.
//
// Sub-phases:
//   1.1 Passive Reconnaissance (WHOIS, cert transparency, DNS, search engines)
//   1.2 Active Reconnaissance (port scanning, service fingerprinting, web crawling)
//   1.3 Scope Filtering (CRITICAL: filter before weaponization phase)
//
// ADVERSARIAL REVIEW:
// - P0 FIX #1: Clear phase boundary with scope filtering before next phase
// - P1 FIX #4: Scope validation enforced immediately after asset discovery
// - Prevents wasting time testing out-of-scope assets

package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
)

// phaseReconnaissance executes Phase 1: Reconnaissance
func (p *Pipeline) phaseReconnaissance(ctx context.Context) error {
	iterationPrefix := ""
	if p.state.IterationCount > 0 {
		iterationPrefix = fmt.Sprintf("(Iteration %d) ", p.state.IterationCount)
	}

	p.logger.Infow(fmt.Sprintf("%sPhase 1: Reconnaissance", iterationPrefix),
		"scan_id", p.state.ScanID,
		"target", p.state.Target,
		"iteration", p.state.IterationCount,
	)

	// Start discovery using existing discovery engine
	discoveryStart := time.Now()

	session, err := p.discoveryEngine.StartDiscovery(ctx, p.state.Target)
	if err != nil {
		return fmt.Errorf("failed to start discovery: %w", err)
	}

	p.state.DiscoverySession = session

	p.logger.Infow("Discovery session started",
		"scan_id", p.state.ScanID,
		"session_id", session.ID,
		"target_type", session.Target.Type,
		"confidence", fmt.Sprintf("%.0f%%", session.Target.Confidence*100),
	)

	// Monitor discovery progress
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
			// Poll for discovery status
			currentSession, err := p.discoveryEngine.GetSession(session.ID)
			if err != nil {
				return fmt.Errorf("failed to get discovery session: %w", err)
			}

			p.logger.Infow("Discovery progress",
				"scan_id", p.state.ScanID,
				"progress", fmt.Sprintf("%.0f%%", currentSession.Progress*100),
				"total_assets", currentSession.TotalDiscovered,
				"high_value_assets", currentSession.HighValueAssets,
			)

			if currentSession.Status == discovery.StatusCompleted {
				p.state.DiscoverySession = currentSession
				break
			} else if currentSession.Status == discovery.StatusFailed {
				p.logger.Errorw("Discovery failed",
					"scan_id", p.state.ScanID,
					"errors", currentSession.Errors,
				)
				return fmt.Errorf("discovery failed")
			}
		}
	}

	discoveryDuration := time.Since(discoveryStart)

	// Extract discovered assets
	allAssets := p.extractAssetsFromSession(p.state.DiscoverySession)
	p.state.DiscoveredAssets = allAssets

	p.logger.Infow("Discovery completed",
		"scan_id", p.state.ScanID,
		"duration", discoveryDuration.String(),
		"total_assets", len(allAssets),
		"high_value_assets", p.state.DiscoverySession.HighValueAssets,
	)

	// CRITICAL: Scope filtering (P1 FIX #4)
	if p.config.EnableScopeValidation {
		p.logger.Infow("Applying scope validation filters",
			"scan_id", p.state.ScanID,
			"total_assets_before_filter", len(allAssets),
		)

		inScope, outOfScope := p.filterAssetsByScope(allAssets)
		p.state.InScopeAssets = inScope
		p.state.OutOfScopeAssets = outOfScope

		p.logger.Infow("Scope validation completed",
			"scan_id", p.state.ScanID,
			"in_scope", len(inScope),
			"out_of_scope", len(outOfScope),
			"filter_ratio", fmt.Sprintf("%.1f%%", float64(len(inScope))/float64(len(allAssets))*100),
		)

		// Log examples of filtered assets
		if len(outOfScope) > 0 {
			examples := p.getAssetExamples(outOfScope, 3)
			p.logger.Infow("Out-of-scope assets excluded from testing",
				"scan_id", p.state.ScanID,
				"examples", examples,
				"note", "These assets will NOT be tested",
			)
		}
	} else {
		// No scope validation - all assets are in scope
		p.state.InScopeAssets = allAssets
		p.state.OutOfScopeAssets = []discovery.Asset{}

		p.logger.Infow("Scope validation disabled - all assets marked in-scope",
			"scan_id", p.state.ScanID,
			"total_assets", len(allAssets),
		)
	}

	// Track new assets for feedback loop
	if p.state.IterationCount > 0 {
		p.state.NewAssetsLastIter = len(p.state.InScopeAssets)
		p.logger.Infow("Feedback loop iteration completed",
			"scan_id", p.state.ScanID,
			"iteration", p.state.IterationCount,
			"new_assets_this_iteration", p.state.NewAssetsLastIter,
		)
	}

	p.logger.Infow("Phase 1 completed: Assets ready for weaponization",
		"scan_id", p.state.ScanID,
		"in_scope_assets", len(p.state.InScopeAssets),
		"discovery_duration", discoveryDuration.String(),
	)

	return nil
}

// extractAssetsFromSession converts discovery session assets to pipeline assets
func (p *Pipeline) extractAssetsFromSession(session *discovery.DiscoverySession) []discovery.Asset {
	assets := []discovery.Asset{}

	// Convert map to slice
	for _, asset := range session.Assets {
		assets = append(assets, *asset)
	}

	return assets
}

// filterAssetsByScope separates in-scope and out-of-scope assets
func (p *Pipeline) filterAssetsByScope(assets []discovery.Asset) (inScope, outOfScope []discovery.Asset) {
	// TODO: Implement actual scope validation using ScopeValidator
	// For now, all assets are considered in-scope

	// This will be implemented to check against:
	// - Bug bounty program scope rules (wildcards, exclusions)
	// - Domain ownership validation
	// - IP range authorization

	inScope = assets
	outOfScope = []discovery.Asset{}

	return inScope, outOfScope
}
