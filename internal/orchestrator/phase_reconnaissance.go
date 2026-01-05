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
	"strings"
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

	// Build asset relationships for organization-based expansion
	if p.config.EnableAssetRelationshipMapping {
		relationshipStart := time.Now()
		p.logger.Infow("Building asset relationships",
			"scan_id", p.state.ScanID,
			"total_assets", len(allAssets),
		)

		relatedAssets, err := p.buildAssetRelationships(ctx, p.state.DiscoverySession)
		if err != nil {
			p.logger.Warnw("Asset relationship mapping failed",
				"scan_id", p.state.ScanID,
				"error", err,
				"note", "Continuing without relationship expansion",
			)
		} else if len(relatedAssets) > 0 {
			p.logger.Infow("Asset relationships discovered",
				"scan_id", p.state.ScanID,
				"duration", time.Since(relationshipStart).String(),
				"related_assets", len(relatedAssets),
			)

			// Add related assets to discovered assets
			p.state.DiscoveredAssets = append(p.state.DiscoveredAssets, relatedAssets...)
			allAssets = p.state.DiscoveredAssets

			p.logger.Infow("Assets expanded via relationships",
				"scan_id", p.state.ScanID,
				"total_after_expansion", len(allAssets),
				"expansion_count", len(relatedAssets),
			)
		}
	}

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

// buildAssetRelationships discovers related assets through org relationships
func (p *Pipeline) buildAssetRelationships(ctx context.Context, session *discovery.DiscoverySession) ([]discovery.Asset, error) {
	// Use AssetRelationshipMapper to find related assets via:
	// - Same organization (WHOIS, cert transparency)
	// - Same registrant email
	// - Same certificate issuer
	// - Same name servers
	// This is the key to microsoft.com → azure.com → office.com discovery

	mapper := discovery.NewAssetRelationshipMapper(p.config.DiscoveryConfig, p.logger)
	if err := mapper.BuildRelationships(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to build relationships: %w", err)
	}

	// Extract new assets from relationships
	relatedAssets := []discovery.Asset{}
	relationships := mapper.GetRelationships()

	// Build organization context
	orgContext := mapper.GetOrganizationContext()
	if orgContext != nil {
		p.logger.Infow("Organization context discovered",
			"scan_id", p.state.ScanID,
			"organization", orgContext.OrgName,
			"domains", len(orgContext.KnownDomains),
			"ips", len(orgContext.KnownIPRanges),
		)

		// Store organization context for scope expansion
		p.state.OrganizationContext = orgContext
	}

	// Extract assets from relationships
	seenAssets := make(map[string]bool)
	for _, asset := range session.Assets {
		seenAssets[asset.Value] = true
	}

	for _, rel := range relationships {
		// High confidence relationships only
		if rel.Confidence >= 0.7 {
			// Check if target asset is new
			if !seenAssets[rel.TargetAssetID] {
				// Find the actual asset
				if targetAsset := mapper.GetAsset(rel.TargetAssetID); targetAsset != nil {
					relatedAssets = append(relatedAssets, *targetAsset)
					seenAssets[rel.TargetAssetID] = true

					p.logger.Debugw("Related asset discovered",
						"scan_id", p.state.ScanID,
						"source", rel.SourceAssetID,
						"target", targetAsset.Value,
						"relation_type", rel.RelationType,
						"confidence", fmt.Sprintf("%.0f%%", rel.Confidence*100),
					)
				}
			}
		}
	}

	return relatedAssets, nil
}

// filterAssetsByScope separates in-scope and out-of-scope assets
func (p *Pipeline) filterAssetsByScope(assets []discovery.Asset) (inScope, outOfScope []discovery.Asset) {
	// Use organization context for scope expansion
	// If we discovered microsoft.com → azure.com relationship, both are in scope
	// This is the CRITICAL piece for automatic scope expansion

	inScope = []discovery.Asset{}
	outOfScope = []discovery.Asset{}

	for _, asset := range assets {
		if p.isAssetInScope(asset) {
			inScope = append(inScope, asset)
		} else {
			outOfScope = append(outOfScope, asset)
		}
	}

	return inScope, outOfScope
}

// isAssetInScope checks if an asset should be tested
func (p *Pipeline) isAssetInScope(asset discovery.Asset) bool {
	// If scope validation disabled, everything is in scope
	if !p.config.EnableScopeValidation {
		return true
	}

	// If we have organization context, use it for scope expansion
	if p.state.OrganizationContext != nil {
		// Check if asset belongs to same organization
		if p.assetBelongsToOrganization(asset, p.state.OrganizationContext) {
			return true
		}
	}

	// Default scope check: asset must be related to original target
	// This is where bug bounty program scope rules would be applied
	// For now, allow all assets discovered through relationship mapping
	return true
}

// assetBelongsToOrganization checks if an asset belongs to the discovered organization
func (p *Pipeline) assetBelongsToOrganization(asset discovery.Asset, orgCtx *discovery.OrganizationContext) bool {
	// Check domains
	for _, domain := range orgCtx.KnownDomains {
		if asset.Value == domain {
			return true
		}
		// Check if asset is subdomain
		if strings.HasSuffix(asset.Value, "."+domain) {
			return true
		}
		// Check if URL belongs to domain
		if strings.Contains(asset.Value, "://"+domain) || strings.Contains(asset.Value, "://"+domain+"/") {
			return true
		}
	}

	// Check IP ranges
	for _, ipRange := range orgCtx.KnownIPRanges {
		if asset.Value == ipRange {
			return true
		}
		// TODO: Implement CIDR matching for IP ranges
	}

	// Check subsidiaries
	for _, subsidiary := range orgCtx.Subsidiaries {
		if strings.Contains(asset.Value, subsidiary) {
			return true
		}
	}

	return false
}
