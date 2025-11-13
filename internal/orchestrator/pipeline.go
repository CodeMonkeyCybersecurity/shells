// internal/orchestrator/pipeline.go
//
// ═══════════════════════════════════════════════════════════════════════════
// CYBER KILL CHAIN ALIGNED PIPELINE ORCHESTRATION
// ═══════════════════════════════════════════════════════════════════════════
//
// IMPLEMENTATION SUMMARY (2025-10-28):
//
// This implements a complete architectural refactoring of the shells bug bounty
// pipeline to align with the Cyber Kill Chain and 2025 bug bounty best practices.
//
// PROBLEM STATEMENT:
// The original implementation had no clear phase boundaries, ran tests in
// illogical order (business logic before authentication), and had an
// "intelligent scanner selector" that generated recommendations but then
// IGNORED them. The VulnerabilityCorrelator existed but was never called.
// Discovery ran once, testing ran once - no feedback loop when findings
// revealed new assets.
//
// SOLUTION: 7-PHASE KILL CHAIN ALIGNED PIPELINE
//
// Phase 0: Target Classification & Scope Loading
//   - Classify target (domain/IP/company/email)
//   - Load bug bounty program scope (if --platform/--program specified)
//   - Validate authorization before reconnaissance
//   - File: phase_classification.go
//
// Phase 1: Reconnaissance (Passive → Active)
//   - Passive recon (WHOIS, cert transparency, DNS)
//   - Active recon (port scanning, service fingerprinting, web crawling)
//   - SCOPE FILTERING (P1 FIX #4): Filter assets BEFORE weaponization
//   - File: phase_reconnaissance.go
//
// Phase 2: Weaponization (Attack Surface Mapping & Prioritization)
//   - Deep endpoint discovery (auth endpoints, APIs, admin panels, file uploads)
//   - Authentication mechanism discovery (SAML, OAuth2, WebAuthn, JWT)
//   - API specification discovery (Swagger, GraphQL introspection)
//   - Threat modeling (tech stack → likely vulnerabilities)
//   - INTELLIGENT SCANNER SELECTION (P0 FIX #2): Actually USE recommendations
//   - File: weaponization.go
//
// Phase 3: Delivery (Proof-of-Concept Preparation)
//   - Currently minimal (placeholder for future PoC payload generation)
//   - Implemented inline in pipeline.go
//
// Phase 4: Exploitation (Vulnerability Testing in CORRECT ORDER)
//   - Stage 4.1: Infrastructure (Nmap, Nuclei CVE scanning)
//   - Stage 4.2: Authentication (SAML, OAuth2, WebAuthn, JWT) - FOUNDATIONAL
//   - Stage 4.3: API Testing (REST, GraphQL) - REQUIRES auth sessions from 4.2
//   - Stage 4.4: Access Control (IDOR, SCIM) - REQUIRES auth sessions from 4.2
//   - Stage 4.5: Business Logic - REQUIRES full context + auth sessions
//   - Stage 4.6: Injection (SQLi, XSS, SSRF)
//   - Stage 4.7: Specialized (GraphQL, HTTP smuggling, CORS)
//   - P1 FIX #5: Correct dependency-aware order (auth BEFORE API testing)
//   - File: exploitation.go
//
// Phase 5: Installation (Evidence Collection)
//   - Findings already stored during exploitation
//   - Evidence collection metadata recorded
//   - Implemented inline in pipeline.go
//
// Phase 6: Command & Control (Exploit Chain Analysis & Enrichment)
//   - Exploit chain detection (P1 FIX #6: VulnerabilityCorrelator NOW USED)
//   - CVSS scoring, exploit availability checks
//   - Remediation guidance generation
//   - Business impact analysis
//   - File: correlation.go
//
// Phase 7: Actions on Objectives (Reporting & Submission)
//   - Generate per-vulnerability reports (Markdown, JSON, HTML)
//   - Save findings to PostgreSQL
//   - Display summary to user
//   - File: phase_reporting.go
//
// FEEDBACK LOOP (P0 FIX #3):
// - Phases 1-4 can ITERATE if new assets discovered during testing
// - Example: IDOR test finds /api/v2/internal → triggers new Phase 1 (Reconnaissance)
// - Maximum 3 iterations to prevent infinite loops
// - Iteration tracking in PipelineState
//
// ADVERSARIAL REVIEW FIXES IMPLEMENTED:
//
// P0 (CRITICAL):
// ✅ FIX #1: Explicit phase boundaries (8 phases with clear transitions)
// ✅ FIX #2: Weaponization phase implemented (IntelligentScannerSelector NOW USED)
// ✅ FIX #3: Feedback loop (findings → new assets → iterate phases 1-4)
//
// P1 (HIGH PRIORITY):
// ✅ FIX #4: Scope validation at phase boundaries (Phase 1 → filter before Phase 2)
// ✅ FIX #5: Testing order fixed (Infrastructure → Auth → API → Access → Logic → Injection)
// ✅ FIX #6: Exploit chain detection (VulnerabilityCorrelator NOW CALLED in Phase 6)
//
// MIGRATION PATH:
// 1. Old code: BugBountyEngine.Execute(ctx, target)
// 2. New code: BugBountyEngine.ExecuteWithPipeline(ctx, target)
// 3. Enable with: shells example.com --use-pipeline (future flag)
// 4. Once stable, ExecuteWithPipeline becomes default
// 5. Old Execute() method deprecated
//
// FILES CREATED:
// - internal/orchestrator/pipeline.go (THIS FILE) - Core pipeline orchestration
// - internal/orchestrator/phase_classification.go - Phase 0 implementation
// - internal/orchestrator/phase_reconnaissance.go - Phase 1 implementation
// - internal/orchestrator/weaponization.go - Phase 2 implementation
// - internal/orchestrator/exploitation.go - Phase 4 implementation
// - internal/orchestrator/correlation.go - Phase 6 implementation
// - internal/orchestrator/phase_reporting.go - Phase 7 implementation
// - internal/orchestrator/bounty_engine.go (MODIFIED) - Added ExecuteWithPipeline()
//
// PHILOSOPHY ALIGNMENT:
// - Human-centric: Clear phase transitions, transparent progress, actionable output
// - Evidence-based: Each phase builds on verified results from previous phase
// - Sustainable: Maintainable phase structure, checkpointing for resumption
// - Collaborative: Feedback loop allows scanners to inform discovery

package orchestrator

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/core"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/checkpoint"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
	"github.com/google/uuid"
)

// PipelinePhase represents a stage in the Cyber Kill Chain aligned pipeline
type PipelinePhase int

const (
	// PhaseTargetClassification identifies target type and loads scope rules
	PhaseTargetClassification PipelinePhase = iota

	// PhaseReconnaissance discovers all assets (passive + active)
	PhaseReconnaissance

	// PhaseWeaponization analyzes attack surface and prioritizes targets
	PhaseWeaponization

	// PhaseDelivery prepares proof-of-concept payloads (currently minimal - future expansion)
	PhaseDelivery

	// PhaseExploitation executes vulnerability tests in dependency-aware order
	PhaseExploitation

	// PhaseInstallation collects evidence and documents findings
	PhaseInstallation

	// PhaseCorrelation detects exploit chains and enriches findings
	PhaseCorrelation

	// PhaseReporting generates actionable vulnerability reports
	PhaseReporting
)

// String returns human-readable phase name
func (p PipelinePhase) String() string {
	names := []string{
		"Target Classification",
		"Reconnaissance",
		"Weaponization",
		"Delivery",
		"Exploitation",
		"Installation",
		"Correlation",
		"Reporting",
	}
	if int(p) < len(names) {
		return names[p]
	}
	return "Unknown"
}

// PipelineState tracks progress through the Kill Chain pipeline
type PipelineState struct {
	// Identification
	ScanID       string
	Target       string
	TargetType   discovery.TargetType
	StartedAt    time.Time
	CompletedAt  *time.Time

	// Phase tracking
	CurrentPhase    PipelinePhase
	CompletedPhases map[PipelinePhase]time.Time
	PhaseErrors     map[PipelinePhase][]string

	// Discovery results (Phase 1)
	DiscoverySession     *discovery.DiscoverySession
	DiscoveredAssets     []discovery.Asset // All discovered assets (before filtering)
	InScopeAssets        []discovery.Asset // Filtered by scope validation
	OutOfScopeAssets     []discovery.Asset // Excluded by scope rules
	OrganizationContext  *discovery.OrganizationContext // Organization context for scope expansion

	// Weaponization results (Phase 2)
	AttackSurface       *AttackSurface           // Analyzed attack surface
	PrioritizedTargets  []PrioritizedTarget      // Targets sorted by priority
	ScannerAssignments  map[string][]string      // target URL → scanner names

	// Exploitation results (Phase 4)
	RawFindings           []types.Finding        // Findings before enrichment
	AuthenticationSessions map[string]interface{} // Auth sessions for API testing

	// Correlation results (Phase 6)
	EnrichedFindings []types.Finding   // Findings after CVSS, exploits, remediation
	ExploitChains    []ExploitChain    // Detected vulnerability chains

	// Iteration tracking (feedback loop)
	IterationCount       int
	NewAssetsLastIter    int // Assets discovered in last iteration
	FeedbackLoopActive   bool // True if iterating due to new discoveries

	// Checkpointing
	LastCheckpointAt *time.Time
}

// Pipeline orchestrates the full Cyber Kill Chain aligned bug bounty workflow
type Pipeline struct {
	state   *PipelineState
	config  BugBountyConfig
	logger  *logger.Logger
	store   core.ResultStore

	// Phase executors
	discoveryEngine      *discovery.Engine
	weaponizationEngine  *WeaponizationEngine
	exploitationEngine   *ExploitationEngine
	correlationEngine    *CorrelationEngine

	// Checkpointing
	checkpointManager *checkpoint.Manager
}

// NewPipeline creates a new Kill Chain aligned pipeline
func NewPipeline(
	target string,
	config BugBountyConfig,
	logger *logger.Logger,
	store core.ResultStore,
	discoveryEngine *discovery.Engine,
) (*Pipeline, error) {
	scanID := uuid.New().String()

	state := &PipelineState{
		ScanID:                 scanID,
		Target:                 target,
		StartedAt:              time.Now(),
		CurrentPhase:           PhaseTargetClassification,
		CompletedPhases:        make(map[PipelinePhase]time.Time),
		PhaseErrors:            make(map[PipelinePhase][]string),
		DiscoveredAssets:       []discovery.Asset{},
		InScopeAssets:          []discovery.Asset{},
		OutOfScopeAssets:       []discovery.Asset{},
		ScannerAssignments:     make(map[string][]string),
		RawFindings:            []types.Finding{},
		EnrichedFindings:       []types.Finding{},
		ExploitChains:          []ExploitChain{},
		AuthenticationSessions: make(map[string]interface{}),
		IterationCount:         0,
		NewAssetsLastIter:      0,
		FeedbackLoopActive:     false,
	}

	// Initialize checkpoint manager if enabled
	var checkpointMgr *checkpoint.Manager
	if config.EnableCheckpointing {
		var err error
		checkpointMgr, err = checkpoint.NewManager()
		if err != nil {
			logger.Warnw("Failed to initialize checkpoint manager - checkpointing disabled",
				"error", err,
				"scan_id", scanID,
			)
		}
	}

	pipeline := &Pipeline{
		state:             state,
		config:            config,
		logger:            logger.WithComponent("pipeline"),
		store:             store,
		discoveryEngine:   discoveryEngine,
		checkpointManager: checkpointMgr,
	}

	logger.Infow("Pipeline initialized",
		"scan_id", scanID,
		"target", target,
		"total_phases", 8,
		"checkpointing_enabled", config.EnableCheckpointing,
	)

	return pipeline, nil
}

// Execute runs the full Kill Chain pipeline with feedback loop
func (p *Pipeline) Execute(ctx context.Context) (*PipelineResult, error) {
	p.logger.Infow("Starting Kill Chain aligned pipeline execution",
		"scan_id", p.state.ScanID,
		"target", p.state.Target,
		"max_iterations", 3,
	)

	// Phase 0: Target Classification & Scope Loading
	if err := p.executePhase(ctx, PhaseTargetClassification); err != nil {
		return nil, fmt.Errorf("phase 0 (target classification) failed: %w", err)
	}

	// FEEDBACK LOOP: Phases 1-4 can iterate if new assets discovered
	maxIterations := 3
	for iteration := 0; iteration < maxIterations; iteration++ {
		p.state.IterationCount = iteration
		iterationLogger := p.logger.WithFields(
			"scan_id", p.state.ScanID,
			"iteration", iteration,
		)

		iterationLogger.Infow("Starting pipeline iteration",
			"is_feedback_loop", iteration > 0,
		)

		// Phase 1: Reconnaissance (discover assets)
		if err := p.executePhase(ctx, PhaseReconnaissance); err != nil {
			iterationLogger.LogError(ctx, err, "Phase 1 (reconnaissance) failed")
			// Don't fail entire pipeline - continue with existing assets
		}

		// Check if we discovered new assets
		if iteration > 0 && p.state.NewAssetsLastIter == 0 {
			iterationLogger.Infow("No new assets discovered - terminating iteration loop",
				"total_iterations", iteration,
				"total_assets", len(p.state.InScopeAssets),
			)
			break
		}

		// Phase 2: Weaponization (analyze attack surface, prioritize)
		if err := p.executePhase(ctx, PhaseWeaponization); err != nil {
			return nil, fmt.Errorf("phase 2 (weaponization) failed: %w", err)
		}

		// Phase 3: Delivery (prepare PoC payloads)
		if err := p.executePhase(ctx, PhaseDelivery); err != nil {
			iterationLogger.Warnw("Phase 3 (delivery) failed - continuing",
				"error", err,
			)
			// Non-critical phase, continue
		}

		// Phase 4: Exploitation (run vulnerability tests)
		if err := p.executePhase(ctx, PhaseExploitation); err != nil {
			iterationLogger.LogError(ctx, err, "Phase 4 (exploitation) failed")
			// Don't fail entire pipeline - continue with existing findings
		}

		// Check if findings revealed new assets (FEEDBACK LOOP)
		newAssets := p.extractNewAssetsFromFindings()
		if len(newAssets) > 0 {
			iterationLogger.Infow("Findings revealed new assets - starting next iteration",
				"new_assets", len(newAssets),
				"next_iteration", iteration+1,
				"examples", p.getAssetExamples(newAssets, 3),
			)

			// Add to discovered assets for next iteration
			p.state.DiscoveredAssets = append(p.state.DiscoveredAssets, newAssets...)
			p.state.NewAssetsLastIter = len(newAssets)
			p.state.FeedbackLoopActive = true
			continue
		}

		// No new assets, exit feedback loop
		p.state.FeedbackLoopActive = false
		break
	}

	// Phase 5: Installation (evidence collection)
	if err := p.executePhase(ctx, PhaseInstallation); err != nil {
		p.logger.Warnw("Phase 5 (installation) failed - evidence collection incomplete",
			"error", err,
		)
		// Non-critical, continue
	}

	// Phase 6: Correlation (exploit chains, enrichment)
	if err := p.executePhase(ctx, PhaseCorrelation); err != nil {
		p.logger.LogError(ctx, err, "Phase 6 (correlation) failed")
		// Continue with un-enriched findings
	}

	// Phase 7: Reporting (generate reports)
	if err := p.executePhase(ctx, PhaseReporting); err != nil {
		return nil, fmt.Errorf("phase 7 (reporting) failed: %w", err)
	}

	// Mark pipeline completion
	now := time.Now()
	p.state.CompletedAt = &now

	result := &PipelineResult{
		ScanID:           p.state.ScanID,
		Target:           p.state.Target,
		Duration:         time.Since(p.state.StartedAt),
		Iterations:       p.state.IterationCount + 1,
		TotalAssets:      len(p.state.DiscoveredAssets),
		InScopeAssets:    len(p.state.InScopeAssets),
		OutOfScopeAssets: len(p.state.OutOfScopeAssets),
		TotalFindings:    len(p.state.EnrichedFindings),
		CriticalFindings: p.countBySeverity(types.SeverityCritical),
		HighFindings:     p.countBySeverity(types.SeverityHigh),
		MediumFindings:   p.countBySeverity(types.SeverityMedium),
		LowFindings:      p.countBySeverity(types.SeverityLow),
		ExploitChains:    len(p.state.ExploitChains),
	}

	p.logger.Infow("Pipeline execution completed",
		"scan_id", p.state.ScanID,
		"duration", result.Duration.String(),
		"iterations", result.Iterations,
		"total_findings", result.TotalFindings,
		"exploit_chains", result.ExploitChains,
	)

	return result, nil
}

// executePhase executes a single pipeline phase with checkpointing
func (p *Pipeline) executePhase(ctx context.Context, phase PipelinePhase) error {
	phaseStart := time.Now()
	p.state.CurrentPhase = phase

	phaseLogger := p.logger.WithFields(
		"scan_id", p.state.ScanID,
		"phase", phase.String(),
		"phase_number", int(phase),
	)

	phaseLogger.Infow("Executing pipeline phase")

	// Phase-specific execution
	var err error
	switch phase {
	case PhaseTargetClassification:
		err = p.executeTargetClassification(ctx)
	case PhaseReconnaissance:
		err = p.executeReconnaissance(ctx)
	case PhaseWeaponization:
		err = p.executeWeaponization(ctx)
	case PhaseDelivery:
		err = p.executeDelivery(ctx)
	case PhaseExploitation:
		err = p.executeExploitation(ctx)
	case PhaseInstallation:
		err = p.executeInstallation(ctx)
	case PhaseCorrelation:
		err = p.executeCorrelation(ctx)
	case PhaseReporting:
		err = p.executeReporting(ctx)
	default:
		return fmt.Errorf("unknown phase: %v", phase)
	}

	phaseDuration := time.Since(phaseStart)

	if err != nil {
		p.state.PhaseErrors[phase] = append(
			p.state.PhaseErrors[phase],
			err.Error(),
		)
		phaseLogger.LogError(ctx, err, "Phase execution failed",
			"phase_duration", phaseDuration.String(),
		)
		return err
	}

	// Mark phase as completed
	p.state.CompletedPhases[phase] = time.Now()

	phaseLogger.Infow("Phase execution completed",
		"phase_duration", phaseDuration.String(),
		"completed_phases", len(p.state.CompletedPhases),
	)

	// Save checkpoint after each phase (if enabled)
	if p.checkpointManager != nil {
		if err := p.saveCheckpoint(ctx); err != nil {
			phaseLogger.Warnw("Failed to save checkpoint",
				"error", err,
			)
		}
	}

	return nil
}

// Phase-specific execution methods (to be implemented in separate files)

func (p *Pipeline) executeTargetClassification(ctx context.Context) error {
	// Implemented in phase_classification.go
	return p.phaseTargetClassification(ctx)
}

func (p *Pipeline) executeReconnaissance(ctx context.Context) error {
	// Implemented in phase_reconnaissance.go
	return p.phaseReconnaissance(ctx)
}

func (p *Pipeline) executeWeaponization(ctx context.Context) error {
	// Implemented in weaponization.go
	if p.weaponizationEngine == nil {
		return fmt.Errorf("weaponization engine not initialized")
	}
	return p.weaponizationEngine.Execute(ctx, p.state)
}

func (p *Pipeline) executeDelivery(ctx context.Context) error {
	// Minimal implementation - future expansion for PoC payload generation
	p.logger.Infow("Phase 3 (Delivery) - PoC payload preparation",
		"scan_id", p.state.ScanID,
		"note", "Currently minimal - payloads generated during exploitation",
	)
	return nil
}

func (p *Pipeline) executeExploitation(ctx context.Context) error {
	// Implemented in exploitation.go
	if p.exploitationEngine == nil {
		return fmt.Errorf("exploitation engine not initialized")
	}
	return p.exploitationEngine.Execute(ctx, p.state)
}

func (p *Pipeline) executeInstallation(ctx context.Context) error {
	// Evidence collection - findings already stored during exploitation
	p.logger.Infow("Phase 5 (Installation) - Evidence collection",
		"scan_id", p.state.ScanID,
		"findings_count", len(p.state.RawFindings),
		"note", "Evidence collected during exploitation phase",
	)
	return nil
}

func (p *Pipeline) executeCorrelation(ctx context.Context) error {
	// Implemented in correlation.go
	if p.correlationEngine == nil {
		return fmt.Errorf("correlation engine not initialized")
	}
	return p.correlationEngine.Execute(ctx, p.state)
}

func (p *Pipeline) executeReporting(ctx context.Context) error {
	// Implemented in phase_reporting.go
	return p.phaseReporting(ctx)
}

// Helper methods

func (p *Pipeline) saveCheckpoint(ctx context.Context) error {
	if p.checkpointManager == nil {
		return nil
	}

	checkpointState := &checkpoint.State{
		ScanID:       p.state.ScanID,
		Target:       p.state.Target,
		CurrentPhase: p.state.CurrentPhase.String(),
		Progress:     float64(len(p.state.CompletedPhases)) / 8.0 * 100, // 0-100 scale
		UpdatedAt:    time.Now(),
		CompletedTests: func() []string {
			tests := make([]string, 0, len(p.state.CompletedPhases))
			for _, phase := range p.state.CompletedPhases {
				tests = append(tests, phase.String())
			}
			return tests
		}(),
	}

	if err := p.checkpointManager.Save(ctx, checkpointState); err != nil {
		return fmt.Errorf("failed to save checkpoint: %w", err)
	}

	now := time.Now()
	p.state.LastCheckpointAt = &now

	p.logger.Infow("Checkpoint saved",
		"scan_id", p.state.ScanID,
		"phase", p.state.CurrentPhase.String(),
		"progress", fmt.Sprintf("%.0f%%", checkpointState.Progress*100),
	)

	return nil
}

func (p *Pipeline) extractNewAssetsFromFindings() []discovery.Asset {
	// Extract new assets discovered during exploitation
	// Example: IDOR testing finds /api/v2/internal → new API endpoint
	newAssets := []discovery.Asset{}
	seenAssets := make(map[string]bool)

	// Build map of already-discovered assets for deduplication
	for _, asset := range p.state.DiscoveredAssets {
		seenAssets[asset.Value] = true
	}

	// Parse findings for new domains, IPs, URLs, and endpoints
	for _, finding := range p.state.RawFindings {
		// Extract from evidence field
		if finding.Evidence != "" {
			extracted := extractAssetsFromText(finding.Evidence)
			for _, asset := range extracted {
				if !seenAssets[asset.Value] {
					newAssets = append(newAssets, asset)
					seenAssets[asset.Value] = true
				}
			}
		}

		// Extract from metadata (API endpoints, subdomains, etc.)
		if finding.Metadata != nil {
			if endpoint, ok := finding.Metadata["endpoint"].(string); ok && endpoint != "" {
				asset := discovery.Asset{
					ID:          uuid.New().String(),
					Type:        discovery.AssetTypeURL,
					Value:       endpoint,
					Source:      "finding_metadata",
					Confidence:  0.9,
					DiscoveredAt: time.Now(),
				}
				if !seenAssets[asset.Value] {
					newAssets = append(newAssets, asset)
					seenAssets[asset.Value] = true
				}
			}
			if subdomain, ok := finding.Metadata["subdomain"].(string); ok && subdomain != "" {
				asset := discovery.Asset{
					ID:          uuid.New().String(),
					Type:        discovery.AssetTypeDomain,
					Value:       subdomain,
					Source:      "finding_metadata",
					Confidence:  0.9,
					DiscoveredAt: time.Now(),
				}
				if !seenAssets[asset.Value] {
					newAssets = append(newAssets, asset)
					seenAssets[asset.Value] = true
				}
			}
			if ip, ok := finding.Metadata["ip_address"].(string); ok && ip != "" {
				asset := discovery.Asset{
					ID:          uuid.New().String(),
					Type:        discovery.AssetTypeIP,
					Value:       ip,
					Source:      "finding_metadata",
					Confidence:  0.9,
					DiscoveredAt: time.Now(),
				}
				if !seenAssets[asset.Value] {
					newAssets = append(newAssets, asset)
					seenAssets[asset.Value] = true
				}
			}
		}
	}

	if len(newAssets) > 0 {
		p.logger.Infow("Extracted new assets from findings",
			"new_assets_count", len(newAssets),
			"feedback_loop", "active",
			"phase", p.state.CurrentPhase.String(),
		)
	}

	return newAssets
}

func (p *Pipeline) getAssetExamples(assets []discovery.Asset, limit int) []string {
	examples := []string{}
	for i, asset := range assets {
		if i >= limit {
			break
		}
		examples = append(examples, asset.Value)
	}
	return examples
}

func (p *Pipeline) countBySeverity(severity types.Severity) int {
	count := 0
	for _, finding := range p.state.EnrichedFindings {
		if finding.Severity == severity {
			count++
		}
	}
	return count
}

// PipelineResult contains the final results of pipeline execution
type PipelineResult struct {
	ScanID           string
	Target           string
	Duration         time.Duration
	Iterations       int
	TotalAssets      int
	InScopeAssets    int
	OutOfScopeAssets int
	TotalFindings    int
	CriticalFindings int
	HighFindings     int
	MediumFindings   int
	LowFindings      int
	ExploitChains    int
}

// GetState returns the current pipeline state (for checkpointing)
func (p *Pipeline) GetState() *PipelineState {
	return p.state
}

// extractAssetsFromText parses text (evidence, descriptions) for domains, IPs, and URLs
func extractAssetsFromText(text string) []discovery.Asset {
	assets := []discovery.Asset{}

	// Regex patterns for asset extraction
	domainPattern := regexp.MustCompile(`(?i)\b([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b`)
	ipPattern := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	urlPattern := regexp.MustCompile(`https?://[^\s<>"{}|\\^\[\]` + "`" + `]+`)

	// Extract URLs (highest priority - most specific)
	urlMatches := urlPattern.FindAllString(text, -1)
	for _, url := range urlMatches {
		assets = append(assets, discovery.Asset{
			ID:          uuid.New().String(),
			Type:        discovery.AssetTypeURL,
			Value:       url,
			Source:      "finding_evidence",
			Confidence:  0.95,
			DiscoveredAt: time.Now(),
		})
	}

	// Extract domains
	domainMatches := domainPattern.FindAllString(text, -1)
	for _, domain := range domainMatches {
		// Skip common false positives
		if isCommonFalsePositive(domain) {
			continue
		}
		assets = append(assets, discovery.Asset{
			ID:          uuid.New().String(),
			Type:        discovery.AssetTypeDomain,
			Value:       domain,
			Source:      "finding_evidence",
			Confidence:  0.85,
			DiscoveredAt: time.Now(),
		})
	}

	// Extract IP addresses
	ipMatches := ipPattern.FindAllString(text, -1)
	for _, ip := range ipMatches {
		// Skip invalid IPs (e.g., version numbers)
		if isValidIP(ip) {
			assets = append(assets, discovery.Asset{
				ID:          uuid.New().String(),
				Type:        discovery.AssetTypeIP,
				Value:       ip,
				Source:      "finding_evidence",
				Confidence:  0.9,
				DiscoveredAt: time.Now(),
			})
		}
	}

	return assets
}

// isCommonFalsePositive filters out common false positive domains
func isCommonFalsePositive(domain string) bool {
	falsePositives := []string{
		"example.com", "example.org", "example.net",
		"localhost.localdomain", "test.com", "test.local",
		"w3.org", "ietf.org", "rfc-editor.org",
		"schema.org", "xmlns.com",
	}

	lowerDomain := strings.ToLower(domain)
	for _, fp := range falsePositives {
		if lowerDomain == fp {
			return true
		}
	}
	return false
}

// isValidIP checks if an IP address is valid and not a false positive
func isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		num := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
			num = num*10 + int(c-'0')
		}
		if num > 255 {
			return false
		}
	}

	// Skip private/reserved ranges for external scanning
	// (keep them for internal networks)
	firstOctet := 0
	fmt.Sscanf(parts[0], "%d", &firstOctet)

	// Allow all IPs - let scope validation handle filtering
	return true
}
