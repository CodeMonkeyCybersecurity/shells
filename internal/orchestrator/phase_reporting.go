// internal/orchestrator/phase_reporting.go
//
// PHASE 7: Actions on Objectives (Reporting & Submission)
//
// This phase generates actionable bug bounty reports and optionally submits them.
// Corresponds to the final stage of the Cyber Kill Chain.
//
// Actions:
//   7.1 Generate per-vulnerability reports (Markdown, JSON, HTML)
//   7.2 Platform submission (optional - HackerOne, Bugcrowd, etc.)
//   7.3 Temporal comparison report (if re-scan)
//
// PHILOSOPHY ALIGNMENT:
// - Human-centric: Clear, actionable reports that security teams can use
// - Evidence-based: All claims backed by reproduction steps and evidence
// - Collaborative: Report format designed for transparent communication

package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// phaseReporting executes Phase 7: Reporting
func (p *Pipeline) phaseReporting(ctx context.Context) error {
	p.logger.Infow("Phase 7: Reporting - Generating Vulnerability Reports",
		"scan_id", p.state.ScanID,
		"enriched_findings", len(p.state.EnrichedFindings),
		"exploit_chains", len(p.state.ExploitChains),
	)

	// Save all findings to database
	if err := p.saveFindingsToDatabase(ctx); err != nil {
		p.logger.LogError(ctx, err, "Failed to save findings to database")
		// Don't fail - continue with report generation
	}

	// Generate summary report
	p.generateSummaryReport()

	// Optionally generate export files
	if p.config.Verbose {
		p.logger.Infow("Use 'shells results export' to generate detailed reports",
			"scan_id", p.state.ScanID,
			"formats", []string{"JSON", "CSV", "HTML", "Markdown"},
		)
	}

	return nil
}

// saveFindingsToDatabase persists all findings to PostgreSQL
func (p *Pipeline) saveFindingsToDatabase(ctx context.Context) error {
	if p.store == nil {
		return fmt.Errorf("result store not initialized")
	}

	// Save enriched findings
	if err := p.store.SaveFindings(ctx, p.state.EnrichedFindings); err != nil {
		return fmt.Errorf("failed to save findings: %w", err)
	}

	p.logger.Infow("Findings saved to database",
		"scan_id", p.state.ScanID,
		"findings_saved", len(p.state.EnrichedFindings),
	)

	return nil
}

// generateSummaryReport displays a human-readable summary
func (p *Pipeline) generateSummaryReport() {
	p.logger.Infow("═══════════════════════════════════════════════════════════",
		"scan_id", p.state.ScanID,
	)
	p.logger.Infow("                    SCAN SUMMARY                            ",
		"scan_id", p.state.ScanID,
	)
	p.logger.Infow("═══════════════════════════════════════════════════════════",
		"scan_id", p.state.ScanID,
	)

	// Scan metadata
	duration := time.Since(p.state.StartedAt)
	p.logger.Infow("Scan Metadata",
		"scan_id", p.state.ScanID,
		"target", p.state.Target,
		"duration", duration.String(),
		"iterations", p.state.IterationCount+1,
	)

	// Asset discovery
	p.logger.Infow("Asset Discovery",
		"scan_id", p.state.ScanID,
		"total_discovered", len(p.state.DiscoveredAssets),
		"in_scope", len(p.state.InScopeAssets),
		"out_of_scope", len(p.state.OutOfScopeAssets),
	)

	// Findings summary
	critical := p.countBySeverity(types.SeverityCritical)
	high := p.countBySeverity(types.SeverityHigh)
	medium := p.countBySeverity(types.SeverityMedium)
	low := p.countBySeverity(types.SeverityLow)
	info := p.countBySeverity(types.SeverityInfo)

	p.logger.Infow("Vulnerability Findings",
		"scan_id", p.state.ScanID,
		"total_findings", len(p.state.EnrichedFindings),
		"critical", critical,
		"high", high,
		"medium", medium,
		"low", low,
		"info", info,
	)

	// Exploit chains
	if len(p.state.ExploitChains) > 0 {
		p.logger.Infow("Exploit Chains (HIGH VALUE)",
			"scan_id", p.state.ScanID,
			"chains_detected", len(p.state.ExploitChains),
		)
		for i, chain := range p.state.ExploitChains {
			p.logger.Infow(fmt.Sprintf("  %d. %s", i+1, chain.Name),
				"scan_id", p.state.ScanID,
				"severity", chain.Severity,
				"cvss_score", chain.CVSSScore,
			)
		}
	}

	// Next steps
	p.logger.Infow("═══════════════════════════════════════════════════════════",
		"scan_id", p.state.ScanID,
	)
	p.logger.Infow("Next Steps",
		"scan_id", p.state.ScanID,
	)
	p.logger.Infow("  1. Review findings: shells results query --scan-id "+p.state.ScanID,
		"scan_id", p.state.ScanID,
	)
	p.logger.Infow("  2. Export report: shells results export "+p.state.ScanID+" --format markdown",
		"scan_id", p.state.ScanID,
	)
	p.logger.Infow("  3. View in dashboard: http://localhost:8080/scans/"+p.state.ScanID,
		"scan_id", p.state.ScanID,
	)
	if critical > 0 || high > 0 {
		p.logger.Infow("  ⚠️  Critical/High findings detected - prioritize for bug bounty submission",
			"scan_id", p.state.ScanID,
		)
	}
	p.logger.Infow("═══════════════════════════════════════════════════════════",
		"scan_id", p.state.ScanID,
	)
}
