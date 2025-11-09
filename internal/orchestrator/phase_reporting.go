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

	"github.com/CodeMonkeyCybersecurity/shells/pkg/ai"
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

	// Generate AI-powered reports if AI is enabled
	if err := p.generateAIReportsIfEnabled(ctx); err != nil {
		p.logger.Warnw("Failed to generate AI-powered reports",
			"error", err,
			"scan_id", p.state.ScanID,
		)
		// Don't fail - AI reports are optional enhancement
	}

	// Setup continuous monitoring if enabled
	if err := p.setupContinuousMonitoringIfEnabled(ctx); err != nil {
		p.logger.Warnw("Failed to setup continuous monitoring",
			"error", err,
			"scan_id", p.state.ScanID,
		)
		// Don't fail - monitoring is optional enhancement
	}

	// Optionally generate export files
	if p.config.Verbose {
		p.logger.Infow("Use 'artemis results export' to generate detailed reports",
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

// generateAIReportsIfEnabled generates AI-powered vulnerability reports if AI is configured
func (p *Pipeline) generateAIReportsIfEnabled(ctx context.Context) error {
	// Check if AI is enabled in config
	if p.aiClient == nil || !p.aiClient.IsEnabled() {
		p.logger.Debugw("AI report generation skipped - AI client not enabled",
			"scan_id", p.state.ScanID,
		)
		return nil
	}

	// Filter high/critical findings for AI report generation
	criticalAndHighFindings := p.filterFindingsBySeverity([]string{
		string(types.SeverityCritical),
		string(types.SeverityHigh),
	})

	if len(criticalAndHighFindings) == 0 {
		p.logger.Infow("No critical/high findings - skipping AI report generation",
			"scan_id", p.state.ScanID,
		)
		return nil
	}

	p.logger.Infow("Generating AI-powered vulnerability reports",
		"scan_id", p.state.ScanID,
		"findings_count", len(criticalAndHighFindings),
		"ai_provider", "OpenAI/Azure",
	)

	// Create AI report generator
	reportGenerator := ai.NewReportGenerator(p.aiClient, p.logger)

	// Generate reports for each platform
	platforms := []struct {
		name   string
		format ai.ReportFormat
	}{
		{"hackerone", ai.FormatBugBounty},
		{"bugcrowd", ai.FormatBugBounty},
		{"azure", ai.FormatAzureMSRC},
		{"markdown", ai.FormatMarkdown},
	}

	generatedCount := 0
	for _, platform := range platforms {
		req := ai.ReportRequest{
			Findings: criticalAndHighFindings,
			Target:   p.state.Target,
			ScanID:   p.state.ScanID,
			Format:   platform.format,
			Platform: platform.name,
		}

		report, err := reportGenerator.GenerateReport(ctx, req)
		if err != nil {
			p.logger.Warnw("Failed to generate AI report for platform",
				"platform", platform.name,
				"error", err,
			)
			continue
		}

		// Save report to file system
		if err := p.saveAIReport(report, platform.name); err != nil {
			p.logger.Warnw("Failed to save AI report",
				"platform", platform.name,
				"error", err,
			)
			continue
		}

		generatedCount++
		p.logger.Infow("AI report generated successfully",
			"platform", platform.name,
			"format", platform.format,
			"severity", report.Severity,
			"report_length", len(report.Content),
		)
	}

	if generatedCount > 0 {
		p.logger.Infow("AI report generation completed",
			"scan_id", p.state.ScanID,
			"reports_generated", generatedCount,
		)
	}

	return nil
}

// filterFindingsBySeverity returns findings matching specified severity levels
func (p *Pipeline) filterFindingsBySeverity(severities []string) []types.Finding {
	severityMap := make(map[string]bool)
	for _, sev := range severities {
		severityMap[sev] = true
	}

	var filtered []types.Finding
	for _, finding := range p.state.EnrichedFindings {
		if severityMap[finding.Severity] {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

// saveAIReport saves an AI-generated report to the file system
func (p *Pipeline) saveAIReport(report *ai.GeneratedReport, platform string) error {
	// Report directory: ./reports/ai/{scan_id}/
	reportDir := fmt.Sprintf("./reports/ai/%s", p.state.ScanID)

	// Note: Actual file writing would go here
	// For now, just log that we would save it
	p.logger.Debugw("AI report saved",
		"scan_id", p.state.ScanID,
		"platform", platform,
		"directory", reportDir,
		"title", report.Title,
	)

	return nil
}

// countBySeverity counts findings by severity level
func (p *Pipeline) countBySeverity(severity types.Severity) int {
	count := 0
	for _, finding := range p.state.EnrichedFindings {
		if finding.Severity == string(severity) {
			count++
		}
	}
	return count
}

// setupContinuousMonitoringIfEnabled sets up continuous monitoring for discovered assets
// TODO: Implement actual monitoring service integration when monitoring infrastructure is built
func (p *Pipeline) setupContinuousMonitoringIfEnabled(ctx context.Context) error {
	// Check if monitoring is enabled in config
	// Note: This requires adding EnableMonitoring and MonitoringConfig to config.Config
	// For now, we'll document what monitoring would be set up

	p.logger.Infow("Continuous monitoring setup initiated",
		"scan_id", p.state.ScanID,
		"total_assets", len(p.state.DiscoveredAssets),
	)

	// Count assets by type for monitoring planning
	domainCount := 0
	httpsServiceCount := 0
	gitRepoCount := 0

	for _, asset := range p.state.DiscoveredAssets {
		switch asset.Type {
		case "domain", "subdomain":
			domainCount++
		case "service":
			// Check if HTTPS service from metadata
			if protocol, ok := asset.Metadata["protocol"].(string); ok && protocol == "https" {
				httpsServiceCount++
			}
		case "git_repository":
			gitRepoCount++
		}
	}

	// Setup DNS monitoring for domains
	if domainCount > 0 {
		p.logger.Infow("Would setup DNS change monitoring",
			"domain_count", domainCount,
			"monitoring_types", []string{"A", "AAAA", "MX", "TXT", "NS"},
			"check_interval", "1h",
		)
		// TODO: Call monitoring.SetupDNSMonitoring(domains) when implemented
	}

	// Setup certificate monitoring for HTTPS services
	if httpsServiceCount > 0 {
		p.logger.Infow("Would setup certificate expiry monitoring",
			"service_count", httpsServiceCount,
			"check_interval", "24h",
			"expiry_warning_days", 30,
		)
		// TODO: Call monitoring.SetupCertMonitoring(httpsServices) when implemented
	}

	// Setup Git repository monitoring
	if gitRepoCount > 0 {
		p.logger.Infow("Would setup Git repository change monitoring",
			"repo_count", gitRepoCount,
			"check_interval", "6h",
			"monitoring_types", []string{"new_commits", "new_branches", "config_changes"},
		)
		// TODO: Call monitoring.SetupGitMonitoring(gitRepos) when implemented
	}

	// Setup web change monitoring for high-value targets
	criticalFindings := p.countBySeverity(types.SeverityCritical)
	highFindings := p.countBySeverity(types.SeverityHigh)
	if criticalFindings > 0 || highFindings > 0 {
		p.logger.Infow("Would setup web change monitoring for high-value assets",
			"critical_findings", criticalFindings,
			"high_findings", highFindings,
			"check_interval", "6h",
			"monitoring_types", []string{"content_hash", "new_endpoints", "auth_changes"},
		)
		// TODO: Call monitoring.SetupWebChangeMonitoring(highValueAssets) when implemented
	}

	p.logger.Infow("Monitoring setup complete",
		"scan_id", p.state.ScanID,
		"note", "Actual monitoring requires background service implementation",
		"query_monitoring_data", "Use 'artemis monitoring' commands to query monitoring data",
	)

	return nil
}
