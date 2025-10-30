// internal/orchestrator/persistence.go
//
// Persistence Manager - Handles result storage and checkpointing
//
// REFACTORING CONTEXT:
// Extracted from bounty_engine.go storeResults() (lines 3327-3471, ~144 lines)
// plus helper functions (lines 3473-3568, ~95 lines)
// Total: ~239 lines extracted
//
// This module isolates all database interaction and persistence logic from the engine,
// providing clean separation of concerns for storage operations.
//
// PHILOSOPHY ALIGNMENT:
// - Sustainable: Clear persistence boundaries, easy to test storage logic
// - Evidence-based: Structured storage with severity tracking
// - Human-centric: Enrichment integration for actionable findings

package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/enrichment"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// PersistenceManager handles result storage and checkpointing
type PersistenceManager struct {
	store             core.ResultStore
	enricher          *enrichment.ResultEnricher
	checkpointManager CheckpointManager
	logger            *logger.Logger
	config            BugBountyConfig
}

// NewPersistenceManager creates a new persistence manager
func NewPersistenceManager(
	store core.ResultStore,
	enricher *enrichment.ResultEnricher,
	checkpointManager CheckpointManager,
	logger *logger.Logger,
	config BugBountyConfig,
) *PersistenceManager {
	return &PersistenceManager{
		store:             store,
		enricher:          enricher,
		checkpointManager: checkpointManager,
		logger:            logger.WithComponent("persistence"),
		config:            config,
	}
}

// SaveResults persists scan results to database with optional enrichment
func (p *PersistenceManager) SaveResults(ctx context.Context, scanID string, result *BugBountyResult) error {
	p.logger.Infow("Saving scan results",
		"scan_id", scanID,
		"findings_count", len(result.Findings),
	)

	// Prepare scan configuration for storage
	configJSON := p.buildConfigJSON()

	// Prepare results summary with severity counts
	resultJSON := p.buildResultJSON(result)

	// Save scan metadata
	if err := p.saveScanMetadata(ctx, scanID, result, configJSON, resultJSON); err != nil {
		return fmt.Errorf("failed to save scan metadata: %w", err)
	}

	// Enrich and save findings
	if len(result.Findings) > 0 {
		if err := p.enrichAndSaveFindings(ctx, scanID, result); err != nil {
			return fmt.Errorf("failed to save findings: %w", err)
		}
	}

	p.logger.Infow("Scan results saved successfully",
		"scan_id", scanID,
		"findings_count", len(result.Findings),
	)

	return nil
}

// buildConfigJSON creates configuration map for storage
func (p *PersistenceManager) buildConfigJSON() map[string]interface{} {
	return map[string]interface{}{
		"discovery_timeout":          p.config.DiscoveryTimeout.String(),
		"scan_timeout":               p.config.ScanTimeout.String(),
		"total_timeout":              p.config.TotalTimeout.String(),
		"max_assets":                 p.config.MaxAssets,
		"max_depth":                  p.config.MaxDepth,
		"enable_port_scan":           p.config.EnablePortScan,
		"enable_web_crawl":           p.config.EnableWebCrawl,
		"enable_dns":                 p.config.EnableDNS,
		"enable_subdomain_enum":      p.config.EnableSubdomainEnum,
		"enable_cert_transparency":   p.config.EnableCertTransparency,
		"enable_whois_analysis":      p.config.EnableWHOISAnalysis,
		"enable_related_domain_disc": p.config.EnableRelatedDomainDisc,
		"enable_auth_testing":        p.config.EnableAuthTesting,
		"enable_api_testing":         p.config.EnableAPITesting,
		"enable_scim_testing":        p.config.EnableSCIMTesting,
		"enable_graphql_testing":     p.config.EnableGraphQLTesting,
		"enable_nuclei_scan":         p.config.EnableNucleiScan,
		"enable_service_fingerprint": p.config.EnableServiceFingerprint,
	}
}

// buildResultJSON creates results summary with severity counts
func (p *PersistenceManager) buildResultJSON(result *BugBountyResult) map[string]interface{} {
	resultJSON := map[string]interface{}{
		"scan_id":        result.ScanID,
		"target":         result.Target,
		"start_time":     result.StartTime,
		"end_time":       result.EndTime,
		"duration":       result.Duration.String(),
		"status":         result.Status,
		"discovered_at":  result.DiscoveredAt,
		"tested_assets":  result.TestedAssets,
		"total_findings": result.TotalFindings,
		"phase_results":  result.PhaseResults,
		"findings_by_severity": map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
			"info":     0,
		},
	}

	// Count findings by severity
	severityCounts := resultJSON["findings_by_severity"].(map[string]int)
	for _, finding := range result.Findings {
		switch strings.ToUpper(string(finding.Severity)) {
		case "CRITICAL":
			severityCounts["critical"]++
		case "HIGH":
			severityCounts["high"]++
		case "MEDIUM":
			severityCounts["medium"]++
		case "LOW":
			severityCounts["low"]++
		default:
			severityCounts["info"]++
		}
	}

	return resultJSON
}

// saveScanMetadata persists scan metadata to database
func (p *PersistenceManager) saveScanMetadata(
	ctx context.Context,
	scanID string,
	result *BugBountyResult,
	configJSON, resultJSON map[string]interface{},
) error {
	startedAt := result.StartTime
	completedAt := result.EndTime

	scan := &types.ScanRequest{
		ID:          scanID,
		Target:      result.Target,
		Type:        types.ScanTypeAuth, // Using ScanTypeAuth for comprehensive scans
		Status:      types.ScanStatusCompleted,
		CreatedAt:   result.StartTime,
		StartedAt:   &startedAt,
		CompletedAt: &completedAt,
		Config:      configJSON,
		Result:      resultJSON,
	}

	if err := p.store.SaveScan(ctx, scan); err != nil {
		return err
	}

	return nil
}

// enrichAndSaveFindings enriches findings with CVSS/exploits and saves to database
func (p *PersistenceManager) enrichAndSaveFindings(
	ctx context.Context,
	scanID string,
	result *BugBountyResult,
) error {
	// Enrich findings if enricher is available
	if p.enricher != nil {
		p.logger.Infow("Enriching findings with CVSS, exploits, and remediation guidance",
			"findings_count", len(result.Findings),
			"enrichment_level", p.config.EnrichmentLevel,
		)

		enrichedFindings, err := p.enricher.EnrichFindings(ctx, result.Findings)
		if err != nil {
			p.logger.Warnw("Enrichment failed - saving findings without enrichment",
				"error", err,
				"findings_count", len(result.Findings),
			)
		} else {
			p.applyEnrichment(result.Findings, enrichedFindings)
			p.logger.Infow("Findings enriched successfully",
				"enriched_count", len(enrichedFindings),
			)
		}
	}

	// Set scan ID for all findings
	for i := range result.Findings {
		result.Findings[i].ScanID = scanID
	}

	// Save findings to database
	if err := p.store.SaveFindings(ctx, result.Findings); err != nil {
		return err
	}

	return nil
}

// applyEnrichment applies enriched metadata to findings
func (p *PersistenceManager) applyEnrichment(
	findings []types.Finding,
	enriched []enrichment.EnrichedFinding,
) {
	for i := range findings {
		if i >= len(enriched) {
			break
		}

		// Apply CVSS scoring
		if enriched[i].CVSSScore != nil {
			if findings[i].Metadata == nil {
				findings[i].Metadata = make(map[string]interface{})
			}
			findings[i].Metadata["cvss_score"] = enriched[i].CVSSScore.BaseScore
			findings[i].Metadata["cvss_vector"] = enriched[i].CVSSScore.Vector
			findings[i].Metadata["cvss_severity"] = enriched[i].CVSSScore.Severity
		}

		// Apply exploit information
		if enriched[i].ExploitInfo != nil && enriched[i].ExploitInfo.ExploitAvailable {
			if findings[i].Metadata == nil {
				findings[i].Metadata = make(map[string]interface{})
			}
			findings[i].Metadata["exploit_available"] = true
			findings[i].Metadata["exploit_count"] = enriched[i].ExploitInfo.ExploitCount
		}

		// Apply remediation guidance
		if enriched[i].Remediation != nil {
			if enriched[i].Remediation.Summary != "" {
				findings[i].Solution = enriched[i].Remediation.Summary
			}
			if findings[i].Metadata == nil {
				findings[i].Metadata = make(map[string]interface{})
			}
			findings[i].Metadata["remediation_priority"] = enriched[i].Remediation.Priority
			findings[i].Metadata["estimated_effort"] = enriched[i].Remediation.EstimatedEffort
		}
	}
}

// =============================================================================
// HELPER FUNCTIONS (extracted from bounty_engine.go)
// =============================================================================

// containsAny checks if string contains any of the substrings (case-insensitive)
func containsAny(s string, substrs []string) bool {
	s = strings.ToLower(s)
	for _, substr := range substrs {
		if strings.Contains(s, strings.ToLower(substr)) {
			return true
		}
	}
	return false
}

// convertVulnerabilityToFinding converts auth.common.Vulnerability to types.Finding
// This is used by authentication scanners to convert protocol-specific vulnerabilities
func convertVulnerabilityToFinding(vuln interface{}, target string) types.Finding {
	// Type assertion to access actual vulnerability fields
	v, ok := vuln.(struct {
		ID          string
		Type        string
		Protocol    string
		Severity    string
		Title       string
		Description string
		Impact      string
		Evidence    []interface{}
		References  []string
		CVSS        float64
		CWE         string
	})

	if !ok {
		// Fallback if type assertion fails
		return types.Finding{
			ID:          fmt.Sprintf("finding-%d", time.Now().UnixNano()),
			ScanID:      "current-scan",
			Type:        "UNKNOWN_VULNERABILITY",
			Severity:    types.SeverityMedium,
			Title:       "Vulnerability detected",
			Description: fmt.Sprintf("Vulnerability found in %s", target),
			Tool:        "auth-scanner",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
	}

	// Map severity string to types.Severity
	severity := MapSeverity(v.Severity)

	// Build evidence string from array
	evidenceStr := ""
	if len(v.Evidence) > 0 {
		evidenceStr = fmt.Sprintf("%v", v.Evidence)
	}

	// Build metadata map
	metadata := map[string]interface{}{
		"cvss":     v.CVSS,
		"cwe":      v.CWE,
		"protocol": v.Protocol,
		"impact":   v.Impact,
	}

	return types.Finding{
		ID:          v.ID,
		ScanID:      "current-scan",
		Type:        v.Type,
		Severity:    severity,
		Title:       v.Title,
		Description: v.Description,
		Evidence:    evidenceStr,
		Solution:    "", // Will be populated by enrichment
		References:  v.References,
		Metadata:    metadata,
		Tool:        fmt.Sprintf("auth-%s", strings.ToLower(v.Protocol)),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// MapSeverity maps severity strings to types.Severity constants
func MapSeverity(severityStr string) types.Severity {
	switch strings.ToUpper(severityStr) {
	case "CRITICAL":
		return types.SeverityCritical
	case "HIGH":
		return types.SeverityHigh
	case "MEDIUM":
		return types.SeverityMedium
	case "LOW":
		return types.SeverityLow
	case "INFO", "INFORMATIONAL":
		return types.SeverityInfo
	default:
		// Default to medium if unknown
		return types.SeverityMedium
	}
}
