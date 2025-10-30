// internal/orchestrator/organization_footprinting.go
//
// Organization Footprinting - WHOIS, Certificate Transparency, ASN Discovery
//
// REFACTORING CONTEXT:
// Extracted from bounty_engine.go Execute() method (lines 507-619, ~113 lines)
// Isolates organization correlation logic from core execution flow.
//
// PHILOSOPHY ALIGNMENT:
// - Human-centric: Clear CLI feedback showing what's being analyzed
// - Evidence-based: Multiple authoritative sources (WHOIS, cert logs, ASN)
// - Sustainable: Isolated module for organization intelligence
// - Safe: Comprehensive error handling, stores failed phase results
//
// CAPABILITIES:
// - WHOIS lookup for organization details
// - Certificate transparency logs for related domains
// - ASN discovery for IP ranges
// - Related domain discovery (same org, same cert, same email)

package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// OrganizationFootprinting handles organization asset discovery and correlation
type OrganizationFootprinting struct {
	correlator     *correlation.OrganizationCorrelator
	outputFormatter *OutputFormatter
	logger         *logger.Logger
	config         BugBountyConfig
}

// NewOrganizationFootprinting creates a new organization footprinting manager
func NewOrganizationFootprinting(
	correlator *correlation.OrganizationCorrelator,
	outputFormatter *OutputFormatter,
	logger *logger.Logger,
	config BugBountyConfig,
) *OrganizationFootprinting {
	return &OrganizationFootprinting{
		correlator:      correlator,
		outputFormatter: outputFormatter,
		logger:          logger.WithComponent("org-footprinting"),
		config:          config,
	}
}

// FootprintingResult contains the results of organization footprinting
type FootprintingResult struct {
	Organization  *correlation.Organization
	Domains       []string
	PhaseResult   PhaseResult
}

// CorrelateOrganization performs organization footprinting and correlation
// Returns discovered organization, related domains, and phase result
func (o *OrganizationFootprinting) CorrelateOrganization(
	ctx context.Context,
	target string,
	updateProgress func(phase string, pct float64, completed []string),
	saveCheckpoint func(phase string, pct float64, completed []string, findings []types.Finding),
) *FootprintingResult {
	// Check if correlation is enabled
	if o.correlator == nil || o.config.SkipDiscovery {
		return nil
	}

	footprintStart := time.Now()

	// IMMEDIATE CLI FEEDBACK - Show user what's happening
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Phase 0: Organization Footprinting")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("   Analyzing: %s\n", target)
	fmt.Printf("   • WHOIS lookup for organization details...\n")
	fmt.Printf("   • Certificate transparency logs for related domains...\n")
	fmt.Printf("   • ASN discovery for IP ranges...\n")
	fmt.Println()

	o.logger.Infow("  Phase 0: Organization Footprinting",
		"target", target,
		"enable_whois", o.config.EnableWHOISAnalysis,
		"enable_cert_transparency", o.config.EnableCertTransparency,
		"enable_related_domains", o.config.EnableRelatedDomainDisc,
	)

	// Correlate organization from target
	org, err := o.correlator.FindOrganizationAssets(ctx, target)

	// Handle errors
	if err != nil {
		return o.handleCorrelationError(err, target, footprintStart)
	}

	// Handle nil result (no error but no organization found)
	if org == nil {
		return o.handleNilResult(target, footprintStart)
	}

	// Success - process organization data
	return o.handleSuccess(org, target, footprintStart, updateProgress, saveCheckpoint)
}

// handleCorrelationError handles errors during organization correlation
func (o *OrganizationFootprinting) handleCorrelationError(
	err error,
	target string,
	startTime time.Time,
) *FootprintingResult {
	// ENHANCED ERROR LOGGING: Provide detailed diagnostics
	o.logger.Errorw("CRITICAL: Organization footprinting failed",
		"error", err,
		"error_type", fmt.Sprintf("%T", err),
		"target", target,
		"whois_enabled", o.config.EnableWHOISAnalysis,
		"cert_enabled", o.config.EnableCertTransparency,
		"asn_enabled", true,
		"elapsed_time", time.Since(startTime).String(),
	)

	// Store failed phase result
	phaseResult := PhaseResult{
		Phase:     "footprinting",
		Status:    "failed",
		StartTime: startTime,
		EndTime:   time.Now(),
		Duration:  time.Since(startTime),
		Error:     err.Error(),
	}

	return &FootprintingResult{
		Organization: nil,
		Domains:      []string{},
		PhaseResult:  phaseResult,
	}
}

// handleNilResult handles nil organization result (no error, but no data found)
func (o *OrganizationFootprinting) handleNilResult(
	target string,
	startTime time.Time,
) *FootprintingResult {
	// NULL RESULT: Correlation returned nil without error
	o.logger.Warnw("  Organization footprinting returned nil (no error)",
		"target", target,
		"elapsed_time", time.Since(startTime).String(),
	)

	phaseResult := PhaseResult{
		Phase:     "footprinting",
		Status:    "completed",
		StartTime: startTime,
		EndTime:   time.Now(),
		Duration:  time.Since(startTime),
		Findings:  0,
	}

	return &FootprintingResult{
		Organization: nil,
		Domains:      []string{},
		PhaseResult:  phaseResult,
	}
}

// handleSuccess processes successful organization correlation
func (o *OrganizationFootprinting) handleSuccess(
	org *correlation.Organization,
	target string,
	startTime time.Time,
	updateProgress func(phase string, pct float64, completed []string),
	saveCheckpoint func(phase string, pct float64, completed []string, findings []types.Finding),
) *FootprintingResult {
	o.logger.Infow("  Organization footprinting completed",
		"organization_name", org.Name,
		"domains_found", len(org.Domains),
		"asns_found", len(org.ASNs),
		"ip_ranges_found", len(org.IPRanges),
		"certificates_found", len(org.Certificates),
		"confidence", org.Confidence,
		"sources", org.Sources,
		"duration", time.Since(startTime).String(),
	)

	// USER-FRIENDLY CLI DISPLAY
	if o.outputFormatter != nil {
		o.outputFormatter.DisplayOrganizationFootprinting(org, time.Since(startTime))
	}

	// Log each discovered domain
	for i, domain := range org.Domains {
		o.logger.Infow("  Discovered related domain",
			"index", i+1,
			"domain", domain,
			"organization", org.Name,
		)
	}

	// Create phase result
	phaseResult := PhaseResult{
		Phase:     "footprinting",
		Status:    "completed",
		StartTime: startTime,
		EndTime:   time.Now(),
		Duration:  time.Since(startTime),
		Findings:  len(org.Domains), // Count domains as findings
	}

	// Update progress tracking
	if updateProgress != nil {
		updateProgress("footprinting", 5.0, []string{"footprinting"})
	}
	if saveCheckpoint != nil {
		saveCheckpoint("footprinting", 5.0, []string{"footprinting"}, []types.Finding{})
	}

	return &FootprintingResult{
		Organization: org,
		Domains:      org.Domains,
		PhaseResult:  phaseResult,
	}
}

// IsEnabled checks if organization footprinting is enabled
func (o *OrganizationFootprinting) IsEnabled() bool {
	return o.correlator != nil && !o.config.SkipDiscovery
}
