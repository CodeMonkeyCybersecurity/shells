package nomad

// Nomad Integration Package
//
// Extracted from cmd/scanners/infrastructure.go and cmd/scan.go during Phase 3 refactoring (2025-10-06)
// Consolidates all Nomad cluster interaction code into a single, isolated package
// Nomad is optional infrastructure for distributed scanning

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/nomad"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// NomadIntegration handles Nomad cluster interactions for distributed scanning
type NomadIntegration struct {
	log    *logger.Logger
	client *nomad.Client
}

// New creates a new Nomad integration instance
// Returns nil if Nomad is not available, allowing graceful degradation
func New(log *logger.Logger) *NomadIntegration {
	client := nomad.NewClient("")

	if !client.IsAvailable() {
		log.Debugw("Nomad cluster not available, integration disabled")
		return nil
	}

	log.Infow("Nomad cluster detected, distributed execution enabled")
	return &NomadIntegration{
		log:    log,
		client: client,
	}
}

// GetClient returns the underlying Nomad client
func (n *NomadIntegration) GetClient() *nomad.Client {
	return n.client
}

// IsAvailable checks if Nomad cluster is available
func (n *NomadIntegration) IsAvailable() bool {
	if n == nil {
		return false
	}
	return n.client.IsAvailable()
}

// SubmitScan submits a scan job to Nomad cluster and waits for completion
// Returns findings from the completed scan job
func (n *NomadIntegration) SubmitScan(ctx context.Context, scanType types.ScanType, target string, options map[string]string) ([]types.Finding, error) {
	if n == nil {
		return nil, fmt.Errorf("nomad integration not available")
	}

	// Generate unique scan ID
	scanID := fmt.Sprintf("scan-%s-%d", scanType, time.Now().Unix())

	n.log.Infow("Submitting scan to Nomad",
		"scan_type", scanType,
		"target", target,
		"scan_id", scanID)

	// Submit scan job to Nomad
	jobID, err := n.client.SubmitScan(ctx, scanType, target, scanID, options)
	if err != nil {
		n.log.LogError(ctx, err, "Failed to submit scan job to Nomad",
			"scan_type", scanType,
			"target", target)
		return nil, fmt.Errorf("failed to submit nomad job: %w", err)
	}

	n.log.Infow("Scan job submitted to Nomad", "job_id", jobID, "scan_id", scanID)

	// Wait for job completion with timeout
	timeout := 10 * time.Minute // Configurable timeout
	jobStatus, err := n.client.WaitForCompletion(ctx, jobID, timeout)
	if err != nil {
		n.log.LogError(ctx, err, "Scan job failed or timed out",
			"job_id", jobID,
			"timeout", timeout)
		return nil, fmt.Errorf("job execution failed: %w", err)
	}

	// Get job logs for parsing results
	logs, err := n.client.GetJobLogs(ctx, jobID)
	if err != nil {
		n.log.LogError(ctx, err, "Failed to retrieve scan logs", "job_id", jobID)
		// Don't fail completely - create a basic finding
		return n.createBasicFinding(scanType, target, scanID, "Failed to retrieve detailed results"), nil
	}

	// Parse scan results from logs
	findings := n.parseScanResults(scanType, target, scanID, logs, jobStatus)

	n.log.Infow("Nomad scan completed",
		"job_id", jobID,
		"scan_type", scanType,
		"findings_count", len(findings),
		"status", jobStatus.Status)

	return findings, nil
}

// createBasicFinding creates a basic finding for failed nomad jobs
func (n *NomadIntegration) createBasicFinding(scanType types.ScanType, target, scanID, message string) []types.Finding {
	finding := types.Finding{
		ID:          fmt.Sprintf("%s-%s", scanType, scanID),
		ScanID:      scanID,
		Type:        string(scanType),
		Tool:        string(scanType),
		Title:       fmt.Sprintf("%s Scan Partial", scanType),
		Description: message,
		Severity:    types.SeverityInfo,
		Evidence:    fmt.Sprintf("Nomad job executed but %s", message),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	return []types.Finding{finding}
}
