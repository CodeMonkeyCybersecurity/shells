// cmd/display_helpers.go - Shared display and formatting helpers
package cmd

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/fatih/color"
)

// Shared display helper functions for all commands

func colorStatus(status string) string {
	switch status {
	case "completed":
		return color.New(color.FgGreen).Sprint("✓ " + status)
	case "running":
		return color.New(color.FgYellow).Sprint("⟳ " + status)
	case "failed":
		return color.New(color.FgRed).Sprint("✗ " + status)
	default:
		return status
	}
}

func colorPhaseStatus(status string) string {
	switch status {
	case "completed":
		return color.New(color.FgGreen).Sprint("✓")
	case "running":
		return color.New(color.FgYellow).Sprint("⟳")
	case "failed":
		return color.New(color.FgRed).Sprint("✗")
	default:
		return "○"
	}
}

func colorSeverity(severity types.Severity) string {
	switch severity {
	case types.SeverityCritical:
		return color.New(color.FgRed, color.Bold).Sprint("CRITICAL")
	case types.SeverityHigh:
		return color.New(color.FgRed).Sprint("HIGH")
	case types.SeverityMedium:
		return color.New(color.FgYellow).Sprint("MEDIUM")
	case types.SeverityLow:
		return color.New(color.FgCyan).Sprint("LOW")
	case types.SeverityInfo:
		return color.New(color.FgWhite).Sprint("INFO")
	default:
		return string(severity)
	}
}

func groupFindingsBySeverity(findings []types.Finding) map[types.Severity]int {
	counts := make(map[types.Severity]int)
	for _, finding := range findings {
		counts[finding.Severity]++
	}
	return counts
}

func displayTopFindings(findings []types.Finding, limit int) {
	// Sort by severity (critical first)
	sortedFindings := make([]types.Finding, len(findings))
	copy(sortedFindings, findings)

	// Simple sort: critical, high, medium, low, info
	severityOrder := map[types.Severity]int{
		types.SeverityCritical: 0,
		types.SeverityHigh:     1,
		types.SeverityMedium:   2,
		types.SeverityLow:      3,
		types.SeverityInfo:     4,
	}

	// Bubble sort by severity
	for i := 0; i < len(sortedFindings); i++ {
		for j := i + 1; j < len(sortedFindings); j++ {
			if severityOrder[sortedFindings[i].Severity] > severityOrder[sortedFindings[j].Severity] {
				sortedFindings[i], sortedFindings[j] = sortedFindings[j], sortedFindings[i]
			}
		}
	}

	count := 0
	for _, finding := range sortedFindings {
		if count >= limit {
			break
		}

		fmt.Printf("\n%s - %s\n", colorSeverity(finding.Severity), finding.Title)
		fmt.Printf("  Tool: %s | Type: %s\n", finding.Tool, finding.Type)

		if finding.Description != "" {
			// Truncate description if too long
			desc := finding.Description
			if len(desc) > 150 {
				desc = desc[:147] + "..."
			}
			fmt.Printf("  %s\n", desc)
		}

		if finding.Evidence != "" {
			// Show first line of evidence
			evidence := finding.Evidence
			if len(evidence) > 100 {
				evidence = evidence[:97] + "..."
			}
			fmt.Printf("  Evidence: %s\n", evidence)
		}

		count++
	}
}

// noopTelemetry is a no-op implementation of core.Telemetry
// Shared across commands that need telemetry but don't have a real implementation yet
type noopTelemetry struct{}

func (n *noopTelemetry) RecordScan(scanType types.ScanType, duration float64, success bool) {}
func (n *noopTelemetry) RecordFinding(severity types.Severity)                              {}
func (n *noopTelemetry) RecordWorkerMetrics(status *types.WorkerStatus)                     {}
func (n *noopTelemetry) Close() error                                                       { return nil }
