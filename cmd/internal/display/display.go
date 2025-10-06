// Package display provides reusable display and formatting functions for Shells CLI commands.
//
// This package centralizes all output formatting, colorization, and display logic
// to maintain consistency across commands and reduce code duplication.
package display

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/fatih/color"
)

// ColorStatus returns a colorized status string with appropriate icon
func ColorStatus(status string) string {
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

// ColorPhaseStatus returns a colorized icon for phase status
func ColorPhaseStatus(status string) string {
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

// ColorSeverity returns a colorized severity string
func ColorSeverity(severity types.Severity) string {
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

// GroupFindingsBySeverity groups findings by severity level
func GroupFindingsBySeverity(findings []types.Finding) map[types.Severity]int {
	counts := make(map[types.Severity]int)
	for _, finding := range findings {
		counts[finding.Severity]++
	}
	return counts
}

// DisplayTopFindings shows the top N findings sorted by severity
func DisplayTopFindings(findings []types.Finding, limit int) {
	sortedFindings := make([]types.Finding, len(findings))
	copy(sortedFindings, findings)

	// Sort by severity priority
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

		fmt.Printf("\n%s - %s\n", ColorSeverity(finding.Severity), finding.Title)
		fmt.Printf("  Tool: %s | Type: %s\n", finding.Tool, finding.Type)

		if finding.Description != "" {
			desc := finding.Description
			if len(desc) > 150 {
				desc = desc[:147] + "..."
			}
			fmt.Printf("  %s\n", desc)
		}

		if finding.Evidence != "" {
			evidence := finding.Evidence
			if len(evidence) > 100 {
				evidence = evidence[:97] + "..."
			}
			fmt.Printf("  Evidence: %s\n", evidence)
		}

		count++
	}
}
