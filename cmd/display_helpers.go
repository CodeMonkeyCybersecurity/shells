// cmd/display_helpers.go - Shared display and formatting helpers
//
// This file re-exports display and helper functions from cmd/internal packages
// for backward compatibility. All commands can use these functions without
// importing the internal packages directly.
package cmd

import (
	"github.com/CodeMonkeyCybersecurity/shells/cmd/internal/display"
	"github.com/CodeMonkeyCybersecurity/shells/cmd/internal/helpers"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// Re-export display functions for backward compatibility
var (
	colorStatus              = display.ColorStatus
	colorPhaseStatus         = display.ColorPhaseStatus
	colorSeverity            = display.ColorSeverity
	groupFindingsBySeverity  = display.GroupFindingsBySeverity
	displayTopFindings       = display.DisplayTopFindings
)

// Re-export helper functions for backward compatibility
func prioritizeAssetsForBugBounty(assets []*discovery.Asset, log *logger.Logger) []*helpers.BugBountyAssetPriority {
	return helpers.PrioritizeAssetsForBugBounty(assets, log)
}

func displayTopBugBountyTargets(assets []*helpers.BugBountyAssetPriority) {
	helpers.DisplayTopBugBountyTargets(assets)
}

// noopTelemetry is a no-op implementation of core.Telemetry
// Shared across commands that need telemetry but don't have a real implementation yet
type noopTelemetry struct{}

func (n *noopTelemetry) RecordScan(scanType types.ScanType, duration float64, success bool) {}
func (n *noopTelemetry) RecordFinding(severity types.Severity)                              {}
func (n *noopTelemetry) RecordWorkerMetrics(status *types.WorkerStatus)                     {}
func (n *noopTelemetry) Close() error                                                       { return nil }
