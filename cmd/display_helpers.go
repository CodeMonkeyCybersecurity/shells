// cmd/display_helpers.go - Thin re-export layer for backward compatibility
//
// REFACTORED 2025-10-30: Business logic moved to pkg/cli/
// This file maintains backward compatibility for existing cmd/* code

package cmd

import (
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/cli/display"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/cli/helpers"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// Re-export display functions from pkg/cli/display
var (
	colorStatus             = display.ColorStatus
	colorPhaseStatus        = display.ColorPhaseStatus
	colorSeverity           = display.ColorSeverity
	groupFindingsBySeverity = display.GroupFindingsBySeverity
	displayTopFindings      = display.DisplayTopFindings
)

// Re-export helper functions from pkg/cli
func prioritizeAssetsForBugBounty(assets []*discovery.Asset, log *logger.Logger) []*helpers.BugBountyAssetPriority {
	return display.PrioritizeAssetsForBugBounty(assets, log)
}

func displayTopBugBountyTargets(assets []*helpers.BugBountyAssetPriority) {
	display.DisplayTopBugBountyTargets(assets)
}

// noopTelemetry is a no-op implementation of core.Telemetry
// TODO: Move to pkg/cli/telemetry/noop.go
type noopTelemetry struct{}

func (n *noopTelemetry) RecordScan(scanType types.ScanType, duration float64, success bool) {}
func (n *noopTelemetry) RecordFinding(severity types.Severity)                              {}
func (n *noopTelemetry) RecordWorkerMetrics(status *types.WorkerStatus)                     {}
func (n *noopTelemetry) Close() error                                                       { return nil }

// Legacy display functions for backward compatibility with resume.go
// TODO: Refactor resume.go to use pkg/cli/commands
func displayOrganizationFootprinting(info interface{}) {
	// Stub for backward compatibility
}

func displayAssetDiscoveryResults(assets []*discovery.Asset, session *discovery.DiscoverySession) {
	// Stub for backward compatibility
	if len(assets) > 0 {
		display.DisplayTopBugBountyTargets(prioritizeAssetsForBugBounty(assets, nil))
	}
}

func displayOrchestratorResults(result interface{}, config interface{}) {
	// Stub for backward compatibility
}
