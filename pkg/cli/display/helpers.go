// pkg/cli/display/helpers.go - Display and formatting helpers
//
// REFACTORED 2025-10-30: Moved from cmd/display_helpers.go
// This extracts reusable display logic from cmd/ into pkg/cli/

package display

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/cli/helpers"
	"github.com/fatih/color"
)

// PrioritizeAssetsForBugBounty prioritizes discovered assets for bug bounty hunting
func PrioritizeAssetsForBugBounty(assets []*discovery.Asset, log *logger.Logger) []*helpers.BugBountyAssetPriority {
	return helpers.PrioritizeAssetsForBugBounty(assets, log)
}

// DisplayTopBugBountyTargets displays the top bug bounty targets
func DisplayTopBugBountyTargets(assets []*helpers.BugBountyAssetPriority) {
	if len(assets) == 0 {
		return
	}

	color.Cyan("\n🎯 Top Bug Bounty Targets:\n")
	color.Cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	displayCount := 20
	if len(assets) < displayCount {
		displayCount = len(assets)
	}

	for i := 0; i < displayCount; i++ {
		asset := assets[i]
		priorityColor := color.New(color.FgGreen)
		if asset.Score > 90 {
			priorityColor = color.New(color.FgRed, color.Bold)
		} else if asset.Score > 70 {
			priorityColor = color.New(color.FgYellow)
		}

		priorityColor.Printf("%2d. [%3d] ", i+1, asset.Score)
		fmt.Printf("%s\n", asset.Asset.Value)
		if len(asset.Reasons) > 0 {
			fmt.Printf("    %s\n", color.HiBlackString(strings.Join(asset.Reasons, ", ")))
		}
	}

	if len(assets) > displayCount {
		color.HiBlackString("    ... and %d more assets\n", len(assets)-displayCount)
	}

	color.Cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}
