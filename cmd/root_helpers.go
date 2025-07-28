package cmd

import (
	"fmt"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"strings"
)

// BugBountyAssetPriority represents a prioritized asset for bug bounty testing
type BugBountyAssetPriority struct {
	Asset    *discovery.Asset
	Score    int
	Reasons  []string
	Features AssetFeatures
}

// AssetFeatures represents features of an asset relevant to vulnerability testing
type AssetFeatures struct {
	HasAuthentication bool
	HasAPI            bool
	HasPayment        bool
	HasUserData       bool
}

// prioritizeAssetsForBugBounty assigns priority scores to discovered assets
func prioritizeAssetsForBugBounty(assets []*discovery.Asset, log *logger.Logger) []*BugBountyAssetPriority {
	var prioritized []*BugBountyAssetPriority

	for _, asset := range assets {
		ap := &BugBountyAssetPriority{
			Asset:   asset,
			Score:   0,
			Reasons: []string{},
		}

		// Score based on asset value patterns
		value := strings.ToLower(asset.Value)

		// Authentication endpoints (highest priority)
		if strings.Contains(value, "login") || strings.Contains(value, "auth") ||
			strings.Contains(value, "signin") || strings.Contains(value, "oauth") ||
			strings.Contains(value, "saml") {
			ap.Score += 100
			ap.Reasons = append(ap.Reasons, "Authentication endpoint")
			ap.Features.HasAuthentication = true
		}

		// API endpoints
		if strings.Contains(value, "api") || strings.Contains(value, "graphql") ||
			strings.Contains(value, "rest") || strings.Contains(value, "v1") ||
			strings.Contains(value, "v2") {
			ap.Score += 90
			ap.Reasons = append(ap.Reasons, "API endpoint")
			ap.Features.HasAPI = true
		}

		// Admin/Dashboard
		if strings.Contains(value, "admin") || strings.Contains(value, "dashboard") ||
			strings.Contains(value, "panel") || strings.Contains(value, "console") {
			ap.Score += 85
			ap.Reasons = append(ap.Reasons, "Admin interface")
		}

		// Payment/Financial
		if strings.Contains(value, "payment") || strings.Contains(value, "checkout") ||
			strings.Contains(value, "billing") || strings.Contains(value, "invoice") {
			ap.Score += 85
			ap.Reasons = append(ap.Reasons, "Payment functionality")
			ap.Features.HasPayment = true
		}

		// File upload
		if strings.Contains(value, "upload") || strings.Contains(value, "import") {
			ap.Score += 75
			ap.Reasons = append(ap.Reasons, "File upload")
		}

		// User data
		if strings.Contains(value, "profile") || strings.Contains(value, "account") ||
			strings.Contains(value, "user") || strings.Contains(value, "settings") {
			ap.Score += 70
			ap.Reasons = append(ap.Reasons, "User data access")
			ap.Features.HasUserData = true
		}

		// SSRF indicators
		if strings.Contains(value, "webhook") || strings.Contains(value, "callback") ||
			strings.Contains(value, "proxy") || strings.Contains(value, "url") {
			ap.Score += 70
			ap.Reasons = append(ap.Reasons, "SSRF potential")
		}

		// Only include assets with score > 0
		if ap.Score > 0 {
			prioritized = append(prioritized, ap)
		}
	}

	// Sort by score descending
	for i := 0; i < len(prioritized)-1; i++ {
		for j := i + 1; j < len(prioritized); j++ {
			if prioritized[j].Score > prioritized[i].Score {
				prioritized[i], prioritized[j] = prioritized[j], prioritized[i]
			}
		}
	}

	return prioritized
}

// displayTopBugBountyTargets displays the top high-value targets
func displayTopBugBountyTargets(assets []*BugBountyAssetPriority) {
	fmt.Printf("\n%sTop High-Value Targets:%s\n", "\033[1;33m", "\033[0m")
	for i, asset := range assets {
		scoreColor := "\033[0m"
		if asset.Score >= 90 {
			scoreColor = "\033[1;31m" // Red for critical
		} else if asset.Score >= 70 {
			scoreColor = "\033[1;33m" // Yellow for high
		}

		fmt.Printf("%d. %s[Score: %d]%s %s\n",
			i+1, scoreColor, asset.Score, "\033[0m", asset.Asset.Value)

		// Show reasons
		if len(asset.Reasons) > 0 {
			fmt.Printf("   → %s\n", strings.Join(asset.Reasons[:min(2, len(asset.Reasons))], ", "))
		}
	}
}
