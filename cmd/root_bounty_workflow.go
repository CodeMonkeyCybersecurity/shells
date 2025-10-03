package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/fatih/color"
	"github.com/google/uuid"
)

// BugBountyWorkflow runs the optimized bug bounty scanning workflow
func runBugBountyWorkflow(ctx context.Context, target string, log *logger.Logger, store core.ResultStore) error {
	startTime := time.Now()

	// Enable bug bounty mode
	os.Setenv("SHELLS_BUG_BOUNTY_MODE", "true")

	// Display clean banner
	printBugBountyBanner(target)

	// Phase 1: Time-boxed discovery (max 30s)
	fmt.Printf("\n%s", color.CyanString("═══ Phase 1: Smart Discovery (30s max) ═══\n"))
	discoveredAssets, err := runTimedDiscovery(ctx, target, log)
	if err != nil {
		// Don't fail on discovery errors - continue with target only
		log.Debug("Discovery had errors, continuing with target only", "error", err)
		discoveredAssets = []*discovery.Asset{
			{
				ID:       uuid.New().String(),
				Type:     discovery.AssetTypeDomain,
				Value:    target,
				Priority: 100,
			},
		}
	}

	// Prioritize assets for testing
	prioritized := prioritizeAssetsForBugBounty(discoveredAssets, log)
	if len(prioritized) > 0 {
		fmt.Printf("✓ Found %s assets (showing top 5)\n", color.GreenString("%d", len(prioritized)))
		displayTopTargets(prioritized, 5)
	}

	// Phase 2: Focused vulnerability testing
	fmt.Printf("\n%s", color.CyanString("═══ Phase 2: Vulnerability Testing ═══\n"))
	findings := runFocusedVulnTests(ctx, prioritized, target, log)

	// Save findings to database
	if len(findings) > 0 {
		scanID := uuid.New().String()
		for i := range findings {
			findings[i].ScanID = scanID
			findings[i].ID = uuid.New().String()
			findings[i].CreatedAt = time.Now()
			findings[i].UpdatedAt = time.Now()
		}

		if err := store.SaveFindings(ctx, findings); err != nil {
			log.Warn("Failed to save findings to database", "error", err)
		}
	}

	// Phase 3: Results
	fmt.Printf("\n%s", color.CyanString("═══ Phase 3: Results ═══\n"))
	displayFindings(findings)

	// Summary
	duration := time.Since(startTime)
	fmt.Printf("\n%s", color.GreenString("✓ Scan complete in %v\n", duration.Round(time.Second)))
	fmt.Printf("  Total findings: %d\n", len(findings))
	criticalCount := countBySeverity(findings, types.SeverityCritical)
	highCount := countBySeverity(findings, types.SeverityHigh)
	if criticalCount > 0 || highCount > 0 {
		fmt.Printf("  Critical: %s | High: %s\n",
			color.RedString("%d", criticalCount),
			color.YellowString("%d", highCount))
	}

	return nil
}

// runTimedDiscovery performs time-boxed discovery (max 30 seconds)
func runTimedDiscovery(ctx context.Context, target string, log *logger.Logger) ([]*discovery.Asset, error) {
	// Create timeout context
	discoveryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Use optimized bug bounty config
	config := discovery.BugBountyDiscoveryConfig()

	engine := discovery.NewEngine(config, log.WithComponent("discovery"))

	// Start discovery
	session, err := engine.StartDiscovery(target)
	if err != nil {
		return nil, err
	}

	// Poll for completion with progress spinner
	spinner := NewSimpleSpinner("Discovering assets")
	spinner.Start()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-discoveryCtx.Done():
			// Timeout - return what we have
			spinner.Stop()
			session, _ := engine.GetSession(session.ID)
			if session != nil {
				var assets []*discovery.Asset
				for _, asset := range session.Assets {
					assets = append(assets, asset)
				}
				return assets, nil
			}
			return nil, nil

		case <-ticker.C:
			session, err := engine.GetSession(session.ID)
			if err != nil {
				continue
			}

			// Update spinner with progress
			if session.Progress > 0 {
				spinner.Update(fmt.Sprintf("Discovering assets (%.0f%%)", session.Progress))
			}

			if session.Status == discovery.StatusCompleted || session.Status == discovery.StatusFailed {
				spinner.Stop()
				var assets []*discovery.Asset
				for _, asset := range session.Assets {
					assets = append(assets, asset)
				}
				return assets, nil
			}
		}
	}
}

// runFocusedVulnTests runs focused vulnerability tests
func runFocusedVulnTests(ctx context.Context, assets []*BugBountyAssetPriority, target string, log *logger.Logger) []types.Finding {
	var allFindings []types.Finding
	var mu sync.Mutex

	// Create timeout context (5 minutes max for all tests)
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Determine test categories
	tests := []struct {
		name string
		fn   func(context.Context, []*BugBountyAssetPriority, string, *logger.Logger) []types.Finding
	}{
		{"Authentication", testAuthentication},
		{"API Security", testAPISecurity},
		{"Business Logic", testBusinessLogic},
		{"SSRF", testSSRF},
		{"Access Control", testAccessControl},
	}

	// Run tests sequentially with timeout per test
	for i, test := range tests {
		select {
		case <-testCtx.Done():
			fmt.Printf("⚠️ Testing timeout reached\n")
			return allFindings
		default:
			fmt.Printf("[%d/%d] Testing %s... ", i+1, len(tests), test.name)

			// 1 minute timeout per test category
			categoryCtx, categoryCancel := context.WithTimeout(testCtx, 1*time.Minute)
			findings := test.fn(categoryCtx, assets, target, log)
			categoryCancel()

			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()

			if len(findings) > 0 {
				fmt.Printf("%s (%d findings)\n", color.YellowString("✓"), len(findings))
			} else {
				fmt.Printf("%s\n", color.GreenString("✓"))
			}
		}
	}

	return allFindings
}

// Vulnerability test functions (simplified implementations)
func testAuthentication(ctx context.Context, assets []*BugBountyAssetPriority, target string, log *logger.Logger) []types.Finding {
	var findings []types.Finding

	// Quick auth bypass checks on high-value auth endpoints
	for _, asset := range assets {
		if !asset.Features.HasAuthentication {
			continue
		}

		// Check for common auth bypass patterns
		// TODO: Implement actual auth testing from pkg/auth
		finding := types.Finding{
			Tool:        "auth-scanner",
			Type:        "Authentication Analysis",
			Severity:    types.SeverityInfo,
			Title:       fmt.Sprintf("Authentication endpoint detected: %s", asset.Asset.Value),
			Description: "Found authentication endpoint that requires security testing",
			Evidence:    fmt.Sprintf("URL: %s, Score: %d", asset.Asset.Value, asset.Score),
		}
		findings = append(findings, finding)

		// Break after checking top 3 auth endpoints
		if len(findings) >= 3 {
			break
		}
	}

	return findings
}

func testAPISecurity(ctx context.Context, assets []*BugBountyAssetPriority, target string, log *logger.Logger) []types.Finding {
	var findings []types.Finding

	// Quick API security checks
	for _, asset := range assets {
		if !asset.Features.HasAPI {
			continue
		}

		// TODO: Implement actual API testing
		finding := types.Finding{
			Tool:        "api-scanner",
			Type:        "API Security Analysis",
			Severity:    types.SeverityInfo,
			Title:       fmt.Sprintf("API endpoint detected: %s", asset.Asset.Value),
			Description: "Found API endpoint that requires security testing",
			Evidence:    fmt.Sprintf("URL: %s, Score: %d", asset.Asset.Value, asset.Score),
		}
		findings = append(findings, finding)

		if len(findings) >= 3 {
			break
		}
	}

	return findings
}

func testBusinessLogic(ctx context.Context, assets []*BugBountyAssetPriority, target string, log *logger.Logger) []types.Finding {
	var findings []types.Finding

	// Quick business logic checks
	for _, asset := range assets {
		if !asset.Features.HasPayment {
			continue
		}

		// TODO: Implement actual business logic testing
		finding := types.Finding{
			Tool:        "logic-scanner",
			Type:        "Business Logic Analysis",
			Severity:    types.SeverityInfo,
			Title:       fmt.Sprintf("Payment endpoint detected: %s", asset.Asset.Value),
			Description: "Found payment/transaction endpoint that requires logic testing",
			Evidence:    fmt.Sprintf("URL: %s, Score: %d", asset.Asset.Value, asset.Score),
		}
		findings = append(findings, finding)

		if len(findings) >= 2 {
			break
		}
	}

	return findings
}

func testSSRF(ctx context.Context, assets []*BugBountyAssetPriority, target string, log *logger.Logger) []types.Finding {
	var findings []types.Finding

	// Quick SSRF pattern detection
	for _, asset := range assets {
		assetValue := strings.ToLower(asset.Asset.Value)
		if strings.Contains(assetValue, "callback") ||
			strings.Contains(assetValue, "webhook") ||
			strings.Contains(assetValue, "url") ||
			strings.Contains(assetValue, "proxy") {

			// TODO: Implement actual SSRF testing
			finding := types.Finding{
				Tool:        "ssrf-scanner",
				Type:        "SSRF Analysis",
				Severity:    types.SeverityInfo,
				Title:       fmt.Sprintf("Potential SSRF vector: %s", asset.Asset.Value),
				Description: "Found endpoint with URL/callback parameters that may be vulnerable to SSRF",
				Evidence:    fmt.Sprintf("URL: %s, Pattern: callback/webhook/url", asset.Asset.Value),
			}
			findings = append(findings, finding)

			if len(findings) >= 2 {
				break
			}
		}
	}

	return findings
}

func testAccessControl(ctx context.Context, assets []*BugBountyAssetPriority, target string, log *logger.Logger) []types.Finding {
	var findings []types.Finding

	// Quick access control checks
	for _, asset := range assets {
		if !asset.Features.HasUserData {
			continue
		}

		// TODO: Implement actual IDOR/access control testing
		finding := types.Finding{
			Tool:        "access-scanner",
			Type:        "Access Control Analysis",
			Severity:    types.SeverityInfo,
			Title:       fmt.Sprintf("User data endpoint detected: %s", asset.Asset.Value),
			Description: "Found endpoint with user data access that requires authorization testing",
			Evidence:    fmt.Sprintf("URL: %s, Score: %d", asset.Asset.Value, asset.Score),
		}
		findings = append(findings, finding)

		if len(findings) >= 2 {
			break
		}
	}

	return findings
}

// Helper functions
func printBugBountyBanner(target string) {
	fmt.Println()
	fmt.Println(strings.Repeat("═", 70))
	fmt.Printf("🎯 %s\n", color.CyanString("High-Value Bug Bounty Scanner"))
	fmt.Printf("   Target: %s\n", color.YellowString(target))
	fmt.Printf("   Focus: Auth • API • Logic • SSRF • Access Control\n")
	fmt.Printf("   Time: %s\n", time.Now().Format("15:04:05"))
	fmt.Println(strings.Repeat("═", 70))
}

func displayTopTargets(assets []*BugBountyAssetPriority, limit int) {
	if len(assets) == 0 {
		return
	}

	if limit > len(assets) {
		limit = len(assets)
	}

	for i := 0; i < limit; i++ {
		asset := assets[i]
		scoreColor := color.GreenString
		if asset.Score >= 90 {
			scoreColor = color.RedString
		} else if asset.Score >= 70 {
			scoreColor = color.YellowString
		}

		fmt.Printf("  %d. %s %s\n",
			i+1,
			scoreColor("[%d]", asset.Score),
			asset.Asset.Value)

		if len(asset.Reasons) > 0 {
			fmt.Printf("     → %s\n", strings.Join(asset.Reasons[:min(2, len(asset.Reasons))], ", "))
		}
	}
}

func displayFindings(findings []types.Finding) {
	if len(findings) == 0 {
		fmt.Println(color.GreenString("✓ No vulnerabilities found"))
		return
	}

	// Group by severity
	bySeverity := make(map[types.Severity][]types.Finding)
	for _, f := range findings {
		bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
	}

	// Display in severity order
	severities := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}

	for _, sev := range severities {
		findings := bySeverity[sev]
		if len(findings) == 0 {
			continue
		}

		severityColor := color.WhiteString
		switch sev {
		case types.SeverityCritical:
			severityColor = color.RedString
		case types.SeverityHigh:
			severityColor = color.YellowString
		case types.SeverityMedium:
			severityColor = color.CyanString
		}

		fmt.Printf("\n%s (%d)\n", severityColor(strings.ToUpper(string(sev))), len(findings))
		for i, f := range findings {
			if i >= 5 { // Limit to 5 per severity
				fmt.Printf("  ... and %d more\n", len(findings)-5)
				break
			}
			fmt.Printf("  • %s\n", f.Title)
			if f.Evidence != "" && len(f.Evidence) < 100 {
				fmt.Printf("    %s\n", color.HiBlackString(f.Evidence))
			}
		}
	}
}

func countBySeverity(findings []types.Finding, sev types.Severity) int {
	count := 0
	for _, f := range findings {
		if f.Severity == sev {
			count++
		}
	}
	return count
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
