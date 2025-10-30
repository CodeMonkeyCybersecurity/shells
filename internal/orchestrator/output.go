// internal/orchestrator/output.go
//
// Output Formatter - Terminal display and CLI output
//
// REFACTORING CONTEXT:
// Extracted from bounty_engine.go display methods (lines 3791-4039, ~248 lines)
// Separates terminal output concerns from engine logic for clean I/O isolation.
//
// PHILOSOPHY ALIGNMENT:
// - Human-centric: Clear, actionable CLI output for security researchers
// - Evidence-based: Displays findings with severity and context
// - Sustainable: Output logic isolated from business logic

package orchestrator

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// OutputFormatter handles terminal display and CLI output
type OutputFormatter struct {
	logger *logger.Logger
	config BugBountyConfig
}

// NewOutputFormatter creates a new output formatter
func NewOutputFormatter(logger *logger.Logger, config BugBountyConfig) *OutputFormatter {
	return &OutputFormatter{
		logger: logger.WithComponent("output"),
		config: config,
	}
}

// DisplayOrganizationFootprinting shows organization footprinting results
func (o *OutputFormatter) DisplayOrganizationFootprinting(org *correlation.Organization, duration time.Duration) {
	if !o.config.ShowProgress {
		return // Skip display if progress disabled
	}

	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("  Organization Footprinting Results")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	if org.Name != "" {
		fmt.Printf("✓ Organization: %s\n", org.Name)
	} else {
		fmt.Println("⚠  Organization name not found")
	}

	fmt.Printf("✓ Confidence Score: %.0f%%\n", org.Confidence*100)
	fmt.Printf("✓ Duration: %s\n", duration.Round(time.Millisecond))

	if len(org.Domains) > 0 {
		fmt.Printf("\n  Related Domains (%d found):\n", len(org.Domains))
		maxDisplay := len(org.Domains)
		if maxDisplay > 10 {
			maxDisplay = 10
		}
		for i := 0; i < maxDisplay; i++ {
			if i == 0 {
				fmt.Printf("    • %s (primary)\n", org.Domains[i])
			} else {
				fmt.Printf("    • %s\n", org.Domains[i])
			}
		}
		if len(org.Domains) > 10 {
			fmt.Printf("    ... and %d more domains\n", len(org.Domains)-10)
		}
	} else {
		fmt.Println("\n  Related Domains: None discovered")
	}

	if len(org.Certificates) > 0 {
		fmt.Printf("\n  SSL/TLS Certificates: %d found\n", len(org.Certificates))
		cert := org.Certificates[0]
		fmt.Printf("    • Subject: %s\n", cert.Subject)
		fmt.Printf("    • Issuer: %s\n", cert.Issuer)
		if len(cert.SANs) > 0 {
			fmt.Printf("    • SANs: %d domains\n", len(cert.SANs))
		}
		if len(org.Certificates) > 1 {
			fmt.Printf("    ... and %d more certificates\n", len(org.Certificates)-1)
		}
	}

	if len(org.ASNs) > 0 {
		fmt.Printf("\n  Autonomous Systems: %d found\n", len(org.ASNs))
		for _, asn := range org.ASNs {
			fmt.Printf("    • %s\n", asn)
		}
	}

	if len(org.IPRanges) > 0 {
		fmt.Printf("\n  IP Ranges: %d found\n", len(org.IPRanges))
		for _, ipRange := range org.IPRanges {
			fmt.Printf("    • %s\n", ipRange)
		}
	}

	fmt.Printf("\n  Data Sources: %s\n", strings.Join(org.Sources, ", "))
	fmt.Println("═══════════════════════════════════════════════════════════════")
}

// DisplayDiscoveryResults shows asset discovery results
func (o *OutputFormatter) DisplayDiscoveryResults(assets []*discovery.Asset, duration time.Duration) {
	if !o.config.ShowProgress {
		return
	}

	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("  Asset Discovery Results")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	fmt.Printf("✓ Total Assets: %d\n", len(assets))
	fmt.Printf("✓ Duration: %s\n", duration.Round(time.Millisecond))

	// Group assets by type
	assetsByType := make(map[discovery.AssetType][]*discovery.Asset)
	for _, asset := range assets {
		assetsByType[asset.Type] = append(assetsByType[asset.Type], asset)
	}

	// Display URLs/Endpoints
	if urls, ok := assetsByType[discovery.AssetTypeURL]; ok && len(urls) > 0 {
		fmt.Printf("\n  Web Endpoints (%d):\n", len(urls))
		maxDisplay := len(urls)
		if maxDisplay > 10 {
			maxDisplay = 10
		}
		for i := 0; i < maxDisplay; i++ {
			fmt.Printf("    • %s\n", urls[i].Value)
		}
		if len(urls) > 10 {
			fmt.Printf("    ... and %d more endpoints\n", len(urls)-10)
		}
	}

	// Display domains
	if domains, ok := assetsByType[discovery.AssetTypeDomain]; ok && len(domains) > 0 {
		fmt.Printf("\n  Domains (%d):\n", len(domains))
		maxDisplay := len(domains)
		if maxDisplay > 10 {
			maxDisplay = 10
		}
		for i := 0; i < maxDisplay; i++ {
			fmt.Printf("    • %s\n", domains[i].Value)
		}
		if len(domains) > 10 {
			fmt.Printf("    ... and %d more domains\n", len(domains)-10)
		}
	}

	// Display IPs
	if ips, ok := assetsByType[discovery.AssetTypeIP]; ok && len(ips) > 0 {
		fmt.Printf("\n  IP Addresses (%d):\n", len(ips))
		maxDisplay := len(ips)
		if maxDisplay > 5 {
			maxDisplay = 5
		}
		for i := 0; i < maxDisplay; i++ {
			fmt.Printf("    • %s\n", ips[i].Value)
		}
		if len(ips) > 5 {
			fmt.Printf("    ... and %d more IPs\n", len(ips)-5)
		}
	}

	// Display services
	if services, ok := assetsByType[discovery.AssetTypeService]; ok && len(services) > 0 {
		fmt.Printf("\n  Services (%d):\n", len(services))
		maxDisplay := len(services)
		if maxDisplay > 10 {
			maxDisplay = 10
		}
		for i := 0; i < maxDisplay; i++ {
			service := services[i]
			if service.Port > 0 && service.Protocol != "" {
				fmt.Printf("    • %s:%d (%s)\n", service.Value, service.Port, service.Protocol)
			} else if service.Port > 0 {
				fmt.Printf("    • %s:%d\n", service.Value, service.Port)
			} else {
				fmt.Printf("    • %s\n", service.Value)
			}
		}
		if len(services) > 10 {
			fmt.Printf("    ... and %d more services\n", len(services)-10)
		}
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
}

// DisplayScanSummary shows final scan results summary
func (o *OutputFormatter) DisplayScanSummary(result *BugBountyResult) {
	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("  Scan Complete!")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	fmt.Printf("  Scan ID: %s\n", result.ScanID)
	fmt.Printf("  Target: %s\n", result.Target)
	fmt.Printf("  Duration: %s\n", result.Duration.Round(time.Millisecond))

	// Group findings by severity
	severityCounts := make(map[string]int)
	for _, finding := range result.Findings {
		severityCounts[string(finding.Severity)]++
	}

	fmt.Printf("\n  Findings: %d total\n", len(result.Findings))
	if critical, ok := severityCounts["CRITICAL"]; ok && critical > 0 {
		fmt.Printf("    • CRITICAL: %d\n", critical)
	}
	if high, ok := severityCounts["HIGH"]; ok && high > 0 {
		fmt.Printf("    • HIGH: %d\n", high)
	}
	if medium, ok := severityCounts["MEDIUM"]; ok && medium > 0 {
		fmt.Printf("    • MEDIUM: %d\n", medium)
	}
	if low, ok := severityCounts["LOW"]; ok && low > 0 {
		fmt.Printf("    • LOW: %d\n", low)
	}
	if len(result.Findings) == 0 {
		fmt.Println("    • No vulnerabilities found")
	}

	// Show sample findings
	if len(result.Findings) > 0 {
		fmt.Println("\n  Top Findings:")
		maxDisplay := len(result.Findings)
		if maxDisplay > 5 {
			maxDisplay = 5
		}
		for i := 0; i < maxDisplay; i++ {
			finding := result.Findings[i]
			fmt.Printf("\n    [%s] %s\n", finding.Severity, finding.Title)
			fmt.Printf("      Tool: %s | Type: %s\n", finding.Tool, finding.Type)
			if finding.Description != "" && len(finding.Description) < 100 {
				fmt.Printf("      %s\n", finding.Description)
			}
		}
		if len(result.Findings) > 5 {
			fmt.Printf("\n    ... and %d more findings\n", len(result.Findings)-5)
		}
	}

	fmt.Println("\n  Next Steps:")
	fmt.Printf("    • View detailed results: shells results show %s\n", result.ScanID)
	fmt.Printf("    • Export report: shells results export %s --format html\n", result.ScanID)
	fmt.Printf("    • Web dashboard: http://localhost:8080 (if server running)\n")

	fmt.Println("═══════════════════════════════════════════════════════════════")
}

// StreamHighSeverityFinding displays critical/high findings in real-time
// Provides immediate feedback during scans instead of waiting until the end
func StreamHighSeverityFinding(finding types.Finding) {
	// Only stream CRITICAL and HIGH severity findings
	if finding.Severity != types.SeverityCritical && finding.Severity != types.SeverityHigh {
		return
	}

	// Color coding for severity
	severityStr := fmt.Sprintf("[%s]", finding.Severity)
	if finding.Severity == types.SeverityCritical {
		severityStr = fmt.Sprintf("\033[1;31m[CRITICAL]\033[0m") // Bold Red
	} else if finding.Severity == types.SeverityHigh {
		severityStr = fmt.Sprintf("\033[1;33m[HIGH]\033[0m") // Bold Yellow
	}

	// Immediate CLI output
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf(" %s VULNERABILITY FOUND\n", severityStr)
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("   Title: %s\n", finding.Title)
	fmt.Printf("   Type: %s\n", finding.Type)
	fmt.Printf("   Tool: %s\n", finding.Tool)
	fmt.Printf("   Severity: %s\n", finding.Severity)
	if finding.Description != "" {
		// Truncate long descriptions
		desc := finding.Description
		if len(desc) > 200 {
			desc = desc[:197] + "..."
		}
		fmt.Printf("   Description: %s\n", desc)
	}
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()
}
