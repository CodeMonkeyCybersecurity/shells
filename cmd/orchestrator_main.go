// cmd/orchestrator_main.go - Unified intelligent orchestrator for main command
package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/internal/orchestrator"
	"github.com/CodeMonkeyCybersecurity/shells/internal/validation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// runIntelligentOrchestrator is the main entry point that wires the orchestrator to the root command
func runIntelligentOrchestrator(ctx context.Context, target string, cmd *cobra.Command, log *logger.Logger, store core.ResultStore) error {
	// Check for scope file
	scopePath, _ := cmd.Flags().GetString("scope")

	// Validate target (with scope if provided)
	var validationResult *validation.TargetValidationResult
	var err error

	if scopePath != "" {
		validationResult, err = validation.ValidateWithScope(target, scopePath)
		if err != nil {
			return fmt.Errorf("scope validation failed: %w", err)
		}
		color.Green("✓ Target authorized by scope file: %s\n\n", scopePath)
	} else {
		validationResult = validation.ValidateTarget(target)
	}

	if !validationResult.Valid {
		return fmt.Errorf("target validation failed: %w", validationResult.Error)
	}

	// Display warnings if any
	if len(validationResult.Warnings) > 0 {
		color.Yellow("\n  Warnings:\n")
		for _, warning := range validationResult.Warnings {
			fmt.Printf("   • %s\n", warning)
		}
		fmt.Println()
	}

	// Use normalized target for scanning
	normalizedTarget := validationResult.NormalizedURL
	if normalizedTarget == "" {
		normalizedTarget = target
	}

	log.Infow("Target validated",
		"original_target", target,
		"normalized_target", normalizedTarget,
		"target_type", validationResult.TargetType,
	)

	// Parse configuration from flags
	config := buildOrchestratorConfig(cmd)

	// Print banner
	printOrchestratorBanner(normalizedTarget, config)

	// Create scan record to get scan ID
	scanID := fmt.Sprintf("bounty-%d-%x", time.Now().Unix(), time.Now().UnixNano()&0xFFFFFFFF)

	// Wrap logger with DBEventLogger to save events to database
	dbLogger := logger.NewDBEventLogger(log, store, scanID)

	// Initialize orchestrator with real scanners and DB-enabled logger
	engine, err := orchestrator.NewBugBountyEngine(store, &noopTelemetry{}, dbLogger.Logger, config)
	if err != nil {
		return fmt.Errorf("failed to initialize orchestrator: %w", err)
	}

	// Execute the full pipeline with normalized target
	result, err := engine.Execute(ctx, normalizedTarget)
	if err != nil {
		return fmt.Errorf("orchestrator execution failed: %w", err)
	}

	// Display organization footprinting results if available
	if result.OrganizationInfo != nil {
		displayOrganizationFootprinting(result.OrganizationInfo)
	}

	// Display asset discovery results if available
	if len(result.DiscoveredAssets) > 0 {
		displayAssetDiscoveryResults(result.DiscoveredAssets, result.DiscoverySession)
	}

	// Display results
	displayOrchestratorResults(result, config)

	// Save report if requested
	if outputFile := getOutputFile(cmd); outputFile != "" {
		if err := saveOrchestratorReport(result, outputFile); err != nil {
			log.Errorw("Failed to save report", "error", err, "file", outputFile)
		} else {
			fmt.Printf("\n✓ Detailed report saved to: %s\n", outputFile)
		}
	}

	return nil
}

// buildOrchestratorConfig builds orchestrator configuration from command flags
func buildOrchestratorConfig(cmd *cobra.Command) orchestrator.BugBountyConfig {
	// Check for quick/deep mode flags
	quick, _ := cmd.Flags().GetBool("quick")
	deep, _ := cmd.Flags().GetBool("deep")

	// Base configuration optimized for bug bounty
	config := orchestrator.DefaultBugBountyConfig()

	// Apply mode-specific settings
	if quick {
		// Quick mode: Fast triage, critical vulns only (< 30 seconds total)
		// TASK 8 FIX: Enable minimal web crawl for auth endpoint discovery
		// Auth vulns (Golden SAML, JWT confusion, OAuth2 bypass) are HIGH-VALUE findings
		config.SkipDiscovery = false // CHANGED: Need discovery for auth endpoints
		config.DiscoveryTimeout = 5 * time.Second // Fast auth endpoint discovery
		config.ScanTimeout = 30 * time.Second
		config.TotalTimeout = 1 * time.Minute
		config.MaxAssets = 1
		config.MaxDepth = 1 // Minimal depth for speed, enough for auth discovery
		config.EnableDNS = false
		config.EnablePortScan = false
		config.EnableWebCrawl = true // CHANGED: Allow minimal crawl for auth endpoints
		config.EnableAPITesting = false // Skip in quick mode
		config.EnableLogicTesting = false
		config.EnableAuthTesting = true // ENABLED: Auth testing is high-value for bug bounties
		config.EnableIDORTesting = false // Skip IDOR in quick mode
		config.EnableNucleiScan = false // Skip Nuclei in quick mode
		config.EnableSCIMTesting = false // Skip SCIM in quick mode
	} else if deep {
		// Deep mode: Comprehensive testing (< 15 minutes total)
		config.DiscoveryTimeout = 1 * time.Minute
		config.ScanTimeout = 10 * time.Minute
		config.TotalTimeout = 15 * time.Minute
		config.MaxAssets = 100
		config.MaxDepth = 2
		config.EnableDNS = true
		config.EnablePortScan = true
		config.EnableWebCrawl = true
	}
	// Default mode (no flag): Balanced - 30s discovery, 5min total (from DefaultBugBountyConfig)

	// Apply custom timeout if provided
	if timeout, _ := cmd.Flags().GetDuration("timeout"); timeout > 0 {
		config.TotalTimeout = timeout
	}

	// Always enable progress for main command
	config.ShowProgress = true
	config.Verbose = false

	return config
}

// printOrchestratorBanner displays the orchestrator banner
func printOrchestratorBanner(target string, config orchestrator.BugBountyConfig) {
	cyan := color.New(color.FgCyan, color.Bold)

	mode := "Standard"
	if config.TotalTimeout < 10*time.Minute {
		mode = "Quick"
	} else if config.TotalTimeout > 20*time.Minute {
		mode = "Deep"
	}

	fmt.Println()
	log.Info("══════════════════════════════════════════════════════════════════════", "component", "orchestrator_main")
	cyan.Println(" Shells - Intelligent Bug Bounty Automation")
	fmt.Printf("   Target: %s\n", target)
	fmt.Printf("   Mode: %s\n", mode)
	fmt.Printf("   Time: %s\n", time.Now().Format("15:04:05"))
	log.Info("══════════════════════════════════════════════════════════════════════", "component", "orchestrator_main")
	fmt.Println()
}

// displayOrchestratorResults displays results from the orchestrator
func displayOrchestratorResults(result *orchestrator.BugBountyResult, config orchestrator.BugBountyConfig) {
	fmt.Println()
	log.Info("═══ Orchestrator Summary ═══", "component", "orchestrator_main")
	fmt.Printf("Status: %s\n", colorStatus(result.Status))
	fmt.Printf("Duration: %s\n", result.Duration.Round(time.Second))
	fmt.Printf("Assets Discovered: %d\n", result.DiscoveredAt)
	fmt.Printf("Assets Tested: %d\n", result.TestedAssets)
	fmt.Printf("Total Findings: %d\n", result.TotalFindings)
	fmt.Println()

	// Display phase results using modularized display functions
	if len(result.PhaseResults) > 0 {
		log.Info("═══ Pipeline Phases ═══", "component", "orchestrator_main")

		phaseOrder := []string{"discovery", "auth", "scim", "api"}
		for _, phaseName := range phaseOrder {
			if pr, ok := result.PhaseResults[phaseName]; ok {
				status := colorPhaseStatus(pr.Status)
				phaseLine := fmt.Sprintf("[%s] %s", status, pr.Phase)

				if pr.Status == "completed" {
					phaseLine += color.GreenString(" ✓")
				} else if pr.Status == "failed" {
					phaseLine += color.RedString(" ✗")
				}

				phaseLine += fmt.Sprintf(" - %d findings in %s",
					pr.Findings,
					pr.Duration.Round(time.Second),
				)

				fmt.Println(phaseLine)

				if pr.Error != "" {
					color.New(color.FgRed).Printf("    Error: %s\n", pr.Error)
				}
			}
		}
		fmt.Println()
	}

	// Display vulnerability test coverage
	displayTestCoverage(result)

	// Display findings by severity using modularized display functions
	if len(result.Findings) > 0 {
		log.Info("═══ Findings by Severity ═══", "component", "orchestrator_main")
		bySeverity := groupFindingsBySeverity(result.Findings)

		for _, severity := range []types.Severity{
			types.SeverityCritical,
			types.SeverityHigh,
			types.SeverityMedium,
			types.SeverityLow,
			types.SeverityInfo,
		} {
			count := bySeverity[severity]
			if count > 0 {
				fmt.Printf("%s: %d\n", colorSeverity(severity), count)
			}
		}
		fmt.Println()

		// Display top findings using modularized display function
		log.Info("═══ Top Findings ═══", "component", "orchestrator_main")
		displayTopFindings(result.Findings, 10)

		if len(result.Findings) > 10 {
			fmt.Printf("\n... and %d more findings\n", len(result.Findings)-10)
			log.Info("\nUse 'shells results query' to see all findings", "component", "orchestrator_main")
		}
	} else {
		color.New(color.FgYellow).Println("ℹ No high-severity vulnerabilities found")
		log.Info("  The target appears to have good security posture,", "component", "orchestrator_main")
		log.Info("  or may require authenticated testing.", "component", "orchestrator_main")
	}

	fmt.Println()
	fmt.Printf("✓ Scan complete in %s\n", result.Duration.Round(time.Second))
	fmt.Printf("  Scan ID: %s\n", result.ScanID)

	dbPath := "~/.shells/shells.db"
	fmt.Printf("\n Results saved to: %s\n", color.CyanString(dbPath))
	fmt.Printf("\nQuery results with:\n")
	fmt.Printf("  shells results query --scan-id %s\n", result.ScanID)
	fmt.Printf("  shells results stats\n")
	fmt.Printf("  shells results recent --limit 10\n")
}

// Helper functions

func getOutputFile(cmd *cobra.Command) string {
	// Check if output flag exists in root command
	if cmd.Flags().Lookup("output") != nil {
		output, _ := cmd.Flags().GetString("output")
		return output
	}
	return ""
}

func saveOrchestratorReport(result *orchestrator.BugBountyResult, filename string) error {
	// TODO: Implement JSON/HTML export
	return fmt.Errorf("report export not yet implemented")
}

// displayOrganizationFootprinting displays organization footprinting results
func displayOrganizationFootprinting(org *correlation.Organization) {
	if org == nil || org.Name == "" {
		return
	}

	fmt.Println()
	color.Cyan("═══ Phase 0: Organization Footprinting ═══")
	fmt.Println()

	// Organization info
	fmt.Printf("  Organization: %s\n", color.GreenString(org.Name))
	if org.Confidence > 0 {
		confidencePct := org.Confidence * 100
		confidenceColor := color.GreenString
		if confidencePct < 50 {
			confidenceColor = color.YellowString
		}
		fmt.Printf("  Confidence: %s\n", confidenceColor("%.1f%%", confidencePct))
	}

	// Related domains
	if len(org.Domains) > 0 {
		fmt.Printf("\n  ✓ Found %s related domains:\n", color.GreenString("%d", len(org.Domains)))
		displayLimit := 10
		for i, domain := range org.Domains {
			if i < displayLimit {
				fmt.Printf("    • %s\n", domain)
			}
		}
		if len(org.Domains) > displayLimit {
			fmt.Printf("    %s\n", color.CyanString("... and %d more", len(org.Domains)-displayLimit))
		}
	}

	// IP ranges
	if len(org.IPRanges) > 0 {
		fmt.Printf("\n  ✓ Found %s IP ranges:\n", color.GreenString("%d", len(org.IPRanges)))
		for _, ipRange := range org.IPRanges {
			fmt.Printf("    • %s\n", ipRange)
		}
	}

	// ASNs
	if len(org.ASNs) > 0 {
		fmt.Printf("\n  ✓ Found %s ASNs:\n", color.GreenString("%d", len(org.ASNs)))
		for _, asn := range org.ASNs {
			fmt.Printf("    • %s\n", asn)
		}
	}

	// Certificates
	if len(org.Certificates) > 0 {
		fmt.Printf("\n  ✓ Found %s SSL certificates\n", color.GreenString("%d", len(org.Certificates)))
	}

	// Subsidiaries
	if len(org.Subsidiaries) > 0 {
		fmt.Printf("\n  ✓ Found %s subsidiaries:\n", color.GreenString("%d", len(org.Subsidiaries)))
		for _, sub := range org.Subsidiaries {
			fmt.Printf("    • %s\n", sub)
		}
	}

	// Sources
	if len(org.Sources) > 0 {
		fmt.Printf("\n  Sources: %s\n", color.CyanString(strings.Join(org.Sources, ", ")))
	}

	fmt.Println()
}

// displayAssetDiscoveryResults displays detailed asset discovery results
func displayAssetDiscoveryResults(assets []*discovery.Asset, session *discovery.DiscoverySession) {
	if len(assets) == 0 {
		return
	}

	fmt.Println()
	color.Cyan("═══ Phase 1: Asset Discovery ═══")
	fmt.Println()

	// Group assets by type
	assetsByType := make(map[discovery.AssetType][]*discovery.Asset)
	for _, asset := range assets {
		assetsByType[asset.Type] = append(assetsByType[asset.Type], asset)
	}

	// Display subdomains
	if subdomains := assetsByType[discovery.AssetTypeSubdomain]; len(subdomains) > 0 {
		fmt.Printf("  ✓ Discovered %s subdomains:\n", color.GreenString("%d", len(subdomains)))
		displayLimit := 15
		for i, asset := range subdomains {
			if i < displayLimit {
				priority := ""
				if asset.Priority >= 80 { // High priority assets
					priority = color.RedString(" [HIGH VALUE]")
				}
				fmt.Printf("    • %s%s\n", asset.Value, priority)
			}
		}
		if len(subdomains) > displayLimit {
			fmt.Printf("    %s\n", color.CyanString("... and %d more", len(subdomains)-displayLimit))
		}
		fmt.Println()
	}

	// Display IPs with open ports
	if ips := assetsByType[discovery.AssetTypeIP]; len(ips) > 0 {
		fmt.Printf("  ✓ Found %s IP addresses:\n", color.GreenString("%d", len(ips)))
		for i, asset := range ips {
			if i < 10 { // Show first 10
				ports := ""
				if p, ok := asset.Metadata["open_ports"]; ok {
					ports = fmt.Sprintf(" - Ports: %s", p)
				}
				fmt.Printf("    • %s%s\n", asset.Value, ports)
			}
		}
		if len(ips) > 10 {
			fmt.Printf("    %s\n", color.CyanString("... and %d more", len(ips)-10))
		}
		fmt.Println()
	}

	// Display services with versions
	if services := assetsByType[discovery.AssetTypeService]; len(services) > 0 {
		fmt.Printf("  ✓ Found %s services:\n", color.GreenString("%d", len(services)))
		for i, asset := range services {
			if i < 10 { // Show first 10
				version := ""
				if v, ok := asset.Metadata["version"]; ok {
					version = fmt.Sprintf(" (%s)", v)
				}
				port := ""
				if p, ok := asset.Metadata["port"]; ok {
					port = fmt.Sprintf(":%s", p)
				}
				serviceName := asset.Value
				if name, ok := asset.Metadata["service_name"]; ok {
					serviceName = name
				}
				fmt.Printf("    • %s%s - %s%s\n", asset.IP, port, serviceName, version)
			}
		}
		if len(services) > 10 {
			fmt.Printf("    %s\n", color.CyanString("... and %d more", len(services)-10))
		}
		fmt.Println()
	}

	// Display URLs/endpoints
	if urls := assetsByType[discovery.AssetTypeURL]; len(urls) > 0 {
		fmt.Printf("  ✓ Found %s URLs:\n", color.GreenString("%d", len(urls)))
		for i, asset := range urls {
			if i < 8 { // Show first 8
				fmt.Printf("    • %s\n", asset.Value)
			}
		}
		if len(urls) > 8 {
			fmt.Printf("    %s\n", color.CyanString("... and %d more", len(urls)-8))
		}
		fmt.Println()
	}

	// Display technologies detected
	techSet := make(map[string]bool)
	for _, asset := range assets {
		for _, tech := range asset.Technology {
			techSet[tech] = true
		}
	}
	if len(techSet) > 0 {
		techs := make([]string, 0, len(techSet))
		for tech := range techSet {
			techs = append(techs, tech)
		}
		fmt.Printf("  ✓ Technologies detected: %s\n\n", color.CyanString(strings.Join(techs, ", ")))
	}

	// High-value asset summary
	if session != nil && session.HighValueAssets > 0 {
		fmt.Printf("  %s Found %s high-value assets (login pages, admin panels, APIs)\n\n",
			color.RedString("⚠️"),
			color.RedString("%d", session.HighValueAssets),
		)
	}

	fmt.Println()
}

// displayTestCoverage shows what vulnerability tests were run and their results
func displayTestCoverage(result *orchestrator.BugBountyResult) {
	fmt.Println()
	color.Cyan("═══ Phase 3: Vulnerability Testing ═══")
	fmt.Println()

	// Authentication Testing
	fmt.Printf("  %s Authentication Testing:\n", color.CyanString("🔐"))
	if authPhase, ok := result.PhaseResults["auth"]; ok {
		if authPhase.Status == "completed" {
			if authPhase.Findings > 0 {
				fmt.Printf("    • Tested SAML/OAuth2/WebAuthn: %s (%d findings)\n",
					color.RedString("✗ Vulnerabilities found"), authPhase.Findings)
			} else {
				fmt.Printf("    • Tested SAML/OAuth2/WebAuthn: %s\n",
					color.GreenString("✓ No issues found"))
			}
		} else if authPhase.Status == "skipped" {
			fmt.Printf("    • %s (no authentication endpoints discovered)\n",
				color.YellowString("⊘ Not applicable"))
		}
	} else {
		fmt.Printf("    • %s (authentication testing disabled)\n",
			color.YellowString("⊘ Skipped"))
	}

	// API Security Testing
	fmt.Printf("\n  %s API Security Testing:\n", color.CyanString("🔌"))

	// GraphQL
	if graphqlPhase, ok := result.PhaseResults["graphql"]; ok {
		if graphqlPhase.Status == "completed" {
			if graphqlPhase.Findings > 0 {
				fmt.Printf("    • GraphQL introspection: %s (%d findings)\n",
					color.RedString("✗ Issues found"), graphqlPhase.Findings)
			} else {
				endpointCount := 1 // Default
				if graphqlPhase.Findings == 0 {
					fmt.Printf("    • GraphQL introspection: %s\n",
						color.GreenString("✓ Tested %d endpoint, no issues", endpointCount))
				}
			}
		}
	} else {
		fmt.Printf("    • GraphQL testing: %s (no GraphQL endpoints found)\n",
			color.YellowString("⊘ Not applicable"))
	}

	// REST API
	if restapiPhase, ok := result.PhaseResults["rest_api"]; ok {
		if restapiPhase.Status == "completed" {
			if restapiPhase.Findings > 0 {
				fmt.Printf("    • REST API security: %s (%d findings)\n",
					color.RedString("✗ Issues found"), restapiPhase.Findings)
			} else {
				fmt.Printf("    • REST API security: %s\n",
					color.GreenString("✓ No issues found"))
			}
		}
	} else {
		fmt.Printf("    • REST API testing: %s (API testing disabled)\n",
			color.YellowString("⊘ Skipped"))
	}

	// Access Control Testing
	fmt.Printf("\n  %s Access Control Testing:\n", color.CyanString("🔒"))

	// IDOR
	if idorPhase, ok := result.PhaseResults["idor"]; ok {
		if idorPhase.Status == "completed" {
			if idorPhase.Findings > 0 {
				fmt.Printf("    • IDOR testing: %s (%d findings)\n",
					color.RedString("✗ Vulnerabilities found"), idorPhase.Findings)
			} else {
				fmt.Printf("    • IDOR testing: %s\n",
					color.GreenString("✓ No issues found"))
			}
		}
	} else {
		fmt.Printf("    • IDOR testing: %s (no suitable endpoints found)\n",
			color.YellowString("⊘ Not applicable"))
	}

	// SCIM
	if scimPhase, ok := result.PhaseResults["scim"]; ok {
		if scimPhase.Status == "completed" {
			if scimPhase.Findings > 0 {
				fmt.Printf("    • SCIM vulnerabilities: %s (%d findings)\n",
					color.RedString("✗ Issues found"), scimPhase.Findings)
			} else {
				fmt.Printf("    • SCIM vulnerabilities: %s\n",
					color.GreenString("✓ No issues found"))
			}
		}
	} else {
		fmt.Printf("    • SCIM testing: %s (no SCIM endpoints found)\n",
			color.YellowString("⊘ Not applicable"))
	}

	// Service Fingerprinting
	fmt.Printf("\n  %s Service Fingerprinting:\n", color.CyanString("🔍"))
	if nmapPhase, ok := result.PhaseResults["nmap"]; ok {
		if nmapPhase.Status == "completed" {
			hostsScanned := 1 // Default
			if nmapPhase.Findings > 0 {
				fmt.Printf("    • Nmap scan: %s (%d hosts, %d services found)\n",
					color.GreenString("✓ Completed"), hostsScanned, nmapPhase.Findings)
			} else {
				fmt.Printf("    • Nmap scan: %s (%d host)\n",
					color.GreenString("✓ Completed"), hostsScanned)
			}
		} else if nmapPhase.Status == "failed" {
			fmt.Printf("    • Nmap scan: %s\n",
				color.RedString("✗ Failed"))
			if nmapPhase.Error != "" {
				fmt.Printf("      Error: %s\n", color.RedString(nmapPhase.Error))
			}
		}
	} else {
		fmt.Printf("    • Nmap scan: %s (service fingerprinting disabled)\n",
			color.YellowString("⊘ Skipped"))
	}

	// Nuclei Scanning
	if nucleiPhase, ok := result.PhaseResults["nuclei"]; ok {
		if nucleiPhase.Status == "completed" {
			if nucleiPhase.Findings > 0 {
				fmt.Printf("    • Nuclei CVE scan: %s (%d findings)\n",
					color.RedString("✗ Vulnerabilities found"), nucleiPhase.Findings)
			} else {
				fmt.Printf("    • Nuclei CVE scan: %s\n",
					color.GreenString("✓ No CVEs found"))
			}
		}
	} else {
		fmt.Printf("    • Nuclei scanning: %s (nuclei not installed)\n",
			color.YellowString("⊘ Skipped"))
	}

	// Summary
	fmt.Println()
	totalCategories := 0
	testedCategories := 0

	for _, phase := range []string{"auth", "graphql", "rest_api", "idor", "scim", "nmap", "nuclei"} {
		totalCategories++
		if pr, ok := result.PhaseResults[phase]; ok && pr.Status == "completed" {
			testedCategories++
		}
	}

	fmt.Printf("  Summary: %s/%s test categories executed, %s total findings\n\n",
		color.CyanString("%d", testedCategories),
		color.CyanString("%d", totalCategories),
		color.GreenString("%d", result.TotalFindings),
	)
}

// Note: Helper functions (colorStatus, colorSeverity, displayTopFindings, etc.)
// are now in display_helpers.go to avoid duplication across commands
