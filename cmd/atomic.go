package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/integrations/atomic"
	"github.com/spf13/cobra"
)

// atomicCmd represents the atomic command
var atomicCmd = &cobra.Command{
	Use:   "atomic",
	Short: "Run Atomic Red Team tests to demonstrate vulnerability impact",
	Long: `Safe integration with Atomic Red Team for demonstrating vulnerability impact using MITRE ATT&CK techniques.

This command provides bug bounty safe execution of atomic tests to demonstrate the potential impact of discovered vulnerabilities. All tests are filtered for safety and executed with appropriate constraints.

Key Features:
- ATT&CK technique mapping for vulnerabilities
- Safe test execution with Docker sandboxing
- MITRE Navigator report generation
- Bug bounty compliance and safety validation
- Comprehensive impact demonstration

Examples:
  shells atomic demo --vuln-type SSRF --target https://example.com
  shells atomic list --category discovery
  shells atomic report --findings findings.json --output attack-report.html
  shells atomic validate --technique T1552.001`,
}

// atomicListCmd lists available safe atomic tests
var atomicListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available safe atomic tests and techniques",
	Long: `List all atomic tests that are safe for bug bounty execution.

This command shows all available ATT&CK techniques and their corresponding atomic tests that have been validated for bug bounty safety. You can filter by vulnerability type, technique category, or severity level.

Examples:
  shells atomic list
  shells atomic list --vuln-type SSRF
  shells atomic list --category credential-access
  shells atomic list --tactic discovery`,
	Run: func(cmd *cobra.Command, args []string) {
		vulnType, _ := cmd.Flags().GetString("vuln-type")
		_ = vulnType // Use the variable
		output, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")

		// Initialize atomic client
		config := atomic.Config{
			SafetyMode:  true,
			DryRun:      true,
			SandboxMode: false,
			Timeout:     30 * time.Second,
		}

		client, err := atomic.NewAtomicClient(config)
		if err != nil {
			fmt.Printf("Error initializing atomic client: %v\n", err)
			os.Exit(1)
		}

		techniques := client.ListSafeTechniques()

		if vulnType != "" {
			// Filter by vulnerability type
			mapper := atomic.NewVulnToAttackMapper()
			vulnTechniques := mapper.GetTechniques(vulnType)
			techniques = filterTechniques(techniques, vulnTechniques)
		}

		if output == "json" {
			printTechniquesJSON(techniques, client)
		} else {
			printTechniquesTable(techniques, client, verbose)
		}
	},
}

// atomicDemoCmd demonstrates vulnerability impact using atomic tests
var atomicDemoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Demonstrate vulnerability impact using ATT&CK techniques",
	Long: `Demonstrate the potential impact of vulnerabilities using safe atomic tests.

This command maps vulnerabilities to relevant ATT&CK techniques and executes safe demonstrations to show potential impact. All tests are validated for bug bounty safety and can be run in dry-run mode for planning.

Examples:
  shells atomic demo --vuln-type SSRF --target https://example.com
  shells atomic demo --technique T1552.001 --target https://example.com --dry-run
  shells atomic demo --finding CVE-2023-1234 --target https://example.com --sandbox`,
	Run: func(cmd *cobra.Command, args []string) {
		vulnType, _ := cmd.Flags().GetString("vuln-type")
		technique, _ := cmd.Flags().GetString("technique")
		target, _ := cmd.Flags().GetString("target")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		sandbox, _ := cmd.Flags().GetBool("sandbox")
		output, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if target == "" {
			log.Info("Error: --target is required", "component", "atomic")
			os.Exit(1)
		}

		if vulnType == "" && technique == "" {
			log.Info("Error: either --vuln-type or --technique is required", "component", "atomic")
			os.Exit(1)
		}

		// Initialize atomic client
		config := atomic.Config{
			SafetyMode:  true,
			DryRun:      dryRun,
			SandboxMode: sandbox,
			Timeout:     30 * time.Second,
		}

		client, err := atomic.NewAtomicClient(config)
		if err != nil {
			fmt.Printf("Error initializing atomic client: %v\n", err)
			os.Exit(1)
		}

		targetObj := atomic.Target{
			URL:  target,
			Type: "web",
		}

		fmt.Printf("🧪 Demonstrating impact for target: %s\n", target)
		if dryRun {
			fmt.Printf(" Running in dry-run mode (no actual execution)\n")
		}
		if sandbox {
			fmt.Printf("🐳 Using Docker sandbox for safe execution\n")
		}
		fmt.Println()

		var demonstrations []atomic.Demonstration

		if technique != "" {
			// Demonstrate specific technique
			demo, err := runTechniqueDemo(client, technique, targetObj)
			if err != nil {
				fmt.Printf("Error demonstrating technique %s: %v\n", technique, err)
				os.Exit(1)
			}
			demonstrations = append(demonstrations, *demo)
		} else {
			// Map vulnerability to techniques and demonstrate
			demos, err := runVulnerabilityDemo(client, vulnType, targetObj)
			if err != nil {
				fmt.Printf("Error demonstrating vulnerability %s: %v\n", vulnType, err)
				os.Exit(1)
			}
			demonstrations = demos
		}

		// Output results
		if output == "json" {
			printDemonstrationsJSON(demonstrations)
		} else {
			printDemonstrationsTable(demonstrations, verbose)
		}
	},
}

// atomicValidateCmd validates atomic tests for safety
var atomicValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate atomic tests for bug bounty safety",
	Long: `Validate atomic tests against bug bounty safety criteria.

This command performs comprehensive safety validation of atomic tests to ensure they meet bug bounty testing requirements. It checks for destructive operations, elevation requirements, and compliance with safety guidelines.

Examples:
  shells atomic validate --technique T1552.001
  shells atomic validate --test-file /path/to/custom-test.yaml
  shells atomic validate --all`,
	Run: func(cmd *cobra.Command, args []string) {
		technique, _ := cmd.Flags().GetString("technique")
		testFile, _ := cmd.Flags().GetString("test-file")
		validateAll, _ := cmd.Flags().GetBool("all")
		output, _ := cmd.Flags().GetString("output")

		if technique == "" && testFile == "" && !validateAll {
			log.Info("Error: specify --technique, --test-file, or --all", "component", "atomic")
			os.Exit(1)
		}

		// Initialize atomic client
		config := atomic.Config{
			SafetyMode: true,
			DryRun:     true,
		}

		client, err := atomic.NewAtomicClient(config)
		if err != nil {
			fmt.Printf("Error initializing atomic client: %v\n", err)
			os.Exit(1)
		}

		if technique != "" {
			// Validate specific technique
			report, err := client.ValidateTestSafety(technique)
			if err != nil {
				fmt.Printf("Error validating technique %s: %v\n", technique, err)
				os.Exit(1)
			}

			if output == "json" {
				printSafetyReportJSON(*report)
			} else {
				printSafetyReportTable(*report)
			}
		} else if validateAll {
			// Validate all available techniques
			techniques := client.ListSafeTechniques()
			fmt.Printf(" Validating %d safe techniques...\n\n", len(techniques))

			passed := 0
			failed := 0

			for _, tech := range techniques {
				report, err := client.ValidateTestSafety(tech)
				if err != nil {
					fmt.Printf("❌ %s: Validation error - %v\n", tech, err)
					failed++
					continue
				}

				if report.IsSafe {
					fmt.Printf(" %s: Safe for bug bounty testing\n", tech)
					passed++
				} else {
					fmt.Printf("❌ %s: Failed safety validation\n", tech)
					for _, violation := range report.Violations {
						fmt.Printf("   - %s\n", violation)
					}
					failed++
				}
			}

			fmt.Printf("\n Validation Summary: %d passed, %d failed\n", passed, failed)
		}
	},
}

// atomicReportCmd generates ATT&CK reports from findings
var atomicReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate ATT&CK-mapped reports from findings",
	Long: `Generate comprehensive ATT&CK reports with technique mapping and Navigator layers.

This command creates detailed reports that map security findings to MITRE ATT&CK techniques, providing actionable intelligence and defensive recommendations. Reports can be generated in multiple formats including HTML and Navigator JSON.

Examples:
  shells atomic report --findings findings.json --output report.html
  shells atomic report --findings findings.json --navigator navigator.json
  shells atomic report --vuln-type SSRF --target https://example.com --format pdf`,
	Run: func(cmd *cobra.Command, args []string) {
		findingsFile, _ := cmd.Flags().GetString("findings")
		vulnType, _ := cmd.Flags().GetString("vuln-type")
		target, _ := cmd.Flags().GetString("target")
		outputFile, _ := cmd.Flags().GetString("output")
		navigatorFile, _ := cmd.Flags().GetString("navigator")
		format, _ := cmd.Flags().GetString("format")

		if findingsFile == "" && vulnType == "" {
			log.Info("Error: specify --findings file or --vuln-type", "component", "atomic")
			os.Exit(1)
		}

		var findings []atomic.Finding
		var demonstrations []atomic.Demonstration

		if findingsFile != "" {
			// Load findings from file
			var err error
			findings, err = loadFindingsFromFile(findingsFile)
			if err != nil {
				fmt.Printf("Error loading findings: %v\n", err)
				os.Exit(1)
			}
		} else {
			// Create finding from vulnerability type
			findings = []atomic.Finding{
				{
					ID:          "DEMO-001",
					Type:        vulnType,
					Severity:    "HIGH",
					Title:       fmt.Sprintf("%s Vulnerability", vulnType),
					Description: fmt.Sprintf("Demonstration of %s vulnerability impact", vulnType),
					Impact:      "Potential security compromise",
					Target:      target,
				},
			}
		}

		// Generate demonstrations for findings
		config := atomic.Config{
			SafetyMode: true,
			DryRun:     true,
		}

		client, err := atomic.NewAtomicClient(config)
		if err != nil {
			fmt.Printf("Error initializing client: %v\n", err)
			os.Exit(1)
		}

		for _, finding := range findings {
			targetObj := atomic.Target{URL: finding.Target, Type: "web"}

			// Get techniques for this vulnerability type
			mapper := atomic.NewVulnToAttackMapper()
			techniques := mapper.GetTechniques(finding.Type)

			for _, technique := range techniques {
				demo, err := client.DemonstrateImpact(technique, targetObj)
				if err != nil {
					fmt.Printf("Warning: Could not demonstrate %s for %s: %v\n", technique, finding.Type, err)
					continue
				}

				demonstration := atomic.Demonstration{
					Technique:   technique,
					Name:        demo.TestName,
					Description: mapper.GetDescription(technique),
					Result:      demo.Impact,
					Finding:     finding.Description,
					Severity:    demo.Severity,
					Evidence:    demo.Evidence,
					Duration:    demo.Duration,
				}
				demonstrations = append(demonstrations, demonstration)
			}
		}

		// Generate report
		reporter := atomic.NewBugBountyReporter()
		report := reporter.GenerateBugBountyReport(findings, demonstrations)

		// Save Navigator layer if requested
		if navigatorFile != "" {
			atomicReporter := atomic.NewAtomicReporter()
			err := atomicReporter.SaveNavigatorLayer(report.Navigator, navigatorFile)
			if err != nil {
				fmt.Printf("Error saving Navigator layer: %v\n", err)
			} else {
				fmt.Printf(" Navigator layer saved to: %s\n", navigatorFile)
			}
		}

		// Generate report in requested format
		if outputFile != "" {
			switch format {
			case "html":
				atomicReporter := atomic.NewAtomicReporter()
				err := atomicReporter.GenerateHTMLReport(&report.ATTACKReport, outputFile)
				if err != nil {
					fmt.Printf("Error generating HTML report: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("📄 HTML report saved to: %s\n", outputFile)
			case "json":
				data, err := json.MarshalIndent(report, "", "  ")
				if err != nil {
					fmt.Printf("Error marshaling report: %v\n", err)
					os.Exit(1)
				}
				err = os.WriteFile(outputFile, data, 0644)
				if err != nil {
					fmt.Printf("Error saving report: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("📄 JSON report saved to: %s\n", outputFile)
			default:
				fmt.Printf("Error: unsupported format %s (use html or json)\n", format)
				os.Exit(1)
			}
		} else {
			// Print summary to console
			printAtomicReportSummary(report)
		}
	},
}

// Helper functions

func filterTechniques(available []string, filter []string) []string {
	filterMap := make(map[string]bool)
	for _, t := range filter {
		filterMap[t] = true
	}

	var filtered []string
	for _, t := range available {
		if filterMap[t] {
			filtered = append(filtered, t)
		}
	}
	return filtered
}

func runTechniqueDemo(client *atomic.AtomicClient, technique string, target atomic.Target) (*atomic.Demonstration, error) {
	demo, err := client.DemonstrateImpact(technique, target)
	if err != nil {
		return nil, err
	}

	mapper := atomic.NewVulnToAttackMapper()

	return &atomic.Demonstration{
		Technique:   technique,
		Name:        demo.TestName,
		Description: mapper.GetDescription(technique),
		Result:      demo.Impact,
		Finding:     "Direct technique demonstration",
		Severity:    demo.Severity,
		Evidence:    demo.Evidence,
		Duration:    demo.Duration,
	}, nil
}

func runVulnerabilityDemo(client *atomic.AtomicClient, vulnType string, target atomic.Target) ([]atomic.Demonstration, error) {
	mapper := atomic.NewVulnToAttackMapper()
	techniques := mapper.GetTechniques(vulnType)

	var demonstrations []atomic.Demonstration

	for _, technique := range techniques {
		demo, err := runTechniqueDemo(client, technique, target)
		if err != nil {
			continue // Skip failed demonstrations
		}
		demo.Finding = fmt.Sprintf("%s vulnerability", vulnType)
		demonstrations = append(demonstrations, *demo)
	}

	return demonstrations, nil
}

func loadFindingsFromFile(filename string) ([]atomic.Finding, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var findings []atomic.Finding
	err = json.Unmarshal(data, &findings)
	return findings, err
}

// Output formatting functions

func printTechniquesJSON(techniques []string, client *atomic.AtomicClient) {
	mapper := atomic.NewVulnToAttackMapper()

	type TechniqueInfo struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		Tactic      string `json:"tactic"`
		Available   bool   `json:"available"`
	}

	var info []TechniqueInfo
	for _, technique := range techniques {
		_, err := client.GetSafeTest(technique)
		info = append(info, TechniqueInfo{
			ID:          technique,
			Description: mapper.GetDescription(technique),
			Tactic:      mapper.GetTactic(technique),
			Available:   err == nil,
		})
	}

	data, _ := json.MarshalIndent(info, "", "  ")
	fmt.Println(string(data))
}

func printTechniquesTable(techniques []string, client *atomic.AtomicClient, verbose bool) {
	mapper := atomic.NewVulnToAttackMapper()

	fmt.Printf("🎯 Available Safe ATT&CK Techniques (%d total)\n", len(techniques))
	fmt.Printf("═══════════════════════════════════════════════\n\n")

	for _, technique := range techniques {
		test, err := client.GetSafeTest(technique)
		status := " Available"
		if err != nil {
			status = "❌ Not Available"
		}

		fmt.Printf("🔹 %s - %s\n", technique, mapper.GetTactic(technique))
		fmt.Printf("   %s\n", status)

		if verbose && test != nil {
			fmt.Printf("   Name: %s\n", test.DisplayName)
			fmt.Printf("   Tests: %d\n", len(test.AtomicTests))
		}

		fmt.Printf("   %s\n\n", mapper.GetDescription(technique))
	}
}

func printDemonstrationsJSON(demonstrations []atomic.Demonstration) {
	data, _ := json.MarshalIndent(demonstrations, "", "  ")
	fmt.Println(string(data))
}

func printDemonstrationsTable(demonstrations []atomic.Demonstration, verbose bool) {
	fmt.Printf("🧪 Demonstration Results (%d techniques)\n", len(demonstrations))
	fmt.Printf("═══════════════════════════════════════════\n\n")

	for i, demo := range demonstrations {
		fmt.Printf("%d. %s (%s)\n", i+1, demo.Technique, demo.Name)
		fmt.Printf("   Severity: %s\n", demo.Severity)
		fmt.Printf("   Result: %s\n", demo.Result)
		fmt.Printf("   Duration: %s\n", demo.Duration)

		if verbose && len(demo.Evidence) > 0 {
			fmt.Printf("   Evidence:\n")
			for _, evidence := range demo.Evidence {
				fmt.Printf("     - %s: %s\n", evidence.Type, evidence.Description)
			}
		}
		fmt.Println()
	}
}

func printSafetyReportJSON(report atomic.SafetyReport) {
	data, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(data))
}

func printSafetyReportTable(report atomic.SafetyReport) {
	fmt.Printf(" Safety Validation Report\n")
	fmt.Printf("═══════════════════════════\n\n")

	fmt.Printf("Technique: %s\n", report.Technique)
	fmt.Printf("Test: %s\n", report.TestName)

	if report.IsSafe {
		fmt.Printf("Status:  SAFE for bug bounty testing\n\n")
	} else {
		fmt.Printf("Status: ❌ NOT SAFE for bug bounty testing\n\n")

		if len(report.Violations) > 0 {
			fmt.Printf("Violations:\n")
			for _, violation := range report.Violations {
				fmt.Printf("  ❌ %s\n", violation)
			}
			fmt.Println()
		}
	}

	if len(report.Warnings) > 0 {
		fmt.Printf("Warnings:\n")
		for _, warning := range report.Warnings {
			fmt.Printf("    %s\n", warning)
		}
		fmt.Println()
	}

	fmt.Printf("Safety Checks:\n")
	for _, check := range report.Checks {
		status := ""
		if !check.Passed {
			status = "❌"
		}
		fmt.Printf("  %s %s\n", status, check.RuleName)
		if check.Details != "" {
			fmt.Printf("     %s\n", check.Details)
		}
	}
}

func printAtomicReportSummary(report *atomic.BugBountyReport) {
	fmt.Printf(" ATT&CK Assessment Report Summary\n")
	fmt.Printf("═══════════════════════════════════\n\n")

	fmt.Printf("Target: %s\n", report.Metadata.Target)
	fmt.Printf("Generated: %s\n", report.Metadata.GeneratedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Total Techniques: %d\n", report.Metadata.TotalTechniques)
	fmt.Printf("High Risk Techniques: %d\n\n", report.Metadata.HighRiskTechniques)

	fmt.Printf("Executive Summary:\n%s\n\n", report.ExecutiveSummary)

	fmt.Printf("Impact Assessment:\n")
	fmt.Printf("  Overall Risk: %s\n", report.ImpactAssessment.OverallRisk)
	fmt.Printf("  Attack Complexity: %s\n", report.ImpactAssessment.AttackComplexity)
	fmt.Printf("  Exploitability Score: %.1f/10\n\n", report.ImpactAssessment.ExploitabilityScore)

	if len(report.RecommendedActions) > 0 {
		fmt.Printf("Top Priority Actions:\n")
		for i, action := range report.RecommendedActions {
			if i >= 3 { // Show only top 3
				break
			}
			fmt.Printf("  %d. [%s] %s (%s)\n", i+1, action.Priority, action.Action, action.Timeline)
		}
	}
}

func init() {
	// Add atomic command to root
	rootCmd.AddCommand(atomicCmd)

	// Add subcommands
	atomicCmd.AddCommand(atomicListCmd)
	atomicCmd.AddCommand(atomicDemoCmd)
	atomicCmd.AddCommand(atomicValidateCmd)
	atomicCmd.AddCommand(atomicReportCmd)

	// Global flags
	atomicCmd.PersistentFlags().StringP("output", "o", "text", "Output format (text, json)")
	atomicCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")

	// List command flags
	atomicListCmd.Flags().String("vuln-type", "", "Filter by vulnerability type")
	atomicListCmd.Flags().String("category", "", "Filter by technique category")
	atomicListCmd.Flags().String("tactic", "", "Filter by ATT&CK tactic")

	// Demo command flags
	atomicDemoCmd.Flags().String("vuln-type", "", "Vulnerability type to demonstrate")
	atomicDemoCmd.Flags().String("technique", "", "Specific ATT&CK technique to demonstrate")
	atomicDemoCmd.Flags().StringP("target", "t", "", "Target URL or system")
	atomicDemoCmd.Flags().Bool("dry-run", false, "Show what would be executed without running")
	atomicDemoCmd.Flags().Bool("sandbox", false, "Execute in Docker sandbox")

	// Validate command flags
	atomicValidateCmd.Flags().String("technique", "", "ATT&CK technique to validate")
	atomicValidateCmd.Flags().String("test-file", "", "Custom test file to validate")
	atomicValidateCmd.Flags().Bool("all", false, "Validate all available techniques")

	// Report command flags
	atomicReportCmd.Flags().String("findings", "", "JSON file containing security findings")
	atomicReportCmd.Flags().String("vuln-type", "", "Vulnerability type for demo report")
	atomicReportCmd.Flags().StringP("target", "t", "", "Target for demonstration")
	atomicReportCmd.Flags().String("navigator", "", "Save Navigator layer to file")
	atomicReportCmd.Flags().String("format", "html", "Report format (html, json)")
}
