package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/integrations/prowler"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/spf13/cobra"
)

var (
	awsProfile     string
	prowlerGroups  []string
	prowlerChecks  []string
	excludeGroups  []string
	excludeChecks  []string
	regions        []string
	services       []string
	severity       []string
	prowlerTimeout time.Duration
	nomadAddr      string
	dockerImage    string
	parallelJobs   int
	reportFormat   string
	reportFile     string
	navigatorFile  string
	htmlFile       string
	listFormat     string
	quiet          bool
)

// scanAWSCmd represents the AWS scanning command
var scanAWSCmd = &cobra.Command{
	Use:   "aws",
	Short: "Scan AWS infrastructure with Prowler",
	Long: `Scan AWS infrastructure using Prowler security scanner with Nomad-based execution.

Prowler is a comprehensive AWS security scanner that checks your AWS infrastructure
against security best practices and compliance frameworks like CIS, SOC2, and PCI-DSS.

This integration uses Nomad for containerized execution, providing isolation and
scalability for security assessments.

Examples:
  shells scan aws --profile production --groups iam,s3
  shells scan aws --checks iam_password_policy_minimum_length_14,s3_bucket_public_access_block
  shells scan aws --profile dev --regions us-east-1,us-west-2 --report-file aws-report.json
  shells scan aws --profile staging --services iam,s3,ec2 --html-file security-report.html`,
	RunE: runAWSScan,
}

// awsListCmd lists available Prowler checks and groups
var awsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available Prowler checks and groups",
	Long: `List all available Prowler checks, groups, and services.

This command helps you discover what security checks are available and how they're
organized into groups and services.`,
	Example: `  shells scan aws list
  shells scan aws list --format json
  shells scan aws list --groups
  shells scan aws list --services`,
	RunE: runAWSList,
}

// awsValidateCmd validates AWS credentials and connectivity
var awsValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate AWS credentials and Prowler setup",
	Long: `Validate AWS credentials, Nomad connectivity, and Prowler Docker image availability.

This command performs health checks to ensure everything is properly configured
before running security scans.`,
	RunE: runAWSValidate,
}

func init() {
	// Add aws command to scan
	scanCmd.AddCommand(scanAWSCmd)

	// Add subcommands
	scanAWSCmd.AddCommand(awsListCmd, awsValidateCmd)

	// Global AWS scanning flags
	scanAWSCmd.PersistentFlags().StringVar(&awsProfile, "profile", "", "AWS profile to use")
	scanAWSCmd.PersistentFlags().StringVar(&nomadAddr, "nomad-addr", "http://localhost:4646", "Nomad cluster address")
	scanAWSCmd.PersistentFlags().StringVar(&dockerImage, "docker-image", "toniblyx/prowler:latest", "Prowler Docker image")
	scanAWSCmd.PersistentFlags().DurationVar(&prowlerTimeout, "timeout", 30*time.Minute, "Scan timeout")
	scanAWSCmd.PersistentFlags().IntVar(&parallelJobs, "parallel-jobs", 5, "Number of parallel Nomad jobs")
	scanAWSCmd.PersistentFlags().BoolVar(&quiet, "quiet", false, "Quiet mode - minimal output")

	// Scan filtering flags
	scanAWSCmd.Flags().StringSliceVar(&prowlerGroups, "groups", []string{}, "Prowler check groups to include (e.g., iam,s3,ec2)")
	scanAWSCmd.Flags().StringSliceVar(&prowlerChecks, "checks", []string{}, "Specific Prowler checks to run")
	scanAWSCmd.Flags().StringSliceVar(&excludeGroups, "exclude-groups", []string{}, "Prowler check groups to exclude")
	scanAWSCmd.Flags().StringSliceVar(&excludeChecks, "exclude-checks", []string{}, "Specific Prowler checks to exclude")
	scanAWSCmd.Flags().StringSliceVar(&regions, "regions", []string{}, "AWS regions to scan (default: all available)")
	scanAWSCmd.Flags().StringSliceVar(&services, "services", []string{}, "AWS services to scan (default: all)")
	scanAWSCmd.Flags().StringSliceVar(&severity, "severity", []string{}, "Filter by severity (critical,high,medium,low)")

	// Output flags
	scanAWSCmd.Flags().StringVar(&reportFormat, "format", "json", "Output format (json, table)")
	scanAWSCmd.Flags().StringVar(&reportFile, "report-file", "", "Save detailed report to file")
	scanAWSCmd.Flags().StringVar(&navigatorFile, "navigator-file", "", "Save ATT&CK Navigator layer to file")
	scanAWSCmd.Flags().StringVar(&htmlFile, "html-file", "", "Save HTML report to file")

	// List command flags
	awsListCmd.Flags().StringVar(&listFormat, "format", "table", "Output format (table, json)")
	awsListCmd.Flags().Bool("groups", false, "List available check groups")
	awsListCmd.Flags().Bool("services", false, "List available AWS services")
	awsListCmd.Flags().Bool("checks", false, "List all individual checks")
}

func runAWSScan(cmd *cobra.Command, args []string) error {
	ctx := GetContext()
	_ = GetLogger() // Logger available if needed

	// Create Prowler configuration
	config := prowler.Config{
		NomadAddr:    nomadAddr,
		DockerImage:  dockerImage,
		Timeout:      prowlerTimeout,
		ParallelJobs: parallelJobs,
		AWSProfile:   awsProfile,
	}

	// Initialize Prowler client
	client, err := prowler.NewClient(config, log)
	if err != nil {
		return fmt.Errorf("failed to initialize Prowler client: %w", err)
	}

	if !quiet {
		fmt.Printf(" Starting AWS security scan with Prowler\n")
		fmt.Printf("Profile: %s\n", awsProfile)
		if len(prowlerGroups) > 0 {
			fmt.Printf("Groups: %s\n", strings.Join(prowlerGroups, ", "))
		}
		if len(prowlerChecks) > 0 {
			fmt.Printf("Checks: %s\n", strings.Join(prowlerChecks, ", "))
		}
		if len(regions) > 0 {
			fmt.Printf("Regions: %s\n", strings.Join(regions, ", "))
		}
		fmt.Println()
	}

	// Execute scan based on parameters
	var findings []types.Finding
	var scanErr error

	start := time.Now()

	if len(prowlerChecks) > 0 {
		// Run specific checks
		findings, scanErr = client.RunSpecificChecks(ctx, awsProfile, prowlerChecks)
	} else if len(prowlerGroups) > 0 {
		// Run by groups
		findings, scanErr = client.RunChecksByGroup(ctx, awsProfile, prowlerGroups)
	} else {
		// Run all checks
		findings, scanErr = client.RunAllChecks(ctx, awsProfile)
	}

	duration := time.Since(start)

	if scanErr != nil {
		return fmt.Errorf("scan failed: %w", scanErr)
	}

	// Filter results if needed
	findings = filterFindings(findings, severity)

	if !quiet {
		fmt.Printf(" Scan completed in %s\n", duration)
		fmt.Printf(" Found %d security findings\n\n", len(findings))
	}

	// Generate summary
	summary := generateScanSummary(findings, duration)

	// Output results
	switch reportFormat {
	case "json":
		return outputJSONResults(findings, summary, reportFile)
	case "table":
		return outputTableResults(findings, summary)
	default:
		return fmt.Errorf("unsupported format: %s", reportFormat)
	}
}

func runAWSList(cmd *cobra.Command, args []string) error {
	ctx := GetContext()

	config := prowler.Config{
		NomadAddr:   nomadAddr,
		DockerImage: dockerImage,
		Timeout:     5 * time.Minute,
	}

	client, err := prowler.NewClient(config, log)
	if err != nil {
		return fmt.Errorf("failed to initialize Prowler client: %w", err)
	}

	// Check what to list
	listGroups, _ := cmd.Flags().GetBool("groups")
	listServices, _ := cmd.Flags().GetBool("services")
	listChecks, _ := cmd.Flags().GetBool("checks")

	if !listGroups && !listServices && !listChecks {
		// Default: list available checks
		listChecks = true
	}

	if listChecks {
		checks, err := client.GetAvailableChecks(ctx)
		if err != nil {
			return fmt.Errorf("failed to get available checks: %w", err)
		}

		return displayChecks(checks, listFormat)
	}

	if listGroups {
		return displayCheckGroups(listFormat)
	}

	if listServices {
		return displayServices(listFormat)
	}

	return nil
}

func runAWSValidate(cmd *cobra.Command, args []string) error {
	ctx := GetContext()

	config := prowler.Config{
		NomadAddr:   nomadAddr,
		DockerImage: dockerImage,
		Timeout:     2 * time.Minute,
	}

	client, err := prowler.NewClient(config, log)
	if err != nil {
		return fmt.Errorf("failed to initialize Prowler client: %w", err)
	}

	fmt.Printf(" Validating AWS security scan setup...\n\n")

	// Check Nomad connectivity
	fmt.Printf("Checking Nomad connectivity (%s)... ", nomadAddr)
	if err := client.Health(ctx); err != nil {
		fmt.Printf("❌ Failed\n")
		return fmt.Errorf("Nomad health check failed: %w", err)
	}
	fmt.Printf(" OK\n")

	// Check Docker image availability
	fmt.Printf("Checking Prowler Docker image (%s)... ", dockerImage)
	// This is checked as part of health check
	fmt.Printf(" OK\n")

	// Check AWS credentials (if profile specified)
	if awsProfile != "" {
		fmt.Printf("Checking AWS credentials (profile: %s)... ", awsProfile)

		// Set AWS profile environment variable
		if err := os.Setenv("AWS_PROFILE", awsProfile); err != nil {
			return fmt.Errorf("failed to set AWS_PROFILE environment variable: %w", err)
		}

		// Test AWS credentials by calling STS GetCallerIdentity
		cmd := exec.Command("aws", "sts", "get-caller-identity", "--profile", awsProfile)
		output, err := cmd.CombinedOutput()

		if err != nil {
			fmt.Printf("❌ Failed\n")
			fmt.Printf("   Error: %v\n", err)
			if len(output) > 0 {
				fmt.Printf("   Output: %s\n", string(output))
			}
			fmt.Printf("   Ensure AWS credentials are configured for profile '%s'\n", awsProfile)
			return fmt.Errorf("AWS credential validation failed")
		}

		fmt.Printf(" Valid\n")

		// Parse and display account info
		var accountInfo struct {
			UserId  string `json:"UserId"`
			Account string `json:"Account"`
			Arn     string `json:"Arn"`
		}
		if err := json.Unmarshal(output, &accountInfo); err == nil {
			fmt.Printf("   Account: %s\n", accountInfo.Account)
			fmt.Printf("   User ARN: %s\n", accountInfo.Arn)
		}
	}

	fmt.Printf("\n Setup validation completed successfully!\n")
	fmt.Printf("Ready to run AWS security scans.\n")

	return nil
}

// Helper functions

func filterFindings(findings []types.Finding, severityFilter []string) []types.Finding {
	if len(severityFilter) == 0 {
		return findings
	}

	severitySet := make(map[string]bool)
	for _, sev := range severityFilter {
		severitySet[strings.ToUpper(sev)] = true
	}

	var filtered []types.Finding
	for _, finding := range findings {
		if severitySet[strings.ToUpper(string(finding.Severity))] {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

func generateScanSummary(findings []types.Finding, duration time.Duration) AWSScanSummary {
	summary := AWSScanSummary{
		TotalFindings: len(findings),
		Duration:      duration,
		ByService:     make(map[string]int),
		BySeverity:    make(map[string]int),
	}

	for _, finding := range findings {
		// Count by severity
		summary.BySeverity[string(finding.Severity)]++

		// Count by service (extract from metadata)
		if service, ok := finding.Metadata["service"].(string); ok {
			summary.ByService[service]++
		}
	}

	return summary
}

type AWSScanSummary struct {
	TotalFindings int            `json:"total_findings"`
	Duration      time.Duration  `json:"duration"`
	ByService     map[string]int `json:"by_service"`
	BySeverity    map[string]int `json:"by_severity"`
}

func outputJSONResults(findings []types.Finding, summary AWSScanSummary, filename string) error {
	result := map[string]interface{}{
		"summary":  summary,
		"findings": findings,
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	if filename != "" {
		if err := os.WriteFile(filename, data, 0644); err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		fmt.Printf("📄 Results saved to: %s\n", filename)
	} else {
		fmt.Println(string(data))
	}

	return nil
}

func outputTableResults(findings []types.Finding, summary AWSScanSummary) error {
	// Display summary
	fmt.Printf(" Scan Summary\n")
	fmt.Printf("═══════════════\n")
	fmt.Printf("Total Findings: %d\n", summary.TotalFindings)
	fmt.Printf("Duration: %s\n\n", summary.Duration)

	// Severity breakdown
	if len(summary.BySeverity) > 0 {
		fmt.Printf("By Severity:\n")
		for severity, count := range summary.BySeverity {
			fmt.Printf("  %s: %d\n", severity, count)
		}
		fmt.Println()
	}

	// Service breakdown
	if len(summary.ByService) > 0 {
		fmt.Printf("By Service:\n")
		for service, count := range summary.ByService {
			fmt.Printf("  %s: %d\n", service, count)
		}
		fmt.Println()
	}

	// Display findings
	if len(findings) > 0 {
		fmt.Printf(" Security Findings\n")
		fmt.Printf("══════════════════\n\n")

		for i, finding := range findings {
			severityIcon := getAWSSeverityIcon(string(finding.Severity))
			fmt.Printf("%d. %s %s [%s]\n", i+1, severityIcon, finding.Title, finding.Severity)
			fmt.Printf("   %s\n", finding.Description)

			if service, ok := finding.Metadata["service"].(string); ok {
				fmt.Printf("   Service: %s\n", service)
			}

			fmt.Println()
		}
	}

	return nil
}

func getAWSSeverityIcon(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "🔴"
	case "HIGH":
		return "🟠"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🟢"
	default:
		return "ℹ️"
	}
}

func displayChecks(checks []prowler.Check, format string) error {
	switch format {
	case "json":
		data, err := json.MarshalIndent(checks, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	case "table":
		fmt.Printf("📋 Available Prowler Checks (%d total)\n", len(checks))
		fmt.Printf("═══════════════════════════════════\n\n")

		for _, check := range checks {
			fmt.Printf("🔹 %s\n", check.ID)
			fmt.Printf("   Service: %s | Severity: %s\n", check.Service, check.Severity)
			fmt.Printf("   %s\n\n", check.Description)
		}
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	return nil
}

func displayCheckGroups(format string) error {
	groups := prowler.DefaultCheckGroups

	switch format {
	case "json":
		data, err := json.MarshalIndent(groups, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	case "table":
		fmt.Printf("📂 Available Check Groups\n")
		fmt.Printf("═════════════════════════\n\n")

		for groupName, checks := range groups {
			fmt.Printf("🔸 %s (%d checks)\n", groupName, len(checks))
			for _, check := range checks {
				fmt.Printf("   - %s\n", check)
			}
			fmt.Println()
		}
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	return nil
}

func displayServices(format string) error {
	services := []string{
		"iam", "s3", "ec2", "vpc", "cloudtrail", "cloudwatch",
		"config", "kms", "lambda", "rds", "redshift", "elasticache",
		"efs", "fsx", "route53", "cloudfront", "elb", "elbv2",
		"autoscaling", "ecs", "eks", "emr", "sagemaker", "glue",
	}

	switch format {
	case "json":
		result := map[string]interface{}{
			"services": services,
			"total":    len(services),
		}
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	case "table":
		fmt.Printf("  Available AWS Services (%d total)\n", len(services))
		fmt.Printf("══════════════════════════════════\n\n")

		for i, service := range services {
			fmt.Printf("%d. %s\n", i+1, service)
		}
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	return nil
}
