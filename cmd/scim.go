package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/scim"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/spf13/cobra"
)

var scimCmd = &cobra.Command{
	Use:   "scim",
	Short: "Test SCIM implementations for vulnerabilities",
	Long: `SCIM (System for Cross-domain Identity Management) vulnerability scanner.

This command provides comprehensive testing for SCIM implementations including:
- Endpoint discovery
- Authentication bypass testing
- Filter injection vulnerabilities
- Bulk operation abuse
- User enumeration
- Privilege escalation via provisioning
- Schema information disclosure

Examples:
  shells scim discover https://example.com --auth-token "Bearer xyz"
  shells scim test https://example.com/scim/v2 --test-all
  shells scim test https://example.com/scim/v2 --test-filters --test-auth
  shells scim provision https://example.com/scim/v2/Users --dry-run`,
}

var scimDiscoverCmd = &cobra.Command{
	Use:   "discover [target]",
	Short: "Discover SCIM endpoints",
	Long: `Discover SCIM endpoints at the target URL.

This command attempts to discover SCIM endpoints by:
- Checking well-known SCIM paths
- Testing for ServiceProviderConfig endpoints
- Identifying available resources (Users, Groups, etc.)
- Analyzing supported operations and schemas

Examples:
  shells scim discover https://example.com
  shells scim discover https://example.com --auth-token "Bearer xyz"
  shells scim discover https://example.com --auth-type basic --username admin --password secret`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]

		// Get flags
		authToken, _ := cmd.Flags().GetString("auth-token")
		authType, _ := cmd.Flags().GetString("auth-type")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		timeout, _ := cmd.Flags().GetString("timeout")
		output, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")

		// Build options
		options := map[string]string{
			"auth-token": authToken,
			"auth-type":  authType,
			"username":   username,
			"password":   password,
			"timeout":    timeout,
		}

		// Create scanner
		scanner := scim.NewScanner()

		// Run discovery with shorter timeout
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		findings, err := scanner.Scan(ctx, target, options)
		if err != nil {
			if strings.Contains(err.Error(), "context deadline exceeded") {
				fmt.Printf("⚠️  SCIM discovery timed out, performing basic endpoint check\n")
				performBasicSCIMCheck(target)
				return
			}
			fmt.Printf("Error during SCIM discovery: %v\n", err)
			os.Exit(1)
		}

		// Output results
		if output != "" {
			outputFindings(findings, output, "json")
		} else {
			printSCIMDiscoveryResults(findings, verbose)
		}
	},
}

var scimTestCmd = &cobra.Command{
	Use:   "test [target]",
	Short: "Test SCIM endpoint for vulnerabilities",
	Long: `Test a SCIM endpoint for security vulnerabilities.

This command performs comprehensive security testing including:
- Authentication bypass attempts
- Filter injection testing
- Bulk operation abuse detection
- User enumeration vulnerabilities
- Privilege escalation testing
- Schema information disclosure

Examples:
  shells scim test https://example.com/scim/v2
  shells scim test https://example.com/scim/v2 --auth-token "Bearer xyz"
  shells scim test https://example.com/scim/v2 --test-filters --test-bulk
  shells scim test https://example.com/scim/v2 --test-all --output results.json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]

		// Get flags
		authToken, _ := cmd.Flags().GetString("auth-token")
		authType, _ := cmd.Flags().GetString("auth-type")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		timeout, _ := cmd.Flags().GetString("timeout")
		testAll, _ := cmd.Flags().GetBool("test-all")
		testAuth, _ := cmd.Flags().GetBool("test-auth")
		testFilters, _ := cmd.Flags().GetBool("test-filters")
		testBulk, _ := cmd.Flags().GetBool("test-bulk")
		testProvision, _ := cmd.Flags().GetBool("test-provision")
		output, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")

		// Build options
		options := map[string]string{
			"auth-token": authToken,
			"auth-type":  authType,
			"username":   username,
			"password":   password,
			"timeout":    timeout,
		}

		// Set test options
		if testAll {
			options["test-auth"] = "true"
			options["test-filters"] = "true"
			options["test-bulk"] = "true"
			options["test-provision"] = "true"
		} else {
			if testAuth {
				options["test-auth"] = "true"
			}
			if testFilters {
				options["test-filters"] = "true"
			}
			if testBulk {
				options["test-bulk"] = "true"
			}
			if testProvision {
				options["test-provision"] = "true"
			}
		}

		// Create scanner
		scanner := scim.NewScanner()

		// Run tests
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		findings, err := scanner.Scan(ctx, target, options)
		if err != nil {
			fmt.Printf("Error during SCIM testing: %v\n", err)
			os.Exit(1)
		}

		// Output results
		if output != "" {
			outputFindings(findings, output, "json")
		} else {
			printSCIMTestResults(findings, verbose)
		}
	},
}

var scimProvisionCmd = &cobra.Command{
	Use:   "provision [target]",
	Short: "Test SCIM provisioning for abuse",
	Long: `Test SCIM provisioning endpoints for abuse and privilege escalation.

This command specifically tests:
- Privilege escalation through user provisioning
- Administrative group assignment
- Bulk provisioning abuse
- Unauthorized resource creation

Examples:
  shells scim provision https://example.com/scim/v2/Users --dry-run
  shells scim provision https://example.com/scim/v2/Users --auth-token "Bearer xyz"
  shells scim provision https://example.com/scim/v2/Users --test-privesc`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]

		// Get flags
		authToken, _ := cmd.Flags().GetString("auth-token")
		authType, _ := cmd.Flags().GetString("auth-type")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		testPrivesc, _ := cmd.Flags().GetBool("test-privesc")
		output, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")

		// Build options
		options := map[string]string{
			"auth-token":     authToken,
			"auth-type":      authType,
			"username":       username,
			"password":       password,
			"test-provision": "true",
		}

		if dryRun {
			options["dry-run"] = "true"
		}
		if testPrivesc {
			options["test-privesc"] = "true"
		}

		// Create scanner
		scanner := scim.NewScanner()

		// Run provisioning tests
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		findings, err := scanner.Scan(ctx, target, options)
		if err != nil {
			fmt.Printf("Error during SCIM provisioning test: %v\n", err)
			os.Exit(1)
		}

		// Output results
		if output != "" {
			outputFindings(findings, output, "json")
		} else {
			printSCIMProvisionResults(findings, verbose)
		}
	},
}

func init() {
	rootCmd.AddCommand(scimCmd)

	// Add subcommands
	scimCmd.AddCommand(scimDiscoverCmd)
	scimCmd.AddCommand(scimTestCmd)
	scimCmd.AddCommand(scimProvisionCmd)

	// Global flags
	scimCmd.PersistentFlags().String("auth-token", "", "Bearer token for authentication")
	scimCmd.PersistentFlags().String("auth-type", "bearer", "Authentication type (bearer, basic, oauth)")
	scimCmd.PersistentFlags().String("username", "", "Username for basic authentication")
	scimCmd.PersistentFlags().String("password", "", "Password for basic authentication")
	scimCmd.PersistentFlags().String("timeout", "30s", "Request timeout")
	scimCmd.PersistentFlags().String("output", "", "Output file for results")
	scimCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")

	// Test command flags
	scimTestCmd.Flags().Bool("test-all", false, "Run all tests")
	scimTestCmd.Flags().Bool("test-auth", false, "Test authentication vulnerabilities")
	scimTestCmd.Flags().Bool("test-filters", false, "Test filter injection")
	scimTestCmd.Flags().Bool("test-bulk", false, "Test bulk operations")
	scimTestCmd.Flags().Bool("test-provision", false, "Test provisioning abuse")

	// Provision command flags
	scimProvisionCmd.Flags().Bool("dry-run", false, "Perform dry run without actual provisioning")
	scimProvisionCmd.Flags().Bool("test-privesc", false, "Test privilege escalation")
}

// printSCIMDiscoveryResults prints SCIM discovery results
func printSCIMDiscoveryResults(findings []types.Finding, verbose bool) {
	fmt.Printf("📊 SCIM Discovery Results\n")
	fmt.Printf("═══════════════════════════════════\n\n")

	if len(findings) == 0 {
		fmt.Printf("No SCIM endpoints discovered\n")
		return
	}

	for _, finding := range findings {
		fmt.Printf("🔍 %s\n", finding.Title)
		fmt.Printf("   Severity: %s\n", finding.Severity)
		fmt.Printf("   Description: %s\n", finding.Description)

		if verbose {
			fmt.Printf("   Evidence: %s\n", finding.Evidence)
		}

		fmt.Printf("\n")
	}
}

// printSCIMTestResults prints SCIM test results
func printSCIMTestResults(findings []types.Finding, verbose bool) {
	fmt.Printf("🔒 SCIM Security Test Results\n")
	fmt.Printf("═══════════════════════════════════\n\n")

	if len(findings) == 0 {
		fmt.Printf("✅ No SCIM vulnerabilities found\n")
		return
	}

	// Group findings by severity
	severityGroups := make(map[types.Severity][]types.Finding)
	for _, finding := range findings {
		severityGroups[finding.Severity] = append(severityGroups[finding.Severity], finding)
	}

	// Print results by severity
	severityOrder := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}

	for _, severity := range severityOrder {
		if findings, exists := severityGroups[severity]; exists {
			fmt.Printf("🚨 %s Severity (%d findings)\n", severity, len(findings))
			fmt.Printf("─────────────────────────────────\n")

			for _, finding := range findings {
				fmt.Printf("• %s\n", finding.Title)
				fmt.Printf("  Type: %s\n", finding.Type)
				fmt.Printf("  Description: %s\n", finding.Description)

				if verbose {
					fmt.Printf("  Evidence: %s\n", finding.Evidence)
					fmt.Printf("  Solution: %s\n", finding.Solution)
				}

				fmt.Printf("\n")
			}
		}
	}

	fmt.Printf("📊 Summary: %d vulnerabilities found\n", len(findings))
}

// printSCIMProvisionResults prints SCIM provisioning results
func printSCIMProvisionResults(findings []types.Finding, verbose bool) {
	fmt.Printf("👤 SCIM Provisioning Test Results\n")
	fmt.Printf("═══════════════════════════════════\n\n")

	if len(findings) == 0 {
		fmt.Printf("✅ No provisioning vulnerabilities found\n")
		return
	}

	for _, finding := range findings {
		fmt.Printf("⚠️  %s\n", finding.Title)
		fmt.Printf("   Severity: %s\n", finding.Severity)
		fmt.Printf("   Type: %s\n", finding.Type)
		fmt.Printf("   Description: %s\n", finding.Description)

		if verbose {
			fmt.Printf("   Evidence: %s\n", finding.Evidence)
			fmt.Printf("   Solution: %s\n", finding.Solution)
		}

		fmt.Printf("\n")
	}
}

// outputFindings outputs findings to a file
func outputFindings(findings []types.Finding, filename, format string) {
	var data []byte
	var err error

	switch format {
	case "json":
		data, err = json.MarshalIndent(findings, "", "  ")
	default:
		data, err = json.MarshalIndent(findings, "", "  ")
	}

	if err != nil {
		fmt.Printf("Error marshaling findings: %v\n", err)
		return
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}

	fmt.Printf("Results written to %s\n", filename)
}

// performBasicSCIMCheck performs a basic SCIM endpoint check
func performBasicSCIMCheck(target string) {
	fmt.Printf("🔍 Basic SCIM Endpoint Discovery for %s\n", target)
	fmt.Printf("═══════════════════════════════════\n\n")

	scimPaths := []string{"/scim/v2", "/scim", "/api/scim/v2", "/api/scim"}
	client := &http.Client{Timeout: 5 * time.Second}

	found := false
	for _, path := range scimPaths {
		url := strings.TrimRight(target, "/") + path
		resp, err := client.Head(url)
		if err != nil {
			continue
		}
		httpclient.CloseBody(resp)

		if resp.StatusCode < 500 {
			fmt.Printf("✅ SCIM endpoint found: %s [%d]\n", path, resp.StatusCode)
			found = true
		}
	}

	if !found {
		fmt.Printf("❌ No SCIM endpoints discovered\n")
	}

	fmt.Printf("\n📊 Summary: Basic SCIM endpoint check completed\n")
}
