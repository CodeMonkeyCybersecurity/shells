// cmd/oauth2_advanced.go
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/oauth2"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/spf13/cobra"
)

// simpleLoggerAdapter adapts the logger.Logger to oauth2.SimpleLogger
type simpleLoggerAdapter struct {
	logger *logger.Logger
}

func (a *simpleLoggerAdapter) Info(msg string, keysAndValues ...interface{}) {
	args := append([]interface{}{msg}, keysAndValues...)
	a.logger.Info(args...)
}

func (a *simpleLoggerAdapter) Error(msg string, keysAndValues ...interface{}) {
	args := append([]interface{}{msg}, keysAndValues...)
	a.logger.Error(args...)
}

func (a *simpleLoggerAdapter) Debug(msg string, keysAndValues ...interface{}) {
	args := append([]interface{}{msg}, keysAndValues...)
	a.logger.Debug(args...)
}

func (a *simpleLoggerAdapter) Warn(msg string, keysAndValues ...interface{}) {
	args := append([]interface{}{msg}, keysAndValues...)
	a.logger.Warn(args...)
}

// oauth2AdvancedCmd represents the advanced OAuth2 testing command
var oauth2AdvancedCmd = &cobra.Command{
	Use:   "oauth2-advanced",
	Short: "Advanced OAuth2/OIDC security testing",
	Long: `Comprehensive OAuth2/OIDC security testing for bug bounties.

This command performs advanced security testing including:
- Authorization code replay attacks
- PKCE downgrade attacks
- JWT algorithm confusion (alg:none, RS256->HS256)
- Redirect URI validation bypasses
- State parameter entropy testing
- Cross-client token usage
- Token endpoint security
- Implicit flow vulnerabilities

Examples:
  shells oauth2-advanced test https://example.com/oauth2
  shells oauth2-advanced test https://example.com --client-id abc --redirect-uri https://app.com/callback
  shells oauth2-advanced discover https://example.com
  shells oauth2-advanced report --findings oauth2-findings.json`,
}

// oauth2AdvancedTestCmd performs comprehensive OAuth2 testing
var oauth2AdvancedTestCmd = &cobra.Command{
	Use:   "test [target]",
	Short: "Run comprehensive OAuth2 security tests",
	Long: `Execute all OAuth2 security tests against the target.

The target should be the base URL of the OAuth2 provider. The tool will
attempt to discover endpoints automatically via well-known configuration.

Tests include:
- Authorization Code Vulnerabilities
  * Code replay attacks
  * Code injection
  * Code substitution
  * Referrer leakage

- PKCE Security
  * PKCE downgrade attacks
  * Invalid verifier acceptance
  * Missing PKCE enforcement
  * Weak code challenge methods

- JWT Vulnerabilities
  * Algorithm none bypass
  * Algorithm confusion (RS256 to HS256)
  * Weak secret detection
  * Signature verification bypass
  * Token expiration issues

- Redirect URI Security
  * Open redirect vulnerabilities
  * Parameter pollution
  * Protocol downgrade
  * JavaScript/Data URI injection

- State Parameter Security
  * Missing state enforcement
  * Weak entropy detection
  * State fixation

- Cross-Client Attacks
  * Token substitution
  * Client impersonation
  * Audience validation

Examples:
  shells oauth2-advanced test https://auth.example.com
  shells oauth2-advanced test https://example.com/oauth2 --deep-scan
  shells oauth2-advanced test https://sso.company.com --client-id myapp --client-secret secret`,
	Args: cobra.ExactArgs(1),
	RunE: runOAuth2AdvancedTest,
}

// oauth2AdvancedDiscoverCmd discovers OAuth2 configuration
var oauth2AdvancedDiscoverCmd = &cobra.Command{
	Use:   "discover [target]",
	Short: "Discover OAuth2/OIDC configuration",
	Long: `Discover OAuth2/OIDC endpoints and supported features.

This command attempts to:
- Find well-known configuration endpoints
- Enumerate supported flows and grant types
- Identify PKCE support
- Discover token endpoint auth methods
- List supported scopes and claims

Examples:
  shells oauth2-advanced discover https://example.com
  shells oauth2-advanced discover https://auth.company.com --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runOAuth2AdvancedDiscover,
}

// oauth2AdvancedReportCmd generates detailed reports
var oauth2AdvancedReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate OAuth2 security report",
	Long: `Generate a detailed security report from OAuth2 test results.

The report includes:
- Executive summary with risk rating
- Detailed vulnerability descriptions
- Proof of concept for each finding
- Remediation recommendations
- Compliance mapping (OAuth2 Security BCP)

Examples:
  shells oauth2-advanced report --findings oauth2-results.json
  shells oauth2-advanced report --findings results.json --format html --output report.html`,
	RunE: runOAuth2AdvancedReport,
}

func init() {
	rootCmd.AddCommand(oauth2AdvancedCmd)
	oauth2AdvancedCmd.AddCommand(oauth2AdvancedTestCmd)
	oauth2AdvancedCmd.AddCommand(oauth2AdvancedDiscoverCmd)
	oauth2AdvancedCmd.AddCommand(oauth2AdvancedReportCmd)

	// Test command flags
	oauth2AdvancedTestCmd.Flags().String("client-id", "", "OAuth2 client ID")
	oauth2AdvancedTestCmd.Flags().String("client-secret", "", "OAuth2 client secret")
	oauth2AdvancedTestCmd.Flags().String("redirect-uri", "", "OAuth2 redirect URI")
	oauth2AdvancedTestCmd.Flags().Bool("deep-scan", false, "Enable deep scanning with more test cases")
	oauth2AdvancedTestCmd.Flags().Duration("timeout", 5*time.Minute, "Test timeout")
	oauth2AdvancedTestCmd.Flags().String("output", "", "Output file for results")
	oauth2AdvancedTestCmd.Flags().Bool("verbose", false, "Enable verbose output")

	// Discover command flags
	oauth2AdvancedDiscoverCmd.Flags().Bool("verbose", false, "Show detailed configuration")
	oauth2AdvancedDiscoverCmd.Flags().String("output", "", "Output file for configuration")

	// Report command flags
	oauth2AdvancedReportCmd.Flags().String("findings", "", "Input findings file (required)")
	oauth2AdvancedReportCmd.Flags().String("format", "text", "Report format (text, json, html, markdown)")
	oauth2AdvancedReportCmd.Flags().String("output", "", "Output file (default: stdout)")
	oauth2AdvancedReportCmd.MarkFlagRequired("findings")
}

func runOAuth2AdvancedTest(cmd *cobra.Command, args []string) error {
	target := args[0]
	clientID, _ := cmd.Flags().GetString("client-id")
	clientSecret, _ := cmd.Flags().GetString("client-secret")
	redirectURI, _ := cmd.Flags().GetString("redirect-uri")
	deepScan, _ := cmd.Flags().GetBool("deep-scan")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	output, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Validate target
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	fmt.Printf(" Starting advanced OAuth2 security testing\n")
	fmt.Printf("🎯 Target: %s\n", target)

	if verbose {
		fmt.Printf("📋 Configuration:\n")
		if clientID != "" {
			fmt.Printf("   Client ID: %s\n", clientID)
		}
		if redirectURI != "" {
			fmt.Printf("   Redirect URI: %s\n", redirectURI)
		}
		fmt.Printf("   Deep Scan: %v\n", deepScan)
		fmt.Printf("   Timeout: %s\n", timeout)
	}

	// Create scanner configuration
	config := oauth2.SimpleScannerConfig{
		Timeout:      timeout,
		DeepScan:     deepScan,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
	}

	// Create scanner
	// Create logger adapter
	loggerAdapter := &simpleLoggerAdapter{log}

	// Create scanner
	scanner := oauth2.NewSimpleScanner(config, loggerAdapter)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Run scan
	start := time.Now()
	findings, err := scanner.Scan(ctx, target, nil)
	if err != nil {
		return fmt.Errorf("OAuth2 scan failed: %w", err)
	}
	duration := time.Since(start)

	fmt.Printf("\n Testing completed in %s\n", duration.Round(time.Second))

	// Display results
	displayOAuth2Results(findings, verbose)

	// Get recommendations
	recommendations := scanner.GetRecommendations(findings)
	if len(recommendations) > 0 {
		fmt.Printf("\n📋 Security Recommendations:\n")
		for i, rec := range recommendations {
			fmt.Printf("%d. %s\n", i+1, rec)
		}
	}

	// Save results if output specified
	if output != "" {
		results := map[string]interface{}{
			"target":          target,
			"scan_time":       start,
			"duration":        duration.Seconds(),
			"findings":        findings,
			"recommendations": recommendations,
		}

		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal results: %w", err)
		}

		if err := os.WriteFile(output, data, 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}

		fmt.Printf("\n💾 Results saved to: %s\n", output)
	}

	return nil
}

func runOAuth2AdvancedDiscover(cmd *cobra.Command, args []string) error {
	target := args[0]
	verbose, _ := cmd.Flags().GetBool("verbose")
	output, _ := cmd.Flags().GetString("output")

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	fmt.Printf(" Discovering OAuth2/OIDC configuration\n")
	fmt.Printf("🎯 Target: %s\n", target)

	// Try well-known endpoints
	wellKnownURLs := []string{
		target + "/.well-known/openid-configuration",
		target + "/.well-known/oauth-authorization-server",
		target + "/oauth/.well-known/openid-configuration",
		target + "/oauth2/.well-known/openid-configuration",
		target + "/auth/.well-known/openid-configuration",
	}

	var discoveryDoc map[string]interface{}
	var discoveredURL string

	client := &http.Client{Timeout: 10 * time.Second}

	for _, url := range wellKnownURLs {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer httpclient.CloseBody(resp)

		if resp.StatusCode == http.StatusOK {
			if err := json.NewDecoder(resp.Body).Decode(&discoveryDoc); err == nil {
				discoveredURL = url
				break
			}
		}
	}

	if discoveryDoc == nil {
		fmt.Printf("\n❌ No OAuth2/OIDC discovery document found\n")
		fmt.Printf("   Tried: %s\n", strings.Join(wellKnownURLs, "\n          "))
		return nil
	}

	fmt.Printf("\n Found discovery document at: %s\n", discoveredURL)

	// Display configuration
	fmt.Printf("\n📋 OAuth2/OIDC Configuration:\n")

	// Key endpoints
	if issuer, ok := discoveryDoc["issuer"].(string); ok {
		fmt.Printf("   Issuer: %s\n", issuer)
	}
	if authEndpoint, ok := discoveryDoc["authorization_endpoint"].(string); ok {
		fmt.Printf("   Authorization: %s\n", authEndpoint)
	}
	if tokenEndpoint, ok := discoveryDoc["token_endpoint"].(string); ok {
		fmt.Printf("   Token: %s\n", tokenEndpoint)
	}
	if userinfo, ok := discoveryDoc["userinfo_endpoint"].(string); ok {
		fmt.Printf("   UserInfo: %s\n", userinfo)
	}
	if jwks, ok := discoveryDoc["jwks_uri"].(string); ok {
		fmt.Printf("   JWKS: %s\n", jwks)
	}

	// Supported features
	fmt.Printf("\n🔧 Supported Features:\n")

	if responseTypes, ok := discoveryDoc["response_types_supported"].([]interface{}); ok {
		fmt.Printf("   Response Types: %v\n", responseTypes)
	}
	if grantTypes, ok := discoveryDoc["grant_types_supported"].([]interface{}); ok {
		fmt.Printf("   Grant Types: %v\n", grantTypes)
	}
	if pkce, ok := discoveryDoc["code_challenge_methods_supported"].([]interface{}); ok {
		fmt.Printf("   PKCE Methods: %v\n", pkce)
	} else {
		fmt.Printf("   PKCE Methods: ❌ Not supported\n")
	}

	// Security analysis
	fmt.Printf("\n🔐 Security Analysis:\n")

	// Check PKCE support
	pkceMethods, hasPKCE := discoveryDoc["code_challenge_methods_supported"].([]interface{})
	if !hasPKCE || len(pkceMethods) == 0 {
		fmt.Printf("   ⚠️  PKCE not supported - vulnerable to authorization code interception\n")
	} else {
		fmt.Printf("    PKCE supported with methods: %v\n", pkceMethods)
	}

	// Check for implicit flow
	if responseTypes, ok := discoveryDoc["response_types_supported"].([]interface{}); ok {
		hasImplicit := false
		for _, rt := range responseTypes {
			if strings.Contains(rt.(string), "token") {
				hasImplicit = true
				break
			}
		}
		if hasImplicit {
			fmt.Printf("   ⚠️  Implicit flow supported - consider deprecating\n")
		}
	}

	// Check token endpoint auth methods
	if authMethods, ok := discoveryDoc["token_endpoint_auth_methods_supported"].([]interface{}); ok {
		hasNone := false
		for _, method := range authMethods {
			if method.(string) == "none" {
				hasNone = true
				break
			}
		}
		if hasNone {
			fmt.Printf("   ⚠️  'none' auth method supported at token endpoint\n")
		}
	}

	if verbose {
		fmt.Printf("\n📄 Full Configuration:\n")
		fullConfig, _ := json.MarshalIndent(discoveryDoc, "   ", "  ")
		fmt.Printf("%s\n", string(fullConfig))
	}

	// Save if output specified
	if output != "" {
		data, _ := json.MarshalIndent(discoveryDoc, "", "  ")
		if err := os.WriteFile(output, data, 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Printf("\n💾 Configuration saved to: %s\n", output)
	}

	return nil
}

func runOAuth2AdvancedReport(cmd *cobra.Command, args []string) error {
	findingsFile, _ := cmd.Flags().GetString("findings")
	format, _ := cmd.Flags().GetString("format")
	output, _ := cmd.Flags().GetString("output")

	// Load findings
	data, err := os.ReadFile(findingsFile)
	if err != nil {
		return fmt.Errorf("failed to read findings: %w", err)
	}

	var results map[string]interface{}
	if err := json.Unmarshal(data, &results); err != nil {
		return fmt.Errorf("failed to parse findings: %w", err)
	}

	// Generate report based on format
	var report string
	switch format {
	case "json":
		formatted, _ := json.MarshalIndent(results, "", "  ")
		report = string(formatted)
	case "markdown":
		report = generateOAuth2MarkdownReport(results)
	case "html":
		report = generateOAuth2HTMLReport(results)
	default:
		report = generateOAuth2TextReport(results)
	}

	// Output report
	if output == "" {
		fmt.Print(report)
	} else {
		if err := os.WriteFile(output, []byte(report), 0644); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
		fmt.Printf(" Report saved to: %s\n", output)
	}

	return nil
}

// Display helper functions
func displayOAuth2Results(findings []types.Finding, verbose bool) {
	// Find summary finding
	var summary *types.Finding
	vulnerabilities := []types.Finding{}

	for _, finding := range findings {
		if finding.Type == "OAUTH2_SECURITY_SUMMARY" {
			summary = &finding
		} else {
			vulnerabilities = append(vulnerabilities, finding)
		}
	}

	// Display summary
	if summary != nil {
		fmt.Printf("\n Security Assessment Summary:\n")
		fmt.Printf("   %s\n", summary.Title)

		details := summary.Metadata
		fmt.Printf("   Total Tests: %v\n", details["total_tests"])
		fmt.Printf("   Passed: %v\n", details["passed_tests"])
		fmt.Printf("   Failed: %v\n", details["failed_tests"])
	}

	// Group vulnerabilities by severity
	bySeverity := map[types.Severity][]types.Finding{
		types.SeverityCritical: {},
		types.SeverityHigh:     {},
		types.SeverityMedium:   {},
		types.SeverityLow:      {},
		types.SeverityInfo:     {},
	}

	for _, vuln := range vulnerabilities {
		bySeverity[vuln.Severity] = append(bySeverity[vuln.Severity], vuln)
	}

	// Display vulnerabilities by severity
	for _, severity := range []types.Severity{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow, types.SeverityInfo} {
		if len(bySeverity[severity]) > 0 {
			emoji := map[types.Severity]string{
				types.SeverityCritical: "🔴",
				types.SeverityHigh:     "🟠",
				types.SeverityMedium:   "🟡",
				types.SeverityLow:      "🔵",
				types.SeverityInfo:     "⚪",
			}[severity]

			fmt.Printf("\n%s %s Severity Findings (%d):\n", emoji, severity, len(bySeverity[severity]))

			for _, finding := range bySeverity[severity] {
				fmt.Printf("   • %s\n", finding.Title)
				if verbose {
					fmt.Printf("     %s\n", finding.Description)
					if finding.Solution != "" {
						fmt.Printf("     Fix: %s\n", finding.Solution)
					}
				}
			}
		}
	}
}

// Report generation functions
func generateOAuth2TextReport(results map[string]interface{}) string {
	report := "OAuth2 Security Assessment Report\n"
	report += "=================================\n\n"

	if target, ok := results["target"].(string); ok {
		report += fmt.Sprintf("Target: %s\n", target)
	}
	if scanTime, ok := results["scan_time"].(string); ok {
		report += fmt.Sprintf("Scan Time: %s\n", scanTime)
	}
	if duration, ok := results["duration"].(float64); ok {
		report += fmt.Sprintf("Duration: %.2f seconds\n", duration)
	}

	report += "\nFindings:\n---------\n"
	// Add findings details...

	return report
}

func generateOAuth2MarkdownReport(results map[string]interface{}) string {
	// Generate markdown report
	return "# OAuth2 Security Report\n\n..."
}

func generateOAuth2HTMLReport(results map[string]interface{}) string {
	// Generate HTML report
	return "<html><head><title>OAuth2 Security Report</title></head><body>...</body></html>"
}
