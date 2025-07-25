// cmd/protocol.go
package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/protocol"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/spf13/cobra"
)

// ProtocolLogger is an adapter that wraps our logger to match the protocol.Logger interface
type ProtocolLogger struct {
	log *logger.Logger
}

func (p *ProtocolLogger) Info(msg string, fields ...interface{}) {
	if p.log != nil {
		args := []interface{}{msg}
		args = append(args, fields...)
		p.log.Info(args...)
	}
}

func (p *ProtocolLogger) Error(msg string, fields ...interface{}) {
	if p.log != nil {
		args := []interface{}{msg}
		args = append(args, fields...)
		p.log.Error(args...)
	}
}

func (p *ProtocolLogger) Debug(msg string, fields ...interface{}) {
	if p.log != nil {
		args := []interface{}{msg}
		args = append(args, fields...)
		p.log.Debug(args...)
	}
}

func (p *ProtocolLogger) Warn(msg string, fields ...interface{}) {
	if p.log != nil {
		args := []interface{}{msg}
		args = append(args, fields...)
		p.log.Warn(args...)
	}
}

// protocolCmd represents the protocol command
var protocolCmd = &cobra.Command{
	Use:   "protocol",
	Short: "Protocol-specific security testing",
	Long: `Comprehensive protocol security testing for various network protocols.

This command provides specialized testing for:
- SSL/TLS: Certificate validation, cipher suites, protocol versions, known vulnerabilities
- SMTP: User enumeration, open relay, STARTTLS security, authentication methods
- LDAP: Anonymous bind, null bind, information disclosure, injection risks

The protocol scanner performs deep security analysis beyond basic connectivity testing,
identifying configuration weaknesses and known vulnerabilities.

Examples:
  shells protocol tls example.com:443
  shells protocol smtp mail.example.com
  shells protocol ldap ldap.example.com
  shells protocol all example.com --output report.json`,
}

// protocolTLSCmd performs TLS/SSL testing
var protocolTLSCmd = &cobra.Command{
	Use:   "tls [target]",
	Short: "Test SSL/TLS security",
	Long: `Perform comprehensive SSL/TLS security testing.

This command tests:
- Supported protocol versions (SSL 2.0 through TLS 1.3)
- Cipher suite strength and configuration
- Certificate chain validation
- Common vulnerabilities (Heartbleed, POODLE, BEAST, CRIME)
- Certificate expiration and validity
- Hostname verification
- Key strength
- Forward secrecy support

Examples:
  shells protocol tls example.com:443
  shells protocol tls example.com:8443 --check-vulns
  shells protocol tls mail.example.com:465 --check-ciphers`,
	Args: cobra.ExactArgs(1),
	RunE: runProtocolTLS,
}

// protocolSMTPCmd performs SMTP testing
var protocolSMTPCmd = &cobra.Command{
	Use:   "smtp [target]",
	Short: "Test SMTP security",
	Long: `Perform SMTP server security testing.

This command tests:
- User enumeration via VRFY, EXPN, and RCPT TO
- Open relay configuration
- STARTTLS support and enforcement
- Authentication methods and security
- Anonymous authentication
- TLS configuration when using STARTTLS

Examples:
  shells protocol smtp mail.example.com
  shells protocol smtp mail.example.com:587
  shells protocol smtp 192.168.1.10:25`,
	Args: cobra.ExactArgs(1),
	RunE: runProtocolSMTP,
}

// protocolLDAPCmd performs LDAP testing
var protocolLDAPCmd = &cobra.Command{
	Use:   "ldap [target]",
	Short: "Test LDAP security",
	Long: `Perform LDAP server security testing.

This command tests:
- Anonymous bind vulnerability
- Null bind vulnerability (authentication bypass)
- Information disclosure through root DSE
- User enumeration possibilities
- Common LDAP injection patterns
- Exposed sensitive object classes

Examples:
  shells protocol ldap ldap.example.com
  shells protocol ldap ldap.example.com:636
  shells protocol ldap 192.168.1.20:389`,
	Args: cobra.ExactArgs(1),
	RunE: runProtocolLDAP,
}

// protocolAllCmd tests all protocols
var protocolAllCmd = &cobra.Command{
	Use:   "all [target]",
	Short: "Test all protocols on common ports",
	Long: `Test all supported protocols on their common ports.

This command will attempt to test:
- TLS on ports 443, 8443, 465, 993, 995
- SMTP on ports 25, 465, 587
- LDAP on ports 389, 636

Examples:
  shells protocol all example.com
  shells protocol all 192.168.1.1`,
	Args: cobra.ExactArgs(1),
	RunE: runProtocolAll,
}

func init() {
	rootCmd.AddCommand(protocolCmd)
	protocolCmd.AddCommand(protocolTLSCmd)
	protocolCmd.AddCommand(protocolSMTPCmd)
	protocolCmd.AddCommand(protocolLDAPCmd)
	protocolCmd.AddCommand(protocolAllCmd)

	// Common flags
	protocolCmd.PersistentFlags().Duration("timeout", 10*time.Second, "Connection timeout")
	protocolCmd.PersistentFlags().String("output", "", "Output file for results")
	protocolCmd.PersistentFlags().Bool("verbose", false, "Verbose output")

	// TLS specific flags
	protocolTLSCmd.Flags().Bool("check-ciphers", true, "Test all cipher suites")
	protocolTLSCmd.Flags().Bool("check-vulns", true, "Test for known vulnerabilities")
	protocolTLSCmd.Flags().String("min-version", "TLS1.0", "Minimum TLS version to test")

	// SMTP specific flags
	protocolSMTPCmd.Flags().StringSlice("test-users", []string{"admin", "test", "guest"}, "Users to test for enumeration")
	protocolSMTPCmd.Flags().Bool("test-relay", true, "Test for open relay")

	// LDAP specific flags
	protocolLDAPCmd.Flags().String("base-dn", "", "Base DN for LDAP searches")
	protocolLDAPCmd.Flags().Bool("test-anon", true, "Test anonymous bind")
}

func runProtocolTLS(cmd *cobra.Command, args []string) error {
	target := args[0]
	timeout, _ := cmd.Flags().GetDuration("timeout")
	checkCiphers, _ := cmd.Flags().GetBool("check-ciphers")
	checkVulns, _ := cmd.Flags().GetBool("check-vulns")
	output, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")

	fmt.Printf("🔍 Starting TLS security scan for: %s\n", target)

	// Create scanner config
	config := protocol.Config{
		Timeout:      timeout,
		CheckCiphers: checkCiphers,
		CheckVulns:   checkVulns,
	}

	// Create scanner
	protocolLogger := &ProtocolLogger{log: log}
	scanner := protocol.NewScanner(config, protocolLogger)

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Run scan
	start := time.Now()
	findings, err := scanner.ScanTLS(ctx, target)
	if err != nil {
		return fmt.Errorf("TLS scan failed: %w", err)
	}
	duration := time.Since(start)

	fmt.Printf("\n✅ TLS scan completed in %s\n", duration.Round(time.Second))

	// Display results
	displayProtocolResults(findings, verbose)

	// Save results if output specified
	if output != "" {
		if err := saveProtocolResults(findings, output); err != nil {
			return fmt.Errorf("failed to save results: %w", err)
		}
		fmt.Printf("\n💾 Results saved to: %s\n", output)
	}

	return nil
}

func runProtocolSMTP(cmd *cobra.Command, args []string) error {
	target := args[0]
	timeout, _ := cmd.Flags().GetDuration("timeout")
	// testRelay, _ := cmd.Flags().GetBool("test-relay") // TODO: use this parameter
	output, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")

	fmt.Printf("🔍 Starting SMTP security scan for: %s\n", target)

	// Create scanner config
	config := protocol.Config{
		Timeout: timeout,
	}

	// Create scanner
	protocolLogger := &ProtocolLogger{log: log}
	scanner := protocol.NewScanner(config, protocolLogger)

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Run scan
	start := time.Now()
	findings, err := scanner.ScanSMTP(ctx, target)
	if err != nil {
		return fmt.Errorf("SMTP scan failed: %w", err)
	}
	duration := time.Since(start)

	fmt.Printf("\n✅ SMTP scan completed in %s\n", duration.Round(time.Second))

	// Display results
	displayProtocolResults(findings, verbose)

	// Save results if output specified
	if output != "" {
		if err := saveProtocolResults(findings, output); err != nil {
			return fmt.Errorf("failed to save results: %w", err)
		}
		fmt.Printf("\n💾 Results saved to: %s\n", output)
	}

	return nil
}

func runProtocolLDAP(cmd *cobra.Command, args []string) error {
	target := args[0]
	timeout, _ := cmd.Flags().GetDuration("timeout")
	baseDN, _ := cmd.Flags().GetString("base-dn")
	output, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")

	fmt.Printf("🔍 Starting LDAP security scan for: %s\n", target)

	// Create scanner config
	config := protocol.Config{
		Timeout:        timeout,
		LDAPSearchBase: baseDN,
	}

	// Create scanner
	protocolLogger := &ProtocolLogger{log: log}
	scanner := protocol.NewScanner(config, protocolLogger)

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Run scan
	start := time.Now()
	findings, err := scanner.ScanLDAP(ctx, target)
	if err != nil {
		return fmt.Errorf("LDAP scan failed: %w", err)
	}
	duration := time.Since(start)

	fmt.Printf("\n✅ LDAP scan completed in %s\n", duration.Round(time.Second))

	// Display results
	displayProtocolResults(findings, verbose)

	// Save results if output specified
	if output != "" {
		if err := saveProtocolResults(findings, output); err != nil {
			return fmt.Errorf("failed to save results: %w", err)
		}
		fmt.Printf("\n💾 Results saved to: %s\n", output)
	}

	return nil
}

func runProtocolAll(cmd *cobra.Command, args []string) error {
	target := args[0]
	timeout, _ := cmd.Flags().GetDuration("timeout")
	output, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")

	fmt.Printf("🔍 Starting comprehensive protocol scan for: %s\n", target)

	// Test configurations
	tests := []struct {
		protocol string
		ports    []string
		scanner  func(context.Context, string) ([]types.Finding, error)
	}{
		{
			protocol: "TLS",
			ports:    []string{"443", "8443", "465", "993", "995"},
		},
		{
			protocol: "SMTP",
			ports:    []string{"25", "465", "587"},
		},
		{
			protocol: "LDAP",
			ports:    []string{"389", "636"},
		},
	}

	// Create scanner
	config := protocol.Config{
		Timeout:      timeout,
		CheckCiphers: true,
		CheckVulns:   true,
	}
	protocolLogger := &ProtocolLogger{log: log}
	scanner := protocol.NewScanner(config, protocolLogger)

	allFindings := []types.Finding{}

	// Test each protocol on its common ports
	for _, test := range tests {
		fmt.Printf("\n📋 Testing %s protocol...\n", test.protocol)

		for _, port := range test.ports {
			testTarget := fmt.Sprintf("%s:%s", target, port)
			fmt.Printf("   Checking port %s... ", port)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)

			var findings []types.Finding
			var err error

			switch test.protocol {
			case "TLS":
				findings, err = scanner.ScanTLS(ctx, testTarget)
			case "SMTP":
				findings, err = scanner.ScanSMTP(ctx, testTarget)
			case "LDAP":
				findings, err = scanner.ScanLDAP(ctx, testTarget)
			}

			cancel()

			if err != nil {
				fmt.Printf("❌ (error: %s)\n", err)
			} else if len(findings) > 0 {
				fmt.Printf("✅ (found %d issues)\n", len(findings))
				allFindings = append(allFindings, findings...)
			} else {
				fmt.Printf("➖ (no service)\n")
			}
		}
	}

	fmt.Printf("\n📊 Total findings: %d\n", len(allFindings))

	// Display results
	if len(allFindings) > 0 {
		displayProtocolResults(allFindings, verbose)
	}

	// Save results if output specified
	if output != "" && len(allFindings) > 0 {
		if err := saveProtocolResults(allFindings, output); err != nil {
			return fmt.Errorf("failed to save results: %w", err)
		}
		fmt.Printf("\n💾 Results saved to: %s\n", output)
	}

	return nil
}

// Helper functions

func displayProtocolResults(findings []types.Finding, verbose bool) {
	// Group by severity
	bySeverity := map[string][]types.Finding{
		"CRITICAL": {},
		"HIGH":     {},
		"MEDIUM":   {},
		"LOW":      {},
		"INFO":     {},
	}

	// Find summary findings
	summaries := []types.Finding{}

	for _, finding := range findings {
		if strings.Contains(finding.Type, "_SUMMARY") {
			summaries = append(summaries, finding)
		} else {
			bySeverity[string(finding.Severity)] = append(bySeverity[string(finding.Severity)], finding)
		}
	}

	// Display summaries
	if len(summaries) > 0 {
		fmt.Printf("\n📊 Scan Summary:\n")
		for _, summary := range summaries {
			fmt.Printf("   %s\n", summary.Title)
			if verbose && summary.Description != "" {
				fmt.Printf("   %s\n", summary.Description)
			}
		}
	}

	// Display findings by severity
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if len(bySeverity[severity]) > 0 {
			emoji := map[string]string{
				"CRITICAL": "🔴",
				"HIGH":     "🟠",
				"MEDIUM":   "🟡",
				"LOW":      "🔵",
				"INFO":     "⚪",
			}[severity]

			fmt.Printf("\n%s %s Severity (%d):\n", emoji, severity, len(bySeverity[severity]))

			for _, finding := range bySeverity[severity] {
				fmt.Printf("   • %s\n", finding.Title)

				if verbose {
					if finding.Description != "" {
						fmt.Printf("     %s\n", finding.Description)
					}
					if finding.Solution != "" {
						fmt.Printf("     Fix: %s\n", finding.Solution)
					}
					if len(finding.Metadata) > 0 {
						fmt.Printf("     Details:\n")
						for k, v := range finding.Metadata {
							fmt.Printf("       - %s: %v\n", k, v)
						}
					}
				}
			}
		}
	}
}

func saveProtocolResults(findings []types.Finding, output string) error {
	file, err := os.Create(output)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create report
	fmt.Fprintf(file, "Protocol Security Scan Report\n")
	fmt.Fprintf(file, "Generated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(file, "=====================================\n\n")

	// Group by target
	byTarget := make(map[string][]types.Finding)
	for _, finding := range findings {
		target := ""
		if t, ok := finding.Metadata["target"]; ok {
			if targetStr, ok := t.(string); ok {
				target = targetStr
			}
		}
		byTarget[target] = append(byTarget[target], finding)
	}

	for target, targetFindings := range byTarget {
		fmt.Fprintf(file, "Target: %s\n", target)
		fmt.Fprintf(file, "-------------------\n")

		for _, finding := range targetFindings {
			fmt.Fprintf(file, "\nTitle: %s\n", finding.Title)
			fmt.Fprintf(file, "Type: %s\n", finding.Type)
			fmt.Fprintf(file, "Severity: %s\n", finding.Severity)
			fmt.Fprintf(file, "Description: %s\n", finding.Description)

			if finding.Solution != "" {
				fmt.Fprintf(file, "Remediation: %s\n", finding.Solution)
			}

			if len(finding.References) > 0 {
				fmt.Fprintf(file, "References:\n")
				for _, ref := range finding.References {
					fmt.Fprintf(file, "  - %s\n", ref)
				}
			}
		}

		fmt.Fprintf(file, "\n=====================================\n\n")
	}

	return nil
}
