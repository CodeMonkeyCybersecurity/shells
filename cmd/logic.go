package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/logic"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/logic/core"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/logic/payments"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/logic/recovery"
	"github.com/spf13/cobra"
)

// logicCmd represents the logic command
var logicCmd = &cobra.Command{
	Use:   "logic",
	Short: "Test business logic vulnerabilities",
	Long: `Comprehensive business logic testing framework for identifying high-value vulnerabilities.

This command provides specialized testing for:
- Password reset flow vulnerabilities
- Multi-step workflow bypasses  
- Race condition exploitation
- MFA bypass techniques
- Account recovery flaws
- Time-based logic manipulation
- Payment and business logic flaws

Focus on vulnerabilities that lead to account takeover, financial loss, or privilege escalation.

Examples:
  shells logic reset --target https://example.com --test-all
  shells logic workflow --target https://example.com/login --max-depth 5
  shells logic race --target https://example.com/api --workers 20
  shells logic mfa --target https://example.com --test-bypasses`,
}

// logicResetCmd tests password reset flows
var logicResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Test password reset flows for vulnerabilities",
	Long: `Comprehensive password reset flow testing including:

Token Security:
- Weak entropy analysis
- Predictable token patterns
- Token collision detection
- Token expiration testing
- Token reuse vulnerabilities

Flow Vulnerabilities:
- Host header injection
- User enumeration
- Race conditions in token generation
- Email parameter pollution
- IDOR in reset flows

Advanced Attacks:
- Multiple token generation
- Reset token hijacking
- Direct password change bypass
- Cross-user token usage

Examples:
  shells logic reset --target https://example.com
  shells logic reset --target https://example.com --test-entropy --samples 200
  shells logic reset --target https://example.com --test-host-header
  shells logic reset --target https://example.com --output json`,
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		output, _ := cmd.Flags().GetString("output")
		testAll, _ := cmd.Flags().GetBool("test-all")
		testEntropy, _ := cmd.Flags().GetBool("test-entropy")
		testHostHeader, _ := cmd.Flags().GetBool("test-host-header")
		samples, _ := cmd.Flags().GetInt("samples")
		workers, _ := cmd.Flags().GetInt("workers")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if target == "" {
			fmt.Println("Error: --target is required")
			os.Exit(1)
		}

		// Configure test settings
		config := &logic.TestConfig{
			Target:            target,
			TestTokenEntropy:  testEntropy || testAll,
			TestHostHeader:    testHostHeader || testAll,
			TokenSamples:      samples,
			BruteForceThreads: workers,
			Timeout:           30 * time.Second,
			VerboseOutput:     verbose,
		}

		fmt.Printf("🔐 Testing password reset flows for: %s\n", target)
		if config.TestTokenEntropy {
			fmt.Printf("📊 Token entropy analysis with %d samples\n", samples)
		}
		if config.TestHostHeader {
			fmt.Printf("🌐 Host header injection testing enabled\n")
		}
		fmt.Println()

		// Initialize analyzer
		analyzer := recovery.NewPasswordResetAnalyzer(config)

		// Perform analysis
		startTime := time.Now()
		results := analyzer.AnalyzeResetFlow(target)
		duration := time.Since(startTime)

		fmt.Printf("✅ Analysis completed in %v\n\n", duration)

		// Output results
		if output == "json" {
			printResetAnalysisJSON(results)
		} else {
			printResetAnalysisTable(results, verbose)
		}

		// Show security score
		fmt.Printf("\n🏆 Security Score: %d/100\n", results.SecurityScore)

		if results.SecurityScore < 70 {
			fmt.Printf("⚠️  CRITICAL: Significant vulnerabilities detected!\n")
		} else if results.SecurityScore < 85 {
			fmt.Printf("⚠️  WARNING: Security improvements needed\n")
		} else {
			fmt.Printf("✅ Good: Password reset flow appears secure\n")
		}
	},
}

// logicWorkflowCmd analyzes multi-step workflows
var logicWorkflowCmd = &cobra.Command{
	Use:   "workflow",
	Short: "Analyze multi-step business workflows",
	Long: `Comprehensive workflow analysis for business logic vulnerabilities:

State Manipulation:
- Step skipping and reordering
- State transition bypasses
- Parallel execution attacks
- Workflow termination bypasses

Value Manipulation:
- Negative value attacks
- Integer overflow testing
- Type confusion vulnerabilities
- Extreme value handling

Authorization Flaws:
- Privilege escalation paths
- Cross-user action testing
- IDOR in workflow states
- Session upgrade bypasses

Temporal Attacks:
- Expired action execution
- Future-dated operations
- Timezone manipulation

Examples:
  shells logic workflow --target https://example.com/checkout
  shells logic workflow --target https://example.com/register --max-depth 10
  shells logic workflow --target https://example.com/admin --test-privileges`,
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		output, _ := cmd.Flags().GetString("output")
		maxDepth, _ := cmd.Flags().GetInt("max-depth")
		testPrivileges, _ := cmd.Flags().GetBool("test-privileges")
		followRedirects, _ := cmd.Flags().GetBool("follow-redirects")
		maintainSession, _ := cmd.Flags().GetBool("maintain-session")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if target == "" {
			fmt.Println("Error: --target is required")
			os.Exit(1)
		}

		config := &logic.TestConfig{
			Target:          target,
			MaxWorkers:      10,
			Timeout:         60 * time.Second,
			FollowRedirects: followRedirects,
			MaintainSession: maintainSession,
			VerboseOutput:   verbose,
		}

		fmt.Printf("🔄 Analyzing workflow starting from: %s\n", target)
		fmt.Printf("📊 Maximum depth: %d levels\n", maxDepth)
		if testPrivileges {
			fmt.Printf("🔐 Privilege escalation testing enabled\n")
		}
		fmt.Println()

		// Initialize analyzer
		analyzer := core.NewWorkflowAnalyzer(config)

		// Perform analysis
		startTime := time.Now()
		results := analyzer.AnalyzeWorkflow(target)
		duration := time.Since(startTime)

		fmt.Printf("✅ Workflow analysis completed in %v\n\n", duration)

		// Output results
		if output == "json" {
			printWorkflowAnalysisJSON(results)
		} else {
			printWorkflowAnalysisTable(results, verbose)
		}

		// Show workflow diagram
		if verbose {
			fmt.Println("\n📊 Workflow Diagram:")
			fmt.Println("═══════════════════")
			fmt.Println(results.Diagram)
		}
	},
}

// logicRaceCmd tests for race conditions
var logicRaceCmd = &cobra.Command{
	Use:   "race",
	Short: "Test for race condition vulnerabilities",
	Long: `Comprehensive race condition testing across multiple categories:

Authentication Race Conditions:
- Concurrent login attempts
- Password reset token races
- Account creation conflicts
- Session fixation races

Payment Race Conditions:
- Double payment processing
- Cart manipulation races
- Coupon/discount races
- Refund processing conflicts

Business Logic Races:
- Resource allocation conflicts
- Rate limit bypasses
- State transition races
- File upload conflicts

High-Impact Tests:
- Inventory overselling
- Double booking prevention
- Quota enforcement bypasses
- Locking mechanism failures

Examples:
  shells logic race --target https://example.com --workers 20
  shells logic race --target https://example.com/api/payment --test-payments
  shells logic race --target https://example.com/cart --test-inventory`,
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		output, _ := cmd.Flags().GetString("output")
		workers, _ := cmd.Flags().GetInt("workers")
		testPayments, _ := cmd.Flags().GetBool("test-payments")
		testInventory, _ := cmd.Flags().GetBool("test-inventory")
		requestDelay, _ := cmd.Flags().GetInt("request-delay")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if target == "" {
			fmt.Println("Error: --target is required")
			os.Exit(1)
		}

		config := &logic.TestConfig{
			Target:        target,
			MaxWorkers:    workers,
			Timeout:       30 * time.Second,
			RequestDelay:  time.Duration(requestDelay) * time.Millisecond,
			VerboseOutput: verbose,
		}

		fmt.Printf("⚡ Testing race conditions for: %s\n", target)
		fmt.Printf("👥 Concurrent workers: %d\n", workers)
		if requestDelay > 0 {
			fmt.Printf("⏱️  Request delay: %dms\n", requestDelay)
		}
		if testPayments {
			fmt.Printf("💳 Payment race testing enabled\n")
		}
		if testInventory {
			fmt.Printf("📦 Inventory race testing enabled\n")
		}
		fmt.Println()

		// Initialize tester
		tester := core.NewRaceConditionTester(config)

		// Perform testing
		startTime := time.Now()
		results := tester.TestAllEndpoints(target)
		duration := time.Since(startTime)

		fmt.Printf("✅ Race condition testing completed in %v\n\n", duration)

		// Output results
		if output == "json" {
			printRaceResultsJSON(results)
		} else {
			printRaceResultsTable(results, verbose)
		}

		// Summary
		vulnerableCount := 0
		for _, result := range results {
			if result.Vulnerable {
				vulnerableCount++
			}
		}

		fmt.Printf("\n📊 Race Condition Summary:\n")
		fmt.Printf("   Total endpoints tested: %d\n", len(results))
		fmt.Printf("   Vulnerable endpoints: %d\n", vulnerableCount)

		if vulnerableCount > 0 {
			fmt.Printf("⚠️  CRITICAL: Race condition vulnerabilities detected!\n")
		} else {
			fmt.Printf("✅ No race condition vulnerabilities found\n")
		}
	},
}

// logicMfaCmd tests MFA bypass vulnerabilities
var logicMfaCmd = &cobra.Command{
	Use:   "mfa",
	Short: "Test Multi-Factor Authentication bypass vulnerabilities",
	Long: `Comprehensive MFA bypass testing using multiple attack vectors:

Token-Based Bypasses:
- Remember Me token abuse
- Backup code vulnerabilities
- Token reuse attacks
- Weak token generation

Flow-Based Bypasses:
- Recovery flow manipulation
- Session upgrade bypasses
- Authentication flow skipping
- API endpoint bypasses

Technical Bypasses:
- Race condition exploitation
- Response manipulation
- Cookie manipulation
- JavaScript bypasses

Advanced Techniques:
- Time-based bypasses
- Social engineering preparation
- Implementation flaw exploitation

Examples:
  shells logic mfa --target https://example.com --test-bypasses
  shells logic mfa --target https://example.com --test-tokens
  shells logic mfa --target https://example.com --test-recovery`,
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		output, _ := cmd.Flags().GetString("output")
		testBypasses, _ := cmd.Flags().GetBool("test-bypasses")
		testTokens, _ := cmd.Flags().GetBool("test-tokens")
		testRecovery, _ := cmd.Flags().GetBool("test-recovery")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if target == "" {
			fmt.Println("Error: --target is required")
			os.Exit(1)
		}

		config := &logic.TestConfig{
			Target:          target,
			Timeout:         30 * time.Second,
			FollowRedirects: true,
			MaintainSession: true,
			VerboseOutput:   verbose,
		}

		fmt.Printf("🔐 Testing MFA bypass vulnerabilities for: %s\n", target)
		if testBypasses {
			fmt.Printf("🎯 All bypass methods enabled\n")
		}
		if testTokens {
			fmt.Printf("🎫 Token-based bypass testing enabled\n")
		}
		if testRecovery {
			fmt.Printf("🔄 Recovery flow bypass testing enabled\n")
		}
		fmt.Println()

		// Initialize tester
		tester := recovery.NewMFABypassTester(config)

		// Perform testing
		startTime := time.Now()
		results := tester.TestAllMethods(target)
		duration := time.Since(startTime)

		fmt.Printf("✅ MFA bypass testing completed in %v\n\n", duration)

		// Output results
		if output == "json" {
			printMFAResultsJSON(results)
		} else {
			printMFAResultsTable(results, verbose)
		}

		// Security assessment
		criticalCount := 0
		highCount := 0

		for _, vuln := range results {
			switch vuln.Severity {
			case logic.SeverityCritical:
				criticalCount++
			case logic.SeverityHigh:
				highCount++
			}
		}

		fmt.Printf("\n🛡️  MFA Security Assessment:\n")
		fmt.Printf("   Total vulnerabilities: %d\n", len(results))
		fmt.Printf("   Critical bypasses: %d\n", criticalCount)
		fmt.Printf("   High-risk bypasses: %d\n", highCount)

		if criticalCount > 0 {
			fmt.Printf("🚨 CRITICAL: MFA can be completely bypassed!\n")
		} else if highCount > 0 {
			fmt.Printf("⚠️  WARNING: MFA bypass vulnerabilities detected\n")
		} else if len(results) > 0 {
			fmt.Printf("ℹ️  INFO: Minor MFA implementation issues found\n")
		} else {
			fmt.Printf("✅ MFA implementation appears secure\n")
		}
	},
}

// logicPaymentCmd tests e-commerce payment logic vulnerabilities
var logicPaymentCmd = &cobra.Command{
	Use:   "payment",
	Short: "Test e-commerce payment logic vulnerabilities",
	Long: `Comprehensive e-commerce payment logic testing including:

Shopping Cart Vulnerabilities:
- Negative quantity manipulation
- Integer overflow in calculations
- Cart parameter manipulation
- Race conditions in cart operations
- Cart session hijacking

Payment Processing Flaws:
- Payment bypass vulnerabilities
- Double charging via race conditions
- Currency confusion attacks
- Payment flow manipulation
- Refund logic exploitation

Pricing Logic Issues:
- Price manipulation vulnerabilities
- Floating point precision errors
- Discount calculation flaws
- Tax calculation bypass
- Currency conversion issues

Coupon & Discount Abuse:
- Coupon stacking vulnerabilities
- Coupon reuse attacks
- Discount code brute forcing
- Promotional code manipulation
- Referral system abuse

Examples:
  shells logic payment --target https://shop.example.com --test-all
  shells logic payment --target https://shop.example.com --test-cart
  shells logic payment --target https://shop.example.com --test-pricing`,
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		output, _ := cmd.Flags().GetString("output")
		testAll, _ := cmd.Flags().GetBool("test-all")
		testCart, _ := cmd.Flags().GetBool("test-cart")
		testPricing, _ := cmd.Flags().GetBool("test-pricing")
		testCoupons, _ := cmd.Flags().GetBool("test-coupons")
		testRace, _ := cmd.Flags().GetBool("test-race")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if target == "" {
			fmt.Println("Error: --target is required")
			os.Exit(1)
		}

		config := &logic.TestConfig{
			Target:        target,
			MaxWorkers:    10,
			Timeout:       30 * time.Second,
			VerboseOutput: verbose,
		}

		fmt.Printf("💳 Testing e-commerce payment logic for: %s\n", target)
		if testAll || testCart {
			fmt.Printf("🛒 Shopping cart testing enabled\n")
		}
		if testAll || testPricing {
			fmt.Printf("💰 Pricing logic testing enabled\n")
		}
		if testAll || testCoupons {
			fmt.Printf("🎫 Coupon logic testing enabled\n")
		}
		if testAll || testRace {
			fmt.Printf("⚡ Race condition testing enabled\n")
		}
		fmt.Println()

		// Initialize e-commerce tester
		tester := payments.NewEcommerceLogicTester(config)

		// Perform testing
		startTime := time.Now()
		results := tester.TestAllEcommerceLogic(target)
		duration := time.Since(startTime)

		fmt.Printf("✅ E-commerce testing completed in %v\n\n", duration)

		// Output results
		if output == "json" {
			printPaymentResultsJSON(results)
		} else {
			printPaymentResultsTable(results, verbose)
		}

		// Security assessment
		criticalCount := 0
		highCount := 0

		for _, vuln := range results {
			switch vuln.Severity {
			case logic.SeverityCritical:
				criticalCount++
			case logic.SeverityHigh:
				highCount++
			}
		}

		fmt.Printf("\n💳 E-commerce Security Assessment:\n")
		fmt.Printf("   Total vulnerabilities: %d\n", len(results))
		fmt.Printf("   Critical issues: %d\n", criticalCount)
		fmt.Printf("   High-risk issues: %d\n", highCount)

		if criticalCount > 0 {
			fmt.Printf("🚨 CRITICAL: Financial exploitation possible!\n")
		} else if highCount > 0 {
			fmt.Printf("⚠️  WARNING: Payment logic vulnerabilities detected\n")
		} else if len(results) > 0 {
			fmt.Printf("ℹ️  INFO: Minor payment logic issues found\n")
		} else {
			fmt.Printf("✅ Payment logic appears secure\n")
		}
	},
}

// logicRecoveryCmd tests account recovery vulnerabilities
var logicRecoveryCmd = &cobra.Command{
	Use:   "recovery",
	Short: "Test account recovery vulnerabilities",
	Long: `Comprehensive account recovery testing including:

Recovery Method Testing:
- Password reset flow analysis
- Security question vulnerabilities
- SMS recovery method flaws
- Email recovery weaknesses
- Backup code vulnerabilities

Recovery Flow Analysis:
- Recovery method chaining
- Cross-recovery method attacks
- Recovery session hijacking
- Recovery token manipulation
- Recovery flow bypasses

Advanced Recovery Attacks:
- Social recovery exploitation
- Biometric recovery bypasses
- Admin recovery vulnerabilities
- Device recovery flaws
- Knowledge-based auth bypass

Security Assessments:
- Recovery token entropy analysis
- Recovery method enumeration
- Recovery flow race conditions
- Recovery session validation
- Recovery rate limiting

Examples:
  shells logic recovery --target https://example.com --test-all
  shells logic recovery --target https://example.com --test-password-reset
  shells logic recovery --target https://example.com --test-security-questions`,
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		output, _ := cmd.Flags().GetString("output")
		testAll, _ := cmd.Flags().GetBool("test-all")
		testPasswordReset, _ := cmd.Flags().GetBool("test-password-reset")
		testSecQuestions, _ := cmd.Flags().GetBool("test-security-questions")
		testSMS, _ := cmd.Flags().GetBool("test-sms")
		testEmail, _ := cmd.Flags().GetBool("test-email")
		testBackupCodes, _ := cmd.Flags().GetBool("test-backup-codes")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if target == "" {
			fmt.Println("Error: --target is required")
			os.Exit(1)
		}

		config := &logic.TestConfig{
			Target:           target,
			TestTokenEntropy: true,
			TestHostHeader:   true,
			TokenSamples:     50,
			MaxWorkers:       10,
			Timeout:          30 * time.Second,
			VerboseOutput:    verbose,
		}

		fmt.Printf("🔐 Testing account recovery for: %s\n", target)
		if testAll || testPasswordReset {
			fmt.Printf("🔑 Password reset testing enabled\n")
		}
		if testAll || testSecQuestions {
			fmt.Printf("❓ Security questions testing enabled\n")
		}
		if testAll || testSMS {
			fmt.Printf("📱 SMS recovery testing enabled\n")
		}
		if testAll || testEmail {
			fmt.Printf("📧 Email recovery testing enabled\n")
		}
		if testAll || testBackupCodes {
			fmt.Printf("🎫 Backup codes testing enabled\n")
		}
		fmt.Println()

		// Initialize recovery tester
		tester := recovery.NewAccountRecoveryTester(config)

		// Perform testing
		startTime := time.Now()
		results := tester.TestAllMethods(target)
		duration := time.Since(startTime)

		fmt.Printf("✅ Account recovery testing completed in %v\n\n", duration)

		// Output results
		if output == "json" {
			printRecoveryResultsJSON(results)
		} else {
			printRecoveryResultsTable(results, verbose)
		}

		// Security assessment
		criticalCount := 0
		highCount := 0

		for _, vuln := range results {
			switch vuln.Severity {
			case logic.SeverityCritical:
				criticalCount++
			case logic.SeverityHigh:
				highCount++
			}
		}

		fmt.Printf("\n🔐 Recovery Security Assessment:\n")
		fmt.Printf("   Total vulnerabilities: %d\n", len(results))
		fmt.Printf("   Critical bypasses: %d\n", criticalCount)
		fmt.Printf("   High-risk bypasses: %d\n", highCount)

		if criticalCount > 0 {
			fmt.Printf("🚨 CRITICAL: Account recovery can be fully bypassed!\n")
		} else if highCount > 0 {
			fmt.Printf("⚠️  WARNING: Recovery bypass vulnerabilities detected\n")
		} else if len(results) > 0 {
			fmt.Printf("ℹ️  INFO: Minor recovery implementation issues found\n")
		} else {
			fmt.Printf("✅ Account recovery appears secure\n")
		}
	},
}

// logicAllCmd runs all comprehensive business logic tests
var logicAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Run all comprehensive business logic tests",
	Long: `Comprehensive business logic testing suite that runs all available tests:

Test Categories:
- Password reset flow vulnerabilities
- Multi-step workflow bypasses
- Race condition exploitation
- MFA bypass techniques
- Account recovery flaws
- E-commerce payment logic
- Time-based logic manipulation
- Session management issues

High-Value Targets:
- Account takeover vulnerabilities
- Financial exploitation flaws
- Privilege escalation paths
- Business process bypasses
- Payment manipulation attacks
- Data exposure risks

Report Generation:
- Detailed vulnerability analysis
- Business impact assessment
- Remediation recommendations
- Executive summary
- Technical details with PoCs

Examples:
  shells logic all --target https://example.com
  shells logic all --target https://example.com --output json
  shells logic all --target https://example.com --include-business-impact`,
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		output, _ := cmd.Flags().GetString("output")
		includeBusiness, _ := cmd.Flags().GetBool("include-business-impact")
		reportFile, _ := cmd.Flags().GetString("report-file")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if target == "" {
			fmt.Println("Error: --target is required")
			os.Exit(1)
		}

		fmt.Printf("🔍 Running comprehensive business logic tests for: %s\n", target)
		fmt.Printf("📋 Test suite includes: password reset, workflow, race conditions, MFA, recovery, and e-commerce\n")
		fmt.Println()

		// Run comprehensive tests
		startTime := time.Now()
		vulnerabilities := runComprehensiveTests(target)
		duration := time.Since(startTime)

		fmt.Printf("✅ Comprehensive testing completed in %v\n\n", duration)

		// Generate report
		report := generateBusinessLogicReport(vulnerabilities, includeBusiness)

		// Output results
		if output == "json" {
			data, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println(string(data))
		} else {
			printReportSummary(report, verbose)
		}

		// Save report if requested
		if reportFile != "" {
			err := saveReport(report, reportFile, "html")
			if err != nil {
				fmt.Printf("Error saving report: %v\n", err)
			} else {
				fmt.Printf("📄 Detailed report saved to: %s\n", reportFile)
			}
		}

		// Final security assessment
		fmt.Printf("\n🛡️  Overall Security Assessment:\n")
		if report.Metadata.CriticalCount > 0 {
			fmt.Printf("🚨 CRITICAL: Immediate action required - %d critical vulnerabilities\n", report.Metadata.CriticalCount)
		} else if report.Metadata.HighCount > 2 {
			fmt.Printf("⚠️  HIGH RISK: Significant vulnerabilities detected - %d high-risk issues\n", report.Metadata.HighCount)
		} else if report.Metadata.HighCount > 0 {
			fmt.Printf("⚠️  WARNING: Some high-risk vulnerabilities - %d issues\n", report.Metadata.HighCount)
		} else if report.Metadata.VulnsFound > 0 {
			fmt.Printf("ℹ️  INFO: Minor security issues found - %d total\n", report.Metadata.VulnsFound)
		} else {
			fmt.Printf("✅ SECURE: No significant business logic vulnerabilities found\n")
		}
	},
}

// logicReportCmd generates comprehensive business logic reports
var logicReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate comprehensive business logic vulnerability reports",
	Long: `Generate detailed reports combining all business logic testing results:

Report Types:
- Executive summary with business impact
- Technical vulnerability details
- Risk assessment and prioritization
- Remediation recommendations

Business Impact Analysis:
- Financial risk calculation
- User impact assessment
- Compliance violation analysis
- Reputation damage estimation

Output Formats:
- HTML reports with charts
- JSON data for integration
- PDF executive summaries
- CSV vulnerability lists

Examples:
  shells logic report --target https://example.com --output report.html
  shells logic report --findings findings.json --format pdf
  shells logic report --target https://example.com --include-business-impact`,
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		outputFile, _ := cmd.Flags().GetString("output")
		findingsFile, _ := cmd.Flags().GetString("findings")
		format, _ := cmd.Flags().GetString("format")
		includeBusiness, _ := cmd.Flags().GetBool("include-business-impact")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if target == "" && findingsFile == "" {
			fmt.Println("Error: specify --target or --findings")
			os.Exit(1)
		}

		fmt.Printf("📋 Generating business logic security report...\n")

		var vulnerabilities []logic.Vulnerability

		if findingsFile != "" {
			// Load existing findings
			var err error
			vulnerabilities, err = loadVulnerabilitiesFromFile(findingsFile)
			if err != nil {
				fmt.Printf("Error loading findings: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("📁 Loaded %d vulnerabilities from %s\n", len(vulnerabilities), findingsFile)
		} else {
			// Run comprehensive testing
			fmt.Printf("🔍 Running comprehensive business logic tests for: %s\n", target)
			vulnerabilities = runComprehensiveTests(target)
			fmt.Printf("🔍 Found %d vulnerabilities\n", len(vulnerabilities))
		}

		// Generate report
		report := generateBusinessLogicReport(vulnerabilities, includeBusiness)

		// Output report
		if outputFile != "" {
			err := saveReport(report, outputFile, format)
			if err != nil {
				fmt.Printf("Error saving report: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("📄 Report saved to: %s\n", outputFile)
		} else {
			printReportSummary(report, verbose)
		}
	},
}

// Output formatting functions

func printResetAnalysisJSON(analysis *recovery.ResetFlowAnalysis) {
	data, _ := json.MarshalIndent(analysis, "", "  ")
	fmt.Println(string(data))
}

func printResetAnalysisTable(analysis *recovery.ResetFlowAnalysis, verbose bool) {
	fmt.Printf("🔐 Password Reset Flow Analysis\n")
	fmt.Printf("═══════════════════════════════\n\n")

	fmt.Printf("📊 Endpoints discovered: %d\n", len(analysis.Endpoints))
	for _, endpoint := range analysis.Endpoints {
		status := "❌ Inactive"
		if endpoint.IsActive {
			status = "✅ Active"
		}
		fmt.Printf("   %s %s (%s)\n", endpoint.Method, endpoint.URL, status)
	}

	fmt.Printf("\n🎯 Vulnerabilities found: %d\n", len(analysis.Vulnerabilities))
	for i, vuln := range analysis.Vulnerabilities {
		severity := getSeverityEmoji(vuln.Severity)
		fmt.Printf("%d. %s [%s] %s\n", i+1, severity, vuln.Severity, vuln.Title)
		fmt.Printf("   %s\n", vuln.Description)

		if verbose && vuln.PoC != "" {
			fmt.Printf("   PoC: %s\n", vuln.PoC)
		}
		fmt.Println()
	}

	if analysis.TokenAnalysis.Tokens != nil && len(analysis.TokenAnalysis.Tokens) > 0 {
		fmt.Printf("🎫 Token Analysis:\n")
		fmt.Printf("   Entropy: %.2f bits\n", analysis.TokenAnalysis.Entropy)
		fmt.Printf("   Predictable: %v\n", analysis.TokenAnalysis.IsPredictable)
		if analysis.TokenAnalysis.Collisions > 0 {
			fmt.Printf("   Collisions: %d\n", analysis.TokenAnalysis.Collisions)
		}
		fmt.Println()
	}
}

func printWorkflowAnalysisJSON(analysis *core.WorkflowAnalysis) {
	data, _ := json.MarshalIndent(analysis, "", "  ")
	fmt.Println(string(data))
}

func printWorkflowAnalysisTable(analysis *core.WorkflowAnalysis, verbose bool) {
	fmt.Printf("🔄 Workflow Analysis Results\n")
	fmt.Printf("═══════════════════════════\n\n")

	fmt.Printf("📊 Workflow Statistics:\n")
	fmt.Printf("   Total states: %d\n", len(analysis.States))
	fmt.Printf("   Vulnerabilities: %d\n", len(analysis.Vulnerabilities))
	fmt.Printf("   Security score: %d/100\n\n", analysis.SecurityScore)

	if len(analysis.Vulnerabilities) > 0 {
		fmt.Printf("🎯 Vulnerabilities:\n")
		for i, vuln := range analysis.Vulnerabilities {
			severity := getSeverityEmoji(vuln.Severity)
			fmt.Printf("%d. %s [%s] %s\n", i+1, severity, vuln.Severity, vuln.Title)
			fmt.Printf("   %s\n", vuln.Description)
			if verbose && vuln.Details != "" {
				fmt.Printf("   Details: %s\n", vuln.Details)
			}
			fmt.Println()
		}
	}

	if verbose {
		fmt.Printf("📈 Summary:\n%s\n", analysis.Summary)
	}
}

func printRaceResultsJSON(results []logic.RaceConditionTest) {
	data, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(data))
}

func printRaceResultsTable(results []logic.RaceConditionTest, verbose bool) {
	fmt.Printf("⚡ Race Condition Test Results\n")
	fmt.Printf("════════════════════════════\n\n")

	for i, result := range results {
		status := "✅ Safe"
		if result.Vulnerable {
			status = "🚨 VULNERABLE"
		}

		fmt.Printf("%d. %s - %s\n", i+1, result.Name, status)
		fmt.Printf("   Endpoint: %s\n", result.Endpoint)

		if result.Vulnerable {
			fmt.Printf("   Impact: %s\n", result.Impact)
			if verbose && len(result.Evidence) > 0 {
				fmt.Printf("   Evidence:\n")
				for _, evidence := range result.Evidence {
					fmt.Printf("     - %s\n", evidence)
				}
			}
		}
		fmt.Println()
	}
}

func printMFAResultsJSON(results []logic.Vulnerability) {
	data, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(data))
}

func printMFAResultsTable(results []logic.Vulnerability, verbose bool) {
	fmt.Printf("🔐 MFA Bypass Test Results\n")
	fmt.Printf("═════════════════════════\n\n")

	if len(results) == 0 {
		fmt.Printf("✅ No MFA bypass vulnerabilities found\n")
		return
	}

	for i, vuln := range results {
		severity := getSeverityEmoji(vuln.Severity)
		fmt.Printf("%d. %s [%s] %s\n", i+1, severity, vuln.Severity, vuln.Title)
		fmt.Printf("   %s\n", vuln.Description)
		fmt.Printf("   Impact: %s\n", vuln.Impact)

		if verbose && vuln.Details != "" {
			fmt.Printf("   Details: %s\n", vuln.Details)
		}
		fmt.Println()
	}
}

func printReportSummary(report *logic.BusinessLogicReport, verbose bool) {
	fmt.Printf("📊 Business Logic Security Report\n")
	fmt.Printf("════════════════════════════════\n\n")

	fmt.Printf("🎯 Executive Summary:\n")
	fmt.Printf("%s\n\n", report.Executive.Overview)

	fmt.Printf("📈 Vulnerability Breakdown:\n")
	fmt.Printf("   Critical: %d\n", report.Metadata.CriticalCount)
	fmt.Printf("   High: %d\n", report.Metadata.HighCount)
	fmt.Printf("   Medium: %d\n", report.Metadata.MediumCount)
	fmt.Printf("   Low: %d\n", report.Metadata.LowCount)
	fmt.Printf("   Total: %d\n\n", report.Metadata.VulnsFound)

	if len(report.Executive.KeyFindings) > 0 {
		fmt.Printf("🔑 Key Findings:\n")
		for _, finding := range report.Executive.KeyFindings {
			fmt.Printf("   • %s\n", finding)
		}
		fmt.Println()
	}

	if report.BusinessImpact.FinancialImpact != "" {
		fmt.Printf("💰 Business Impact:\n")
		fmt.Printf("   Financial Impact: %s\n", report.BusinessImpact.FinancialImpact)
		fmt.Printf("   Users Affected: %d\n", report.BusinessImpact.UsersAffected)
		fmt.Printf("   Recovery Time: %s\n", report.BusinessImpact.RecoveryTime)
		fmt.Println()
	}

	if len(report.Executive.ImmediateActions) > 0 {
		fmt.Printf("🚨 Immediate Actions Required:\n")
		for _, action := range report.Executive.ImmediateActions {
			fmt.Printf("   • %s\n", action)
		}
		fmt.Println()
	}
}

func printPaymentResultsJSON(results []logic.Vulnerability) {
	data, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(data))
}

func printPaymentResultsTable(results []logic.Vulnerability, verbose bool) {
	fmt.Printf("💳 E-commerce Payment Logic Test Results\n")
	fmt.Printf("════════════════════════════════════════\n\n")

	if len(results) == 0 {
		fmt.Printf("✅ No e-commerce payment logic vulnerabilities found\n")
		return
	}

	for i, vuln := range results {
		severity := getSeverityEmoji(vuln.Severity)
		fmt.Printf("%d. %s [%s] %s\n", i+1, severity, vuln.Severity, vuln.Title)
		fmt.Printf("   %s\n", vuln.Description)
		fmt.Printf("   Impact: %s\n", vuln.Impact)

		if verbose && vuln.Details != "" {
			fmt.Printf("   Details: %s\n", vuln.Details)
		}
		if verbose && vuln.Remediation != "" {
			fmt.Printf("   Remediation: %s\n", vuln.Remediation)
		}
		fmt.Println()
	}
}

func printRecoveryResultsJSON(results []logic.Vulnerability) {
	data, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(data))
}

func printRecoveryResultsTable(results []logic.Vulnerability, verbose bool) {
	fmt.Printf("🔐 Account Recovery Test Results\n")
	fmt.Printf("═══════════════════════════════\n\n")

	if len(results) == 0 {
		fmt.Printf("✅ No account recovery vulnerabilities found\n")
		return
	}

	for i, vuln := range results {
		severity := getSeverityEmoji(vuln.Severity)
		fmt.Printf("%d. %s [%s] %s\n", i+1, severity, vuln.Severity, vuln.Title)
		fmt.Printf("   %s\n", vuln.Description)
		fmt.Printf("   Impact: %s\n", vuln.Impact)

		if verbose && vuln.Details != "" {
			fmt.Printf("   Details: %s\n", vuln.Details)
		}
		if verbose && vuln.Remediation != "" {
			fmt.Printf("   Remediation: %s\n", vuln.Remediation)
		}
		fmt.Println()
	}
}

// Helper functions

func getSeverityEmoji(severity string) string {
	switch severity {
	case logic.SeverityCritical:
		return "🚨"
	case logic.SeverityHigh:
		return "⚠️"
	case logic.SeverityMedium:
		return "⚡"
	case logic.SeverityLow:
		return "ℹ️"
	default:
		return "📋"
	}
}

func loadVulnerabilitiesFromFile(filename string) ([]logic.Vulnerability, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var vulnerabilities []logic.Vulnerability
	err = json.Unmarshal(data, &vulnerabilities)
	return vulnerabilities, err
}

func runComprehensiveTests(target string) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	config := &logic.TestConfig{
		Target:           target,
		TestTokenEntropy: true,
		TestHostHeader:   true,
		TokenSamples:     50,
		MaxWorkers:       10,
		Timeout:          30 * time.Second,
	}

	// Run password reset tests
	resetAnalyzer := recovery.NewPasswordResetAnalyzer(config)
	resetResults := resetAnalyzer.AnalyzeResetFlow(target)
	vulnerabilities = append(vulnerabilities, resetResults.Vulnerabilities...)

	// Run workflow tests
	workflowAnalyzer := core.NewWorkflowAnalyzer(config)
	workflowResults := workflowAnalyzer.AnalyzeWorkflow(target)
	vulnerabilities = append(vulnerabilities, workflowResults.Vulnerabilities...)

	// Run race condition tests
	raceTester := core.NewRaceConditionTester(config)
	raceResults := raceTester.TestAllEndpoints(target)
	for _, result := range raceResults {
		if result.Vulnerable {
			vuln := logic.Vulnerability{
				ID:          "race-" + result.Endpoint,
				Type:        logic.VulnRaceCondition,
				Severity:    logic.SeverityHigh,
				Title:       result.Name,
				Description: "Race condition vulnerability detected",
				Impact:      result.Impact,
				Timestamp:   time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	// Run MFA bypass tests
	mfaTester := recovery.NewMFABypassTester(config)
	mfaResults := mfaTester.TestAllMethods(target)
	vulnerabilities = append(vulnerabilities, mfaResults...)

	// Run e-commerce tests
	ecommerceTester := payments.NewEcommerceLogicTester(config)
	ecommerceResults := ecommerceTester.TestAllEcommerceLogic(target)
	vulnerabilities = append(vulnerabilities, ecommerceResults...)

	// Run account recovery tests
	recoveryTester := recovery.NewAccountRecoveryTester(config)
	recoveryResults := recoveryTester.TestAllMethods(target)
	vulnerabilities = append(vulnerabilities, recoveryResults...)

	return vulnerabilities
}

func generateBusinessLogicReport(vulnerabilities []logic.Vulnerability, includeBusiness bool) *logic.BusinessLogicReport {
	// Count vulnerabilities by severity
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, vuln := range vulnerabilities {
		switch vuln.Severity {
		case logic.SeverityCritical:
			criticalCount++
		case logic.SeverityHigh:
			highCount++
		case logic.SeverityMedium:
			mediumCount++
		case logic.SeverityLow:
			lowCount++
		}
	}

	// Generate executive summary
	executiveSummary := generateExecutiveSummary(vulnerabilities, criticalCount, highCount)

	// Generate business impact if requested
	var businessImpact logic.BusinessImpact
	if includeBusiness {
		businessImpact = generateBusinessImpact(vulnerabilities, criticalCount, highCount)
	}

	report := &logic.BusinessLogicReport{
		Metadata: logic.ReportMetadata{
			GeneratedAt:   time.Now(),
			VulnsFound:    len(vulnerabilities),
			CriticalCount: criticalCount,
			HighCount:     highCount,
			MediumCount:   mediumCount,
			LowCount:      lowCount,
		},
		Executive:       executiveSummary,
		Vulnerabilities: vulnerabilities,
		BusinessImpact:  businessImpact,
	}

	return report
}

func generateExecutiveSummary(vulnerabilities []logic.Vulnerability, critical, high int) logic.ExecutiveSummary {
	overview := fmt.Sprintf("Business logic security assessment identified %d vulnerabilities, including %d critical and %d high-severity issues.",
		len(vulnerabilities), critical, high)

	keyFindings := []string{}
	immediateActions := []string{}

	// Analyze vulnerability types
	vulnTypes := make(map[string]int)
	for _, vuln := range vulnerabilities {
		vulnTypes[vuln.Type]++
	}

	// Generate findings based on vulnerability types
	if vulnTypes[logic.VulnPasswordResetHijack] > 0 {
		keyFindings = append(keyFindings, "Password reset flow can be hijacked for account takeover")
		immediateActions = append(immediateActions, "Fix host header injection in password reset")
	}

	if vulnTypes[logic.VulnMFABypass] > 0 {
		keyFindings = append(keyFindings, "Multi-factor authentication can be bypassed")
		immediateActions = append(immediateActions, "Review and strengthen MFA implementation")
	}

	if vulnTypes[logic.VulnRaceCondition] > 0 {
		keyFindings = append(keyFindings, "Race conditions allow business logic bypass")
		immediateActions = append(immediateActions, "Implement proper synchronization controls")
	}

	businessRisk := "LOW"
	if critical > 0 {
		businessRisk = "CRITICAL"
	} else if high > 2 {
		businessRisk = "HIGH"
	} else if high > 0 {
		businessRisk = "MEDIUM"
	}

	return logic.ExecutiveSummary{
		Overview:         overview,
		KeyFindings:      keyFindings,
		BusinessRisk:     businessRisk,
		ImmediateActions: immediateActions,
		EstimatedImpact:  "Account takeover and financial loss potential",
	}
}

func generateBusinessImpact(vulnerabilities []logic.Vulnerability, critical, high int) logic.BusinessImpact {
	var estimatedLoss float64
	usersAffected := 1000 // Default estimate

	// Calculate financial impact based on vulnerability types
	for _, vuln := range vulnerabilities {
		switch vuln.Type {
		case logic.VulnPasswordResetHijack, logic.VulnMFABypass:
			estimatedLoss += 50000 // Account takeover impact
		case logic.VulnPriceManipulation, logic.VulnPaymentBypass:
			estimatedLoss += 100000 // Financial fraud impact
		case logic.VulnRaceCondition:
			estimatedLoss += 25000 // Business logic impact
		}
	}

	financialImpact := "Low"
	if estimatedLoss > 100000 {
		financialImpact = "Critical"
		usersAffected = 10000
	} else if estimatedLoss > 50000 {
		financialImpact = "High"
		usersAffected = 5000
	} else if estimatedLoss > 10000 {
		financialImpact = "Medium"
		usersAffected = 2000
	}

	return logic.BusinessImpact{
		FinancialImpact:     financialImpact,
		DataExposureRisk:    "High",
		UsersAffected:       usersAffected,
		ReputationImpact:    "Significant",
		ComplianceViolation: critical > 0,
		EstimatedLoss:       estimatedLoss,
		RecoveryTime:        "1-4 weeks",
	}
}

func saveReport(report *logic.BusinessLogicReport, filename, format string) error {
	switch format {
	case "json":
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filename, data, 0644)
	case "html":
		// Generate HTML report (simplified)
		html := generateHTMLReport(report)
		return os.WriteFile(filename, []byte(html), 0644)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func generateHTMLReport(report *logic.BusinessLogicReport) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Business Logic Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; }
        .summary { background: #ecf0f1; padding: 20px; margin: 20px 0; }
        .vuln { border-left: 4px solid #e74c3c; padding: 10px; margin: 10px 0; }
        .critical { border-left-color: #e74c3c; }
        .high { border-left-color: #f39c12; }
        .medium { border-left-color: #f1c40f; }
        .low { border-left-color: #27ae60; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Business Logic Security Report</h1>
        <p>Generated: %s</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>%s</p>
        <p><strong>Total Vulnerabilities:</strong> %d</p>
        <p><strong>Critical:</strong> %d | <strong>High:</strong> %d | <strong>Medium:</strong> %d | <strong>Low:</strong> %d</p>
    </div>
    
    <h2>Vulnerabilities</h2>
    %s
</body>
</html>`,
		report.Metadata.GeneratedAt.Format("2006-01-02 15:04:05"),
		report.Executive.Overview,
		report.Metadata.VulnsFound,
		report.Metadata.CriticalCount,
		report.Metadata.HighCount,
		report.Metadata.MediumCount,
		report.Metadata.LowCount,
		generateVulnerabilityHTML(report.Vulnerabilities))
}

func generateVulnerabilityHTML(vulnerabilities []logic.Vulnerability) string {
	html := ""
	for _, vuln := range vulnerabilities {
		severity := strings.ToLower(vuln.Severity)
		html += fmt.Sprintf(`
    <div class="vuln %s">
        <h3>%s [%s]</h3>
        <p><strong>Description:</strong> %s</p>
        <p><strong>Impact:</strong> %s</p>
        <p><strong>CWE:</strong> %s | <strong>CVSS:</strong> %.1f</p>
    </div>`, severity, vuln.Title, vuln.Severity, vuln.Description, vuln.Impact, vuln.CWE, vuln.CVSS)
	}
	return html
}

func init() {
	// Add logic command to root
	rootCmd.AddCommand(logicCmd)

	// Add subcommands
	logicCmd.AddCommand(logicResetCmd)
	logicCmd.AddCommand(logicWorkflowCmd)
	logicCmd.AddCommand(logicRaceCmd)
	logicCmd.AddCommand(logicMfaCmd)
	logicCmd.AddCommand(logicPaymentCmd)
	logicCmd.AddCommand(logicRecoveryCmd)
	logicCmd.AddCommand(logicAllCmd)
	logicCmd.AddCommand(logicReportCmd)

	// Global flags
	logicCmd.PersistentFlags().StringP("target", "t", "", "Target URL to test")
	logicCmd.PersistentFlags().StringP("output", "o", "text", "Output format (text, json)")
	logicCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")

	// Reset command flags
	logicResetCmd.Flags().Bool("test-all", false, "Run all password reset tests")
	logicResetCmd.Flags().Bool("test-entropy", false, "Test token entropy")
	logicResetCmd.Flags().Bool("test-host-header", false, "Test host header injection")
	logicResetCmd.Flags().Int("samples", 100, "Number of token samples for entropy analysis")
	logicResetCmd.Flags().Int("workers", 50, "Number of concurrent workers for testing")

	// Workflow command flags
	logicWorkflowCmd.Flags().Int("max-depth", 10, "Maximum workflow depth to analyze")
	logicWorkflowCmd.Flags().Bool("test-privileges", false, "Test privilege escalation paths")
	logicWorkflowCmd.Flags().Bool("follow-redirects", true, "Follow HTTP redirects")
	logicWorkflowCmd.Flags().Bool("maintain-session", true, "Maintain session state")

	// Race command flags
	logicRaceCmd.Flags().Int("workers", 20, "Number of concurrent workers")
	logicRaceCmd.Flags().Bool("test-payments", false, "Test payment race conditions")
	logicRaceCmd.Flags().Bool("test-inventory", false, "Test inventory race conditions")
	logicRaceCmd.Flags().Int("request-delay", 0, "Delay between requests (ms)")

	// MFA command flags
	logicMfaCmd.Flags().Bool("test-bypasses", false, "Test all bypass methods")
	logicMfaCmd.Flags().Bool("test-tokens", false, "Test token-based bypasses")
	logicMfaCmd.Flags().Bool("test-recovery", false, "Test recovery flow bypasses")

	// Payment command flags
	logicPaymentCmd.Flags().Bool("test-all", false, "Test all e-commerce payment logic")
	logicPaymentCmd.Flags().Bool("test-cart", false, "Test shopping cart logic")
	logicPaymentCmd.Flags().Bool("test-pricing", false, "Test pricing logic")
	logicPaymentCmd.Flags().Bool("test-coupons", false, "Test coupon logic")
	logicPaymentCmd.Flags().Bool("test-race", false, "Test race conditions")

	// Recovery command flags
	logicRecoveryCmd.Flags().Bool("test-all", false, "Test all recovery methods")
	logicRecoveryCmd.Flags().Bool("test-password-reset", false, "Test password reset recovery")
	logicRecoveryCmd.Flags().Bool("test-security-questions", false, "Test security questions")
	logicRecoveryCmd.Flags().Bool("test-sms", false, "Test SMS recovery")
	logicRecoveryCmd.Flags().Bool("test-email", false, "Test email recovery")
	logicRecoveryCmd.Flags().Bool("test-backup-codes", false, "Test backup codes")

	// All command flags
	logicAllCmd.Flags().Bool("include-business-impact", false, "Include business impact analysis")
	logicAllCmd.Flags().String("report-file", "", "Save detailed report to file")

	// Report command flags
	logicReportCmd.Flags().String("findings", "", "Load findings from JSON file")
	logicReportCmd.Flags().String("format", "html", "Report format (html, json, pdf)")
	logicReportCmd.Flags().Bool("include-business-impact", false, "Include business impact analysis")
}
