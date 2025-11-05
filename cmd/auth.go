package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/common"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/federation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/oauth2"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/saml"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/webauthn"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// authCmd represents the auth command
var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Test authentication and identity systems",
	Long: `Comprehensive authentication security testing framework for modern authentication protocols.

This command provides advanced testing capabilities for:
- SAML (including Golden SAML attacks)
- OAuth2/OIDC (including JWT analysis)
- WebAuthn/FIDO2 (including virtual authenticator attacks)
- Federation confusion testing
- Cross-protocol attack chain detection

Examples:
  shells auth discover --target https://example.com
  shells auth test --target https://example.com --protocol saml
  shells auth chain --target https://example.com
  shells auth all --target https://example.com --output json`,
}

// authDiscoverCmd discovers authentication endpoints and methods
var authDiscoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover authentication endpoints and methods",
	Long: `Discover all authentication endpoints and methods for a target.

This command will:
- Scan for SAML endpoints and metadata
- Discover OAuth2/OIDC configurations
- Find WebAuthn/FIDO2 endpoints
- Identify federation providers
- Map trust relationships

Examples:
  shells auth discover --target https://example.com
  shells auth discover --target https://example.com --verbose
  shells auth discover --target https://example.com --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		output, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if target == "" {
			return fmt.Errorf("--target is required")
		}

		// Create structured logger
		log, err := getAuthLogger(verbose)
		if err != nil {
			return fmt.Errorf("failed to initialize logger: %w", err)
		}

		log.Infow("Discovering authentication methods",
			"target", target,
			"output_format", output,
		)

		// Use comprehensive authentication discovery
		discoveryConfig := &discovery.Config{
			MaxDepth:           3,
			FollowRedirects:    true,
			MaxRedirects:       10,
			Timeout:            30 * time.Second,
			UserAgent:          "shells-auth-discovery/1.0",
			Threads:            10,
			EnableJSAnalysis:   true,
			EnableAPIDiscovery: true,
			EnablePortScanning: false,
		}

		engine := discovery.NewEngine(log, discoveryConfig)
		discoveryResult, err := engine.Discover(cmd.Context(), target)
		if err != nil {
			return fmt.Errorf("discovery failed: %w", err)
		}

		// Also run legacy discovery for federation
		crossAnalyzer := common.NewCrossProtocolAnalyzer(log)
		legacyConfig, _ := crossAnalyzer.AnalyzeTarget(target)

		domain := extractDomain(target)
		httpClient := &http.Client{
			Timeout: 30 * time.Second,
		}
		discoverer := federation.NewFederationDiscoverer(httpClient, log)
		federationResult := discoverer.DiscoverAllProviders(domain)

		// Create combined result
		result := struct {
			Target               string                                `json:"target"`
			ComprehensiveResults *discovery.DiscoveryResult            `json:"comprehensive_results"`
			LegacyProtocols      []common.AuthProtocol                 `json:"legacy_protocols,omitempty"`
			LegacyEndpoints      []common.AuthEndpoint                 `json:"legacy_endpoints,omitempty"`
			Federation           *federation.FederationDiscoveryResult `json:"federation"`
			Summary              DiscoverySummary                      `json:"summary"`
			Timestamp            time.Time                             `json:"timestamp"`
		}{
			Target:               target,
			ComprehensiveResults: discoveryResult,
			Federation:           federationResult,
			Timestamp:            time.Now(),
		}

		// Add legacy results if available
		if legacyConfig != nil {
			result.LegacyProtocols = legacyConfig.Configuration.Protocols
			result.LegacyEndpoints = legacyConfig.Configuration.Endpoints
		}

		// Generate summary combining both discovery methods
		result.Summary = DiscoverySummary{
			TotalEndpoints:      discoveryResult.TotalEndpoints + len(result.LegacyEndpoints),
			ProtocolsFound:      len(discoveryResult.Implementations),
			FederationProviders: federationResult.TotalFound,
			HasSAML:             containsAuthType(discoveryResult.Implementations, discovery.AuthTypeSAML),
			HasOAuth2:           containsAuthType(discoveryResult.Implementations, discovery.AuthTypeOAuth2),
			HasOIDC:             containsAuthType(discoveryResult.Implementations, discovery.AuthTypeOIDC),
			HasWebAuthn:         containsAuthType(discoveryResult.Implementations, discovery.AuthTypeWebAuthn),
			HasFederation:       federationResult.TotalFound > 0,
		}

		// Output results
		if output == "json" {
			jsonData, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			printComprehensiveDiscoveryResults(result)
		}

		log.Infow("Authentication discovery completed",
			"target", target,
			"total_endpoints", result.Summary.TotalEndpoints,
			"protocols_found", result.Summary.ProtocolsFound,
			"federation_providers", result.Summary.FederationProviders,
			"has_saml", result.Summary.HasSAML,
			"has_oauth2", result.Summary.HasOAuth2,
			"has_webauthn", result.Summary.HasWebAuthn,
		)

		return nil
	},
}

// authTestCmd runs comprehensive authentication tests
var authTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Run comprehensive authentication tests",
	Long: `Run comprehensive security tests against authentication systems.

This command supports testing:
- SAML (Golden SAML, XSW, signature bypass)
- OAuth2/OIDC (JWT attacks, flow vulnerabilities)
- WebAuthn/FIDO2 (virtual authenticator attacks)
- Federation (confused deputy, trust issues)

Examples:
  shells auth test --target https://example.com --protocol saml
  shells auth test --target https://example.com --protocol oauth2
  shells auth test --target https://example.com --protocol webauthn
  shells auth test --target https://example.com --protocol all`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		protocol, _ := cmd.Flags().GetString("protocol")
		output, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if target == "" {
			return fmt.Errorf("--target is required")
		}

		if protocol == "" {
			protocol = "all"
		}

		// Create logger
		logger := NewLogger(verbose)

		fmt.Printf("🧪 Running authentication tests for: %s\n", target)
		if protocol != "all" {
			fmt.Printf(" Protocol: %s\n", strings.ToUpper(protocol))
		}
		fmt.Println()

		var report *common.AuthReport
		var err error

		// Run tests based on protocol
		switch protocol {
		case "saml":
			report, err = runSAMLTests(target, logger)
		case "oauth2":
			report, err = runOAuth2Tests(target, logger)
		case "webauthn":
			report, err = runWebAuthnTests(target, logger)
		case "all":
			report, err = runAllTests(target, logger)
		default:
			return fmt.Errorf("unknown protocol '%s'. Supported: saml, oauth2, webauthn, all", protocol)
		}

		if err != nil {
			return fmt.Errorf("authentication tests failed: %w", err)
		}

		// Save results to database
		var dbScanType types.ScanType
		switch protocol {
		case "saml":
			dbScanType = types.ScanTypeSAML
		case "oauth2":
			dbScanType = types.ScanTypeOAuth2
		case "webauthn":
			dbScanType = types.ScanTypeWebAuthn
		default:
			dbScanType = types.ScanTypeAuth
		}

		if err := saveAuthResultsToDatabase(target, report, dbScanType); err != nil {
			fmt.Printf("Warning: Failed to save results to database: %v\n", err)
		} else {
			fmt.Printf(" Results saved to database\n")
		}

		// Output results
		if output == "json" {
			jsonData, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			printTestResults(report)
		}
		return nil
	},
}

// authChainCmd finds authentication bypass chains
var authChainCmd = &cobra.Command{
	Use:   "chain",
	Short: "Find authentication bypass chains",
	Long: `Find authentication bypass chains and attack paths.

This command analyzes multiple authentication methods to find potential
attack chains that could lead to authentication bypass. It looks for:
- Cross-protocol vulnerabilities
- Authentication downgrade paths
- Federation confusion attacks
- Multi-step bypass scenarios

Examples:
  shells auth chain --target https://example.com
  shells auth chain --target https://example.com --max-depth 5
  shells auth chain --target https://example.com --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		maxDepth, _ := cmd.Flags().GetInt("max-depth")
		output, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if target == "" {
			return fmt.Errorf("--target is required")
		}

		if maxDepth <= 0 {
			maxDepth = 5
		}

		// Create logger
		logger := NewLogger(verbose)

		fmt.Printf("🔗 Finding authentication bypass chains for: %s\n", target)
		fmt.Printf(" Maximum chain depth: %d\n\n", maxDepth)

		// Analyze target for vulnerabilities
		crossAnalyzer := common.NewCrossProtocolAnalyzer(logger)
		config, err := crossAnalyzer.AnalyzeTarget(target)
		if err != nil {
			return fmt.Errorf("target analysis failed: %w", err)
		}

		// Find attack chains
		chainAnalyzer := common.NewAuthChainAnalyzer(logger)
		chains := chainAnalyzer.FindBypassChains(config.Configuration, config.Vulnerabilities)

		// Create result
		result := struct {
			Target    string               `json:"target"`
			Chains    []common.AttackChain `json:"chains"`
			Summary   ChainSummary         `json:"summary"`
			Timestamp time.Time            `json:"timestamp"`
		}{
			Target:    target,
			Chains:    chains,
			Timestamp: time.Now(),
		}

		// Generate summary
		result.Summary = ChainSummary{
			TotalChains:       len(chains),
			CriticalChains:    countChainsBySeverity(chains, "CRITICAL"),
			HighChains:        countChainsBySeverity(chains, "HIGH"),
			MediumChains:      countChainsBySeverity(chains, "MEDIUM"),
			LowChains:         countChainsBySeverity(chains, "LOW"),
			LongestChain:      getLongestChain(chains),
			ProtocolsInvolved: getProtocolsInvolved(chains),
		}

		// Output results
		if output == "json" {
			jsonData, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			printChainResults(result)
		}
		return nil
	},
}

// authAllCmd runs all authentication tests
var authAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Run all authentication tests and analysis",
	Long: `Run comprehensive authentication security analysis including:
- Discovery of all authentication methods
- Security testing of each protocol
- Attack chain analysis
- Federation vulnerability assessment
- Comprehensive reporting

This is the most thorough authentication security assessment.

Examples:
  shells auth all --target https://example.com
  shells auth all --target https://example.com --output json
  shells auth all --target https://example.com --save-report report.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		output, _ := cmd.Flags().GetString("output")
		saveReport, _ := cmd.Flags().GetString("save-report")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if target == "" {
			return fmt.Errorf("--target is required")
		}

		// Create logger
		logger := NewLogger(verbose)

		fmt.Printf(" Running comprehensive authentication security analysis\n")
		fmt.Printf(" Target: %s\n\n", target)

		// Run comprehensive analysis
		report, err := runComprehensiveAnalysis(target, logger)
		if err != nil {
			return fmt.Errorf("comprehensive analysis failed: %w", err)
		}

		// Save results to database
		if err := saveAuthResultsToDatabase(target, report, types.ScanTypeAuth); err != nil {
			fmt.Printf("Warning: Failed to save results to database: %v\n", err)
		} else {
			fmt.Printf(" Results saved to database\n")
		}

		// Save report if requested
		if saveReport != "" {
			if err := saveReportToFile(report, saveReport); err != nil {
				fmt.Printf("Warning: Failed to save report: %v\n", err)
			} else {
				fmt.Printf("📄 Report saved to: %s\n", saveReport)
			}
		}

		// Output results
		if output == "json" {
			jsonData, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			printComprehensiveResults(report)
		}
		return nil
	},
}

// Helper functions and types

type DiscoverySummary struct {
	TotalEndpoints      int  `json:"total_endpoints"`
	ProtocolsFound      int  `json:"protocols_found"`
	FederationProviders int  `json:"federation_providers"`
	HasSAML             bool `json:"has_saml"`
	HasOAuth2           bool `json:"has_oauth2"`
	HasOIDC             bool `json:"has_oidc"`
	HasWebAuthn         bool `json:"has_webauthn"`
	HasFederation       bool `json:"has_federation"`
}

type ChainSummary struct {
	TotalChains       int                   `json:"total_chains"`
	CriticalChains    int                   `json:"critical_chains"`
	HighChains        int                   `json:"high_chains"`
	MediumChains      int                   `json:"medium_chains"`
	LowChains         int                   `json:"low_chains"`
	LongestChain      int                   `json:"longest_chain"`
	ProtocolsInvolved []common.AuthProtocol `json:"protocols_involved"`
}

// Test runner functions

func runSAMLTests(target string, logger common.Logger) (*common.AuthReport, error) {
	scanner := saml.NewSAMLScanner(logger)
	return scanner.Scan(target, map[string]interface{}{})
}

func runOAuth2Tests(target string, logger common.Logger) (*common.AuthReport, error) {
	scanner := oauth2.NewOAuth2Scanner(logger)
	return scanner.Scan(target, map[string]interface{}{})
}

func runWebAuthnTests(target string, logger common.Logger) (*common.AuthReport, error) {
	scanner := webauthn.NewWebAuthnScanner(logger)
	return scanner.Scan(target, map[string]interface{}{})
}

func runAllTests(target string, logger common.Logger) (*common.AuthReport, error) {
	crossAnalyzer := common.NewCrossProtocolAnalyzer(logger)
	return crossAnalyzer.AnalyzeTarget(target)
}

func runComprehensiveAnalysis(target string, logger common.Logger) (*common.AuthReport, error) {
	// This would implement comprehensive analysis including all protocols
	return runAllTests(target, logger)
}

// Output functions

func printDiscoveryResults(result struct {
	Target     string                                `json:"target"`
	Protocols  []common.AuthProtocol                 `json:"protocols"`
	Endpoints  []common.AuthEndpoint                 `json:"endpoints"`
	Federation *federation.FederationDiscoveryResult `json:"federation"`
	Summary    DiscoverySummary                      `json:"summary"`
	Timestamp  time.Time                             `json:"timestamp"`
}) {
	fmt.Printf(" Authentication Discovery Results\n")
	fmt.Printf("═══════════════════════════════════════\n\n")

	fmt.Printf(" Target: %s\n", result.Target)
	fmt.Printf("🕐 Scanned: %s\n\n", result.Timestamp.Format("2006-01-02 15:04:05"))

	fmt.Printf(" Summary:\n")
	fmt.Printf("  • Total endpoints: %d\n", result.Summary.TotalEndpoints)
	fmt.Printf("  • Protocols found: %d\n", result.Summary.ProtocolsFound)
	fmt.Printf("  • Federation providers: %d\n", result.Summary.FederationProviders)
	fmt.Println()

	fmt.Printf(" Protocols Detected:\n")
	if result.Summary.HasSAML {
		fmt.Printf("   SAML\n")
	}
	if result.Summary.HasOAuth2 {
		fmt.Printf("   OAuth2\n")
	}
	if result.Summary.HasOIDC {
		fmt.Printf("   OIDC\n")
	}
	if result.Summary.HasWebAuthn {
		fmt.Printf("   WebAuthn/FIDO2\n")
	}
	if result.Summary.HasFederation {
		fmt.Printf("   Federation\n")
	}

	if len(result.Protocols) == 0 {
		fmt.Printf("   No authentication protocols detected\n")
	}
	fmt.Println()

	if len(result.Endpoints) > 0 {
		fmt.Printf("🔗 Endpoints Found:\n")
		for _, endpoint := range result.Endpoints {
			fmt.Printf("  • %s [%s] - %s\n", endpoint.URL, endpoint.Method, endpoint.Protocol)
		}
		fmt.Println()
	}

	if result.Federation != nil && result.Federation.TotalFound > 0 {
		fmt.Printf("🤝 Federation Providers:\n")
		for _, provider := range result.Federation.Providers {
			fmt.Printf("  • %s [%s] - %s\n", provider.Name, provider.Type, provider.MetadataURL)
		}
		fmt.Println()
	}
}

func printTestResults(report *common.AuthReport) {
	fmt.Printf("🧪 Authentication Test Results\n")
	fmt.Printf("═══════════════════════════════════════\n\n")

	fmt.Printf(" Target: %s\n", report.Target)
	fmt.Printf("⏱️  Duration: %s\n\n", report.EndTime.Sub(report.StartTime))

	fmt.Printf(" Summary:\n")
	fmt.Printf("  • Total vulnerabilities: %d\n", report.Summary.TotalVulnerabilities)
	fmt.Printf("  • Critical: %d\n", report.Summary.BySeverity["CRITICAL"])
	fmt.Printf("  • High: %d\n", report.Summary.BySeverity["HIGH"])
	fmt.Printf("  • Medium: %d\n", report.Summary.BySeverity["MEDIUM"])
	fmt.Printf("  • Low: %d\n", report.Summary.BySeverity["LOW"])
	fmt.Printf("  • Attack chains: %d\n", report.Summary.AttackChains)
	fmt.Println()

	if len(report.Vulnerabilities) > 0 {
		fmt.Printf(" Vulnerabilities Found:\n")
		for _, vuln := range report.Vulnerabilities {
			severityIcon := getSeverityIcon(vuln.Severity)
			fmt.Printf("  %s [%s] %s\n", severityIcon, vuln.Severity, vuln.Title)
			fmt.Printf("    Protocol: %s\n", vuln.Protocol)
			fmt.Printf("    Impact: %s\n", vuln.Impact)
			fmt.Println()
		}
	} else {
		fmt.Printf(" No vulnerabilities found\n\n")
	}
}

func printChainResults(result struct {
	Target    string               `json:"target"`
	Chains    []common.AttackChain `json:"chains"`
	Summary   ChainSummary         `json:"summary"`
	Timestamp time.Time            `json:"timestamp"`
}) {
	fmt.Printf("🔗 Attack Chain Analysis Results\n")
	fmt.Printf("═══════════════════════════════════════\n\n")

	fmt.Printf(" Target: %s\n", result.Target)
	fmt.Printf("🕐 Analyzed: %s\n\n", result.Timestamp.Format("2006-01-02 15:04:05"))

	fmt.Printf(" Summary:\n")
	fmt.Printf("  • Total chains: %d\n", result.Summary.TotalChains)
	fmt.Printf("  • Critical: %d\n", result.Summary.CriticalChains)
	fmt.Printf("  • High: %d\n", result.Summary.HighChains)
	fmt.Printf("  • Medium: %d\n", result.Summary.MediumChains)
	fmt.Printf("  • Low: %d\n", result.Summary.LowChains)
	fmt.Printf("  • Longest chain: %d steps\n", result.Summary.LongestChain)
	fmt.Println()

	if len(result.Chains) > 0 {
		fmt.Printf("⛓️  Attack Chains Found:\n")
		for i, chain := range result.Chains {
			severityIcon := getSeverityIcon(chain.Severity)
			fmt.Printf("  %d. %s [%s] %s\n", i+1, severityIcon, chain.Severity, chain.Name)
			fmt.Printf("     Impact: %s\n", chain.Impact)
			fmt.Printf("     Steps: %d\n", len(chain.Steps))

			for j, step := range chain.Steps {
				statusIcon := ""
				if !step.Success {
					statusIcon = ""
				}
				fmt.Printf("       %d. %s [%s] %s\n", j+1, statusIcon, step.Protocol, step.Description)
			}
			fmt.Println()
		}
	} else {
		fmt.Printf(" No attack chains found\n\n")
	}
}

func printComprehensiveResults(report *common.AuthReport) {
	fmt.Printf(" Comprehensive Authentication Analysis\n")
	fmt.Printf("═══════════════════════════════════════\n\n")

	printTestResults(report)

	if len(report.AttackChains) > 0 {
		fmt.Printf("⛓️  Attack Chains:\n")
		for i, chain := range report.AttackChains {
			severityIcon := getSeverityIcon(chain.Severity)
			fmt.Printf("  %d. %s [%s] %s\n", i+1, severityIcon, chain.Severity, chain.Name)
			fmt.Printf("     Impact: %s\n", chain.Impact)
			fmt.Printf("     Steps: %d\n", len(chain.Steps))
		}
		fmt.Println()
	}

	fmt.Printf("🏁 Analysis Complete\n")
	fmt.Printf("Run 'shells auth --help' for more specific testing options.\n")
}

// Helper functions

func saveAuthResultsToDatabase(target string, report *common.AuthReport, scanType types.ScanType) error {
	store := GetStore()
	if store == nil {
		return fmt.Errorf("database not initialized")
	}

	// Create scan request
	scanRequest := &types.ScanRequest{
		ID:          uuid.New().String(),
		Target:      target,
		Type:        scanType,
		Status:      types.ScanStatusCompleted,
		CreatedAt:   report.StartTime,
		StartedAt:   &report.StartTime,
		CompletedAt: &report.EndTime,
	}

	// Save scan to database
	if err := store.SaveScan(GetContext(), scanRequest); err != nil {
		return fmt.Errorf("failed to save scan: %w", err)
	}

	// Convert vulnerabilities to findings
	var findings []types.Finding
	for _, vuln := range report.Vulnerabilities {
		// Map severity
		severity := types.SeverityInfo
		switch vuln.Severity {
		case "CRITICAL":
			severity = types.SeverityCritical
		case "HIGH":
			severity = types.SeverityHigh
		case "MEDIUM":
			severity = types.SeverityMedium
		case "LOW":
			severity = types.SeverityLow
		}

		// Convert evidence to string
		evidenceStr := ""
		if len(vuln.Evidence) > 0 {
			evidenceData, _ := json.Marshal(vuln.Evidence)
			evidenceStr = string(evidenceData)
		}

		finding := types.Finding{
			ID:          uuid.New().String(),
			ScanID:      scanRequest.ID,
			Tool:        string(vuln.Protocol),
			Type:        "authentication_vulnerability",
			Severity:    severity,
			Title:       vuln.Title,
			Description: vuln.Description,
			Evidence:    evidenceStr,
			Solution:    vuln.Remediation.Description,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		findings = append(findings, finding)
	}

	// Save findings to database
	if len(findings) > 0 {
		if err := store.SaveFindings(GetContext(), findings); err != nil {
			return fmt.Errorf("failed to save findings: %w", err)
		}
	}

	return nil
}

func printComprehensiveDiscoveryResults(result struct {
	Target               string                                `json:"target"`
	ComprehensiveResults *discovery.DiscoveryResult            `json:"comprehensive_results"`
	LegacyProtocols      []common.AuthProtocol                 `json:"legacy_protocols,omitempty"`
	LegacyEndpoints      []common.AuthEndpoint                 `json:"legacy_endpoints,omitempty"`
	Federation           *federation.FederationDiscoveryResult `json:"federation"`
	Summary              DiscoverySummary                      `json:"summary"`
	Timestamp            time.Time                             `json:"timestamp"`
}) {
	fmt.Printf(" Comprehensive Authentication Discovery Results\n")
	fmt.Printf("═══════════════════════════════════════════════════\n\n")

	fmt.Printf(" Target: %s\n", result.Target)
	fmt.Printf("🕐 Scanned: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("⏱️  Discovery Time: %s\n\n", result.ComprehensiveResults.DiscoveryTime)

	// Print comprehensive results
	fmt.Printf(" Discovery Summary:\n")
	fmt.Printf("  • Authentication Implementations: %d\n", len(result.ComprehensiveResults.Implementations))
	fmt.Printf("  • Total Endpoints: %d\n", result.ComprehensiveResults.TotalEndpoints)
	fmt.Printf("  • Federation Providers: %d\n", result.Summary.FederationProviders)
	fmt.Printf("  • Risk Score: %.1f/10\n\n", result.ComprehensiveResults.RiskScore)

	// Print discovered implementations
	if len(result.ComprehensiveResults.Implementations) > 0 {
		fmt.Printf(" Authentication Implementations:\n")
		for i, impl := range result.ComprehensiveResults.Implementations {
			fmt.Printf("  %d. %s\n", i+1, impl.Name)
			fmt.Printf("     Type: %s\n", impl.Type)
			fmt.Printf("     Domain: %s\n", impl.Domain)
			fmt.Printf("     Endpoints: %d\n", len(impl.Endpoints))

			if len(impl.SecurityFeatures) > 0 {
				fmt.Printf("      Features: %s\n", strings.Join(impl.SecurityFeatures[:min(3, len(impl.SecurityFeatures))], ", "))
			}

			if len(impl.Vulnerabilities) > 0 {
				fmt.Printf("       Vulnerabilities: %d found\n", len(impl.Vulnerabilities))
			}
			fmt.Println()
		}
	}

	// Print protocols detected
	fmt.Printf(" Protocols Detected:\n")
	if result.Summary.HasSAML {
		fmt.Printf("   SAML\n")
	}
	if result.Summary.HasOAuth2 {
		fmt.Printf("   OAuth2\n")
	}
	if result.Summary.HasOIDC {
		fmt.Printf("   OpenID Connect\n")
	}
	if result.Summary.HasWebAuthn {
		fmt.Printf("   WebAuthn/FIDO2\n")
	}
	if result.Summary.HasFederation {
		fmt.Printf("   Federation\n")
	}
	fmt.Println()

	// Print recommendations
	if len(result.ComprehensiveResults.Recommendations) > 0 {
		fmt.Printf("💡 Recommendations:\n")
		for _, rec := range result.ComprehensiveResults.Recommendations {
			fmt.Printf("  • %s\n", rec)
		}
		fmt.Println()
	}

	// Print federation details if available
	if result.Federation != nil && result.Federation.TotalFound > 0 {
		fmt.Printf("🏢 Federation Providers:\n")
		for _, provider := range result.Federation.Providers {
			fmt.Printf("  • %s: %d endpoints\n", provider.Name, len(provider.Endpoints))
		}
	}
}

func contains(slice []common.AuthProtocol, item common.AuthProtocol) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsAuthType(implementations []discovery.AuthImplementation, authType discovery.AuthType) bool {
	for _, impl := range implementations {
		if impl.Type == authType {
			return true
		}
	}
	return false
}

func extractDomain(url string) string {
	// Simple domain extraction
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	return url
}

func countChainsBySeverity(chains []common.AttackChain, severity string) int {
	count := 0
	for _, chain := range chains {
		if chain.Severity == severity {
			count++
		}
	}
	return count
}

func getLongestChain(chains []common.AttackChain) int {
	longest := 0
	for _, chain := range chains {
		if len(chain.Steps) > longest {
			longest = len(chain.Steps)
		}
	}
	return longest
}

func getProtocolsInvolved(chains []common.AttackChain) []common.AuthProtocol {
	protocolMap := make(map[common.AuthProtocol]bool)
	for _, chain := range chains {
		for _, step := range chain.Steps {
			protocolMap[step.Protocol] = true
		}
	}

	protocols := make([]common.AuthProtocol, 0, len(protocolMap))
	for protocol := range protocolMap {
		protocols = append(protocols, protocol)
	}
	return protocols
}

func getSeverityIcon(severity string) string {
	switch severity {
	case "CRITICAL":
		return ""
	case "HIGH":
		return "🟠"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return ""
	default:
		return "⚪"
	}
}

func saveReportToFile(report *common.AuthReport, filename string) error {
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, jsonData, 0644)
}

// getAuthLogger creates a properly configured logger for auth commands
// Uses console format for user-friendly output while maintaining structure
func getAuthLogger(verbose bool) (*logger.Logger, error) {
	logLevel := "info"
	if verbose {
		logLevel = "debug"
	}

	log, err := logger.New(config.LoggerConfig{
		Level:  logLevel,
		Format: "console", // Console format supports emojis and is human-friendly
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	return log.WithComponent("auth"), nil
}

func init() {
	// Add auth command to root
	rootCmd.AddCommand(authCmd)

	// Add subcommands
	authCmd.AddCommand(authDiscoverCmd)
	authCmd.AddCommand(authTestCmd)
	authCmd.AddCommand(authChainCmd)
	authCmd.AddCommand(authAllCmd)

	// Global flags
	authCmd.PersistentFlags().StringP("target", "t", "", "Target URL to test")
	authCmd.PersistentFlags().StringP("output", "o", "text", "Output format (text, json)")
	authCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")

	// Discover flags
	authDiscoverCmd.Flags().StringP("target", "t", "", "Target URL to discover")
	authDiscoverCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")
	authDiscoverCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")

	// Test flags
	authTestCmd.Flags().StringP("target", "t", "", "Target URL to test")
	authTestCmd.Flags().StringP("protocol", "p", "all", "Protocol to test (saml, oauth2, webauthn, all)")
	authTestCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")
	authTestCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")

	// Chain flags
	authChainCmd.Flags().StringP("target", "t", "", "Target URL to analyze")
	authChainCmd.Flags().IntP("max-depth", "d", 5, "Maximum chain depth")
	authChainCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")
	authChainCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")

	// All flags
	authAllCmd.Flags().StringP("target", "t", "", "Target URL to analyze")
	authAllCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")
	authAllCmd.Flags().StringP("save-report", "s", "", "Save report to file")
	authAllCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")
}
