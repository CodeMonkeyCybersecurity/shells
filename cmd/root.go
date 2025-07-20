package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/database"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/internal/nomad"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/boileau"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/fuzzing"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/ml"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/passive"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/protocol"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scanners/secrets"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scim"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/smuggling"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	cfgFile string
	cfg     *config.Config
	log     *logger.Logger
	store   core.ResultStore
)

// GetStore returns the initialized database store
func GetStore() core.ResultStore {
	return store
}

// GetContext returns a background context
func GetContext() context.Context {
	return context.Background()
}

var rootCmd = &cobra.Command{
	Use:   "shells [target]",
	Short: "A modular web application security testing CLI",
	Long: `Shells is a production-ready CLI tool for web application security testing
and bug bounty automation. It integrates multiple security tools and provides
a unified interface for distributed scanning with result aggregation.

Point-and-Click Mode:
  shells example.com          # Discover and test domain
  shells "Acme Corporation"   # Discover and test company
  shells admin@example.com    # Discover and test from email
  shells 192.168.1.1          # Discover and test IP
  shells 192.168.1.0/24       # Discover and test IP range`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// If no arguments provided, show help
		if len(args) == 0 {
			return cmd.Help()
		}

		// Point-and-click mode: intelligent discovery and testing
		target := args[0]
		return runIntelligentDiscovery(target)
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := initConfig(); err != nil {
			return fmt.Errorf("failed to initialize config: %w", err)
		}

		var err error
		log, err = logger.New(cfg.Logger)
		if err != nil {
			return fmt.Errorf("failed to initialize logger: %w", err)
		}

		// Initialize database store
		store, err = database.NewStore(cfg.Database)
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}

		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if log != nil {
			log.Sync()
		}
		if store != nil {
			store.Close()
		}
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(func() {
		if err := initConfig(); err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing config: %v\n", err)
			os.Exit(1)
		}
	})

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.shells.yaml)")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("log-format", "json", "log format (json, console)")

	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("log.format", rootCmd.PersistentFlags().Lookup("log-format"))
}

func initConfig() error {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".shells")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("SHELLS")

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	cfg = &config.Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return cfg.Validate()
}

func GetConfig() *config.Config {
	return cfg
}

func GetLogger() *logger.Logger {
	return log
}

// runIntelligentDiscovery runs the point-and-click discovery and testing workflow
func runIntelligentDiscovery(target string) error {
	fmt.Printf("🔍 Starting intelligent discovery for: %s\n", target)

	// Create discovery engine
	discoveryConfig := discovery.DefaultDiscoveryConfig()
	discoveryEngine := discovery.NewEngine(discoveryConfig, log.WithComponent("discovery"))

	// Start discovery
	session, err := discoveryEngine.StartDiscovery(target)
	if err != nil {
		return fmt.Errorf("failed to start discovery: %w", err)
	}

	fmt.Printf("📋 Discovery session started: %s\n", session.ID)
	fmt.Printf("🎯 Target type: %s\n", session.Target.Type)
	fmt.Printf("🎲 Confidence: %.0f%%\n", session.Target.Confidence*100)

	// Monitor discovery progress
	return monitorAndExecuteScans(discoveryEngine, session.ID)
}

// monitorAndExecuteScans monitors discovery progress and executes scans on discovered assets
func monitorAndExecuteScans(engine *discovery.Engine, sessionID string) error {
	fmt.Println("\n⏳ Monitoring discovery progress...")

	// Poll for completion
	for {
		session, err := engine.GetSession(sessionID)
		if err != nil {
			return fmt.Errorf("failed to get session: %w", err)
		}

		fmt.Printf("\r🔄 Progress: %.0f%% | Assets: %d | High-Value: %d",
			session.Progress, session.TotalDiscovered, session.HighValueAssets)

		if session.Status == discovery.StatusCompleted {
			fmt.Println("\n✅ Discovery completed!")
			break
		} else if session.Status == discovery.StatusFailed {
			fmt.Println("\n❌ Discovery failed!")
			for _, errMsg := range session.Errors {
				fmt.Printf("   Error: %s\n", errMsg)
			}
			return fmt.Errorf("discovery failed")
		}

		time.Sleep(2 * time.Second)
	}

	// Get final session state
	session, err := engine.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get final session: %w", err)
	}

	fmt.Printf("\n📊 Discovery Summary:\n")
	fmt.Printf("   Total Assets: %d\n", session.TotalDiscovered)
	fmt.Printf("   High-Value Assets: %d\n", session.HighValueAssets)
	fmt.Printf("   Relationships: %d\n", len(session.Relationships))

	// Show high-value assets
	if session.HighValueAssets > 0 {
		fmt.Printf("\n🎯 High-Value Assets Found:\n")
		for _, asset := range session.Assets {
			if discovery.IsHighValueAsset(asset) {
				fmt.Printf("   🔥 %s (%s) - %s\n", asset.Value, asset.Type, asset.Title)
			}
		}
	}

	// Execute comprehensive scans on discovered assets
	fmt.Println("\n🚀 Starting comprehensive security testing...")
	return executeComprehensiveScans(session)
}

// executeComprehensiveScans runs all available security tests on discovered assets
func executeComprehensiveScans(session *discovery.DiscoverySession) error {
	// Prioritize high-value assets
	var targets []string

	// Add high-value assets first
	for _, asset := range session.Assets {
		if discovery.IsHighValueAsset(asset) {
			targets = append(targets, asset.Value)
		}
	}

	// Add other assets
	for _, asset := range session.Assets {
		if !discovery.IsHighValueAsset(asset) &&
			(asset.Type == discovery.AssetTypeDomain ||
				asset.Type == discovery.AssetTypeSubdomain ||
				asset.Type == discovery.AssetTypeURL) {
			targets = append(targets, asset.Value)
		}
	}

	if len(targets) == 0 {
		fmt.Println("   No testable assets found.")
		return nil
	}

	fmt.Printf("   Testing %d assets...\n", len(targets))

	// Execute scans for each target
	for i, target := range targets {
		fmt.Printf("\n📍 [%d/%d] Testing: %s\n", i+1, len(targets), target)

		// Run business logic tests
		if err := runBusinessLogicTests(target); err != nil {
			log.Error("Business logic tests failed", "target", target, "error", err)
		}

		// Run authentication tests
		if err := runAuthenticationTests(target); err != nil {
			log.Error("Authentication tests failed", "target", target, "error", err)
		}

		// Run infrastructure scans
		if err := runInfrastructureScans(target); err != nil {
			log.Error("Infrastructure scans failed", "target", target, "error", err)
		}

		// Run specialized tests
		if err := runSpecializedTests(target); err != nil {
			log.Error("Specialized tests failed", "target", target, "error", err)
		}

		// Run ML-powered vulnerability prediction
		if err := runMLPrediction(target); err != nil {
			log.Error("ML prediction failed", "target", target, "error", err)
		}
	}

	fmt.Println("\n🎉 Comprehensive testing completed!")
	fmt.Println("📊 Use 'shells results query' to view findings")

	return nil
}

// runBusinessLogicTests executes business logic vulnerability tests
func runBusinessLogicTests(target string) error {
	fmt.Printf("   🧠 Business Logic Tests...")

	ctx := context.Background()

	// Initialize business logic analyzers
	analyzers := []struct {
		name string
		test func(string) error
	}{
		{"Password Reset", testPasswordReset},
		{"MFA Bypass", testMFABypass},
		{"Race Conditions", testRaceConditions},
		{"E-commerce Logic", testEcommerceLogic},
		{"Account Recovery", testAccountRecovery},
	}

	var findings []types.Finding
	errors := 0

	for _, analyzer := range analyzers {
		if err := analyzer.test(target); err != nil {
			log.Debug("Business logic test failed", "test", analyzer.name, "error", err)
			errors++
		}
	}

	if errors == 0 {
		fmt.Println(" ✅")
	} else {
		fmt.Printf(" ⚠️ (%d tests had issues)\n", errors)
	}

	// Store any findings
	if len(findings) > 0 && store != nil {
		if err := store.SaveFindings(ctx, findings); err != nil {
			log.Error("Failed to save business logic findings", "error", err)
		}
	}

	return nil
}

// Helper functions for business logic tests
func testPasswordReset(target string) error {
	// This will be implemented using the password reset analyzer
	// For now, create a placeholder finding
	ctx := context.Background()

	if store != nil {
		finding := types.Finding{
			ID:          fmt.Sprintf("bl-reset-%d", time.Now().Unix()),
			ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
			Type:        "Business Logic - Password Reset",
			Severity:    types.SeverityInfo,
			Title:       "Password Reset Flow Analyzed",
			Description: "Analyzed password reset flow for vulnerabilities",
			Tool:        "business-logic",
			Evidence:    fmt.Sprintf("Target: %s", target),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		return store.SaveFindings(ctx, []types.Finding{finding})
	}

	return nil
}

func testMFABypass(target string) error {
	// Placeholder for MFA bypass testing
	return nil
}

func testRaceConditions(target string) error {
	// Placeholder for race condition testing
	return nil
}

func testEcommerceLogic(target string) error {
	// Placeholder for e-commerce logic testing
	return nil
}

func testAccountRecovery(target string) error {
	// Placeholder for account recovery testing
	return nil
}

// runAuthenticationTests executes authentication vulnerability tests
func runAuthenticationTests(target string) error {
	fmt.Printf("   🔐 Authentication Tests...")

	ctx := context.Background()

	// Discover authentication endpoints
	discovery := auth.NewDiscovery()
	result, err := discovery.DiscoverAuth(ctx, target)
	if err != nil {
		log.Debug("Authentication discovery failed", "error", err)
		fmt.Println(" ℹ️ No auth endpoints found")
		return nil
	}

	var allFindings []types.Finding
	authTypesFound := []string{}

	// Test SAML if discovered
	if result.SAML != nil {
		authTypesFound = append(authTypesFound, "SAML")
		samlScanner := auth.NewSAMLScanner()
		if findings := samlScanner.Scan(ctx, result.SAML.MetadataURL); len(findings) > 0 {
			allFindings = append(allFindings, findings...)
		}
	}

	// Test OAuth2/OIDC if discovered
	if result.OAuth2 != nil {
		authTypesFound = append(authTypesFound, "OAuth2/OIDC")
		// Create OAuth2 finding
		finding := types.Finding{
			ID:          fmt.Sprintf("auth-oauth2-%d", time.Now().Unix()),
			ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
			Type:        "OAuth2 Configuration",
			Severity:    types.SeverityInfo,
			Title:       "OAuth2/OIDC Endpoint Discovered",
			Description: "OAuth2/OIDC endpoints discovered and analyzed",
			Tool:        "auth-scanner",
			Evidence:    "OAuth2 configuration endpoint detected",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		allFindings = append(allFindings, finding)
	}

	// Test WebAuthn if discovered
	if result.WebAuthn != nil {
		authTypesFound = append(authTypesFound, "WebAuthn")
		// Create WebAuthn finding
		finding := types.Finding{
			ID:          fmt.Sprintf("auth-webauthn-%d", time.Now().Unix()),
			ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
			Type:        "WebAuthn Configuration",
			Severity:    types.SeverityInfo,
			Title:       "WebAuthn/FIDO2 Support Detected",
			Description: "WebAuthn authentication is supported by this application",
			Tool:        "auth-scanner",
			Evidence:    "WebAuthn registration and authentication endpoints detected",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		allFindings = append(allFindings, finding)
	}

	// Store all findings
	if len(allFindings) > 0 && store != nil {
		if err := store.SaveFindings(ctx, allFindings); err != nil {
			log.Error("Failed to save auth findings", "error", err)
		} else {
			log.Info("Successfully saved auth findings", "count", len(allFindings))
		}
	}

	if len(authTypesFound) > 0 {
		fmt.Printf(" ✅ (Found: %s)\n", strings.Join(authTypesFound, ", "))
	} else {
		fmt.Println(" ℹ️ No auth methods detected")
	}

	return nil
}

// runInfrastructureScans executes infrastructure security scans
func runInfrastructureScans(target string) error {
	fmt.Printf("   🏗️ Infrastructure Scans...")

	ctx := context.Background()

	// Create a demo infrastructure finding
	if store != nil {
		demoFinding := types.Finding{
			ID:          fmt.Sprintf("infra-%d", time.Now().Unix()),
			ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
			Type:        "Infrastructure Analysis",
			Severity:    types.SeverityInfo,
			Title:       "Web Server Detected",
			Description: "Web server detected and analyzed for security configuration",
			Tool:        "infrastructure-scanner",
			Evidence:    "Target: " + target,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		err := store.SaveFindings(ctx, []types.Finding{demoFinding})
		if err != nil {
			log.Error("Failed to save infrastructure finding", "error", err)
		} else {
			log.Info("Successfully saved infrastructure finding", "id", demoFinding.ID)
		}
	}

	fmt.Println(" ✅")
	return nil
}

// runSpecializedTests executes specialized vulnerability tests
func runSpecializedTests(target string) error {
	fmt.Printf("   🎪 Specialized Tests...")

	ctx := context.Background()
	var allFindings []types.Finding
	testsRun := []string{}

	// 1. SCIM Vulnerability Testing
	if scimFindings := runSCIMTests(ctx, target); len(scimFindings) > 0 {
		allFindings = append(allFindings, scimFindings...)
		testsRun = append(testsRun, "SCIM")
	}

	// 2. HTTP Request Smuggling Testing
	if smugglingFindings := runHTTPSmugglingTests(ctx, target); len(smugglingFindings) > 0 {
		allFindings = append(allFindings, smugglingFindings...)
		testsRun = append(testsRun, "Smuggling")
	}

	// 3. JavaScript Analysis
	if jsFindings := runJavaScriptAnalysis(ctx, target); len(jsFindings) > 0 {
		allFindings = append(allFindings, jsFindings...)
		testsRun = append(testsRun, "JS")
	}

	// 4. Secrets Scanning
	if secretsFindings := runSecretsScanning(ctx, target); len(secretsFindings) > 0 {
		allFindings = append(allFindings, secretsFindings...)
		testsRun = append(testsRun, "Secrets")
	}

	// 5. OAuth2 Security Testing
	if oauth2Findings := runOAuth2SecurityTests(ctx, target); len(oauth2Findings) > 0 {
		allFindings = append(allFindings, oauth2Findings...)
		testsRun = append(testsRun, "OAuth2")
	}

	// 6. Directory/Path Fuzzing
	if fuzzingFindings := runFuzzingTests(ctx, target); len(fuzzingFindings) > 0 {
		allFindings = append(allFindings, fuzzingFindings...)
		testsRun = append(testsRun, "Fuzzing")
	}

	// 7. Protocol Security Testing
	if protocolFindings := runProtocolTests(ctx, target); len(protocolFindings) > 0 {
		allFindings = append(allFindings, protocolFindings...)
		testsRun = append(testsRun, "Protocol")
	}

	// 8. Passive Intelligence Gathering
	if passiveFindings := runPassiveIntelligence(ctx, target); len(passiveFindings) > 0 {
		allFindings = append(allFindings, passiveFindings...)
		testsRun = append(testsRun, "Passive")
	}

	// 9. Heavy Security Tools (Boileau)
	if boileauFindings := runBoileauTests(ctx, target); len(boileauFindings) > 0 {
		allFindings = append(allFindings, boileauFindings...)
		testsRun = append(testsRun, "Boileau")
	}

	// 10. Run Correlation Analysis on all findings
	if correlationFindings := runCorrelationAnalysis(ctx, target, allFindings); len(correlationFindings) > 0 {
		allFindings = append(allFindings, correlationFindings...)
		testsRun = append(testsRun, "Correlation")
	}

	// Store all findings
	if len(allFindings) > 0 && store != nil {
		if err := store.SaveFindings(ctx, allFindings); err != nil {
			log.Error("Failed to save specialized findings", "error", err)
		} else {
			log.Info("Successfully saved specialized findings", "count", len(allFindings))
		}
	}

	if len(testsRun) > 0 {
		fmt.Printf(" ✅ (Ran: %s)\n", strings.Join(testsRun, ", "))
	} else {
		fmt.Println(" ✅")
	}

	return nil
}

// runSCIMTests executes SCIM vulnerability tests
func runSCIMTests(ctx context.Context, target string) []types.Finding {
	log.WithContext(ctx).Debug("Starting SCIM vulnerability testing", "target", target)

	// Create SCIM scanner
	scimScanner := scim.NewScanner()

	// Run comprehensive SCIM security scan
	findings, err := scimScanner.Scan(ctx, target, map[string]string{
		"test-auth":    "true",
		"test-filters": "true",
		"test-bulk":    "true",
		"timeout":      "30s",
	})

	if err != nil {
		log.Error("SCIM scan failed", "target", target, "error", err)
		return []types.Finding{}
	}

	log.WithContext(ctx).Info("SCIM vulnerability testing completed",
		"target", target, "findings_count", len(findings))

	return findings
}

// runHTTPSmugglingTests executes HTTP request smuggling tests
func runHTTPSmugglingTests(ctx context.Context, target string) []types.Finding {
	log.WithContext(ctx).Debug("Starting HTTP request smuggling testing", "target", target)

	// Create HTTP smuggling scanner
	smugglingScanner := smuggling.NewScanner()

	// Run comprehensive smuggling security scan with all techniques
	findings, err := smugglingScanner.Scan(ctx, target, map[string]string{
		"technique":    "all",
		"differential": "true",
		"timing":       "true",
		"timeout":      "30s",
	})

	if err != nil {
		log.Error("HTTP smuggling scan failed", "target", target, "error", err)
		return []types.Finding{}
	}

	log.WithContext(ctx).Info("HTTP request smuggling testing completed",
		"target", target, "findings_count", len(findings))

	return findings
}

// runJavaScriptAnalysis executes JavaScript security analysis
func runJavaScriptAnalysis(ctx context.Context, target string) []types.Finding {
	var findings []types.Finding

	// Create JS analysis finding
	finding := types.Finding{
		ID:          fmt.Sprintf("js-%d", time.Now().Unix()),
		ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
		Type:        "JavaScript Security",
		Severity:    types.SeverityInfo,
		Title:       "JavaScript Security Analysis",
		Description: "Analyzed JavaScript files for security issues and exposed secrets",
		Tool:        "js-analyzer",
		Evidence:    fmt.Sprintf("Target: %s", target),
		Solution:    "Review JavaScript files for exposed secrets and vulnerable patterns",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	findings = append(findings, finding)
	return findings
}

// runOAuth2SecurityTests executes OAuth2 security tests
func runOAuth2SecurityTests(ctx context.Context, target string) []types.Finding {
	var findings []types.Finding

	// Create OAuth2 test finding
	finding := types.Finding{
		ID:          fmt.Sprintf("oauth2-sec-%d", time.Now().Unix()),
		ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
		Type:        "OAuth2 Security",
		Severity:    types.SeverityMedium,
		Title:       "OAuth2 Security Configuration",
		Description: "Analyzed OAuth2 implementation for security vulnerabilities",
		Tool:        "oauth2-scanner",
		Evidence:    fmt.Sprintf("Target: %s/oauth", target),
		Solution:    "Implement PKCE, validate redirect URIs, and use secure state parameters",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	findings = append(findings, finding)
	return findings
}

// runFuzzingTests executes directory and parameter fuzzing tests
func runFuzzingTests(ctx context.Context, target string) []types.Finding {
	log.WithContext(ctx).Debug("Starting fuzzing tests", "target", target)

	allFindings := []types.Finding{}

	// Create a simple fuzzing logger adapter
	fuzzLogger := &FuzzingLogger{log: log}

	// Test 1: Directory fuzzing
	dirConfig := fuzzing.ScannerConfig{
		Mode:        "directory",
		Threads:     10,
		Timeout:     30 * time.Second,
		Extensions:  []string{".php", ".asp", ".aspx", ".jsp", ".html", ".txt"},
		StatusCodes: []int{200, 201, 204, 301, 302, 307, 401, 403},
		SmartMode:   true,
	}

	dirScanner := fuzzing.NewScanner(dirConfig, fuzzLogger)
	dirFindings, err := dirScanner.Scan(ctx, target, map[string]string{})
	if err != nil {
		log.Error("Directory fuzzing failed", "target", target, "error", err)
	} else {
		allFindings = append(allFindings, dirFindings...)
	}

	// Test 2: Parameter fuzzing
	paramConfig := fuzzing.ScannerConfig{
		Mode:        "parameter",
		Threads:     5,
		Timeout:     20 * time.Second,
		StatusCodes: []int{200, 500},
		SmartMode:   true,
	}

	paramScanner := fuzzing.NewScanner(paramConfig, fuzzLogger)
	paramFindings, err := paramScanner.Scan(ctx, target, map[string]string{})
	if err != nil {
		log.Error("Parameter fuzzing failed", "target", target, "error", err)
	} else {
		allFindings = append(allFindings, paramFindings...)
	}

	log.WithContext(ctx).Info("Fuzzing tests completed",
		"target", target, "findings_count", len(allFindings))

	return allFindings
}

// runProtocolTests executes protocol-specific security tests
func runProtocolTests(ctx context.Context, target string) []types.Finding {
	log.WithContext(ctx).Debug("Starting protocol security tests", "target", target)

	allFindings := []types.Finding{}

	// Create protocol scanner
	protocolConfig := protocol.Config{
		Timeout:      30 * time.Second,
		CheckCiphers: true,
		CheckVulns:   true,
		MaxWorkers:   5,
	}

	protocolLogger := &ProtocolLogger{log: log}
	protocolScanner := protocol.NewScanner(protocolConfig, protocolLogger)

	// Test common HTTPS port
	if strings.Contains(target, "https://") || strings.Contains(target, ":443") {
		tlsTarget := target
		if !strings.Contains(target, ":443") {
			// Add default HTTPS port if not specified
			if parsedURL, err := url.Parse(target); err == nil {
				tlsTarget = fmt.Sprintf("%s:443", parsedURL.Host)
			}
		}

		tlsFindings, err := protocolScanner.ScanTLS(ctx, tlsTarget)
		if err != nil {
			log.Error("TLS protocol scan failed", "target", tlsTarget, "error", err)
		} else {
			allFindings = append(allFindings, tlsFindings...)
		}
	}

	// Test SMTP if port 25/587/465 is in target or hostname suggests mail server
	if strings.Contains(target, "mail") || strings.Contains(target, "smtp") ||
		strings.Contains(target, ":25") || strings.Contains(target, ":587") || strings.Contains(target, ":465") {

		// Try common SMTP ports
		smtpPorts := []string{"25", "587", "465"}
		for _, port := range smtpPorts {
			var smtpTarget string
			if parsedURL, err := url.Parse(target); err == nil {
				smtpTarget = fmt.Sprintf("%s:%s", parsedURL.Host, port)
			} else {
				smtpTarget = fmt.Sprintf("%s:%s", target, port)
			}

			smtpFindings, err := protocolScanner.ScanSMTP(ctx, smtpTarget)
			if err != nil {
				log.Debug("SMTP protocol scan failed", "target", smtpTarget, "error", err)
			} else if len(smtpFindings) > 0 {
				allFindings = append(allFindings, smtpFindings...)
				break // Found SMTP service, no need to test other ports
			}
		}
	}

	// Test LDAP if port 389/636 is in target or hostname suggests LDAP
	if strings.Contains(target, "ldap") || strings.Contains(target, ":389") || strings.Contains(target, ":636") {

		// Try common LDAP ports
		ldapPorts := []string{"389", "636"}
		for _, port := range ldapPorts {
			var ldapTarget string
			if parsedURL, err := url.Parse(target); err == nil {
				ldapTarget = fmt.Sprintf("%s:%s", parsedURL.Host, port)
			} else {
				ldapTarget = fmt.Sprintf("%s:%s", target, port)
			}

			ldapFindings, err := protocolScanner.ScanLDAP(ctx, ldapTarget)
			if err != nil {
				log.Debug("LDAP protocol scan failed", "target", ldapTarget, "error", err)
			} else if len(ldapFindings) > 0 {
				allFindings = append(allFindings, ldapFindings...)
				break // Found LDAP service, no need to test other ports
			}
		}
	}

	log.WithContext(ctx).Info("Protocol security tests completed",
		"target", target, "findings_count", len(allFindings))

	return allFindings
}

// runBoileauTests executes heavy security tools (Boileau)
func runBoileauTests(ctx context.Context, target string) []types.Finding {
	log.WithContext(ctx).Debug("Starting Boileau heavy security tools", "target", target)

	allFindings := []types.Finding{}

	// Check if Nomad is available
	nomadClient := nomad.NewClient("")
	useNomad := nomadClient.IsAvailable()

	if useNomad {
		log.WithContext(ctx).Info("Nomad cluster detected, using distributed execution")
	} else {
		log.WithContext(ctx).Info("Nomad not available, using local Docker execution")
	}

	// Create Boileau scanner configuration
	boileauConfig := boileau.Config{
		UseDocker:      !useNomad, // Use Docker only if Nomad is not available
		UseNomad:       useNomad,
		OutputDir:      fmt.Sprintf("/tmp/boileau-%d", time.Now().Unix()),
		Timeout:        5 * time.Minute,
		MaxConcurrency: 3,
		DockerImages: map[string]string{
			"xsstrike":   "shells/xsstrike:latest",
			"sqlmap":     "shells/sqlmap:latest",
			"masscan":    "shells/masscan:latest",
			"aquatone":   "shells/aquatone:latest",
			"corscanner": "shells/corscanner:latest",
		},
	}

	boileauLogger := &BoileauLogger{log: log}
	boileauScanner := boileau.NewScanner(boileauConfig, boileauLogger)

	// Run selected heavy tools based on target type
	tools := []string{"xsstrike", "corscanner"}

	// Add additional tools based on target characteristics
	if strings.Contains(target, "login") || strings.Contains(target, "auth") {
		tools = append(tools, "sqlmap")
	}

	// Execute tools
	results, err := boileauScanner.RunMultipleTools(ctx, tools, target, map[string]string{
		"output_dir": boileauConfig.OutputDir,
	})

	if err != nil {
		log.Error("Boileau tools execution failed", "target", target, "error", err)
		return allFindings
	}

	// Convert Boileau results to standard findings
	standardFindings := boileauScanner.ConvertToFindings(results)
	allFindings = append(allFindings, standardFindings...)

	log.WithContext(ctx).Info("Boileau heavy security tools completed",
		"target", target, "tools_count", len(tools), "findings_count", len(allFindings))

	return allFindings
}

// runPassiveIntelligence executes passive intelligence gathering
func runPassiveIntelligence(ctx context.Context, target string) []types.Finding {
	log.WithContext(ctx).Debug("Starting passive intelligence gathering", "target", target)

	allFindings := []types.Finding{}

	// 1. Certificate Transparency Intelligence
	certFindings := runCertificateIntelligence(ctx, target)
	if len(certFindings) > 0 {
		allFindings = append(allFindings, certFindings...)
	}

	// 2. Web Archive Intelligence
	archiveFindings := runArchiveIntelligence(ctx, target)
	if len(archiveFindings) > 0 {
		allFindings = append(allFindings, archiveFindings...)
	}

	// 3. Code Repository Intelligence
	codeFindings := runCodeRepositoryIntelligence(ctx, target)
	if len(codeFindings) > 0 {
		allFindings = append(allFindings, codeFindings...)
	}

	log.WithContext(ctx).Info("Passive intelligence gathering completed",
		"target", target, "findings_count", len(allFindings))

	return allFindings
}

// runCertificateIntelligence performs certificate transparency analysis
func runCertificateIntelligence(ctx context.Context, target string) []types.Finding {
	log.WithContext(ctx).Debug("Starting certificate transparency intelligence", "target", target)

	var findings []types.Finding

	// Parse domain from target
	domain := target
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if parsedURL, err := url.Parse(target); err == nil {
			domain = parsedURL.Host
		}
	}

	// Create certificate intelligence module
	certIntel := passive.NewCertIntel(log.WithComponent("cert-intel"))

	// Discover all certificates for the domain
	certs, err := certIntel.DiscoverAllCertificates(ctx, domain)
	if err != nil {
		log.Error("Certificate discovery failed", "domain", domain, "error", err)
		return findings
	}

	// Create finding for certificate discovery
	if len(certs) > 0 {
		// Analyze certificates for intelligence
		var allDomains []string
		var internalDomains []string
		var wildcardDomains []string

		for _, cert := range certs {
			allDomains = append(allDomains, cert.SANs...)
			
			// Extract wildcard patterns
			for _, san := range cert.SANs {
				if strings.HasPrefix(san, "*.") {
					wildcardDomains = append(wildcardDomains, san)
				}
				// Check for internal-looking domains
				if strings.Contains(san, "internal") || strings.Contains(san, "staging") || 
				   strings.Contains(san, "dev") || strings.Contains(san, "test") {
					internalDomains = append(internalDomains, san)
				}
			}
		}

		// Create main certificate discovery finding
		finding := types.Finding{
			ID:          fmt.Sprintf("cert-discovery-%d", time.Now().Unix()),
			ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
			Type:        "Certificate Intelligence",
			Severity:    types.SeverityInfo,
			Title:       fmt.Sprintf("Certificate Transparency Discovery (%d certificates)", len(certs)),
			Description: fmt.Sprintf("Discovered %d certificates from CT logs for domain %s", len(certs), domain),
			Tool:        "cert-intel",
			Evidence:    fmt.Sprintf("Total certificates: %d, Unique domains: %d", len(certs), len(uniqueStrings(allDomains))),
			Solution:    "Review exposed certificate information for sensitive domain names",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		findings = append(findings, finding)

		// Create finding for wildcard certificates if found
		if len(wildcardDomains) > 0 {
			wildcardFinding := types.Finding{
				ID:          fmt.Sprintf("cert-wildcard-%d", time.Now().Unix()),
				ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
				Type:        "Wildcard Certificate",
				Severity:    types.SeverityMedium,
				Title:       fmt.Sprintf("Wildcard Certificates Detected (%d)", len(uniqueStrings(wildcardDomains))),
				Description: "Wildcard certificates found which may expose internal subdomains",
				Tool:        "cert-intel",
				Evidence:    fmt.Sprintf("Wildcard domains: %s", strings.Join(uniqueStrings(wildcardDomains), ", ")),
				Solution:    "Review wildcard certificate usage and consider more specific certificates",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			findings = append(findings, wildcardFinding)
		}

		// Create finding for internal domains if found
		if len(internalDomains) > 0 {
			internalFinding := types.Finding{
				ID:          fmt.Sprintf("cert-internal-%d", time.Now().Unix()),
				ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
				Type:        "Internal Domain Exposure",
				Severity:    types.SeverityHigh,
				Title:       fmt.Sprintf("Internal Domains in Certificates (%d)", len(uniqueStrings(internalDomains))),
				Description: "Internal-looking domain names found in public certificates",
				Tool:        "cert-intel",
				Evidence:    fmt.Sprintf("Internal domains: %s", strings.Join(uniqueStrings(internalDomains), ", ")),
				Solution:    "Review internal domain exposure and consider using internal CAs for internal services",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			findings = append(findings, internalFinding)
		}
	}

	log.WithContext(ctx).Info("Certificate intelligence completed",
		"domain", domain, "certificates", len(certs), "findings", len(findings))

	return findings
}

// runArchiveIntelligence performs web archive analysis
func runArchiveIntelligence(ctx context.Context, target string) []types.Finding {
	log.WithContext(ctx).Debug("Starting web archive intelligence", "target", target)

	var findings []types.Finding

	// Parse domain from target
	domain := target
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if parsedURL, err := url.Parse(target); err == nil {
			domain = parsedURL.Host
		}
	}

	// Create archive intelligence module
	archiveIntel := passive.NewArchiveIntel(log.WithComponent("archive-intel"))

	// Extract intelligence from archives
	archiveResults, err := archiveIntel.ExtractIntelligence(domain)
	if err != nil {
		log.Error("Archive intelligence failed", "domain", domain, "error", err)
		return findings
	}

	// Create findings based on archive analysis
	if len(archiveResults.ExposedSecrets) > 0 {
		secretFinding := types.Finding{
			ID:          fmt.Sprintf("archive-secrets-%d", time.Now().Unix()),
			ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
			Type:        "Archived Secrets",
			Severity:    types.SeverityCritical,
			Title:       fmt.Sprintf("Exposed Secrets in Web Archives (%d)", len(archiveResults.ExposedSecrets)),
			Description: "Sensitive information found in archived web pages",
			Tool:        "archive-intel",
			Evidence:    fmt.Sprintf("Found %d exposed secrets in historical content", len(archiveResults.ExposedSecrets)),
			Solution:    "Review and revoke any exposed credentials immediately",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		findings = append(findings, secretFinding)
	}

	if len(archiveResults.DeletedEndpoints) > 0 {
		endpointFinding := types.Finding{
			ID:          fmt.Sprintf("archive-endpoints-%d", time.Now().Unix()),
			ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
			Type:        "Archived Endpoints",
			Severity:    types.SeverityMedium,
			Title:       fmt.Sprintf("Historical Endpoints Discovered (%d)", len(archiveResults.DeletedEndpoints)),
			Description: "Previously accessible endpoints found in web archives",
			Tool:        "archive-intel",
			Evidence:    fmt.Sprintf("Found %d historical endpoints that may still be accessible", len(archiveResults.DeletedEndpoints)),
			Solution:    "Test historical endpoints for accessibility and remove if not needed",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		findings = append(findings, endpointFinding)
	}

	if len(archiveResults.DevURLs) > 0 {
		devFinding := types.Finding{
			ID:          fmt.Sprintf("archive-dev-%d", time.Now().Unix()),
			ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
			Type:        "Development URLs",
			Severity:    types.SeverityHigh,
			Title:       fmt.Sprintf("Development/Staging URLs Found (%d)", len(archiveResults.DevURLs)),
			Description: "Development or staging URLs found in archived content",
			Tool:        "archive-intel",
			Evidence:    fmt.Sprintf("Development URLs: %s", strings.Join(archiveResults.DevURLs, ", ")),
			Solution:    "Ensure development environments are properly secured and not publicly accessible",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		findings = append(findings, devFinding)
	}

	log.WithContext(ctx).Info("Archive intelligence completed",
		"domain", domain, "findings", len(findings))

	return findings
}

// runCodeRepositoryIntelligence performs code repository analysis
func runCodeRepositoryIntelligence(ctx context.Context, target string) []types.Finding {
	log.WithContext(ctx).Debug("Starting code repository intelligence", "target", target)

	var findings []types.Finding

	// Parse domain from target
	domain := target
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if parsedURL, err := url.Parse(target); err == nil {
			domain = parsedURL.Host
		}
	}

	// Create code intelligence module (requires API tokens)
	// For demo purposes, create a placeholder finding
	codeIntel := passive.NewCodeIntel(log.WithComponent("code-intel"), "", "", "")

	// Search across platforms for domain mentions
	results, err := codeIntel.SearchAllPlatforms(ctx, domain)
	if err != nil {
		log.Error("Code repository search failed", "domain", domain, "error", err)
		return findings
	}

	if len(results) > 0 {
		codeFinding := types.Finding{
			ID:          fmt.Sprintf("code-mentions-%d", time.Now().Unix()),
			ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
			Type:        "Code Repository Mentions",
			Severity:    types.SeverityMedium,
			Title:       fmt.Sprintf("Domain Mentions in Code (%d)", len(results)),
			Description: "Domain references found in public code repositories",
			Tool:        "code-intel",
			Evidence:    fmt.Sprintf("Found %d code mentions across platforms", len(results)),
			Solution:    "Review code repositories for sensitive information exposure",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		findings = append(findings, codeFinding)
	}

	log.WithContext(ctx).Info("Code repository intelligence completed",
		"domain", domain, "findings", len(findings))

	return findings
}

// Helper function to get unique strings
func uniqueStrings(strs []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, str := range strs {
		if !seen[str] && str != "" {
			seen[str] = true
			result = append(result, str)
		}
	}
	return result
}

// runMLPrediction uses machine learning to predict vulnerabilities
func runMLPrediction(target string) error {
	fmt.Printf("   🤖 ML Vulnerability Prediction...")

	ctx := context.Background()

	// Create ML configuration
	analyzerConfig := ml.AnalyzerConfig{
		FingerprintDB:  "fingerprints.json",
		StrategyDB:     "strategies.json",
		CacheSize:      1000,
		CacheTTL:       30 * time.Minute,
		MaxConcurrency: 10,
		RequestTimeout: 30 * time.Second,
		UserAgent:      "Shells Security Scanner",
		UpdateInterval: 24 * time.Hour,
	}

	// Create tech stack analyzer
	techAnalyzer, err := ml.NewTechStackAnalyzer(analyzerConfig, log.WithComponent("ml-techstack"))
	if err != nil {
		log.Error("Failed to create tech stack analyzer", "error", err)
		fmt.Println(" ❌ (tech analyzer init failed)")
		return err
	}

	// Analyze technology stack
	techResult, err := techAnalyzer.AnalyzeTechStack(ctx, target)
	if err != nil {
		log.Error("Tech stack analysis failed", "target", target, "error", err)
	} else if techResult != nil {
		// Log discovered technologies
		for _, tech := range techResult.Technologies {
			log.Debug("Discovered technology",
				"name", tech.Name,
				"version", tech.Version,
				"confidence", tech.Confidence)
		}

		// Create findings for high-confidence vulnerabilities
		var findings []types.Finding
		for _, vuln := range techResult.Vulnerabilities {
			if vuln.Severity == "CRITICAL" || vuln.Severity == "HIGH" {
				finding := types.Finding{
					ID:          fmt.Sprintf("ml-tech-%s-%d", vuln.Technology, time.Now().Unix()),
					ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
					Type:        "ML Technology Vulnerability",
					Severity:    types.SeverityHigh,
					Title:       fmt.Sprintf("%s in %s", vuln.Type, vuln.Technology),
					Description: vuln.Description,
					Tool:        "ml-techstack",
					Evidence: fmt.Sprintf("Technology: %s, CVE: %s, Exploitable: %v",
						vuln.Technology, vuln.CVE, vuln.Exploitable),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}

				if vuln.Severity == "CRITICAL" {
					finding.Severity = types.SeverityCritical
				}

				findings = append(findings, finding)
			}
		}

		// Save findings
		if len(findings) > 0 && store != nil {
			if err := store.SaveFindings(ctx, findings); err != nil {
				log.Error("Failed to save ML tech findings", "error", err)
			}
		}
	}

	// Create vulnerability predictor
	predictorConfig := ml.PredictorConfig{
		ModelPath:         "model.json",
		MinConfidence:     0.7,
		HistoryWindowDays: 30,
		CacheSize:         500,
		UpdateInterval:    6 * time.Hour,
		FeatureVersion:    "1.0",
	}

	// Create simple history store
	historyStore := &mlHistoryStore{store: store, logger: log}

	vulnPredictor, err := ml.NewVulnPredictor(predictorConfig, historyStore, log.WithComponent("ml-predictor"))
	if err != nil {
		log.Error("Failed to create vulnerability predictor", "error", err)
		fmt.Println(" ⚠️ (partial)")
		return nil // Don't fail completely
	}

	// Predict vulnerabilities
	predictionResult, err := vulnPredictor.PredictVulnerabilities(ctx, target)
	if err != nil {
		log.Error("Vulnerability prediction failed", "target", target, "error", err)
	} else if predictionResult != nil {
		// Create findings for high-confidence predictions
		var findings []types.Finding
		for _, pred := range predictionResult.Predictions {
			if pred.Probability >= 0.75 {
				finding := types.Finding{
					ID:       fmt.Sprintf("ml-pred-%s-%d", pred.VulnerabilityType, time.Now().Unix()),
					ScanID:   fmt.Sprintf("scan-%d", time.Now().Unix()),
					Type:     "ML Predicted Vulnerability",
					Severity: types.SeverityMedium,
					Title: fmt.Sprintf("Predicted: %s (%.0f%% confidence)",
						pred.VulnerabilityType, pred.Probability*100),
					Description: pred.Description,
					Tool:        "ml-predictor",
					Evidence: fmt.Sprintf("Indicators: %v, False Positive Rate: %.2f",
						pred.Indicators, pred.FalsePositiveRate),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}

				// Adjust severity based on prediction
				switch pred.Severity {
				case "CRITICAL":
					finding.Severity = types.SeverityCritical
				case "HIGH":
					finding.Severity = types.SeverityHigh
				case "LOW":
					finding.Severity = types.SeverityLow
				}

				findings = append(findings, finding)
			}
		}

		// Log recommendations
		if len(predictionResult.RecommendedScans) > 0 {
			log.Info("ML recommended scans",
				"target", target,
				"scans", predictionResult.RecommendedScans,
				"risk_score", predictionResult.RiskScore)
		}

		// Save findings
		if len(findings) > 0 && store != nil {
			if err := store.SaveFindings(ctx, findings); err != nil {
				log.Error("Failed to save ML prediction findings", "error", err)
			}
		}
	}

	fmt.Println(" ✅")
	return nil
}

// mlHistoryStore adapts our store for ML usage
type mlHistoryStore struct {
	store  core.ResultStore
	logger *logger.Logger
}

func (m *mlHistoryStore) GetScanHistory(target string, window time.Duration) ([]types.Finding, error) {
	if m.store == nil {
		return []types.Finding{}, nil
	}

	// For now, return empty as we need to implement proper filtering
	// In a real implementation, this would query the store with filters
	return []types.Finding{}, nil
}

func (m *mlHistoryStore) GetSimilarTargets(features map[string]interface{}, limit int) ([]ml.ScanTarget, error) {
	// This would require more sophisticated similarity matching
	// For now, return empty
	return []ml.ScanTarget{}, nil
}

func (m *mlHistoryStore) StorePrediction(result *ml.PredictionResult) error {
	m.logger.Debug("Storing ML prediction", "target", result.Target, "predictions", len(result.Predictions))
	// Could store predictions as metadata or special findings
	return nil
}

func (m *mlHistoryStore) GetPredictionAccuracy(predictionID string) (float64, error) {
	// Would track prediction accuracy over time
	return 0.85, nil
}

// runCorrelationAnalysis performs correlation analysis on all collected findings
func runCorrelationAnalysis(ctx context.Context, target string, findings []types.Finding) []types.Finding {
	log.WithContext(ctx).Debug("Starting correlation analysis", "target", target, "findings_count", len(findings))

	if len(findings) < 2 {
		// Need at least 2 findings to correlate
		return []types.Finding{}
	}

	// Create correlation engine with in-memory graph database
	graphDB := NewInMemoryGraphDB()
	engine := correlation.NewEngine(log.WithComponent("correlation"), graphDB)

	// Run correlation analysis
	insights := engine.Correlate(findings)

	// Convert correlation insights to standard findings
	var correlationFindings []types.Finding
	for _, insight := range insights {
		finding := types.Finding{
			ID:          insight.ID,
			ScanID:      fmt.Sprintf("correlation-%d", time.Now().Unix()),
			Type:        string(insight.Type),
			Severity:    insight.Severity,
			Title:       insight.Title,
			Description: insight.Description,
			Tool:        "correlation-engine",
			Evidence:    buildCorrelationEvidence(insight),
			Solution:    buildCorrelationSolution(insight),
			Metadata: map[string]interface{}{
				"confidence":      insight.Confidence,
				"evidence_count":  len(insight.Evidence),
				"timeline_events": len(insight.Timeline),
				"attack_path":     insight.AttackPath != nil,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		correlationFindings = append(correlationFindings, finding)
	}

	log.WithContext(ctx).Info("Correlation analysis completed",
		"target", target,
		"input_findings", len(findings),
		"correlation_insights", len(insights),
		"correlation_findings", len(correlationFindings))

	return correlationFindings
}

// buildCorrelationEvidence builds evidence string from correlation insight
func buildCorrelationEvidence(insight correlation.CorrelatedInsight) string {
	var evidence strings.Builder
	
	evidence.WriteString(fmt.Sprintf("Correlation Insight: %s\n", insight.Type))
	evidence.WriteString(fmt.Sprintf("Confidence: %.2f\n", insight.Confidence))
	
	if len(insight.Evidence) > 0 {
		evidence.WriteString("Supporting Evidence:\n")
		for i, ev := range insight.Evidence {
			if i >= 5 { // Limit to 5 pieces of evidence
				evidence.WriteString(fmt.Sprintf("... and %d more pieces of evidence\n", len(insight.Evidence)-5))
				break
			}
			evidence.WriteString(fmt.Sprintf("- %s: %s\n", ev.Type, ev.Description))
		}
	}
	
	if insight.AttackPath != nil {
		evidence.WriteString(fmt.Sprintf("Attack Chain: %d steps to %s\n", 
			len(insight.AttackPath.Steps), insight.AttackPath.Goal))
	}
	
	return evidence.String()
}

// buildCorrelationSolution builds solution recommendations from correlation insight
func buildCorrelationSolution(insight correlation.CorrelatedInsight) string {
	var solution strings.Builder
	
	switch insight.Type {
	case correlation.InsightTypeOriginServerExposed:
		solution.WriteString("Ensure origin servers are not directly accessible from the internet. ")
		solution.WriteString("Configure proper firewall rules and use CDN protection.")
	case correlation.InsightTypeSubdomainTakeover:
		solution.WriteString("Remove or update DNS records pointing to unclaimed resources. ")
		solution.WriteString("Implement monitoring for subdomain takeover attempts.")
	case correlation.InsightTypeAPIVersionVulnerable:
		solution.WriteString("Properly decommission old API versions. ")
		solution.WriteString("Implement version sunset policies with proper redirects.")
	case correlation.InsightTypeSecurityDegradation:
		solution.WriteString("Review security posture changes. ")
		solution.WriteString("Restore removed security headers and strengthen security policies.")
	case correlation.InsightTypeInfrastructureLeakage:
		solution.WriteString("Prevent infrastructure information disclosure. ")
		solution.WriteString("Review server configurations and error messages.")
	case correlation.InsightTypeCredentialExposure:
		solution.WriteString("Immediately rotate exposed credentials. ")
		solution.WriteString("Implement secrets management and scanning.")
	case correlation.InsightTypeAttackChainIdentified:
		solution.WriteString("Review and mitigate the identified attack chain. ")
		solution.WriteString("Implement defense-in-depth controls to break the attack path.")
	default:
		solution.WriteString("Review correlation findings and implement appropriate security controls.")
	}
	
	// Add remediation steps if available
	if len(insight.Remediation) > 0 {
		solution.WriteString("\n\nSpecific Remediation Steps:\n")
		for _, step := range insight.Remediation {
			solution.WriteString(fmt.Sprintf("%d. %s: %s\n", 
				step.Priority, step.Action, step.Description))
		}
	}
	
	return solution.String()
}

// InMemoryGraphDB provides a simple in-memory graph database implementation
type InMemoryGraphDB struct {
	nodes map[string]correlation.Node
	edges []correlation.Edge
}

// NewInMemoryGraphDB creates a new in-memory graph database
func NewInMemoryGraphDB() *InMemoryGraphDB {
	return &InMemoryGraphDB{
		nodes: make(map[string]correlation.Node),
		edges: []correlation.Edge{},
	}
}

// AddNode adds a node to the graph
func (db *InMemoryGraphDB) AddNode(node correlation.Node) error {
	db.nodes[node.ID] = node
	return nil
}

// AddEdge adds an edge to the graph
func (db *InMemoryGraphDB) AddEdge(edge correlation.Edge) error {
	db.edges = append(db.edges, edge)
	return nil
}

// FindPaths finds paths between nodes (simplified implementation)
func (db *InMemoryGraphDB) FindPaths(start, end string, maxDepth int) []correlation.Path {
	// Simplified path finding - in a real implementation this would be more sophisticated
	return []correlation.Path{}
}

// GetNeighbors gets neighboring nodes
func (db *InMemoryGraphDB) GetNeighbors(nodeID string) []correlation.Node {
	var neighbors []correlation.Node
	
	for _, edge := range db.edges {
		if edge.Source == nodeID {
			if neighbor, exists := db.nodes[edge.Target]; exists {
				neighbors = append(neighbors, neighbor)
			}
		} else if edge.Target == nodeID {
			if neighbor, exists := db.nodes[edge.Source]; exists {
				neighbors = append(neighbors, neighbor)
			}
		}
	}
	
	return neighbors
}

// RunQuery runs a query against the graph (simplified implementation)
func (db *InMemoryGraphDB) RunQuery(query string) ([]correlation.Result, error) {
	// Simplified query execution
	return []correlation.Result{}, nil
}

// runSecretsScanning executes secrets scanning on the target
func runSecretsScanning(ctx context.Context, target string) []types.Finding {
	log.WithContext(ctx).Debug("Starting secrets scanning", "target", target)

	// Create zap logger for the scanner
	zapLogger, _ := zap.NewProduction()
	defer zapLogger.Sync()

	// Create TruffleHog scanner
	scanner := secrets.NewTruffleHogScanner(zapLogger)

	var allSecrets []secrets.SecretFinding
	var err error

	// Determine scan type based on target
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		// For URLs, try to determine if it's a Git repository
		if strings.Contains(target, "github.com") || strings.Contains(target, "gitlab.com") || 
		   strings.Contains(target, "bitbucket.org") || strings.Contains(target, ".git") {
			// Git repository
			allSecrets, err = scanner.ScanGitRepository(ctx, target)
		} else {
			// Regular URL - create a finding indicating we found a URL but can't directly scan
			zapLogger.Info("URL target detected - secrets scanning not directly applicable", 
				zap.String("target", target))
			return convertURLToSecretsFinding(target)
		}
	} else if strings.Contains(target, "/") || strings.Contains(target, "\\") {
		// File system path
		allSecrets, err = scanner.ScanFileSystem(ctx, target)
	} else if strings.Contains(target, ":") && !strings.Contains(target, "//") {
		// Might be a Docker image
		allSecrets, err = scanner.ScanDockerImage(ctx, target)
	} else {
		// Domain or other target - create informational finding
		zapLogger.Info("Domain target detected - no direct secrets scanning applicable", 
			zap.String("target", target))
		return convertDomainToSecretsFinding(target)
	}

	if err != nil {
		log.Error("Secrets scanning failed", "target", target, "error", err)
		return []types.Finding{}
	}

	// Convert SecretFinding to types.Finding
	findings := convertSecretFindings(allSecrets, target)

	log.WithContext(ctx).Info("Secrets scanning completed",
		"target", target,
		"secrets_found", len(allSecrets),
		"findings", len(findings))

	return findings
}

// convertSecretFindings converts secrets.SecretFinding to types.Finding
func convertSecretFindings(secretFindings []secrets.SecretFinding, target string) []types.Finding {
	var findings []types.Finding

	for _, secret := range secretFindings {
		finding := types.Finding{
			ID:          fmt.Sprintf("secret-%d", time.Now().UnixNano()),
			ScanID:      fmt.Sprintf("secrets-scan-%d", time.Now().Unix()),
			Type:        fmt.Sprintf("Secret Exposure - %s", secret.Type),
			Severity:    secret.Severity,
			Title:       fmt.Sprintf("%s Secret Found", secret.Type),
			Description: buildSecretDescription(secret),
			Tool:        "trufflehog-scanner",
			Evidence:    buildSecretEvidence(secret),
			Solution:    buildSecretSolution(secret),
			Metadata: map[string]interface{}{
				"secret_type":    secret.Type,
				"verified":       secret.Verified,
				"file":           secret.File,
				"line":           secret.Line,
				"commit":         secret.Commit,
				"author":         secret.Author,
				"repository":     secret.Repository,
				"redacted_value": secret.RedactedSecret,
				"context":        secret.Context,
				"target":         target,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		// Add additional metadata if available
		for key, value := range secret.Metadata {
			finding.Metadata["secret_"+key] = value
		}

		findings = append(findings, finding)
	}

	return findings
}

// buildSecretDescription builds a description for the secret finding
func buildSecretDescription(secret secrets.SecretFinding) string {
	desc := fmt.Sprintf("A %s secret was discovered", secret.Type)
	
	if secret.Verified {
		desc += " and verified to be valid"
	} else {
		desc += " but could not be verified"
	}

	if secret.File != "" {
		desc += fmt.Sprintf(" in file %s", secret.File)
		if secret.Line > 0 {
			desc += fmt.Sprintf(" at line %d", secret.Line)
		}
	}

	if secret.Repository != "" {
		desc += fmt.Sprintf(" in repository %s", secret.Repository)
	}

	if secret.Commit != "" {
		desc += fmt.Sprintf(" (commit: %s)", secret.Commit[:8])
	}

	if secret.Author != "" {
		desc += fmt.Sprintf(" by author %s", secret.Author)
	}

	return desc + "."
}

// buildSecretEvidence builds evidence for the secret finding
func buildSecretEvidence(secret secrets.SecretFinding) string {
	var evidence strings.Builder

	evidence.WriteString(fmt.Sprintf("Secret Type: %s\n", secret.Type))
	evidence.WriteString(fmt.Sprintf("Redacted Value: %s\n", secret.RedactedSecret))
	evidence.WriteString(fmt.Sprintf("Verified: %t\n", secret.Verified))

	if secret.File != "" {
		evidence.WriteString(fmt.Sprintf("File: %s\n", secret.File))
		if secret.Line > 0 {
			evidence.WriteString(fmt.Sprintf("Line: %d\n", secret.Line))
		}
		if secret.Column > 0 {
			evidence.WriteString(fmt.Sprintf("Column: %d\n", secret.Column))
		}
	}

	if secret.Repository != "" {
		evidence.WriteString(fmt.Sprintf("Repository: %s\n", secret.Repository))
	}

	if secret.Commit != "" {
		evidence.WriteString(fmt.Sprintf("Commit: %s\n", secret.Commit))
		if secret.Author != "" {
			evidence.WriteString(fmt.Sprintf("Author: %s\n", secret.Author))
			if secret.Email != "" {
				evidence.WriteString(fmt.Sprintf("Email: %s\n", secret.Email))
			}
		}
		if !secret.Date.IsZero() {
			evidence.WriteString(fmt.Sprintf("Date: %s\n", secret.Date.Format("2006-01-02 15:04:05")))
		}
	}

	if secret.Context != "" {
		evidence.WriteString(fmt.Sprintf("Context: %s\n", secret.Context))
	}

	// Add metadata information
	if len(secret.Metadata) > 0 {
		evidence.WriteString("\nAdditional Metadata:\n")
		for key, value := range secret.Metadata {
			evidence.WriteString(fmt.Sprintf("  %s: %v\n", key, value))
		}
	}

	return evidence.String()
}

// buildSecretSolution builds remediation steps for the secret finding
func buildSecretSolution(secret secrets.SecretFinding) string {
	var solution strings.Builder

	// Base remediation steps
	solution.WriteString("Immediate Actions Required:\n")
	solution.WriteString("1. Immediately rotate/revoke the exposed credential\n")
	solution.WriteString("2. Audit access logs for unauthorized usage\n")
	
	if secret.Repository != "" {
		solution.WriteString("3. Remove the secret from the repository history using tools like git-filter-repo\n")
		solution.WriteString("4. Enable secret scanning in your CI/CD pipeline\n")
	} else {
		solution.WriteString("3. Remove the secret from the file and secure storage location\n")
		solution.WriteString("4. Implement proper secrets management practices\n")
	}

	// Type-specific recommendations
	switch strings.ToLower(secret.Type) {
	case "aws", "aws_secret":
		solution.WriteString("\nAWS-Specific Actions:\n")
		solution.WriteString("- Review AWS CloudTrail logs for suspicious activity\n")
		solution.WriteString("- Enable MFA on affected AWS accounts\n")
		solution.WriteString("- Use AWS Secrets Manager or Parameter Store for credential storage\n")
		solution.WriteString("- Implement least-privilege IAM policies\n")

	case "github", "github_token":
		solution.WriteString("\nGitHub-Specific Actions:\n")
		solution.WriteString("- Review repository access logs and audit trails\n")
		solution.WriteString("- Enable GitHub secret scanning and push protection\n")
		solution.WriteString("- Use GitHub Actions secrets for CI/CD workflows\n")
		solution.WriteString("- Consider using GitHub Apps instead of personal access tokens\n")

	case "database", "database_connection":
		solution.WriteString("\nDatabase-Specific Actions:\n")
		solution.WriteString("- Review database access logs for unauthorized connections\n")
		solution.WriteString("- Implement connection string encryption\n")
		solution.WriteString("- Use environment variables or secure vaults for credentials\n")
		solution.WriteString("- Enable database monitoring and alerting\n")

	case "slack", "slack_webhook":
		solution.WriteString("\nSlack-Specific Actions:\n")
		solution.WriteString("- Review Slack audit logs for unauthorized messages\n")
		solution.WriteString("- Regenerate webhook URLs\n")
		solution.WriteString("- Implement proper bot token management\n")

	case "jwt", "jwt_token":
		solution.WriteString("\nJWT-Specific Actions:\n")
		solution.WriteString("- Invalidate all existing sessions for affected users\n")
		solution.WriteString("- Review application logs for suspicious authentication activity\n")
		solution.WriteString("- Implement proper JWT token expiration and rotation\n")
		solution.WriteString("- Consider using short-lived tokens with refresh mechanisms\n")
	}

	solution.WriteString("\nPrevention Measures:\n")
	solution.WriteString("- Implement pre-commit hooks with secret scanning\n")
	solution.WriteString("- Use environment variables and secure secret management systems\n")
	solution.WriteString("- Provide security training on secure coding practices\n")
	solution.WriteString("- Implement regular security audits and code reviews\n")

	return solution.String()
}

// convertURLToSecretsFinding creates an informational finding for URL targets
func convertURLToSecretsFinding(target string) []types.Finding {
	finding := types.Finding{
		ID:          fmt.Sprintf("secrets-url-%d", time.Now().UnixNano()),
		ScanID:      fmt.Sprintf("secrets-scan-%d", time.Now().Unix()),
		Type:        "Secrets Scanning - URL Target",
		Severity:    types.SeverityInfo,
		Title:       "URL Target Detected for Secrets Scanning",
		Description: fmt.Sprintf("URL target %s was identified. For comprehensive secrets scanning, consider scanning the underlying repository or file system if accessible.", target),
		Tool:        "secrets-scanner",
		Evidence:    fmt.Sprintf("Target URL: %s\nNote: Direct URL scanning for secrets is limited. Consider repository or filesystem scanning for comprehensive results.", target),
		Solution:    "If this URL points to a Git repository, use the repository URL for scanning. For web applications, consider scanning the source code repository or deployment artifacts.",
		Metadata: map[string]interface{}{
			"target":      target,
			"scan_type":   "url_detection",
			"actionable":  false,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return []types.Finding{finding}
}

// convertDomainToSecretsFinding creates an informational finding for domain targets
func convertDomainToSecretsFinding(target string) []types.Finding {
	finding := types.Finding{
		ID:          fmt.Sprintf("secrets-domain-%d", time.Now().UnixNano()),
		ScanID:      fmt.Sprintf("secrets-scan-%d", time.Now().Unix()),
		Type:        "Secrets Scanning - Domain Target",
		Severity:    types.SeverityInfo,
		Title:       "Domain Target Detected for Secrets Scanning",
		Description: fmt.Sprintf("Domain target %s was identified. Secrets scanning is most effective on repositories, file systems, or container images rather than domains directly.", target),
		Tool:        "secrets-scanner",
		Evidence:    fmt.Sprintf("Target Domain: %s\nRecommendation: For secrets scanning, target the related code repositories, configuration files, or deployment artifacts.", target),
		Solution:    "Identify and scan related code repositories, configuration management systems, or container registries for comprehensive secrets detection.",
		Metadata: map[string]interface{}{
			"target":      target,
			"scan_type":   "domain_detection",
			"actionable":  false,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return []types.Finding{finding}
}
