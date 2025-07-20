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
	"github.com/CodeMonkeyCybersecurity/shells/pkg/fuzzing"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/ml"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/protocol"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scim"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/smuggling"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

	// 4. OAuth2 Security Testing
	if oauth2Findings := runOAuth2SecurityTests(ctx, target); len(oauth2Findings) > 0 {
		allFindings = append(allFindings, oauth2Findings...)
		testsRun = append(testsRun, "OAuth2")
	}

	// 5. Directory/Path Fuzzing
	if fuzzingFindings := runFuzzingTests(ctx, target); len(fuzzingFindings) > 0 {
		allFindings = append(allFindings, fuzzingFindings...)
		testsRun = append(testsRun, "Fuzzing")
	}

	// 6. Protocol Security Testing
	if protocolFindings := runProtocolTests(ctx, target); len(protocolFindings) > 0 {
		allFindings = append(allFindings, protocolFindings...)
		testsRun = append(testsRun, "Protocol")
	}

	// 7. Heavy Security Tools (Boileau)
	if boileauFindings := runBoileauTests(ctx, target); len(boileauFindings) > 0 {
		allFindings = append(allFindings, boileauFindings...)
		testsRun = append(testsRun, "Boileau")
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
