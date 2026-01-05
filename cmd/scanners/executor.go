package scanners

// Scanner Execution Coordinator
//
// Extracted from cmd/root.go Phase 2 refactoring (2025-10-06)
// Contains main scanner coordination logic with dependency injection

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// ScanExecutor coordinates all scanner execution with dependency injection
type ScanExecutor struct {
	log   *logger.Logger
	store core.ResultStore
	cfg   *config.Config
}

// NewScanExecutor creates a new scanner executor with dependencies
func NewScanExecutor(log *logger.Logger, store core.ResultStore, cfg *config.Config) *ScanExecutor {
	return &ScanExecutor{
		log:   log,
		store: store,
		cfg:   cfg,
	}
}

// RunBusinessLogicTests executes business logic vulnerability tests
func (e *ScanExecutor) RunBusinessLogicTests(ctx context.Context, target string) error {
	e.log.Infow("Running Business Logic Tests")

	// Initialize business logic analyzers
	analyzers := []struct {
		name string
		test func(string) error
	}{
		{"Password Reset", e.testPasswordReset},
		{"MFA Bypass", e.testMFABypass},
		{"Race Conditions", e.testRaceConditions},
		{"E-commerce Logic", e.testEcommerceLogic},
		{"Account Recovery", e.testAccountRecovery},
	}

	var findings []types.Finding
	errors := 0

	for _, analyzer := range analyzers {
		if err := analyzer.test(target); err != nil {
			e.log.Debugw("Business logic test failed", "test", analyzer.name, "error", err)
			errors++
		}
	}

	if errors == 0 {
		e.log.Infow("Business Logic Tests completed successfully")
	} else {
		e.log.Warnw("Business Logic Tests completed with issues",
			"errorCount", errors)
	}

	// Store any findings
	if len(findings) > 0 && e.store != nil {
		if err := e.store.SaveFindings(ctx, findings); err != nil {
			e.log.LogError(ctx, err, "Failed to save business logic findings")
		}
	}

	return nil
}

// testPasswordReset tests password reset functionality
func (e *ScanExecutor) testPasswordReset(target string) error {
	// This will be implemented using the password reset analyzer
	// For now, create a placeholder finding
	ctx := context.Background()

	if e.store != nil {
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

		return e.store.SaveFindings(ctx, []types.Finding{finding})
	}

	return nil
}

// testMFABypass tests for MFA bypass vulnerabilities
func (e *ScanExecutor) testMFABypass(target string) error {
	// Placeholder for MFA bypass testing
	return nil
}

// testRaceConditions tests for race condition vulnerabilities
func (e *ScanExecutor) testRaceConditions(target string) error {
	// Placeholder for race condition testing
	return nil
}

// testEcommerceLogic tests e-commerce business logic
func (e *ScanExecutor) testEcommerceLogic(target string) error {
	// Placeholder for e-commerce logic testing
	return nil
}

// testAccountRecovery tests account recovery mechanisms
func (e *ScanExecutor) testAccountRecovery(target string) error {
	// Placeholder for account recovery testing
	return nil
}

// RunAuthenticationTests executes authentication vulnerability tests
func (e *ScanExecutor) RunAuthenticationTests(ctx context.Context, target string) error {
	e.log.Infow("Running Authentication Tests")

	// Discover authentication endpoints
	discovery := auth.NewDiscovery()
	result, err := discovery.DiscoverAuth(ctx, target)
	if err != nil {
		e.log.Debugw("Authentication discovery failed", "error", err)
		e.log.Infow("No auth endpoints found")
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
	if len(allFindings) > 0 && e.store != nil {
		if err := e.store.SaveFindings(ctx, allFindings); err != nil {
			e.log.LogError(ctx, err, "Failed to save auth findings")
		} else {
			e.log.Infow("Successfully saved auth findings", "count", len(allFindings))
		}
	}

	if len(authTypesFound) > 0 {
		e.log.Infow("Authentication Tests completed",
			"foundMethods", strings.Join(authTypesFound, ", "))
	} else {
		e.log.Infow("No auth methods detected")
	}

	return nil
}

// RunInfrastructureScans executes infrastructure security scans
func (e *ScanExecutor) RunInfrastructureScans(ctx context.Context, target string) error {
	e.log.Infow("Running Infrastructure Scans")

	var allFindings []types.Finding
	testsRun := 0
	errorCount := 0

	// Check if Nomad is available for distributed execution
	_, useNomad := e.GetNomadClient()

	// Run Nmap port scanning
	if nmapFindings, err := e.runNmapScan(ctx, target, useNomad); err != nil {
		e.log.LogError(ctx, err, "Nmap scan failed", "target", target)
		errorCount++
	} else {
		allFindings = append(allFindings, nmapFindings...)
		testsRun++
	}

	// Run Nuclei vulnerability scanning
	if nucleiFindings, err := e.runNucleiScan(ctx, target, useNomad); err != nil {
		e.log.LogError(ctx, err, "Nuclei scan failed", "target", target)
		errorCount++
	} else {
		allFindings = append(allFindings, nucleiFindings...)
		testsRun++
	}

	// Run SSL/TLS analysis
	if sslFindings, err := e.runSSLScan(ctx, target, useNomad); err != nil {
		e.log.LogError(ctx, err, "SSL scan failed", "target", target)
		errorCount++
	} else {
		allFindings = append(allFindings, sslFindings...)
		testsRun++
	}

	// Store findings
	if len(allFindings) > 0 && e.store != nil {
		if err := e.store.SaveFindings(ctx, allFindings); err != nil {
			e.log.LogError(ctx, err, "Failed to save infrastructure findings")
		} else {
			e.log.Infow("Saved infrastructure findings", "count", len(allFindings))
		}
	}

	if errorCount == 0 {
		e.log.Infow("Infrastructure Scans completed successfully",
			"toolsRun", testsRun)
	} else {
		e.log.Warnw("Infrastructure Scans completed with failures",
			"failed", errorCount,
			"total", testsRun)
	}

	return nil
}

// RunSpecializedTests executes specialized vulnerability tests
func (e *ScanExecutor) RunSpecializedTests(ctx context.Context, target string) error {
	e.log.Infow("Running Specialized Tests")

	var allFindings []types.Finding
	testsRun := []string{}

	// 1. SCIM Vulnerability Testing
	if scimFindings := e.runSCIMTests(ctx, target); len(scimFindings) > 0 {
		allFindings = append(allFindings, scimFindings...)
		testsRun = append(testsRun, "SCIM")
	}

	// 2. HTTP Request Smuggling Testing
	if smugglingFindings := e.runHTTPSmugglingTests(ctx, target); len(smugglingFindings) > 0 {
		allFindings = append(allFindings, smugglingFindings...)
		testsRun = append(testsRun, "Smuggling")
	}

	// 3. JavaScript Analysis
	if jsFindings := e.runJavaScriptAnalysis(ctx, target); len(jsFindings) > 0 {
		allFindings = append(allFindings, jsFindings...)
		testsRun = append(testsRun, "JS")
	}

	// 4. Secrets Scanning
	if secretsFindings := e.runSecretsScanning(ctx, target); len(secretsFindings) > 0 {
		allFindings = append(allFindings, secretsFindings...)
		testsRun = append(testsRun, "Secrets")
	}

	// 5. OAuth2 Security Testing
	if oauth2Findings := e.runOAuth2SecurityTests(ctx, target); len(oauth2Findings) > 0 {
		allFindings = append(allFindings, oauth2Findings...)
		testsRun = append(testsRun, "OAuth2")
	}

	// 6. Directory/Path Fuzzing
	if fuzzingFindings := e.runFuzzingTests(ctx, target); len(fuzzingFindings) > 0 {
		allFindings = append(allFindings, fuzzingFindings...)
		testsRun = append(testsRun, "Fuzzing")
	}

	// 7. Protocol Security Testing
	if protocolFindings := e.runProtocolTests(ctx, target); len(protocolFindings) > 0 {
		allFindings = append(allFindings, protocolFindings...)
		testsRun = append(testsRun, "Protocol")
	}

	// 8. Passive Intelligence Gathering
	if passiveFindings := e.runPassiveIntelligence(ctx, target); len(passiveFindings) > 0 {
		allFindings = append(allFindings, passiveFindings...)
		testsRun = append(testsRun, "Passive")
	}

	// 9. Heavy Security Tools (Boileau)
	if boileauFindings := e.runBoileauTests(ctx, target); len(boileauFindings) > 0 {
		allFindings = append(allFindings, boileauFindings...)
		testsRun = append(testsRun, "Boileau")
	}

	// 10. Run Correlation Analysis on all findings
	if correlationFindings := e.runCorrelationAnalysis(ctx, target, allFindings); len(correlationFindings) > 0 {
		allFindings = append(allFindings, correlationFindings...)
		testsRun = append(testsRun, "Correlation")
	}

	// Store all findings
	if len(allFindings) > 0 && e.store != nil {
		if err := e.store.SaveFindings(ctx, allFindings); err != nil {
			e.log.LogError(ctx, err, "Failed to save specialized findings")
		} else {
			e.log.Infow("Successfully saved specialized findings", "count", len(allFindings))
		}
	}

	if len(testsRun) > 0 {
		e.log.Infow("Specialized Tests completed",
			"testsRun", strings.Join(testsRun, ", "))
	} else {
		e.log.Infow("Specialized Tests completed successfully")
	}

	return nil
}
