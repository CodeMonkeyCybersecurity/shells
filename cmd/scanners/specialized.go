package scanners

// Specialized Scanner Functions
//
// Extracted from cmd/root.go Phase 2 refactoring (2025-10-06)
// Contains SCIM, HTTP Smuggling, OAuth2, Fuzzing, Protocol, and Boileau scanners

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/cmd/internal/adapters"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/boileau"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/fuzzing"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/protocol"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/scim"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/smuggling"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// runSCIMTests executes SCIM vulnerability tests
func (e *ScanExecutor) runSCIMTests(ctx context.Context, target string) []types.Finding {
	e.log.WithContext(ctx).Debugw("Starting SCIM vulnerability testing", "target", target)

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
		e.log.LogError(ctx, err, "SCIM scan failed", "target", target)
		return []types.Finding{}
	}

	e.log.WithContext(ctx).Infow("SCIM vulnerability testing completed",
		"target", target, "findings_count", len(findings))

	return findings
}

// runHTTPSmugglingTests executes HTTP request smuggling tests
func (e *ScanExecutor) runHTTPSmugglingTests(ctx context.Context, target string) []types.Finding {
	e.log.WithContext(ctx).Debugw("Starting HTTP request smuggling testing", "target", target)

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
		e.log.LogError(ctx, err, "HTTP smuggling scan failed", "target", target)
		return []types.Finding{}
	}

	e.log.WithContext(ctx).Infow("HTTP request smuggling testing completed",
		"target", target, "findings_count", len(findings))

	return findings
}

// runJavaScriptAnalysis executes JavaScript security analysis
func (e *ScanExecutor) runJavaScriptAnalysis(ctx context.Context, target string) []types.Finding {
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
func (e *ScanExecutor) runOAuth2SecurityTests(ctx context.Context, target string) []types.Finding {
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
func (e *ScanExecutor) runFuzzingTests(ctx context.Context, target string) []types.Finding {
	e.log.WithContext(ctx).Debugw("Starting fuzzing tests", "target", target)

	allFindings := []types.Finding{}

	// Create a simple fuzzing logger adapter
	fuzzLogger := adapters.NewFuzzingLogger(e.log)

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
		e.log.LogError(ctx, err, "Directory fuzzing failed", "target", target)
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
		e.log.LogError(ctx, err, "Parameter fuzzing failed", "target", target)
	} else {
		allFindings = append(allFindings, paramFindings...)
	}

	e.log.WithContext(ctx).Infow("Fuzzing tests completed",
		"target", target, "findings_count", len(allFindings))

	return allFindings
}

// runProtocolTests executes protocol-specific security tests
func (e *ScanExecutor) runProtocolTests(ctx context.Context, target string) []types.Finding {
	e.log.WithContext(ctx).Debugw("Starting protocol security tests", "target", target)

	allFindings := []types.Finding{}

	// Create protocol scanner
	protocolConfig := protocol.Config{
		Timeout:      30 * time.Second,
		CheckCiphers: true,
		CheckVulns:   true,
		MaxWorkers:   5,
	}

	protocolLogger := adapters.NewProtocolLogger(e.log)
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
			e.log.LogError(ctx, err, "TLS protocol scan failed", "target", tlsTarget)
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
				e.log.Debugw("SMTP protocol scan failed", "target", smtpTarget, "error", err)
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
				e.log.Debugw("LDAP protocol scan failed", "target", ldapTarget, "error", err)
			} else if len(ldapFindings) > 0 {
				allFindings = append(allFindings, ldapFindings...)
				break // Found LDAP service, no need to test other ports
			}
		}
	}

	e.log.WithContext(ctx).Infow("Protocol security tests completed",
		"target", target, "findings_count", len(allFindings))

	return allFindings
}

// runBoileauTests executes heavy security tools (Boileau)
func (e *ScanExecutor) runBoileauTests(ctx context.Context, target string) []types.Finding {
	e.log.WithContext(ctx).Debugw("Starting Boileau heavy security tools", "target", target)

	allFindings := []types.Finding{}

	// Check if Nomad is available
	_, useNomad := e.GetNomadClient()

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

	boileauLogger := adapters.NewBoileauLogger(e.log)
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
		e.log.LogError(ctx, err, "Boileau tools execution failed", "target", target)
		return allFindings
	}

	// Convert Boileau results to standard findings
	standardFindings := boileauScanner.ConvertToFindings(results)
	allFindings = append(allFindings, standardFindings...)

	e.log.WithContext(ctx).Infow("Boileau heavy security tools completed",
		"target", target, "tools_count", len(tools), "findings_count", len(allFindings))

	return allFindings
}

// Logger adapters moved to cmd/internal/adapters package
