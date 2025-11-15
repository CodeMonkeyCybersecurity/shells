// internal/orchestrator/scanners/authentication.go
//
// Authentication Scanner - Tests SAML, OAuth2/OIDC, WebAuthn, and JWT
//
// REFACTORING CONTEXT:
// Extracted from bounty_engine.go runAuthenticationTests() (lines 2325-2561, ~238 lines)
// This scanner discovers and tests all authentication mechanisms on discovered assets
//
// PHILOSOPHY ALIGNMENT:
// - Human-centric: Transparent authentication testing with clear progress
// - Evidence-based: Structured findings with reproducible evidence
// - Sustainable: Modular design, easy to extend with new auth protocols

package scanners

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/auth"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/auth/common"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/auth/oauth2"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/auth/saml"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/auth/webauthn"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
	"github.com/google/uuid"
)

// AuthenticationScanner tests authentication mechanisms
type AuthenticationScanner struct {
	samlScanner     *saml.SAMLScanner
	oauth2Scanner   *oauth2.OAuth2Scanner
	webauthnScanner *webauthn.WebAuthnScanner
	authDiscovery   *auth.AuthDiscoveryEngine
	logger          *logger.Logger
}

// NewAuthenticationScanner creates a new authentication scanner
func NewAuthenticationScanner(
	samlScanner *saml.SAMLScanner,
	oauth2Scanner *oauth2.OAuth2Scanner,
	webauthnScanner *webauthn.WebAuthnScanner,
	authDiscovery *auth.AuthDiscoveryEngine,
	logger *logger.Logger,
) *AuthenticationScanner {
	return &AuthenticationScanner{
		samlScanner:     samlScanner,
		oauth2Scanner:   oauth2Scanner,
		webauthnScanner: webauthnScanner,
		authDiscovery:   authDiscovery,
		logger:          logger.WithComponent("auth-scanner"),
	}
}

// Name returns the scanner name
func (s *AuthenticationScanner) Name() string {
	return "Authentication Scanner"
}

// Type returns the scanner type
func (s *AuthenticationScanner) Type() string {
	return "auth"
}

// Priority returns execution priority (2 = runs early, after infrastructure)
func (s *AuthenticationScanner) Priority() int {
	return 2 // Auth testing should run early (after infrastructure, before API testing)
}

// CanHandle determines if this scanner can test the asset
func (s *AuthenticationScanner) CanHandle(asset *AssetPriority) bool {
	// Authentication scanner can test any web asset
	// Discovery will determine if auth endpoints exist
	return asset.Features.HasAuthentication || asset.Asset.Type == "web"
}

// Execute runs authentication testing against prioritized assets
func (s *AuthenticationScanner) Execute(ctx context.Context, assets []*AssetPriority) ([]types.Finding, error) {
	startTime := time.Now()
	allFindings := []types.Finding{}

	s.logger.Infow("Starting authentication testing",
		"asset_count", len(assets),
	)

	// Test each asset for authentication vulnerabilities
	for _, asset := range assets {
		select {
		case <-ctx.Done():
			return allFindings, ctx.Err()
		default:
		}

		// Get target URL from asset
		target := s.getTargetURL(asset)
		if target == "" {
			s.logger.Debugw("Skipping asset - no valid URL",
				"asset_id", asset.Asset.ID,
			)
			continue
		}

		s.logger.Infow("Testing asset for authentication vulnerabilities",
			"target", target,
			"asset_type", asset.Asset.Type,
		)

		// Discover authentication endpoints
		findings, err := s.testAuthentication(ctx, target)
		if err != nil {
			s.logger.Warnw("Authentication testing failed for asset",
				"target", target,
				"error", err,
			)
			continue
		}

		allFindings = append(allFindings, findings...)
	}

	duration := time.Since(startTime)
	s.logger.Infow("Authentication testing completed",
		"total_findings", len(allFindings),
		"duration", duration.String(),
	)

	return allFindings, nil
}

// testAuthentication discovers and tests all authentication mechanisms for a target
func (s *AuthenticationScanner) testAuthentication(ctx context.Context, target string) ([]types.Finding, error) {
	findings := []types.Finding{}

	// Step 1: Discover authentication endpoints
	s.logger.Infow("Discovering authentication endpoints",
		"target", target,
	)

	authInventory, err := s.authDiscovery.DiscoverAllAuth(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("authentication discovery failed: %w", err)
	}

	// Log discovered protocols
	protocolsFound := []string{}
	if authInventory.SAML != nil {
		protocolsFound = append(protocolsFound, "SAML")
	}
	if authInventory.OAuth2 != nil {
		protocolsFound = append(protocolsFound, "OAuth2/OIDC")
	}
	if authInventory.WebAuthn != nil {
		protocolsFound = append(protocolsFound, "WebAuthn/FIDO2")
	}

	s.logger.Infow("Authentication endpoint discovery complete",
		"saml_found", authInventory.SAML != nil,
		"oauth2_found", authInventory.OAuth2 != nil,
		"webauthn_found", authInventory.WebAuthn != nil,
		"protocols_found", protocolsFound,
	)

	// Step 2: Test SAML if discovered
	if authInventory.SAML != nil && authInventory.SAML.MetadataURL != "" {
		samlFindings, err := s.testSAML(ctx, target, authInventory.SAML)
		if err != nil {
			s.logger.Warnw("SAML testing failed",
				"error", err,
				"target", target,
			)
		} else {
			findings = append(findings, samlFindings...)
		}
	} else {
		s.logger.Debugw("No SAML endpoints discovered - skipping SAML tests",
			"target", target,
		)
	}

	// Step 3: Test OAuth2 if discovered
	if authInventory.OAuth2 != nil && authInventory.OAuth2.AuthorizationURL != "" {
		oauth2Findings, err := s.testOAuth2(ctx, target, authInventory.OAuth2)
		if err != nil {
			s.logger.Warnw("OAuth2 testing failed",
				"error", err,
				"target", target,
			)
		} else {
			findings = append(findings, oauth2Findings...)
		}
	} else {
		s.logger.Debugw("No OAuth2 endpoints discovered - skipping OAuth2 tests",
			"target", target,
		)
	}

	// Step 4: Test WebAuthn if discovered
	if authInventory.WebAuthn != nil && authInventory.WebAuthn.RegisterURL != "" {
		webauthnFindings, err := s.testWebAuthn(ctx, target, authInventory.WebAuthn)
		if err != nil {
			s.logger.Warnw("WebAuthn testing failed",
				"error", err,
				"target", target,
			)
		} else {
			findings = append(findings, webauthnFindings...)
		}
	} else {
		s.logger.Debugw("No WebAuthn endpoints discovered - skipping WebAuthn tests",
			"target", target,
		)
	}

	return findings, nil
}

// testSAML tests SAML authentication for vulnerabilities
func (s *AuthenticationScanner) testSAML(ctx context.Context, target string, samlEndpoint *auth.SAMLEndpoints) ([]types.Finding, error) {
	s.logger.Infow("Testing SAML authentication security",
		"metadata_url", samlEndpoint.MetadataURL,
		"tests", []string{"Golden SAML", "XML Signature Wrapping", "Assertion manipulation"},
	)

	samlOptions := map[string]interface{}{
		"metadata_url": samlEndpoint.MetadataURL,
		"test_golden":  true,
		"test_xsw":     true,
	}

	report, err := s.samlScanner.Scan(target, samlOptions)
	if err != nil {
		return nil, err
	}

	if report == nil {
		return []types.Finding{}, nil
	}

	s.logger.Infow("SAML scan complete",
		"vulnerabilities_found", len(report.Vulnerabilities),
		"attack_chains", len(report.AttackChains),
	)

	// Convert vulnerabilities to findings
	findings := []types.Finding{}
	for _, vuln := range report.Vulnerabilities {
		finding := s.convertSAMLVulnToFinding(vuln, target)
		findings = append(findings, finding)

		s.logger.Infow("SAML vulnerability found",
			"type", vuln.Type,
			"severity", vuln.Severity,
			"title", vuln.Title,
		)
	}

	return findings, nil
}

// testOAuth2 tests OAuth2/OIDC authentication for vulnerabilities
func (s *AuthenticationScanner) testOAuth2(ctx context.Context, target string, oauth2Endpoint *auth.OAuth2Endpoints) ([]types.Finding, error) {
	s.logger.Infow("Testing OAuth2/OIDC authentication security",
		"authorization_url", oauth2Endpoint.AuthorizationURL,
		"token_url", oauth2Endpoint.TokenURL,
		"tests", []string{"JWT algorithm confusion", "PKCE bypass", "State validation", "Scope escalation"},
	)

	oauth2Options := map[string]interface{}{
		"authorization_url": oauth2Endpoint.AuthorizationURL,
		"token_url":         oauth2Endpoint.TokenURL,
		"test_jwt":          true,
		"test_pkce":         true,
	}

	report, err := s.oauth2Scanner.Scan(target, oauth2Options)
	if err != nil {
		return nil, err
	}

	if report == nil {
		return []types.Finding{}, nil
	}

	s.logger.Infow("OAuth2 scan complete",
		"vulnerabilities_found", len(report.Vulnerabilities),
		"attack_chains", len(report.AttackChains),
	)

	findings := []types.Finding{}
	for _, vuln := range report.Vulnerabilities {
		finding := s.convertOAuth2VulnToFinding(vuln, target)
		findings = append(findings, finding)

		s.logger.Infow("OAuth2 vulnerability found",
			"type", vuln.Type,
			"severity", vuln.Severity,
			"title", vuln.Title,
		)
	}

	return findings, nil
}

// testWebAuthn tests WebAuthn/FIDO2 authentication for vulnerabilities
func (s *AuthenticationScanner) testWebAuthn(ctx context.Context, target string, webauthnEndpoint *auth.WebAuthnEndpoints) ([]types.Finding, error) {
	s.logger.Infow("Testing WebAuthn/FIDO2 authentication security",
		"register_url", webauthnEndpoint.RegisterURL,
		"login_url", webauthnEndpoint.LoginURL,
		"tests", []string{"Virtual authenticator", "Credential substitution", "Challenge reuse", "Origin validation"},
	)

	webauthnOptions := map[string]interface{}{
		"register_url": webauthnEndpoint.RegisterURL,
		"login_url":    webauthnEndpoint.LoginURL,
	}

	report, err := s.webauthnScanner.Scan(target, webauthnOptions)
	if err != nil {
		return nil, err
	}

	if report == nil {
		return []types.Finding{}, nil
	}

	s.logger.Infow("WebAuthn scan complete",
		"vulnerabilities_found", len(report.Vulnerabilities),
		"attack_chains", len(report.AttackChains),
	)

	findings := []types.Finding{}
	for _, vuln := range report.Vulnerabilities {
		finding := s.convertWebAuthnVulnToFinding(vuln, target)
		findings = append(findings, finding)

		s.logger.Infow("WebAuthn vulnerability found",
			"type", vuln.Type,
			"severity", vuln.Severity,
			"title", vuln.Title,
		)
	}

	return findings, nil
}

// Helper methods to convert protocol-specific vulnerabilities to unified findings

func (s *AuthenticationScanner) convertSAMLVulnToFinding(vuln common.Vulnerability, target string) types.Finding {
	return types.Finding{
		ID:          fmt.Sprintf("saml-%s", uuid.New().String()[:8]),
		ScanID:      "current-scan",
		Tool:        "saml",
		Type:        vuln.Type,
		Severity:    s.convertSeverity(vuln.Severity),
		Title:       vuln.Title,
		Description: vuln.Description,
		Evidence:    fmt.Sprintf("%v", vuln.Evidence),
		Solution:    vuln.Remediation.Description,
		Metadata: map[string]interface{}{
			"protocol":    "SAML",
			"impact":      vuln.Impact,
			"cvss":        vuln.CVSS,
			"cwe":         vuln.CWE,
			"references":  vuln.References,
			"remediation": vuln.Remediation,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func (s *AuthenticationScanner) convertOAuth2VulnToFinding(vuln common.Vulnerability, target string) types.Finding {
	return types.Finding{
		ID:          fmt.Sprintf("oauth2-%s", uuid.New().String()[:8]),
		ScanID:      "current-scan",
		Tool:        "oauth2",
		Type:        vuln.Type,
		Severity:    s.convertSeverity(vuln.Severity),
		Title:       vuln.Title,
		Description: vuln.Description,
		Evidence:    fmt.Sprintf("%v", vuln.Evidence),
		Solution:    vuln.Remediation.Description,
		Metadata: map[string]interface{}{
			"protocol":    "OAuth2/OIDC",
			"impact":      vuln.Impact,
			"cvss":        vuln.CVSS,
			"cwe":         vuln.CWE,
			"references":  vuln.References,
			"remediation": vuln.Remediation,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func (s *AuthenticationScanner) convertWebAuthnVulnToFinding(vuln common.Vulnerability, target string) types.Finding {
	return types.Finding{
		ID:          fmt.Sprintf("webauthn-%s", uuid.New().String()[:8]),
		ScanID:      "current-scan",
		Tool:        "webauthn",
		Type:        vuln.Type,
		Severity:    s.convertSeverity(vuln.Severity),
		Title:       vuln.Title,
		Description: vuln.Description,
		Evidence:    fmt.Sprintf("%v", vuln.Evidence),
		Solution:    vuln.Remediation.Description,
		Metadata: map[string]interface{}{
			"protocol":    "WebAuthn/FIDO2",
			"impact":      vuln.Impact,
			"cvss":        vuln.CVSS,
			"cwe":         vuln.CWE,
			"references":  vuln.References,
			"remediation": vuln.Remediation,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// convertSeverity converts string severity to types.Severity
func (s *AuthenticationScanner) convertSeverity(severity string) types.Severity {
	switch severity {
	case "Critical", "CRITICAL":
		return types.SeverityCritical
	case "High", "HIGH":
		return types.SeverityHigh
	case "Medium", "MEDIUM":
		return types.SeverityMedium
	case "Low", "LOW":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

// getTargetURL extracts URL from asset
func (s *AuthenticationScanner) getTargetURL(asset *AssetPriority) string {
	if asset.Asset.Value != "" {
		return asset.Asset.Value
	}
	if asset.Asset.Domain != "" {
		return fmt.Sprintf("https://%s", asset.Asset.Domain)
	}
	if asset.Asset.IP != "" {
		return fmt.Sprintf("https://%s", asset.Asset.IP)
	}
	return ""
}
