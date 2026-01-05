// Package converters provides type conversion functions for Shells CLI commands.
//
// This package centralizes all conversion logic between different scanner result types
// and the standard types.Finding format used throughout the application.
package converters

import (
	"fmt"
	"strings"
	"time"

	authdiscovery "github.com/CodeMonkeyCybersecurity/shells/pkg/auth/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scanners/secrets"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// ConvertSecretFindings converts secret scanner findings to standard findings
func ConvertSecretFindings(secretFindings []secrets.SecretFinding, target string) []types.Finding {
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

// ConvertAuthInventoryToFindings converts auth inventory to findings
func ConvertAuthInventoryToFindings(inventory *authdiscovery.AuthInventory, domain string, sessionID string) []types.Finding {
	var findings []types.Finding

	// Count total auth mechanisms
	totalAuthMechanisms := 0
	if inventory.NetworkAuth != nil {
		totalAuthMechanisms += getNetworkAuthCount(inventory.NetworkAuth)
	}
	if inventory.WebAuth != nil {
		totalAuthMechanisms += getWebAuthCount(inventory.WebAuth)
	}
	if inventory.APIAuth != nil {
		totalAuthMechanisms += getAPIAuthCount(inventory.APIAuth)
	}

	// Create inventory summary finding
	summaryFinding := types.Finding{
		ID:       fmt.Sprintf("auth-inventory-%d", time.Now().UnixNano()),
		ScanID:   sessionID,
		Type:     "Authentication Inventory",
		Severity: types.SeverityInfo,
		Title:    fmt.Sprintf("Authentication Mechanisms Discovered: %d methods", totalAuthMechanisms),
		Description: fmt.Sprintf("Comprehensive authentication inventory for %s identified %d authentication mechanisms across network, web, and API layers.",
			domain, totalAuthMechanisms),
		Tool:     "auth-discovery",
		Evidence: buildAuthInventoryEvidence(inventory),
		Solution: "Review discovered authentication mechanisms for security misconfigurations, weak implementations, or unnecessary exposure.",
		Metadata: map[string]interface{}{
			"domain":                domain,
			"total_auth_mechanisms": totalAuthMechanisms,
			"network_auth_count":    getNetworkAuthCount(inventory.NetworkAuth),
			"web_auth_count":        getWebAuthCount(inventory.WebAuth),
			"api_auth_count":        getAPIAuthCount(inventory.APIAuth),
			"scan_timestamp":        inventory.Timestamp.Format(time.RFC3339),
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	findings = append(findings, summaryFinding)
	return findings
}

// ConvertCorrelatedInsight converts correlation insights to findings
func ConvertCorrelatedInsight(insight correlation.CorrelatedInsight, sessionID string) types.Finding {
	return types.Finding{
		ID:          fmt.Sprintf("correlation-%d", time.Now().UnixNano()),
		ScanID:      sessionID,
		Type:        string(insight.Type),
		Severity:    insight.Severity,
		Title:       insight.Title,
		Description: insight.Description,
		Tool:        "correlation-engine",
		Evidence:    buildCorrelationEvidence(insight),
		Solution:    buildCorrelationSolution(insight),
		Metadata: map[string]interface{}{
			"confidence":    insight.Confidence,
			"related_nodes": insight.RelatedNodes,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// Helper functions for building descriptions and evidence

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

	if len(secret.Metadata) > 0 {
		evidence.WriteString("\nAdditional Metadata:\n")
		for key, value := range secret.Metadata {
			evidence.WriteString(fmt.Sprintf("  %s: %v\n", key, value))
		}
	}

	return evidence.String()
}

func buildSecretSolution(secret secrets.SecretFinding) string {
	var solution strings.Builder

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

func buildAuthInventoryEvidence(inventory *authdiscovery.AuthInventory) string {
	var evidence strings.Builder

	evidence.WriteString("=== Authentication Inventory ===\n\n")

	if inventory.NetworkAuth != nil {
		evidence.WriteString("Network Authentication:\n")
		if len(inventory.NetworkAuth.SSH) > 0 {
			evidence.WriteString(fmt.Sprintf("  - SSH Endpoints: %d\n", len(inventory.NetworkAuth.SSH)))
		}
		if len(inventory.NetworkAuth.RDP) > 0 {
			evidence.WriteString(fmt.Sprintf("  - RDP Endpoints: %d\n", len(inventory.NetworkAuth.RDP)))
		}
		if len(inventory.NetworkAuth.Kerberos) > 0 {
			evidence.WriteString(fmt.Sprintf("  - Kerberos Endpoints: %d\n", len(inventory.NetworkAuth.Kerberos)))
		}
		if len(inventory.NetworkAuth.LDAP) > 0 {
			evidence.WriteString(fmt.Sprintf("  - LDAP Endpoints: %d\n", len(inventory.NetworkAuth.LDAP)))
		}
		evidence.WriteString("\n")
	}

	if inventory.WebAuth != nil {
		evidence.WriteString("Web Authentication:\n")
		if len(inventory.WebAuth.FormLogin) > 0 {
			evidence.WriteString(fmt.Sprintf("  - Form Login Endpoints: %d\n", len(inventory.WebAuth.FormLogin)))
		}
		if len(inventory.WebAuth.BasicAuth) > 0 {
			evidence.WriteString(fmt.Sprintf("  - Basic Auth Endpoints: %d\n", len(inventory.WebAuth.BasicAuth)))
		}
		if len(inventory.WebAuth.OAuth2) > 0 {
			evidence.WriteString(fmt.Sprintf("  - OAuth2 Endpoints: %d\n", len(inventory.WebAuth.OAuth2)))
		}
		if len(inventory.WebAuth.SAML) > 0 {
			evidence.WriteString(fmt.Sprintf("  - SAML Endpoints: %d\n", len(inventory.WebAuth.SAML)))
		}
		if len(inventory.WebAuth.WebAuthn) > 0 {
			evidence.WriteString(fmt.Sprintf("  - WebAuthn Endpoints: %d\n", len(inventory.WebAuth.WebAuthn)))
		}
		evidence.WriteString("\n")
	}

	if inventory.APIAuth != nil {
		evidence.WriteString("API Authentication:\n")
		if len(inventory.APIAuth.REST) > 0 {
			evidence.WriteString(fmt.Sprintf("  - REST Endpoints: %d\n", len(inventory.APIAuth.REST)))
		}
		if len(inventory.APIAuth.GraphQL) > 0 {
			evidence.WriteString(fmt.Sprintf("  - GraphQL Endpoints: %d\n", len(inventory.APIAuth.GraphQL)))
		}
		if len(inventory.APIAuth.SOAP) > 0 {
			evidence.WriteString(fmt.Sprintf("  - SOAP Endpoints: %d\n", len(inventory.APIAuth.SOAP)))
		}
		evidence.WriteString("\n")
	}

	return evidence.String()
}

// buildCorrelationEvidence builds evidence string from correlation insight
// NOTE: This is a simplified version. There's a more detailed implementation
// in cmd/scanners/ml_correlation.go that handles specific InsightTypes.
// TODO: Consolidate these two implementations
func buildCorrelationEvidence(insight correlation.CorrelatedInsight) string {
	var evidence strings.Builder

	evidence.WriteString(fmt.Sprintf("Confidence: %.2f\n", insight.Confidence))
	evidence.WriteString(fmt.Sprintf("Type: %s\n", insight.Type))

	if len(insight.Evidence) > 0 {
		evidence.WriteString("\nEvidence:\n")
		for i, ev := range insight.Evidence {
			if i < 5 { // Limit to first 5 evidence items
				evidence.WriteString(fmt.Sprintf("  - %s\n", ev.Description))
			}
		}
	}

	if len(insight.RelatedNodes) > 0 {
		evidence.WriteString("\nRelated Nodes:\n")
		for i, node := range insight.RelatedNodes {
			if i < 5 { // Limit to first 5 nodes
				evidence.WriteString(fmt.Sprintf("  - %s\n", node))
			}
		}
	}

	return evidence.String()
}

// buildCorrelationSolution builds solution recommendations from correlation insight
// NOTE: This is a simplified version. There's a more detailed implementation
// in cmd/scanners/ml_correlation.go that handles specific InsightTypes.
// TODO: Consolidate these two implementations
func buildCorrelationSolution(insight correlation.CorrelatedInsight) string {
	// Default solution based on insight type
	solutions := map[string]string{
		"infrastructure": "Review infrastructure configuration and security posture. Ensure all components are up-to-date and properly secured.",
		"technology":     "Analyze technology stack for known vulnerabilities. Update to latest secure versions where possible.",
		"organization":   "Review organization-level security policies and access controls.",
	}

	if solution, ok := solutions[string(insight.Type)]; ok {
		return solution
	}

	return "Review this correlation finding and assess potential security implications."
}

func getNetworkAuthCount(networkAuth *authdiscovery.NetworkAuthMethods) int {
	return len(networkAuth.SSH) + len(networkAuth.RDP) +
		len(networkAuth.Kerberos) + len(networkAuth.LDAP) +
		len(networkAuth.RADIUS) + len(networkAuth.SMB) +
		len(networkAuth.SMTP) + len(networkAuth.IMAP)
}

func getWebAuthCount(webAuth *authdiscovery.WebAuthMethods) int {
	return len(webAuth.FormLogin) + len(webAuth.BasicAuth) +
		len(webAuth.OAuth2) + len(webAuth.SAML) +
		len(webAuth.OIDC) + len(webAuth.WebAuthn) +
		len(webAuth.CAS) + len(webAuth.JWT) +
		len(webAuth.NTLM) + len(webAuth.Cookies) +
		len(webAuth.Headers)
}

func getAPIAuthCount(apiAuth *authdiscovery.APIAuthMethods) int {
	return len(apiAuth.REST) + len(apiAuth.GraphQL) + len(apiAuth.SOAP)
}
