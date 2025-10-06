package scanners

// Secrets Scanning Functions
//
// Extracted from cmd/root.go Phase 2 refactoring (2025-10-06)
// Contains TruffleHog integration and secrets detection

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/scanners/secrets"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// runSecretsScanning executes secrets scanning on the target
func (e *ScanExecutor) runSecretsScanning(ctx context.Context, target string) []types.Finding {
	e.log.WithContext(ctx).Debugw("Starting secrets scanning", "target", target)

	// Create TruffleHog scanner with internal logger
	scanner := secrets.NewTruffleHogScanner(e.log.WithComponent("trufflehog"))

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
			e.log.Infow("URL target detected - secrets scanning not directly applicable",
				"target", target)
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
		e.log.Infow("Domain target detected - no direct secrets scanning applicable",
			"target", target)
		return convertDomainToSecretsFinding(target)
	}

	if err != nil {
		e.log.LogError(ctx, err, "Secrets scanning failed", "target", target)
		return []types.Finding{}
	}

	// Convert SecretFinding to types.Finding
	findings := convertSecretFindings(allSecrets, target)

	e.log.WithContext(ctx).Infow("Secrets scanning completed",
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
			"target":     target,
			"scan_type":  "url_detection",
			"actionable": false,
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
			"target":     target,
			"scan_type":  "domain_detection",
			"actionable": false,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return []types.Finding{finding}
}
