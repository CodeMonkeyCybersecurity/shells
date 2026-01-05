package scanners

// Passive Intelligence Functions
//
// Extracted from cmd/root.go Phase 2 refactoring (2025-10-06)
// Contains certificate transparency, archive analysis, and code repository intelligence

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/cmd/internal/utils"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/passive"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// runPassiveIntelligence executes passive intelligence gathering
func (e *ScanExecutor) runPassiveIntelligence(ctx context.Context, target string) []types.Finding {
	e.log.WithContext(ctx).Debugw("Starting passive intelligence gathering", "target", target)

	allFindings := []types.Finding{}

	// 1. Certificate Transparency Intelligence
	certFindings := e.runCertificateIntelligence(ctx, target)
	if len(certFindings) > 0 {
		allFindings = append(allFindings, certFindings...)
	}

	// 2. Web Archive Intelligence
	archiveFindings := e.runArchiveIntelligence(ctx, target)
	if len(archiveFindings) > 0 {
		allFindings = append(allFindings, archiveFindings...)
	}

	// 3. Code Repository Intelligence
	codeFindings := e.runCodeRepositoryIntelligence(ctx, target)
	if len(codeFindings) > 0 {
		allFindings = append(allFindings, codeFindings...)
	}

	e.log.WithContext(ctx).Infow("Passive intelligence gathering completed",
		"target", target, "findings_count", len(allFindings))

	return allFindings
}

// runCertificateIntelligence performs certificate transparency analysis
func (e *ScanExecutor) runCertificateIntelligence(ctx context.Context, target string) []types.Finding {
	e.log.WithContext(ctx).Debugw("Starting certificate transparency intelligence", "target", target)

	var findings []types.Finding

	// Parse domain from target
	domain := target
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if parsedURL, err := url.Parse(target); err == nil {
			domain = parsedURL.Host
		}
	}

	// Create certificate intelligence module
	certIntel := passive.NewCertIntel(e.log.WithComponent("cert-intel"))

	// Discover all certificates for the domain
	certs, err := certIntel.DiscoverAllCertificates(ctx, domain)
	if err != nil {
		e.log.LogError(ctx, err, "Certificate discovery failed", "domain", domain)
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
			Evidence:    fmt.Sprintf("Total certificates: %d, Unique domains: %d", len(certs), len(utils.UniqueStrings(allDomains))),
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
				Title:       fmt.Sprintf("Wildcard Certificates Detected (%d)", len(utils.UniqueStrings(wildcardDomains))),
				Description: "Wildcard certificates found which may expose internal subdomains",
				Tool:        "cert-intel",
				Evidence:    fmt.Sprintf("Wildcard domains: %s", strings.Join(utils.UniqueStrings(wildcardDomains), ", ")),
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
				Title:       fmt.Sprintf("Internal Domains in Certificates (%d)", len(utils.UniqueStrings(internalDomains))),
				Description: "Internal-looking domain names found in public certificates",
				Tool:        "cert-intel",
				Evidence:    fmt.Sprintf("Internal domains: %s", strings.Join(utils.UniqueStrings(internalDomains), ", ")),
				Solution:    "Review internal domain exposure and consider using internal CAs for internal services",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			findings = append(findings, internalFinding)
		}
	}

	e.log.WithContext(ctx).Infow("Certificate intelligence completed",
		"domain", domain, "certificates", len(certs), "findings", len(findings))

	return findings
}

// runArchiveIntelligence performs web archive analysis
func (e *ScanExecutor) runArchiveIntelligence(ctx context.Context, target string) []types.Finding {
	e.log.WithContext(ctx).Debugw("Starting web archive intelligence", "target", target)

	var findings []types.Finding

	// Parse domain from target
	domain := target
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if parsedURL, err := url.Parse(target); err == nil {
			domain = parsedURL.Host
		}
	}

	// Create archive intelligence module
	archiveIntel := passive.NewArchiveIntel(e.log.WithComponent("archive-intel"))

	// Extract intelligence from archives
	archiveResults, err := archiveIntel.ExtractIntelligence(domain)
	if err != nil {
		e.log.LogError(ctx, err, "Archive intelligence failed", "domain", domain)
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

	e.log.WithContext(ctx).Infow("Archive intelligence completed",
		"domain", domain, "findings", len(findings))

	return findings
}

// runCodeRepositoryIntelligence performs code repository analysis
func (e *ScanExecutor) runCodeRepositoryIntelligence(ctx context.Context, target string) []types.Finding {
	e.log.WithContext(ctx).Debugw("Starting code repository intelligence", "target", target)

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
	codeIntel := passive.NewCodeIntel(e.log.WithComponent("code-intel"), "", "", "")

	// Search across platforms for domain mentions
	results, err := codeIntel.SearchAllPlatforms(ctx, domain)
	if err != nil {
		e.log.LogError(ctx, err, "Code repository search failed", "domain", domain)
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

	e.log.WithContext(ctx).Infow("Code repository intelligence completed",
		"domain", domain, "findings", len(findings))

	return findings
}
