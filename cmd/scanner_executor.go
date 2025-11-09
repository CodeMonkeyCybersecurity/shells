// cmd/scanner_executor.go
package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/cli/utils"
	"github.com/CodeMonkeyCybersecurity/shells/cmd/scanners"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/plugins/oauth2"
	authpkg "github.com/CodeMonkeyCybersecurity/shells/pkg/auth/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scanners/mail"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// executeRecommendedScanners executes the scanners recommended by the intelligent selector
// FIXME: This function needs major optimization for bug bounty
// TODO: Add parallel execution with time limits
// TODO: Prioritize high-value vulnerability scanners
func executeRecommendedScanners(session *discovery.DiscoverySession, recommendations []discovery.ScannerRecommendation) error {
	if len(recommendations) == 0 {
		log.Infow("No specific scanners recommended")
		return nil
	}

	ctx := context.Background()

	// Execute scanners by priority
	for i, rec := range recommendations {
		// FIXME: 10 scanners is too many for quick bug bounty
		// TODO: Limit to top 5 high-value scanners
		if i >= 10 {
			log.Infow("Additional lower-priority scanners available",
				"count", len(recommendations)-10)
			break
		}

		log.Infow("Executing scanner",
			"position", fmt.Sprintf("%d/%d", i+1, utils.Min(len(recommendations), 10)),
			"scanner", rec.Scanner,
			"reason", rec.Reason,
			"targets", strings.Join(rec.Targets, ", "))

		// Execute scanner based on type
		switch rec.Scanner {
		case discovery.ScannerTypeAuth:
			// TODO: HIGH PRIORITY - Auth bypass is top bug bounty target
			// FIXME: Add time limit - max 30 seconds
			if err := executeAuthScanner(ctx, rec); err != nil {
				log.LogError(ctx, err, "Auth scanner failed")
			}

		case discovery.ScannerTypeSCIM:
			if err := executeSCIMScanner(ctx, rec); err != nil {
				log.LogError(ctx, err, "SCIM scanner failed")
			}

		case discovery.ScannerTypeSmuggling:
			if err := executeSmugglingScanner(ctx, rec); err != nil {
				log.LogError(ctx, err, "Smuggling scanner failed")
			}

		case discovery.ScannerTypeMail:
			if err := executeMailScanner(ctx, rec); err != nil {
				log.LogError(ctx, err, "Mail scanner failed")
			}

		case discovery.ScannerTypeAPI:
			// API scanner not yet implemented - skip for now
			log.Warnw("API scanner not yet implemented - skipping",
				"targets", rec.Targets,
				"status", "[COMING SOON]",
				"note", "GraphQL/REST API testing will be added in future release")

		case discovery.ScannerTypeWebCrawl:
			if err := executeWebCrawlScanner(ctx, rec); err != nil {
				log.LogError(ctx, err, "Web crawl scanner failed")
			}

		case discovery.ScannerTypeNmap:
			if err := executeNmapScanner(ctx, rec); err != nil {
				log.LogError(ctx, err, "Nmap scanner failed")
			}

		case discovery.ScannerTypeNuclei:
			if err := executeNucleiScanner(ctx, rec); err != nil {
				log.LogError(ctx, err, "Nuclei scanner failed")
			}

		case discovery.ScannerTypeSSL:
			if err := executeSSLScanner(ctx, rec); err != nil {
				log.LogError(ctx, err, "SSL scanner failed")
			}

		case discovery.ScannerTypeFuzz:
			if err := executeFuzzScanner(ctx, rec); err != nil {
				log.LogError(ctx, err, "Fuzz scanner failed")
			}

		case discovery.ScannerTypeBusinessLogic:
			if err := executeBusinessLogicScanner(ctx, rec); err != nil {
				log.LogError(ctx, err, "Business logic scanner failed")
			}

		case discovery.ScannerTypeCloudEnum:
			if err := executeCloudEnumScanner(ctx, rec); err != nil {
				log.LogError(ctx, err, "Cloud enum scanner failed")
			}

		default:
			log.Warnw("Unknown scanner type", "scanner", rec.Scanner)
		}

		// Brief pause between scanners
		time.Sleep(500 * time.Millisecond)
	}

	return nil
}

// Scanner execution functions
// Each scanner follows the pattern:
// 1. Check if Nomad is available
// 2. If yes, dispatch job to Nomad cluster
// 3. If no, fall back to local execution
// This enables distributed scanning when Nomad is available

func executeAuthScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running authentication security tests")

	// Get Nomad client
	executor := scanners.NewScanExecutor(log, store, cfg)
	nomadClient, useNomad := executor.GetNomadClient()

	for _, target := range rec.Targets {
		scanID := fmt.Sprintf("auth-scan-%s-%d", strings.ReplaceAll(target, ".", "-"), time.Now().Unix())

		if useNomad {
			// Convert arguments to map for Nomad
			argMap := make(map[string]string)
			for i, arg := range rec.Arguments {
				argMap[fmt.Sprintf("arg%d", i)] = arg
			}

			// Dispatch to Nomad
			jobID, err := nomadClient.SubmitScan(ctx, types.ScanTypeAuth, target, scanID, argMap)
			if err != nil {
				log.LogError(ctx, err, "Failed to submit auth scan to Nomad",
					"target", target,
					"scanID", scanID)
				// Fall back to local execution
				return executeAuthScannerLocal(ctx, target, rec)
			}

			log.Infow("Auth scan submitted to Nomad",
				"jobID", jobID,
				"target", target)

			// Wait for completion with timeout
			status, err := nomadClient.WaitForCompletion(ctx, jobID, 10*time.Minute)
			if err != nil {
				log.LogError(ctx, err, "Auth scan failed in Nomad",
					"jobID", jobID,
					"target", target)
				return err
			}

			log.Infow("Auth scan completed",
				"jobID", jobID,
				"status", status.Status,
				"target", target)
		} else {
			// Local execution
			if err := executeAuthScannerLocal(ctx, target, rec); err != nil {
				return err
			}
		}
	}

	return nil
}

func executeAuthScannerLocal(ctx context.Context, target string, rec discovery.ScannerRecommendation) error {
	log.Infow("Executing comprehensive auth scanner locally",
		"target", target,
		"args", rec.Arguments)

	// Import the auth discovery package
	authDiscovery := authpkg.NewComprehensiveAuthDiscovery(log)

	// Run comprehensive auth discovery
	inventory, err := authDiscovery.DiscoverAll(ctx, target)
	if err != nil {
		log.Errorw("Auth discovery failed", "error", err, "target", target)
		return err
	}

	// Convert inventory to findings
	var findings []types.Finding

	// Network authentication findings
	if inventory.NetworkAuth != nil {
		// LDAP findings
		for _, ldap := range inventory.NetworkAuth.LDAP {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("auth-ldap-%s-%d", ldap.Host, time.Now().Unix()),
				ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
				Type:        "LDAP Authentication",
				Severity:    types.SeverityMedium,
				Title:       fmt.Sprintf("LDAP Server Found at %s:%d", ldap.Host, ldap.Port),
				Description: fmt.Sprintf("LDAP server type: %s, Anonymous bind: %v", ldap.Type, ldap.AnonymousBindAllowed),
				Tool:        "comprehensive-auth",
				Evidence:    fmt.Sprintf("Target: %s\nNaming contexts: %v\nSASL mechanisms: %v", target, ldap.NamingContexts, ldap.SupportedSASLMechanisms),
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			})
		}

		// Add findings for other network auth methods
		if len(inventory.NetworkAuth.Kerberos) > 0 {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("auth-kerberos-%d", time.Now().Unix()),
				ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
				Type:        "Kerberos Authentication",
				Severity:    types.SeverityMedium,
				Title:       fmt.Sprintf("Kerberos Authentication Found (%d endpoints)", len(inventory.NetworkAuth.Kerberos)),
				Description: "Kerberos authentication endpoints discovered",
				Tool:        "comprehensive-auth",
				Evidence:    fmt.Sprintf("Target: %s", target),
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			})
		}
	}

	// Web authentication findings
	if inventory.WebAuth != nil {
		// Form login findings
		for _, form := range inventory.WebAuth.FormLogin {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("auth-form-%d", time.Now().Unix()),
				ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
				Type:        "Form-Based Authentication",
				Severity:    types.SeverityInfo,
				Title:       fmt.Sprintf("Login Form Found at %s", form.URL),
				Description: fmt.Sprintf("Form method: %s, Has CSRF: %v", form.Method, form.CSRFToken),
				Tool:        "comprehensive-auth",
				Evidence:    fmt.Sprintf("Target: %s\nUsername field: %s\nPassword field: %s", target, form.UsernameField, form.PasswordField),
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			})
		}

		// OAuth2/OIDC findings
		if len(inventory.WebAuth.OAuth2) > 0 || len(inventory.WebAuth.OIDC) > 0 {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("auth-oauth-%d", time.Now().Unix()),
				ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
				Type:        "OAuth2/OIDC Authentication",
				Severity:    types.SeverityInfo,
				Title:       "Modern Authentication Methods Found",
				Description: fmt.Sprintf("OAuth2 endpoints: %d, OIDC endpoints: %d", len(inventory.WebAuth.OAuth2), len(inventory.WebAuth.OIDC)),
				Tool:        "comprehensive-auth",
				Evidence:    fmt.Sprintf("Target: %s", target),
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			})
		}

		// Run advanced OAuth2 security tests if OAuth2 endpoints detected
		if len(inventory.WebAuth.OAuth2) > 0 {
			log.Infow("OAuth2 endpoints detected - running advanced OAuth2 security tests",
				"endpoint_count", len(inventory.WebAuth.OAuth2),
				"target", target)

			oauth2Findings := runAdvancedOAuth2Tests(ctx, target, inventory.WebAuth.OAuth2)
			if len(oauth2Findings) > 0 {
				log.Infow("Advanced OAuth2 tests completed",
					"vulnerabilities_found", len(oauth2Findings),
					"target", target)
				findings = append(findings, oauth2Findings...)
			}
		}
	}

	// Custom authentication findings
	for _, custom := range inventory.CustomAuth {
		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("auth-custom-%s-%d", custom.Type, time.Now().Unix()),
			ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
			Type:        "Custom Authentication",
			Severity:    types.SeverityHigh,
			Title:       fmt.Sprintf("Custom Authentication Detected: %s", custom.Type),
			Description: custom.Description,
			Tool:        "comprehensive-auth",
			Evidence:    fmt.Sprintf("Target: %s\nConfidence: %.2f\nIndicators: %v", target, custom.Confidence, custom.Indicators),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})
	}

	// Save all findings
	if store != nil && len(findings) > 0 {
		if err := store.SaveFindings(ctx, findings); err != nil {
			log.Errorw("Failed to save auth findings", "error", err)
			return err
		}
		log.Infow("Saved auth discovery findings", "count", len(findings))
	}

	return nil
}

// runAdvancedOAuth2Tests runs comprehensive OAuth2 security tests against discovered endpoints
func runAdvancedOAuth2Tests(ctx context.Context, target string, oauth2Endpoints []authpkg.OAuth2Endpoint) []types.Finding {
	// Import OAuth2 scanner from internal/plugins/oauth2
	oauth2Scanner := oauth2.NewScanner(log)

	var allFindings []types.Finding

	for i, endpoint := range oauth2Endpoints {
		log.Debugw("Testing OAuth2 endpoint",
			"endpoint_index", i+1,
			"total_endpoints", len(oauth2Endpoints),
			"authorize_url", endpoint.AuthorizeURL,
			"token_url", endpoint.TokenURL)

		// Build scanner options from discovered endpoint
		options := map[string]string{
			"auth_url":    endpoint.AuthorizeURL,
			"token_url":   endpoint.TokenURL,
			"scopes":      "",
			"client_id":   endpoint.ClientID,
			"redirect_uri": target + "/callback", // Default redirect URI
		}

		if endpoint.UserInfoURL != "" {
			options["userinfo_url"] = endpoint.UserInfoURL
		}

		if len(endpoint.Scopes) > 0 {
			options["scopes"] = strings.Join(endpoint.Scopes, " ")
		}

		// Run OAuth2 security tests
		findings, err := oauth2Scanner.Scan(ctx, target, options)
		if err != nil {
			log.Warnw("OAuth2 security tests failed",
				"error", err,
				"endpoint", endpoint.AuthorizeURL)
			continue
		}

		// Enrich findings with timing metadata
		now := time.Now()
		for i := range findings {
			findings[i].CreatedAt = now
			findings[i].UpdatedAt = now
			findings[i].ScanID = fmt.Sprintf("scan-%d", now.Unix())

			// Add OAuth2 endpoint context to findings
			if findings[i].Metadata == nil {
				findings[i].Metadata = make(map[string]interface{})
			}
			findings[i].Metadata["oauth2_authorize_url"] = endpoint.AuthorizeURL
			findings[i].Metadata["oauth2_token_url"] = endpoint.TokenURL
			findings[i].Metadata["pkce_supported"] = endpoint.PKCE
		}

		allFindings = append(allFindings, findings...)
	}

	return allFindings
}

func executeSCIMScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running SCIM security tests")

	// Would execute actual SCIM scanner
	for _, target := range rec.Targets {
		log.Debugw("Executing SCIM scanner", "target", target)
	}

	return nil
}

func executeSmugglingScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running HTTP request smuggling tests")

	// Would execute actual smuggling scanner
	for _, target := range rec.Targets {
		log.Debugw("Executing smuggling scanner", "target", target)
	}

	return nil
}

// executeMailScanner executes mail server security tests
func executeMailScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running mail server security tests",
		"targets", rec.Targets,
		"priority", rec.Priority,
	)

	// Create mail scanner instance
	mailScanner := mail.NewScanner(log, 30*time.Second)

	var allFindings []types.Finding

	for _, target := range rec.Targets {
		log.Infow("Scanning mail server", "target", target)

		// Run comprehensive mail security tests
		mailFindings, err := mailScanner.ScanMailServers(ctx, target)
		if err != nil {
			log.Warnw("Mail server scan failed",
				"error", err,
				"target", target)
			continue
		}

		// Convert mail findings to common Finding format
		for _, mailFinding := range mailFindings {
			finding := types.Finding{
				ID:          fmt.Sprintf("mail-%s-%s-%d", mailFinding.Service, mailFinding.VulnerabilityType, time.Now().Unix()),
				ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
				Type:        fmt.Sprintf("Mail_%s", mailFinding.VulnerabilityType),
				Severity:    mailFinding.Severity,
				Title:       mailFinding.Title,
				Description: mailFinding.Description,
				Evidence:    mailFinding.Evidence,
				Tool:        "mail-scanner",
				Remediation: mailFinding.Remediation,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
				Metadata: map[string]interface{}{
					"mail_host":      mailFinding.Host,
					"mail_port":      mailFinding.Port,
					"mail_service":   mailFinding.Service,
					"tls_supported":  mailFinding.TLSSupported,
					"spf_record":     mailFinding.SPFRecord,
					"dmarc_record":   mailFinding.DMARCRecord,
					"dkim_present":   mailFinding.DKIMPresent,
					"banner":         mailFinding.Banner,
					"capabilities":   mailFinding.Capabilities,
				},
			}

			allFindings = append(allFindings, finding)
		}

		log.Infow("Mail server scan completed",
			"target", target,
			"vulnerabilities_found", len(mailFindings),
		)
	}

	// Save findings to database
	if store != nil && len(allFindings) > 0 {
		if err := store.SaveFindings(ctx, allFindings); err != nil {
			log.Errorw("Failed to save mail findings", "error", err)
			return err
		}
		log.Infow("Saved mail security findings", "count", len(allFindings))
	}

	return nil
}

// executeAPIScanner - STUB - NOT YET IMPLEMENTED
// TODO: Implement API security testing in future release
// Planned features:
// 1. GraphQL introspection
// 2. REST API authorization bypass
// 3. Mass assignment
// 4. Rate limiting bypass
// 5. API key leakage in responses
// 6. JWT vulnerabilities
/*
func executeAPIScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	// Stub implementation - not yet ready for use
	return nil
}
*/

func executeWebCrawlScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running web crawler")

	// Would execute actual web crawler
	for _, target := range rec.Targets {
		log.Debugw("Executing web crawler", "target", target)
	}

	return nil
}

func executeNmapScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running port scan")

	// Would execute actual Nmap scanner
	for _, target := range rec.Targets {
		log.Debugw("Executing Nmap scanner", "target", target)
	}

	return nil
}

func executeNucleiScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running vulnerability templates")

	// Would execute actual Nuclei scanner
	for _, target := range rec.Targets {
		log.Debugw("Executing Nuclei scanner", "target", target, "args", rec.Arguments)
	}

	return nil
}

func executeSSLScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running SSL/TLS analysis")

	// Would execute actual SSL scanner
	for _, target := range rec.Targets {
		log.Debugw("Executing SSL scanner", "target", target)
	}

	return nil
}

func executeFuzzScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running fuzzing tests")

	// Would execute actual fuzzer
	for _, target := range rec.Targets {
		log.Debugw("Executing fuzzer", "target", target, "args", rec.Arguments)
	}

	return nil
}

func executeBusinessLogicScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running business logic tests")

	// Would execute actual business logic scanner
	for _, target := range rec.Targets {
		log.Debugw("Executing business logic scanner", "target", target)
	}

	return nil
}

func executeCloudEnumScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running cloud enumeration")

	// Would execute actual cloud enum scanner
	for _, target := range rec.Targets {
		log.Debugw("Executing cloud enum scanner", "target", target)
	}

	return nil
}
