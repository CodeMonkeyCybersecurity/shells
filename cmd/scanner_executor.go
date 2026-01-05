// cmd/scanner_executor.go
package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/cmd/scanners"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	authpkg "github.com/CodeMonkeyCybersecurity/shells/pkg/auth/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/cli/utils"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scanners/api"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scanners/mail"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

type structuredLoggerAdapter struct {
	base *logger.Logger
}

func convertSeverity(sev string) types.Severity {
	switch strings.ToLower(sev) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

func (a *structuredLoggerAdapter) Info(msg string, keysAndValues ...interface{}) {
	if a.base != nil {
		a.base.Infow(msg, keysAndValues...)
	}
}

func (a *structuredLoggerAdapter) Infow(msg string, keysAndValues ...interface{}) {
	if a.base != nil {
		a.base.Infow(msg, keysAndValues...)
	}
}

func (a *structuredLoggerAdapter) Debug(msg string, keysAndValues ...interface{}) {
	if a.base != nil {
		a.base.Debugw(msg, keysAndValues...)
	}
}

func (a *structuredLoggerAdapter) Debugw(msg string, keysAndValues ...interface{}) {
	if a.base != nil {
		a.base.Debugw(msg, keysAndValues...)
	}
}

func (a *structuredLoggerAdapter) Warn(msg string, keysAndValues ...interface{}) {
	if a.base != nil {
		a.base.Warnw(msg, keysAndValues...)
	}
}

func (a *structuredLoggerAdapter) Warnw(msg string, keysAndValues ...interface{}) {
	if a.base != nil {
		a.base.Warnw(msg, keysAndValues...)
	}
}

func (a *structuredLoggerAdapter) Error(msg string, keysAndValues ...interface{}) {
	if a.base != nil {
		a.base.Errorw(msg, keysAndValues...)
	}
}

func (a *structuredLoggerAdapter) Errorw(msg string, keysAndValues ...interface{}) {
	if a.base != nil {
		a.base.Errorw(msg, keysAndValues...)
	}
}

func adaptStructuredLogger(l *logger.Logger) *structuredLoggerAdapter {
	if l == nil {
		return nil
	}
	return &structuredLoggerAdapter{base: l}
}

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
			if err := executeAPIScanner(ctx, rec); err != nil {
				log.LogError(ctx, err, "API scanner failed")
			}

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
		"args", rec.Arguments,
	)

	authDiscovery := authpkg.NewComprehensiveAuthDiscovery(log)

	inventory, err := authDiscovery.DiscoverAll(ctx, target)
	if err != nil {
		log.Errorw("Auth discovery failed", "error", err, "target", target)
		return err
	}

	var findings []types.Finding

	if inventory.NetworkAuth != nil {
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

	if inventory.WebAuth != nil {
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
	}

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

	if store != nil && len(findings) > 0 {
		if err := store.SaveFindings(ctx, findings); err != nil {
			log.Errorw("Failed to save auth findings", "error", err)
			return err
		}
		log.Infow("Saved auth discovery findings", "count", len(findings))
	}

	return nil
}

func executeSCIMScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running SCIM security tests")

	for _, target := range rec.Targets {
		log.Debugw("Executing SCIM scanner", "target", target)
	}

	return nil
}

func executeSmugglingScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running HTTP request smuggling tests")

	for _, target := range rec.Targets {
		log.Debugw("Executing smuggling scanner", "target", target)
	}

	return nil
}

func executeMailScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running mail server security tests",
		"targets", rec.Targets,
		"priority", rec.Priority,
	)

	// Create mail scanner instance
	mailScanner := mail.NewScanner(adaptStructuredLogger(log), 30*time.Second)

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
				Severity:    convertSeverity(mailFinding.Severity),
				Title:       mailFinding.Title,
				Description: mailFinding.Description,
				Evidence:    mailFinding.Evidence,
				Tool:        "mail-scanner",
				Solution:    mailFinding.Remediation,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
				Metadata: map[string]interface{}{
					"mail_host":     mailFinding.Host,
					"mail_port":     mailFinding.Port,
					"mail_service":  mailFinding.Service,
					"tls_supported": mailFinding.TLSSupported,
					"spf_record":    mailFinding.SPFRecord,
					"dmarc_record":  mailFinding.DMARCRecord,
					"dkim_present":  mailFinding.DKIMPresent,
					"banner":        mailFinding.Banner,
					"capabilities":  mailFinding.Capabilities,
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

func executeAPIScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running API security tests",
		"targets", rec.Targets,
		"priority", rec.Priority,
	)

	// Create API scanner instance
	apiScanner := api.NewScanner(adaptStructuredLogger(log), 60*time.Second)

	var allFindings []types.Finding

	for _, target := range rec.Targets {
		log.Infow("Scanning API endpoint", "target", target)

		// Run comprehensive API security tests
		apiFindings, err := apiScanner.ScanAPI(ctx, target)
		if err != nil {
			log.Warnw("API scan failed",
				"error", err,
				"target", target)
			continue
		}

		// Convert API findings to common Finding format
		for _, apiFinding := range apiFindings {
			finding := types.Finding{
				ID:          fmt.Sprintf("api-%s-%s-%d", apiFinding.APIType, apiFinding.VulnerabilityType, time.Now().Unix()),
				ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
				Type:        fmt.Sprintf("API_%s", apiFinding.VulnerabilityType),
				Severity:    convertSeverity(apiFinding.Severity),
				Title:       apiFinding.Title,
				Description: apiFinding.Description,
				Evidence:    apiFinding.Evidence,
				Tool:        "api-scanner",
				Solution:    apiFinding.Remediation,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
				Metadata: map[string]interface{}{
					"api_endpoint":     apiFinding.Endpoint,
					"api_type":         apiFinding.APIType,
					"http_method":      apiFinding.Method,
					"http_status_code": apiFinding.StatusCode,
					"authentication":   apiFinding.Authentication,
					"request_body":     apiFinding.RequestBody,
					"response_body":    apiFinding.ResponseBody,
					"exploit_payload":  apiFinding.ExploitPayload,
				},
			}

			// Merge additional metadata if present
			if apiFinding.Metadata != nil {
				for k, v := range apiFinding.Metadata {
					finding.Metadata[k] = v
				}
			}

			allFindings = append(allFindings, finding)
		}

		log.Infow("API scan completed",
			"target", target,
			"vulnerabilities_found", len(apiFindings),
		)
	}

	// Save findings to database
	if store != nil && len(allFindings) > 0 {
		if err := store.SaveFindings(ctx, allFindings); err != nil {
			log.Errorw("Failed to save API findings", "error", err)
			return err
		}
		log.Infow("Saved API security findings", "count", len(allFindings))
	}

	return nil
}

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
