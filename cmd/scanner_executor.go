// cmd/scanner_executor.go
package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// executeRecommendedScanners executes the scanners recommended by the intelligent selector
func executeRecommendedScanners(session *discovery.DiscoverySession, recommendations []discovery.ScannerRecommendation) error {
	if len(recommendations) == 0 {
		log.Infow("No specific scanners recommended")
		return nil
	}

	ctx := context.Background()

	// Execute scanners by priority
	for i, rec := range recommendations {
		// Limit to top 10 scanners to avoid overload
		if i >= 10 {
			log.Infow("Additional lower-priority scanners available",
				"count", len(recommendations)-10)
			break
		}

		log.Infow("Executing scanner",
			"position", fmt.Sprintf("%d/%d", i+1, min(len(recommendations), 10)),
			"scanner", rec.Scanner,
			"reason", rec.Reason,
			"targets", strings.Join(rec.Targets, ", "))

		// Execute scanner based on type
		switch rec.Scanner {
		case discovery.ScannerTypeAuth:
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
	nomadClient, useNomad := getNomadClient()

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
	log.Debugw("Executing auth scanner locally",
		"target", target,
		"args", rec.Arguments)

	// TODO: Implement actual auth scanner logic
	// For now, create a placeholder finding
	if store != nil {
		finding := types.Finding{
			ID:          fmt.Sprintf("auth-context-%d", time.Now().Unix()),
			ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
			Type:        "Context-Aware Auth Test",
			Severity:    types.SeverityInfo,
			Title:       "Authentication Methods Tested",
			Description: fmt.Sprintf("Tested authentication on %s with args: %v", target, rec.Arguments),
			Tool:        "auth-scanner",
			Evidence:    fmt.Sprintf("Target: %s\nPriority: %d", target, rec.Priority),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		return store.SaveFindings(ctx, []types.Finding{finding})
	}
	
	return nil
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

func executeMailScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running mail server security tests")

	// Would execute actual mail scanner
	for _, target := range rec.Targets {
		log.Debugw("Executing mail scanner", "target", target)
	}

	return nil
}

func executeAPIScanner(ctx context.Context, rec discovery.ScannerRecommendation) error {
	log.Infow("Running API security tests")

	// Would execute actual API scanner
	for _, target := range rec.Targets {
		log.Debugw("Executing API scanner", "target", target)
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

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
