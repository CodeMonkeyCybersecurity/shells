// internal/orchestrator/scanners/cloud/prowler.go
//
// Prowler Scanner - Multi-cloud security auditing
//
// INTEGRATION CONTEXT:
// Activates existing Prowler integration from pkg/integrations/prowler/ (734 lines)
// that was fully implemented but never registered in scanner manager.
//
// Prowler provides:
// - AWS: 400+ security checks (IAM, S3, CloudTrail, GuardDuty, etc.)
// - Azure: 200+ checks (Azure AD, Storage, Network Security)
// - GCP: 150+ checks (IAM, Cloud Storage, Compute)
// - CIS Benchmark compliance (CIS AWS v1.5, CIS Azure v1.5, CIS GCP v1.3)

package cloud

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/orchestrator/scanners"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/integrations/prowler"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// ProwlerScanner performs multi-cloud security auditing using Prowler
type ProwlerScanner struct {
	client *prowler.ProwlerClient
	logger *logger.Logger
	config ProwlerConfig
}

// ProwlerConfig contains Prowler scanner configuration
type ProwlerConfig struct {
	// Providers to scan
	Providers []string // ["aws", "azure", "gcp"]

	// AWS-specific
	AWSProfile     string   // AWS credential profile
	AWSRegions     []string // Regions to scan
	CISProfile     string   // "cis", "hipaa", "gdpr", "pci-dss"
	CheckGroups    []string // Specific check groups to run
	SkipCheckIDs   []string // Check IDs to skip
	MaxWorkers     int      // Parallel checks
	Timeout        time.Duration
	OutputFormat   string // "json", "csv", "html"
	EnableBaseline bool   // Store first scan as baseline
}

// NewProwlerScanner creates a new Prowler scanner
func NewProwlerScanner(client *prowler.ProwlerClient, logger *logger.Logger, config ProwlerConfig) *ProwlerScanner {
	if len(config.Providers) == 0 {
		config.Providers = []string{"aws"} // Default to AWS
	}
	if config.AWSProfile == "" {
		config.AWSProfile = "default"
	}
	if config.CISProfile == "" {
		config.CISProfile = "cis"
	}
	if config.MaxWorkers == 0 {
		config.MaxWorkers = 5
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Minute
	}
	if config.OutputFormat == "" {
		config.OutputFormat = "json"
	}

	return &ProwlerScanner{
		client: client,
		logger: logger.WithComponent("prowler-scanner"),
		config: config,
	}
}

// Name returns the scanner name
func (s *ProwlerScanner) Name() string {
	return "Prowler Cloud Security Scanner"
}

// Type returns the scanner type
func (s *ProwlerScanner) Type() string {
	return "cloud"
}

// Priority returns execution priority (3 = runs after infrastructure discovery)
func (s *ProwlerScanner) Priority() int {
	return 3 // After port scanning, before app-level testing
}

// CanHandle determines if this scanner can test the asset
func (s *ProwlerScanner) CanHandle(asset *scanners.AssetPriority) bool {
	// Check if asset has cloud-related tags
	for _, tag := range asset.Asset.Tags {
		if strings.Contains(tag, "aws") || strings.Contains(tag, "azure") || strings.Contains(tag, "gcp") ||
		   strings.Contains(tag, "cloud") {
			return true
		}
	}

	// Check metadata for cloud provider
	if provider, ok := asset.Asset.Metadata["cloud_provider"]; ok {
		return s.supportsProvider(provider)
	}

	// Check for cloud service patterns in domain or value
	domain := asset.Asset.Domain
	if domain == "" {
		domain = asset.Asset.Value
	}

	if domain != "" {
		cloudPatterns := []string{
			"amazonaws.com",
			"s3",
			"cloudfront",
			"azurewebsites.net",
			"blob.core.windows.net",
			"googleapis.com",
			"appspot.com",
			"cloudfunctions.net",
		}
		for _, pattern := range cloudPatterns {
			if strings.Contains(domain, pattern) {
				return true
			}
		}
	}

	return false
}

// Execute runs Prowler scanning against cloud assets
func (s *ProwlerScanner) Execute(ctx context.Context, assets []*scanners.AssetPriority) ([]types.Finding, error) {
	startTime := time.Now()
	var allFindings []types.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	s.logger.Infow("Starting Prowler cloud security audit",
		"providers", s.config.Providers,
		"profile", s.config.CISProfile,
		"asset_count", len(assets),
	)

	// Determine which cloud providers to scan based on assets
	providersToScan := s.determineProviders(assets)
	if len(providersToScan) == 0 {
		s.logger.Infow("No cloud assets detected, skipping Prowler scan")
		return []types.Finding{}, nil
	}

	s.logger.Infow("Detected cloud providers",
		"providers", providersToScan,
	)

	// Create timeout context for entire scan
	scanCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	// Scan each provider in parallel
	for _, provider := range providersToScan {
		provider := provider // Capture for goroutine

		wg.Add(1)
		go func() {
			defer wg.Done()

			s.logger.Infow("Scanning cloud provider with Prowler",
				"provider", provider,
			)

			var findings []types.Finding
			var err error

			switch provider {
			case "aws":
				findings, err = s.scanAWS(scanCtx)
			case "azure":
				findings, err = s.scanAzure(scanCtx)
			case "gcp":
				findings, err = s.scanGCP(scanCtx)
			default:
				s.logger.Warnw("Unsupported cloud provider",
					"provider", provider,
				)
				return
			}

			if err != nil {
				s.logger.Errorw("Prowler scan failed",
					"provider", provider,
					"error", err,
				)
				return
			}

			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()

			s.logger.Infow("Prowler scan completed",
				"provider", provider,
				"findings", len(findings),
			)
		}()
	}

	wg.Wait()

	duration := time.Since(startTime)
	s.logger.Infow("Prowler cloud security audit completed",
		"total_findings", len(allFindings),
		"duration", duration.String(),
		"providers_scanned", len(providersToScan),
	)

	return allFindings, nil
}

// scanAWS runs Prowler against AWS
func (s *ProwlerScanner) scanAWS(ctx context.Context) ([]types.Finding, error) {
	s.logger.Infow("Running Prowler AWS checks",
		"profile", s.config.AWSProfile,
		"cis_profile", s.config.CISProfile,
	)

	// Use check groups if specified, otherwise run all checks
	if len(s.config.CheckGroups) > 0 {
		return s.client.RunChecksByGroup(ctx, s.config.AWSProfile, s.config.CheckGroups)
	}

	// Run all checks for the specified CIS profile
	return s.client.RunAllChecks(ctx, s.config.AWSProfile)
}

// scanAzure runs Prowler against Azure
func (s *ProwlerScanner) scanAzure(ctx context.Context) ([]types.Finding, error) {
	s.logger.Infow("Running Prowler Azure checks",
		"cis_profile", s.config.CISProfile,
	)

	// Note: Prowler Azure support may require different credential configuration
	// For now, use similar pattern to AWS
	return s.client.RunAllChecks(ctx, "azure")
}

// scanGCP runs Prowler against GCP
func (s *ProwlerScanner) scanGCP(ctx context.Context) ([]types.Finding, error) {
	s.logger.Infow("Running Prowler GCP checks",
		"cis_profile", s.config.CISProfile,
	)

	// Note: Prowler GCP support may require different credential configuration
	return s.client.RunAllChecks(ctx, "gcp")
}

// determineProviders identifies which cloud providers to scan based on assets
func (s *ProwlerScanner) determineProviders(assets []*scanners.AssetPriority) []string {
	providerSet := make(map[string]bool)

	for _, asset := range assets {
		if !s.CanHandle(asset) {
			continue
		}

		// Check metadata for explicit cloud provider
		if provider, ok := asset.Asset.Metadata["cloud_provider"]; ok {
			providerLower := strings.ToLower(provider)
			if s.supportsProvider(providerLower) {
				providerSet[providerLower] = true
			}
			continue
		}

		// Check tags for provider
		for _, tag := range asset.Asset.Tags {
			tagLower := strings.ToLower(tag)
			if tagLower == "aws" || tagLower == "amazon" {
				providerSet["aws"] = true
			} else if tagLower == "azure" || tagLower == "microsoft" {
				providerSet["azure"] = true
			} else if tagLower == "gcp" || tagLower == "google" {
				providerSet["gcp"] = true
			}
		}

		// Infer from domain patterns
		domain := asset.Asset.Domain
		if domain == "" {
			domain = asset.Asset.Value
		}

		if domain != "" {
			if strings.Contains(domain, "amazonaws.com") || strings.Contains(domain, "s3") || strings.Contains(domain, "cloudfront") {
				providerSet["aws"] = true
			} else if strings.Contains(domain, "azurewebsites.net") || strings.Contains(domain, "blob.core.windows.net") {
				providerSet["azure"] = true
			} else if strings.Contains(domain, "googleapis.com") || strings.Contains(domain, "appspot.com") || strings.Contains(domain, "cloudfunctions.net") {
				providerSet["gcp"] = true
			}
		}
	}

	// Convert set to slice
	providers := []string{}
	for provider := range providerSet {
		providers = append(providers, provider)
	}

	return providers
}

// supportsProvider checks if a provider is supported and enabled
func (s *ProwlerScanner) supportsProvider(provider string) bool {
	provider = strings.ToLower(provider)
	for _, p := range s.config.Providers {
		if strings.ToLower(p) == provider {
			return true
		}
	}
	return false
}
