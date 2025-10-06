package platform

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/platforms"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/platforms/aws"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/platforms/azure"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/platforms/bugcrowd"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/platforms/hackerone"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// WorkflowManager handles automated platform submission workflows
type WorkflowManager struct {
	config    *config.Config
	platforms map[string]platforms.Platform
}

// NewWorkflowManager creates a new workflow manager
func NewWorkflowManager(cfg *config.Config) *WorkflowManager {
	wm := &WorkflowManager{
		config:    cfg,
		platforms: make(map[string]platforms.Platform),
	}

	// Initialize enabled platforms
	if cfg.Platforms.HackerOne.Enabled {
		wm.platforms["hackerone"] = hackerone.NewClient(cfg.Platforms.HackerOne)
	}
	if cfg.Platforms.Bugcrowd.Enabled {
		wm.platforms["bugcrowd"] = bugcrowd.NewClient(cfg.Platforms.Bugcrowd)
	}
	if cfg.Platforms.AWS.Enabled {
		wm.platforms["aws"] = aws.NewClient(cfg.Platforms.AWS)
	}
	if cfg.Platforms.Azure.Enabled {
		wm.platforms["azure"] = azure.NewClient(cfg.Platforms.Azure)
	}

	return wm
}

// SubmissionResult represents the result of a platform submission
type SubmissionResult struct {
	Platform  string
	Success   bool
	Response  *platforms.SubmissionResponse
	Error     error
	Skipped   bool
	SkipReason string
}

// AutoSubmitFindings automatically submits findings to all enabled platforms
func (wm *WorkflowManager) AutoSubmitFindings(ctx context.Context, findings []types.Finding, programHandle string) []SubmissionResult {
	results := make([]SubmissionResult, 0)

	for platformName, client := range wm.platforms {
		platformCfg := wm.getPlatformConfig(platformName)

		if !shouldAutoSubmit(platformCfg) {
			continue
		}

		for _, finding := range findings {
			// Check severity threshold
			if !meetsSeverityThreshold(string(finding.Severity), platformCfg) {
				results = append(results, SubmissionResult{
					Platform:   platformName,
					Success:    false,
					Skipped:    true,
					SkipReason: fmt.Sprintf("Below minimum severity threshold (%s)", getMinSeverity(platformCfg)),
				})
				continue
			}

			// Convert finding to report
			report := convertFindingToReport(&finding, programHandle)

			// Submit with timeout
			submitCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			response, err := client.Submit(submitCtx, report)
			cancel()

			result := SubmissionResult{
				Platform: platformName,
				Success:  err == nil,
				Response: response,
				Error:    err,
			}

			results = append(results, result)
		}
	}

	return results
}

// SubmitFinding submits a single finding to a specific platform
func (wm *WorkflowManager) SubmitFinding(ctx context.Context, finding *types.Finding, platformName, programHandle string) (*platforms.SubmissionResponse, error) {
	client, exists := wm.platforms[platformName]
	if !exists {
		return nil, fmt.Errorf("platform %s not enabled or not found", platformName)
	}

	report := convertFindingToReport(finding, programHandle)

	submitCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	return client.Submit(submitCtx, report)
}

// GetEnabledPlatforms returns list of enabled platform names
func (wm *WorkflowManager) GetEnabledPlatforms() []string {
	platforms := make([]string, 0, len(wm.platforms))
	for name := range wm.platforms {
		platforms = append(platforms, name)
	}
	return platforms
}

// ValidateAllCredentials validates credentials for all enabled platforms
func (wm *WorkflowManager) ValidateAllCredentials(ctx context.Context) map[string]error {
	results := make(map[string]error)

	for name, client := range wm.platforms {
		validateCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := client.ValidateCredentials(validateCtx)
		cancel()

		results[name] = err
	}

	return results
}

// Helper functions

func (wm *WorkflowManager) getPlatformConfig(platform string) interface{} {
	switch platform {
	case "hackerone":
		return wm.config.Platforms.HackerOne
	case "bugcrowd":
		return wm.config.Platforms.Bugcrowd
	case "aws":
		return wm.config.Platforms.AWS
	case "azure":
		return wm.config.Platforms.Azure
	default:
		return nil
	}
}

func shouldAutoSubmit(cfg interface{}) bool {
	switch c := cfg.(type) {
	case config.HackerOneConfig:
		return c.AutoSubmit
	case config.BugcrowdConfig:
		return c.AutoSubmit
	case config.AWSBountyConfig:
		return c.AutoSubmit
	case config.AzureBountyConfig:
		return c.AutoSubmit
	default:
		return false
	}
}

func meetsSeverityThreshold(severity string, cfg interface{}) bool {
	threshold := getMinSeverity(cfg)

	severityLevels := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
		"INFO":     0,
	}

	findingSev := severityLevels[severity]
	thresholdSev := severityLevels[threshold]

	return findingSev >= thresholdSev
}

func getMinSeverity(cfg interface{}) string {
	switch c := cfg.(type) {
	case config.HackerOneConfig:
		return c.MinimumSeverity
	case config.BugcrowdConfig:
		return c.MinimumSeverity
	case config.AWSBountyConfig:
		return c.MinimumSeverity
	case config.AzureBountyConfig:
		return c.MinimumSeverity
	default:
		return "MEDIUM"
	}
}

func convertFindingToReport(finding *types.Finding, programHandle string) *platforms.VulnerabilityReport {
	// Extract additional metadata if available
	var cwe string
	var cvssScore float64
	var impact string
	var assetURL string
	var remediation string
	var discoveredAt = finding.CreatedAt
	reproSteps := []string{}

	if finding.Metadata != nil {
		if c, ok := finding.Metadata["cwe"].(string); ok {
			cwe = c
		}
		if score, ok := finding.Metadata["cvss_score"].(float64); ok {
			cvssScore = score
		}
		if imp, ok := finding.Metadata["impact"].(string); ok {
			impact = imp
		}
		if url, ok := finding.Metadata["asset_url"].(string); ok {
			assetURL = url
		}
		if url, ok := finding.Metadata["target"].(string); ok && assetURL == "" {
			assetURL = url
		}
		if rem, ok := finding.Metadata["remediation"].(string); ok {
			remediation = rem
		}
		if steps, ok := finding.Metadata["repro_steps"].([]interface{}); ok {
			for _, step := range steps {
				if s, ok := step.(string); ok {
					reproSteps = append(reproSteps, s)
				}
			}
		}
	}

	// Use Solution field as remediation if not in metadata
	if remediation == "" {
		remediation = finding.Solution
	}

	return &platforms.VulnerabilityReport{
		Title:          finding.Title,
		Description:    finding.Description,
		Severity:       string(finding.Severity),
		CVSSScore:      cvssScore,
		CWE:            cwe,
		ProgramHandle:  programHandle,
		AssetURL:       assetURL,
		ProofOfConcept: finding.Evidence,
		ReproSteps:     reproSteps,
		Impact:         impact,
		Remediation:    remediation,
		DiscoveredAt:   discoveredAt,
		ScanID:         finding.ScanID,
		ToolName:       finding.Tool,
	}
}
