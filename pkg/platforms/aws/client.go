package aws

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/platforms"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/platforms/hackerone"
)

// Client implements the AWS Vulnerability Research Program client
// AWS uses HackerOne for their bug bounty program
type Client struct {
	config          config.AWSBountyConfig
	hackerOneClient *hackerone.Client
}

// NewClient creates a new AWS VRP client
func NewClient(cfg config.AWSBountyConfig) *Client {
	// AWS uses HackerOne, so we create a HackerOne client
	h1Config := config.HackerOneConfig{
		Enabled:         cfg.Enabled,
		APIUsername:     cfg.APIUsername,
		APIToken:        cfg.APIToken,
		BaseURL:         "https://api.hackerone.com/v1",
		Timeout:         cfg.Timeout,
		AutoSubmit:      cfg.AutoSubmit,
		MinimumSeverity: cfg.MinimumSeverity,
		DraftMode:       true, // Always draft for AWS
	}

	return &Client{
		config:          cfg,
		hackerOneClient: hackerone.NewClient(h1Config),
	}
}

// Name returns the platform name
func (c *Client) Name() string {
	return "AWS VRP (via HackerOne)"
}

// ValidateCredentials validates the API credentials
func (c *Client) ValidateCredentials(ctx context.Context) error {
	return c.hackerOneClient.ValidateCredentials(ctx)
}

// GetPrograms returns the AWS VRP program
func (c *Client) GetPrograms(ctx context.Context) ([]*platforms.Program, error) {
	// Get the specific AWS program from HackerOne
	program, err := c.hackerOneClient.GetProgramByHandle(ctx, c.config.ProgramHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS VRP program: %w", err)
	}

	return []*platforms.Program{program}, nil
}

// GetProgramByHandle retrieves the AWS VRP program
func (c *Client) GetProgramByHandle(ctx context.Context, handle string) (*platforms.Program, error) {
	// AWS only has one program handle
	if handle != c.config.ProgramHandle {
		return nil, fmt.Errorf("invalid program handle for AWS VRP: %s (expected: %s)", handle, c.config.ProgramHandle)
	}

	return c.hackerOneClient.GetProgramByHandle(ctx, c.config.ProgramHandle)
}

// Submit submits a vulnerability report to AWS VRP via HackerOne
func (c *Client) Submit(ctx context.Context, report *platforms.VulnerabilityReport) (*platforms.SubmissionResponse, error) {
	// Ensure the report is for the AWS program
	if report.ProgramHandle == "" {
		report.ProgramHandle = c.config.ProgramHandle
	}

	// P0-4 FIX: Validate report before submission
	if err := report.Validate(); err != nil {
		return nil, fmt.Errorf("invalid report: %w", err)
	}

	// Add AWS-specific context to the report
	awsContext := fmt.Sprintf("\n\n---\n**AWS Service**: %s\n**Region**: %s\n**Account Type**: %s",
		getServiceFromAsset(report.AssetURL),
		"N/A", // Region would be extracted from asset context
		"Public Cloud",
	)
	report.Description += awsContext

	// Submit via HackerOne
	response, err := c.hackerOneClient.Submit(ctx, report)
	if err != nil {
		return nil, fmt.Errorf("failed to submit to AWS VRP: %w", err)
	}

	// Update response to indicate AWS VRP
	response.PlatformData["platform"] = "aws-vrp"
	response.PlatformData["program"] = c.config.ProgramHandle

	return response, nil
}

// getServiceFromAsset attempts to extract AWS service name from asset URL
func getServiceFromAsset(assetURL string) string {
	// This would parse the URL to determine AWS service
	// For now, return a generic identifier
	return "AWS Cloud Service"
}
