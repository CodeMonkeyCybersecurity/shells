package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/platforms"
)

// Client implements the Microsoft Azure Bug Bounty client
// Note: Azure uses MSRC (Microsoft Security Response Center) email-based reporting
// This client formats reports for email submission
type Client struct {
	config config.AzureBountyConfig
}

// NewClient creates a new Azure bug bounty client
func NewClient(cfg config.AzureBountyConfig) *Client {
	return &Client{
		config: cfg,
	}
}

// Name returns the platform name
func (c *Client) Name() string {
	return "Microsoft Azure Bug Bounty"
}

// ValidateCredentials validates the configuration
// For Azure, this just validates that we have required config
func (c *Client) ValidateCredentials(ctx context.Context) error {
	if c.config.ReportingEmail == "" {
		return fmt.Errorf("reporting email not configured for Azure bounty")
	}
	return nil
}

// GetPrograms returns the Azure bug bounty programs
func (c *Client) GetPrograms(ctx context.Context) ([]*platforms.Program, error) {
	programs := []*platforms.Program{
		{
			Handle:   "azure",
			Name:     "Microsoft Azure Bounty Program",
			Platform: "azure",
			URL:      "https://www.microsoft.com/en-us/msrc/bounty-microsoft-azure",
			IsActive: true,
			Description: "The Microsoft Azure Bounty Program rewards researchers for identifying and reporting security vulnerabilities in Azure services.",
			Scope: []platforms.Asset{
				{
					Type:        "cloud_service",
					Identifier:  "Azure Cloud Services",
					Description: "Azure compute, storage, networking, and other cloud services",
					MaxSeverity: "Critical",
				},
			},
			Rewards: &platforms.Rewards{
				Currency: "USD",
				Bounties: map[string]float64{
					"critical":  60000,
					"important": 20000,
					"moderate":  5000,
					"low":       500,
				},
			},
		},
		{
			Handle:   "azure-devops",
			Name:     "Microsoft Azure DevOps Bounty Program",
			Platform: "azure",
			URL:      "https://www.microsoft.com/en-us/msrc/bounty-azure-devops",
			IsActive: true,
			Description: "The Azure DevOps Bounty Program covers Azure DevOps services and related infrastructure.",
			Scope: []platforms.Asset{
				{
					Type:        "cloud_service",
					Identifier:  "Azure DevOps Services",
					Description: "Azure DevOps pipelines, repos, boards, and related services",
					MaxSeverity: "Critical",
				},
			},
			Rewards: &platforms.Rewards{
				Currency: "USD",
				Bounties: map[string]float64{
					"critical":  20000,
					"important": 10000,
					"moderate":  2000,
					"low":       500,
				},
			},
		},
	}

	return programs, nil
}

// GetProgramByHandle retrieves a specific Azure program
func (c *Client) GetProgramByHandle(ctx context.Context, handle string) (*platforms.Program, error) {
	programs, err := c.GetPrograms(ctx)
	if err != nil {
		return nil, err
	}

	for _, p := range programs {
		if p.Handle == handle {
			return p, nil
		}
	}

	return nil, fmt.Errorf("program not found: %s", handle)
}

// Submit creates a formatted report for Azure MSRC submission
// Note: This generates an email-ready report. Actual submission requires email client or SMTP
func (c *Client) Submit(ctx context.Context, report *platforms.VulnerabilityReport) (*platforms.SubmissionResponse, error) {
	// Map severity to MSRC format
	severity := mapSeverity(report.Severity)

	// Format the report for MSRC
	emailBody := formatMSRCReport(report, severity, c.config.ProgramType)

	// In a real implementation, this would send via SMTP or integrate with an email client
	// For now, we return the formatted report
	reportID := fmt.Sprintf("azure-%d", time.Now().Unix())

	// P0-5 FIX: Report is NOT automatically submitted - user must manually send email
	// Success: false to indicate manual action required
	return &platforms.SubmissionResponse{
		Success:  false, // CRITICAL: Report is NOT submitted - user must manually email
		ReportID: reportID,
		ReportURL: "mailto:" + c.config.ReportingEmail + "?subject=" +
			fmt.Sprintf("Azure Security Vulnerability: %s", report.Title) +
			"&body=" + emailBody,
		Status: "requires_manual_email", // User must click mailto link or copy email body
		Message: fmt.Sprintf("⚠️  MANUAL ACTION REQUIRED: Report formatted but NOT submitted.\n"+
			"Please click the mailto: link above or manually email the report to %s\n"+
			"The email body has been formatted according to MSRC guidelines.",
			c.config.ReportingEmail),
		SubmittedAt: time.Now(),
		PlatformData: map[string]interface{}{
			"reporting_email": c.config.ReportingEmail,
			"program_type":    c.config.ProgramType,
			"severity":        severity,
			"email_body":      emailBody,
			"requires_manual_submission": true,
		},
	}, nil
}

// mapSeverity maps shells severity to MSRC severity levels
func mapSeverity(shellsSeverity string) string {
	switch shellsSeverity {
	case "CRITICAL":
		return "Critical"
	case "HIGH":
		return "Important"
	case "MEDIUM":
		return "Moderate"
	case "LOW":
		return "Low"
	default:
		return "Low"
	}
}

// formatMSRCReport formats a report for MSRC submission
func formatMSRCReport(report *platforms.VulnerabilityReport, severity, programType string) string {
	var sb strings.Builder

	sb.WriteString("MICROSOFT SECURITY VULNERABILITY REPORT\n")
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")

	sb.WriteString(fmt.Sprintf("Program: %s\n", programType))
	sb.WriteString(fmt.Sprintf("Severity: %s\n", severity))
	if report.CVSSScore > 0 {
		sb.WriteString(fmt.Sprintf("CVSS Score: %.1f\n", report.CVSSScore))
	}
	if report.CWE != "" {
		sb.WriteString(fmt.Sprintf("CWE: %s\n", report.CWE))
	}
	sb.WriteString("\n")

	sb.WriteString(fmt.Sprintf("TITLE: %s\n\n", report.Title))

	sb.WriteString("DESCRIPTION:\n")
	sb.WriteString(report.Description + "\n\n")

	sb.WriteString("AFFECTED ASSET:\n")
	sb.WriteString(fmt.Sprintf("URL/Service: %s\n", report.AssetURL))
	if report.AssetType != "" {
		sb.WriteString(fmt.Sprintf("Type: %s\n", report.AssetType))
	}
	sb.WriteString("\n")

	if len(report.ReproSteps) > 0 {
		sb.WriteString("REPRODUCTION STEPS:\n")
		for i, step := range report.ReproSteps {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("PROOF OF CONCEPT:\n")
	sb.WriteString(report.ProofOfConcept + "\n\n")

	sb.WriteString("IMPACT:\n")
	sb.WriteString(report.Impact + "\n\n")

	if report.Remediation != "" {
		sb.WriteString("SUGGESTED REMEDIATION:\n")
		sb.WriteString(report.Remediation + "\n\n")
	}

	if len(report.References) > 0 {
		sb.WriteString("REFERENCES:\n")
		for _, ref := range report.References {
			sb.WriteString(fmt.Sprintf("- %s\n", ref))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(strings.Repeat("-", 50) + "\n")
	sb.WriteString(fmt.Sprintf("Discovered: %s\n", report.DiscoveredAt.Format(time.RFC3339)))
	if report.ToolName != "" {
		sb.WriteString(fmt.Sprintf("Discovery Tool: %s\n", report.ToolName))
	}
	if report.ScanID != "" {
		sb.WriteString(fmt.Sprintf("Scan ID: %s\n", report.ScanID))
	}

	return sb.String()
}
