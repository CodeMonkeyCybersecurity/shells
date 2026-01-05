// pkg/ai/report_generator.go
//
// AI-Powered Report Generator for Bug Bounty Submissions
//
// Generates professional, evidence-based vulnerability reports using OpenAI/Azure OpenAI
// Supports multiple report formats and platform-specific requirements

package ai

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// ReportGenerator generates AI-powered vulnerability reports
type ReportGenerator struct {
	client *Client
	logger *logger.Logger
}

// NewReportGenerator creates a new AI report generator
func NewReportGenerator(client *Client, logger *logger.Logger) *ReportGenerator {
	return &ReportGenerator{
		client: client,
		logger: logger,
	}
}

// ReportFormat defines the output format for generated reports
type ReportFormat string

const (
	FormatBugBounty ReportFormat = "bug_bounty" // Bug bounty platform format (HackerOne, Bugcrowd)
	FormatMarkdown  ReportFormat = "markdown"   // Markdown technical report
	FormatHTML      ReportFormat = "html"       // HTML report
	FormatJSON      ReportFormat = "json"       // Structured JSON report
	FormatAzureMSRC ReportFormat = "azure_msrc" // Microsoft Security Response Center email format
	FormatAWSVRP    ReportFormat = "aws_vrp"    // AWS Vulnerability Reporting Program format
)

// ReportRequest contains parameters for report generation
type ReportRequest struct {
	Findings      []types.Finding
	Target        string
	ScanID        string
	Format        ReportFormat
	Platform      string // "hackerone", "bugcrowd", "azure", "aws"
	IncludeProof  bool
	MaxLength     int // Maximum report length in words
	Severity      string
	CustomContext string // Additional context to include
}

// GeneratedReport contains the AI-generated report and metadata
type GeneratedReport struct {
	Title            string
	Content          string
	Summary          string
	Severity         string
	CVSS             float64
	CWE              []string
	Platform         string
	Format           ReportFormat
	GeneratedAt      time.Time
	TokensUsed       int
	EstimatedCostUSD float64
}

// GenerateReport generates an AI-powered vulnerability report from findings
func (rg *ReportGenerator) GenerateReport(ctx context.Context, req ReportRequest) (*GeneratedReport, error) {
	if !rg.client.IsEnabled() {
		return nil, fmt.Errorf("AI client not enabled - configure OpenAI/Azure OpenAI API keys")
	}

	if len(req.Findings) == 0 {
		return nil, fmt.Errorf("no findings provided for report generation")
	}

	rg.logger.Infow("Generating AI-powered report",
		"target", req.Target,
		"scan_id", req.ScanID,
		"format", req.Format,
		"platform", req.Platform,
		"finding_count", len(req.Findings),
	)

	// Build prompt based on format and findings
	prompt := rg.buildPrompt(req)

	// Generate report using AI
	reportContent, err := rg.client.GenerateCompletion(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AI report: %w", err)
	}

	// Parse and structure the report
	report := rg.parseGeneratedReport(reportContent, req)

	rg.logger.Infow("AI report generated successfully",
		"target", req.Target,
		"format", req.Format,
		"report_length", len(report.Content),
		"severity", report.Severity,
	)

	return report, nil
}

// buildPrompt constructs the AI prompt based on findings and format
func (rg *ReportGenerator) buildPrompt(req ReportRequest) string {
	var prompt strings.Builder

	// System context
	prompt.WriteString("You are a professional security researcher writing a vulnerability report for ")
	switch req.Platform {
	case "hackerone":
		prompt.WriteString("HackerOne bug bounty platform. Follow HackerOne's report guidelines: clear title, detailed description, step-by-step reproduction, impact assessment, and remediation recommendations.")
	case "bugcrowd":
		prompt.WriteString("Bugcrowd bug bounty platform. Follow Bugcrowd's VRT (Vulnerability Rating Taxonomy) and provide clear, actionable reports.")
	case "azure":
		prompt.WriteString("Microsoft Security Response Center (MSRC). Use professional, concise language suitable for email submission.")
	case "aws":
		prompt.WriteString("AWS Vulnerability Reporting Program. Focus on AWS-specific services and impact to AWS infrastructure.")
	default:
		prompt.WriteString("a professional security assessment. Use clear, evidence-based language with actionable recommendations.")
	}

	prompt.WriteString("\n\n")

	// Target context
	prompt.WriteString(fmt.Sprintf("Target: %s\n", req.Target))
	if req.ScanID != "" {
		prompt.WriteString(fmt.Sprintf("Scan ID: %s\n", req.ScanID))
	}
	prompt.WriteString("\n")

	// Findings summary
	prompt.WriteString(fmt.Sprintf("The following %d vulnerabilities were discovered:\n\n", len(req.Findings)))

	// Include each finding with details
	for i, finding := range req.Findings {
		prompt.WriteString(fmt.Sprintf("## Vulnerability %d\n", i+1))
		prompt.WriteString(fmt.Sprintf("Type: %s\n", finding.Type))
		prompt.WriteString(fmt.Sprintf("Severity: %s\n", finding.Severity))
		if finding.CVSS > 0 {
			prompt.WriteString(fmt.Sprintf("CVSS Score: %.1f\n", finding.CVSS))
		}
		if finding.CWE != "" {
			prompt.WriteString(fmt.Sprintf("CWE: %s\n", finding.CWE))
		}
		prompt.WriteString(fmt.Sprintf("Description: %s\n", finding.Description))
		if finding.Evidence != "" {
			prompt.WriteString(fmt.Sprintf("Evidence: %s\n", finding.Evidence))
		}
		if finding.Remediation != "" {
			prompt.WriteString(fmt.Sprintf("Recommended Fix: %s\n", finding.Remediation))
		}
		prompt.WriteString("\n")
	}

	// Custom context
	if req.CustomContext != "" {
		prompt.WriteString(fmt.Sprintf("\nAdditional Context:\n%s\n\n", req.CustomContext))
	}

	// Format-specific instructions
	prompt.WriteString("\n## Report Requirements:\n")
	switch req.Format {
	case FormatBugBounty:
		prompt.WriteString(rg.getBugBountyInstructions(req.Platform))
	case FormatMarkdown:
		prompt.WriteString(rg.getMarkdownInstructions())
	case FormatHTML:
		prompt.WriteString(rg.getHTMLInstructions())
	case FormatJSON:
		prompt.WriteString(rg.getJSONInstructions())
	case FormatAzureMSRC:
		prompt.WriteString(rg.getAzureMSRCInstructions())
	case FormatAWSVRP:
		prompt.WriteString(rg.getAWSVRPInstructions())
	}

	return prompt.String()
}

// getBugBountyInstructions returns bug bounty platform-specific instructions
func (rg *ReportGenerator) getBugBountyInstructions(platform string) string {
	instructions := `
Generate a professional bug bounty report with the following sections:

1. **Title**: Clear, concise vulnerability title (e.g., "SQL Injection in login endpoint allows authentication bypass")

2. **Summary**: 2-3 sentence executive summary of the vulnerability and its impact

3. **Description**: Detailed technical description including:
   - What the vulnerability is
   - Where it was found
   - How it works
   - Why it's a security issue

4. **Steps to Reproduce**: Clear, numbered steps that allow the security team to reproduce the issue

5. **Impact**: Realistic assessment of what an attacker could accomplish:
   - Data exposure or manipulation
   - Privilege escalation
   - Service disruption
   - Business impact

6. **Remediation**: Specific, actionable recommendations to fix the vulnerability

7. **Supporting Evidence**: Include relevant evidence (sanitized if containing sensitive data)

Use professional language, focus on facts and evidence, and provide actionable information.
`

	// Platform-specific additions
	switch platform {
	case "hackerone":
		instructions += "\nFormat for HackerOne: Use markdown formatting. Include CVSS score if applicable. Tag appropriate weakness (CWE).\n"
	case "bugcrowd":
		instructions += "\nFormat for Bugcrowd: Align severity with Bugcrowd VRT. Use clear section headings. Include proof-of-concept if applicable.\n"
	}

	return instructions
}

// getMarkdownInstructions returns markdown report instructions
func (rg *ReportGenerator) getMarkdownInstructions() string {
	return `
Generate a comprehensive technical security report in Markdown format with:

1. Executive Summary
2. Findings Overview (table format)
3. Detailed Vulnerability Analysis for each finding:
   - Description
   - Technical Details
   - Evidence
   - CVSS/Severity
   - CWE Mapping
   - Remediation Steps
4. Recommendations
5. References

Use proper markdown formatting with headers, code blocks, tables, and lists.
`
}

// getHTMLInstructions returns HTML report instructions
func (rg *ReportGenerator) getHTMLInstructions() string {
	return `
Generate an HTML security report with professional styling. Include:
- Styled header with target and scan information
- Executive summary section
- Findings table with severity color-coding
- Detailed findings sections with collapsible evidence
- Remediation recommendations
- Footer with generation timestamp

Use semantic HTML5 and include inline CSS for styling.
`
}

// getJSONInstructions returns JSON report instructions
func (rg *ReportGenerator) getJSONInstructions() string {
	return `
Generate a structured JSON report with the following schema:
{
  "title": "Report Title",
  "summary": "Executive summary",
  "target": "Target identifier",
  "scan_id": "Scan identifier",
  "severity": "Overall severity",
  "findings": [
    {
      "id": "finding-id",
      "type": "vulnerability type",
      "severity": "severity level",
      "cvss": cvss_score,
      "cwe": "CWE-XXX",
      "description": "detailed description",
      "evidence": "technical evidence",
      "impact": "impact assessment",
      "remediation": "fix recommendations"
    }
  ],
  "recommendations": ["recommendation 1", "recommendation 2"],
  "generated_at": "ISO 8601 timestamp"
}

Return ONLY valid JSON, no markdown formatting.
`
}

// getAzureMSRCInstructions returns Azure MSRC email format instructions
func (rg *ReportGenerator) getAzureMSRCInstructions() string {
	return `
Generate a professional email for Microsoft Security Response Center (MSRC) submission:

Subject: Security Vulnerability Report - [Vulnerability Type] in [Product/Service]

Body:
- Professional greeting
- Clear, concise description of the vulnerability
- Affected product/service and version
- Step-by-step reproduction instructions
- Impact assessment
- Your contact information for follow-up
- Professional closing

Use formal business email language. Keep total length under 1000 words.
Include all necessary technical details but remain concise.
`
}

// getAWSVRPInstructions returns AWS VRP format instructions
func (rg *ReportGenerator) getAWSVRPInstructions() string {
	return `
Generate an AWS Vulnerability Reporting Program submission with:

1. Summary: Brief description of the vulnerability
2. Affected Service: Specific AWS service affected
3. Vulnerability Type: Classification (e.g., authorization bypass, injection)
4. Reproduction Steps: Clear, detailed steps
5. Impact: Potential impact to AWS customers or infrastructure
6. Recommended Remediation: AWS-specific fix recommendations

Focus on AWS infrastructure and services. Use technical accuracy and clarity.
`
}

// parseGeneratedReport parses the AI-generated content into a structured report
func (rg *ReportGenerator) parseGeneratedReport(content string, req ReportRequest) *GeneratedReport {
	// Extract title (first line or heading)
	lines := strings.Split(content, "\n")
	title := rg.extractTitle(lines)

	// Extract summary (first paragraph or executive summary section)
	summary := rg.extractSummary(content)

	// Determine overall severity from findings
	severity := rg.calculateOverallSeverity(req.Findings)

	// Calculate CVSS (highest from findings)
	cvss := rg.calculateHighestCVSS(req.Findings)

	// Collect unique CWEs
	cwes := rg.collectCWEs(req.Findings)

	return &GeneratedReport{
		Title:       title,
		Content:     content,
		Summary:     summary,
		Severity:    severity,
		CVSS:        cvss,
		CWE:         cwes,
		Platform:    req.Platform,
		Format:      req.Format,
		GeneratedAt: time.Now(),
	}
}

// extractTitle extracts a title from the generated content
func (rg *ReportGenerator) extractTitle(lines []string) string {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for markdown heading
		if strings.HasPrefix(line, "#") {
			return strings.TrimSpace(strings.TrimPrefix(line, "#"))
		}
		// Look for "Title:" prefix
		if strings.HasPrefix(strings.ToLower(line), "title:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Title:"))
		}
		// First non-empty line could be title
		if line != "" && len(line) < 200 {
			return line
		}
	}
	return "Security Vulnerability Report"
}

// extractSummary extracts a summary from the generated content
func (rg *ReportGenerator) extractSummary(content string) string {
	// Look for "Summary:" or "Executive Summary:" section
	summaryMarkers := []string{"summary:", "executive summary:", "overview:"}
	lowerContent := strings.ToLower(content)

	for _, marker := range summaryMarkers {
		if idx := strings.Index(lowerContent, marker); idx != -1 {
			// Extract text after marker until next section or paragraph break
			start := idx + len(marker)
			remaining := content[start:]

			// Find end (double newline or next heading)
			end := strings.Index(remaining, "\n\n")
			if end == -1 {
				end = len(remaining)
			}
			if headingIdx := strings.Index(remaining, "\n#"); headingIdx != -1 && headingIdx < end {
				end = headingIdx
			}

			summary := strings.TrimSpace(remaining[:end])
			if len(summary) > 0 {
				return summary
			}
		}
	}

	// Fallback: use first paragraph
	paragraphs := strings.Split(content, "\n\n")
	for _, para := range paragraphs {
		para = strings.TrimSpace(para)
		if len(para) > 50 && len(para) < 500 {
			return para
		}
	}

	return "AI-generated vulnerability report"
}

// calculateOverallSeverity determines the highest severity from findings
func (rg *ReportGenerator) calculateOverallSeverity(findings []types.Finding) string {
	severityOrder := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
		"INFO":     0,
	}

	highestSev := "INFO"
	highestVal := 0

	for _, finding := range findings {
		if val, ok := severityOrder[strings.ToUpper(string(finding.Severity))]; ok {
			if val > highestVal {
				highestVal = val
				highestSev = strings.ToUpper(string(finding.Severity))
			}
		}
	}

	return highestSev
}

// calculateHighestCVSS returns the highest CVSS score from findings
func (rg *ReportGenerator) calculateHighestCVSS(findings []types.Finding) float64 {
	highest := 0.0
	for _, finding := range findings {
		if finding.CVSS > highest {
			highest = finding.CVSS
		}
	}
	return highest
}

// collectCWEs collects unique CWE identifiers from findings
func (rg *ReportGenerator) collectCWEs(findings []types.Finding) []string {
	cweMap := make(map[string]bool)
	var cwes []string

	for _, finding := range findings {
		if finding.CWE != "" && !cweMap[finding.CWE] {
			cweMap[finding.CWE] = true
			cwes = append(cwes, finding.CWE)
		}
	}

	return cwes
}

// GenerateBatchReports generates multiple reports for different platforms from the same findings
func (rg *ReportGenerator) GenerateBatchReports(ctx context.Context, findings []types.Finding, target, scanID string) (map[string]*GeneratedReport, error) {
	reports := make(map[string]*GeneratedReport)

	platforms := []struct {
		name   string
		format ReportFormat
	}{
		{"hackerone", FormatBugBounty},
		{"bugcrowd", FormatBugBounty},
		{"azure", FormatAzureMSRC},
		{"markdown", FormatMarkdown},
	}

	for _, platform := range platforms {
		req := ReportRequest{
			Findings: findings,
			Target:   target,
			ScanID:   scanID,
			Format:   platform.format,
			Platform: platform.name,
		}

		report, err := rg.GenerateReport(ctx, req)
		if err != nil {
			rg.logger.Warnw("Failed to generate report for platform",
				"platform", platform.name,
				"error", err,
			)
			continue
		}

		reports[platform.name] = report
	}

	rg.logger.Infow("Batch report generation completed",
		"target", target,
		"reports_generated", len(reports),
	)

	return reports, nil
}
