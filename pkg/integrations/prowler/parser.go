package prowler

import (
	"bufio"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Parser handles parsing of Prowler output and results
type Parser struct {
	config Config
}

// NewParser creates a new Prowler output parser
func NewParser(config Config) *Parser {
	return &Parser{
		config: config,
	}
}

// ParseScanOutput parses raw Prowler scan output into structured findings
func (p *Parser) ParseScanOutput(output string) (*ScanResult, error) {
	result := &ScanResult{
		StartTime: time.Now(),
		Findings:  []ProwlerFinding{},
		Summary:   ScanSummary{
			ServiceBreakdown: make(map[string]int),
			RegionBreakdown:  make(map[string]int),
		},
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and non-JSON output
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		// Parse JSON finding
		var finding ProwlerFinding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			// Log parse error but continue
			continue
		}

		// Add to results
		result.Findings = append(result.Findings, finding)
		
		// Update summary statistics
		p.updateSummary(&result.Summary, finding)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.TotalChecks = len(result.Findings)

	// Finalize summary
	p.finalizeSummary(&result.Summary)

	return result, nil
}

// ParseChecksList parses the output of prowler -l command
func (p *Parser) ParseChecksList(output string) ([]Check, error) {
	var checks []Check
	
	scanner := bufio.NewScanner(strings.NewReader(output))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "INFO") {
			continue
		}

		check := p.parseCheckLine(line)
		if check.ID != "" {
			checks = append(checks, check)
		}
	}

	// Sort checks by ID
	sort.Slice(checks, func(i, j int) bool {
		return checks[i].ID < checks[j].ID
	})

	return checks, nil
}

// parseCheckLine parses a single check line from prowler -l output
func (p *Parser) parseCheckLine(line string) Check {
	// Expected format: checkID: description [service] [severity]
	// Example: iam_password_policy_minimum_length_14: IAM password policy minimum length 14 [iam] [medium]
	
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return Check{}
	}

	checkID := strings.TrimSpace(parts[0])
	remainder := strings.TrimSpace(parts[1])

	// Extract service and severity from brackets
	service := extractBracketedValue(remainder, 0)
	severity := extractBracketedValue(remainder, 1)
	
	// Description is everything except the bracketed parts
	description := removeBracketedValues(remainder)

	check := Check{
		ID:          checkID,
		Description: description,
		Service:     service,
		Severity:    severity,
	}

	// Infer categories from check ID
	check.Categories = p.inferCategories(checkID)

	return check
}

// updateSummary updates scan summary with a new finding
func (p *Parser) updateSummary(summary *ScanSummary, finding ProwlerFinding) {
	summary.TotalChecks++

	// Count by status
	switch strings.ToLower(finding.Status) {
	case "pass", "passed":
		summary.PassedChecks++
	case "fail", "failed":
		summary.FailedChecks++
	}

	// Count by severity
	switch strings.ToLower(finding.Severity) {
	case "critical":
		summary.CriticalFindings++
	case "high":
		summary.HighFindings++
	case "medium":
		summary.MediumFindings++
	case "low":
		summary.LowFindings++
	}

	// Count by service
	if finding.ServiceName != "" {
		summary.ServiceBreakdown[finding.ServiceName]++
	}

	// Count by region
	if finding.Region != "" {
		summary.RegionBreakdown[finding.Region]++
	}
}

// finalizeSummary performs final calculations on the summary
func (p *Parser) finalizeSummary(summary *ScanSummary) {
	// Calculate total failed checks
	if summary.FailedChecks == 0 {
		summary.FailedChecks = summary.CriticalFindings + summary.HighFindings + 
		                      summary.MediumFindings + summary.LowFindings
	}

	// Calculate passed checks if not already set
	if summary.PassedChecks == 0 && summary.TotalChecks > summary.FailedChecks {
		summary.PassedChecks = summary.TotalChecks - summary.FailedChecks
	}
}

// GenerateReport creates a comprehensive Prowler report
func (p *Parser) GenerateReport(scanResult *ScanResult, profile string) *ProwlerReport {
	report := &ProwlerReport{
		Metadata: ReportMetadata{
			GeneratedAt:    time.Now(),
			AWSProfile:     profile,
			ScanDuration:   scanResult.Duration,
			TotalResources: scanResult.TotalChecks,
			Regions:        p.extractRegions(scanResult.Findings),
		},
		Summary:  scanResult.Summary,
		Findings: scanResult.Findings,
		Services: p.generateServiceSummaries(scanResult.Findings),
		Regions:  p.generateRegionSummaries(scanResult.Findings),
		Compliance: p.generateComplianceSummaries(scanResult.Findings),
		Recommendations: p.generateRecommendations(scanResult.Findings),
	}

	return report
}

// generateServiceSummaries creates per-service summaries
func (p *Parser) generateServiceSummaries(findings []ProwlerFinding) []ServiceSummary {
	serviceMap := make(map[string]*ServiceSummary)

	for _, finding := range findings {
		service := finding.ServiceName
		if service == "" {
			service = "unknown"
		}

		if _, exists := serviceMap[service]; !exists {
			serviceMap[service] = &ServiceSummary{
				Service: service,
			}
		}

		summary := serviceMap[service]
		summary.TotalChecks++

		switch strings.ToLower(finding.Status) {
		case "pass", "passed":
			summary.PassedChecks++
		case "fail", "failed":
			summary.FailedChecks++
		}

		switch strings.ToLower(finding.Severity) {
		case "critical":
			summary.CriticalIssues++
		case "high":
			summary.HighIssues++
		case "medium":
			summary.MediumIssues++
		case "low":
			summary.LowIssues++
		}
	}

	// Calculate compliance scores and convert to slice
	var summaries []ServiceSummary
	for _, summary := range serviceMap {
		if summary.TotalChecks > 0 {
			summary.ComplianceScore = float64(summary.PassedChecks) / float64(summary.TotalChecks) * 100
		}
		summaries = append(summaries, *summary)
	}

	// Sort by service name
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Service < summaries[j].Service
	})

	return summaries
}

// generateRegionSummaries creates per-region summaries
func (p *Parser) generateRegionSummaries(findings []ProwlerFinding) []RegionSummary {
	regionMap := make(map[string]*RegionSummary)

	for _, finding := range findings {
		region := finding.Region
		if region == "" {
			region = "global"
		}

		if _, exists := regionMap[region]; !exists {
			regionMap[region] = &RegionSummary{
				Region:   region,
				Services: []string{},
			}
		}

		summary := regionMap[region]
		summary.TotalChecks++

		// Track unique services per region
		if finding.ServiceName != "" {
			serviceExists := false
			for _, svc := range summary.Services {
				if svc == finding.ServiceName {
					serviceExists = true
					break
				}
			}
			if !serviceExists {
				summary.Services = append(summary.Services, finding.ServiceName)
			}
		}

		switch strings.ToLower(finding.Status) {
		case "pass", "passed":
			summary.PassedChecks++
		case "fail", "failed":
			summary.FailedChecks++
		}

		switch strings.ToLower(finding.Severity) {
		case "critical":
			summary.CriticalIssues++
		case "high":
			summary.HighIssues++
		case "medium":
			summary.MediumIssues++
		case "low":
			summary.LowIssues++
		}
	}

	// Convert to slice and sort services
	var summaries []RegionSummary
	for _, summary := range regionMap {
		sort.Strings(summary.Services)
		summaries = append(summaries, *summary)
	}

	// Sort by region name
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Region < summaries[j].Region
	})

	return summaries
}

// generateComplianceSummaries creates compliance framework analysis
func (p *Parser) generateComplianceSummaries(findings []ProwlerFinding) []ComplianceSummary {
	var summaries []ComplianceSummary

	for frameworkName, framework := range ComplianceFrameworks {
		summary := ComplianceSummary{
			Framework:       frameworkName,
			TotalControls:   len(framework.Controls),
			PassingControls: 0,
			FailingControls: 0,
			CriticalGaps:    []string{},
		}

		// Check each control in the framework
		for controlID, checkID := range framework.Controls {
			found := false
			passed := false

			for _, finding := range findings {
				if finding.CheckID == checkID {
					found = true
					if strings.ToLower(finding.Status) == "pass" || strings.ToLower(finding.Status) == "passed" {
						passed = true
					} else if strings.ToLower(finding.Severity) == "critical" || strings.ToLower(finding.Severity) == "high" {
						summary.CriticalGaps = append(summary.CriticalGaps, controlID)
					}
					break
				}
			}

			if found {
				if passed {
					summary.PassingControls++
				} else {
					summary.FailingControls++
				}
			}
		}

		// Calculate compliance score
		if summary.TotalControls > 0 {
			summary.ComplianceScore = float64(summary.PassingControls) / float64(summary.TotalControls) * 100
		}

		summaries = append(summaries, summary)
	}

	return summaries
}

// generateRecommendations creates actionable recommendations
func (p *Parser) generateRecommendations(findings []ProwlerFinding) []Recommendation {
	var recommendations []Recommendation

	// Group findings by service and severity
	serviceIssues := make(map[string][]ProwlerFinding)
	
	for _, finding := range findings {
		if strings.ToLower(finding.Status) != "fail" && strings.ToLower(finding.Status) != "failed" {
			continue
		}

		service := finding.ServiceName
		if service == "" {
			service = "general"
		}

		serviceIssues[service] = append(serviceIssues[service], finding)
	}

	// Generate recommendations per service
	for service, issues := range serviceIssues {
		if len(issues) == 0 {
			continue
		}

		// Count severity levels
		critical := 0
		high := 0
		medium := 0
		low := 0

		for _, issue := range issues {
			switch strings.ToLower(issue.Severity) {
			case "critical":
				critical++
			case "high":
				high++
			case "medium":
				medium++
			case "low":
				low++
			}
		}

		// Determine priority
		priority := "LOW"
		if critical > 0 {
			priority = "CRITICAL"
		} else if high > 0 {
			priority = "HIGH"
		} else if medium > 0 {
			priority = "MEDIUM"
		}

		// Create recommendation
		rec := Recommendation{
			Priority:    priority,
			Service:     service,
			Category:    "Security Configuration",
			Title:       fmt.Sprintf("Address %s Security Issues", strings.ToUpper(service)),
			Description: fmt.Sprintf("Found %d security issues in %s service (%d critical, %d high, %d medium, %d low)", 
				len(issues), service, critical, high, medium, low),
			Remediation: p.getServiceRemediation(service),
			Impact:      p.getServiceImpact(service, critical, high),
			Effort:      p.getRemediationEffort(len(issues), critical, high),
			References:  p.getServiceReferences(service),
		}

		// Add affected check IDs
		for _, issue := range issues {
			rec.AffectedChecks = append(rec.AffectedChecks, issue.CheckID)
		}

		recommendations = append(recommendations, rec)
	}

	// Sort by priority
	sort.Slice(recommendations, func(i, j int) bool {
		priorityOrder := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
		return priorityOrder[recommendations[i].Priority] > priorityOrder[recommendations[j].Priority]
	})

	return recommendations
}

// Helper functions

func extractBracketedValue(text string, index int) string {
	brackets := 0
	values := []string{}
	
	start := -1
	for i, char := range text {
		if char == '[' {
			if start == -1 {
				start = i + 1
			}
		} else if char == ']' && start != -1 {
			value := strings.TrimSpace(text[start:i])
			if value != "" {
				values = append(values, value)
			}
			start = -1
			brackets++
		}
	}

	if index < len(values) {
		return values[index]
	}
	return ""
}

func removeBracketedValues(text string) string {
	result := text
	start := strings.Index(result, "[")
	for start != -1 {
		end := strings.Index(result[start:], "]")
		if end == -1 {
			break
		}
		end += start + 1
		result = strings.TrimSpace(result[:start] + result[end:])
		start = strings.Index(result, "[")
	}
	return result
}

func (p *Parser) inferCategories(checkID string) []string {
	categories := []string{}
	
	if strings.Contains(checkID, "password") || strings.Contains(checkID, "mfa") {
		categories = append(categories, "authentication")
	}
	if strings.Contains(checkID, "encryption") || strings.Contains(checkID, "ssl") || strings.Contains(checkID, "tls") {
		categories = append(categories, "encryption")
	}
	if strings.Contains(checkID, "public") || strings.Contains(checkID, "internet") {
		categories = append(categories, "exposure")
	}
	if strings.Contains(checkID, "logging") || strings.Contains(checkID, "cloudtrail") {
		categories = append(categories, "logging")
	}
	if strings.Contains(checkID, "backup") || strings.Contains(checkID, "snapshot") {
		categories = append(categories, "backup")
	}

	return categories
}

func (p *Parser) extractRegions(findings []ProwlerFinding) []string {
	regionSet := make(map[string]bool)
	
	for _, finding := range findings {
		if finding.Region != "" {
			regionSet[finding.Region] = true
		}
	}

	var regions []string
	for region := range regionSet {
		regions = append(regions, region)
	}

	sort.Strings(regions)
	return regions
}

func (p *Parser) getServiceRemediation(service string) string {
	remediation := map[string]string{
		"iam": "Review IAM policies, enable MFA, implement least privilege access, rotate access keys regularly",
		"s3": "Enable bucket encryption, configure public access blocks, implement secure transport policies",
		"ec2": "Review security groups, enable instance encryption, implement proper network segmentation",
		"cloudtrail": "Enable multi-region logging, configure log file validation, set up CloudWatch integration",
		"vpc": "Enable VPC Flow Logs, review network ACLs, implement proper subnet segmentation",
	}

	if rem, exists := remediation[service]; exists {
		return rem
	}
	return "Review security configuration and implement AWS security best practices"
}

func (p *Parser) getServiceImpact(service string, critical, high int) string {
	if critical > 0 {
		return fmt.Sprintf("Critical security vulnerabilities in %s may lead to unauthorized access or data breach", service)
	}
	if high > 0 {
		return fmt.Sprintf("High-risk security issues in %s may compromise system security", service)
	}
	return fmt.Sprintf("Security configuration issues in %s may increase attack surface", service)
}

func (p *Parser) getRemediationEffort(totalIssues, critical, high int) string {
	if critical > 0 {
		return "HIGH - Immediate action required"
	}
	if high > 2 {
		return "MEDIUM - Should be addressed promptly"
	}
	if totalIssues > 10 {
		return "MEDIUM - Multiple issues require systematic approach"
	}
	return "LOW - Can be addressed during regular maintenance"
}

func (p *Parser) getServiceReferences(service string) []string {
	references := map[string][]string{
		"iam": {
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
			"https://aws.amazon.com/iam/getting-started/",
		},
		"s3": {
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html",
			"https://aws.amazon.com/s3/security/",
		},
		"ec2": {
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html",
			"https://aws.amazon.com/ec2/security/",
		},
		"cloudtrail": {
			"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html",
			"https://aws.amazon.com/cloudtrail/getting-started/",
		},
	}

	if refs, exists := references[service]; exists {
		return refs
	}

	return []string{
		"https://docs.aws.amazon.com/security/",
		"https://aws.amazon.com/architecture/security-identity-compliance/",
	}
}