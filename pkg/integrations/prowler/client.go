package prowler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
	"github.com/google/uuid"
)

// ProwlerClient provides interface for running Prowler AWS security scans
type ProwlerClient struct {
	config      Config
	logger      *logger.Logger
	jobTracker  map[string]*ProwlerJob
	jobMutex    sync.RWMutex
	prowlerPath string
}

// ProwlerJob represents a running Prowler scan
type ProwlerJob struct {
	ID        string
	Profile   string
	StartTime time.Time
	Status    string
	Progress  float64
	Cancel    context.CancelFunc
	Result    *ScanResult
	Error     error
}

// NewClient creates a new Prowler client
func NewClient(config Config, logger *logger.Logger) (*ProwlerClient, error) {
	// Find Prowler installation
	prowlerPath, err := findProwlerInstallation()
	if err != nil {
		// If not found, check if we can run via Docker
		if config.DockerImage != "" {
			prowlerPath = "docker"
		} else {
			return nil, fmt.Errorf("prowler not found in PATH and no Docker image specified: %w", err)
		}
	}

	client := &ProwlerClient{
		config:      config,
		logger:      logger,
		jobTracker:  make(map[string]*ProwlerJob),
		prowlerPath: prowlerPath,
	}

	// Ensure cache directory exists
	if config.CacheDir != "" {
		if err := os.MkdirAll(config.CacheDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create cache directory: %w", err)
		}
	}

	return client, nil
}

// findProwlerInstallation locates Prowler executable
func findProwlerInstallation() (string, error) {
	// Check common installation paths
	paths := []string{
		"prowler",
		"/usr/local/bin/prowler",
		"/opt/prowler/prowler",
		"./prowler/prowler.py",
	}

	for _, path := range paths {
		if _, err := exec.LookPath(path); err == nil {
			return path, nil
		}
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("prowler executable not found")
}

// RunAllChecks runs all Prowler checks for the given AWS profile
func (p *ProwlerClient) RunAllChecks(ctx context.Context, profile string) ([]types.Finding, error) {
	jobID := uuid.New().String()

	// Create scan configuration
	prowlerConfig := ProwlerConfig{
		Profile:  profile,
		Parallel: p.config.ParallelJobs,
		Quiet:    true,
	}

	// Focus on identity-related groups
	identityGroups := []string{
		"iam",
		"accessanalyzer",
		"sso",
		"organizations",
		"cloudtrail", // For identity audit
		"guardduty",  // For identity threat detection
		"detective",  // For identity investigation
		"securityhub",
		"identitystore",
		"cognito",
	}

	// Run identity-focused scan
	return p.runProwlerScan(ctx, jobID, prowlerConfig, identityGroups)
}

// RunChecksByGroup runs Prowler checks for specific groups
func (p *ProwlerClient) RunChecksByGroup(ctx context.Context, profile string, groups []string) ([]types.Finding, error) {
	jobID := uuid.New().String()

	prowlerConfig := ProwlerConfig{
		Profile:  profile,
		Groups:   groups,
		Parallel: p.config.ParallelJobs,
		Quiet:    true,
	}

	return p.runProwlerScan(ctx, jobID, prowlerConfig, groups)
}

// RunSpecificChecks runs specific Prowler checks
func (p *ProwlerClient) RunSpecificChecks(ctx context.Context, profile string, checkIDs []string) ([]types.Finding, error) {
	jobID := uuid.New().String()

	prowlerConfig := ProwlerConfig{
		Profile:  profile,
		Checks:   checkIDs,
		Parallel: p.config.ParallelJobs,
		Quiet:    true,
	}

	return p.runProwlerScan(ctx, jobID, prowlerConfig, nil)
}

// runProwlerScan executes a Prowler scan with the given configuration
func (p *ProwlerClient) runProwlerScan(ctx context.Context, jobID string, config ProwlerConfig, groups []string) ([]types.Finding, error) {
	// Create a cancellable context
	scanCtx, cancel := context.WithCancel(ctx)

	// Create job entry
	job := &ProwlerJob{
		ID:        jobID,
		Profile:   config.Profile,
		StartTime: time.Now(),
		Status:    "running",
		Progress:  0,
		Cancel:    cancel,
	}

	// Track the job
	p.jobMutex.Lock()
	p.jobTracker[jobID] = job
	p.jobMutex.Unlock()

	defer func() {
		p.jobMutex.Lock()
		delete(p.jobTracker, jobID)
		p.jobMutex.Unlock()
	}()

	// Build Prowler command
	cmd, outputPath, err := p.buildProwlerCommand(scanCtx, config, groups)
	if err != nil {
		job.Status = "failed"
		job.Error = err
		return nil, err
	}

	// Execute Prowler
	p.logger.Info("Starting Prowler scan",
		"job_id", jobID,
		"profile", config.Profile,
		"groups", groups)

	// Create output buffer for real-time progress monitoring
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// Start the command
	if err := cmd.Start(); err != nil {
		job.Status = "failed"
		job.Error = fmt.Errorf("failed to start Prowler: %w", err)
		return nil, job.Error
	}

	// Wait for completion
	cmdErr := cmd.Wait()

	// Update job status
	if cmdErr != nil {
		job.Status = "failed"
		job.Error = fmt.Errorf("prowler execution failed: %w, stderr: %s", cmdErr, stderr.String())
		return nil, job.Error
	}

	job.Status = "completed"
	job.Progress = 100

	// Parse results
	findings, err := p.parseProwlerOutput(outputPath)
	if err != nil {
		job.Status = "failed"
		job.Error = fmt.Errorf("failed to parse Prowler output: %w", err)
		return nil, job.Error
	}

	// Convert to internal findings format
	return p.convertToFindings(findings), nil
}

// buildProwlerCommand constructs the Prowler command
func (p *ProwlerClient) buildProwlerCommand(ctx context.Context, config ProwlerConfig, groups []string) (*exec.Cmd, string, error) {
	outputDir := filepath.Join(p.config.CacheDir, fmt.Sprintf("prowler_%s_%d", config.Profile, time.Now().Unix()))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, "", fmt.Errorf("failed to create output directory: %w", err)
	}

	var args []string

	// If using Docker
	if p.prowlerPath == "docker" {
		args = append(args, "run", "--rm",
			"-v", fmt.Sprintf("%s:/output", outputDir),
			"-v", fmt.Sprintf("%s/.aws:/root/.aws:ro", os.Getenv("HOME")),
			p.config.DockerImage,
		)
	}

	// Base Prowler arguments
	args = append(args, "aws")

	// Add profile
	if config.Profile != "" {
		args = append(args, "--profile", config.Profile)
	}

	// Add groups
	if len(groups) > 0 {
		args = append(args, "-g", strings.Join(groups, ","))
	}

	// Add specific checks
	if len(config.Checks) > 0 {
		args = append(args, "-c", strings.Join(config.Checks, ","))
	}

	// Add output format
	args = append(args, "-M", "json", "-o", outputDir)

	// Add parallel execution
	if config.Parallel > 0 {
		args = append(args, "-p", fmt.Sprintf("%d", config.Parallel))
	}

	// Add quiet mode
	if config.Quiet {
		args = append(args, "-q")
	}

	cmd := exec.CommandContext(ctx, p.prowlerPath, args...)

	// Set environment variables
	if config.Environment != nil {
		cmd.Env = os.Environ()
		for k, v := range config.Environment {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	return cmd, filepath.Join(outputDir, "prowler-output.json"), nil
}

// parseProwlerOutput parses Prowler JSON output
func (p *ProwlerClient) parseProwlerOutput(outputPath string) ([]ProwlerFinding, error) {
	file, err := os.Open(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open output file: %w", err)
	}
	defer file.Close()

	var findings []ProwlerFinding
	scanner := bufio.NewScanner(file)

	// Prowler outputs NDJSON (newline-delimited JSON)
	for scanner.Scan() {
		var finding ProwlerFinding
		if err := json.Unmarshal(scanner.Bytes(), &finding); err != nil {
			p.logger.Error("Failed to parse finding", "error", err)
			continue
		}

		// Only include failed checks
		if finding.Status == "FAIL" {
			findings = append(findings, finding)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading output file: %w", err)
	}

	return findings, nil
}

// convertToFindings converts Prowler findings to internal format
func (p *ProwlerClient) convertToFindings(prowlerFindings []ProwlerFinding) []types.Finding {
	var findings []types.Finding

	for _, pf := range prowlerFindings {
		finding := types.Finding{
			ID:          fmt.Sprintf("prowler_%s_%s", pf.CheckID, pf.ResourceUID),
			Type:        fmt.Sprintf("AWS_%s", pf.ServiceName),
			Title:       pf.CheckTitle,
			Description: pf.Description,
			Severity:    p.mapSeverity(pf.Severity),
			Evidence:    p.buildEvidence(pf),
			Solution:    pf.Remediation,
			References:  p.extractReferences(pf),
			Metadata: map[string]interface{}{
				"target":        pf.ResourceArn,
				"tags":          p.buildTags(pf),
				"check_id":      pf.CheckID,
				"service":       pf.ServiceName,
				"region":        pf.Region,
				"resource_name": pf.ResourceName,
				"compliance":    pf.Compliance,
				"categories":    pf.Categories,
			},
		}

		findings = append(findings, finding)
	}

	return findings
}

// buildEvidence constructs evidence from Prowler finding
func (p *ProwlerClient) buildEvidence(finding ProwlerFinding) string {
	var evidence strings.Builder

	evidence.WriteString(fmt.Sprintf("Resource: %s\n", finding.ResourceArn))
	evidence.WriteString(fmt.Sprintf("Region: %s\n", finding.Region))
	evidence.WriteString(fmt.Sprintf("Service: %s\n", finding.ServiceName))

	if finding.Risk != "" {
		evidence.WriteString(fmt.Sprintf("\nRisk: %s\n", finding.Risk))
	}

	if finding.Description != "" {
		evidence.WriteString(fmt.Sprintf("\nDetails: %s\n", finding.Description))
	}

	return evidence.String()
}

// extractReferences extracts references from compliance data
func (p *ProwlerClient) extractReferences(finding ProwlerFinding) []string {
	var refs []string

	// Add compliance framework references
	for framework, controls := range finding.Compliance {
		for _, control := range controls {
			refs = append(refs, fmt.Sprintf("%s: %s", framework, control))
		}
	}

	// Add AWS documentation reference
	refs = append(refs, fmt.Sprintf("https://docs.aws.amazon.com/service/%s", strings.ToLower(finding.ServiceName)))

	return refs
}

// buildTags creates tags from finding metadata
func (p *ProwlerClient) buildTags(finding ProwlerFinding) []string {
	tags := []string{
		"prowler",
		"aws",
		finding.ServiceName,
		finding.Region,
	}

	// Add categories as tags
	tags = append(tags, finding.Categories...)

	// Add compliance frameworks as tags
	for framework := range finding.Compliance {
		tags = append(tags, framework)
	}

	// Add identity-specific tags
	if p.isIdentityRelated(finding) {
		tags = append(tags, "identity", "iam")
	}

	return tags
}

// isIdentityRelated checks if a finding is identity-related
func (p *ProwlerClient) isIdentityRelated(finding ProwlerFinding) bool {
	identityServices := []string{
		"iam", "sts", "sso", "organizations", "cognito",
		"identitystore", "accessanalyzer", "ram",
	}

	service := strings.ToLower(finding.ServiceName)
	for _, idService := range identityServices {
		if strings.Contains(service, idService) {
			return true
		}
	}

	// Check if the check itself is identity-related
	checkID := strings.ToLower(finding.CheckID)
	identityKeywords := []string{
		"iam", "user", "role", "policy", "permission", "access",
		"credential", "key", "mfa", "password", "authentication",
		"authorization", "identity", "principal", "assume",
	}

	for _, keyword := range identityKeywords {
		if strings.Contains(checkID, keyword) || strings.Contains(strings.ToLower(finding.CheckTitle), keyword) {
			return true
		}
	}

	return false
}

// GetAvailableChecks returns all available Prowler checks
func (p *ProwlerClient) GetAvailableChecks(ctx context.Context) ([]Check, error) {
	// Return predefined identity-focused checks
	return p.getIdentityFocusedChecks(), nil
}

// getIdentityFocusedChecks returns identity and access management checks
func (p *ProwlerClient) getIdentityFocusedChecks() []Check {
	return []Check{
		// IAM User checks
		{ID: "iam_user_mfa_enabled_console_access", Description: "Ensure MFA is enabled for console users", Service: "iam", Severity: "high", Categories: []string{"identity", "authentication"}},
		{ID: "iam_user_hardware_mfa_enabled", Description: "Ensure hardware MFA is enabled for privileged users", Service: "iam", Severity: "high", Categories: []string{"identity", "authentication"}},
		{ID: "iam_user_accesskey_unused", Description: "Ensure access keys are rotated regularly", Service: "iam", Severity: "medium", Categories: []string{"identity", "credentials"}},
		{ID: "iam_user_console_access_unused", Description: "Ensure unused console access is removed", Service: "iam", Severity: "medium", Categories: []string{"identity", "access"}},

		// IAM Policy checks
		{ID: "iam_policy_no_administrative_privileges", Description: "Ensure no policies grant full administrative privileges", Service: "iam", Severity: "critical", Categories: []string{"identity", "authorization"}},
		{ID: "iam_policy_attached_only_to_group_or_roles", Description: "Ensure policies are attached to groups or roles", Service: "iam", Severity: "medium", Categories: []string{"identity", "authorization"}},

		// Root account checks
		{ID: "iam_root_mfa_enabled", Description: "Ensure MFA is enabled for root account", Service: "iam", Severity: "critical", Categories: []string{"identity", "authentication"}},
		{ID: "iam_root_access_key_exists", Description: "Ensure root account has no access keys", Service: "iam", Severity: "critical", Categories: []string{"identity", "credentials"}},
		{ID: "iam_root_signing_certificates", Description: "Ensure root account has no signing certificates", Service: "iam", Severity: "high", Categories: []string{"identity", "credentials"}},

		// Password policy checks
		{ID: "iam_password_policy_minimum_length_14", Description: "Ensure password policy requires minimum length", Service: "iam", Severity: "medium", Categories: []string{"identity", "authentication"}},
		{ID: "iam_password_policy_symbol", Description: "Ensure password policy requires symbols", Service: "iam", Severity: "low", Categories: []string{"identity", "authentication"}},
		{ID: "iam_password_policy_number", Description: "Ensure password policy requires numbers", Service: "iam", Severity: "low", Categories: []string{"identity", "authentication"}},
		{ID: "iam_password_policy_uppercase", Description: "Ensure password policy requires uppercase", Service: "iam", Severity: "low", Categories: []string{"identity", "authentication"}},
		{ID: "iam_password_policy_lowercase", Description: "Ensure password policy requires lowercase", Service: "iam", Severity: "low", Categories: []string{"identity", "authentication"}},
		{ID: "iam_password_policy_expires_passwords_within_90_days", Description: "Ensure passwords expire within 90 days", Service: "iam", Severity: "medium", Categories: []string{"identity", "authentication"}},
		{ID: "iam_password_policy_reuse_24", Description: "Ensure password reuse is prevented", Service: "iam", Severity: "medium", Categories: []string{"identity", "authentication"}},

		// Role and trust checks
		{ID: "iam_role_cross_account_readonlyaccess_policy", Description: "Check cross-account role trust policies", Service: "iam", Severity: "high", Categories: []string{"identity", "trust"}},
		{ID: "iam_role_administratoraccess_policy", Description: "Ensure roles don't have administrative access", Service: "iam", Severity: "high", Categories: []string{"identity", "authorization"}},

		// SSO and federation checks
		{ID: "sso_permissionset_inlinepolicy_attached", Description: "Check SSO permission sets for inline policies", Service: "sso", Severity: "medium", Categories: []string{"identity", "federation"}},
		{ID: "organizations_scp_check_deny_regions", Description: "Ensure SCPs restrict region access", Service: "organizations", Severity: "medium", Categories: []string{"identity", "governance"}},

		// Access Analyzer checks
		{ID: "accessanalyzer_enabled", Description: "Ensure Access Analyzer is enabled", Service: "accessanalyzer", Severity: "high", Categories: []string{"identity", "monitoring"}},
		{ID: "accessanalyzer_findings_resolved", Description: "Ensure Access Analyzer findings are resolved", Service: "accessanalyzer", Severity: "high", Categories: []string{"identity", "compliance"}},

		// CloudTrail checks for identity monitoring
		{ID: "cloudtrail_multi_region_enabled", Description: "Ensure CloudTrail is enabled in all regions", Service: "cloudtrail", Severity: "high", Categories: []string{"identity", "audit"}},
		{ID: "cloudtrail_kms_encryption_enabled", Description: "Ensure CloudTrail logs are encrypted", Service: "cloudtrail", Severity: "high", Categories: []string{"identity", "audit"}},

		// GuardDuty checks for identity threats
		{ID: "guardduty_is_enabled", Description: "Ensure GuardDuty is enabled", Service: "guardduty", Severity: "high", Categories: []string{"identity", "threat-detection"}},
		{ID: "guardduty_no_high_severity_findings", Description: "Ensure no high severity findings exist", Service: "guardduty", Severity: "high", Categories: []string{"identity", "threat-detection"}},
	}
}

// GetCheckGroups returns all available check groups
func (p *ProwlerClient) GetCheckGroups(ctx context.Context) ([]CheckGroup, error) {
	// Return identity-focused groups
	groups := []CheckGroup{
		{
			Name:        "identity_authentication",
			Description: "Identity and authentication security checks",
			Service:     "iam",
			Categories:  []string{"identity", "authentication"},
			Checks: []string{
				"iam_user_mfa_enabled_console_access",
				"iam_user_hardware_mfa_enabled",
				"iam_root_mfa_enabled",
				"iam_password_policy_minimum_length_14",
				"iam_password_policy_expires_passwords_within_90_days",
			},
		},
		{
			Name:        "identity_authorization",
			Description: "Identity authorization and permissions checks",
			Service:     "iam",
			Categories:  []string{"identity", "authorization"},
			Checks: []string{
				"iam_policy_no_administrative_privileges",
				"iam_policy_attached_only_to_group_or_roles",
				"iam_role_administratoraccess_policy",
			},
		},
		{
			Name:        "identity_credentials",
			Description: "Identity credential management checks",
			Service:     "iam",
			Categories:  []string{"identity", "credentials"},
			Checks: []string{
				"iam_user_accesskey_unused",
				"iam_root_access_key_exists",
				"iam_root_signing_certificates",
			},
		},
		{
			Name:        "identity_federation",
			Description: "Identity federation and SSO checks",
			Service:     "sso",
			Categories:  []string{"identity", "federation"},
			Checks: []string{
				"sso_permissionset_inlinepolicy_attached",
				"organizations_scp_check_deny_regions",
			},
		},
		{
			Name:        "identity_monitoring",
			Description: "Identity monitoring and audit checks",
			Service:     "multi",
			Categories:  []string{"identity", "monitoring", "audit"},
			Checks: []string{
				"accessanalyzer_enabled",
				"cloudtrail_multi_region_enabled",
				"guardduty_is_enabled",
			},
		},
	}

	// Also include default groups
	for name, checks := range DefaultCheckGroups {
		groups = append(groups, CheckGroup{
			Name:        name,
			Description: fmt.Sprintf("Default %s checks", name),
			Service:     name,
			Checks:      checks,
			Categories:  []string{name},
		})
	}

	return groups, nil
}

// GetServices returns all AWS services covered by Prowler
func (p *ProwlerClient) GetServices(ctx context.Context) ([]AWSService, error) {
	// Return identity-related services
	return []AWSService{
		{
			Name:        "iam",
			DisplayName: "Identity and Access Management",
			Description: "Core identity and access management service",
			Categories:  []string{"identity", "security"},
		},
		{
			Name:        "sso",
			DisplayName: "AWS Single Sign-On",
			Description: "Centralized portal for SSO access",
			Categories:  []string{"identity", "federation"},
		},
		{
			Name:        "organizations",
			DisplayName: "AWS Organizations",
			Description: "Account management and governance",
			Categories:  []string{"identity", "governance"},
		},
		{
			Name:        "accessanalyzer",
			DisplayName: "AWS IAM Access Analyzer",
			Description: "Analyze resource access policies",
			Categories:  []string{"identity", "compliance"},
		},
		{
			Name:        "cloudtrail",
			DisplayName: "AWS CloudTrail",
			Description: "Audit trail for AWS API calls",
			Categories:  []string{"identity", "audit"},
		},
		{
			Name:        "guardduty",
			DisplayName: "Amazon GuardDuty",
			Description: "Threat detection service",
			Categories:  []string{"identity", "threat-detection"},
		},
		{
			Name:        "detective",
			DisplayName: "Amazon Detective",
			Description: "Security investigation service",
			Categories:  []string{"identity", "investigation"},
		},
		{
			Name:        "cognito",
			DisplayName: "Amazon Cognito",
			Description: "User identity and data synchronization",
			Categories:  []string{"identity", "authentication"},
		},
		{
			Name:        "identitystore",
			DisplayName: "AWS Identity Store",
			Description: "Identity source for AWS SSO",
			Categories:  []string{"identity", "directory"},
		},
	}, nil
}

// GetJobStatus returns the status of a Prowler job
func (p *ProwlerClient) GetJobStatus(ctx context.Context, jobID string) (*ProwlerJobStatus, error) {
	p.jobMutex.RLock()
	job, exists := p.jobTracker[jobID]
	p.jobMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}

	status := &ProwlerJobStatus{
		JobID:     job.ID,
		Status:    job.Status,
		StartTime: job.StartTime,
		Progress:  job.Progress,
	}

	if job.Error != nil {
		status.Error = job.Error.Error()
	}

	return status, nil
}

// CancelJob cancels a running Prowler job
func (p *ProwlerClient) CancelJob(ctx context.Context, jobID string) error {
	p.jobMutex.RLock()
	job, exists := p.jobTracker[jobID]
	p.jobMutex.RUnlock()

	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}

	if job.Cancel != nil {
		job.Cancel()
		job.Status = "cancelled"
		return nil
	}

	return fmt.Errorf("job cannot be cancelled")
}

// Health checks the health of the Prowler service
func (p *ProwlerClient) Health(ctx context.Context) error {
	// Check if Prowler is accessible
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if p.prowlerPath == "docker" {
		cmd = exec.CommandContext(ctx, "docker", "images", p.config.DockerImage)
	} else {
		cmd = exec.CommandContext(ctx, p.prowlerPath, "--version")
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("prowler health check failed: %w", err)
	}

	return nil
}

// Version returns the Prowler version
func (p *ProwlerClient) Version(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if p.prowlerPath == "docker" {
		cmd = exec.CommandContext(ctx, "docker", "run", "--rm", p.config.DockerImage, "--version")
	} else {
		cmd = exec.CommandContext(ctx, p.prowlerPath, "--version")
	}

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Prowler version: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

// mapSeverity maps Prowler severity to internal severity type
func (p *ProwlerClient) mapSeverity(severity string) types.Severity {
	switch severity {
	case "critical", "CRITICAL":
		return types.SeverityCritical
	case "high", "HIGH":
		return types.SeverityHigh
	case "medium", "MEDIUM":
		return types.SeverityMedium
	case "low", "LOW":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}
