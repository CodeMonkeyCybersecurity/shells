package nuclei

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

type nucleiScanner struct {
	cfg    NucleiConfig
	logger interface {
		Info(msg string, keysAndValues ...interface{})
		Error(msg string, keysAndValues ...interface{})
		Debug(msg string, keysAndValues ...interface{})
	}
}

type NucleiConfig struct {
	BinaryPath    string
	TemplatesPath string
	CustomTemplates string
	Timeout       time.Duration
	RateLimit     int
	BulkSize      int
	Concurrency   int
	Retries       int
}

type NucleiOutput struct {
	TemplateID   string      `json:"template-id"`
	TemplatePath string      `json:"template-path"`
	Info         NucleiInfo  `json:"info"`
	Type         string      `json:"type"`
	Host         string      `json:"host"`
	Matched      string      `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results,omitempty"`
	Meta         interface{} `json:"meta,omitempty"`
	Timestamp    string      `json:"timestamp"`
	MatcherStatus bool       `json:"matcher-status"`
	CurlCommand  string      `json:"curl-command,omitempty"`
}

type NucleiInfo struct {
	Name        string   `json:"name"`
	Author      []string `json:"author"`
	Tags        []string `json:"tags"`
	Description string   `json:"description"`
	Reference   []string `json:"reference,omitempty"`
	Severity    string   `json:"severity"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

func NewScanner(cfg NucleiConfig, logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}) core.Scanner {
	if cfg.BinaryPath == "" {
		cfg.BinaryPath = "nuclei"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Minute
	}
	if cfg.RateLimit == 0 {
		cfg.RateLimit = 150
	}
	if cfg.BulkSize == 0 {
		cfg.BulkSize = 25
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 25
	}
	
	return &nucleiScanner{
		cfg:    cfg,
		logger: logger,
	}
}

func (s *nucleiScanner) Name() string {
	return "nuclei"
}

func (s *nucleiScanner) Type() types.ScanType {
	return types.ScanType("vulnerability")
}

func (s *nucleiScanner) Validate(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	
	if _, err := exec.LookPath(s.cfg.BinaryPath); err != nil {
		return fmt.Errorf("nuclei binary not found: %w", err)
	}
	
	return nil
}

func (s *nucleiScanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("nuclei_%d.json", time.Now().Unix()))
	defer os.Remove(tempFile)
	
	args := s.buildNucleiArgs(target, tempFile, options)
	
	s.logger.Info("Running nuclei scan", "target", target, "args", args)
	
	cmd := exec.CommandContext(ctx, s.cfg.BinaryPath, args...)
	
	// Capture stderr for debugging
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}
	
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start nuclei: %w", err)
	}
	
	// Log stderr output
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			s.logger.Debug("nuclei stderr", "output", scanner.Text())
		}
	}()
	
	if err := cmd.Wait(); err != nil {
		// Nuclei returns non-zero exit code when vulnerabilities are found
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			s.logger.Debug("Nuclei found vulnerabilities", "exit_code", 1)
		} else {
			return nil, fmt.Errorf("nuclei scan failed: %w", err)
		}
	}
	
	return s.parseNucleiOutput(tempFile, target)
}

func (s *nucleiScanner) buildNucleiArgs(target, outputFile string, options map[string]string) []string {
	args := []string{
		"-u", target,
		"-json",
		"-o", outputFile,
		"-rate-limit", fmt.Sprintf("%d", s.cfg.RateLimit),
		"-bulk-size", fmt.Sprintf("%d", s.cfg.BulkSize),
		"-c", fmt.Sprintf("%d", s.cfg.Concurrency),
		"-retries", fmt.Sprintf("%d", s.cfg.Retries),
		"-timeout", fmt.Sprintf("%d", int(s.cfg.Timeout.Seconds())),
		"-stats",
		"-silent",
	}
	
	// Add severity filter
	if severity := options["severity"]; severity != "" {
		args = append(args, "-severity", severity)
	} else {
		args = append(args, "-severity", "critical,high,medium,low,info")
	}
	
	// Add template filters
	if tags := options["tags"]; tags != "" {
		args = append(args, "-tags", tags)
	}
	
	// Add specific templates
	if templates := options["templates"]; templates != "" {
		for _, template := range strings.Split(templates, ",") {
			args = append(args, "-t", strings.TrimSpace(template))
		}
	} else if s.cfg.TemplatesPath != "" {
		args = append(args, "-t", s.cfg.TemplatesPath)
	}
	
	// Add custom templates
	if s.cfg.CustomTemplates != "" {
		args = append(args, "-t", s.cfg.CustomTemplates)
	}
	
	// Add OAuth2 specific templates
	if scanType := options["scan_type"]; scanType == "oauth2" {
		args = append(args, "-tags", "oauth,jwt,oidc,auth")
		args = append(args, "-t", "exposures/configs/oauth-secret.yaml")
		args = append(args, "-t", "vulnerabilities/generic/jwt-none-alg.yaml")
		args = append(args, "-t", "misconfiguration/oauth-public-clients.yaml")
	}
	
	// Add API specific templates
	if scanType := options["scan_type"]; scanType == "api" {
		args = append(args, "-tags", "api,graphql,rest,swagger")
	}
	
	// Advanced options
	if options["follow_redirects"] == "true" {
		args = append(args, "-follow-redirects")
	}
	
	if options["headless"] == "true" {
		args = append(args, "-headless")
	}
	
	if proxy := options["proxy"]; proxy != "" {
		args = append(args, "-proxy", proxy)
	}
	
	// Add authentication headers
	if authHeader := options["auth_header"]; authHeader != "" {
		args = append(args, "-H", authHeader)
	}
	
	return args
}

func (s *nucleiScanner) parseNucleiOutput(outputFile, target string) ([]types.Finding, error) {
	file, err := os.Open(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open nuclei output: %w", err)
	}
	defer file.Close()
	
	findings := []types.Finding{}
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		var output NucleiOutput
		if err := json.Unmarshal(scanner.Bytes(), &output); err != nil {
			s.logger.Error("Failed to parse nuclei output line", "error", err)
			continue
		}
		
		finding := s.convertToFinding(output, target)
		findings = append(findings, finding)
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading nuclei output: %w", err)
	}
	
	return findings, nil
}

func (s *nucleiScanner) convertToFinding(output NucleiOutput, target string) types.Finding {
	severity := s.mapNucleiSeverity(output.Info.Severity)
	
	finding := types.Finding{
		Tool:        "nuclei",
		Type:        s.determineVulnType(output),
		Severity:    severity,
		Title:       output.Info.Name,
		Description: s.buildDescription(output),
		Evidence:    s.buildEvidence(output),
		Solution:    s.buildSolution(output),
		References:  output.Info.Reference,
		Metadata: map[string]interface{}{
			"template_id":   output.TemplateID,
			"template_path": output.TemplatePath,
			"matched_at":    output.Matched,
			"tags":          output.Info.Tags,
			"authors":       output.Info.Author,
			"metadata":      output.Info.Metadata,
		},
	}
	
	// Add extracted results if any
	if len(output.ExtractedResults) > 0 {
		finding.Metadata["extracted_results"] = output.ExtractedResults
	}
	
	// Add curl command for reproduction
	if output.CurlCommand != "" {
		finding.Metadata["curl_command"] = output.CurlCommand
	}
	
	// Special handling for OAuth2/JWT vulnerabilities
	if s.isOAuth2Vuln(output) {
		finding.Metadata["oauth2_specific"] = true
		finding.Solution = s.getOAuth2Solution(output.TemplateID)
	}
	
	return finding
}

func (s *nucleiScanner) mapNucleiSeverity(severity string) types.Severity {
	switch strings.ToLower(severity) {
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

func (s *nucleiScanner) determineVulnType(output NucleiOutput) string {
	// Check tags for specific vulnerability types
	tags := output.Info.Tags
	
	for _, tag := range tags {
		switch strings.ToLower(tag) {
		case "sqli", "sql":
			return "sql_injection"
		case "xss":
			return "cross_site_scripting"
		case "xxe":
			return "xml_external_entity"
		case "ssrf":
			return "server_side_request_forgery"
		case "rce":
			return "remote_code_execution"
		case "lfi":
			return "local_file_inclusion"
		case "oauth", "oidc":
			return "oauth2_vulnerability"
		case "jwt":
			return "jwt_vulnerability"
		case "graphql":
			return "graphql_vulnerability"
		case "api":
			return "api_vulnerability"
		case "misconfig", "misconfiguration":
			return "misconfiguration"
		case "exposure", "disclosure":
			return "information_disclosure"
		}
	}
	
	// Fallback to template type
	return output.Type
}

func (s *nucleiScanner) buildDescription(output NucleiOutput) string {
	desc := output.Info.Description
	
	if desc == "" {
		desc = fmt.Sprintf("Vulnerability detected using Nuclei template: %s", output.TemplateID)
	}
	
	// Add context about where it was found
	desc += fmt.Sprintf("\n\nDetected at: %s", output.Matched)
	
	// Add metadata if relevant
	if output.Info.Metadata != nil {
		if impact, ok := output.Info.Metadata["impact"]; ok {
			desc += fmt.Sprintf("\n\nImpact: %v", impact)
		}
	}
	
	return desc
}

func (s *nucleiScanner) buildEvidence(output NucleiOutput) string {
	evidence := fmt.Sprintf("Template: %s\n", output.TemplateID)
	evidence += fmt.Sprintf("Matched at: %s\n", output.Matched)
	evidence += fmt.Sprintf("Timestamp: %s\n", output.Timestamp)
	
	if len(output.ExtractedResults) > 0 {
		evidence += "\nExtracted Results:\n"
		for i, result := range output.ExtractedResults {
			evidence += fmt.Sprintf("  [%d] %s\n", i+1, result)
		}
	}
	
	if output.CurlCommand != "" {
		evidence += fmt.Sprintf("\nReproduction:\n%s", output.CurlCommand)
	}
	
	return evidence
}

func (s *nucleiScanner) buildSolution(output NucleiOutput) string {
	// Check if template has remediation info
	if output.Info.Metadata != nil {
		if remediation, ok := output.Info.Metadata["remediation"]; ok {
			return fmt.Sprintf("%v", remediation)
		}
	}
	
	// Provide generic solutions based on vulnerability type
	for _, tag := range output.Info.Tags {
		switch strings.ToLower(tag) {
		case "sqli":
			return "Use parameterized queries, input validation, and least privilege database access"
		case "xss":
			return "Implement proper output encoding, Content Security Policy, and input validation"
		case "xxe":
			return "Disable XML external entity processing in all XML parsers"
		case "ssrf":
			return "Implement URL validation, use allowlists, and restrict outbound connections"
		case "rce":
			return "Sanitize user input, use safe APIs, and implement proper access controls"
		case "jwt":
			return "Verify JWT signatures, validate claims, use strong algorithms, and implement proper key management"
		case "oauth":
			return "Follow OAuth 2.0 Security Best Practices (RFC 8252), implement PKCE, validate redirect URIs"
		}
	}
	
	return "Review and fix the identified vulnerability according to security best practices"
}

func (s *nucleiScanner) isOAuth2Vuln(output NucleiOutput) bool {
	oauth2Templates := []string{
		"oauth", "oidc", "jwt", "auth", "authentication", "authorization",
		"client-secret", "redirect-uri", "state-parameter", "pkce",
	}
	
	templateID := strings.ToLower(output.TemplateID)
	for _, keyword := range oauth2Templates {
		if strings.Contains(templateID, keyword) {
			return true
		}
	}
	
	for _, tag := range output.Info.Tags {
		for _, keyword := range oauth2Templates {
			if strings.Contains(strings.ToLower(tag), keyword) {
				return true
			}
		}
	}
	
	return false
}

func (s *nucleiScanner) getOAuth2Solution(templateID string) string {
	solutions := map[string]string{
		"jwt-none-alg": "Explicitly verify JWT algorithm and reject 'none' algorithm. Use a whitelist of allowed algorithms.",
		"oauth-public-clients": "Implement PKCE for public clients, use client authentication for confidential clients.",
		"oauth-secret": "Remove client secrets from public repositories and rotate compromised credentials immediately.",
		"redirect-uri": "Implement strict redirect URI validation using exact string matching.",
		"state-parameter": "Always use cryptographically random state parameters and validate them on callback.",
	}
	
	for key, solution := range solutions {
		if strings.Contains(strings.ToLower(templateID), key) {
			return solution
		}
	}
	
	return "Follow OAuth 2.0 Security Best Current Practice (RFC 8252) and implement all recommended security measures."
}