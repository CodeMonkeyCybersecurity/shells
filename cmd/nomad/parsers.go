package nomad

// Nomad Result Parsers
//
// Extracted from cmd/scanners/infrastructure.go during Phase 3 refactoring (2025-10-06)
// Handles parsing of scan results from Nomad job logs

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/nomad"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// parseScanResults parses scan output from Nomad job logs and converts to findings
func (n *NomadIntegration) parseScanResults(scanType types.ScanType, target, scanID, logs string, jobStatus *nomad.JobStatusResponse) []types.Finding {
	var findings []types.Finding

	// Create a basic finding with job execution details
	baseFinding := types.Finding{
		ID:        fmt.Sprintf("%s-%s", scanType, scanID),
		ScanID:    scanID,
		Type:      string(scanType),
		Tool:      string(scanType),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Parse scan-specific results from logs
	switch scanType {
	case types.ScanTypePort:
		findings = append(findings, n.parseNmapResults(baseFinding, logs)...)
	case types.ScanTypeVuln:
		findings = append(findings, n.parseNucleiResults(baseFinding, logs)...)
	case types.ScanTypeSSL:
		findings = append(findings, n.parseSSLResults(baseFinding, logs)...)
	default:
		// Generic finding
		baseFinding.Title = fmt.Sprintf("%s Scan Complete", scanType)
		baseFinding.Description = fmt.Sprintf("Nomad job executed successfully for %s scan", scanType)
		baseFinding.Severity = types.SeverityInfo
		baseFinding.Evidence = fmt.Sprintf("Job Status: %s\nLogs:\n%s", jobStatus.Status, logs)
		findings = append(findings, baseFinding)
	}

	return findings
}

// parseNmapResults parses Nmap output into findings
func (n *NomadIntegration) parseNmapResults(baseFinding types.Finding, logs string) []types.Finding {
	var findings []types.Finding

	// Look for open ports in logs (simplified parsing)
	if strings.Contains(logs, "open") {
		baseFinding.Title = "Open Ports Discovered"
		baseFinding.Description = "Nmap discovered open ports on target"
		baseFinding.Severity = types.SeverityInfo
		baseFinding.Evidence = logs
		findings = append(findings, baseFinding)
	} else {
		baseFinding.Title = "Port Scan Complete"
		baseFinding.Description = "Nmap port scan completed"
		baseFinding.Severity = types.SeverityInfo
		baseFinding.Evidence = logs
		findings = append(findings, baseFinding)
	}

	return findings
}

// parseNucleiResults parses Nuclei output into findings
func (n *NomadIntegration) parseNucleiResults(baseFinding types.Finding, logs string) []types.Finding {
	var findings []types.Finding

	// Look for vulnerabilities in logs (simplified parsing)
	if strings.Contains(logs, "critical") || strings.Contains(logs, "high") {
		baseFinding.Title = "Vulnerabilities Discovered"
		baseFinding.Description = "Nuclei discovered potential vulnerabilities"
		baseFinding.Severity = types.SeverityHigh
		baseFinding.Evidence = logs
		findings = append(findings, baseFinding)
	} else if strings.Contains(logs, "medium") || strings.Contains(logs, "low") {
		baseFinding.Title = "Issues Discovered"
		baseFinding.Description = "Nuclei discovered potential issues"
		baseFinding.Severity = types.SeverityMedium
		baseFinding.Evidence = logs
		findings = append(findings, baseFinding)
	} else {
		baseFinding.Title = "Vulnerability Scan Complete"
		baseFinding.Description = "Nuclei vulnerability scan completed"
		baseFinding.Severity = types.SeverityInfo
		baseFinding.Evidence = logs
		findings = append(findings, baseFinding)
	}

	return findings
}

// parseSSLResults parses SSL scan output into findings
func (n *NomadIntegration) parseSSLResults(baseFinding types.Finding, logs string) []types.Finding {
	var findings []types.Finding

	// Look for SSL/TLS issues in logs (simplified parsing)
	if strings.Contains(logs, "weak") || strings.Contains(logs, "vulnerable") {
		baseFinding.Title = "SSL/TLS Issues Discovered"
		baseFinding.Description = "SSL scanner discovered configuration issues"
		baseFinding.Severity = types.SeverityMedium
		baseFinding.Evidence = logs
		findings = append(findings, baseFinding)
	} else {
		baseFinding.Title = "SSL/TLS Scan Complete"
		baseFinding.Description = "SSL/TLS analysis completed"
		baseFinding.Severity = types.SeverityInfo
		baseFinding.Evidence = logs
		findings = append(findings, baseFinding)
	}

	return findings
}
