package nomad

// Legacy Nomad Job Template Functions
//
// Extracted from cmd/scan.go during Phase 3 refactoring (2025-10-06)
// These functions support the older direct Nomad CLI-based job submission
// Retained for backward compatibility with existing workflows

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/security"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// RunLegacyScan executes a scan using the legacy Nomad job template approach
// This uses direct Nomad CLI commands instead of the client library
func RunLegacyScan(scanType types.ScanType, target string, options map[string]string, scanID string) ([]types.Finding, error) {
	jobTemplate := GenerateJobTemplate(scanType, target, options, scanID)

	// Write job template to secure temporary file
	tempFile, err := security.CreateSecureTempFile("scan_", ".nomad")
	if err != nil {
		return nil, fmt.Errorf("failed to create secure temp file: %w", err)
	}
	defer func() {
		if closeErr := tempFile.Close(); closeErr != nil {
			// Log error but don't fail
		}
	}()

	if _, err := tempFile.Write([]byte(jobTemplate)); err != nil {
		return nil, fmt.Errorf("failed to write job template: %w", err)
	}

	jobFile := tempFile.Name()

	// Submit job to Nomad
	cmd := exec.Command("nomad", "job", "run", jobFile)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to submit nomad job: %w", err)
	}

	// Wait for job completion and collect results
	return WaitForJobCompletion(scanID)
}

// GenerateJobTemplate creates a Nomad job HCL template for a scan
func GenerateJobTemplate(scanType types.ScanType, target string, options map[string]string, scanID string) string {
	var image, command string

	switch scanType {
	case types.ScanTypePort:
		image = "instrumentisto/nmap:latest"
		command = fmt.Sprintf("nmap -oJ /results/%s.json -p %s %s", scanID, getOption(options, "ports", "1-1000"), target)
	case types.ScanTypeSSL:
		image = "alpine/openssl:latest"
		command = fmt.Sprintf("openssl s_client -connect %s:443 -servername %s > /results/%s.txt", target, target, scanID)
	case types.ScanTypeWeb:
		image = "owasp/zap2docker-stable:latest"
		command = fmt.Sprintf("zap-baseline.py -t %s -J /results/%s.json", target, scanID)
	case types.ScanTypeVuln:
		image = "projectdiscovery/nuclei:latest"
		command = fmt.Sprintf("nuclei -u %s -json -o /results/%s.json", target, scanID)
	case "http_probe":
		image = "projectdiscovery/httpx:latest"
		command = fmt.Sprintf("echo %s | httpx -json -o /results/%s.json", target, scanID)
	case types.ScanTypeDirectory:
		image = "ffuf/ffuf:latest"
		command = fmt.Sprintf("ffuf -u %s/FUZZ -w /usr/share/wordlists/common.txt -o /results/%s.json", target, scanID)
	default:
		image = "alpine:latest"
		command = fmt.Sprintf("echo 'Scan type %s not supported in container mode' > /results/%s.txt", scanType, scanID)
	}

	template := `job "scan-%s" {
  datacenters = ["dc1"]
  type = "batch"

  group "scanner" {
    count = 1

    volume "results" {
      type      = "host"
      source    = "scan-results"
      read_only = false
    }

    task "scan" {
      driver = "docker"

      volume_mount {
        volume      = "results"
        destination = "/results"
        read_only   = false
      }

      config {
        image = "%s"
        command = "sh"
        args = ["-c", "%s"]

        auth {
          username = ""
          password = ""
        }
      }

      env {
        SCAN_ID = "%s"
        TARGET = "%s"
        SCAN_TYPE = "%s"
      }

      resources {
        cpu    = 500
        memory = 256
      }

      restart {
        attempts = 1
        interval = "5m"
        delay    = "15s"
        mode     = "fail"
      }
    }
  }
}`

	return fmt.Sprintf(template, scanID, image, command, scanID, target, scanType)
}

// getOption retrieves an option from the options map with a default value
func getOption(options map[string]string, key, defaultValue string) string {
	if options != nil && options[key] != "" {
		return options[key]
	}
	return defaultValue
}

// WaitForJobCompletion polls for Nomad job completion using CLI
func WaitForJobCompletion(scanID string) ([]types.Finding, error) {
	// Poll for job completion
	jobName := fmt.Sprintf("scan-%s", scanID)
	maxWait := 5 * time.Minute
	pollInterval := 10 * time.Second

	timeout := time.After(maxWait)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("scan job %s timed out after %s", jobName, maxWait)
		case <-ticker.C:
			// Check job status
			cmd := exec.Command("nomad", "job", "status", jobName)
			output, err := cmd.Output()
			if err != nil {
				continue
			}

			if strings.Contains(string(output), "Status = dead") && strings.Contains(string(output), "successful") {
				// Job completed successfully, collect results
				return CollectResults(scanID)
			} else if strings.Contains(string(output), "Status = dead") && strings.Contains(string(output), "failed") {
				return nil, fmt.Errorf("scan job %s failed", jobName)
			}
		}
	}
}

// CollectResults reads scan results from the Nomad job volume
func CollectResults(scanID string) ([]types.Finding, error) {
	// Validate scanID to prevent path traversal
	if strings.Contains(scanID, "..") || strings.Contains(scanID, "/") {
		return nil, fmt.Errorf("invalid scan ID")
	}

	// Read results from the mounted volume with validated paths
	resultFiles := []string{
		fmt.Sprintf("/tmp/scan-results/%s.json", scanID),
		fmt.Sprintf("/tmp/scan-results/%s.txt", scanID),
	}

	var findings []types.Finding

	for _, file := range resultFiles {
		if content, err := os.ReadFile(file); err == nil {
			// Parse the results based on file type
			if strings.HasSuffix(file, ".json") {
				// Try to parse as JSON findings
				if parsedFindings := parseJSONResults(string(content), scanID); len(parsedFindings) > 0 {
					findings = append(findings, parsedFindings...)
				}
			} else {
				// Create a basic finding from text content
				finding := types.Finding{
					ID:          fmt.Sprintf("%s-result", scanID),
					ScanID:      scanID,
					Type:        "scan_result",
					Tool:        "container-scan",
					Title:       "Scan Results",
					Description: "Containerized scan completed",
					Severity:    types.SeverityInfo,
					Evidence:    string(content),
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// parseJSONResults parses tool-specific JSON output formats
func parseJSONResults(content, scanID string) []types.Finding {
	// This would parse tool-specific JSON output formats
	// For now, create a basic finding with the raw content
	var findings []types.Finding

	if len(content) > 0 {
		finding := types.Finding{
			ID:          fmt.Sprintf("%s-parsed", scanID),
			ScanID:      scanID,
			Type:        "parsed_result",
			Tool:        "json-parser",
			Title:       "JSON Scan Results",
			Description: "Parsed results from containerized scan",
			Severity:    types.SeverityInfo,
			Evidence:    content,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		findings = append(findings, finding)
	}

	return findings
}
