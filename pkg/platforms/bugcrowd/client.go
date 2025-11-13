package bugcrowd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/platforms"
)

// Client implements the Bugcrowd API client
type Client struct {
	config     config.BugcrowdConfig
	httpClient *http.Client
}

// NewClient creates a new Bugcrowd API client
func NewClient(cfg config.BugcrowdConfig) *Client {
	return &Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// Name returns the platform name
func (c *Client) Name() string {
	return "Bugcrowd"
}

// ValidateCredentials validates the API credentials
func (c *Client) ValidateCredentials(ctx context.Context) error {
	// Bugcrowd uses token-based authentication
	// Test by making a simple API call
	req, err := http.NewRequestWithContext(ctx, "GET", c.config.BaseURL+"/programs", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	c.setAuthHeader(req)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to validate credentials: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("invalid credentials: unauthorized")
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("credential validation failed: status %d", resp.StatusCode)
	}

	return nil
}

// GetPrograms lists available bug bounty programs
func (c *Client) GetPrograms(ctx context.Context) ([]*platforms.Program, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.config.BaseURL+"/programs", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setAuthHeader(req)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get programs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read error response (status %d): %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("failed to get programs: status %d, body: %s", resp.StatusCode, string(body))
	}

	var response programsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	programs := make([]*platforms.Program, 0, len(response.Programs))
	for _, p := range response.Programs {
		programs = append(programs, convertProgram(p))
	}

	return programs, nil
}

// GetProgramByHandle retrieves a specific program by handle
func (c *Client) GetProgramByHandle(ctx context.Context, handle string) (*platforms.Program, error) {
	url := fmt.Sprintf("%s/programs/%s", c.config.BaseURL, handle)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setAuthHeader(req)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get program: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read error response (status %d): %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("failed to get program: status %d, body: %s", resp.StatusCode, string(body))
	}

	var program programData
	if err := json.NewDecoder(resp.Body).Decode(&program); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return convertProgram(program), nil
}

// Submit submits a vulnerability report to Bugcrowd
func (c *Client) Submit(ctx context.Context, report *platforms.VulnerabilityReport) (*platforms.SubmissionResponse, error) {
	// P0-4 FIX: Validate report before submission
	if err := report.Validate(); err != nil {
		return nil, fmt.Errorf("invalid report: %w", err)
	}

	// Map severity to Bugcrowd priority format (P1-P5)
	mapping := platforms.GetSeverityMapping("bugcrowd")
	priority := mapSeverity(report.Severity, mapping)

	// Build description with repro steps
	description := report.Description + "\n\n## Proof of Concept\n" + report.ProofOfConcept
	if len(report.ReproSteps) > 0 {
		description += "\n\n## Reproduction Steps\n"
		for i, step := range report.ReproSteps {
			description += fmt.Sprintf("%d. %s\n", i+1, step)
		}
	}

	// Create the submission payload
	payload := createSubmissionPayload{
		Submission: submissionData{
			Title:       report.Title,
			Description: description,
			VrtID:       report.CWE, // Bugcrowd uses VRT (Vulnerability Rating Taxonomy)
			URL:         report.AssetURL,
			Priority:    priority,
			Impact:      report.Impact,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	url := fmt.Sprintf("%s/programs/%s/submissions", c.config.BaseURL, report.ProgramHandle)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setAuthHeader(req)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to submit report: %w", err)
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to submit report: status %d, body: %s", resp.StatusCode, string(responseBody))
	}

	var createResponse createSubmissionResponse
	if err := json.Unmarshal(responseBody, &createResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	status := "pending"
	if c.config.DraftMode {
		status = "draft"
	}

	return &platforms.SubmissionResponse{
		Success:     true,
		ReportID:    createResponse.UUID,
		ReportURL:   fmt.Sprintf("https://bugcrowd.com/submissions/%s", createResponse.UUID),
		Status:      status,
		Message:     "Submission created successfully",
		SubmittedAt: time.Now(),
		PlatformData: map[string]interface{}{
			"uuid":     createResponse.UUID,
			"priority": priority,
			"state":    createResponse.State,
		},
	}, nil
}

// setAuthHeader sets the Token authentication header for Bugcrowd
func (c *Client) setAuthHeader(req *http.Request) {
	req.Header.Set("Authorization", "Token "+c.config.APIToken)
}

// mapSeverity maps shells severity to Bugcrowd priority (P1-P5)
func mapSeverity(shellsSeverity string, mapping platforms.SeverityMapping) string {
	switch shellsSeverity {
	case "CRITICAL":
		return mapping.Critical
	case "HIGH":
		return mapping.High
	case "MEDIUM":
		return mapping.Medium
	case "LOW":
		return mapping.Low
	default:
		return mapping.Info
	}
}

// convertProgram converts Bugcrowd program to platform Program
func convertProgram(p programData) *platforms.Program {
	program := &platforms.Program{
		Handle:      p.Code,
		Name:        p.Name,
		Platform:    "bugcrowd",
		URL:         fmt.Sprintf("https://bugcrowd.com/%s", p.Code),
		IsActive:    p.State == "active",
		Description: p.Description,
	}

	// Convert scope if available
	if len(p.Targets) > 0 {
		scope := make([]platforms.Asset, 0)
		for _, t := range p.Targets {
			asset := platforms.Asset{
				Type:        t.Category,
				Identifier:  t.Name,
				Description: t.Description,
			}
			if t.InScope {
				scope = append(scope, asset)
			}
		}
		program.Scope = scope
	}

	return program
}
