package hackerone

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/platforms"
)

// Client implements the HackerOne API client
type Client struct {
	config     config.HackerOneConfig
	httpClient *http.Client
}

// NewClient creates a new HackerOne API client
func NewClient(cfg config.HackerOneConfig) *Client {
	return &Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// Name returns the platform name
func (c *Client) Name() string {
	return "HackerOne"
}

// ValidateCredentials validates the API credentials
func (c *Client) ValidateCredentials(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.config.BaseURL+"/me", nil)
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

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid credentials: status %d", resp.StatusCode)
	}

	return nil
}

// GetPrograms lists available bug bounty programs
func (c *Client) GetPrograms(ctx context.Context) ([]*platforms.Program, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.config.BaseURL+"/hackers/programs", nil)
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

	programs := make([]*platforms.Program, 0, len(response.Data))
	for _, p := range response.Data {
		programs = append(programs, convertProgram(p))
	}

	return programs, nil
}

// GetProgramByHandle retrieves a specific program by handle
func (c *Client) GetProgramByHandle(ctx context.Context, handle string) (*platforms.Program, error) {
	url := fmt.Sprintf("%s/hackers/programs/%s", c.config.BaseURL, handle)
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

	var response programResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return convertProgram(response.Data), nil
}

// Submit submits a vulnerability report to HackerOne
func (c *Client) Submit(ctx context.Context, report *platforms.VulnerabilityReport) (*platforms.SubmissionResponse, error) {
	// P0-4 FIX: Validate report before submission
	if err := report.Validate(); err != nil {
		return nil, fmt.Errorf("invalid report: %w", err)
	}

	// Map severity to HackerOne format
	mapping := platforms.GetSeverityMapping("hackerone")
	severity := mapSeverity(report.Severity, mapping)

	// Create the report payload
	payload := createReportPayload{
		Data: createReportData{
			Type: "report",
			Attributes: reportAttributes{
				TeamHandle:               report.ProgramHandle,
				Title:                    report.Title,
				VulnerabilityInformation: report.Description + "\n\n" + report.ProofOfConcept,
				Severity:                 severity,
				ImpactDescription:        report.Impact,
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	url := c.config.BaseURL + "/hackers/reports"
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

	var createResponse createReportResponse
	if err := json.Unmarshal(responseBody, &createResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	status := "pending"
	if c.config.DraftMode {
		status = "draft"
	}

	return &platforms.SubmissionResponse{
		Success:     true,
		ReportID:    createResponse.Data.ID,
		ReportURL:   fmt.Sprintf("https://hackerone.com/reports/%s", createResponse.Data.ID),
		Status:      status,
		Message:     "Report submitted successfully",
		SubmittedAt: time.Now(),
		PlatformData: map[string]interface{}{
			"report_id": createResponse.Data.ID,
			"state":     createResponse.Data.Attributes.State,
		},
	}, nil
}

// setAuthHeader sets the Basic Authentication header
func (c *Client) setAuthHeader(req *http.Request) {
	credentials := c.config.APIUsername + ":" + c.config.APIToken
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
	req.Header.Set("Authorization", "Basic "+encoded)
}

// mapSeverity maps shells severity to HackerOne severity
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

// convertProgram converts HackerOne program to platform Program
func convertProgram(p programData) *platforms.Program {
	program := &platforms.Program{
		Handle:      p.Attributes.Handle,
		Name:        p.Attributes.Name,
		Platform:    "hackerone",
		URL:         fmt.Sprintf("https://hackerone.com/%s", p.Attributes.Handle),
		IsActive:    p.Attributes.SubmissionState == "open",
		Description: p.Attributes.About,
	}

	// Convert scope
	if p.Relationships.StructuredScopes.Data != nil {
		scope := make([]platforms.Asset, 0)
		outOfScope := make([]platforms.Asset, 0)

		for _, s := range p.Relationships.StructuredScopes.Data {
			asset := platforms.Asset{
				Type:        s.Attributes.AssetType,
				Identifier:  s.Attributes.AssetIdentifier,
				Description: s.Attributes.Instruction,
				MaxSeverity: s.Attributes.MaxSeverity,
			}

			if s.Attributes.EligibleForBounty {
				scope = append(scope, asset)
			} else {
				outOfScope = append(outOfScope, asset)
			}
		}

		program.Scope = scope
		program.OutOfScope = outOfScope
	}

	return program
}
