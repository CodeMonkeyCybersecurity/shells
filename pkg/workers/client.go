package workers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client communicates with the Python worker service
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new worker service client
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GraphQL scan types

type GraphQLScanRequest struct {
	Endpoint   string  `json:"endpoint"`
	AuthHeader *string `json:"auth_header,omitempty"`
	OutputFile *string `json:"output_file,omitempty"`
}

type IDORScanRequest struct {
	Endpoint string   `json:"endpoint"`
	Tokens   []string `json:"tokens"`
	StartID  int      `json:"start_id"`
	EndID    int      `json:"end_id"`
}

type JobStatus struct {
	JobID       string                 `json:"job_id"`
	Status      string                 `json:"status"` // pending, running, completed, failed
	CreatedAt   string                 `json:"created_at"`
	CompletedAt *string                `json:"completed_at,omitempty"`
	Result      map[string]interface{} `json:"result,omitempty"`
	Error       *string                `json:"error,omitempty"`
}

// ScanGraphQL starts a GraphQL scan and returns immediately with job ID
func (c *Client) ScanGraphQL(ctx context.Context, endpoint string, authHeader *string) (*JobStatus, error) {
	req := GraphQLScanRequest{
		Endpoint:   endpoint,
		AuthHeader: authHeader,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/graphql/scan", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("scan failed: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var status JobStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &status, nil
}

// ScanIDOR starts an IDOR scan and returns immediately with job ID
func (c *Client) ScanIDOR(ctx context.Context, endpoint string, tokens []string, startID, endID int) (*JobStatus, error) {
	req := IDORScanRequest{
		Endpoint: endpoint,
		Tokens:   tokens,
		StartID:  startID,
		EndID:    endID,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/idor/scan", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("scan failed: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var status JobStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &status, nil
}

// GetJobStatus retrieves the status of a job
func (c *Client) GetJobStatus(ctx context.Context, jobID string) (*JobStatus, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/jobs/"+jobID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get status failed: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var status JobStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &status, nil
}

// WaitForCompletion polls until job is completed or context times out
func (c *Client) WaitForCompletion(ctx context.Context, jobID string, pollInterval time.Duration) (*JobStatus, error) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			status, err := c.GetJobStatus(ctx, jobID)
			if err != nil {
				return nil, err
			}

			if status.Status == "completed" || status.Status == "failed" {
				return status, nil
			}
		}
	}
}

// ScanGraphQLSync scans GraphQL and waits for completion
func (c *Client) ScanGraphQLSync(ctx context.Context, endpoint string, authHeader *string) (*JobStatus, error) {
	// Start scan
	status, err := c.ScanGraphQL(ctx, endpoint, authHeader)
	if err != nil {
		return nil, err
	}

	// Wait for completion (poll every 2 seconds)
	return c.WaitForCompletion(ctx, status.JobID, 2*time.Second)
}

// ScanIDORSync scans for IDOR and waits for completion
func (c *Client) ScanIDORSync(ctx context.Context, endpoint string, tokens []string, startID, endID int) (*JobStatus, error) {
	// Start scan
	status, err := c.ScanIDOR(ctx, endpoint, tokens, startID, endID)
	if err != nil {
		return nil, err
	}

	// Wait for completion (poll every 2 seconds)
	return c.WaitForCompletion(ctx, status.JobID, 2*time.Second)
}

// Health checks if the worker service is healthy
func (c *Client) Health() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed: status %d", resp.StatusCode)
	}

	return nil
}
