package nomad

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

type JobDispatchRequest struct {
	JobID string            `json:"JobID"`
	Meta  map[string]string `json:"Meta"`
}

type JobDispatchResponse struct {
	DispatchedJobID string `json:"DispatchedJobID"`
	EvalID          string `json:"EvalID"`
	EvalCreateIndex int    `json:"EvalCreateIndex"`
	JobCreateIndex  int    `json:"JobCreateIndex"`
}

type JobStatusResponse struct {
	ID         string      `json:"ID"`
	Status     string      `json:"Status"`
	TaskGroups []TaskGroup `json:"TaskGroups"`
}

type TaskGroup struct {
	Name  string `json:"Name"`
	Tasks []Task `json:"Tasks"`
}

type Task struct {
	Name   string      `json:"Name"`
	State  string      `json:"State"`
	Events []TaskEvent `json:"Events"`
}

type TaskEvent struct {
	Type           string            `json:"Type"`
	Time           time.Time         `json:"Time"`
	DisplayMessage string            `json:"DisplayMessage"`
	Details        map[string]string `json:"Details"`
}

func NewClient(nomadAddr string) *Client {
	if nomadAddr == "" {
		// Try environment variable first
		nomadAddr = os.Getenv("NOMAD_ADDR")
		if nomadAddr == "" {
			nomadAddr = "http://localhost:4646"
		}
	}

	return &Client{
		baseURL: nomadAddr,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) IsAvailable() bool {
	resp, err := c.httpClient.Get(c.baseURL + "/v1/status/leader")
	if err != nil {
		return false
	}
	defer httpclient.CloseBody(resp)

	return resp.StatusCode == 200
}

func (c *Client) SubmitScan(ctx context.Context, scanType types.ScanType, target, scanID string, options map[string]string) (string, error) {
	jobName := fmt.Sprintf("shells-scan-%s", scanType)

	// Prepare dispatch request
	meta := map[string]string{
		"target":  target,
		"scan_id": scanID,
	}

	// Add options to meta
	if options != nil {
		for k, v := range options {
			meta[k] = v
		}
	}

	// Convert options to command line format
	var optionsStr []string
	for k, v := range options {
		if v == "" {
			optionsStr = append(optionsStr, fmt.Sprintf("--%s", k))
		} else {
			optionsStr = append(optionsStr, fmt.Sprintf("--%s=%s", k, v))
		}
	}
	meta["options"] = strings.Join(optionsStr, " ")

	dispatchReq := JobDispatchRequest{
		JobID: jobName,
		Meta:  meta,
	}

	// Submit job
	jsonData, err := json.Marshal(dispatchReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal dispatch request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/job/%s/dispatch", c.baseURL, jobName)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to submit job: %w", err)
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("job submission failed with status %d: %s", resp.StatusCode, string(body))
	}

	var dispatchResp JobDispatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&dispatchResp); err != nil {
		return "", fmt.Errorf("failed to decode dispatch response: %w", err)
	}

	return dispatchResp.DispatchedJobID, nil
}

func (c *Client) WaitForCompletion(ctx context.Context, jobID string, timeout time.Duration) (*JobStatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for job completion")
		case <-ticker.C:
			status, err := c.GetJobStatus(ctx, jobID)
			if err != nil {
				continue // Keep trying
			}

			switch status.Status {
			case "complete":
				return status, nil
			case "failed", "cancelled":
				return status, fmt.Errorf("job %s with status: %s", jobID, status.Status)
			default:
				// Still running, continue waiting
				continue
			}
		}
	}
}

func (c *Client) GetJobStatus(ctx context.Context, jobID string) (*JobStatusResponse, error) {
	url := fmt.Sprintf("%s/v1/job/%s", c.baseURL, jobID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get job status: %w", err)
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get job status: %s", string(body))
	}

	var status JobStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode job status: %w", err)
	}

	return &status, nil
}

func (c *Client) GetJobLogs(ctx context.Context, jobID string) (string, error) {
	// Get allocation ID first
	allocsURL := fmt.Sprintf("%s/v1/job/%s/allocations", c.baseURL, jobID)
	req, err := http.NewRequestWithContext(ctx, "GET", allocsURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get allocations: %w", err)
	}
	defer httpclient.CloseBody(resp)

	var allocs []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&allocs); err != nil {
		return "", fmt.Errorf("failed to decode allocations: %w", err)
	}

	if len(allocs) == 0 {
		return "", fmt.Errorf("no allocations found for job")
	}

	allocID := allocs[0]["ID"].(string)

	// Get logs
	logsURL := fmt.Sprintf("%s/v1/client/fs/logs/%s", c.baseURL, allocID)
	req, err = http.NewRequestWithContext(ctx, "GET", logsURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create logs request: %w", err)
	}

	q := req.URL.Query()
	q.Add("task", "scanner") // Adjust based on task name
	q.Add("type", "stdout")
	req.URL.RawQuery = q.Encode()

	resp, err = c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get logs: %w", err)
	}
	defer httpclient.CloseBody(resp)

	logs, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read logs: %w", err)
	}

	return string(logs), nil
}

func (c *Client) RegisterJob(ctx context.Context, jobName, jobHCL string) error {
	url := fmt.Sprintf("%s/v1/jobs", c.baseURL)

	jobData := map[string]interface{}{
		"Job": jobHCL,
	}

	jsonData, err := json.Marshal(jobData)
	if err != nil {
		return fmt.Errorf("failed to marshal job: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to register job: %w", err)
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("job registration failed: %s", string(body))
	}

	return nil
}

// StopJob stops a Nomad job
func (c *Client) StopJob(ctx context.Context, jobID string) error {
	url := fmt.Sprintf("%s/v1/job/%s", c.baseURL, jobID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to stop job: %w", err)
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("job stop failed: %s", string(body))
	}

	return nil
}
