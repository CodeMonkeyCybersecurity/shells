// pkg/workflow/airflow/client.go
package airflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"io"
	"net/http"
	"time"
)

// AirflowClient provides integration with Apache Airflow
type AirflowClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	config     AirflowConfig
}

// AirflowConfig holds Airflow configuration
type AirflowConfig struct {
	BaseURL     string
	APIKey      string
	Timeout     time.Duration
	MaxRetries  int
	RetryDelay  time.Duration
	WebserverID string
}

// DAG represents an Airflow DAG
type DAG struct {
	ID               string                 `json:"dag_id"`
	Description      string                 `json:"description"`
	IsPaused         bool                   `json:"is_paused"`
	IsActive         bool                   `json:"is_active"`
	FileToken        string                 `json:"file_token"`
	Owners           []string               `json:"owners"`
	Tags             []string               `json:"tags"`
	ScheduleInterval string                 `json:"schedule_interval"`
	DefaultArgs      map[string]interface{} `json:"default_args"`
}

// DAGRun represents an Airflow DAG run
type DAGRun struct {
	ID              string                 `json:"dag_run_id"`
	DAGID           string                 `json:"dag_id"`
	LogicalDate     time.Time              `json:"logical_date"`
	ExecutionDate   time.Time              `json:"execution_date"`
	StartDate       *time.Time             `json:"start_date"`
	EndDate         *time.Time             `json:"end_date"`
	State           string                 `json:"state"`
	ExternalTrigger bool                   `json:"external_trigger"`
	Conf            map[string]interface{} `json:"conf"`
}

// TaskInstance represents a task instance in a DAG run
type TaskInstance struct {
	TaskID         string     `json:"task_id"`
	DAGID          string     `json:"dag_id"`
	DAGRunID       string     `json:"dag_run_id"`
	ExecutionDate  time.Time  `json:"execution_date"`
	StartDate      *time.Time `json:"start_date"`
	EndDate        *time.Time `json:"end_date"`
	Duration       float64    `json:"duration"`
	State          string     `json:"state"`
	TryNumber      int        `json:"try_number"`
	MaxTries       int        `json:"max_tries"`
	Hostname       string     `json:"hostname"`
	Pool           string     `json:"pool"`
	Queue          string     `json:"queue"`
	PriorityWeight int        `json:"priority_weight"`
	Operator       string     `json:"operator"`
	QueuedWhen     *time.Time `json:"queued_when"`
	PID            *int       `json:"pid"`
	ExecutorConfig string     `json:"executor_config"`
}

// SecurityScanDAG represents a security scanning workflow DAG
type SecurityScanDAG struct {
	*DAG
	ScanConfig ScanConfiguration `json:"scan_config"`
}

// ScanConfiguration holds scanning workflow configuration
type ScanConfiguration struct {
	Target          string                 `json:"target"`
	ScanType        string                 `json:"scan_type"`
	Scanners        []string               `json:"scanners"`
	MaxConcurrency  int                    `json:"max_concurrency"`
	ConditionalFlow map[string]interface{} `json:"conditional_flow"`
	Notifications   NotificationConfig     `json:"notifications"`
}

// NotificationConfig holds notification settings
type NotificationConfig struct {
	OnSuccess []string                 `json:"on_success"`
	OnFailure []string                 `json:"on_failure"`
	OnRetry   []string                 `json:"on_retry"`
	Channels  map[string]ChannelConfig `json:"channels"`
}

// ChannelConfig holds channel-specific notification config
type ChannelConfig struct {
	Type     string            `json:"type"`
	Settings map[string]string `json:"settings"`
}

// NewAirflowClient creates a new Airflow client
func NewAirflowClient(config AirflowConfig) (*AirflowClient, error) {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 5 * time.Second
	}

	return &AirflowClient{
		baseURL: config.BaseURL,
		apiKey:  config.APIKey,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		config: config,
	}, nil
}

// CreateSecurityScanDAG creates a new security scanning DAG
func (c *AirflowClient) CreateSecurityScanDAG(ctx context.Context, scanConfig ScanConfiguration) (*SecurityScanDAG, error) {
	dagID := fmt.Sprintf("security_scan_%s_%d", sanitizeID(scanConfig.Target), time.Now().Unix())

	dag := &SecurityScanDAG{
		DAG: &DAG{
			ID:               dagID,
			Description:      fmt.Sprintf("Security scan workflow for %s", scanConfig.Target),
			Tags:             []string{"security", "bug-bounty", scanConfig.ScanType},
			ScheduleInterval: "None", // Manual trigger only
			DefaultArgs: map[string]interface{}{
				"owner":           "security-team",
				"depends_on_past": false,
				"retries":         1,
				"retry_delay":     "5m",
			},
		},
		ScanConfig: scanConfig,
	}

	// Generate DAG Python code
	dagCode := c.generateDAGCode(dag)

	// Deploy DAG to Airflow
	if err := c.deployDAG(ctx, dagID, dagCode); err != nil {
		return nil, fmt.Errorf("failed to deploy DAG: %w", err)
	}

	return dag, nil
}

// TriggerDAGRun triggers a DAG run
func (c *AirflowClient) TriggerDAGRun(ctx context.Context, dagID string, conf map[string]interface{}) (*DAGRun, error) {
	runID := fmt.Sprintf("manual__%s", time.Now().Format("2006-01-02T15:04:05"))

	payload := map[string]interface{}{
		"dag_run_id": runID,
		"conf":       conf,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/api/v1/dags/%s/dagRuns", c.baseURL, dagID),
		bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	c.setHeaders(req)

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var dagRun DAGRun
	if err := json.NewDecoder(resp.Body).Decode(&dagRun); err != nil {
		return nil, err
	}

	return &dagRun, nil
}

// GetDAGRunStatus gets the status of a DAG run
func (c *AirflowClient) GetDAGRunStatus(ctx context.Context, dagID, runID string) (*DAGRun, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/api/v1/dags/%s/dagRuns/%s", c.baseURL, dagID, runID), nil)
	if err != nil {
		return nil, err
	}

	c.setHeaders(req)

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var dagRun DAGRun
	if err := json.NewDecoder(resp.Body).Decode(&dagRun); err != nil {
		return nil, err
	}

	return &dagRun, nil
}

// GetTaskInstances gets task instances for a DAG run
func (c *AirflowClient) GetTaskInstances(ctx context.Context, dagID, runID string) ([]TaskInstance, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/api/v1/dags/%s/dagRuns/%s/taskInstances", c.baseURL, dagID, runID), nil)
	if err != nil {
		return nil, err
	}

	c.setHeaders(req)

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		TaskInstances []TaskInstance `json:"task_instances"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.TaskInstances, nil
}

// generateDAGCode generates Python DAG code for security scanning workflow
func (c *AirflowClient) generateDAGCode(dag *SecurityScanDAG) string {
	template := `
from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.operators.python import PythonOperator, BranchPythonOperator
from airflow.operators.trigger_dagrun import TriggerDagRunOperator
from airflow.utils.task_group import TaskGroup
from airflow.models import Variable
import json

default_args = %s

dag = DAG(
    '%s',
    default_args=default_args,
    description='%s',
    schedule_interval=%s,
    start_date=datetime(2024, 1, 1),
    catchup=False,
    tags=%s,
)

# Scan configuration
scan_config = %s

def trigger_scanner(**context):
    """Trigger individual scanner based on configuration"""
    scanner = context['task_instance'].task_id.replace('scan_', '')
    target = scan_config['target']
    
    # Execute scanner via shells CLI
    return f"shells scan {scanner} --target {target} --output json"

def evaluate_results(**context):
    """Evaluate scan results and determine next steps"""
    task_instance = context['task_instance']
    
    # Get results from all previous scanner tasks
    results = {}
    for scanner in scan_config['scanners']:
        scanner_task_id = f'scan_{scanner}'
        try:
            result = task_instance.xcom_pull(task_ids=scanner_task_id)
            results[scanner] = json.loads(result) if result else {}
        except:
            results[scanner] = {}
    
    # Apply conditional logic
    critical_findings = sum(1 for r in results.values() 
                          for f in r.get('findings', []) 
                          if f.get('severity') == 'critical')
    
    if critical_findings > 0:
        return 'escalate_findings'
    elif len(results) > 0:
        return 'generate_report'
    else:
        return 'mark_complete'

def escalate_findings(**context):
    """Escalate critical findings"""
    # Send notifications, create tickets, etc.
    pass

def generate_report(**context):
    """Generate comprehensive scan report"""
    # Aggregate all findings and create report
    pass

# Create scanner tasks
with TaskGroup("scanners", dag=dag) as scanner_group:
    scanner_tasks = []
    for scanner in scan_config['scanners']:
        task = BashOperator(
            task_id=f'scan_{scanner}',
            bash_command=f'shells scan {scanner} --target {scan_config["target"]} --output json',
            dag=dag,
        )
        scanner_tasks.append(task)

# Evaluation branching
evaluate_task = BranchPythonOperator(
    task_id='evaluate_results',
    python_callable=evaluate_results,
    dag=dag,
)

# Conditional tasks
escalate_task = PythonOperator(
    task_id='escalate_findings',
    python_callable=escalate_findings,
    dag=dag,
)

report_task = PythonOperator(
    task_id='generate_report',
    python_callable=generate_report,
    dag=dag,
)

complete_task = BashOperator(
    task_id='mark_complete',
    bash_command='echo "Scan completed with no critical findings"',
    dag=dag,
)

# Set up task dependencies
scanner_group >> evaluate_task
evaluate_task >> [escalate_task, report_task, complete_task]
`

	// Format the template with actual values
	defaultArgsJSON, _ := json.Marshal(dag.DefaultArgs)
	tagsJSON, _ := json.Marshal(dag.Tags)
	scanConfigJSON, _ := json.Marshal(dag.ScanConfig)

	return fmt.Sprintf(template,
		string(defaultArgsJSON),
		dag.ID,
		dag.Description,
		"None",
		string(tagsJSON),
		string(scanConfigJSON),
	)
}

// deployDAG deploys DAG code to Airflow
func (c *AirflowClient) deployDAG(ctx context.Context, dagID string, dagCode string) error {
	// In production, this would deploy to Airflow's DAG folder
	// via Git, S3, or direct file system access

	// For this example, we'll assume a deployment endpoint
	payload := map[string]string{
		"dag_id":   dagID,
		"dag_code": dagCode,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/api/experimental/dags/deploy", c.baseURL),
		bytes.NewReader(body))
	if err != nil {
		return err
	}

	c.setHeaders(req)

	resp, err := c.doWithRetry(req)
	if err != nil {
		return err
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("deployment failed: %s", string(body))
	}

	return nil
}

// setHeaders sets common headers for API requests
func (c *AirflowClient) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	}
}

// doWithRetry performs HTTP request with retry logic
func (c *AirflowClient) doWithRetry(req *http.Request) (*http.Response, error) {
	var lastErr error

	for i := 0; i < c.config.MaxRetries; i++ {
		resp, err := c.httpClient.Do(req)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}

		lastErr = err
		if resp != nil {
			httpclient.CloseBody(resp)
		}

		if i < c.config.MaxRetries-1 {
			time.Sleep(c.config.RetryDelay)
		}
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// Helper functions

func sanitizeID(s string) string {
	// Replace non-alphanumeric characters with underscores
	result := ""
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			result += string(r)
		} else {
			result += "_"
		}
	}
	return result
}
