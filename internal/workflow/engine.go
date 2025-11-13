package workflow

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/core"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
	"golang.org/x/sync/errgroup"
)

type WorkflowEngine struct {
	plugins   core.PluginManager
	store     core.ResultStore
	queue     core.JobQueue
	telemetry core.Telemetry
	logger    *logger.Logger
}

type Workflow struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Steps       []WorkflowStep  `json:"steps"`
	Options     WorkflowOptions `json:"options"`
}

type WorkflowStep struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Scanner    string              `json:"scanner"`
	Options    map[string]string   `json:"options"`
	DependsOn  []string            `json:"depends_on"`
	Conditions []WorkflowCondition `json:"conditions"`
	Parallel   bool                `json:"parallel"`
	ContinueOn string              `json:"continue_on"` // "success", "failure", "always"
	Timeout    time.Duration       `json:"timeout"`
}

type WorkflowCondition struct {
	Type     string      `json:"type"`     // "finding_count", "severity", "scanner_success"
	Operator string      `json:"operator"` // "gt", "lt", "eq", "contains"
	Value    interface{} `json:"value"`
}

type WorkflowOptions struct {
	MaxConcurrency int           `json:"max_concurrency"`
	Timeout        time.Duration `json:"timeout"`
	OnFailure      string        `json:"on_failure"` // "continue", "stop"
	RetryCount     int           `json:"retry_count"`
}

type WorkflowResult struct {
	WorkflowID    string          `json:"workflow_id"`
	Target        string          `json:"target"`
	Status        string          `json:"status"`
	StartTime     time.Time       `json:"start_time"`
	EndTime       time.Time       `json:"end_time"`
	Duration      time.Duration   `json:"duration"`
	StepResults   []StepResult    `json:"step_results"`
	TotalFindings int             `json:"total_findings"`
	Findings      []types.Finding `json:"findings"`
}

type StepResult struct {
	StepID    string          `json:"step_id"`
	Scanner   string          `json:"scanner"`
	Status    string          `json:"status"`
	StartTime time.Time       `json:"start_time"`
	EndTime   time.Time       `json:"end_time"`
	Duration  time.Duration   `json:"duration"`
	Findings  []types.Finding `json:"findings"`
	ErrorMsg  string          `json:"error_msg,omitempty"`
}

func NewWorkflowEngine(
	plugins core.PluginManager,
	store core.ResultStore,
	queue core.JobQueue,
	telemetry core.Telemetry,
	logger *logger.Logger,
) *WorkflowEngine {
	return &WorkflowEngine{
		plugins:   plugins,
		store:     store,
		queue:     queue,
		telemetry: telemetry,
		logger:    logger,
	}
}

func (e *WorkflowEngine) ExecuteWorkflow(ctx context.Context, workflow *Workflow, target string) (*WorkflowResult, error) {
	e.logger.Infow("Starting workflow execution", "workflow", workflow.Name, "target", target)

	result := &WorkflowResult{
		WorkflowID:  workflow.ID,
		Target:      target,
		Status:      "running",
		StartTime:   time.Now(),
		StepResults: make([]StepResult, 0),
		Findings:    make([]types.Finding, 0),
	}

	// Create execution context with timeout
	execCtx := ctx
	if workflow.Options.Timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, workflow.Options.Timeout)
		defer cancel()
	}

	// Build dependency graph
	depGraph, err := e.buildDependencyGraph(workflow.Steps)
	if err != nil {
		return nil, fmt.Errorf("failed to build dependency graph: %w", err)
	}

	// Execute steps according to dependency order
	if err := e.executeSteps(execCtx, depGraph, workflow.Options, target, result); err != nil {
		result.Status = "failed"
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result, err
	}

	result.Status = "completed"
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.TotalFindings = len(result.Findings)

	e.logger.Info("Workflow execution completed",
		"workflow", workflow.Name,
		"target", target,
		"duration", result.Duration,
		"findings", result.TotalFindings,
	)

	return result, nil
}

func (e *WorkflowEngine) buildDependencyGraph(steps []WorkflowStep) ([][]WorkflowStep, error) {
	// Create a map for quick lookup
	stepMap := make(map[string]WorkflowStep)
	for _, step := range steps {
		stepMap[step.ID] = step
	}

	// Validate dependencies
	for _, step := range steps {
		for _, dep := range step.DependsOn {
			if _, exists := stepMap[dep]; !exists {
				return nil, fmt.Errorf("step %s depends on non-existent step %s", step.ID, dep)
			}
		}
	}

	// Build execution levels (topological sort)
	var levels [][]WorkflowStep
	executed := make(map[string]bool)
	remaining := make(map[string]WorkflowStep)

	for id, step := range stepMap {
		remaining[id] = step
	}

	for len(remaining) > 0 {
		var currentLevel []WorkflowStep

		// Find steps with no unexecuted dependencies
		for _, step := range remaining {
			canExecute := true
			for _, dep := range step.DependsOn {
				if !executed[dep] {
					canExecute = false
					break
				}
			}

			if canExecute {
				currentLevel = append(currentLevel, step)
			}
		}

		if len(currentLevel) == 0 {
			// Circular dependency detected
			var remainingSteps []string
			for id := range remaining {
				remainingSteps = append(remainingSteps, id)
			}
			return nil, fmt.Errorf("circular dependency detected among steps: %v", remainingSteps)
		}

		// Mark these steps as executed and remove from remaining
		for _, step := range currentLevel {
			executed[step.ID] = true
			delete(remaining, step.ID)
		}

		levels = append(levels, currentLevel)
	}

	return levels, nil
}

func (e *WorkflowEngine) executeSteps(ctx context.Context, levels [][]WorkflowStep, options WorkflowOptions, target string, result *WorkflowResult) error {
	for levelIndex, level := range levels {
		e.logger.Debug("Executing workflow level", "level", levelIndex, "steps", len(level))

		// Separate parallel and sequential steps
		var parallelSteps []WorkflowStep
		var sequentialSteps []WorkflowStep

		for _, step := range level {
			if step.Parallel {
				parallelSteps = append(parallelSteps, step)
			} else {
				sequentialSteps = append(sequentialSteps, step)
			}
		}

		// Execute parallel steps
		if len(parallelSteps) > 0 {
			if err := e.executeParallelSteps(ctx, parallelSteps, options, target, result); err != nil {
				if options.OnFailure == "stop" {
					return err
				}
				e.logger.Error("Parallel steps failed but continuing", "error", err)
			}
		}

		// Execute sequential steps
		for _, step := range sequentialSteps {
			if err := e.executeStep(ctx, step, target, result); err != nil {
				if options.OnFailure == "stop" || step.ContinueOn == "success" {
					return err
				}
				e.logger.Error("Step failed but continuing", "step", step.ID, "error", err)
			}
		}
	}

	return nil
}

func (e *WorkflowEngine) executeParallelSteps(ctx context.Context, steps []WorkflowStep, options WorkflowOptions, target string, result *WorkflowResult) error {
	maxConcurrency := options.MaxConcurrency
	if maxConcurrency <= 0 {
		maxConcurrency = len(steps)
	}

	// Create a semaphore to limit concurrency
	semaphore := make(chan struct{}, maxConcurrency)

	g, gCtx := errgroup.WithContext(ctx)

	// Mutex to protect result updates
	var mu sync.Mutex

	for _, step := range steps {
		step := step // Capture loop variable

		g.Go(func() error {
			// Acquire semaphore
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-gCtx.Done():
				return gCtx.Err()
			}

			err := e.executeStep(gCtx, step, target, result)

			// Update result with proper locking
			mu.Lock()
			defer mu.Unlock()

			if err != nil && step.ContinueOn == "success" {
				return err
			}

			return nil
		})
	}

	return g.Wait()
}

func (e *WorkflowEngine) executeStep(ctx context.Context, step WorkflowStep, target string, result *WorkflowResult) error {
	e.logger.Infow("Executing workflow step", "step", step.ID, "scanner", step.Scanner)

	stepResult := StepResult{
		StepID:    step.ID,
		Scanner:   step.Scanner,
		Status:    "running",
		StartTime: time.Now(),
	}

	// Check conditions
	if !e.evaluateConditions(step.Conditions, result) {
		stepResult.Status = "skipped"
		stepResult.EndTime = time.Now()
		stepResult.Duration = stepResult.EndTime.Sub(stepResult.StartTime)
		result.StepResults = append(result.StepResults, stepResult)
		return nil
	}

	// Get scanner
	scanner, err := e.plugins.Get(step.Scanner)
	if err != nil {
		stepResult.Status = "failed"
		stepResult.ErrorMsg = err.Error()
		stepResult.EndTime = time.Now()
		stepResult.Duration = stepResult.EndTime.Sub(stepResult.StartTime)
		result.StepResults = append(result.StepResults, stepResult)
		return fmt.Errorf("scanner %s not found: %w", step.Scanner, err)
	}

	// Create step context with timeout
	stepCtx := ctx
	if step.Timeout > 0 {
		var cancel context.CancelFunc
		stepCtx, cancel = context.WithTimeout(ctx, step.Timeout)
		defer cancel()
	}

	// Execute scanner
	startTime := time.Now()
	findings, err := scanner.Scan(stepCtx, target, step.Options)
	duration := time.Since(startTime)

	// Record telemetry
	e.telemetry.RecordScan(scanner.Type(), duration.Seconds(), err == nil)

	if err != nil {
		stepResult.Status = "failed"
		stepResult.ErrorMsg = err.Error()
		stepResult.EndTime = time.Now()
		stepResult.Duration = stepResult.EndTime.Sub(stepResult.StartTime)
		result.StepResults = append(result.StepResults, stepResult)

		if step.ContinueOn != "failure" && step.ContinueOn != "always" {
			return fmt.Errorf("step %s failed: %w", step.ID, err)
		}

		return nil
	}

	// Record findings telemetry
	for _, finding := range findings {
		e.telemetry.RecordFinding(finding.Severity)
	}

	stepResult.Status = "completed"
	stepResult.EndTime = time.Now()
	stepResult.Duration = stepResult.EndTime.Sub(stepResult.StartTime)
	stepResult.Findings = findings

	result.StepResults = append(result.StepResults, stepResult)
	result.Findings = append(result.Findings, findings...)

	e.logger.Info("Step completed",
		"step", step.ID,
		"scanner", step.Scanner,
		"findings", len(findings),
		"duration", stepResult.Duration,
	)

	return nil
}

func (e *WorkflowEngine) evaluateConditions(conditions []WorkflowCondition, result *WorkflowResult) bool {
	if len(conditions) == 0 {
		return true
	}

	for _, condition := range conditions {
		if !e.evaluateCondition(condition, result) {
			return false
		}
	}

	return true
}

func (e *WorkflowEngine) evaluateCondition(condition WorkflowCondition, result *WorkflowResult) bool {
	switch condition.Type {
	case "finding_count":
		return e.compareInt(len(result.Findings), condition.Operator, condition.Value)

	case "severity":
		severityValue := condition.Value.(string)
		for _, finding := range result.Findings {
			if string(finding.Severity) == severityValue {
				return true
			}
		}
		return false

	case "scanner_success":
		scannerName := condition.Value.(string)
		for _, stepResult := range result.StepResults {
			if stepResult.Scanner == scannerName {
				return stepResult.Status == "completed"
			}
		}
		return false

	case "scanner_findings":
		scannerName := condition.Value.(string)
		for _, stepResult := range result.StepResults {
			if stepResult.Scanner == scannerName {
				return len(stepResult.Findings) > 0
			}
		}
		return false

	default:
		e.logger.Warn("Unknown condition type", "type", condition.Type)
		return true
	}
}

func (e *WorkflowEngine) compareInt(actual int, operator string, expectedValue interface{}) bool {
	expected, ok := expectedValue.(int)
	if !ok {
		if f, ok := expectedValue.(float64); ok {
			expected = int(f)
		} else {
			return false
		}
	}

	switch operator {
	case "gt":
		return actual > expected
	case "lt":
		return actual < expected
	case "eq":
		return actual == expected
	case "gte":
		return actual >= expected
	case "lte":
		return actual <= expected
	default:
		return false
	}
}

// Predefined workflows for common scenarios
func GetPredefinedWorkflows() map[string]*Workflow {
	return map[string]*Workflow{
		"comprehensive": {
			ID:          "comprehensive",
			Name:        "Comprehensive Security Scan",
			Description: "Full security assessment including recon, vulnerability scanning, and specialized tests",
			Steps: []WorkflowStep{
				{
					ID:       "recon",
					Name:     "HTTP Reconnaissance",
					Scanner:  "httpx",
					Parallel: false,
					Options: map[string]string{
						"follow_redirects": "true",
						"probe_all_ips":    "true",
					},
					ContinueOn: "always",
					Timeout:    5 * time.Minute,
				},
				{
					ID:       "port_scan",
					Name:     "Port Scanning",
					Scanner:  "nmap",
					Parallel: true,
					Options: map[string]string{
						"profile": "fast",
					},
					ContinueOn: "always",
					Timeout:    10 * time.Minute,
				},
				{
					ID:        "ssl_analysis",
					Name:      "SSL/TLS Analysis",
					Scanner:   "ssl",
					Parallel:  true,
					DependsOn: []string{"recon"},
					Conditions: []WorkflowCondition{
						{Type: "scanner_success", Operator: "eq", Value: "recon"},
					},
					ContinueOn: "always",
					Timeout:    5 * time.Minute,
				},
				{
					ID:        "nuclei_scan",
					Name:      "Nuclei Vulnerability Scan",
					Scanner:   "nuclei",
					Parallel:  false,
					DependsOn: []string{"recon"},
					Options: map[string]string{
						"severity": "critical,high,medium",
					},
					ContinueOn: "always",
					Timeout:    30 * time.Minute,
				},
				{
					ID:        "oauth2_test",
					Name:      "OAuth2 Security Testing",
					Scanner:   "oauth2",
					Parallel:  true,
					DependsOn: []string{"recon"},
					Conditions: []WorkflowCondition{
						{Type: "scanner_findings", Operator: "eq", Value: "httpx"},
					},
					ContinueOn: "always",
					Timeout:    15 * time.Minute,
				},
				{
					ID:         "js_analysis",
					Name:       "JavaScript Analysis",
					Scanner:    "javascript",
					Parallel:   true,
					DependsOn:  []string{"recon"},
					ContinueOn: "always",
					Timeout:    10 * time.Minute,
				},
			},
			Options: WorkflowOptions{
				MaxConcurrency: 3,
				Timeout:        2 * time.Hour,
				OnFailure:      "continue",
				RetryCount:     1,
			},
		},
		"oauth2_focused": {
			ID:          "oauth2_focused",
			Name:        "OAuth2/OIDC Focused Assessment",
			Description: "Specialized OAuth2 and authentication security testing",
			Steps: []WorkflowStep{
				{
					ID:      "http_probe",
					Name:    "HTTP Service Discovery",
					Scanner: "httpx",
					Options: map[string]string{
						"scan_type": "oauth2",
					},
					ContinueOn: "always",
					Timeout:    5 * time.Minute,
				},
				{
					ID:         "oauth2_scan",
					Name:       "OAuth2 Vulnerability Assessment",
					Scanner:    "oauth2",
					DependsOn:  []string{"http_probe"},
					ContinueOn: "always",
					Timeout:    20 * time.Minute,
				},
				{
					ID:        "nuclei_oauth",
					Name:      "Nuclei OAuth2 Templates",
					Scanner:   "nuclei",
					DependsOn: []string{"http_probe"},
					Options: map[string]string{
						"tags": "oauth,jwt,oidc,auth",
					},
					ContinueOn: "always",
					Timeout:    15 * time.Minute,
				},
				{
					ID:         "js_auth_analysis",
					Name:       "JavaScript Authentication Analysis",
					Scanner:    "javascript",
					DependsOn:  []string{"http_probe"},
					ContinueOn: "always",
					Timeout:    10 * time.Minute,
				},
			},
			Options: WorkflowOptions{
				MaxConcurrency: 2,
				Timeout:        1 * time.Hour,
				OnFailure:      "continue",
			},
		},
		"api_security": {
			ID:          "api_security",
			Name:        "API Security Assessment",
			Description: "Comprehensive API and GraphQL security testing",
			Steps: []WorkflowStep{
				{
					ID:      "api_discovery",
					Name:    "API Endpoint Discovery",
					Scanner: "httpx",
					Options: map[string]string{
						"scan_type": "api",
					},
					ContinueOn: "always",
					Timeout:    5 * time.Minute,
				},
				{
					ID:        "graphql_test",
					Name:      "GraphQL Security Testing",
					Scanner:   "graphql",
					DependsOn: []string{"api_discovery"},
					Conditions: []WorkflowCondition{
						{Type: "scanner_findings", Operator: "eq", Value: "httpx"},
					},
					ContinueOn: "always",
					Timeout:    20 * time.Minute,
				},
				{
					ID:        "nuclei_api",
					Name:      "Nuclei API Templates",
					Scanner:   "nuclei",
					DependsOn: []string{"api_discovery"},
					Options: map[string]string{
						"tags": "api,graphql,rest,swagger",
					},
					ContinueOn: "always",
					Timeout:    15 * time.Minute,
				},
			},
			Options: WorkflowOptions{
				MaxConcurrency: 2,
				Timeout:        45 * time.Minute,
				OnFailure:      "continue",
			},
		},
	}
}
