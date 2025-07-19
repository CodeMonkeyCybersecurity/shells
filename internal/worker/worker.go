package worker

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type worker struct {
	id        string
	hostname  string
	queue     core.JobQueue
	plugins   core.PluginManager
	store     core.ResultStore
	telemetry core.Telemetry
	logger    *logger.Logger

	status   types.WorkerStatus
	statusMu sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

func NewWorker(
	queue core.JobQueue,
	plugins core.PluginManager,
	store core.ResultStore,
	telemetry core.Telemetry,
	logger *logger.Logger,
) core.Worker {
	start := time.Now()
	workerID := uuid.New().String()
	
	ctx := context.Background()
	ctx, span := logger.StartOperation(ctx, "worker.NewWorker",
		"worker_id", workerID,
	)
	defer func() {
		logger.FinishOperation(ctx, span, "worker.NewWorker", start, nil)
	}()

	hostname := "unknown"
	if h, err := getHostname(); err == nil {
		hostname = h
		logger.WithContext(ctx).Debugw("Worker hostname resolved",
			"worker_id", workerID,
			"hostname", hostname,
		)
	} else {
		logger.LogError(ctx, err, "worker.NewWorker.getHostname",
			"worker_id", workerID,
			"fallback_hostname", hostname,
		)
	}

	// Initialize worker logger with proper component tagging
	workerLogger := logger.WithComponent("worker").WithFields(
		"worker_id", workerID,
		"hostname", hostname,
	)

	worker := &worker{
		id:        workerID,
		hostname:  hostname,
		queue:     queue,
		plugins:   plugins,
		store:     store,
		telemetry: telemetry,
		logger:    workerLogger,
		done:      make(chan struct{}),
		status: types.WorkerStatus{
			Status: "idle",
		},
	}

	workerLogger.WithContext(ctx).Infow("Worker instance created",
		"worker_id", workerID,
		"hostname", hostname,
		"creation_duration_ms", time.Since(start).Milliseconds(),
		"queue_type", fmt.Sprintf("%T", queue),
		"plugin_manager_type", fmt.Sprintf("%T", plugins),
		"store_type", fmt.Sprintf("%T", store),
	)

	return worker
}

func (w *worker) ID() string {
	return w.id
}

func (w *worker) Start(ctx context.Context) error {
	start := time.Now()
	ctx, span := w.logger.StartOperation(ctx, "worker.Start",
		"worker_id", w.id,
		"hostname", w.hostname,
	)
	defer func() {
		w.logger.FinishOperation(ctx, span, "worker.Start", start, nil)
	}()

	w.logger.WithContext(ctx).Infow("Starting worker",
		"worker_id", w.id,
		"hostname", w.hostname,
		"parent_context_deadline", getContextDeadline(ctx),
	)

	w.ctx, w.cancel = context.WithCancel(ctx)

	w.updateStatus("active", "")
	w.logger.WithContext(ctx).Infow("Worker started successfully", 
		"worker_id", w.id,
		"hostname", w.hostname,
		"startup_duration_ms", time.Since(start).Milliseconds(),
	)

	// Start worker loop in background with proper error handling
	go func() {
		defer func() {
			if r := recover(); r != nil {
				w.logger.LogPanic(w.ctx, r, "worker.run",
					"worker_id", w.id,
					"hostname", w.hostname,
				)
			}
		}()
		w.run()
	}()

	return nil
}

func (w *worker) Stop() error {
	start := time.Now()
	ctx := context.Background()
	ctx, span := w.logger.StartOperation(ctx, "worker.Stop",
		"worker_id", w.id,
		"hostname", w.hostname,
	)
	defer func() {
		w.logger.FinishOperation(ctx, span, "worker.Stop", start, nil)
	}()

	w.logger.WithContext(ctx).Infow("Stopping worker", 
		"worker_id", w.id,
		"hostname", w.hostname,
		"current_status", w.status.Status,
		"jobs_completed", w.status.JobsComplete,
	)

	// Cancel worker context to signal shutdown
	if w.cancel != nil {
		w.cancel()
	}

	// Wait for graceful shutdown with timeout
	stopTimeout := 30 * time.Second
	shutdownStart := time.Now()
	
	select {
	case <-w.done:
		shutdownDuration := time.Since(shutdownStart)
		w.logger.WithContext(ctx).Infow("Worker stopped gracefully", 
			"worker_id", w.id,
			"hostname", w.hostname,
			"shutdown_duration_ms", shutdownDuration.Milliseconds(),
			"total_jobs_completed", w.status.JobsComplete,
		)
	case <-time.After(stopTimeout):
		shutdownDuration := time.Since(shutdownStart)
		w.logger.WithContext(ctx).Warnw("Worker stop timeout - forcing shutdown", 
			"worker_id", w.id,
			"hostname", w.hostname,
			"timeout_ms", stopTimeout.Milliseconds(),
			"shutdown_duration_ms", shutdownDuration.Milliseconds(),
			"jobs_completed", w.status.JobsComplete,
		)
		
		if span := trace.SpanFromContext(ctx); span.IsRecording() {
			span.AddEvent("worker_stop_timeout", trace.WithAttributes(
				attribute.String("worker_id", w.id),
				attribute.Int64("timeout_ms", stopTimeout.Milliseconds()),
			))
		}
	}

	w.updateStatus("stopped", "")
	
	w.logger.WithContext(ctx).Infow("Worker stop completed",
		"worker_id", w.id,
		"total_stop_duration_ms", time.Since(start).Milliseconds(),
		"final_status", "stopped",
	)
	
	return nil
}

func (w *worker) Status() *types.WorkerStatus {
	w.statusMu.RLock()
	defer w.statusMu.RUnlock()

	status := w.status
	status.ID = w.id
	status.Hostname = w.hostname
	status.LastPing = time.Now()

	return &status
}

func (w *worker) run() {
	start := time.Now()
	ctx, span := w.logger.StartOperation(w.ctx, "worker.run",
		"worker_id", w.id,
		"hostname", w.hostname,
	)
	defer func() {
		w.logger.FinishOperation(ctx, span, "worker.run", start, nil)
		close(w.done)
	}()

	w.logger.WithContext(ctx).Infow("Worker main loop started",
		"worker_id", w.id,
		"hostname", w.hostname,
	)

	// Metrics ticker for periodic telemetry updates
	metricsInterval := 5 * time.Second
	ticker := time.NewTicker(metricsInterval)
	defer ticker.Stop()

	// Job processing metrics
	jobsProcessed := 0
	errorCount := 0
	lastMetricsTime := time.Now()

	for {
		select {
		case <-w.ctx.Done():
			w.logger.WithContext(ctx).Infow("Worker shutting down - context cancelled",
				"worker_id", w.id,
				"total_jobs_processed", jobsProcessed,
				"total_errors", errorCount,
				"uptime_ms", time.Since(start).Milliseconds(),
				"shutdown_reason", "context_cancelled",
			)
			return
			
		case <-ticker.C:
			// Record periodic metrics and log worker health
			metricsStart := time.Now()
			status := w.Status()
			w.telemetry.RecordWorkerMetrics(status)
			
			// Calculate throughput since last metrics update
			timeSinceLastMetrics := time.Since(lastMetricsTime)
			jobThroughput := float64(jobsProcessed) / timeSinceLastMetrics.Minutes()
			
			w.logger.WithContext(ctx).Debugw("Worker metrics update",
				"worker_id", w.id,
				"status", status.Status,
				"jobs_complete", status.JobsComplete,
				"current_job", status.CurrentJob,
				"jobs_per_minute", jobThroughput,
				"error_count", errorCount,
				"uptime_ms", time.Since(start).Milliseconds(),
				"metrics_duration_ms", time.Since(metricsStart).Milliseconds(),
			)
			
			// Reset counters for next interval
			jobsProcessed = 0
			errorCount = 0
			lastMetricsTime = time.Now()
			
		default:
			// Process next job from queue
			jobStart := time.Now()
			err := w.processJob()
			jobDuration := time.Since(jobStart)
			
			if err != nil {
				errorCount++
				w.logger.LogError(ctx, err, "worker.processJob",
					"worker_id", w.id,
					"job_duration_ms", jobDuration.Milliseconds(),
					"total_errors", errorCount,
				)
				
				// Backoff on errors to prevent resource exhaustion
				errorBackoff := 5 * time.Second
				w.logger.WithContext(ctx).Debugw("Error backoff initiated",
					"worker_id", w.id,
					"backoff_duration_ms", errorBackoff.Milliseconds(),
					"error_count", errorCount,
				)
				time.Sleep(errorBackoff)
			} else {
				jobsProcessed++
				
				// Log slow job processing
				slowJobThreshold := 30 * time.Second
				w.logger.LogSlowOperation(ctx, "worker.processJob", jobDuration, slowJobThreshold,
					"worker_id", w.id,
					"jobs_processed", jobsProcessed,
				)
			}
		}
	}
}

func (w *worker) processJob() error {
	start := time.Now()
	ctx, span := w.logger.StartOperation(w.ctx, "worker.processJob",
		"worker_id", w.id,
		"hostname", w.hostname,
	)
	defer func() {
		w.logger.FinishOperation(ctx, span, "worker.processJob", start, nil)
	}()

	// Pop job from queue with detailed logging
	popStart := time.Now()
	job, err := w.queue.Pop(w.ctx, w.id)
	popDuration := time.Since(popStart)
	
	if err != nil {
		w.logger.LogError(ctx, err, "worker.processJob.pop",
			"worker_id", w.id,
			"pop_duration_ms", popDuration.Milliseconds(),
		)
		return fmt.Errorf("failed to pop job: %w", err)
	}

	w.logger.LogDuration(ctx, "worker.queue.pop", popStart,
		"worker_id", w.id,
		"job_available", job != nil,
	)

	// No job available - normal condition
	if job == nil {
		w.logger.WithContext(ctx).Debugw("No jobs available in queue",
			"worker_id", w.id,
			"poll_duration_ms", popDuration.Milliseconds(),
		)
		time.Sleep(1 * time.Second)
		return nil
	}

	// Job acquired - start processing
	w.updateStatus("processing", job.ID)
	
	jobCtx, jobSpan := w.logger.StartSpanWithAttributes(ctx, 
		fmt.Sprintf("worker.processJob.%s", job.Type),
		[]attribute.KeyValue{
			attribute.String("job_id", job.ID),
			attribute.String("job_type", job.Type),
			attribute.String("worker_id", w.id),
			attribute.Int("job_retries", job.Retries),
		},
	)
	defer jobSpan.End()

	w.logger.WithContext(jobCtx).Infow("Processing job", 
		"job_id", job.ID, 
		"job_type", job.Type,
		"worker_id", w.id,
		"job_retries", job.Retries,
		"queue_pop_duration_ms", popDuration.Milliseconds(),
	)

	// Extract job details for logging
	target := "unknown"
	if payload, ok := job.Payload["scan_request"].(map[string]interface{}); ok {
		if t, ok := payload["target"].(string); ok {
			target = t
		}
	}

	w.logger.WithContext(jobCtx).Debugw("Job details extracted",
		"job_id", job.ID,
		"target", target,
		"payload_size", len(job.Payload),
	)

	startTime := time.Now()
	executionErr := w.executeJob(job)
	executionDuration := time.Since(startTime)

	if executionErr != nil {
		w.logger.LogError(jobCtx, executionErr, "worker.executeJob",
			"job_id", job.ID,
			"job_type", job.Type,
			"target", target,
			"execution_duration_ms", executionDuration.Milliseconds(),
			"retry_count", job.Retries,
		)
		
		jobSpan.RecordError(executionErr)
		jobSpan.SetStatus(codes.Error, executionErr.Error())

		// Handle job retry or failure
		if job.Retries < 3 {
			retryStart := time.Now()
			if retryErr := w.queue.Retry(w.ctx, job.ID); retryErr != nil {
				w.logger.LogError(jobCtx, retryErr, "worker.queue.retry",
					"job_id", job.ID,
					"retry_attempt", job.Retries + 1,
					"retry_duration_ms", time.Since(retryStart).Milliseconds(),
				)
			} else {
				w.logger.WithContext(jobCtx).Infow("Job scheduled for retry",
					"job_id", job.ID,
					"retry_attempt", job.Retries + 1,
					"max_retries", 3,
					"retry_duration_ms", time.Since(retryStart).Milliseconds(),
				)
			}
		} else {
			failStart := time.Now()
			if failErr := w.queue.Fail(w.ctx, job.ID, executionErr.Error()); failErr != nil {
				w.logger.LogError(jobCtx, failErr, "worker.queue.fail",
					"job_id", job.ID,
					"original_error", executionErr.Error(),
					"fail_duration_ms", time.Since(failStart).Milliseconds(),
				)
			} else {
				w.logger.WithContext(jobCtx).Warnw("Job marked as failed after max retries",
					"job_id", job.ID,
					"max_retries", 3,
					"original_error", executionErr.Error(),
					"fail_duration_ms", time.Since(failStart).Milliseconds(),
				)
			}
		}

		w.telemetry.RecordScan(types.ScanType(job.Type), executionDuration.Seconds(), false)
		w.updateStatus("idle", "")
		return nil
	}

	// Job executed successfully - mark as complete
	jobSpan.SetStatus(codes.Ok, "completed")
	completeStart := time.Now()
	if completeErr := w.queue.Complete(w.ctx, job.ID); completeErr != nil {
		w.logger.LogError(jobCtx, completeErr, "worker.queue.complete",
			"job_id", job.ID,
			"execution_duration_ms", executionDuration.Milliseconds(),
			"complete_duration_ms", time.Since(completeStart).Milliseconds(),
		)
	} else {
		w.logger.WithContext(jobCtx).Infow("Job completed successfully",
			"job_id", job.ID,
			"job_type", job.Type,
			"target", target,
			"execution_duration_ms", executionDuration.Milliseconds(),
			"complete_duration_ms", time.Since(completeStart).Milliseconds(),
			"total_duration_ms", time.Since(start).Milliseconds(),
		)
	}

	w.incrementJobsComplete()
	w.telemetry.RecordScan(types.ScanType(job.Type), executionDuration.Seconds(), true)
	w.updateStatus("idle", "")

	return nil
}

func (w *worker) executeJob(job *types.Job) error {
	start := time.Now()
	ctx, span := w.logger.StartOperation(w.ctx, "worker.executeJob",
		"job_id", job.ID,
		"job_type", job.Type,
		"worker_id", w.id,
	)
	var err error
	defer func() {
		w.logger.FinishOperation(ctx, span, "worker.executeJob", start, err)
	}()

	// Parse and validate job payload
	parseStart := time.Now()
	scanRequest, ok := job.Payload["scan_request"].(map[string]interface{})
	if !ok {
		err = fmt.Errorf("invalid job payload: missing scan_request")
		w.logger.LogError(ctx, err, "worker.executeJob.parse",
			"job_id", job.ID,
			"payload_keys", getMapKeys(job.Payload),
			"parse_duration_ms", time.Since(parseStart).Milliseconds(),
		)
		return err
	}

	target, ok := scanRequest["target"].(string)
	if !ok {
		err = fmt.Errorf("invalid job payload: missing target")
		w.logger.LogError(ctx, err, "worker.executeJob.target",
			"job_id", job.ID,
			"scan_request_keys", getMapKeys(scanRequest),
		)
		return err
	}

	scanType, ok := scanRequest["type"].(string)
	if !ok {
		err = fmt.Errorf("invalid job payload: missing scan type")
		w.logger.LogError(ctx, err, "worker.executeJob.scanType",
			"job_id", job.ID,
			"target", target,
		)
		return err
	}

	w.logger.LogDuration(ctx, "worker.executeJob.parse", parseStart,
		"job_id", job.ID,
		"target", target,
		"scan_type", scanType,
	)

	// Get scanner plugin
	pluginStart := time.Now()
	scanner, err := w.plugins.Get(scanType)
	if err != nil {
		w.logger.LogError(ctx, err, "worker.executeJob.getPlugin",
			"job_id", job.ID,
			"scan_type", scanType,
			"target", target,
			"plugin_duration_ms", time.Since(pluginStart).Milliseconds(),
		)
		err = fmt.Errorf("scanner not found: %w", err)
		return err
	}

	w.logger.LogDuration(ctx, "worker.executeJob.getPlugin", pluginStart,
		"job_id", job.ID,
		"scan_type", scanType,
		"plugin_type", fmt.Sprintf("%T", scanner),
	)

	// Validate target
	validateStart := time.Now()
	if err = scanner.Validate(target); err != nil {
		w.logger.LogError(ctx, err, "worker.executeJob.validate",
			"job_id", job.ID,
			"scan_type", scanType,
			"target", target,
			"validation_duration_ms", time.Since(validateStart).Milliseconds(),
		)
		err = fmt.Errorf("target validation failed: %w", err)
		return err
	}

	w.logger.LogDuration(ctx, "worker.executeJob.validate", validateStart,
		"job_id", job.ID,
		"target", target,
		"validation_success", true,
	)

	// Parse scan options
	optionsStart := time.Now()
	options := make(map[string]string)
	if opts, ok := scanRequest["options"].(map[string]interface{}); ok {
		for k, v := range opts {
			options[k] = fmt.Sprintf("%v", v)
		}
		w.logger.WithContext(ctx).Debugw("Scan options parsed",
			"job_id", job.ID,
			"options_count", len(options),
			"options_keys", getMapKeys(opts),
			"parse_duration_ms", time.Since(optionsStart).Milliseconds(),
		)
	}

	// Create scan context with timeout
	scanTimeout := 30 * time.Minute
	scanCtx, cancel := context.WithTimeout(w.ctx, scanTimeout)
	defer cancel()

	w.logger.WithContext(ctx).Infow("Starting scan execution",
		"job_id", job.ID,
		"scan_type", scanType,
		"target", target,
		"options_count", len(options),
		"timeout", scanTimeout,
		"worker_id", w.id,
	)

	// Execute scan
	scanStart := time.Now()
	findings, err := scanner.Scan(scanCtx, target, options)
	scanDuration := time.Since(scanStart)
	
	if err != nil {
		w.logger.LogError(ctx, err, "worker.executeJob.scan",
			"job_id", job.ID,
			"scan_type", scanType,
			"target", target,
			"scan_duration_ms", scanDuration.Milliseconds(),
			"timeout_ms", scanTimeout.Milliseconds(),
		)
		err = fmt.Errorf("scan failed: %w", err)
		return err
	}

	w.logger.LogDuration(ctx, "worker.executeJob.scan", scanStart,
		"job_id", job.ID,
		"scan_type", scanType,
		"target", target,
		"findings_count", len(findings),
		"scan_success", true,
	)

	// Process scan results
	processStart := time.Now()
	scanID, ok := scanRequest["id"].(string)
	if !ok {
		scanID = uuid.New().String()
		w.logger.WithContext(ctx).Debugw("Generated new scan ID",
			"job_id", job.ID,
			"scan_id", scanID,
		)
	}

	// Process and enrich findings
	severityCounts := make(map[types.Severity]int)
	for i := range findings {
		findings[i].ScanID = scanID
		if findings[i].ID == "" {
			findings[i].ID = uuid.New().String()
		}
		findings[i].CreatedAt = time.Now()
		findings[i].UpdatedAt = findings[i].CreatedAt

		// Count findings by severity
		severityCounts[findings[i].Severity]++
		
		// Record finding in telemetry
		w.telemetry.RecordFinding(findings[i].Severity)
		
		// Log high-severity findings
		if findings[i].Severity == types.SeverityCritical || findings[i].Severity == types.SeverityHigh {
			w.logger.LogVulnerability(ctx, map[string]interface{}{
				"finding_id": findings[i].ID,
				"scan_id": scanID,
				"job_id": job.ID,
				"severity": string(findings[i].Severity),
				"title": findings[i].Title,
				"tool": findings[i].Tool,
				"target": target,
			})
		}
	}

	w.logger.WithContext(ctx).Infow("Findings processed",
		"job_id", job.ID,
		"scan_id", scanID,
		"total_findings", len(findings),
		"severity_breakdown", severityCounts,
		"process_duration_ms", time.Since(processStart).Milliseconds(),
	)

	// Save findings to store
	storeStart := time.Now()
	if err = w.store.SaveFindings(scanCtx, findings); err != nil {
		w.logger.LogError(ctx, err, "worker.executeJob.saveFindings",
			"job_id", job.ID,
			"scan_id", scanID,
			"findings_count", len(findings),
			"store_duration_ms", time.Since(storeStart).Milliseconds(),
		)
		err = fmt.Errorf("failed to save findings: %w", err)
		return err
	}

	w.logger.LogDuration(ctx, "worker.executeJob.saveFindings", storeStart,
		"job_id", job.ID,
		"scan_id", scanID,
		"findings_saved", len(findings),
		"store_success", true,
	)

	w.logger.WithContext(ctx).Infow("Job execution completed successfully",
		"job_id", job.ID,
		"scan_id", scanID,
		"scan_type", scanType,
		"target", target,
		"findings_count", len(findings),
		"severity_breakdown", severityCounts,
		"total_execution_duration_ms", time.Since(start).Milliseconds(),
		"scan_duration_ms", scanDuration.Milliseconds(),
		"worker_id", w.id,
	)

	return nil
}

func (w *worker) updateStatus(status, currentJob string) {
	w.statusMu.Lock()
	defer w.statusMu.Unlock()

	w.status.Status = status
	w.status.CurrentJob = currentJob
	w.status.LastPing = time.Now()
}

func (w *worker) incrementJobsComplete() {
	w.statusMu.Lock()
	defer w.statusMu.Unlock()

	w.status.JobsComplete++
}

func getHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "localhost", fmt.Errorf("failed to get hostname: %w", err)
	}
	return hostname, nil
}

// Helper functions for enhanced logging

func getContextDeadline(ctx context.Context) interface{} {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline.Format(time.RFC3339)
	}
	return "no deadline"
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
