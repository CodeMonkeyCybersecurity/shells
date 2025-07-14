package worker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
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
	hostname := "unknown"
	if h, err := getHostname(); err == nil {
		hostname = h
	}

	return &worker{
		id:        uuid.New().String(),
		hostname:  hostname,
		queue:     queue,
		plugins:   plugins,
		store:     store,
		telemetry: telemetry,
		logger:    logger.WithFields("worker_id", uuid.New().String()),
		done:      make(chan struct{}),
		status: types.WorkerStatus{
			Status: "idle",
		},
	}
}

func (w *worker) ID() string {
	return w.id
}

func (w *worker) Start(ctx context.Context) error {
	w.ctx, w.cancel = context.WithCancel(ctx)

	w.updateStatus("active", "")
	w.logger.Info("Worker started", "id", w.id)

	go w.run()

	return nil
}

func (w *worker) Stop() error {
	w.logger.Info("Stopping worker", "id", w.id)

	w.cancel()

	select {
	case <-w.done:
		w.logger.Info("Worker stopped gracefully", "id", w.id)
	case <-time.After(30 * time.Second):
		w.logger.Warn("Worker stop timeout", "id", w.id)
	}

	w.updateStatus("stopped", "")
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
	defer close(w.done)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.telemetry.RecordWorkerMetrics(w.Status())
		default:
			if err := w.processJob(); err != nil {
				w.logger.Error("Failed to process job", "error", err)
				time.Sleep(5 * time.Second)
			}
		}
	}
}

func (w *worker) processJob() error {
	job, err := w.queue.Pop(w.ctx, w.id)
	if err != nil {
		return fmt.Errorf("failed to pop job: %w", err)
	}

	if job == nil {
		time.Sleep(1 * time.Second)
		return nil
	}

	w.updateStatus("processing", job.ID)
	w.logger.Info("Processing job", "job_id", job.ID, "type", job.Type)

	startTime := time.Now()

	if err := w.executeJob(job); err != nil {
		w.logger.Error("Job execution failed", "job_id", job.ID, "error", err)

		if job.Retries < 3 {
			if err := w.queue.Retry(w.ctx, job.ID); err != nil {
				w.logger.Error("Failed to retry job", "job_id", job.ID, "error", err)
			}
		} else {
			if err := w.queue.Fail(w.ctx, job.ID, err.Error()); err != nil {
				w.logger.Error("Failed to mark job as failed", "job_id", job.ID, "error", err)
			}
		}

		w.telemetry.RecordScan(types.ScanType(job.Type), time.Since(startTime).Seconds(), false)
		return nil
	}

	if err := w.queue.Complete(w.ctx, job.ID); err != nil {
		w.logger.Error("Failed to mark job as complete", "job_id", job.ID, "error", err)
	}

	w.incrementJobsComplete()
	w.telemetry.RecordScan(types.ScanType(job.Type), time.Since(startTime).Seconds(), true)

	return nil
}

func (w *worker) executeJob(job *types.Job) error {
	scanRequest, ok := job.Payload["scan_request"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid job payload: missing scan_request")
	}

	target, ok := scanRequest["target"].(string)
	if !ok {
		return fmt.Errorf("invalid job payload: missing target")
	}

	scanType, ok := scanRequest["type"].(string)
	if !ok {
		return fmt.Errorf("invalid job payload: missing scan type")
	}

	scanner, err := w.plugins.Get(scanType)
	if err != nil {
		return fmt.Errorf("scanner not found: %w", err)
	}

	if err := scanner.Validate(target); err != nil {
		return fmt.Errorf("target validation failed: %w", err)
	}

	options := make(map[string]string)
	if opts, ok := scanRequest["options"].(map[string]interface{}); ok {
		for k, v := range opts {
			options[k] = fmt.Sprintf("%v", v)
		}
	}

	ctx, cancel := context.WithTimeout(w.ctx, 30*time.Minute)
	defer cancel()

	findings, err := scanner.Scan(ctx, target, options)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	scanID, ok := scanRequest["id"].(string)
	if !ok {
		scanID = uuid.New().String()
	}

	for i := range findings {
		findings[i].ScanID = scanID
		if findings[i].ID == "" {
			findings[i].ID = uuid.New().String()
		}
		findings[i].CreatedAt = time.Now()
		findings[i].UpdatedAt = findings[i].CreatedAt

		w.telemetry.RecordFinding(findings[i].Severity)
	}

	if err := w.store.SaveFindings(ctx, findings); err != nil {
		return fmt.Errorf("failed to save findings: %w", err)
	}

	w.logger.Info("Job completed successfully",
		"job_id", job.ID,
		"findings", len(findings),
		"scan_id", scanID,
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
	return "localhost", nil
}
