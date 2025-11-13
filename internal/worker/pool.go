package worker

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/core"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

type workerPool struct {
	workers   []core.Worker
	queue     core.JobQueue
	plugins   core.PluginManager
	store     core.ResultStore
	telemetry core.Telemetry
	logger    *logger.Logger

	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
}

func NewWorkerPool(
	queue core.JobQueue,
	plugins core.PluginManager,
	store core.ResultStore,
	telemetry core.Telemetry,
	logger *logger.Logger,
) core.WorkerPool {
	return &workerPool{
		workers:   make([]core.Worker, 0),
		queue:     queue,
		plugins:   plugins,
		store:     store,
		telemetry: telemetry,
		logger:    logger,
	}
}

func (p *workerPool) Start(ctx context.Context, workerCount int) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ctx != nil {
		return fmt.Errorf("worker pool already started")
	}

	p.ctx, p.cancel = context.WithCancel(ctx)

	p.logger.Infow("Starting worker pool", "workers", workerCount)

	for i := 0; i < workerCount; i++ {
		worker := NewWorker(p.queue, p.plugins, p.store, p.telemetry, p.logger)

		if err := worker.Start(p.ctx); err != nil {
			p.stopAll()
			return fmt.Errorf("failed to start worker %d: %w", i, err)
		}

		p.workers = append(p.workers, worker)
	}

	p.logger.Infow("Worker pool started successfully", "workers", len(p.workers))

	return nil
}

func (p *workerPool) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cancel == nil {
		return fmt.Errorf("worker pool not started")
	}

	p.logger.Info("Stopping worker pool")

	p.cancel()

	return p.stopAll()
}

func (p *workerPool) Scale(workerCount int) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ctx == nil {
		return fmt.Errorf("worker pool not started")
	}

	currentCount := len(p.workers)

	if workerCount == currentCount {
		return nil
	}

	if workerCount > currentCount {
		p.logger.Infow("Scaling up worker pool", "from", currentCount, "to", workerCount)

		for i := currentCount; i < workerCount; i++ {
			worker := NewWorker(p.queue, p.plugins, p.store, p.telemetry, p.logger)

			if err := worker.Start(p.ctx); err != nil {
				return fmt.Errorf("failed to start worker %d: %w", i, err)
			}

			p.workers = append(p.workers, worker)
		}
	} else {
		p.logger.Infow("Scaling down worker pool", "from", currentCount, "to", workerCount)

		workersToStop := p.workers[workerCount:]
		p.workers = p.workers[:workerCount]

		g := new(errgroup.Group)
		for _, worker := range workersToStop {
			w := worker
			g.Go(func() error {
				return w.Stop()
			})
		}

		if err := g.Wait(); err != nil {
			return fmt.Errorf("failed to stop workers: %w", err)
		}
	}

	p.logger.Infow("Worker pool scaled successfully", "workers", len(p.workers))

	return nil
}

func (p *workerPool) Status() []*types.WorkerStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	statuses := make([]*types.WorkerStatus, 0, len(p.workers))

	for _, worker := range p.workers {
		statuses = append(statuses, worker.Status())
	}

	return statuses
}

func (p *workerPool) stopAll() error {
	g := new(errgroup.Group)

	for _, worker := range p.workers {
		w := worker
		g.Go(func() error {
			return w.Stop()
		})
	}

	err := g.Wait()
	p.workers = nil
	p.ctx = nil
	p.cancel = nil

	return err
}
