package scope

import (
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// ScopeMonitor monitors for scope changes
type ScopeMonitor struct {
	manager  *Manager
	logger   *logger.Logger
	interval time.Duration
	stopCh   chan struct{}
	wg       sync.WaitGroup
	running  bool
	mu       sync.Mutex
}

// NewScopeMonitor creates a new scope monitor
func NewScopeMonitor(manager *Manager, logger *logger.Logger, interval time.Duration) *ScopeMonitor {
	return &ScopeMonitor{
		manager:  manager,
		logger:   logger,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// SetInterval sets the monitoring interval
func (m *ScopeMonitor) SetInterval(interval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.interval = interval
}

// Start starts the monitoring
func (m *ScopeMonitor) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return nil
	}

	m.running = true
	m.wg.Add(1)
	go m.monitor()

	m.logger.Info("Scope monitoring started", "interval", m.interval)
	return nil
}

// Stop stops the monitoring
func (m *ScopeMonitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.running = false
	close(m.stopCh)
	m.wg.Wait()

	m.logger.Info("Scope monitoring stopped")
	return nil
}

// monitor is the main monitoring loop
func (m *ScopeMonitor) monitor() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	// Run initial sync
	m.syncPrograms()

	for {
		select {
		case <-ticker.C:
			m.syncPrograms()
		case <-m.stopCh:
			return
		}
	}
}

// syncPrograms syncs all active programs
func (m *ScopeMonitor) syncPrograms() {
	m.logger.Debug("Starting scope sync")

	programs, err := m.manager.ListPrograms()
	if err != nil {
		m.logger.Error("Failed to list programs for sync", "error", err)
		return
	}

	synced := 0
	errors := 0

	for _, program := range programs {
		if !program.Active {
			continue
		}

		// Check if sync is needed
		if time.Since(program.LastSynced) < m.interval {
			continue
		}

		if err := m.manager.SyncProgram(program.ID); err != nil {
			m.logger.Error("Failed to sync program",
				"program", program.Name,
				"error", err)
			errors++
		} else {
			synced++
		}

		// Rate limit
		time.Sleep(5 * time.Second)
	}

	if synced > 0 || errors > 0 {
		m.logger.Info("Scope sync completed",
			"synced", synced,
			"errors", errors)
	}
}