package context

import (
	"context"
	"sync"
	"time"
)

// Manager provides context management with automatic cleanup
type Manager struct {
	contexts map[string]context.CancelFunc
	mu       sync.RWMutex
}

// NewManager creates a new context manager
func NewManager() *Manager {
	return &Manager{
		contexts: make(map[string]context.CancelFunc),
	}
}

// CreateContext creates a new context with timeout and cancellation
func (m *Manager) CreateContext(id string, timeout time.Duration) context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Cancel existing context if it exists
	if cancel, exists := m.contexts[id]; exists {
		cancel()
	}

	// Create new context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	m.contexts[id] = cancel

	return ctx
}

// CancelContext cancels a specific context
func (m *Manager) CancelContext(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cancel, exists := m.contexts[id]; exists {
		cancel()
		delete(m.contexts, id)
	}
}

// CancelAll cancels all contexts
func (m *Manager) CancelAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, cancel := range m.contexts {
		cancel()
		delete(m.contexts, id)
	}
}

// Cleanup cancels all contexts and cleans up resources
func (m *Manager) Cleanup() {
	m.CancelAll()
}