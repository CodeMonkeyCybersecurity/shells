package shutdown

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

// Handler manages graceful shutdown of the application
type Handler struct {
	shutdownFuncs []func() error
	mu            sync.Mutex
	done          chan struct{}
	logger        *logger.Logger
}

// NewHandler creates a new graceful shutdown handler
func NewHandler() *Handler {
	// Create logger for shutdown handler
	log, _ := logger.New(config.LoggerConfig{
		Level:  "info",
		Format: "json",
	})
	return &Handler{
		shutdownFuncs: make([]func() error, 0),
		done:          make(chan struct{}),
		logger:        log.WithComponent("shutdown"),
	}
}

// RegisterShutdownFunc registers a function to be called during shutdown
func (h *Handler) RegisterShutdownFunc(fn func() error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.shutdownFuncs = append(h.shutdownFuncs, fn)
}

// WaitForShutdown waits for shutdown signals and executes shutdown functions
func (h *Handler) WaitForShutdown(ctx context.Context) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		h.logger.Infow("Received signal, starting graceful shutdown", "signal", sig)
		h.Shutdown()
	case <-ctx.Done():
		h.logger.Info("Context cancelled, starting graceful shutdown")
		h.Shutdown()
	}
}

// Shutdown executes all registered shutdown functions
func (h *Handler) Shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.done != nil {
		close(h.done)
		h.done = nil
	}

	// Execute shutdown functions in reverse order
	for i := len(h.shutdownFuncs) - 1; i >= 0; i-- {
		if err := h.shutdownFuncs[i](); err != nil {
			h.logger.Error("Error during shutdown", "error", err)
		}
	}
}

// Done returns a channel that's closed when shutdown is complete
func (h *Handler) Done() <-chan struct{} {
	return h.done
}

// ShutdownWithTimeout executes shutdown with a timeout
func (h *Handler) ShutdownWithTimeout(timeout time.Duration) error {
	done := make(chan struct{})

	go func() {
		defer close(done)
		h.Shutdown()
	}()

	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("shutdown timeout after %v", timeout)
	}
}
