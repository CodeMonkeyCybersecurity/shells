package shutdown

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Handler manages graceful shutdown of the application
type Handler struct {
	shutdownFuncs []func() error
	mu            sync.Mutex
	done          chan struct{}
}

// NewHandler creates a new graceful shutdown handler
func NewHandler() *Handler {
	return &Handler{
		shutdownFuncs: make([]func() error, 0),
		done:          make(chan struct{}),
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
		fmt.Printf("Received signal %s, starting graceful shutdown...\n", sig)
		h.Shutdown()
	case <-ctx.Done():
		fmt.Println("Context cancelled, starting graceful shutdown...")
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
			fmt.Printf("Error during shutdown: %v\n", err)
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