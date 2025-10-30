package orchestrator

import (
	"fmt"
	"strings"
	"sync"
)

// ErrorAggregator collects errors from parallel operations
// Thread-safe: Can be used from multiple goroutines
type ErrorAggregator struct {
	errors []error
	mu     sync.Mutex
}

// NewErrorAggregator creates a new error collector
func NewErrorAggregator() *ErrorAggregator {
	return &ErrorAggregator{
		errors: make([]error, 0),
	}
}

// Add adds an error to the collection (thread-safe)
func (ea *ErrorAggregator) Add(err error) {
	if err == nil {
		return
	}
	ea.mu.Lock()
	defer ea.mu.Unlock()
	ea.errors = append(ea.errors, err)
}

// HasErrors returns true if any errors were collected
func (ea *ErrorAggregator) HasErrors() bool {
	ea.mu.Lock()
	defer ea.mu.Unlock()
	return len(ea.errors) > 0
}

// Count returns the number of errors collected
func (ea *ErrorAggregator) Count() int {
	ea.mu.Lock()
	defer ea.mu.Unlock()
	return len(ea.errors)
}

// GetErrors returns a copy of all collected errors
func (ea *ErrorAggregator) GetErrors() []error {
	ea.mu.Lock()
	defer ea.mu.Unlock()
	result := make([]error, len(ea.errors))
	copy(result, ea.errors)
	return result
}

// Error implements error interface, combining all errors into one message
func (ea *ErrorAggregator) Error() string {
	ea.mu.Lock()
	defer ea.mu.Unlock()

	if len(ea.errors) == 0 {
		return ""
	}

	if len(ea.errors) == 1 {
		return ea.errors[0].Error()
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d errors occurred:\n", len(ea.errors)))
	for i, err := range ea.errors {
		sb.WriteString(fmt.Sprintf("  %d. %v\n", i+1, err))
	}
	return sb.String()
}

// ShouldFail determines if the failure rate warrants aborting
// Returns true if more than threshold% of operations failed
func (ea *ErrorAggregator) ShouldFail(totalOperations int, thresholdPercent float64) bool {
	ea.mu.Lock()
	defer ea.mu.Unlock()

	if totalOperations == 0 {
		return false
	}

	failureRate := float64(len(ea.errors)) / float64(totalOperations) * 100
	return failureRate > thresholdPercent
}

// Summary returns a user-friendly error summary
func (ea *ErrorAggregator) Summary(totalOperations int) string {
	ea.mu.Lock()
	defer ea.mu.Unlock()

	if len(ea.errors) == 0 {
		return fmt.Sprintf("All %d operations succeeded", totalOperations)
	}

	failureRate := float64(len(ea.errors)) / float64(totalOperations) * 100

	return fmt.Sprintf("%d/%d operations failed (%.1f%% failure rate)",
		len(ea.errors), totalOperations, failureRate)
}
