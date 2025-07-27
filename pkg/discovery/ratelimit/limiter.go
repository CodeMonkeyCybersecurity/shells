package ratelimit

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"golang.org/x/time/rate"
)

// RateLimiter manages rate limits for different services
type RateLimiter struct {
	limiters map[string]*ServiceLimiter
	mu       sync.RWMutex
	logger   *logger.Logger
}

// ServiceLimiter represents rate limiting for a specific service
type ServiceLimiter struct {
	limiter    *rate.Limiter
	name       string
	burst      int
	ratePerSec float64
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(logger *logger.Logger) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*ServiceLimiter),
		logger:   logger,
	}

	// Configure default rate limits for known services
	rl.configureDefaults()

	return rl
}

// configureDefaults sets up default rate limits for known services
func (r *RateLimiter) configureDefaults() {
	// Search engines
	r.AddService("google", 1.0, 2)       // 1 request per second, burst of 2
	r.AddService("bing", 2.0, 5)         // 2 requests per second, burst of 5
	r.AddService("duckduckgo", 2.0, 5)   // 2 requests per second, burst of 5
	r.AddService("commoncrawl", 5.0, 10) // 5 requests per second, burst of 10

	// External APIs
	r.AddService("shodan", 1.0, 1)         // 1 request per second (free tier)
	r.AddService("censys", 0.5, 1)         // 1 request per 2 seconds (free tier)
	r.AddService("virustotal", 0.25, 1)    // 4 requests per minute (free tier)
	r.AddService("securitytrails", 0.5, 1) // 1 request per 2 seconds

	// WHOIS services
	r.AddService("whois", 0.5, 2)    // 1 request per 2 seconds
	r.AddService("viewdns", 0.33, 1) // 1 request per 3 seconds

	// Cloud providers
	r.AddService("aws", 10.0, 20)   // 10 requests per second
	r.AddService("azure", 10.0, 20) // 10 requests per second
	r.AddService("gcp", 10.0, 20)   // 10 requests per second

	// DNS queries
	r.AddService("dns", 50.0, 100) // 50 requests per second

	// Default for unknown services
	r.AddService("default", 1.0, 5) // 1 request per second, burst of 5
}

// AddService adds a new service with rate limiting
func (r *RateLimiter) AddService(name string, ratePerSec float64, burst int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.limiters[name] = &ServiceLimiter{
		limiter:    rate.NewLimiter(rate.Limit(ratePerSec), burst),
		name:       name,
		burst:      burst,
		ratePerSec: ratePerSec,
	}

	r.logger.Debug("Rate limiter configured",
		"service", name,
		"rate_per_sec", ratePerSec,
		"burst", burst)
}

// Wait blocks until the service is allowed to proceed
func (r *RateLimiter) Wait(ctx context.Context, service string) error {
	limiter := r.getLimiter(service)

	start := time.Now()
	err := limiter.limiter.Wait(ctx)
	waited := time.Since(start)

	if waited > 100*time.Millisecond {
		r.logger.Debug("Rate limit wait",
			"service", service,
			"waited", waited.String())
	}

	if err != nil {
		return fmt.Errorf("rate limit wait failed for %s: %w", service, err)
	}

	return nil
}

// Allow checks if a request is allowed without blocking
func (r *RateLimiter) Allow(service string) bool {
	limiter := r.getLimiter(service)
	return limiter.limiter.Allow()
}

// Reserve reserves a future use
func (r *RateLimiter) Reserve(service string) *rate.Reservation {
	limiter := r.getLimiter(service)
	return limiter.limiter.Reserve()
}

// getLimiter gets the limiter for a service
func (r *RateLimiter) getLimiter(service string) *ServiceLimiter {
	r.mu.RLock()
	limiter, exists := r.limiters[service]
	r.mu.RUnlock()

	if !exists {
		r.mu.RLock()
		limiter = r.limiters["default"]
		r.mu.RUnlock()

		r.logger.Debug("Using default rate limiter", "service", service)
	}

	return limiter
}

// GetStats returns current rate limiter statistics
func (r *RateLimiter) GetStats() map[string]ServiceStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := make(map[string]ServiceStats)
	for name, limiter := range r.limiters {
		stats[name] = ServiceStats{
			Service:    name,
			RatePerSec: limiter.ratePerSec,
			Burst:      limiter.burst,
			// We can't get tokens available from rate.Limiter directly
		}
	}

	return stats
}

// ServiceStats contains statistics for a service
type ServiceStats struct {
	Service    string
	RatePerSec float64
	Burst      int
}

// MultiServiceLimiter handles rate limiting across multiple services
type MultiServiceLimiter struct {
	limiter *RateLimiter
	logger  *logger.Logger
}

// NewMultiServiceLimiter creates a new multi-service limiter
func NewMultiServiceLimiter(logger *logger.Logger) *MultiServiceLimiter {
	return &MultiServiceLimiter{
		limiter: NewRateLimiter(logger),
		logger:  logger,
	}
}

// ExecuteWithLimit executes a function with rate limiting
func (m *MultiServiceLimiter) ExecuteWithLimit(ctx context.Context, service string, fn func() error) error {
	// Wait for rate limit
	if err := m.limiter.Wait(ctx, service); err != nil {
		return err
	}

	// Execute the function
	return fn()
}

// ExecuteWithRetry executes with rate limiting and retry on rate limit errors
func (m *MultiServiceLimiter) ExecuteWithRetry(ctx context.Context, service string, maxRetries int, fn func() error) error {
	var lastErr error

	for i := 0; i <= maxRetries; i++ {
		// Wait for rate limit
		if err := m.limiter.Wait(ctx, service); err != nil {
			return err
		}

		// Execute the function
		err := fn()
		if err == nil {
			return nil
		}

		// Check if it's a rate limit error
		if isRateLimitError(err) {
			m.logger.Debug("Rate limit error, backing off",
				"service", service,
				"attempt", i+1,
				"error", err)

			// Exponential backoff
			backoff := time.Duration(1<<uint(i)) * time.Second
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}

			select {
			case <-time.After(backoff):
				// Continue to next retry
			case <-ctx.Done():
				return ctx.Err()
			}
		} else {
			// Not a rate limit error, return immediately
			return err
		}

		lastErr = err
	}

	return fmt.Errorf("max retries exceeded for %s: %w", service, lastErr)
}

// isRateLimitError checks if an error is a rate limit error
func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	// Common rate limit error patterns
	patterns := []string{
		"rate limit",
		"too many requests",
		"429",
		"quota exceeded",
		"throttled",
		"slow down",
	}

	for _, pattern := range patterns {
		if containsIgnoreCase(errStr, pattern) {
			return true
		}
	}

	return false
}

// containsIgnoreCase checks if a string contains a substring (case insensitive)
func containsIgnoreCase(s, substr string) bool {
	s = strings.ToLower(s)
	substr = strings.ToLower(substr)
	return strings.Contains(s, substr)
}

// GlobalRateLimiter is a singleton instance for the application
var globalRateLimiter *RateLimiter
var once sync.Once

// GetGlobalRateLimiter returns the global rate limiter instance
func GetGlobalRateLimiter(logger *logger.Logger) *RateLimiter {
	once.Do(func() {
		globalRateLimiter = NewRateLimiter(logger)
	})
	return globalRateLimiter
}
