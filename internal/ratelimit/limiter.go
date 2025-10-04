package ratelimit

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter provides rate limiting for HTTP requests to prevent IP bans
type Limiter struct {
	limiter        *rate.Limiter
	requestDelay   time.Duration
	burstSize      int
	lastRequestMap map[string]time.Time
	mu             sync.Mutex
}

// Config contains rate limiting configuration
type Config struct {
	// RequestsPerSecond limits the number of requests per second
	RequestsPerSecond float64

	// BurstSize allows brief bursts above the rate limit
	BurstSize int

	// MinDelay is the minimum delay between requests to the same host
	MinDelay time.Duration
}

// DefaultConfig returns sensible rate limiting defaults for bug bounty scanning
func DefaultConfig() Config {
	return Config{
		RequestsPerSecond: 10.0,                   // 10 requests per second
		BurstSize:         5,                      // Allow bursts of 5 requests
		MinDelay:          100 * time.Millisecond, // 100ms between requests
	}
}

// AggressiveConfig returns more aggressive (but still safe) rate limiting
func AggressiveConfig() Config {
	return Config{
		RequestsPerSecond: 20.0,
		BurstSize:         10,
		MinDelay:          50 * time.Millisecond,
	}
}

// ConservativeConfig returns very conservative rate limiting to avoid any issues
func ConservativeConfig() Config {
	return Config{
		RequestsPerSecond: 2.0,
		BurstSize:         1,
		MinDelay:          500 * time.Millisecond,
	}
}

// NewLimiter creates a new rate limiter with the given configuration
func NewLimiter(config Config) *Limiter {
	return &Limiter{
		limiter:        rate.NewLimiter(rate.Limit(config.RequestsPerSecond), config.BurstSize),
		requestDelay:   config.MinDelay,
		burstSize:      config.BurstSize,
		lastRequestMap: make(map[string]time.Time),
	}
}

// Wait blocks until the rate limiter allows the request
func (l *Limiter) Wait(ctx context.Context) error {
	return l.limiter.Wait(ctx)
}

// WaitForHost blocks until rate limiter allows a request to a specific host
// This provides per-host rate limiting to be extra cautious
func (l *Limiter) WaitForHost(ctx context.Context, host string) error {
	// First wait for global rate limit
	if err := l.limiter.Wait(ctx); err != nil {
		return err
	}

	// Then enforce per-host minimum delay
	l.mu.Lock()
	defer l.mu.Unlock()

	if lastReq, exists := l.lastRequestMap[host]; exists {
		elapsed := time.Since(lastReq)
		if elapsed < l.requestDelay {
			sleepDuration := l.requestDelay - elapsed
			select {
			case <-time.After(sleepDuration):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	l.lastRequestMap[host] = time.Now()
	return nil
}

// Allow checks if a request is allowed without blocking
func (l *Limiter) Allow() bool {
	return l.limiter.Allow()
}

// SetLimit updates the rate limit dynamically
func (l *Limiter) SetLimit(requestsPerSecond float64) {
	l.limiter.SetLimit(rate.Limit(requestsPerSecond))
}

// SetBurst updates the burst size dynamically
func (l *Limiter) SetBurst(burst int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.burstSize = burst
	l.limiter.SetBurst(burst)
}

// Reset clears the rate limiter state (useful for testing)
func (l *Limiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lastRequestMap = make(map[string]time.Time)
}

// GetStats returns current rate limiter statistics
func (l *Limiter) GetStats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()

	return Stats{
		TrackedHosts: len(l.lastRequestMap),
		BurstSize:    l.burstSize,
		RequestDelay: l.requestDelay,
	}
}

// Stats contains rate limiter statistics
type Stats struct {
	TrackedHosts int
	BurstSize    int
	RequestDelay time.Duration
}
