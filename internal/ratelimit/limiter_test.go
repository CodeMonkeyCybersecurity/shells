package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestNewLimiter(t *testing.T) {
	config := DefaultConfig()
	limiter := NewLimiter(config)

	if limiter == nil {
		t.Fatal("NewLimiter() should return non-nil limiter")
	}

	if limiter.requestDelay != config.MinDelay {
		t.Errorf("limiter.requestDelay = %v, want %v", limiter.requestDelay, config.MinDelay)
	}

	stats := limiter.GetStats()
	if stats.BurstSize != config.BurstSize {
		t.Errorf("stats.BurstSize = %v, want %v", stats.BurstSize, config.BurstSize)
	}
}

func TestLimiter_Wait(t *testing.T) {
	config := Config{
		RequestsPerSecond: 10.0, // 10 requests per second
		BurstSize:         2,
		MinDelay:          10 * time.Millisecond,
	}
	limiter := NewLimiter(config)
	ctx := context.Background()

	// First requests should not block (burst)
	start := time.Now()
	err := limiter.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}

	err = limiter.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}

	duration := time.Since(start)
	if duration > 50*time.Millisecond {
		t.Errorf("Burst requests took too long: %v", duration)
	}

	// Third request should be rate limited
	start = time.Now()
	err = limiter.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	duration = time.Since(start)

	// Should wait approximately 100ms (1/10 second for 10 req/sec)
	if duration < 50*time.Millisecond {
		t.Errorf("Rate limiter did not delay enough: %v", duration)
	}
}

func TestLimiter_WaitForHost(t *testing.T) {
	config := Config{
		RequestsPerSecond: 100.0, // High global rate
		BurstSize:         10,
		MinDelay:          50 * time.Millisecond, // Per-host delay
	}
	limiter := NewLimiter(config)
	ctx := context.Background()

	host := "example.com"

	// First request to host - should be fast
	start := time.Now()
	err := limiter.WaitForHost(ctx, host)
	if err != nil {
		t.Fatalf("WaitForHost() error = %v", err)
	}
	duration := time.Since(start)
	if duration > 20*time.Millisecond {
		t.Errorf("First request took too long: %v", duration)
	}

	// Second request to same host - should enforce min delay
	start = time.Now()
	err = limiter.WaitForHost(ctx, host)
	if err != nil {
		t.Fatalf("WaitForHost() error = %v", err)
	}
	duration = time.Since(start)

	if duration < config.MinDelay {
		t.Errorf("Per-host rate limit did not enforce min delay: %v < %v", duration, config.MinDelay)
	}
}

func TestLimiter_WaitForHost_DifferentHosts(t *testing.T) {
	config := Config{
		RequestsPerSecond: 100.0, // High global rate
		BurstSize:         10,
		MinDelay:          100 * time.Millisecond,
	}
	limiter := NewLimiter(config)
	ctx := context.Background()

	// Requests to different hosts should not block each other
	start := time.Now()

	err := limiter.WaitForHost(ctx, "example1.com")
	if err != nil {
		t.Fatalf("WaitForHost() error = %v", err)
	}

	err = limiter.WaitForHost(ctx, "example2.com")
	if err != nil {
		t.Fatalf("WaitForHost() error = %v", err)
	}

	err = limiter.WaitForHost(ctx, "example3.com")
	if err != nil {
		t.Fatalf("WaitForHost() error = %v", err)
	}

	duration := time.Since(start)

	// Should be fast since they're different hosts
	if duration > 50*time.Millisecond {
		t.Errorf("Different hosts took too long: %v", duration)
	}

	stats := limiter.GetStats()
	if stats.TrackedHosts != 3 {
		t.Errorf("stats.TrackedHosts = %v, want 3", stats.TrackedHosts)
	}
}

func TestLimiter_Allow(t *testing.T) {
	config := Config{
		RequestsPerSecond: 10.0,
		BurstSize:         2,
		MinDelay:          10 * time.Millisecond,
	}
	limiter := NewLimiter(config)

	// Should allow burst requests
	if !limiter.Allow() {
		t.Error("Allow() should allow first burst request")
	}
	if !limiter.Allow() {
		t.Error("Allow() should allow second burst request")
	}

	// Next request should be denied (burst exhausted)
	if limiter.Allow() {
		t.Error("Allow() should deny request after burst exhausted")
	}

	// Wait for token to replenish
	time.Sleep(150 * time.Millisecond)

	if !limiter.Allow() {
		t.Error("Allow() should allow request after token replenishment")
	}
}

func TestLimiter_SetLimit(t *testing.T) {
	config := DefaultConfig()
	limiter := NewLimiter(config)

	// Change rate limit
	newRate := 20.0
	limiter.SetLimit(newRate)

	// Verify by checking behavior
	ctx := context.Background()

	// Exhaust burst
	for i := 0; i < config.BurstSize; i++ {
		limiter.Wait(ctx)
	}

	// Next request should wait approximately 1/20 second
	start := time.Now()
	limiter.Wait(ctx)
	duration := time.Since(start)

	expectedDelay := time.Second / time.Duration(newRate)
	tolerance := 20 * time.Millisecond

	if duration < expectedDelay-tolerance || duration > expectedDelay+tolerance {
		t.Errorf("SetLimit() behavior: delay = %v, want ~%v", duration, expectedDelay)
	}
}

func TestLimiter_Reset(t *testing.T) {
	config := Config{
		RequestsPerSecond: 100.0,
		BurstSize:         10,
		MinDelay:          50 * time.Millisecond,
	}
	limiter := NewLimiter(config)
	ctx := context.Background()

	// Track some hosts
	limiter.WaitForHost(ctx, "host1.com")
	limiter.WaitForHost(ctx, "host2.com")
	limiter.WaitForHost(ctx, "host3.com")

	stats := limiter.GetStats()
	if stats.TrackedHosts != 3 {
		t.Errorf("Before reset: TrackedHosts = %v, want 3", stats.TrackedHosts)
	}

	// Reset
	limiter.Reset()

	stats = limiter.GetStats()
	if stats.TrackedHosts != 0 {
		t.Errorf("After reset: TrackedHosts = %v, want 0", stats.TrackedHosts)
	}
}

func TestLimiter_ContextCancellation(t *testing.T) {
	config := Config{
		RequestsPerSecond: 1.0, // Very slow rate
		BurstSize:         1,
		MinDelay:          10 * time.Millisecond,
	}
	limiter := NewLimiter(config)

	// Exhaust burst
	limiter.Wait(context.Background())

	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	// Wait should return context error
	err := limiter.Wait(ctx)
	if err != context.Canceled {
		t.Errorf("Wait() with cancelled context: error = %v, want %v", err, context.Canceled)
	}
}

func TestLimiter_Configs(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{"Default", DefaultConfig()},
		{"Aggressive", AggressiveConfig()},
		{"Conservative", ConservativeConfig()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewLimiter(tt.config)
			if limiter == nil {
				t.Fatalf("NewLimiter() with %s config should return non-nil", tt.name)
			}

			stats := limiter.GetStats()
			if stats.BurstSize != tt.config.BurstSize {
				t.Errorf("%s config: BurstSize = %v, want %v", tt.name, stats.BurstSize, tt.config.BurstSize)
			}
			if stats.RequestDelay != tt.config.MinDelay {
				t.Errorf("%s config: RequestDelay = %v, want %v", tt.name, stats.RequestDelay, tt.config.MinDelay)
			}
		})
	}
}
