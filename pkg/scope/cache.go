package scope

import (
	"sync"
	"time"
)

// ScopeCache provides caching for scope validations
type ScopeCache struct {
	mu              sync.RWMutex
	validations     map[string]*cacheEntry
	programs        map[string]*Program
	ttl             time.Duration
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

type cacheEntry struct {
	result    *ValidationResult
	timestamp time.Time
}

// NewScopeCache creates a new cache
func NewScopeCache(ttl time.Duration) *ScopeCache {
	cache := &ScopeCache{
		validations:     make(map[string]*cacheEntry),
		programs:        make(map[string]*Program),
		ttl:             ttl,
		cleanupInterval: ttl / 2,
		stopCleanup:     make(chan struct{}),
	}

	// Start cleanup routine
	go cache.cleanupRoutine()

	return cache
}

// GetValidation retrieves a cached validation result
func (c *ScopeCache) GetValidation(asset string) *ValidationResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if entry, exists := c.validations[asset]; exists {
		if time.Since(entry.timestamp) < c.ttl {
			return entry.result
		}
	}

	return nil
}

// StoreValidation stores a validation result
func (c *ScopeCache) StoreValidation(asset string, result *ValidationResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.validations[asset] = &cacheEntry{
		result:    result,
		timestamp: time.Now(),
	}
}

// Clear clears the cache
func (c *ScopeCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.validations = make(map[string]*cacheEntry)
	c.programs = make(map[string]*Program)
}

// cleanupRoutine periodically removes expired entries
func (c *ScopeCache) cleanupRoutine() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopCleanup:
			return
		}
	}
}

// cleanup removes expired entries
func (c *ScopeCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for asset, entry := range c.validations {
		if now.Sub(entry.timestamp) > c.ttl {
			delete(c.validations, asset)
		}
	}
}

// Stop stops the cleanup routine
func (c *ScopeCache) Stop() {
	close(c.stopCleanup)
}