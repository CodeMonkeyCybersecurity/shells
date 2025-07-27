package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// Cache provides a simple file-based cache for API responses
type Cache struct {
	dir      string
	ttl      time.Duration
	mu       sync.RWMutex
	logger   *logger.Logger
	memCache map[string]*CacheEntry
}

// CacheEntry represents a cached item
type CacheEntry struct {
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
	Key       string      `json:"key"`
}

// NewCache creates a new cache instance
func NewCache(dir string, ttl time.Duration, logger *logger.Logger) (*Cache, error) {
	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	cache := &Cache{
		dir:      dir,
		ttl:      ttl,
		logger:   logger,
		memCache: make(map[string]*CacheEntry),
	}

	// Clean up expired entries on startup
	go cache.cleanupExpired()

	return cache, nil
}

// Get retrieves an item from cache
func (c *Cache) Get(key string, result interface{}) error {
	c.mu.RLock()
	// Check memory cache first
	if entry, exists := c.memCache[key]; exists {
		c.mu.RUnlock()
		if time.Since(entry.Timestamp) < c.ttl {
			// Deep copy the cached data
			data, _ := json.Marshal(entry.Data)
			return json.Unmarshal(data, result)
		}
		// Entry expired, remove from memory
		c.mu.Lock()
		delete(c.memCache, key)
		c.mu.Unlock()
	} else {
		c.mu.RUnlock()
	}

	// Check file cache
	filename := c.getFilename(key)
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("cache miss: %s", key)
		}
		return err
	}

	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return err
	}

	// Check if expired
	if time.Since(entry.Timestamp) >= c.ttl {
		os.Remove(filename)
		return fmt.Errorf("cache expired: %s", key)
	}

	// Store in memory cache
	c.mu.Lock()
	c.memCache[key] = &entry
	c.mu.Unlock()

	// Unmarshal the actual data
	dataBytes, _ := json.Marshal(entry.Data)
	return json.Unmarshal(dataBytes, result)
}

// Set stores an item in cache
func (c *Cache) Set(key string, value interface{}) error {
	entry := &CacheEntry{
		Data:      value,
		Timestamp: time.Now(),
		Key:       key,
	}

	// Store in memory cache
	c.mu.Lock()
	c.memCache[key] = entry
	c.mu.Unlock()

	// Store in file cache
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}

	filename := c.getFilename(key)
	return os.WriteFile(filename, data, 0644)
}

// Delete removes an item from cache
func (c *Cache) Delete(key string) error {
	c.mu.Lock()
	delete(c.memCache, key)
	c.mu.Unlock()

	filename := c.getFilename(key)
	return os.Remove(filename)
}

// Clear removes all items from cache
func (c *Cache) Clear() error {
	c.mu.Lock()
	c.memCache = make(map[string]*CacheEntry)
	c.mu.Unlock()

	files, err := filepath.Glob(filepath.Join(c.dir, "*.json"))
	if err != nil {
		return err
	}

	for _, file := range files {
		os.Remove(file)
	}

	return nil
}

// getFilename generates a filename for a cache key
func (c *Cache) getFilename(key string) string {
	hash := sha256.Sum256([]byte(key))
	filename := hex.EncodeToString(hash[:]) + ".json"
	return filepath.Join(c.dir, filename)
}

// cleanupExpired periodically removes expired entries
func (c *Cache) cleanupExpired() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		c.logger.Debug("Running cache cleanup")

		files, err := filepath.Glob(filepath.Join(c.dir, "*.json"))
		if err != nil {
			c.logger.Error("Cache cleanup failed", "error", err)
			continue
		}

		expired := 0
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}

			var entry CacheEntry
			if err := json.Unmarshal(data, &entry); err != nil {
				// Invalid file, remove it
				os.Remove(file)
				expired++
				continue
			}

			if time.Since(entry.Timestamp) >= c.ttl {
				os.Remove(file)
				expired++

				// Also remove from memory cache
				c.mu.Lock()
				delete(c.memCache, entry.Key)
				c.mu.Unlock()
			}
		}

		if expired > 0 {
			c.logger.Debug("Cache cleanup completed", "expired", expired)
		}
	}
}

// APICache wraps API calls with caching
type APICache struct {
	cache *Cache
}

// NewAPICache creates a new API cache
func NewAPICache(cacheDir string, ttl time.Duration, logger *logger.Logger) (*APICache, error) {
	cache, err := NewCache(cacheDir, ttl, logger)
	if err != nil {
		return nil, err
	}

	return &APICache{cache: cache}, nil
}

// CacheKey generates a cache key for an API call
func (a *APICache) CacheKey(service, method string, params interface{}) string {
	paramBytes, _ := json.Marshal(params)
	return fmt.Sprintf("%s:%s:%s", service, method, string(paramBytes))
}

// GetOrFetch retrieves from cache or fetches from API
func (a *APICache) GetOrFetch(key string, fetch func() (interface{}, error), result interface{}) error {
	// Try cache first
	if err := a.cache.Get(key, result); err == nil {
		return nil // Cache hit
	}

	// Cache miss, fetch from API
	data, err := fetch()
	if err != nil {
		return err
	}

	// Store in cache
	if err := a.cache.Set(key, data); err != nil {
		// Log error but don't fail the request
		a.cache.logger.Error("Failed to cache API response", "key", key, "error", err)
	}

	// Copy data to result
	dataBytes, _ := json.Marshal(data)
	return json.Unmarshal(dataBytes, result)
}

// CachedHTTPClient wraps HTTP requests with caching
type CachedHTTPClient struct {
	client *http.Client
	cache  *APICache
	logger *logger.Logger
}

// NewCachedHTTPClient creates a new cached HTTP client
func NewCachedHTTPClient(cacheDir string, ttl time.Duration, logger *logger.Logger) (*CachedHTTPClient, error) {
	cache, err := NewAPICache(cacheDir, ttl, logger)
	if err != nil {
		return nil, err
	}

	return &CachedHTTPClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:  cache,
		logger: logger,
	}, nil
}

// Get performs a cached GET request
func (c *CachedHTTPClient) Get(url string) ([]byte, error) {
	key := c.cache.CacheKey("http", "GET", url)

	var result []byte
	err := c.cache.GetOrFetch(key, func() (interface{}, error) {
		resp, err := c.client.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		return body, nil
	}, &result)

	return result, err
}
