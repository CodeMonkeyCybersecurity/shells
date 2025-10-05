package api

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// LoggingMiddleware logs all HTTP requests
func LoggingMiddleware(log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		c.Next()

		duration := time.Since(start)
		statusCode := c.Writer.Status()

		log.Infow("HTTP request",
			"method", method,
			"path", path,
			"status", statusCode,
			"duration_ms", duration.Milliseconds(),
			"ip", c.ClientIP(),
		)
	}
}

// CORSMiddleware enables CORS for browser extensions
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Allow chrome-extension:// and moz-extension:// origins
		// Also allow localhost (any port) and 127.0.0.1
		if strings.HasPrefix(origin, "chrome-extension://") ||
			strings.HasPrefix(origin, "moz-extension://") ||
			strings.HasPrefix(origin, "http://localhost") ||
			strings.HasPrefix(origin, "http://127.0.0.1") ||
			strings.HasPrefix(origin, "https://localhost") ||
			strings.HasPrefix(origin, "https://127.0.0.1") {

			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token")
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Max-Age", "86400")
		}

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// AuthMiddleware validates API key
func AuthMiddleware(expectedAPIKey string, log *logger.Logger) gin.HandlerFunc {
	// Validate on initialization (fail fast)
	if expectedAPIKey == "" {
		log.Fatalw("API key cannot be empty",
			"hint", "Set SHELLS_API_KEY environment variable or configure security.api_key in config file",
		)
	}

	return func(c *gin.Context) {
		// Skip auth for health check
		if c.Request.URL.Path == "/health" || strings.HasSuffix(c.Request.URL.Path, "/hera/health") {
			c.Next()
			return
		}

		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Warnw("Missing Authorization header",
				"path", c.Request.URL.Path,
				"ip", c.ClientIP(),
			)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Missing Authorization header",
			})
			c.Abort()
			return
		}

		// Extract token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Warnw("Invalid Authorization format",
				"header", authHeader,
				"ip", c.ClientIP(),
			)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid Authorization format. Expected: Bearer <token>",
			})
			c.Abort()
			return
		}

		token := parts[1]

		// Validate token
		if token != expectedAPIKey {
			log.Warnw("Invalid API key",
				"ip", c.ClientIP(),
				"path", c.Request.URL.Path,
			)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid API key",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitMiddleware implements token bucket rate limiting per IP
func RateLimitMiddleware(cfg config.RateLimitConfig) gin.HandlerFunc {
	type client struct {
		limiter  *rate.Limiter
		lastSeen time.Time
	}

	var (
		mu      sync.Mutex
		clients = make(map[string]*client)
		once    sync.Once
	)

	// Start cleanup goroutine ONCE (not on every middleware call)
	once.Do(func() {
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()

			for range ticker.C {
				mu.Lock()
				for ip, c := range clients {
					if time.Since(c.lastSeen) > 10*time.Minute {
						delete(clients, ip)
					}
				}
				mu.Unlock()
			}
		}()
	})

	return func(c *gin.Context) {
		ip := c.ClientIP()

		mu.Lock()
		cl, exists := clients[ip]
		if !exists {
			cl = &client{
				limiter: rate.NewLimiter(
					rate.Limit(cfg.RequestsPerSecond),
					cfg.BurstSize,
				),
				lastSeen: time.Now(),
			}
			clients[ip] = cl
		}
		cl.lastSeen = time.Now()
		mu.Unlock()

		if !cl.limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
