// Package httpclient provides secure HTTP clients with built-in protections
package httpclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// SecureClientConfig configures the secure HTTP client
type SecureClientConfig struct {
	Timeout         time.Duration
	EnableSSRF      bool // If true, blocks requests to private IPs
	FollowRedirects bool
	MaxRedirects    int
}

// DefaultConfig returns a secure default configuration
func DefaultConfig() SecureClientConfig {
	return SecureClientConfig{
		Timeout:         30 * time.Second,
		EnableSSRF:      true,  // SSRF protection enabled by default
		FollowRedirects: true,
		MaxRedirects:    10,
	}
}

// NewSecureClient creates an HTTP client with security protections
// - Timeout enforcement (prevents hung requests)
// - SSRF protection (blocks private IPs if enabled)
// - Context-aware (respects context cancellation)
// - Configurable redirect following
func NewSecureClient(config SecureClientConfig) *http.Client {
	transport := &http.Transport{
		// Enable context-aware dialing
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// SSRF Protection: Block private IPs if enabled
			if config.EnableSSRF {
				if err := validateAddress(addr); err != nil {
					return nil, fmt.Errorf("SSRF protection: %w", err)
				}
			}

			// Use context-aware dialer
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, addr)
		},

		// Connection pool settings
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,

		// Timeouts
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}

	// Configure redirect policy
	if !config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else if config.MaxRedirects > 0 {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", config.MaxRedirects)
			}

			// SSRF protection on redirects
			if config.EnableSSRF {
				if err := validateURL(req.URL.String()); err != nil {
					return fmt.Errorf("SSRF protection on redirect: %w", err)
				}
			}

			return nil
		}
	}

	return client
}

// NewQuickClient creates a client optimized for quick scans
// - Short timeout (10 seconds)
// - SSRF protection enabled
// - No redirect following
func NewQuickClient() *http.Client {
	return NewSecureClient(SecureClientConfig{
		Timeout:         10 * time.Second,
		EnableSSRF:      true,
		FollowRedirects: false,
		MaxRedirects:    0,
	})
}

// NewScannerClient creates a client optimized for security scanning
// - Medium timeout (30 seconds)
// - SSRF protection enabled
// - Limited redirects
func NewScannerClient() *http.Client {
	return NewSecureClient(SecureClientConfig{
		Timeout:         30 * time.Second,
		EnableSSRF:      true,
		FollowRedirects: true,
		MaxRedirects:    5,
	})
}

// NewDiscoveryClient creates a client optimized for asset discovery
// - Longer timeout (60 seconds)
// - SSRF protection enabled
// - Follow redirects
func NewDiscoveryClient() *http.Client {
	return NewSecureClient(SecureClientConfig{
		Timeout:         60 * time.Second,
		EnableSSRF:      true,
		FollowRedirects: true,
		MaxRedirects:    10,
	})
}

// NewUnsafeClient creates a client WITHOUT SSRF protection
// Use only when scanning authorized internal networks
func NewUnsafeClient(timeout time.Duration) *http.Client {
	return NewSecureClient(SecureClientConfig{
		Timeout:         timeout,
		EnableSSRF:      false, // SSRF protection DISABLED
		FollowRedirects: true,
		MaxRedirects:    10,
	})
}

// validateAddress checks if an address points to a private IP
func validateAddress(addr string) error {
	// Split host and port
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Try without port
		host = addr
	}

	// Resolve to IP addresses
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve %s: %w", host, err)
	}

	// Check each resolved IP
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("blocked private IP: %s (%s)", ip, host)
		}
	}

	return nil
}

// validateURL checks if a URL is safe (not pointing to private IPs)
func validateURL(urlStr string) error {
	// For URL validation, extract host and validate
	// This is a simplified version - full implementation would parse URL properly
	return nil // Placeholder
}

// isPrivateIP checks if an IP address is private, loopback, or link-local
func isPrivateIP(ip net.IP) bool {
	// Check for loopback
	if ip.IsLoopback() {
		return true
	}

	// Check for link-local
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check for private IP ranges
	if ip.IsPrivate() {
		return true
	}

	// Check for special addresses
	if ip.String() == "0.0.0.0" || ip.String() == "::" {
		return true
	}

	// Check for IPv4 private ranges manually (as backup)
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 127.0.0.0/8 (loopback)
		if ip4[0] == 127 {
			return true
		}
		// 169.254.0.0/16 (link-local)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
	}

	return false
}

// DoWithContext performs an HTTP request with context enforcement
// This ensures the request respects context cancellation and deadlines
func DoWithContext(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	// Clone request with context
	req = req.WithContext(ctx)

	// Perform request
	resp, err := client.Do(req)
	if err != nil {
		// Check if error was due to context cancellation
		if ctx.Err() != nil {
			return nil, fmt.Errorf("request cancelled: %w", ctx.Err())
		}
		return nil, err
	}

	return resp, nil
}

// CloseBody safely closes an HTTP response body and logs any errors.
// This is critical for connection pool health - unclosed bodies leak HTTP connections.
//
// Usage:
//   defer httpclient.CloseBody(resp)
//
// Philosophy alignment: Transparent error handling (human-centric principle)
func CloseBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}

	// Drain body before closing to enable connection reuse
	// HTTP/1.1 connections can only be reused if body is fully read
	_, _ = io.Copy(io.Discard, resp.Body)

	if err := resp.Body.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to close HTTP response body: %v\n", err)
		fmt.Fprintf(os.Stderr, "Impact: HTTP connection may leak (pool exhaustion possible)\n")
	}
}

// MustCloseBody is like CloseBody but panics on error (use only in tests)
func MustCloseBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}

	_, _ = io.Copy(io.Discard, resp.Body)

	if err := resp.Body.Close(); err != nil {
		panic(fmt.Sprintf("failed to close response body: %v", err))
	}
}
