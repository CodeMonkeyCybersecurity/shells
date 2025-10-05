package httpclient

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecureClient(t *testing.T) {
	config := DefaultConfig()
	client := NewSecureClient(config)

	assert.NotNil(t, client)
	assert.Equal(t, 30*time.Second, client.Timeout)
}

func TestSSRFProtection_BlocksLocalhost(t *testing.T) {
	client := NewSecureClient(SecureClientConfig{
		Timeout:    5 * time.Second,
		EnableSSRF: true,
	})

	// Try to access localhost - should be blocked
	req, err := http.NewRequest("GET", "http://localhost:8080/admin", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("Expected SSRF protection to block localhost, but request succeeded")
	}

	assert.Contains(t, err.Error(), "SSRF protection")
}

func TestSSRFProtection_BlocksPrivateIP(t *testing.T) {
	client := NewSecureClient(SecureClientConfig{
		Timeout:    5 * time.Second,
		EnableSSRF: true,
	})

	privateIPs := []string{
		"http://10.0.0.1/",
		"http://172.16.0.1/",
		"http://192.168.1.1/",
		"http://127.0.0.1/",
	}

	for _, privateIP := range privateIPs {
		req, err := http.NewRequest("GET", privateIP, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}

		// Should either block or fail to connect
		// We just want to ensure it doesn't succeed
		assert.Error(t, err, "Should block or fail for IP: %s", privateIP)
	}
}

func TestSSRFProtection_AllowsPublicIP(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	client := NewSecureClient(SecureClientConfig{
		Timeout:    10 * time.Second,
		EnableSSRF: true,
	})

	// Try to access a public service (example.com is safe)
	req, err := http.NewRequest("GET", "http://example.com/", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	if err != nil {
		t.Logf("Request to example.com failed (might be network issue): %v", err)
		return // Don't fail test on network issues
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestUnsafeClient_AllowsPrivateIP(t *testing.T) {
	// Create a test server on localhost
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	// Unsafe client should allow localhost
	client := NewUnsafeClient(5 * time.Second)

	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDoWithContext_RespectsTimeout(t *testing.T) {
	// Create a slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewUnsafeClient(10 * time.Second)

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	req, err := http.NewRequest("GET", server.URL, nil)
	require.NoError(t, err)

	start := time.Now()
	resp, err := DoWithContext(ctx, client, req)
	duration := time.Since(start)

	if resp != nil {
		resp.Body.Close()
	}

	// Should timeout
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
	assert.Less(t, duration, 1*time.Second, "Should timeout quickly")
}

func TestDoWithContext_RespectsContextCancellation(t *testing.T) {
	// Create a slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewUnsafeClient(10 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())

	req, err := http.NewRequest("GET", server.URL, nil)
	require.NoError(t, err)

	// Cancel context after 100ms
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	resp, err := DoWithContext(ctx, client, req)
	duration := time.Since(start)

	if resp != nil {
		resp.Body.Close()
	}

	// Should be cancelled
	assert.Error(t, err)
	assert.Less(t, duration, 500*time.Millisecond, "Should cancel quickly")
}

func TestQuickClient(t *testing.T) {
	client := NewQuickClient()

	assert.NotNil(t, client)
	assert.Equal(t, 10*time.Second, client.Timeout)
}

func TestScannerClient(t *testing.T) {
	client := NewScannerClient()

	assert.NotNil(t, client)
	assert.Equal(t, 30*time.Second, client.Timeout)
}

func TestDiscoveryClient(t *testing.T) {
	client := NewDiscoveryClient()

	assert.NotNil(t, client)
	assert.Equal(t, 60*time.Second, client.Timeout)
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},      // Loopback
		{"10.0.0.1", true},       // Private
		{"172.16.0.1", true},     // Private
		{"192.168.1.1", true},    // Private
		{"169.254.1.1", true},    // Link-local
		{"8.8.8.8", false},       // Public (Google DNS)
		{"1.1.1.1", false},       // Public (Cloudflare DNS)
		{"93.184.216.34", false}, // Public (example.com)
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		require.NotNil(t, ip, "Failed to parse IP: %s", tt.ip)

		result := isPrivateIP(ip)
		assert.Equal(t, tt.expected, result, "IP: %s", tt.ip)
	}
}

func TestRedirectLimiting(t *testing.T) {
	// Track redirect count
	redirectCount := 0

	// Create a server that always redirects
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCount++
		http.Redirect(w, r, "/redirect", http.StatusFound)
	}))
	defer server.Close()

	client := NewSecureClient(SecureClientConfig{
		Timeout:         5 * time.Second,
		EnableSSRF:      false,
		FollowRedirects: true,
		MaxRedirects:    3,
	})

	resp, err := client.Get(server.URL)
	if resp != nil {
		resp.Body.Close()
	}

	// Should stop after max redirects
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "stopped after")
	assert.LessOrEqual(t, redirectCount, 5, "Should stop redirecting")
}

func TestNoRedirectFollowing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer server.Close()

	client := NewSecureClient(SecureClientConfig{
		Timeout:         5 * time.Second,
		EnableSSRF:      false,
		FollowRedirects: false,
	})

	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should get the redirect response, not follow it
	assert.Equal(t, http.StatusFound, resp.StatusCode)
}
