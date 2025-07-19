package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SecureClient provides a secure HTTP client with proper timeouts
type SecureClient struct {
	client *http.Client
}

// NewSecureClient creates a new secure HTTP client
func NewSecureClient(timeout time.Duration) *SecureClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Limit redirect chains to prevent infinite loops
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &SecureClient{client: client}
}

// Get performs a GET request with context
func (c *SecureClient) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set security headers
	req.Header.Set("User-Agent", "shells-security-scanner/1.0")
	req.Header.Set("Accept", "application/json,text/html,text/plain")
	req.Header.Set("Cache-Control", "no-cache")

	return c.client.Do(req)
}

// Post performs a POST request with context
func (c *SecureClient) Post(ctx context.Context, url, contentType string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader

	// Handle different body types
	switch v := body.(type) {
	case io.Reader:
		reqBody = v
	case string:
		reqBody = strings.NewReader(v)
	case []byte:
		reqBody = bytes.NewReader(v)
	case nil:
		reqBody = nil
	default:
		// For other types, try to marshal to JSON
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal body to JSON: %w", err)
		}
		reqBody = bytes.NewReader(jsonBytes)
		if contentType == "" {
			contentType = "application/json"
		}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Set security headers
	req.Header.Set("User-Agent", "shells-security-scanner/1.0")
	req.Header.Set("Accept", "application/json,text/html,text/plain")
	req.Header.Set("Cache-Control", "no-cache")

	return c.client.Do(req)
}

// DefaultClient returns a default secure HTTP client with 30 second timeout
func DefaultClient() *SecureClient {
	return NewSecureClient(30 * time.Second)
}

// Close closes the client and cleans up resources
func (c *SecureClient) Close() error {
	if transport, ok := c.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}
