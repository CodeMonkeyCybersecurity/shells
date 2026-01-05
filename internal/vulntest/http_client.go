package vulntest

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"
)

// HTTPClient is a wrapper around http.Client with vulnerability testing helpers
type HTTPClient struct {
	Client *http.Client
}

// NewHTTPClient creates a new HTTP client for vulnerability testing
func NewHTTPClient() *HTTPClient {
	// Configure client to handle common scenarios in bug bounty
	return &HTTPClient{
		Client: &http.Client{
			Timeout: 5 * time.Second, // Faster timeout for bug bounty
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Common in bug bounty to test self-signed certs
				},
				DisableKeepAlives: true,
				MaxIdleConns:      10,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Allow up to 10 redirects
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

// TestCredentials attempts to login with given credentials
func (h *HTTPClient) TestCredentials(loginURL, username, password string) (bool, error) {
	// First, try to GET the login page to find the form
	resp, err := h.Client.Get(loginURL)
	if err != nil {
		return false, err
	}
	defer httpclient.CloseBody(resp)

	// Check if it's already using basic auth
	if resp.StatusCode == 401 {
		return h.testBasicAuth(loginURL, username, password)
	}

	// Otherwise, try form-based login
	return h.testFormLogin(loginURL, username, password)
}

// testBasicAuth tests HTTP basic authentication
func (h *HTTPClient) testBasicAuth(loginURL, username, password string) (bool, error) {
	req, err := http.NewRequest("GET", loginURL, nil)
	if err != nil {
		return false, err
	}

	req.SetBasicAuth(username, password)
	resp, err := h.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer httpclient.CloseBody(resp)

	// 200 OK or redirect means successful login
	return resp.StatusCode == 200 || resp.StatusCode == 302, nil
}

// testFormLogin tests form-based authentication
func (h *HTTPClient) testFormLogin(loginURL, username, password string) (bool, error) {
	// Common parameter names for login forms
	paramSets := []struct {
		userParam string
		passParam string
	}{
		{"username", "password"},
		{"user", "pass"},
		{"email", "password"},
		{"login", "password"},
		{"user", "pwd"},
		{"username", "passwd"},
		{"uname", "pwd"},
		{"uid", "pwd"},
	}

	for _, params := range paramSets {
		formData := url.Values{}
		formData.Set(params.userParam, username)
		formData.Set(params.passParam, password)

		req, err := http.NewRequest("POST", loginURL, strings.NewReader(formData.Encode()))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := h.Client.Do(req)
		if err != nil {
			continue
		}
		defer httpclient.CloseBody(resp)

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// Check for signs of successful login
		if resp.StatusCode == 302 || resp.StatusCode == 200 {
			// Look for signs of failure
			failureIndicators := []string{
				"invalid", "failed", "incorrect", "error",
				"wrong", "denied", "unsuccessful", "bad",
			}

			isFailure := false
			lowerBody := strings.ToLower(bodyStr)
			for _, indicator := range failureIndicators {
				if strings.Contains(lowerBody, indicator) {
					isFailure = true
					break
				}
			}

			if !isFailure {
				// Look for signs of success
				successIndicators := []string{
					"dashboard", "welcome", "logout", "profile",
					"account", "settings", "admin", "panel",
				}

				for _, indicator := range successIndicators {
					if strings.Contains(lowerBody, indicator) {
						return true, nil
					}
				}

				// Check location header for redirect to admin area
				if location := resp.Header.Get("Location"); location != "" {
					for _, indicator := range successIndicators {
						if strings.Contains(strings.ToLower(location), indicator) {
							return true, nil
						}
					}
				}
			}
		}
	}

	return false, nil
}

// CheckEndpoint checks if an endpoint exists and returns status code
func (h *HTTPClient) CheckEndpoint(endpoint string) (int, error) {
	resp, err := h.Client.Get(endpoint)
	if err != nil {
		return 0, err
	}
	defer httpclient.CloseBody(resp)
	return resp.StatusCode, nil
}

// GetResponseBody fetches the response body from a URL
func (h *HTTPClient) GetResponseBody(url string) (string, error) {
	resp, err := h.Client.Get(url)
	if err != nil {
		return "", err
	}
	defer httpclient.CloseBody(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
