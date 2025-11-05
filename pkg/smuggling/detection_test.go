package smuggling

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestNewDetector tests detector initialization
func TestNewDetector(t *testing.T) {
	config := &SmugglingConfig{
		Timeout:              10 * time.Second,
		UserAgent:            "test-agent",
		EnableTimingAnalysis: true,
	}

	client := &http.Client{Timeout: config.Timeout}
	detector := NewDetector(client, config)

	if detector == nil {
		t.Fatal("Expected detector to be initialized")
	}

	if detector.client != client {
		t.Error("Expected detector client to match provided client")
	}

	if detector.config != config {
		t.Error("Expected detector config to match provided config")
	}
}

// TestCLTE_VulnerableServer tests CL.TE smuggling detection
func TestCLTE_VulnerableServer(t *testing.T) {
	tests := []struct {
		name             string
		respondDifferent bool
		expectVulnerable bool
	}{
		{
			name:             "vulnerable - different status codes",
			respondDifferent: true,
			expectVulnerable: true,
		},
		{
			name:             "secure - same responses",
			respondDifferent: false,
			expectVulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestCount := 0

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestCount++

				// Simulate CL.TE vulnerability
				if tt.respondDifferent {
					if requestCount == 1 {
						// First request - poison the front-end/back-end desync
						w.WriteHeader(http.StatusOK)
						w.Write([]byte("First response"))
					} else {
						// Second request - affected by smuggled request
						w.WriteHeader(http.StatusNotFound)
						w.Write([]byte("Smuggled request detected"))
					}
				} else {
					// Secure server - consistent responses
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Normal response"))
				}
			}))
			defer server.Close()

			config := &SmugglingConfig{
				Timeout:              5 * time.Second,
				UserAgent:            "test-agent",
				EnableTimingAnalysis: true,
			}

			client := &http.Client{Timeout: config.Timeout}
			detector := NewDetector(client, config)

			payload := SmugglingPayload{
				Name:        "CL.TE Basic",
				Description: "Content-Length Transfer-Encoding desync",
				Technique:   TechniqueCLTE,
				Request1: `POST / HTTP/1.1
Host: TARGET
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED`,
				Request2: `GET / HTTP/1.1
Host: TARGET

`,
			}

			ctx := context.Background()
			result := detector.TestCLTE(ctx, server.URL, payload)

			if tt.expectVulnerable && !result.Vulnerable {
				t.Error("Expected vulnerability to be detected")
			}

			if !tt.expectVulnerable && result.Vulnerable {
				t.Errorf("Unexpected vulnerability detected with confidence %.2f", result.Confidence)
			}

			if result.Vulnerable {
				t.Logf("Detected CL.TE vulnerability with confidence: %.2f", result.Confidence)
				t.Logf("Evidence count: %d", len(result.Evidence))
			}
		})
	}
}

// TestTECL_VulnerableServer tests TE.CL smuggling detection
func TestTECL_VulnerableServer(t *testing.T) {
	tests := []struct {
		name             string
		serverError      bool
		expectVulnerable bool
	}{
		{
			name:             "vulnerable - server error on malformed chunking",
			serverError:      true,
			expectVulnerable: true,
		},
		{
			name:             "secure - handles chunked encoding properly",
			serverError:      false,
			expectVulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check for Transfer-Encoding
				if r.Header.Get("Transfer-Encoding") != "" {
					if tt.serverError {
						// Simulate vulnerability - server can't handle malformed chunking
						w.WriteHeader(http.StatusBadRequest)
						w.Write([]byte("Invalid chunk size"))
						return
					}
				}

				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Normal response"))
			}))
			defer server.Close()

			config := &SmugglingConfig{
				Timeout:              5 * time.Second,
				UserAgent:            "test-agent",
				EnableTimingAnalysis: true,
			}

			client := &http.Client{Timeout: config.Timeout}
			detector := NewDetector(client, config)

			payload := SmugglingPayload{
				Name:        "TE.CL Basic",
				Description: "Transfer-Encoding Content-Length desync",
				Technique:   TechniqueTECL,
				Request1: `POST / HTTP/1.1
Host: TARGET
Content-Length: 6
Transfer-Encoding: chunked

0

X`,
			}

			ctx := context.Background()
			result := detector.TestTECL(ctx, server.URL, payload)

			if tt.expectVulnerable && !result.Vulnerable {
				t.Error("Expected vulnerability to be detected")
			}

			if !tt.expectVulnerable && result.Vulnerable {
				t.Errorf("Unexpected vulnerability detected with confidence %.2f", result.Confidence)
			}

			if result.Vulnerable {
				t.Logf("Detected TE.CL vulnerability with confidence: %.2f", result.Confidence)
			}
		})
	}
}

// TestTETE_VulnerableServer tests TE.TE smuggling detection
func TestTETE_VulnerableServer(t *testing.T) {
	tests := []struct {
		name             string
		acceptMalformed  bool
		expectVulnerable bool
	}{
		{
			name:             "vulnerable - accepts malformed TE",
			acceptMalformed:  true,
			expectVulnerable: true,
		},
		{
			name:             "secure - rejects malformed TE",
			acceptMalformed:  false,
			expectVulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check for multiple or malformed Transfer-Encoding
				teHeaders := r.Header.Values("Transfer-Encoding")
				if len(teHeaders) > 1 || (len(teHeaders) == 1 && strings.Contains(teHeaders[0], ",")) {
					if !tt.acceptMalformed {
						// Secure: reject malformed TE
						w.WriteHeader(http.StatusBadRequest)
						w.Write([]byte("Malformed Transfer-Encoding"))
						return
					}
				}

				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Normal response"))
			}))
			defer server.Close()

			config := &SmugglingConfig{
				Timeout:              5 * time.Second,
				UserAgent:            "test-agent",
				EnableTimingAnalysis: true,
			}

			client := &http.Client{Timeout: config.Timeout}
			detector := NewDetector(client, config)

			payload := SmugglingPayload{
				Name:        "TE.TE Obfuscation",
				Description: "Transfer-Encoding obfuscation",
				Technique:   TechniqueTETE,
				Request1: `POST / HTTP/1.1
Host: TARGET
Transfer-Encoding: chunked
Transfer-Encoding: identity

0

X`,
			}

			ctx := context.Background()
			result := detector.TestTETE(ctx, server.URL, payload)

			if tt.expectVulnerable && !result.Vulnerable {
				t.Error("Expected vulnerability to be detected")
			}

			if !tt.expectVulnerable && result.Vulnerable {
				t.Errorf("Unexpected vulnerability detected with confidence %.2f", result.Confidence)
			}

			if result.Vulnerable {
				t.Logf("Detected TE.TE vulnerability with confidence: %.2f", result.Confidence)
			}
		})
	}
}

// TestHTTP2_Detection tests HTTP/2 smuggling detection
func TestHTTP2_Detection(t *testing.T) {
	tests := []struct {
		name         string
		targetScheme string
		expectHTTP2  bool
	}{
		{
			name:         "HTTPS target - potential HTTP/2",
			targetScheme: "https",
			expectHTTP2:  true,
		},
		{
			name:         "HTTP target - no HTTP/2",
			targetScheme: "http",
			expectHTTP2:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create appropriate server based on scheme
			var server *httptest.Server
			if tt.targetScheme == "https" {
				server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Response"))
				}))
			} else {
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Response"))
				}))
			}
			defer server.Close()

			config := &SmugglingConfig{
				Timeout:              5 * time.Second,
				UserAgent:            "test-agent",
				EnableTimingAnalysis: false,
			}

			client := server.Client()
			detector := NewDetector(client, config)

			payload := SmugglingPayload{
				Name:        "HTTP/2 Downgrade",
				Description: "HTTP/2 downgrade smuggling",
				Technique:   TechniqueHTTP2,
			}

			ctx := context.Background()
			result := detector.TestHTTP2(ctx, server.URL, payload)

			// HTTP/2 detection is basic in current implementation
			if tt.expectHTTP2 && !result.Vulnerable {
				t.Log("HTTP/2 support detected but no vulnerability found (expected for basic detection)")
			}

			t.Logf("HTTP/2 detection result: vulnerable=%v, confidence=%.2f",
				result.Vulnerable, result.Confidence)
		})
	}
}

// TestTimingAnalysis tests timing-based smuggling detection
func TestTimingAnalysis(t *testing.T) {
	// Create server with deliberate timing difference
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate timing difference for smuggled requests
		if r.Header.Get("X-Smuggled") == "true" {
			time.Sleep(100 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Response"))
	}))
	defer server.Close()

	config := &SmugglingConfig{
		Timeout:              5 * time.Second,
		UserAgent:            "test-agent",
		EnableTimingAnalysis: true,
	}

	client := &http.Client{Timeout: config.Timeout}
	detector := NewDetector(client, config)

	// Create payloads with timing markers
	payload := SmugglingPayload{
		Name:      "Timing-based Detection",
		Technique: TechniqueCLTE,
		Request1: `POST / HTTP/1.1
Host: TARGET
X-Smuggled: true
Content-Length: 0

`,
		Request2: `GET / HTTP/1.1
Host: TARGET
Content-Length: 0

`,
	}

	ctx := context.Background()
	result := detector.TestCLTE(ctx, server.URL, payload)

	t.Logf("Timing analysis result: vulnerable=%v, confidence=%.2f, evidence=%d",
		result.Vulnerable, result.Confidence, len(result.Evidence))

	// Check for timing evidence
	hasTimingEvidence := false
	for _, ev := range result.Evidence {
		if ev.Type == DetectionTiming {
			hasTimingEvidence = true
			t.Logf("Found timing evidence: %s", ev.Description)
			if ev.Timing != nil {
				t.Logf("  Request1Time: %v", ev.Timing.Request1Time)
				t.Logf("  Request2Time: %v", ev.Timing.Request2Time)
				t.Logf("  Difference: %v", ev.Timing.Difference)
			}
		}
	}

	if config.EnableTimingAnalysis && !hasTimingEvidence {
		t.Log("Timing analysis enabled but no timing evidence collected")
	}
}

// TestDifferentialAnalysis tests differential response analysis
func TestDifferentialAnalysis(t *testing.T) {
	responseCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responseCount++

		// Alternate responses to simulate desync
		if responseCount%2 == 1 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Response A - Length 12"))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Response B - Different Length 28"))
		}
	}))
	defer server.Close()

	config := &SmugglingConfig{
		Timeout:              5 * time.Second,
		UserAgent:            "test-agent",
		EnableTimingAnalysis: true,
	}

	client := &http.Client{Timeout: config.Timeout}
	detector := NewDetector(client, config)

	payload := SmugglingPayload{
		Name:      "Differential Response",
		Technique: TechniqueCLTE,
		Request1: `POST / HTTP/1.1
Host: TARGET

`,
		Request2: `GET / HTTP/1.1
Host: TARGET

`,
	}

	ctx := context.Background()
	result := detector.TestCLTE(ctx, server.URL, payload)

	// Should detect differential behavior
	hasDifferentialEvidence := false
	for _, ev := range result.Evidence {
		if ev.Type == DetectionDifferential {
			hasDifferentialEvidence = true
			t.Logf("Found differential evidence: %s", ev.Description)
		}
		if ev.Type == DetectionResponse && ev.ResponsePair != nil {
			t.Logf("Response pair detected:")
			t.Logf("  Response1: status=%d, length=%d", ev.ResponsePair.Response1.StatusCode, ev.ResponsePair.Response1.ContentLength)
			t.Logf("  Response2: status=%d, length=%d", ev.ResponsePair.Response2.StatusCode, ev.ResponsePair.Response2.ContentLength)
		}
	}

	t.Logf("Differential analysis result: vulnerable=%v, confidence=%.2f, has_differential=%v",
		result.Vulnerable, result.Confidence, hasDifferentialEvidence)
}

// TestErrorIndicators tests error-based smuggling detection
func TestErrorIndicators(t *testing.T) {
	tests := []struct {
		name           string
		responseBody   string
		expectDetected bool
	}{
		{
			name:           "contains smuggling indicator - bad request",
			responseBody:   "400 Bad Request - Invalid Content-Length",
			expectDetected: true,
		},
		{
			name:           "contains smuggling indicator - chunk error",
			responseBody:   "Error parsing chunked encoding",
			expectDetected: true,
		},
		{
			name:           "normal response - no indicators",
			responseBody:   "Welcome to the homepage",
			expectDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.expectDetected {
					w.WriteHeader(http.StatusBadRequest)
				} else {
					w.WriteHeader(http.StatusOK)
				}
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			config := &SmugglingConfig{
				Timeout:              5 * time.Second,
				UserAgent:            "test-agent",
				EnableTimingAnalysis: false,
			}

			client := &http.Client{Timeout: config.Timeout}
			detector := NewDetector(client, config)

			payload := SmugglingPayload{
				Name:      "Error Detection",
				Technique: TechniqueCLTE,
				Request1: `POST / HTTP/1.1
Host: TARGET

`,
				Request2: `GET / HTTP/1.1
Host: TARGET

`,
			}

			ctx := context.Background()
			result := detector.TestCLTE(ctx, server.URL, payload)

			hasErrorEvidence := false
			for _, ev := range result.Evidence {
				if ev.Type == DetectionError {
					hasErrorEvidence = true
					t.Logf("Found error evidence: %s", ev.Description)
				}
			}

			if tt.expectDetected && !hasErrorEvidence {
				t.Error("Expected error indicator to be detected")
			}

			t.Logf("Error detection result: detected=%v, vulnerable=%v",
				hasErrorEvidence, result.Vulnerable)
		})
	}
}

// TestExtractHost tests host extraction from URLs
func TestExtractHost(t *testing.T) {
	config := &SmugglingConfig{
		Timeout:   5 * time.Second,
		UserAgent: "test-agent",
	}

	client := &http.Client{Timeout: config.Timeout}
	detector := NewDetector(client, config)

	tests := []struct {
		target       string
		expectedHost string
	}{
		{
			target:       "http://example.com",
			expectedHost: "example.com",
		},
		{
			target:       "https://example.com",
			expectedHost: "example.com",
		},
		{
			target:       "https://example.com:8443",
			expectedHost: "example.com:8443",
		},
		{
			target:       "example.com",
			expectedHost: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			host := detector.extractHost(tt.target)
			if host != tt.expectedHost {
				t.Errorf("Expected host '%s', got '%s'", tt.expectedHost, host)
			}
		})
	}
}

// TestSendRawRequest tests raw HTTP request sending
func TestSendRawRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and path
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/test" {
			t.Errorf("Expected /test, got %s", r.URL.Path)
		}

		// Check custom header
		if r.Header.Get("X-Custom") != "test-value" {
			t.Errorf("Expected X-Custom header")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Test response"))
	}))
	defer server.Close()

	config := &SmugglingConfig{
		Timeout:   5 * time.Second,
		UserAgent: "test-agent",
	}

	client := &http.Client{Timeout: config.Timeout}
	detector := NewDetector(client, config)

	rawRequest := `POST /test HTTP/1.1
Host: TARGET
X-Custom: test-value
Content-Length: 11

Request body`

	ctx := context.Background()
	resp, err := detector.sendRawRequest(ctx, server.URL, rawRequest)
	if err != nil {
		t.Fatalf("sendRawRequest failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if resp.Body != "Test response" {
		t.Errorf("Expected 'Test response', got '%s'", resp.Body)
	}

	t.Logf("Raw request successful: status=%d, time=%v", resp.StatusCode, resp.Time)
}

// TestConcurrentDetection tests concurrent smuggling detection
func TestConcurrentDetection(t *testing.T) {
	// Run with: go test -race
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Response"))
	}))
	defer server.Close()

	config := &SmugglingConfig{
		Timeout:              5 * time.Second,
		UserAgent:            "test-agent",
		EnableTimingAnalysis: true,
	}

	done := make(chan bool, 5)

	for i := 0; i < 5; i++ {
		go func(id int) {
			defer func() { done <- true }()

			client := &http.Client{Timeout: config.Timeout}
			detector := NewDetector(client, config)

			payload := SmugglingPayload{
				Name:      fmt.Sprintf("Concurrent Test %d", id),
				Technique: TechniqueCLTE,
				Request1: `POST / HTTP/1.1
Host: TARGET

`,
				Request2: `GET / HTTP/1.1
Host: TARGET

`,
			}

			ctx := context.Background()
			result := detector.TestCLTE(ctx, server.URL, payload)
			t.Logf("Concurrent detection %d: vulnerable=%v", id, result.Vulnerable)
		}(i)
	}

	// Wait for all detections
	for i := 0; i < 5; i++ {
		<-done
	}
}

// BenchmarkCLTEDetection benchmarks CL.TE smuggling detection
func BenchmarkCLTEDetection(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Response"))
	}))
	defer server.Close()

	config := &SmugglingConfig{
		Timeout:              5 * time.Second,
		UserAgent:            "test-agent",
		EnableTimingAnalysis: false,
	}

	client := &http.Client{Timeout: config.Timeout}
	detector := NewDetector(client, config)

	payload := SmugglingPayload{
		Name:      "Benchmark",
		Technique: TechniqueCLTE,
		Request1: `POST / HTTP/1.1
Host: TARGET

`,
		Request2: `GET / HTTP/1.1
Host: TARGET

`,
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.TestCLTE(ctx, server.URL, payload)
	}
}

// BenchmarkTECLDetection benchmarks TE.CL smuggling detection
func BenchmarkTECLDetection(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Response"))
	}))
	defer server.Close()

	config := &SmugglingConfig{
		Timeout:              5 * time.Second,
		UserAgent:            "test-agent",
		EnableTimingAnalysis: false,
	}

	client := &http.Client{Timeout: config.Timeout}
	detector := NewDetector(client, config)

	payload := SmugglingPayload{
		Name:      "Benchmark",
		Technique: TechniqueTECL,
		Request1: `POST / HTTP/1.1
Host: TARGET
Transfer-Encoding: chunked

0

`,
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.TestTECL(ctx, server.URL, payload)
	}
}
