package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// TestNewScanner tests scanner initialization
func TestNewScanner(t *testing.T) {
	scanner := NewScanner()

	if scanner == nil {
		t.Fatal("Expected scanner to be initialized")
	}

	if scanner.Name() != "scim" {
		t.Errorf("Expected scanner name to be 'scim', got '%s'", scanner.Name())
	}

	if scanner.Type() != types.ScanType("scim") {
		t.Errorf("Expected scanner type to be 'scim', got '%s'", scanner.Type())
	}
}

// TestValidate tests target URL validation
func TestValidate(t *testing.T) {
	scanner := NewScanner().(*Scanner)

	tests := []struct {
		name        string
		target      string
		expectError bool
	}{
		{
			name:        "valid HTTP URL",
			target:      "http://example.com",
			expectError: false,
		},
		{
			name:        "valid HTTPS URL",
			target:      "https://example.com",
			expectError: false,
		},
		{
			name:        "empty URL",
			target:      "",
			expectError: true,
		},
		{
			name:        "invalid scheme",
			target:      "ftp://example.com",
			expectError: true,
		},
		{
			name:        "malformed URL",
			target:      "not a url",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := scanner.Validate(tt.target)
			if tt.expectError && err == nil {
				t.Error("Expected validation error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

// TestScan_UnauthorizedAccess tests detection of unauthorized SCIM access
func TestScan_UnauthorizedAccess(t *testing.T) {
	tests := []struct {
		name             string
		requiresAuth     bool
		expectVulnerable bool
	}{
		{
			name:             "vulnerable - no auth required",
			requiresAuth:     false,
			expectVulnerable: true,
		},
		{
			name:             "secure - auth required",
			requiresAuth:     true,
			expectVulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock SCIM server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/scim/v2"):
					// Serve SCIM discovery document
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]interface{}{
						"schemas": []string{
							"urn:ietf:params:scim:api:messages:2.0:ServiceProviderConfig",
						},
						"documentationUri": server.URL + "/scim/docs",
					})

				case strings.Contains(r.URL.Path, "/Users"):
					// Check authentication
					if tt.requiresAuth {
						authHeader := r.Header.Get("Authorization")
						if authHeader == "" {
							w.WriteHeader(http.StatusUnauthorized)
							json.NewEncoder(w).Encode(map[string]string{
								"detail": "Authentication required",
							})
							return
						}
					}

					// Return user list (vulnerable if no auth check)
					w.Header().Set("Content-Type", "application/scim+json")
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
						"totalResults": 2,
						"Resources": []map[string]interface{}{
							{
								"id":       "user1",
								"userName": "admin@example.com",
								"active":   true,
							},
							{
								"id":       "user2",
								"userName": "user@example.com",
								"active":   true,
							},
						},
					})

				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			// Run scan
			scanner := NewScanner()
			ctx := context.Background()
			findings, err := scanner.Scan(ctx, server.URL+"/scim/v2", nil)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			// Check for unauthorized access vulnerability
			if tt.expectVulnerable {
				foundVuln := false
				for _, finding := range findings {
					if finding.Type == VulnSCIMUnauthorizedAccess {
						foundVuln = true
						// Verify severity
						if finding.Severity != types.SeverityHigh {
							t.Errorf("Expected HIGH severity, got %s", finding.Severity)
						}
						break
					}
				}
				if !foundVuln {
					t.Error("Expected unauthorized access vulnerability to be detected")
				}
			} else {
				// Should not find unauthorized access vulnerability
				for _, finding := range findings {
					if finding.Type == VulnSCIMUnauthorizedAccess {
						t.Error("Unexpected unauthorized access vulnerability found")
						break
					}
				}
			}
		})
	}
}

// TestScan_WeakAuthentication tests detection of weak authentication
func TestScan_WeakAuthentication(t *testing.T) {
	// Create mock SCIM server with weak credentials
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/scim/v2"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ServiceProviderConfig"},
			})

		case strings.Contains(r.URL.Path, "/Users"):
			// Check for weak credentials
			username, password, ok := r.BasicAuth()
			if ok && username == "admin" && password == "admin" {
				// Accept weak credentials (vulnerable)
				w.Header().Set("Content-Type", "application/scim+json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
					"totalResults": 1,
					"Resources":    []map[string]interface{}{},
				})
				return
			}

			w.WriteHeader(http.StatusUnauthorized)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	scanner := NewScanner()
	ctx := context.Background()
	findings, err := scanner.Scan(ctx, server.URL+"/scim/v2", nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect weak authentication vulnerability
	foundVuln := false
	for _, finding := range findings {
		if finding.Type == VulnSCIMWeakAuthentication {
			foundVuln = true
			// Verify severity is critical
			if finding.Severity != types.SeverityCritical {
				t.Errorf("Expected CRITICAL severity for weak auth, got %s", finding.Severity)
			}
			break
		}
	}

	if !foundVuln {
		t.Error("Expected weak authentication vulnerability to be detected")
	}
}

// TestScan_FilterInjection tests filter injection detection
func TestScan_FilterInjection(t *testing.T) {
	// Create mock SCIM server vulnerable to filter injection
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/scim/v2"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ServiceProviderConfig"},
				"filter": map[string]bool{
					"supported": true,
				},
			})

		case strings.Contains(r.URL.Path, "/Users"):
			// Check for filter parameter
			filter := r.URL.Query().Get("filter")
			if filter != "" {
				// Vulnerable: accepts any filter without validation
				if strings.Contains(filter, "or") || strings.Contains(filter, "OR") {
					// Filter injection detected
					w.Header().Set("Content-Type", "application/scim+json")
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
						"totalResults": 100, // Injected filter returns all users
						"Resources":    []map[string]interface{}{},
					})
					return
				}
			}

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
				"totalResults": 0,
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	scanner := NewScanner()
	ctx := context.Background()
	options := map[string]string{
		"test-filters": "true",
	}
	findings, err := scanner.Scan(ctx, server.URL+"/scim/v2", options)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Check for filter injection vulnerability
	t.Logf("Found %d findings", len(findings))
	for _, finding := range findings {
		t.Logf("Finding: Type=%s, Severity=%s, Title=%s", finding.Type, finding.Severity, finding.Title)
	}
}

// TestScan_BulkOperations tests bulk operation abuse detection
func TestScan_BulkOperations(t *testing.T) {
	// Create mock SCIM server supporting bulk operations
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/scim/v2"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ServiceProviderConfig"},
				"bulk": map[string]interface{}{
					"supported":     true,
					"maxOperations": 1000, // Vulnerable: too high
				},
			})

		case strings.Contains(r.URL.Path, "/Bulk"):
			// Accept bulk operations
			var bulkRequest map[string]interface{}
			json.NewDecoder(r.Body).Decode(&bulkRequest)

			w.Header().Set("Content-Type", "application/scim+json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:BulkResponse"},
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	scanner := NewScanner()
	ctx := context.Background()
	options := map[string]string{
		"test-bulk": "true",
	}
	findings, err := scanner.Scan(ctx, server.URL+"/scim/v2", options)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	t.Logf("Found %d findings for bulk operations", len(findings))
}

// TestScan_SchemaDisclosure tests schema disclosure detection
func TestScan_SchemaDisclosure(t *testing.T) {
	// Create mock SCIM server with publicly accessible schemas
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/scim/v2"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ServiceProviderConfig"},
			})

		case strings.Contains(r.URL.Path, "/Schemas"):
			// Vulnerable: schemas accessible without authentication
			w.Header().Set("Content-Type", "application/scim+json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
				"totalResults": 1,
				"Resources": []map[string]interface{}{
					{
						"id":   "urn:ietf:params:scim:schemas:core:2.0:User",
						"name": "User",
					},
				},
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	scanner := NewScanner()
	ctx := context.Background()
	findings, err := scanner.Scan(ctx, server.URL+"/scim/v2", nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Check for schema disclosure
	foundVuln := false
	for _, finding := range findings {
		if finding.Type == VulnSCIMSchemaDisclosure {
			foundVuln = true
			// Verify severity is info
			if finding.Severity != types.SeverityInfo {
				t.Errorf("Expected INFO severity for schema disclosure, got %s", finding.Severity)
			}
			break
		}
	}

	if !foundVuln {
		t.Error("Expected schema disclosure vulnerability to be detected")
	}
}

// TestScan_NoEndpoints tests behavior when no SCIM endpoints found
func TestScan_NoEndpoints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	scanner := NewScanner()
	ctx := context.Background()
	findings, err := scanner.Scan(ctx, server.URL, nil)
	if err != nil {
		t.Fatalf("Expected no error when endpoints not found, got: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected no vulnerabilities when no endpoints found, got %d", len(findings))
	}
}

// TestConfigurationOptions tests configuration options handling
func TestConfigurationOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check custom User-Agent
		userAgent := r.Header.Get("User-Agent")
		if userAgent == "custom-agent/1.0" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	scanner := NewScanner()
	ctx := context.Background()
	options := map[string]string{
		"user-agent":   "custom-agent/1.0",
		"timeout":      "5s",
		"test-auth":    "false",
		"test-filters": "false",
		"test-bulk":    "false",
	}

	_, err := scanner.Scan(ctx, server.URL, options)
	// We expect this to fail since no SCIM endpoints, but configuration should be applied
	if err != nil {
		// This is expected - we're just testing that options are processed
		t.Logf("Expected error during scan: %v", err)
	}
}

// TestConcurrentScans tests concurrent scanning for race conditions
func TestConcurrentScans(t *testing.T) {
	// Run with: go test -race
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	done := make(chan bool, 5)

	for i := 0; i < 5; i++ {
		go func(id int) {
			defer func() { done <- true }()

			scanner := NewScanner()
			ctx := context.Background()
			_, err := scanner.Scan(ctx, server.URL, nil)
			if err != nil {
				t.Logf("Concurrent scan %d error: %v", id, err)
			}
		}(i)
	}

	// Wait for all scans
	for i := 0; i < 5; i++ {
		<-done
	}
}

// BenchmarkSCIMScan benchmarks SCIM scanning performance
func BenchmarkSCIMScan(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	scanner := NewScanner()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(ctx, server.URL, nil)
	}
}

// BenchmarkSCIMDiscovery benchmarks endpoint discovery
func BenchmarkSCIMDiscovery(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/scim") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ServiceProviderConfig"},
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	scanner := NewScanner().(*Scanner)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.discoverer.DiscoverEndpoints(ctx, server.URL)
	}
}
