package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/common"
)

// mockLogger implements common.Logger for testing
type mockLogger struct{}

func (m *mockLogger) Info(msg string, keysAndValues ...interface{})  {}
func (m *mockLogger) Debug(msg string, keysAndValues ...interface{}) {}
func (m *mockLogger) Warn(msg string, keysAndValues ...interface{})  {}
func (m *mockLogger) Error(msg string, keysAndValues ...interface{}) {}

// TestNewOAuth2Scanner tests scanner initialization
func TestNewOAuth2Scanner(t *testing.T) {
	logger := &mockLogger{}
	scanner := NewOAuth2Scanner(logger)

	if scanner == nil {
		t.Fatal("Expected scanner to be initialized")
	}

	if scanner.httpClient == nil {
		t.Error("Expected HTTP client to be initialized")
	}

	if scanner.jwtAnalyzer == nil {
		t.Error("Expected JWT analyzer to be initialized")
	}

	if scanner.flowAnalyzer == nil {
		t.Error("Expected flow analyzer to be initialized")
	}
}

// TestOAuth2Scan_JWTAlgorithmConfusion tests JWT 'none' algorithm attack
func TestOAuth2Scan_JWTAlgorithmConfusion(t *testing.T) {
	tests := []struct {
		name              string
		jwtToken          string
		expectVulnerable  bool
		vulnerabilityType string
	}{
		{
			name: "vulnerable to 'none' algorithm",
			// JWT with "alg": "none"
			jwtToken:          "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0IiwiYWRtaW4iOnRydWV9.",
			expectVulnerable:  true,
			vulnerabilityType: "JWT Algorithm Confusion",
		},
		{
			name: "vulnerable to RS256 to HS256 confusion",
			// JWT that could be verified with public key as HMAC secret
			jwtToken:          createMaliciousJWT("HS256", map[string]interface{}{"sub": "test", "admin": true}),
			expectVulnerable:  true,
			vulnerabilityType: "RS256 to HS256",
		},
		{
			name: "properly signed JWT",
			// Properly signed JWT with RS256
			jwtToken:          createValidJWT("RS256", map[string]interface{}{"sub": "test"}),
			expectVulnerable:  false,
			vulnerabilityType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/.well-known/openid-configuration") {
					config := map[string]interface{}{
						"issuer":                 server.URL,
						"authorization_endpoint": server.URL + "/oauth/authorize",
						"token_endpoint":         server.URL + "/oauth/token",
						"jwks_uri":               server.URL + "/oauth/jwks",
					}
					json.NewEncoder(w).Encode(config)
					return
				}

				if strings.Contains(r.URL.Path, "/oauth/token") {
					// Return the test JWT token
					response := map[string]string{
						"access_token": tt.jwtToken,
						"token_type":   "Bearer",
					}
					json.NewEncoder(w).Encode(response)
					return
				}

				if strings.Contains(r.URL.Path, "/oauth/jwks") {
					// Return JWKS
					jwks := map[string]interface{}{
						"keys": []map[string]interface{}{
							{
								"kty": "RSA",
								"kid": "test-key",
								"use": "sig",
								"n":   base64.RawURLEncoding.EncodeToString([]byte("test-modulus")),
								"e":   "AQAB",
							},
						},
					}
					json.NewEncoder(w).Encode(jwks)
					return
				}

				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			// Create scanner
			logger := &mockLogger{}
			scanner := NewOAuth2Scanner(logger)

			// Run scan
			report, err := scanner.Scan(server.URL, nil)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			// Verify results
			if tt.expectVulnerable {
				if len(report.Vulnerabilities) == 0 {
					t.Error("Expected JWT vulnerabilities but found none")
				}

				// Check for specific vulnerability type
				if tt.vulnerabilityType != "" {
					found := false
					for _, vuln := range report.Vulnerabilities {
						if strings.Contains(vuln.Title, tt.vulnerabilityType) ||
							strings.Contains(vuln.Description, tt.vulnerabilityType) {
							found = true

							// Verify severity is critical for algorithm confusion
							if vuln.Severity != common.SeverityCritical {
								t.Errorf("Expected CRITICAL severity for %s, got %s",
									tt.vulnerabilityType, vuln.Severity)
							}
							break
						}
					}

					if !found {
						t.Errorf("Expected %s vulnerability but didn't find it", tt.vulnerabilityType)
					}
				}
			}

			// Verify report structure
			if report.Target != server.URL {
				t.Errorf("Expected target %s, got %s", server.URL, report.Target)
			}
		})
	}
}

// TestOAuth2Scan_PKCEBypass tests PKCE bypass detection
func TestOAuth2Scan_PKCEBypass(t *testing.T) {
	tests := []struct {
		name             string
		supportsPKCE     bool
		requiresPKCE     bool
		expectVulnerable bool
	}{
		{
			name:             "missing PKCE support",
			supportsPKCE:     false,
			requiresPKCE:     false,
			expectVulnerable: true,
		},
		{
			name:             "optional PKCE (not enforced)",
			supportsPKCE:     true,
			requiresPKCE:     false,
			expectVulnerable: true,
		},
		{
			name:             "PKCE required",
			supportsPKCE:     true,
			requiresPKCE:     true,
			expectVulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/.well-known/openid-configuration") {
					config := map[string]interface{}{
						"issuer":                           server.URL,
						"authorization_endpoint":           server.URL + "/oauth/authorize",
						"token_endpoint":                   server.URL + "/oauth/token",
						"code_challenge_methods_supported": []string{},
					}

					if tt.supportsPKCE {
						config["code_challenge_methods_supported"] = []string{"S256"}
					}

					json.NewEncoder(w).Encode(config)
					return
				}

				if strings.Contains(r.URL.Path, "/oauth/token") {
					// Check if PKCE is required
					if tt.requiresPKCE {
						verifier := r.FormValue("code_verifier")
						if verifier == "" {
							w.WriteHeader(http.StatusBadRequest)
							json.NewEncoder(w).Encode(map[string]string{
								"error": "code_verifier required",
							})
							return
						}
					}

					// Return token
					response := map[string]string{
						"access_token": "test-token",
						"token_type":   "Bearer",
					}
					json.NewEncoder(w).Encode(response)
					return
				}

				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			logger := &mockLogger{}
			scanner := NewOAuth2Scanner(logger)

			report, err := scanner.Scan(server.URL, nil)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			if tt.expectVulnerable {
				// Should detect PKCE bypass vulnerability
				found := false
				for _, vuln := range report.Vulnerabilities {
					if strings.Contains(vuln.Title, "PKCE") ||
						strings.Contains(vuln.Description, "PKCE") {
						found = true

						// Verify CWE and CVSS
						if vuln.CWE == "" {
							t.Error("Expected CWE to be set for PKCE vulnerability")
						}
						break
					}
				}

				if !found {
					t.Error("Expected PKCE bypass vulnerability to be detected")
				}
			}
		})
	}
}

// TestOAuth2Scan_StateValidation tests state parameter validation
func TestOAuth2Scan_StateValidation(t *testing.T) {
	tests := []struct {
		name             string
		validatesState   bool
		expectVulnerable bool
	}{
		{
			name:             "missing state parameter validation",
			validatesState:   false,
			expectVulnerable: true,
		},
		{
			name:             "weak state validation",
			validatesState:   true,
			expectVulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/.well-known/openid-configuration") {
					config := map[string]interface{}{
						"issuer":                 server.URL,
						"authorization_endpoint": server.URL + "/oauth/authorize",
						"token_endpoint":         server.URL + "/oauth/token",
					}
					json.NewEncoder(w).Encode(config)
					return
				}

				if strings.Contains(r.URL.Path, "/oauth/authorize") {
					// Check state parameter
					state := r.URL.Query().Get("state")
					if !tt.validatesState || state != "" {
						// Redirect with code
						redirectURI := r.URL.Query().Get("redirect_uri")
						if redirectURI != "" {
							http.Redirect(w, r, redirectURI+"?code=test-code&state="+state, http.StatusFound)
							return
						}
					}
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			logger := &mockLogger{}
			scanner := NewOAuth2Scanner(logger)

			report, err := scanner.Scan(server.URL, nil)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			if tt.expectVulnerable {
				found := false
				for _, vuln := range report.Vulnerabilities {
					if strings.Contains(vuln.Title, "State") ||
						strings.Contains(vuln.Title, "CSRF") {
						found = true
						break
					}
				}

				if !found {
					t.Error("Expected state validation vulnerability to be detected")
				}
			}
		})
	}
}

// TestOAuth2Scan_ScopeEscalation tests scope escalation detection
func TestOAuth2Scan_ScopeEscalation(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/.well-known/openid-configuration") {
			config := map[string]interface{}{
				"issuer":           server.URL,
				"token_endpoint":   server.URL + "/oauth/token",
				"scopes_supported": []string{"read", "write", "admin"},
			}
			json.NewEncoder(w).Encode(config)
			return
		}

		if strings.Contains(r.URL.Path, "/oauth/token") {
			// Vulnerable: grants more scopes than requested
			requestedScope := r.FormValue("scope")
			response := map[string]interface{}{
				"access_token": createJWTWithScopes([]string{"read", "write", "admin"}),
				"token_type":   "Bearer",
				"scope":        "read write admin", // Escalated from requested scope
			}

			if requestedScope == "read" {
				// Should only grant "read" but grants all
			}

			json.NewEncoder(w).Encode(response)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	logger := &mockLogger{}
	scanner := NewOAuth2Scanner(logger)

	report, err := scanner.Scan(server.URL, nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect scope escalation
	found := false
	for _, vuln := range report.Vulnerabilities {
		if strings.Contains(vuln.Title, "Scope") ||
			strings.Contains(vuln.Description, "escalation") {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected scope escalation vulnerability to be detected")
	}
}

// TestJWTAnalyzer_AlgorithmNone tests 'none' algorithm detection
func TestJWTAnalyzer_AlgorithmNone(t *testing.T) {
	logger := &mockLogger{}
	analyzer := NewJWTAnalyzer(logger)

	// Create JWT with "alg": "none"
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test","admin":true}`))
	token := header + "." + payload + "."

	vulns := analyzer.AnalyzeToken(token)

	// Should detect 'none' algorithm vulnerability
	if len(vulns) == 0 {
		t.Fatal("Expected vulnerabilities for 'none' algorithm")
	}

	found := false
	for _, vuln := range vulns {
		if strings.Contains(vuln.Title, "none") ||
			strings.Contains(vuln.Title, "Algorithm") {
			found = true

			// Verify severity
			if vuln.Severity != common.SeverityCritical {
				t.Errorf("Expected CRITICAL severity, got %s", vuln.Severity)
			}
			break
		}
	}

	if !found {
		t.Error("Expected 'none' algorithm vulnerability in results")
	}
}

// TestConcurrentOAuth2Scans tests concurrent scanning for race conditions
func TestConcurrentOAuth2Scans(t *testing.T) {
	// Run with: go test -race
	logger := &mockLogger{}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer": server.URL,
		})
	}))
	defer server.Close()

	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()

			scanner := NewOAuth2Scanner(logger)
			_, err := scanner.Scan(server.URL, nil)
			if err != nil {
				t.Errorf("Concurrent scan failed: %v", err)
			}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// Helper functions

func createMaliciousJWT(alg string, claims map[string]interface{}) string {
	header := map[string]string{"alg": alg, "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	return headerB64 + "." + claimsB64 + ".fake-signature"
}

func createValidJWT(alg string, claims map[string]interface{}) string {
	// For testing purposes, just create a properly formatted JWT
	// In production, this would be properly signed
	header := map[string]string{"alg": alg, "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	return headerB64 + "." + claimsB64 + ".valid-signature"
}

func createJWTWithScopes(scopes []string) string {
	claims := map[string]interface{}{
		"sub":   "test",
		"scope": strings.Join(scopes, " "),
	}
	return createValidJWT("HS256", claims)
}

// BenchmarkOAuth2Scan benchmarks OAuth2 scanning performance
func BenchmarkOAuth2Scan(b *testing.B) {
	logger := &mockLogger{}
	scanner := NewOAuth2Scanner(logger)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer": server.URL,
		})
	}))
	defer server.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(server.URL, nil)
	}
}

// BenchmarkJWTAnalysis benchmarks JWT analysis performance
func BenchmarkJWTAnalysis(b *testing.B) {
	logger := &mockLogger{}
	analyzer := NewJWTAnalyzer(logger)

	token := createValidJWT("HS256", map[string]interface{}{"sub": "test"})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.AnalyzeToken(token)
	}
}
