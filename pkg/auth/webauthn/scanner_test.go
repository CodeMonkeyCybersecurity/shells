package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/auth/common"
)

// mockLogger implements common.Logger for testing
type mockLogger struct{}

func (m *mockLogger) Info(msg string, keysAndValues ...interface{})  {}
func (m *mockLogger) Debug(msg string, keysAndValues ...interface{}) {}
func (m *mockLogger) Warn(msg string, keysAndValues ...interface{})  {}
func (m *mockLogger) Error(msg string, keysAndValues ...interface{}) {}

// TestNewWebAuthnScanner tests scanner initialization
func TestNewWebAuthnScanner(t *testing.T) {
	logger := &mockLogger{}
	scanner := NewWebAuthnScanner(logger)

	if scanner == nil {
		t.Fatal("Expected scanner to be initialized")
	}

	if scanner.httpClient == nil {
		t.Error("Expected HTTP client to be initialized")
	}

	if scanner.virtualAuth == nil {
		t.Error("Expected virtual authenticator to be initialized")
	}

	if scanner.protocolAnalyzer == nil {
		t.Error("Expected protocol analyzer to be initialized")
	}

	// Verify capabilities
	caps := scanner.GetCapabilities()
	expectedCaps := []string{
		"registration_ceremony_testing",
		"authentication_ceremony_testing",
		"virtual_authenticator_attacks",
		"challenge_reuse_detection",
		"credential_substitution",
	}

	for _, expected := range expectedCaps {
		found := false
		for _, cap := range caps {
			if cap == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected capability %s not found", expected)
		}
	}
}

// TestWebAuthnScan_CredentialSubstitution tests credential substitution detection
func TestWebAuthnScan_CredentialSubstitution(t *testing.T) {
	tests := []struct {
		name             string
		validatesCredID  bool
		expectVulnerable bool
	}{
		{
			name:             "accepts any credential ID",
			validatesCredID:  false,
			expectVulnerable: true,
		},
		{
			name:             "validates credential ID",
			validatesCredID:  true,
			expectVulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock WebAuthn server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/webauthn/register/begin"):
					// Return registration challenge
					challenge := map[string]interface{}{
						"challenge": base64.RawURLEncoding.EncodeToString([]byte("test-challenge-123")),
						"rp": map[string]string{
							"name": "Example Corp",
							"id":   "example.com",
						},
						"user": map[string]interface{}{
							"id":          base64.RawURLEncoding.EncodeToString([]byte("user123")),
							"name":        "test@example.com",
							"displayName": "Test User",
						},
						"pubKeyCredParams": []map[string]interface{}{
							{"type": "public-key", "alg": -7}, // ES256
						},
						"timeout":     60000,
						"attestation": "none",
						"authenticatorSelection": map[string]interface{}{
							"authenticatorAttachment": "cross-platform",
							"userVerification":        "preferred",
						},
					}
					json.NewEncoder(w).Encode(challenge)

				case strings.Contains(r.URL.Path, "/webauthn/register/finish"):
					// Accept any credential (vulnerable if validatesCredID is false)
					if tt.validatesCredID {
						// Check credential ID in request
						var body map[string]interface{}
						json.NewDecoder(r.Body).Decode(&body)

						credID := ""
						if rawID, ok := body["rawId"].(string); ok {
							credID = rawID
						}

						// Only accept specific credential
						if credID != base64.RawURLEncoding.EncodeToString([]byte("expected-cred-id")) {
							w.WriteHeader(http.StatusBadRequest)
							json.NewEncoder(w).Encode(map[string]string{
								"error": "invalid credential ID",
							})
							return
						}
					}

					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"status": "ok",
					})

				case strings.Contains(r.URL.Path, "/webauthn/login/begin"):
					// Return authentication challenge
					challenge := map[string]interface{}{
						"challenge": base64.RawURLEncoding.EncodeToString([]byte("auth-challenge-456")),
						"rpId":      "example.com",
						"allowCredentials": []map[string]interface{}{
							{
								"type": "public-key",
								"id":   base64.RawURLEncoding.EncodeToString([]byte("existing-cred-id")),
							},
						},
						"timeout":          60000,
						"userVerification": "preferred",
					}
					json.NewEncoder(w).Encode(challenge)

				case strings.Contains(r.URL.Path, "/webauthn/login/finish"):
					// Accept any credential response (vulnerable behavior)
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"status":       "authenticated",
						"sessionToken": "test-session-token",
					})

				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			// Run scan
			logger := &mockLogger{}
			scanner := NewWebAuthnScanner(logger)

			report, err := scanner.Scan(server.URL, nil)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			// Check for credential substitution vulnerability
			if tt.expectVulnerable {
				foundVuln := false
				for _, vuln := range report.Vulnerabilities {
					if strings.Contains(vuln.Title, "Credential") &&
						(strings.Contains(vuln.Title, "Substitution") || strings.Contains(vuln.Description, "substitution")) {
						foundVuln = true

						// Verify severity
						if vuln.Severity != common.SeverityCritical {
							t.Errorf("Expected CRITICAL severity for credential substitution, got %s", vuln.Severity)
						}
						break
					}
				}
				if !foundVuln {
					t.Error("Expected credential substitution vulnerability to be detected")
				}
			}
		})
	}
}

// TestWebAuthnScan_ChallengeReuse tests challenge reuse detection
func TestWebAuthnScan_ChallengeReuse(t *testing.T) {
	// Track challenges to detect reuse
	challengeUsed := make(map[string]bool)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/webauthn/register/begin"):
			// Always return the same challenge (vulnerable)
			staticChallenge := "reused-challenge-789"
			challenge := map[string]interface{}{
				"challenge": base64.RawURLEncoding.EncodeToString([]byte(staticChallenge)),
				"rp":        map[string]string{"name": "Example Corp", "id": "example.com"},
				"user":      map[string]interface{}{"id": "dXNlcjEyMw", "name": "test@example.com"},
			}
			json.NewEncoder(w).Encode(challenge)

		case strings.Contains(r.URL.Path, "/webauthn/register/finish"):
			// Accept challenge even if reused (vulnerable)
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	logger := &mockLogger{}
	scanner := NewWebAuthnScanner(logger)

	report, err := scanner.Scan(server.URL, nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect challenge reuse vulnerability
	foundReuse := false
	for _, vuln := range report.Vulnerabilities {
		if strings.Contains(vuln.Title, "Challenge") &&
			(strings.Contains(vuln.Title, "Reuse") || strings.Contains(vuln.Description, "reuse")) {
			foundReuse = true

			// Verify severity is high or critical
			if vuln.Severity != common.SeverityHigh && vuln.Severity != common.SeverityCritical {
				t.Errorf("Expected HIGH or CRITICAL severity for challenge reuse, got %s", vuln.Severity)
			}
			break
		}
	}

	if !foundReuse {
		t.Error("Expected challenge reuse vulnerability to be detected")
	}
}

// TestWebAuthnScan_AttestationBypass tests attestation validation bypass
func TestWebAuthnScan_AttestationBypass(t *testing.T) {
	tests := []struct {
		name                 string
		validatesAttestation bool
		expectVulnerable     bool
	}{
		{
			name:                 "accepts any attestation",
			validatesAttestation: false,
			expectVulnerable:     true,
		},
		{
			name:                 "validates attestation properly",
			validatesAttestation: true,
			expectVulnerable:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/webauthn/register/begin"):
					challenge := map[string]interface{}{
						"challenge":   "dGVzdC1jaGFsbGVuZ2U",
						"rp":          map[string]string{"name": "Example", "id": "example.com"},
						"user":        map[string]interface{}{"id": "dXNlcjEyMw", "name": "test@example.com"},
						"attestation": "direct", // Request attestation
					}
					json.NewEncoder(w).Encode(challenge)

				case strings.Contains(r.URL.Path, "/webauthn/register/finish"):
					var body map[string]interface{}
					json.NewDecoder(r.Body).Decode(&body)

					if tt.validatesAttestation {
						// Check for valid attestation
						response, ok := body["response"].(map[string]interface{})
						if !ok {
							w.WriteHeader(http.StatusBadRequest)
							return
						}

						attestationObject := response["attestationObject"]
						if attestationObject == nil {
							w.WriteHeader(http.StatusBadRequest)
							json.NewEncoder(w).Encode(map[string]string{
								"error": "missing attestation",
							})
							return
						}
					}

					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})

				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			logger := &mockLogger{}
			scanner := NewWebAuthnScanner(logger)

			report, err := scanner.Scan(server.URL, nil)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			if tt.expectVulnerable {
				foundVuln := false
				for _, vuln := range report.Vulnerabilities {
					if strings.Contains(vuln.Title, "Attestation") ||
						strings.Contains(vuln.Description, "attestation") {
						foundVuln = true
						break
					}
				}
				if !foundVuln {
					t.Error("Expected attestation bypass vulnerability to be detected")
				}
			}
		})
	}
}

// TestWebAuthnScan_UserVerificationBypass tests UV flag bypass
func TestWebAuthnScan_UserVerificationBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/webauthn/login/begin"):
			challenge := map[string]interface{}{
				"challenge":        "dGVzdC1jaGFsbGVuZ2U",
				"rpId":             "example.com",
				"userVerification": "required", // Require UV
			}
			json.NewEncoder(w).Encode(challenge)

		case strings.Contains(r.URL.Path, "/webauthn/login/finish"):
			// Vulnerable: accepts auth even without UV flag
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "authenticated",
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	logger := &mockLogger{}
	scanner := NewWebAuthnScanner(logger)

	report, err := scanner.Scan(server.URL, nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect UV bypass
	foundUVBypass := false
	for _, vuln := range report.Vulnerabilities {
		if strings.Contains(vuln.Title, "User Verification") ||
			strings.Contains(vuln.Title, "UV") ||
			strings.Contains(vuln.Description, "user verification") {
			foundUVBypass = true
			break
		}
	}

	if !foundUVBypass {
		t.Error("Expected user verification bypass vulnerability to be detected")
	}
}

// TestWebAuthnScan_OriginValidation tests origin validation
func TestWebAuthnScan_OriginValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/webauthn/register/begin"):
			challenge := map[string]interface{}{
				"challenge": "dGVzdC1jaGFsbGVuZ2U",
				"rp":        map[string]string{"name": "Example", "id": "example.com"},
				"user":      map[string]interface{}{"id": "dXNlcjEyMw", "name": "test@example.com"},
			}
			json.NewEncoder(w).Encode(challenge)

		case strings.Contains(r.URL.Path, "/webauthn/register/finish"):
			// Vulnerable: doesn't validate origin
			// Should reject responses from different origin
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	logger := &mockLogger{}
	scanner := NewWebAuthnScanner(logger)

	report, err := scanner.Scan(server.URL, nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect origin validation issues
	foundOriginIssue := false
	for _, vuln := range report.Vulnerabilities {
		if strings.Contains(vuln.Title, "Origin") ||
			strings.Contains(vuln.Description, "origin") {
			foundOriginIssue = true
			break
		}
	}

	if !foundOriginIssue {
		t.Error("Expected origin validation vulnerability to be detected")
	}
}

// TestWebAuthnScan_NoEndpoints tests behavior when no WebAuthn endpoints found
func TestWebAuthnScan_NoEndpoints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	logger := &mockLogger{}
	scanner := NewWebAuthnScanner(logger)

	report, err := scanner.Scan(server.URL, nil)
	if err != nil {
		t.Fatalf("Expected no error when endpoints not found, got: %v", err)
	}

	if len(report.Vulnerabilities) != 0 {
		t.Errorf("Expected no vulnerabilities when no endpoints found, got %d", len(report.Vulnerabilities))
	}

	if report.Target != server.URL {
		t.Errorf("Expected target to be set correctly")
	}
}

// TestConcurrentWebAuthnScans tests concurrent scanning for race conditions
func TestConcurrentWebAuthnScans(t *testing.T) {
	// Run with: go test -race
	logger := &mockLogger{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"challenge": "test",
		})
	}))
	defer server.Close()

	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()

			scanner := NewWebAuthnScanner(logger)
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

// BenchmarkWebAuthnScan benchmarks WebAuthn scanning performance
func BenchmarkWebAuthnScan(b *testing.B) {
	logger := &mockLogger{}
	scanner := NewWebAuthnScanner(logger)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"challenge": "test",
		})
	}))
	defer server.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(server.URL, nil)
	}
}
