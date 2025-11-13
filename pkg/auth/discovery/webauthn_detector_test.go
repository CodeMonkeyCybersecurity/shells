package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWebAuthnDetector(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	detector := NewWebAuthnDetector(logger)

	assert.NotNil(t, detector)
	assert.NotNil(t, detector.logger)
	assert.NotNil(t, detector.httpClient)
	assert.NotNil(t, detector.patterns)
}

func TestWebAuthnDetector_DetectWebAuthn(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	// Create test server with WebAuthn implementation
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`
				<html>
					<script>
						const rpId = "example.com";
						const rpName = "Example Corp";
						
						function authenticate() {
							navigator.credentials.get({
								publicKey: {
									challenge: new Uint8Array(32),
									allowCredentials: [],
									userVerification: "required",
									authenticatorSelection: {
										authenticatorAttachment: "platform",
										residentKey: "preferred"
									}
								}
							});
						}
						
						function register() {
							navigator.credentials.create({
								publicKey: {
									rp: { id: rpId, name: rpName },
									user: { id: new Uint8Array(16), name: "test", displayName: "Test User" },
									challenge: new Uint8Array(32),
									pubKeyCredParams: [
										{ alg: -7, type: "public-key" },
										{ alg: -257, type: "public-key" }
									],
									authenticatorSelection: {
										authenticatorAttachment: "cross-platform",
										userVerification: "required"
									},
									attestation: "direct"
								}
							});
						}
					</script>
				</html>
			`))
		case "/webauthn/register":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"challenge": "dGVzdC1jaGFsbGVuZ2U",
				"rp": {"id": "example.com", "name": "Example"},
				"user": {"id": "dGVzdA", "name": "test", "displayName": "Test"},
				"pubKeyCredParams": [{"alg": -7, "type": "public-key"}]
			}`))
		case "/webauthn/authenticate":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"challenge": "dGVzdC1jaGFsbGVuZ2U",
				"allowCredentials": [],
				"userVerification": "required"
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	detector := NewWebAuthnDetector(logger)
	ctx := context.Background()

	discovery, err := detector.DetectWebAuthn(ctx, server.URL)

	require.NoError(t, err)
	require.NotNil(t, discovery)

	assert.Equal(t, "example.com", discovery.RPID)
	assert.Equal(t, "Example Corp", discovery.RPName)
	assert.Equal(t, "required", discovery.UserVerification)
	assert.Contains(t, discovery.AttachmentModes, "platform")
	assert.Contains(t, discovery.AttachmentModes, "cross-platform")
	assert.Contains(t, discovery.SecurityFeatures, "Navigator Credentials API")
	assert.Contains(t, discovery.SecurityFeatures, "User Verification Required")
	assert.Greater(t, discovery.Confidence, 0.8)
}

func TestWebAuthnDetector_DetectWebAuthn_NoWebAuthn(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	// Create test server without WebAuthn
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>No WebAuthn here</body></html>"))
	}))
	defer server.Close()

	detector := NewWebAuthnDetector(logger)
	ctx := context.Background()

	discovery, err := detector.DetectWebAuthn(ctx, server.URL)

	assert.NoError(t, err)
	assert.Nil(t, discovery) // Should return nil when confidence is too low
}

func TestWebAuthnDetector_AnalyzeWebAuthnSecurity(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	detector := NewWebAuthnDetector(logger)

	tests := []struct {
		name             string
		discovery        *WebAuthn2Discovery
		expectedFeatures []string
		expectedVulns    []string
	}{
		{
			name: "secure WebAuthn configuration",
			discovery: &WebAuthn2Discovery{
				RPID:             "example.com",
				UserVerification: "required",
				ResidentKeys:     "required",
				Algorithms:       []Algorithm{{Name: "ES256", ID: -7}},
				TransportMethods: []string{"internal", "usb"},
				JSImplementation: &JSWebAuthnImpl{HasNavigatorCredentials: true, ErrorHandling: []string{"WebAuthn Error Handling"}},
			},
			expectedFeatures: []string{"Strong User Verification", "Resident Keys", "Cryptographic Algorithms"},
			expectedVulns:    []string{},
		},
		{
			name: "insecure WebAuthn configuration",
			discovery: &WebAuthn2Discovery{
				RPID:             "",
				UserVerification: "discouraged",
				TransportMethods: []string{"nfc", "ble"},
				JSImplementation: &JSWebAuthnImpl{HasNavigatorCredentials: false, ErrorHandling: []string{}},
			},
			expectedFeatures: []string{},
			expectedVulns:    []string{"User verification discouraged", "Missing RP ID", "Only wireless transports", "Missing navigator.credentials", "Insufficient error handling"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector.analyzeWebAuthnSecurity(tt.discovery)

			for _, expectedFeature := range tt.expectedFeatures {
				found := false
				for _, feature := range tt.discovery.SecurityFeatures {
					if strings.Contains(feature, expectedFeature) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected security feature '%s' not found", expectedFeature)
			}

			for _, expectedVuln := range tt.expectedVulns {
				found := false
				for _, vuln := range tt.discovery.Vulnerabilities {
					if strings.Contains(vuln, expectedVuln) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected vulnerability '%s' not found", expectedVuln)
			}
		})
	}
}

func TestWebAuthnDetector_GenerateWebAuthnPaths(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	detector := NewWebAuthnDetector(logger)
	paths := detector.generateWebAuthnPaths("https://example.com")

	assert.NotEmpty(t, paths)
	assert.Contains(t, paths, "https://example.com/webauthn")
	assert.Contains(t, paths, "https://example.com/webauthn/register")
	assert.Contains(t, paths, "https://example.com/fido2/authenticate")
	assert.Contains(t, paths, "https://example.com/u2f")
}

// Fuzz testing for WebAuthn detector
func FuzzWebAuthnDetector_DetectWebAuthn(f *testing.F) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "error", // Reduce noise in fuzz tests
		Format: "console",
	})
	if err != nil {
		f.Fatal(err)
	}

	detector := NewWebAuthnDetector(logger)

	// Seed with various WebAuthn-related inputs
	testInputs := []string{
		"https://example.com",
		"https://webauthn.io",
		"https://demo.yubico.com",
		"invalid-url",
		"",
		"javascript:alert(1)",
		strings.Repeat("a", 1000),
	}

	for _, input := range testInputs {
		f.Add(input)
	}

	f.Fuzz(func(t *testing.T, target string) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Should not panic regardless of input
		discovery, err := detector.DetectWebAuthn(ctx, target)

		// Either succeed or fail gracefully
		if err == nil && discovery != nil {
			assert.GreaterOrEqual(t, discovery.Confidence, 0.0)
			assert.LessOrEqual(t, discovery.Confidence, 1.0)
			assert.NotNil(t, discovery.SecurityFeatures)
			assert.NotNil(t, discovery.Vulnerabilities)
		}
	})
}

// Benchmark tests
func BenchmarkWebAuthnDetector_DetectWebAuthn(b *testing.B) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "error",
		Format: "console",
	})
	if err != nil {
		b.Fatal(err)
	}

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><script>navigator.credentials.get({publicKey: {}});</script></html>`))
	}))
	defer server.Close()

	detector := NewWebAuthnDetector(logger)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = detector.DetectWebAuthn(ctx, server.URL)
	}
}

func TestWebAuthnDetector_EdgeCases(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	detector := NewWebAuthnDetector(logger)
	ctx := context.Background()

	tests := []struct {
		name   string
		target string
	}{
		{"empty target", ""},
		{"invalid URL", "not-a-url"},
		{"unsupported scheme", "ftp://example.com"},
		{"very long URL", "https://" + strings.Repeat("a", 1000) + ".com"},
		{"malicious javascript URL", "javascript:alert(1)"},
		{"data URL", "data:text/html,<script>alert(1)</script>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			require.NotPanics(t, func() {
				_, _ = detector.DetectWebAuthn(ctx, tt.target)
			})
		})
	}
}

func TestWebAuthnDetector_AnalyzeJavaScriptImplementation(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	// Create test server with comprehensive WebAuthn JavaScript
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
			<html>
				<script>
					// Check for WebAuthn support
					if (navigator.credentials && PublicKeyCredential) {
						console.log("WebAuthn supported");
						
						// Registration flow
						navigator.credentials.create({
							publicKey: {
								rp: { id: "example.com", name: "Example" },
								user: { id: new Uint8Array(16), name: "test", displayName: "Test" },
								challenge: new Uint8Array(32),
								pubKeyCredParams: [{ alg: -7, type: "public-key" }]
							}
						}).catch(function(error) {
							if (error instanceof NotAllowedError) {
								console.log("User cancelled");
							}
						});
						
						// Authentication flow
						navigator.credentials.get({
							publicKey: {
								challenge: new Uint8Array(32),
								allowCredentials: []
							}
						}).catch(function(error) {
							if (error instanceof SecurityError) {
								console.log("Security error");
							}
						});
					}
				</script>
			</html>
		`))
	}))
	defer server.Close()

	detector := NewWebAuthnDetector(logger)
	jsImpl := detector.analyzeJavaScriptImplementation(context.Background(), server.URL)

	require.NotNil(t, jsImpl)
	assert.True(t, jsImpl.HasNavigatorCredentials)
	assert.True(t, jsImpl.HasPublicKeyCredential)
	assert.Contains(t, jsImpl.RegistrationFlow, "navigator.credentials.create()")
	assert.Contains(t, jsImpl.AuthenticationFlow, "navigator.credentials.get()")
	assert.Contains(t, jsImpl.ErrorHandling, "WebAuthn Error Handling")
}
