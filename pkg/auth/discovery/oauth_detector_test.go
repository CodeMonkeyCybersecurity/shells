package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOAuthDetector(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)
	
	detector := NewOAuthDetector(logger)
	
	assert.NotNil(t, detector)
	assert.NotNil(t, detector.logger)
	assert.NotNil(t, detector.httpClient)
	assert.NotNil(t, detector.patterns)
}

func TestOAuthDetector_DetectOAuth(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	// Create test server with OAuth endpoints
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid_configuration":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"issuer": "` + server.URL + `",
				"authorization_endpoint": "` + server.URL + `/oauth/authorize",
				"token_endpoint": "` + server.URL + `/oauth/token",
				"userinfo_endpoint": "` + server.URL + `/oauth/userinfo",
				"jwks_uri": "` + server.URL + `/.well-known/jwks.json",
				"response_types_supported": ["code", "token"],
				"grant_types_supported": ["authorization_code", "implicit"],
				"scopes_supported": ["openid", "profile", "email"],
				"code_challenge_methods_supported": ["S256", "plain"]
			}`))
		case "/oauth/authorize":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "invalid_request"}`))
		case "/oauth/token":
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("WWW-Authenticate", "Bearer")
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`
				<html>
					<script>
						const CLIENT_ID = "test-client-123";
						const authURL = "/oauth/authorize?client_id=" + CLIENT_ID + "&state=abc123";
					</script>
				</html>
			`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	detector := NewOAuthDetector(logger)
	ctx := context.Background()

	discovery, err := detector.DetectOAuth(ctx, server.URL)
	
	require.NoError(t, err)
	require.NotNil(t, discovery)
	
	assert.True(t, discovery.OpenIDConnect)
	assert.Equal(t, server.URL, discovery.Issuer)
	assert.Equal(t, server.URL+"/oauth/authorize", discovery.AuthorizationEndpoint)
	assert.Equal(t, server.URL+"/oauth/token", discovery.TokenEndpoint)
	assert.True(t, discovery.PKCESupported)
	assert.Contains(t, discovery.ResponseTypesSupported, "code")
	assert.Contains(t, discovery.GrantTypesSupported, "authorization_code")
	assert.Greater(t, discovery.Confidence, 0.8)
}

func TestOAuthDetector_DetectOAuth_NoOAuth(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	// Create test server without OAuth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>No OAuth here</body></html>"))
	}))
	defer server.Close()

	detector := NewOAuthDetector(logger)
	ctx := context.Background()

	discovery, err := detector.DetectOAuth(ctx, server.URL)
	
	assert.NoError(t, err)
	assert.Nil(t, discovery) // Should return nil when confidence is too low
}

func TestOAuthDetector_AnalyzeOAuthSecurity(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	detector := NewOAuthDetector(logger)

	tests := []struct {
		name                  string
		discovery             *OAuth2Discovery
		expectedFeatures      []string
		expectedVulns         []string
	}{
		{
			name: "secure OAuth configuration",
			discovery: &OAuth2Discovery{
				PKCESupported:              true,
				JWKSUri:                   "https://example.com/.well-known/jwks.json",
				SigningAlgValues:          []string{"RS256", "ES256"},
				TokenEndpointAuthMethods:  []string{"client_secret_jwt", "private_key_jwt"},
			},
			expectedFeatures: []string{"PKCE Protection", "JWT Key Rotation", "Signed ID Tokens"},
			expectedVulns:    []string{},
		},
		{
			name: "insecure OAuth configuration",
			discovery: &OAuth2Discovery{
				PKCESupported:              false,
				SigningAlgValues:          []string{"none"},
				TokenEndpointAuthMethods:  []string{"none"},
				ResponseTypesSupported:    []string{"code"},
			},
			expectedFeatures: []string{},
			expectedVulns:    []string{"PKCE not supported", "Unsigned tokens allowed", "Weak client authentication"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector.analyzeOAuthSecurity(tt.discovery)
			
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

// Fuzz testing for OAuth detector
func FuzzOAuthDetector_DetectOAuth(f *testing.F) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "error", // Reduce noise in fuzz tests
		Format: "console",
	})
	if err != nil {
		f.Fatal(err)
	}

	detector := NewOAuthDetector(logger)

	// Seed with various OAuth-related inputs
	testInputs := []string{
		"https://example.com",
		"https://auth0.com",
		"https://accounts.google.com",
		"https://login.microsoftonline.com",
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
		discovery, err := detector.DetectOAuth(ctx, target)
		
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
func BenchmarkOAuthDetector_DetectOAuth(b *testing.B) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "error",
		Format: "console",
	})
	if err != nil {
		b.Fatal(err)
	}

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid_configuration" {
			w.Write([]byte(`{"issuer": "test", "authorization_endpoint": "/auth"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	detector := NewOAuthDetector(logger)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = detector.DetectOAuth(ctx, server.URL)
	}
}

func TestOAuthDetector_GenerateOAuthPaths(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	detector := NewOAuthDetector(logger)
	paths := detector.generateOAuthPaths("https://example.com")
	
	assert.NotEmpty(t, paths)
	assert.Contains(t, paths, "https://example.com/oauth/authorize")
	assert.Contains(t, paths, "https://example.com/oauth2/token")
	assert.Contains(t, paths, "https://example.com/connect/userinfo")
}

func TestOAuthDetector_EdgeCases(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	detector := NewOAuthDetector(logger)
	ctx := context.Background()

	tests := []struct {
		name   string
		target string
	}{
		{"empty target", ""},
		{"invalid URL", "not-a-url"},
		{"unsupported scheme", "ftp://example.com"},
		{"very long URL", "https://" + strings.Repeat("a", 1000) + ".com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			require.NotPanics(t, func() {
				_, _ = detector.DetectOAuth(ctx, tt.target)
			})
		})
	}
}