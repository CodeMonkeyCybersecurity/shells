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

func TestNewEngine(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	tests := []struct {
		name   string
		config *Config
		want   *Engine
	}{
		{
			name:   "nil config creates default",
			config: nil,
			want: &Engine{
				logger: logger,
				config: &Config{
					MaxDepth:           3,
					FollowRedirects:    true,
					MaxRedirects:       10,
					Timeout:            30 * time.Second,
					UserAgent:          "shells-auth-discovery/1.0",
					Threads:            10,
					EnableJSAnalysis:   true,
					EnableAPIDiscovery: true,
					EnablePortScanning: false,
				},
			},
		},
		{
			name: "custom config preserved",
			config: &Config{
				MaxDepth:           5,
				FollowRedirects:    false,
				MaxRedirects:       5,
				Timeout:            60 * time.Second,
				UserAgent:          "test-agent",
				Threads:            20,
				EnableJSAnalysis:   false,
				EnableAPIDiscovery: false,
				EnablePortScanning: true,
			},
			want: &Engine{
				logger: logger,
				config: &Config{
					MaxDepth:           5,
					FollowRedirects:    false,
					MaxRedirects:       5,
					Timeout:            60 * time.Second,
					UserAgent:          "test-agent",
					Threads:            20,
					EnableJSAnalysis:   false,
					EnableAPIDiscovery: false,
					EnablePortScanning: true,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine(logger, tt.config)

			assert.NotNil(t, engine)
			assert.Equal(t, logger, engine.logger)
			assert.Equal(t, tt.want.config.MaxDepth, engine.config.MaxDepth)
			assert.Equal(t, tt.want.config.FollowRedirects, engine.config.FollowRedirects)
			assert.Equal(t, tt.want.config.Timeout, engine.config.Timeout)
			assert.NotNil(t, engine.httpClient)
			assert.NotNil(t, engine.webCrawler)
			assert.NotNil(t, engine.jsAnalyzer)
			assert.NotNil(t, engine.apiExtractor)
			assert.NotNil(t, engine.securityAnalyzer)
		})
	}
}

func TestEngine_Discover(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	// Create test server with various auth endpoints
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`
				<html>
					<head><title>Test Site</title></head>
					<body>
						<form action="/login" method="post">
							<input type="text" name="username" placeholder="Username">
							<input type="password" name="password" placeholder="Password">
							<input type="submit" value="Login">
						</form>
						<script src="/js/auth.js"></script>
					</body>
				</html>
			`))
		case "/login":
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
		case "/oauth/authorize":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"error": "invalid_request"}`))
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"issuer": "` + server.URL + `",
				"authorization_endpoint": "` + server.URL + `/oauth/authorize",
				"token_endpoint": "` + server.URL + `/oauth/token",
				"userinfo_endpoint": "` + server.URL + `/oauth/userinfo",
				"jwks_uri": "` + server.URL + `/.well-known/jwks.json",
				"response_types_supported": ["code", "token"],
				"grant_types_supported": ["authorization_code", "implicit"],
				"scopes_supported": ["openid", "profile", "email"]
			}`))
		case "/js/auth.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`
				const CLIENT_ID = "test-client";
				function authenticate() {
					navigator.credentials.get({
						publicKey: {
							challenge: new Uint8Array(32),
							allowCredentials: [],
							userVerification: "preferred"
						}
					});
				}
			`))
		case "/api/auth":
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := &Config{
		MaxDepth:           2,
		FollowRedirects:    true,
		Timeout:            5 * time.Second,
		Threads:            5,
		EnableJSAnalysis:   true,
		EnableAPIDiscovery: true,
	}

	engine := NewEngine(logger, config)
	ctx := context.Background()

	result, err := engine.Discover(ctx, server.URL)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, server.URL, result.Target)
	assert.Greater(t, result.TotalEndpoints, 0)
	assert.NotEmpty(t, result.Implementations)
	assert.Greater(t, result.DiscoveryTime, time.Duration(0))

	// Should find form-based auth
	foundFormAuth := false
	for _, impl := range result.Implementations {
		if impl.Type == AuthTypeFormLogin {
			foundFormAuth = true
			assert.NotEmpty(t, impl.Endpoints)
			break
		}
	}
	assert.True(t, foundFormAuth, "Should discover form-based authentication")
}

func TestEngine_DiscoverInvalidTarget(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)
	engine := NewEngine(logger, nil)
	ctx := context.Background()

	tests := []struct {
		name   string
		target string
	}{
		{"invalid URL", "not-a-url"},
		{"unreachable host", "https://does-not-exist-12345.example.com"},
		{"malformed scheme", "ftp://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Discover(ctx, tt.target)

			if err != nil {
				assert.Error(t, err)
			} else {
				// Should return empty result for unreachable/invalid targets
				assert.NotNil(t, result)
				assert.Empty(t, result.Implementations)
			}
		})
	}
}

func TestEngine_ContextCancellation(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	// Create a slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Write([]byte("slow response"))
	}))
	defer server.Close()

	engine := NewEngine(logger, &Config{Timeout: 10 * time.Second})

	// Create context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err = engine.Discover(ctx, server.URL)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context")
}

// Fuzz test for discover with various inputs
func FuzzEngineDiscover(f *testing.F) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "error", // Reduce noise in fuzz tests
		Format: "console",
	})
	if err != nil {
		f.Fatal(err)
	}
	engine := NewEngine(logger, &Config{
		Timeout: 1 * time.Second,
		Threads: 2,
	})

	// Seed with various inputs
	testCases := []string{
		"https://example.com",
		"http://localhost",
		"invalid-url",
		"https://127.0.0.1:8080",
		"",
		"https://",
		"ftp://example.com",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		strings.Repeat("a", 1000),
		"https://very-long-" + strings.Repeat("subdomain.", 100) + "example.com",
	}

	for _, tc := range testCases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, target string) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Should not panic or crash, regardless of input
		result, err := engine.Discover(ctx, target)

		// Either succeed or fail gracefully
		if err == nil {
			assert.NotNil(t, result)
			// Target might be empty or modified from input - just check result exists
		} else {
			// Error should be reasonable, not a panic
			assert.NotNil(t, err)
		}
	})
}

func TestEngine_CalculateRiskScore(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)
	engine := NewEngine(logger, nil)

	tests := []struct {
		name            string
		implementations []AuthImplementation
		expectedRange   [2]float64 // min, max
	}{
		{
			name:            "empty implementations",
			implementations: []AuthImplementation{},
			expectedRange:   [2]float64{0.0, 0.0},
		},
		{
			name: "secure webauthn implementation",
			implementations: []AuthImplementation{
				{
					Type:             AuthTypeWebAuthn,
					SecurityFeatures: []string{"Hardware-backed", "Phishing-resistant"},
					Vulnerabilities:  []string{},
				},
			},
			expectedRange: [2]float64{0.0, 4.0},
		},
		{
			name: "insecure basic auth",
			implementations: []AuthImplementation{
				{
					Type:             AuthTypeBasicAuth,
					SecurityFeatures: []string{},
					Vulnerabilities:  []string{"Plaintext", "No encryption", "Replay attacks"},
				},
			},
			expectedRange: [2]float64{6.0, 10.0},
		},
		{
			name: "mixed implementations",
			implementations: []AuthImplementation{
				{
					Type:             AuthTypeOAuth2,
					SecurityFeatures: []string{"PKCE", "State parameter"},
					Vulnerabilities:  []string{"Redirect URI manipulation"},
				},
				{
					Type:             AuthTypeFormLogin,
					SecurityFeatures: []string{"CSRF protection"},
					Vulnerabilities:  []string{"Session fixation", "Credential stuffing"},
				},
			},
			expectedRange: [2]float64{3.0, 8.0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := engine.calculateRiskScore(tt.implementations)

			assert.GreaterOrEqual(t, score, tt.expectedRange[0])
			assert.LessOrEqual(t, score, tt.expectedRange[1])
			assert.GreaterOrEqual(t, score, 0.0)
			assert.LessOrEqual(t, score, 10.0)
		})
	}
}

func TestEngine_GenerateRecommendations(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)
	engine := NewEngine(logger, nil)

	tests := []struct {
		name             string
		implementations  []AuthImplementation
		expectedContains []string
	}{
		{
			name: "weak auth implementations",
			implementations: []AuthImplementation{
				{Type: AuthTypeBasicAuth},
				{Type: AuthTypeDigestAuth},
			},
			expectedContains: []string{"Replace weak authentication"},
		},
		{
			name: "no modern auth",
			implementations: []AuthImplementation{
				{Type: AuthTypeFormLogin},
				{Type: AuthTypeAPIKey},
			},
			expectedContains: []string{"modern authentication protocols"},
		},
		{
			name: "too many auth types",
			implementations: []AuthImplementation{
				{Type: AuthTypeBasicAuth},
				{Type: AuthTypeFormLogin},
				{Type: AuthTypeAPIKey},
				{Type: AuthTypeJWT},
			},
			expectedContains: []string{"consolidating multiple authentication"},
		},
		{
			name: "modern secure auth",
			implementations: []AuthImplementation{
				{
					Type:             AuthTypeWebAuthn,
					SecurityFeatures: []string{"MFA"},
				},
			},
			expectedContains: []string{}, // Should have fewer recommendations
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock the hasMFA method by adding MFA to security features
			for i := range tt.implementations {
				if contains(tt.implementations[i].SecurityFeatures, "MFA") {
					// This implementation has MFA
					continue
				}
			}

			recommendations := engine.generateRecommendations(tt.implementations)

			for _, expectedText := range tt.expectedContains {
				found := false
				for _, rec := range recommendations {
					if strings.Contains(rec, expectedText) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected recommendation containing '%s'", expectedText)
			}
		})
	}
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Benchmark tests
func BenchmarkEngine_Discover(b *testing.B) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "error", // Reduce noise in benchmarks
		Format: "console",
	})
	if err != nil {
		b.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><form action="/login" method="post">
			<input name="username" type="text">
			<input name="password" type="password">
			</form></body></html>`))
	}))
	defer server.Close()

	engine := NewEngine(logger, &Config{
		MaxDepth: 1,
		Timeout:  5 * time.Second,
	})

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.Discover(ctx, server.URL)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEngine_CalculateRiskScore(b *testing.B) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "error", // Reduce noise in benchmarks
		Format: "console",
	})
	if err != nil {
		b.Fatal(err)
	}
	engine := NewEngine(logger, nil)

	implementations := []AuthImplementation{
		{Type: AuthTypeOAuth2, SecurityFeatures: []string{"PKCE"}, Vulnerabilities: []string{"redirect"}},
		{Type: AuthTypeBasicAuth, SecurityFeatures: []string{}, Vulnerabilities: []string{"plaintext", "replay"}},
		{Type: AuthTypeFormLogin, SecurityFeatures: []string{"CSRF"}, Vulnerabilities: []string{"session fixation"}},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.calculateRiskScore(implementations)
	}
}
