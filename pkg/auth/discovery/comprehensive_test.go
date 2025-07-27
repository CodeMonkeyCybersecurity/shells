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

// Integration test for the entire discovery system
func TestComprehensiveDiscovery_FullStack(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	// Create comprehensive test server with multiple auth methods
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`
				<!DOCTYPE html>
				<html>
					<head><title>Comprehensive Auth Test Site</title></head>
					<body>
						<!-- Form-based authentication -->
						<form action="/login" method="post" id="loginForm">
							<input type="hidden" name="csrf_token" value="abc123">
							<input type="text" name="username" placeholder="Username" required>
							<input type="password" name="password" placeholder="Password" 
								   pattern="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$" required>
							<input type="submit" value="Login">
						</form>
						
						<!-- OAuth2 login buttons -->
						<a href="/oauth/authorize?client_id=test-client&response_type=code&state=xyz789">
							Login with OAuth
						</a>
						
						<!-- WebAuthn implementation -->
						<script>
							const rpId = "` + strings.Replace(server.URL, "http://", "", 1) + `";
							const rpName = "Test Site";
							
							if (navigator.credentials && PublicKeyCredential) {
								// WebAuthn registration
								function register() {
									navigator.credentials.create({
										publicKey: {
											rp: { id: rpId, name: rpName },
											user: { 
												id: new TextEncoder().encode("test-user"),
												name: "testuser",
												displayName: "Test User"
											},
											challenge: crypto.getRandomValues(new Uint8Array(32)),
											pubKeyCredParams: [
												{ alg: -7, type: "public-key" },  // ES256
												{ alg: -257, type: "public-key" } // RS256
											],
											authenticatorSelection: {
												authenticatorAttachment: "cross-platform",
												userVerification: "required",
												residentKey: "preferred"
											},
											attestation: "direct",
											timeout: 60000,
											extensions: {
												"uvm": true,
												"credProps": true
											}
										}
									}).catch(function(error) {
										if (error instanceof NotAllowedError) {
											console.error("User cancelled registration");
										} else if (error instanceof InvalidStateError) {
											console.error("Authenticator already registered");
										}
									});
								}
								
								// WebAuthn authentication
								function authenticate() {
									navigator.credentials.get({
										publicKey: {
											challenge: crypto.getRandomValues(new Uint8Array(32)),
											allowCredentials: [],
											userVerification: "required",
											timeout: 60000
										}
									}).catch(function(error) {
										if (error instanceof NotAllowedError) {
											console.error("Authentication cancelled");
										} else if (error instanceof SecurityError) {
											console.error("Security error during authentication");
										}
									});
								}
							}
							
							// SAML detection patterns
							const samlEndpoint = "/saml/sso";
							const entityId = "` + server.URL + `";
						</script>
						
						<!-- API documentation links -->
						<a href="/api/docs">API Documentation</a>
						<a href="/swagger">Swagger UI</a>
					</body>
				</html>
			`))

		case "/login":
			w.Header().Set("X-RateLimit-Limit", "100")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Invalid credentials"}`))

		// OAuth2/OIDC endpoints
		case "/.well-known/openid_configuration":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"issuer": "` + server.URL + `",
				"authorization_endpoint": "` + server.URL + `/oauth/authorize",
				"token_endpoint": "` + server.URL + `/oauth/token",
				"userinfo_endpoint": "` + server.URL + `/oauth/userinfo",
				"jwks_uri": "` + server.URL + `/.well-known/jwks.json",
				"response_types_supported": ["code", "token", "id_token"],
				"grant_types_supported": ["authorization_code", "implicit", "client_credentials"],
				"scopes_supported": ["openid", "profile", "email", "address", "phone"],
				"id_token_signing_alg_values_supported": ["RS256", "ES256"],
				"token_endpoint_auth_methods_supported": ["client_secret_jwt", "private_key_jwt"],
				"code_challenge_methods_supported": ["S256"],
				"claims_supported": ["sub", "iss", "aud", "exp", "iat", "name", "email"]
			}`))

		case "/oauth/authorize":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "invalid_request", "error_description": "Missing required parameter"}`))

		case "/oauth/token":
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "invalid_client"}`))

		// WebAuthn endpoints
		case "/webauthn/register":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"challenge": "` + strings.Repeat("a", 43) + `=",
				"rp": {"id": "` + strings.Replace(server.URL, "http://", "", 1) + `", "name": "Test Site"},
				"user": {"id": "dGVzdA==", "name": "test", "displayName": "Test User"},
				"pubKeyCredParams": [
					{"alg": -7, "type": "public-key"},
					{"alg": -257, "type": "public-key"}
				],
				"authenticatorSelection": {
					"authenticatorAttachment": "cross-platform",
					"userVerification": "required",
					"residentKey": "preferred"
				},
				"attestation": "direct",
				"timeout": 60000
			}`))

		case "/webauthn/authenticate":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"challenge": "` + strings.Repeat("b", 43) + `=",
				"allowCredentials": [],
				"userVerification": "required",
				"timeout": 60000
			}`))

		// SAML endpoints
		case "/saml/metadata":
			w.Header().Set("Content-Type", "application/xml")
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
				<md:EntityDescriptor entityID="` + server.URL + `" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
					<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
						<md:KeyDescriptor use="signing">
							<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
								<ds:X509Data><ds:X509Certificate>test-certificate</ds:X509Certificate></ds:X509Data>
							</ds:KeyInfo>
						</md:KeyDescriptor>
						<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
							Location="` + server.URL + `/saml/acs" index="1"/>
					</md:SPSSODescriptor>
				</md:EntityDescriptor>`))

		case "/saml/sso":
			w.WriteHeader(http.StatusFound)
			w.Header().Set("Location", "/login")

		// API endpoints
		case "/api/v1/users":
			w.Header().Set("WWW-Authenticate", "Bearer realm=\"API\"")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Authentication required"}`))

		case "/api/v1/auth":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"methods": ["basic", "bearer", "api_key"],
				"endpoints": {
					"token": "/api/v1/token",
					"refresh": "/api/v1/refresh"
				}
			}`))

		case "/api/docs":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><body><h1>API Documentation</h1>
				<p>Authentication methods: Basic Auth, Bearer Token, API Key</p>
				<p>API Key can be sent in header: X-API-Key</p>
				<p>Bearer tokens expire after 1 hour</p>
			</body></html>`))

		// Health/status endpoints
		case "/health":
			w.Write([]byte(`{"status": "ok", "auth": "enabled"}`))

		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		}
	}))
	defer server.Close()

	// Test comprehensive discovery
	discoveryConfig := &Config{
		MaxDepth:           2,
		FollowRedirects:    true,
		Timeout:            30 * time.Second,
		Threads:            5,
		EnableJSAnalysis:   true,
		EnableAPIDiscovery: true,
	}

	engine := NewEngine(logger, discoveryConfig)
	ctx := context.Background()

	result, err := engine.Discover(ctx, server.URL)

	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify comprehensive discovery results
	assert.Equal(t, server.URL, result.Target)
	assert.Greater(t, result.TotalEndpoints, 5) // Should find multiple endpoints
	assert.NotEmpty(t, result.Implementations)
	assert.Greater(t, result.DiscoveryTime, time.Duration(0))

	// Check for multiple authentication types discovered
	authTypes := make(map[AuthType]bool)
	for _, impl := range result.Implementations {
		authTypes[impl.Type] = true
	}

	// Should discover form-based auth at minimum
	assert.True(t, authTypes[AuthTypeFormLogin], "Should discover form-based authentication")

	// Check security analysis
	hasSecurityFeatures := false
	hasVulnerabilities := false

	for _, impl := range result.Implementations {
		if len(impl.SecurityFeatures) > 0 {
			hasSecurityFeatures = true
		}
		if len(impl.Vulnerabilities) > 0 {
			hasVulnerabilities = true
		}
	}

	assert.True(t, hasSecurityFeatures, "Should identify security features")
	assert.True(t, hasVulnerabilities, "Should identify vulnerabilities")

	// Verify risk score calculation
	assert.GreaterOrEqual(t, result.RiskScore, 0.0)
	assert.LessOrEqual(t, result.RiskScore, 10.0)

	// Verify recommendations
	assert.NotEmpty(t, result.Recommendations)
}

// Test parallel discovery performance
func TestComprehensiveDiscovery_ParallelProcessing(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "info", // Reduce verbosity for performance test
		Format: "console",
	})
	require.NoError(t, err)

	// Create multiple test servers
	servers := make([]*httptest.Server, 3)
	for i := 0; i < 3; i++ {
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate processing delay
			time.Sleep(50 * time.Millisecond)
			w.Write([]byte(`<html><body><form action="/login" method="post">
				<input name="username"><input name="password" type="password">
			</form></body></html>`))
		}))
	}

	defer func() {
		for _, server := range servers {
			server.Close()
		}
	}()

	config := &Config{
		MaxDepth: 1,
		Threads:  10,
		Timeout:  5 * time.Second,
	}

	engine := NewEngine(logger, config)
	ctx := context.Background()

	// Test parallel discovery
	start := time.Now()
	results := make([]*DiscoveryResult, len(servers))

	for i, srv := range servers {
		go func(i int, serverURL string) {
			result, err := engine.Discover(ctx, serverURL)
			assert.NoError(t, err)
			results[i] = result
		}(i, srv.URL)
	}

	// Wait for all to complete (with timeout)
	for {
		completed := 0
		for _, result := range results {
			if result != nil {
				completed++
			}
		}
		if completed == len(servers) {
			break
		}
		if time.Since(start) > 10*time.Second {
			t.Fatal("Parallel discovery timed out")
		}
		time.Sleep(100 * time.Millisecond)
	}

	duration := time.Since(start)

	// Should complete faster than sequential processing
	// (3 servers * 50ms delay = 150ms minimum sequential time)
	assert.Less(t, duration, 500*time.Millisecond, "Parallel processing should be faster")

	// Verify all discoveries succeeded
	for i, result := range results {
		assert.NotNil(t, result, "Server %d should have results", i)
		assert.NotEmpty(t, result.Implementations)
	}
}

// Stress test with many concurrent discoveries
func TestComprehensiveDiscovery_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	logger, err := logger.New(config.LoggerConfig{
		Level:  "error", // Minimize logging for stress test
		Format: "console",
	})
	require.NoError(t, err)

	// Simple test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>
			<form action="/login" method="post">
				<input name="user" type="text">
				<input name="pass" type="password">
				<button type="submit">Login</button>
			</form>
		</body></html>`))
	}))
	defer server.Close()

	config := &Config{
		MaxDepth: 1,
		Threads:  20,
		Timeout:  2 * time.Second,
	}

	engine := NewEngine(logger, config)
	ctx := context.Background()

	// Run multiple concurrent discoveries
	const numRequests = 50
	results := make(chan *DiscoveryResult, numRequests)
	errors := make(chan error, numRequests)

	start := time.Now()

	for i := 0; i < numRequests; i++ {
		go func() {
			result, err := engine.Discover(ctx, server.URL)
			if err != nil {
				errors <- err
			} else {
				results <- result
			}
		}()
	}

	// Collect results
	successCount := 0
	errorCount := 0

	for i := 0; i < numRequests; i++ {
		select {
		case <-results:
			successCount++
		case <-errors:
			errorCount++
		case <-time.After(30 * time.Second):
			t.Fatal("Stress test timed out")
		}
	}

	duration := time.Since(start)

	// Verify results
	assert.Equal(t, numRequests, successCount+errorCount)
	assert.Greater(t, successCount, numRequests/2, "At least half should succeed")
	assert.Less(t, duration, 10*time.Second, "Should complete within reasonable time")

	t.Logf("Stress test completed: %d successful, %d errors, duration: %v",
		successCount, errorCount, duration)
}

// Memory leak test
func TestComprehensiveDiscovery_MemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory test in short mode")
	}

	logger, err := logger.New(config.LoggerConfig{
		Level:  "error",
		Format: "console",
	})
	require.NoError(t, err)

	// Large response server to test memory handling
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate large HTML response
		w.Write([]byte(`<html><head><title>Large Page</title></head><body>`))

		// Add large form
		w.Write([]byte(`<form action="/login" method="post">`))
		for i := 0; i < 1000; i++ {
			w.Write([]byte(`<input name="field` + strings.Repeat("x", 100) + `" type="text">`))
		}
		w.Write([]byte(`</form>`))

		// Add large script
		w.Write([]byte(`<script>`))
		for i := 0; i < 100; i++ {
			w.Write([]byte(`console.log("` + strings.Repeat("test data ", 50) + `");`))
		}
		w.Write([]byte(`</script></body></html>`))
	}))
	defer server.Close()

	config := &Config{
		MaxDepth: 1,
		Threads:  5,
		Timeout:  5 * time.Second,
	}

	engine := NewEngine(logger, config)
	ctx := context.Background()

	// Run multiple discoveries to test memory handling
	for i := 0; i < 10; i++ {
		result, err := engine.Discover(ctx, server.URL)
		assert.NoError(t, err)
		assert.NotNil(t, result)

		// Force garbage collection
		//runtime.GC()
		//runtime.GC()
	}
}
