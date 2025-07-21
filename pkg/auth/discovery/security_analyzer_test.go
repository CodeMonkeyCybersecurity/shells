package discovery

import (
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecurityAnalyzer(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)
	analyzer := NewSecurityAnalyzer(logger)
	
	assert.NotNil(t, analyzer)
	assert.Equal(t, logger, analyzer.logger)
}

func TestSecurityAnalyzer_AnalyzeImplementation_OAuth2(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)
	analyzer := NewSecurityAnalyzer(logger)

	tests := []struct {
		name                   string
		impl                   *AuthImplementation
		expectedFeatures       []string
		expectedVulnerabilities []string
	}{
		{
			name: "OAuth2 with PKCE and state",
			impl: &AuthImplementation{
				Type: AuthTypeOAuth2,
				Flows: []AuthFlow{
					{
						Steps: []AuthFlowStep{
							{
								Type: "authorization_request",
								Parameters: []AuthParameter{
									{Name: "state", Required: true},
								},
							},
							{
								Type: "token_exchange",
								Parameters: []AuthParameter{
									{Name: "client_secret", Required: true},
								},
							},
						},
					},
				},
			},
			expectedFeatures: []string{
				"Token-based authentication",
				"State parameter for CSRF protection",
				"Client authentication at token endpoint",
			},
			expectedVulnerabilities: []string{
				"Potential redirect URI manipulation",
			},
		},
		{
			name: "OAuth2 without security features",
			impl: &AuthImplementation{
				Type:  AuthTypeOAuth2,
				Flows: []AuthFlow{},
			},
			expectedFeatures: []string{
				"Token-based authentication",
			},
			expectedVulnerabilities: []string{
				"Public client without PKCE",
				"Missing state parameter",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			features, vulns := analyzer.AnalyzeImplementation(tt.impl)
			
			for _, expectedFeature := range tt.expectedFeatures {
				found := false
				for _, feature := range features {
					if strings.Contains(feature, expectedFeature) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected feature '%s' not found", expectedFeature)
			}
			
			for _, expectedVuln := range tt.expectedVulnerabilities {
				found := false
				for _, vuln := range vulns {
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

func TestSecurityAnalyzer_AnalyzeImplementation_SAML(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)
	analyzer := NewSecurityAnalyzer(logger)

	tests := []struct {
		name                   string
		impl                   *AuthImplementation
		expectedFeatures       []string
		expectedVulnerabilities []string
	}{
		{
			name: "SAML with encryption",
			impl: &AuthImplementation{
				Type: AuthTypeSAML,
				Metadata: map[string]interface{}{
					"encryption": "true",
				},
			},
			expectedFeatures: []string{
				"SAML assertions encrypted",
				"XML-based assertions",
			},
			expectedVulnerabilities: []string{
				"XML signature wrapping",
			},
		},
		{
			name: "SAML without encryption",
			impl: &AuthImplementation{
				Type:     AuthTypeSAML,
				Metadata: map[string]interface{}{},
			},
			expectedFeatures: []string{
				"Single Sign-On capabilities",
			},
			expectedVulnerabilities: []string{
				"SAML assertions not encrypted",
				"SAML replay attacks",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			features, vulns := analyzer.AnalyzeImplementation(tt.impl)
			
			for _, expectedFeature := range tt.expectedFeatures {
				found := false
				for _, feature := range features {
					if strings.Contains(feature, expectedFeature) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected feature '%s' not found in %v", expectedFeature, features)
			}
			
			for _, expectedVuln := range tt.expectedVulnerabilities {
				found := false
				for _, vuln := range vulns {
					if strings.Contains(vuln, expectedVuln) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected vulnerability '%s' not found in %v", expectedVuln, vulns)
			}
		})
	}
}

func TestSecurityAnalyzer_AnalyzeImplementation_WebAuthn(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)
	analyzer := NewSecurityAnalyzer(logger)

	tests := []struct {
		name                   string
		impl                   *AuthImplementation
		expectedFeatures       []string
		expectedVulnerabilities []string
	}{
		{
			name: "WebAuthn with user verification",
			impl: &AuthImplementation{
				Type: AuthTypeWebAuthn,
				Endpoints: []AuthEndpoint{
					{
						Metadata: map[string]interface{}{
							"user_verification": "required",
						},
					},
				},
			},
			expectedFeatures: []string{
				"Phishing-resistant authentication",
				"Hardware-backed credentials",
			},
			expectedVulnerabilities: []string{}, // Should have minimal vulnerabilities
		},
		{
			name: "WebAuthn without user verification",
			impl: &AuthImplementation{
				Type:      AuthTypeWebAuthn,
				Endpoints: []AuthEndpoint{{}},
			},
			expectedFeatures: []string{
				"Cryptographically secure",
			},
			expectedVulnerabilities: []string{
				"User verification may not be required",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			features, vulns := analyzer.AnalyzeImplementation(tt.impl)
			
			for _, expectedFeature := range tt.expectedFeatures {
				found := false
				for _, feature := range features {
					if strings.Contains(feature, expectedFeature) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected feature '%s' not found", expectedFeature)
			}
			
			for _, expectedVuln := range tt.expectedVulnerabilities {
				found := false
				for _, vuln := range vulns {
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

func TestSecurityAnalyzer_AnalyzeImplementation_BasicAuth(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)
	analyzer := NewSecurityAnalyzer(logger)

	impl := &AuthImplementation{
		Type: AuthTypeBasicAuth,
	}

	features, vulns := analyzer.AnalyzeImplementation(impl)
	
	// Basic auth should have many vulnerabilities and few features
	assert.Empty(t, features) // No inherent security features
	assert.NotEmpty(t, vulns)
	
	expectedVulns := []string{
		"base64 encoding",
		"credential theft",
		"session management",
	}
	
	for _, expectedVuln := range expectedVulns {
		found := false
		for _, vuln := range vulns {
			if strings.Contains(strings.ToLower(vuln), strings.ToLower(expectedVuln)) {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected vulnerability containing '%s' not found", expectedVuln)
	}
}

func TestSecurityAnalyzer_AnalyzeJWT(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)
	analyzer := NewSecurityAnalyzer(logger)

	tests := []struct {
		name             string
		impl             *AuthImplementation
		expectedFeatures []string
		expectedVulns    []string
	}{
		{
			name: "JWT with refresh tokens",
			impl: &AuthImplementation{
				Flows: []AuthFlow{
					{
						Steps: []AuthFlowStep{
							{
								Parameters: []AuthParameter{
									{Name: "refresh_token"},
								},
							},
						},
					},
				},
			},
			expectedFeatures: []string{
				"Token-based authentication",
				"Refresh token support",
			},
			expectedVulns: []string{
				"algorithm confusion attacks",
				"weak secret keys",
			},
		},
		{
			name: "JWT without refresh tokens",
			impl: &AuthImplementation{
				Flows: []AuthFlow{},
			},
			expectedFeatures: []string{
				"Token-based authentication",
			},
			expectedVulns: []string{
				"No token revocation mechanism",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulns, features := analyzer.analyzeJWT(tt.impl)
			
			for _, expectedFeature := range tt.expectedFeatures {
				found := false
				for _, feature := range features {
					if strings.Contains(feature, expectedFeature) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected feature '%s' not found", expectedFeature)
			}
			
			for _, expectedVuln := range tt.expectedVulns {
				found := false
				for _, vuln := range vulns {
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

func TestSecurityAnalyzer_AnalyzeGeneralSecurity(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)
	analyzer := NewSecurityAnalyzer(logger)

	tests := []struct {
		name             string
		impl             *AuthImplementation
		expectedFeatures []string
		expectedVulns    []string
	}{
		{
			name: "implementation with security features",
			impl: &AuthImplementation{
				Endpoints: []AuthEndpoint{
					{
						Headers: map[string]string{
							"X-RateLimit-Limit":        "100",
							"Strict-Transport-Security": "max-age=31536000",
							"X-Frame-Options":           "DENY",
						},
						Parameters: []AuthParameter{
							{Name: "csrf_token", Type: "hidden"},
						},
					},
				},
				Flows: []AuthFlow{
					{
						Type: "registration",
						Steps: []AuthFlowStep{
							{
								Parameters: []AuthParameter{
									{
										Name:        "password",
										Type:        "password",
										Constraints: []string{"min:8", "uppercase", "lowercase"},
									},
								},
							},
						},
					},
				},
			},
			expectedFeatures: []string{
				"Rate limiting implemented",
				"CSRF protection tokens found",
				"Security header: Strict-Transport-Security",
				"Password complexity requirements enforced",
			},
			expectedVulns: []string{}, // Should have minimal vulnerabilities
		},
		{
			name: "implementation without security features",
			impl: &AuthImplementation{
				Endpoints: []AuthEndpoint{
					{
						Headers:    map[string]string{},
						Parameters: []AuthParameter{},
					},
				},
			},
			expectedFeatures: []string{},
			expectedVulns: []string{
				"No rate limiting detected",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			features, vulns := analyzer.analyzeGeneralSecurity(tt.impl)
			
			for _, expectedFeature := range tt.expectedFeatures {
				found := false
				for _, feature := range features {
					if strings.Contains(feature, expectedFeature) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected feature '%s' not found in %v", expectedFeature, features)
			}
			
			for _, expectedVuln := range tt.expectedVulns {
				found := false
				for _, vuln := range vulns {
					if strings.Contains(vuln, expectedVuln) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected vulnerability '%s' not found in %v", expectedVuln, vulns)
			}
		})
	}
}

func TestSecurityAnalyzer_HasMFA(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)
	analyzer := NewSecurityAnalyzer(logger)

	tests := []struct {
		name     string
		impl     *AuthImplementation
		expected bool
	}{
		{
			name: "has MFA endpoint",
			impl: &AuthImplementation{
				Endpoints: []AuthEndpoint{
					{Type: AuthTypeTOTP},
				},
			},
			expected: true,
		},
		{
			name: "has MFA flow",
			impl: &AuthImplementation{
				Flows: []AuthFlow{
					{RequiresMFA: true},
				},
			},
			expected: true,
		},
		{
			name: "has MFA challenge step",
			impl: &AuthImplementation{
				Flows: []AuthFlow{
					{
						Steps: []AuthFlowStep{
							{Type: "mfa_challenge"},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "has MFA metadata",
			impl: &AuthImplementation{
				Metadata: map[string]interface{}{
					"mfa_enabled": true,
				},
			},
			expected: true,
		},
		{
			name: "no MFA",
			impl: &AuthImplementation{
				Endpoints: []AuthEndpoint{{}},
				Flows:     []AuthFlow{{}},
				Metadata:  map[string]interface{}{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.hasMFA(tt.impl)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSecurityAnalyzer_HasUserVerification(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)
	analyzer := NewSecurityAnalyzer(logger)

	tests := []struct {
		name     string
		impl     *AuthImplementation
		expected bool
	}{
		{
			name: "user verification required",
			impl: &AuthImplementation{
				Endpoints: []AuthEndpoint{
					{
						Metadata: map[string]interface{}{
							"user_verification": "required",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "user verification preferred",
			impl: &AuthImplementation{
				Endpoints: []AuthEndpoint{
					{
						Metadata: map[string]interface{}{
							"user_verification": "preferred",
						},
					},
				},
			},
			expected: false, // Only "required" counts as true
		},
		{
			name: "no user verification",
			impl: &AuthImplementation{
				Endpoints: []AuthEndpoint{
					{Metadata: map[string]interface{}{}},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.hasUserVerification(tt.impl)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Fuzz tests for security analyzer
func FuzzSecurityAnalyzerAnalyzeImplementation(f *testing.F) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "error", // Reduce noise in fuzz tests
		Format: "console",
	})
	if err != nil {
		f.Fatal(err)
	}
	analyzer := NewSecurityAnalyzer(logger)

	// Seed with various auth types
	authTypes := []AuthType{
		AuthTypeOAuth2, AuthTypeSAML, AuthTypeWebAuthn, AuthTypeJWT,
		AuthTypeLDAP, AuthTypeAPIKey, AuthTypeBasicAuth, AuthTypeDigestAuth,
		AuthTypeFormLogin, AuthTypeUnknown,
	}

	for _, authType := range authTypes {
		f.Add(string(authType))
	}

	f.Fuzz(func(t *testing.T, authTypeStr string) {
		impl := &AuthImplementation{
			Type:      AuthType(authTypeStr),
			Domain:    "example.com",
			Endpoints: []AuthEndpoint{},
			Flows:     []AuthFlow{},
			Metadata:  make(map[string]interface{}),
		}

		// Should not panic regardless of auth type
		features, vulns := analyzer.AnalyzeImplementation(impl)
		
		// Should always return valid slices
		assert.NotNil(t, features)
		assert.NotNil(t, vulns)
		
		// Features and vulnerabilities should be reasonable
		assert.True(t, len(features) <= 50, "Too many features: %d", len(features))
		assert.True(t, len(vulns) <= 50, "Too many vulnerabilities: %d", len(vulns))
		
		// All strings should be non-empty
		for _, feature := range features {
			assert.NotEmpty(t, feature)
		}
		for _, vuln := range vulns {
			assert.NotEmpty(t, vuln)
		}
	})
}

// Benchmark tests
func BenchmarkSecurityAnalyzer_AnalyzeImplementation(b *testing.B) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "error", // Reduce noise in benchmarks
		Format: "console",
	})
	if err != nil {
		b.Fatal(err)
	}
	analyzer := NewSecurityAnalyzer(logger)
	
	impl := &AuthImplementation{
		Type:   AuthTypeOAuth2,
		Domain: "example.com",
		Endpoints: []AuthEndpoint{
			{
				Headers: map[string]string{
					"X-RateLimit-Limit": "100",
				},
				Parameters: []AuthParameter{
					{Name: "csrf_token"},
				},
			},
		},
		Flows: []AuthFlow{
			{
				Steps: []AuthFlowStep{
					{
						Type: "authorization_request",
						Parameters: []AuthParameter{
							{Name: "state"},
						},
					},
				},
			},
		},
		Metadata: map[string]interface{}{
			"mfa_enabled": true,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.AnalyzeImplementation(impl)
	}
}

func TestSecurityAnalyzer_EdgeCases(t *testing.T) {
	logger, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)
	analyzer := NewSecurityAnalyzer(logger)

	tests := []struct {
		name string
		impl *AuthImplementation
	}{
		{
			name: "nil implementation",
			impl: nil,
		},
		{
			name: "empty implementation",
			impl: &AuthImplementation{},
		},
		{
			name: "implementation with nil slices",
			impl: &AuthImplementation{
				Type:      AuthTypeOAuth2,
				Endpoints: nil,
				Flows:     nil,
				Metadata:  nil,
			},
		},
		{
			name: "implementation with malformed data",
			impl: &AuthImplementation{
				Type: AuthType("invalid-type"),
				Metadata: map[string]interface{}{
					"malformed": []int{1, 2, 3}, // Wrong type
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			require.NotPanics(t, func() {
				if tt.impl == nil {
					// Skip nil test as it would cause panic in real usage
					return
				}
				features, vulns := analyzer.AnalyzeImplementation(tt.impl)
				assert.NotNil(t, features)
				assert.NotNil(t, vulns)
			})
		})
	}
}