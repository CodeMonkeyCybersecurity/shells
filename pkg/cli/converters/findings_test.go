package converters

import (
	"testing"
	"time"

	authdiscovery "github.com/CodeMonkeyCybersecurity/shells/pkg/auth/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scanners/secrets"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

func TestConvertSecretFindings(t *testing.T) {
	tests := []struct {
		name           string
		secretFindings []secrets.SecretFinding
		target         string
		expectedCount  int
		checkFirst     func(*testing.T, types.Finding)
	}{
		{
			name: "single AWS key finding",
			secretFindings: []secrets.SecretFinding{
				{
					Type:     "AWS Access Key",
					Severity: types.SeverityHigh,
					Secret:   "AKIAIOSFODNN7EXAMPLE",
					File:     "/etc/config.yml",
					Line:     42,
				},
			},
			target:        "https://example.com",
			expectedCount: 1,
			checkFirst: func(t *testing.T, f types.Finding) {
				if f.Type != "Secret Exposure - AWS Access Key" {
					t.Errorf("Expected type 'Secret Exposure - AWS Access Key', got %s", f.Type)
				}
				if f.Severity != types.SeverityHigh {
					t.Errorf("Expected severity HIGH, got %s", f.Severity)
				}
				if f.Title != "AWS Access Key Secret Found" {
					t.Errorf("Expected title 'AWS Access Key Secret Found', got %s", f.Title)
				}
			},
		},
		{
			name: "multiple secret types",
			secretFindings: []secrets.SecretFinding{
				{
					Type:     "GitHub Token",
					Severity: types.SeverityCritical,
					Secret:   "ghp_1234567890abcdef",
					File:     "/.env",
					Line:     10,
				},
				{
					Type:     "Private SSH Key",
					Severity: types.SeverityHigh,
					Secret:   "-----BEGIN RSA PRIVATE KEY-----",
					File:     "/.ssh/id_rsa",
					Line:     1,
				},
			},
			target:        "https://api.example.com",
			expectedCount: 2,
			checkFirst: func(t *testing.T, f types.Finding) {
				if f.Severity != types.SeverityCritical {
					t.Errorf("Expected first finding to be CRITICAL, got %s", f.Severity)
				}
			},
		},
		{
			name:           "empty findings",
			secretFindings: []secrets.SecretFinding{},
			target:         "https://example.com",
			expectedCount:  0,
			checkFirst:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertSecretFindings(tt.secretFindings, tt.target)

			if len(result) != tt.expectedCount {
				t.Errorf("Expected %d findings, got %d", tt.expectedCount, len(result))
			}

			if tt.checkFirst != nil && len(result) > 0 {
				tt.checkFirst(t, result[0])
			}

			// Verify all findings have required fields
			for i, finding := range result {
				if finding.ID == "" {
					t.Errorf("Finding %d missing ID", i)
				}
				if finding.Type == "" {
					t.Errorf("Finding %d missing Type", i)
				}
				if finding.Description == "" {
					t.Errorf("Finding %d missing Description", i)
				}
				if finding.Solution == "" {
					t.Errorf("Finding %d missing Solution", i)
				}
			}
		})
	}
}

func TestConvertAuthInventoryToFindings(t *testing.T) {
	tests := []struct {
		name          string
		inventory     *authdiscovery.AuthInventory
		domain        string
		sessionID     string
		expectedCount int
		checkContent  func(*testing.T, []types.Finding)
	}{
		{
			name: "inventory with web and api auth",
			inventory: &authdiscovery.AuthInventory{
				Target:      "https://example.com",
				Timestamp:   time.Now(),
				NetworkAuth: &authdiscovery.NetworkAuthMethods{}, // Initialize to avoid nil panic
				WebAuth: &authdiscovery.WebAuthMethods{
					FormLogin: []authdiscovery.FormLoginEndpoint{
						{URL: "https://example.com/login"},
					},
					BasicAuth: []authdiscovery.BasicAuthEndpoint{
						{URL: "https://example.com/admin"},
					},
				},
				APIAuth:    &authdiscovery.APIAuthMethods{}, // Initialize to avoid nil panic
				Confidence: make(map[string]float64),
				Metadata:   make(map[string]interface{}),
			},
			domain:        "example.com",
			sessionID:     "test-session-123",
			expectedCount: 1,
			checkContent: func(t *testing.T, findings []types.Finding) {
				if len(findings) == 0 {
					t.Fatal("Expected at least one finding")
				}
				f := findings[0]
				if f.Type != "Authentication Inventory" {
					t.Errorf("Expected type 'Authentication Inventory', got %s", f.Type)
				}
				if f.Severity != types.SeverityInfo {
					t.Errorf("Expected severity INFO, got %s", f.Severity)
				}
				if f.Description == "" {
					t.Error("Description should not be empty")
				}
			},
		},
		{
			name: "minimal inventory",
			inventory: &authdiscovery.AuthInventory{
				Target:      "https://minimal.com",
				Timestamp:   time.Now(),
				NetworkAuth: &authdiscovery.NetworkAuthMethods{}, // Initialize to avoid nil panic
				WebAuth:     &authdiscovery.WebAuthMethods{},     // Initialize to avoid nil panic
				APIAuth:     &authdiscovery.APIAuthMethods{},     // Initialize to avoid nil panic
				Confidence:  make(map[string]float64),
				Metadata:    make(map[string]interface{}),
			},
			domain:        "minimal.com",
			sessionID:     "test-session-456",
			expectedCount: 1,
			checkContent: func(t *testing.T, findings []types.Finding) {
				if len(findings) != 1 {
					t.Errorf("Expected 1 finding, got %d", len(findings))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertAuthInventoryToFindings(tt.inventory, tt.domain, tt.sessionID)

			if len(result) != tt.expectedCount {
				t.Errorf("Expected %d findings, got %d", tt.expectedCount, len(result))
			}

			if tt.checkContent != nil {
				tt.checkContent(t, result)
			}

			// Verify structure of all findings
			for i, finding := range result {
				if finding.ID == "" {
					t.Errorf("Finding %d missing ID", i)
				}
				if finding.Type == "" {
					t.Errorf("Finding %d missing Type", i)
				}
				if finding.Title == "" {
					t.Errorf("Finding %d missing Title", i)
				}
			}
		})
	}
}

func TestBuildSecretDescription(t *testing.T) {
	secret := secrets.SecretFinding{
		Type:     "API Key",
		Severity: types.SeverityHigh,
		Secret:   "sk_live_1234567890",
		File:     "/config/app.yml",
		Line:     15,
		Context:  "api_key: sk_live_1234567890",
	}

	result := buildSecretDescription(secret)

	if result == "" {
		t.Error("Description should not be empty")
	}

	// Should contain key information
	expectedParts := []string{"API Key", "config/app.yml", "line 15"}
	for _, part := range expectedParts {
		if !contains(result, part) {
			t.Errorf("Description should contain '%s', got: %s", part, result)
		}
	}
}

func TestBuildSecretEvidence(t *testing.T) {
	secret := secrets.SecretFinding{
		Type:     "AWS Access Key",
		Secret:   "AKIAIOSFODNN7EXAMPLE",
		File:     "/etc/config.yml",
		Line:     42,
		Context:  "aws_key: AKIAIOSFODNN7EXAMPLE",
		Verified: true,
	}

	result := buildSecretEvidence(secret)

	if result == "" {
		t.Error("Evidence should not be empty")
	}

	// Should contain structured evidence
	expectedParts := []string{"File", "Line", "Verified"}
	for _, part := range expectedParts {
		if !contains(result, part) {
			t.Errorf("Evidence should contain '%s', got: %s", part, result)
		}
	}
}

func TestBuildSecretSolution(t *testing.T) {
	tests := []struct {
		name         string
		secretType   string
		checkContent func(*testing.T, string)
	}{
		{
			name:       "AWS key",
			secretType: "AWS Access Key",
			checkContent: func(t *testing.T, solution string) {
				if !contains(solution, "rotate") && !contains(solution, "revoke") {
					t.Errorf("AWS key solution should mention rotation/revocation, got: %s", solution)
				}
			},
		},
		{
			name:       "GitHub token",
			secretType: "GitHub Token",
			checkContent: func(t *testing.T, solution string) {
				if !contains(solution, "rotate") && !contains(solution, "revoke") {
					t.Errorf("GitHub token solution should mention rotation/revocation, got: %s", solution)
				}
			},
		},
		{
			name:       "generic secret",
			secretType: "API Key",
			checkContent: func(t *testing.T, solution string) {
				if solution == "" {
					t.Error("Solution should not be empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := secrets.SecretFinding{Type: tt.secretType}
			result := buildSecretSolution(secret)
			tt.checkContent(t, result)
		})
	}
}

// Note: buildAuthDiscoveryDescription is a private function tested indirectly
// through ConvertAuthInventoryToFindings

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
