// pkg/ai/integration_test.go
//
// Integration tests for AI-powered report generation
//
// NOTE: These tests require actual OpenAI/Azure OpenAI API keys
// Set AI_INTEGRATION_TEST=true environment variable to run these tests

package ai

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// skipIfNoAPIKey skips the test if integration tests are not enabled
func skipIfNoAPIKey(t *testing.T) {
	if os.Getenv("AI_INTEGRATION_TEST") != "true" {
		t.Skip("Skipping AI integration test - set AI_INTEGRATION_TEST=true to run")
	}

	if os.Getenv("OPENAI_API_KEY") == "" && os.Getenv("AZURE_OPENAI_API_KEY") == "" {
		t.Skip("Skipping AI integration test - no API key configured")
	}
}

func TestOpenAIClientInitialization(t *testing.T) {
	skipIfNoAPIKey(t)

	log := createTestLogger(t)

	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "OpenAI provider with API key",
			config: Config{
				Provider:    "openai",
				APIKey:      os.Getenv("OPENAI_API_KEY"),
				Model:       "gpt-3.5-turbo",
				MaxTokens:   100,
				Temperature: 0.7,
				Timeout:     30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "Azure OpenAI provider",
			config: Config{
				Provider:        "azure",
				AzureEndpoint:   os.Getenv("AZURE_OPENAI_ENDPOINT"),
				AzureAPIKey:     os.Getenv("AZURE_OPENAI_API_KEY"),
				AzureDeployment: os.Getenv("AZURE_OPENAI_DEPLOYMENT"),
				MaxTokens:       100,
				Temperature:     0.7,
				Timeout:         30 * time.Second,
			},
			wantErr: os.Getenv("AZURE_OPENAI_API_KEY") == "",
		},
		{
			name: "Missing API key",
			config: Config{
				Provider: "openai",
				Model:    "gpt-3.5-turbo",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config, log)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, client)
			assert.Equal(t, !tt.wantErr, client.IsEnabled())
		})
	}
}

func TestGenerateCompletion(t *testing.T) {
	skipIfNoAPIKey(t)

	log := createTestLogger(t)

	config := Config{
		Provider:    "openai",
		APIKey:      os.Getenv("OPENAI_API_KEY"),
		Model:       "gpt-3.5-turbo",
		MaxTokens:   100,
		Temperature: 0.7,
		Timeout:     30 * time.Second,
	}

	client, err := NewClient(config, log)
	require.NoError(t, err)
	require.NotNil(t, client)

	ctx := context.Background()
	prompt := "Write a one-sentence summary of what SQL injection is."

	completion, err := client.GenerateCompletion(ctx, prompt)
	require.NoError(t, err)
	assert.NotEmpty(t, completion)
	assert.Contains(t, completion, "SQL")

	t.Logf("Generated completion: %s", completion)
}

func TestReportGeneratorBugBountyFormat(t *testing.T) {
	skipIfNoAPIKey(t)

	log := createTestLogger(t)

	config := Config{
		Provider:           "openai",
		APIKey:             os.Getenv("OPENAI_API_KEY"),
		Model:              "gpt-3.5-turbo",
		MaxTokens:          1000,
		Temperature:        0.7,
		Timeout:            60 * time.Second,
		MaxCostPerReport:   0.50,
		EnableCostTracking: true,
	}

	client, err := NewClient(config, log)
	require.NoError(t, err)

	generator := NewReportGenerator(client, log)

	findings := []types.Finding{
		{
			Type:        "SQL_INJECTION",
			Severity:    types.SeverityHigh,
			Description: "SQL injection vulnerability in login endpoint allows authentication bypass",
			Evidence:    "Payload: ' OR '1'='1 successfully bypassed authentication",
			Tool:        "artemis-sqli-scanner",
			Metadata: map[string]interface{}{
				"cvss":        8.5,
				"cwe":         "CWE-89",
				"remediation": "Use parameterized queries instead of string concatenation",
			},
		},
	}

	req := ReportRequest{
		Findings: findings,
		Target:   "example.com",
		ScanID:   "test-scan-123",
		Format:   FormatBugBounty,
		Platform: "hackerone",
	}

	ctx := context.Background()
	report, err := generator.GenerateReport(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.NotEmpty(t, report.Title)
	assert.NotEmpty(t, report.Content)
	assert.NotEmpty(t, report.Summary)
	assert.Equal(t, "HIGH", report.Severity)
	assert.Equal(t, 8.5, report.CVSS)
	assert.Contains(t, report.CWE, "CWE-89")

	t.Logf("Generated Report Title: %s", report.Title)
	t.Logf("Report Length: %d characters", len(report.Content))
	t.Logf("Summary: %s", report.Summary)
}

func TestReportGeneratorMultiplePlatforms(t *testing.T) {
	skipIfNoAPIKey(t)

	log := createTestLogger(t)

	config := Config{
		Provider:    "openai",
		APIKey:      os.Getenv("OPENAI_API_KEY"),
		Model:       "gpt-3.5-turbo",
		MaxTokens:   1500,
		Temperature: 0.7,
		Timeout:     90 * time.Second,
	}

	client, err := NewClient(config, log)
	require.NoError(t, err)

	generator := NewReportGenerator(client, log)

	findings := []types.Finding{
		{
			Type:        "XSS",
			Severity:    types.SeverityMedium,
			Description: "Reflected cross-site scripting in search parameter",
			Evidence:    "<script>alert(document.cookie)</script> was reflected in response",
			Tool:        "artemis-xss-scanner",
			Metadata: map[string]interface{}{
				"cvss":        6.5,
				"cwe":         "CWE-79",
				"remediation": "Implement proper output encoding and Content Security Policy",
			},
		},
	}

	ctx := context.Background()
	reports, err := generator.GenerateBatchReports(ctx, findings, "example.com", "test-scan-456")
	require.NoError(t, err)
	assert.NotEmpty(t, reports)

	// Verify reports for different platforms were generated
	platforms := []string{"hackerone", "bugcrowd", "azure", "markdown"}
	for _, platform := range platforms {
		report, exists := reports[platform]
		if exists {
			assert.NotNil(t, report)
			assert.NotEmpty(t, report.Content)
			t.Logf("Platform: %s - Report generated successfully", platform)
		}
	}
}

func TestCostTracking(t *testing.T) {
	skipIfNoAPIKey(t)

	log := createTestLogger(t)

	config := Config{
		Provider:           "openai",
		APIKey:             os.Getenv("OPENAI_API_KEY"),
		Model:              "gpt-3.5-turbo",
		MaxTokens:          500,
		Temperature:        0.7,
		Timeout:            30 * time.Second,
		MaxCostPerReport:   0.10,
		EnableCostTracking: true,
	}

	client, err := NewClient(config, log)
	require.NoError(t, err)

	ctx := context.Background()
	prompt := "Generate a brief security report summary for a SQL injection vulnerability."

	_, err = client.GenerateCompletion(ctx, prompt)
	require.NoError(t, err)

	// Cost tracking is logged but not returned
	// This test verifies the completion succeeds with cost tracking enabled
}

func createTestLogger(t *testing.T) *logger.Logger {
	cfg := config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	}

	log, err := logger.New(cfg)
	require.NoError(t, err)
	return log
}
