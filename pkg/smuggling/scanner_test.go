package smuggling

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

func TestScanner_Name(t *testing.T) {
	scanner := NewScanner()
	if scanner.Name() != "smuggling" {
		t.Errorf("Expected scanner name 'smuggling', got '%s'", scanner.Name())
	}
}

func TestScanner_Type(t *testing.T) {
	scanner := NewScanner()
	if scanner.Type() != types.ScanType("smuggling") {
		t.Errorf("Expected scanner type 'smuggling', got '%s'", scanner.Type())
	}
}

func TestScanner_Validate(t *testing.T) {
	scanner := NewScanner()

	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{
			name:    "valid HTTP URL",
			target:  "http://example.com",
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL",
			target:  "https://example.com",
			wantErr: false,
		},
		{
			name:    "empty target",
			target:  "",
			wantErr: true,
		},
		{
			name:    "invalid URL",
			target:  "not-a-url",
			wantErr: true,
		},
		{
			name:    "invalid scheme",
			target:  "ftp://example.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := scanner.Validate(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestScanner_Scan(t *testing.T) {
	scanner := NewScanner()

	// Test with mock target - this would typically use a test server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	options := map[string]string{
		"technique":    "cl.te",
		"differential": "true",
		"timeout":      "10s",
	}

	// This test would fail with a real target, but we're testing the structure
	_, err := scanner.Scan(ctx, "https://example.com", options)

	// We expect this to not panic and handle gracefully
	if err != nil {
		t.Logf("Expected error for test target: %v", err)
	}
}

func TestUpdateConfigFromOptions(t *testing.T) {
	scanner := NewScanner().(*Scanner)

	options := map[string]string{
		"technique":          "cl.te",
		"timeout":            "60s",
		"user-agent":         "test-agent",
		"verify-ssl":         "false",
		"differential":       "true",
		"timing":             "false",
		"differential-delay": "10s",
		"header-X-Test":      "test-value",
	}

	scanner.updateConfigFromOptions(options)

	if len(scanner.config.Techniques) != 1 || scanner.config.Techniques[0] != "cl.te" {
		t.Errorf("Expected techniques ['cl.te'], got %v", scanner.config.Techniques)
	}

	if scanner.config.Timeout != 60*time.Second {
		t.Errorf("Expected timeout 60s, got %v", scanner.config.Timeout)
	}

	if scanner.config.UserAgent != "test-agent" {
		t.Errorf("Expected user agent 'test-agent', got '%s'", scanner.config.UserAgent)
	}

	if scanner.config.VerifySSL != false {
		t.Errorf("Expected verify SSL false, got %v", scanner.config.VerifySSL)
	}

	if scanner.config.EnableDifferentialAnalysis != true {
		t.Errorf("Expected differential analysis true, got %v", scanner.config.EnableDifferentialAnalysis)
	}

	if scanner.config.EnableTimingAnalysis != false {
		t.Errorf("Expected timing analysis false, got %v", scanner.config.EnableTimingAnalysis)
	}

	if scanner.config.DifferentialDelay != 10*time.Second {
		t.Errorf("Expected differential delay 10s, got %v", scanner.config.DifferentialDelay)
	}

	if scanner.config.CustomHeaders["X-Test"] != "test-value" {
		t.Errorf("Expected custom header X-Test='test-value', got '%s'", scanner.config.CustomHeaders["X-Test"])
	}
}

func TestTechniqueConstants(t *testing.T) {
	techniques := []string{TechniqueCLTE, TechniqueTECL, TechniqueTETE, TechniqueHTTP2}
	expected := []string{"CL.TE", "TE.CL", "TE.TE", "HTTP2"}

	for i, technique := range techniques {
		if technique != expected[i] {
			t.Errorf("Expected technique %s, got %s", expected[i], technique)
		}
	}
}

func TestVulnerabilityConstants(t *testing.T) {
	vulns := []string{VulnSmugglingCLTE, VulnSmugglingTECL, VulnSmugglingTETE, VulnSmugglingHTTP2}

	for _, vuln := range vulns {
		if vuln == "" {
			t.Errorf("Vulnerability constant should not be empty")
		}
		if !strings.Contains(vuln, "HTTP_REQUEST_SMUGGLING") {
			t.Errorf("Vulnerability constant should contain 'HTTP_REQUEST_SMUGGLING': %s", vuln)
		}
	}
}

func TestGetSeverityFromString(t *testing.T) {
	scanner := NewScanner().(*Scanner)

	tests := []struct {
		input    string
		expected types.Severity
	}{
		{"CRITICAL", types.SeverityCritical},
		{"HIGH", types.SeverityHigh},
		{"MEDIUM", types.SeverityMedium},
		{"LOW", types.SeverityLow},
		{"INFO", types.SeverityInfo},
		{"unknown", types.SeverityInfo},
		{"", types.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := scanner.getSeverityFromString(tt.input)
			if result != tt.expected {
				t.Errorf("Expected severity %v, got %v", tt.expected, result)
			}
		})
	}
}
