package scim

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

func TestScanner_Name(t *testing.T) {
	scanner := NewScanner()
	if scanner.Name() != "scim" {
		t.Errorf("Expected scanner name 'scim', got '%s'", scanner.Name())
	}
}

func TestScanner_Type(t *testing.T) {
	scanner := NewScanner()
	if scanner.Type() != types.ScanType("scim") {
		t.Errorf("Expected scanner type 'scim', got '%s'", scanner.Type())
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
		"auth-token": "test-token",
		"auth-type":  "bearer",
	}
	
	// This test would fail with a real target, but we're testing the structure
	_, err := scanner.Scan(ctx, "https://example.com", options)
	
	// We expect this to fail since example.com doesn't have SCIM endpoints
	// but it should fail gracefully, not panic
	if err != nil {
		t.Logf("Expected error for non-SCIM target: %v", err)
	}
}

func TestUpdateConfigFromOptions(t *testing.T) {
	scanner := NewScanner().(*Scanner)
	
	options := map[string]string{
		"auth-token":  "test-token",
		"auth-type":   "bearer",
		"username":    "testuser",
		"password":    "testpass",
		"timeout":     "60s",
		"verify-ssl":  "false",
		"test-auth":   "true",
		"test-filters": "false",
	}
	
	scanner.updateConfigFromOptions(options)
	
	if scanner.config.AuthToken != "test-token" {
		t.Errorf("Expected auth token 'test-token', got '%s'", scanner.config.AuthToken)
	}
	
	if scanner.config.AuthType != "bearer" {
		t.Errorf("Expected auth type 'bearer', got '%s'", scanner.config.AuthType)
	}
	
	if scanner.config.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", scanner.config.Username)
	}
	
	if scanner.config.Password != "testpass" {
		t.Errorf("Expected password 'testpass', got '%s'", scanner.config.Password)
	}
	
	if scanner.config.Timeout != 60*time.Second {
		t.Errorf("Expected timeout 60s, got %v", scanner.config.Timeout)
	}
	
	if scanner.config.VerifySSL != false {
		t.Errorf("Expected verify SSL false, got %v", scanner.config.VerifySSL)
	}
	
	if scanner.config.TestAuthentication != true {
		t.Errorf("Expected test authentication true, got %v", scanner.config.TestAuthentication)
	}
	
	if scanner.config.TestFilters != false {
		t.Errorf("Expected test filters false, got %v", scanner.config.TestFilters)
	}
}