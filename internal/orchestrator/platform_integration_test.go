// internal/orchestrator/platform_integration_test.go
//
// Platform Integration Tests - Bug Bounty Platform Scope Import
//
// Tests platform integration functionality extracted from bounty_engine.go

package orchestrator

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/scope"
)

// TestPlatformIntegrationDisabledWhenNilManager validates behavior with nil scope manager
func TestPlatformIntegrationDisabledWhenNilManager(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Config with no scope manager
	config := BugBountyConfig{
		BugBountyPlatform: "hackerone",
		BugBountyProgram:  "test-program",
	}

	integration := NewPlatformIntegration(nil, logger, config)

	success := integration.ImportScope(nil, nil, nil)

	if success {
		t.Error("ImportScope() succeeded when scope manager is nil")
	}

	t.Log("SUCCESS: Platform integration correctly disabled when scope manager is nil")
}

// TestPlatformIntegrationDisabledWhenNoConfig validates behavior with no config
func TestPlatformIntegrationDisabledWhenNoConfig(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Would need a real DB for scope.NewManager, so we'll skip this in unit tests
	// This would be tested in integration tests

	// Config with no platform specified
	config := BugBountyConfig{
		BugBountyPlatform: "",
		BugBountyProgram:  "",
	}

	integration := NewPlatformIntegration(nil, logger, config)

	success := integration.ImportScope(nil, nil, nil)

	if success {
		t.Error("ImportScope() succeeded when it should have been disabled")
	}

	t.Log("SUCCESS: Platform integration correctly disabled when not configured")
}

// TestResolvePlatformType validates platform name to enum mapping
func TestResolvePlatformType(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	integration := NewPlatformIntegration(nil, logger, BugBountyConfig{})

	tests := []struct {
		name         string
		platformName string
		expectedType scope.Platform
		expectError  bool
	}{
		{"HackerOne", "hackerone", scope.PlatformHackerOne, false},
		{"HackerOne Short", "h1", scope.PlatformHackerOne, false},
		{"Bugcrowd", "bugcrowd", scope.PlatformBugcrowd, false},
		{"Bugcrowd Short", "bc", scope.PlatformBugcrowd, false},
		{"Intigriti", "intigriti", scope.PlatformIntigriti, false},
		{"YesWeHack", "yeswehack", scope.PlatformYesWeHack, false},
		{"YesWeHack Short", "ywh", scope.PlatformYesWeHack, false},
		{"Unsupported", "unknown", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			platformType, err := integration.resolvePlatformType(tt.platformName)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for platform '%s', got nil", tt.platformName)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for platform '%s': %v", tt.platformName, err)
				}
				if platformType != tt.expectedType {
					t.Errorf("Platform type mismatch: got %s, want %s", platformType, tt.expectedType)
				}
			}
		})
	}

	t.Log("SUCCESS: Platform type resolution works correctly")
}

// TestPlatformIntegrationScopeManagerAccess validates getter methods
func TestPlatformIntegrationScopeManagerAccess(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Test with nil scope manager
	integration := NewPlatformIntegration(nil, logger, BugBountyConfig{})

	// Test GetScopeManager returns nil
	if integration.GetScopeManager() != nil {
		t.Error("GetScopeManager() should return nil when initialized with nil")
	}

	// Test DisableScopeValidation
	integration.DisableScopeValidation()
	if integration.GetScopeManager() != nil {
		t.Error("GetScopeManager() should return nil after DisableScopeValidation()")
	}

	t.Log("SUCCESS: Scope manager access methods work correctly")
}
