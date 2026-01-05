// internal/orchestrator/scope_validator_test.go
//
// Scope Validator Tests - Bug Bounty Program Scope Validation
//
// Tests scope validation functionality extracted from bounty_engine.go

package orchestrator

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/orchestrator/scanners"
)

// TestScopeValidatorDisabledWhenNilManager validates behavior with nil scope manager
func TestScopeValidatorDisabledWhenNilManager(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := BugBountyConfig{
		EnableScopeValidation: true,
	}

	validator := NewScopeValidator(nil, logger, config)

	if validator.IsEnabled() {
		t.Error("IsEnabled() should return false when scope manager is nil")
	}

	// Create test assets
	testAssets := []*scanners.AssetPriority{
		{
			Asset: &discovery.Asset{
				Value: "example.com",
				Type:  discovery.AssetTypeDomain,
			},
			Priority: 100,
		},
		{
			Asset: &discovery.Asset{
				Value: "test.example.com",
				Type:  discovery.AssetTypeDomain,
			},
			Priority: 90,
		},
	}

	result := validator.FilterAssets(testAssets)

	if result == nil {
		t.Fatal("FilterAssets() should not return nil")
	}

	// When disabled, all assets should be in-scope
	if len(result.InScope) != len(testAssets) {
		t.Errorf("Expected %d in-scope assets, got %d", len(testAssets), len(result.InScope))
	}

	if len(result.OutOfScope) != 0 {
		t.Errorf("Expected 0 out-of-scope assets, got %d", len(result.OutOfScope))
	}

	if len(result.Unknown) != 0 {
		t.Errorf("Expected 0 unknown assets, got %d", len(result.Unknown))
	}

	t.Log("SUCCESS: Scope validator correctly disabled when manager is nil")
}

// TestScopeValidatorEmptyAssetList validates handling of empty asset list
func TestScopeValidatorEmptyAssetList(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := BugBountyConfig{}
	validator := NewScopeValidator(nil, logger, config)

	result := validator.FilterAssets([]*scanners.AssetPriority{})

	if result == nil {
		t.Fatal("FilterAssets() should not return nil for empty input")
	}

	if len(result.InScope) != 0 {
		t.Errorf("Expected 0 in-scope assets for empty input, got %d", len(result.InScope))
	}

	t.Log("SUCCESS: Empty asset list handled correctly")
}

// TestScopeValidatorIsEnabledCheck validates IsEnabled logic
func TestScopeValidatorIsEnabledCheck(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	tests := []struct {
		name            string
		scopeManager    interface{}
		expectedEnabled bool
	}{
		{
			name:            "Disabled - nil scope manager",
			scopeManager:    nil,
			expectedEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := BugBountyConfig{}

			var validator *ScopeValidator
			if tt.scopeManager == nil {
				validator = NewScopeValidator(nil, logger, config)
			} else {
				// For real scope manager, would need DB - test nil case only
				validator = NewScopeValidator(nil, logger, config)
			}

			enabled := validator.IsEnabled()
			if enabled != tt.expectedEnabled {
				t.Errorf("IsEnabled() = %v, want %v", enabled, tt.expectedEnabled)
			}
		})
	}

	t.Log("SUCCESS: IsEnabled() logic works correctly")
}

// TestScopeValidatorResultStructure validates ValidationResult structure
func TestScopeValidatorResultStructure(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := BugBountyConfig{}
	validator := NewScopeValidator(nil, logger, config)

	testAssets := []*scanners.AssetPriority{
		{
			Asset: &discovery.Asset{
				Value: "example.com",
				Type:  discovery.AssetTypeDomain,
			},
			Priority: 100,
		},
	}

	result := validator.FilterAssets(testAssets)

	// Check result structure
	if result.InScope == nil {
		t.Error("InScope slice should not be nil")
	}

	if result.OutOfScope == nil {
		t.Error("OutOfScope slice should not be nil")
	}

	if result.Unknown == nil {
		t.Error("Unknown slice should not be nil")
	}

	if result.Duration < 0 {
		t.Error("Duration should not be negative")
	}

	t.Log("SUCCESS: ValidationResult structure is correct")
}
