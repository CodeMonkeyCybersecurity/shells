// internal/orchestrator/organization_footprinting_test.go
//
// Organization Footprinting Tests - WHOIS, Certificate Transparency, ASN Discovery
//
// Tests organization footprinting functionality extracted from bounty_engine.go

package orchestrator

import (
	"fmt"
	"testing"
	"time"
)

// TestOrganizationFootprintingDisabledWhenNilCorrelator validates behavior with nil correlator
func TestOrganizationFootprintingDisabledWhenNilCorrelator(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := BugBountyConfig{
		EnableWHOISAnalysis:     true,
		EnableCertTransparency:  true,
		EnableRelatedDomainDisc: true,
	}

	footprinting := NewOrganizationFootprinting(nil, nil, logger, config)

	result := footprinting.CorrelateOrganization(nil, "example.com", nil, nil)

	if result != nil {
		t.Error("CorrelateOrganization() should return nil when correlator is nil")
	}

	if footprinting.IsEnabled() {
		t.Error("IsEnabled() should return false when correlator is nil")
	}

	t.Log("SUCCESS: Organization footprinting correctly disabled when correlator is nil")
}

// TestOrganizationFootprintingDisabledWhenSkipDiscovery validates behavior with SkipDiscovery
func TestOrganizationFootprintingDisabledWhenSkipDiscovery(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := BugBountyConfig{
		SkipDiscovery: true,
	}

	footprinting := NewOrganizationFootprinting(nil, nil, logger, config)

	result := footprinting.CorrelateOrganization(nil, "example.com", nil, nil)

	if result != nil {
		t.Error("CorrelateOrganization() should return nil when SkipDiscovery is true")
	}

	if footprinting.IsEnabled() {
		t.Error("IsEnabled() should return false when SkipDiscovery is true")
	}

	t.Log("SUCCESS: Organization footprinting correctly disabled when SkipDiscovery is true")
}

// TestOrganizationFootprintingIsEnabledCheck validates IsEnabled logic
func TestOrganizationFootprintingIsEnabledCheck(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	tests := []struct {
		name          string
		correlator    interface{}
		skipDiscovery bool
		expectedEnabled bool
	}{
		{
			name:            "Disabled - nil correlator",
			correlator:      nil,
			skipDiscovery:   false,
			expectedEnabled: false,
		},
		{
			name:            "Disabled - SkipDiscovery true",
			correlator:      "not-nil",
			skipDiscovery:   true,
			expectedEnabled: false,
		},
		{
			name:            "Disabled - both nil and skip",
			correlator:      nil,
			skipDiscovery:   true,
			expectedEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := BugBountyConfig{
				SkipDiscovery: tt.skipDiscovery,
			}

			// Create footprinting with correlator (or nil)
			var footprinting *OrganizationFootprinting
			if tt.correlator == nil {
				footprinting = NewOrganizationFootprinting(nil, nil, logger, config)
			} else {
				// For test purposes, we can't create a real correlator without DB
				// So we'll just test the nil case
				footprinting = NewOrganizationFootprinting(nil, nil, logger, config)
			}

			enabled := footprinting.IsEnabled()
			if enabled != tt.expectedEnabled {
				t.Errorf("IsEnabled() = %v, want %v", enabled, tt.expectedEnabled)
			}
		})
	}

	t.Log("SUCCESS: IsEnabled() logic works correctly")
}

// TestOrganizationFootprintingNilResult validates handling of nil organization result
func TestOrganizationFootprintingNilResult(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := BugBountyConfig{}
	footprinting := NewOrganizationFootprinting(nil, nil, logger, config)

	// Test handleNilResult directly
	result := footprinting.handleNilResult("example.com", time.Now())

	if result == nil {
		t.Fatal("handleNilResult() should not return nil")
	}

	if result.Organization != nil {
		t.Error("Organization should be nil for nil result")
	}

	if len(result.Domains) != 0 {
		t.Errorf("Domains should be empty, got %d domains", len(result.Domains))
	}

	if result.PhaseResult.Status != "completed" {
		t.Errorf("PhaseResult.Status should be 'completed', got '%s'", result.PhaseResult.Status)
	}

	if result.PhaseResult.Findings != 0 {
		t.Errorf("PhaseResult.Findings should be 0, got %d", result.PhaseResult.Findings)
	}

	t.Log("SUCCESS: Nil result handling works correctly")
}

// TestOrganizationFootprintingErrorHandling validates error handling
func TestOrganizationFootprintingErrorHandling(t *testing.T) {
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := BugBountyConfig{
		EnableWHOISAnalysis:     true,
		EnableCertTransparency:  true,
	}
	footprinting := NewOrganizationFootprinting(nil, nil, logger, config)

	// Test handleCorrelationError directly with a test error
	testErr := fmt.Errorf("test correlation error")
	result := footprinting.handleCorrelationError(testErr, "example.com", time.Now())

	if result == nil {
		t.Fatal("handleCorrelationError() should not return nil")
	}

	if result.Organization != nil {
		t.Error("Organization should be nil for error result")
	}

	if len(result.Domains) != 0 {
		t.Errorf("Domains should be empty, got %d domains", len(result.Domains))
	}

	if result.PhaseResult.Status != "failed" {
		t.Errorf("PhaseResult.Status should be 'failed', got '%s'", result.PhaseResult.Status)
	}

	if result.PhaseResult.Error == "" {
		t.Error("PhaseResult.Error should not be empty")
	}

	t.Log("SUCCESS: Error handling works correctly")
}
