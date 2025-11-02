package helpers

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

func TestPrioritizeAssetsForBugBounty(t *testing.T) {
	log, _ := logger.New(config.LoggerConfig{Level: "error", Format: "console"})

	tests := []struct {
		name          string
		assets        []*discovery.Asset
		expectedCount int
		topScore      int // Expected score of highest priority asset
	}{
		{
			name: "authentication endpoints",
			assets: []*discovery.Asset{
				{Value: "https://example.com/login"},
				{Value: "https://example.com/auth/callback"},
				{Value: "https://example.com/signin"},
			},
			expectedCount: 3,
			topScore:      100, // Minimum auth score
		},
		{
			name: "API endpoints",
			assets: []*discovery.Asset{
				{Value: "https://example.com/api/data"},     // Just API
				{Value: "https://example.com/graphql/data"}, // Just API
			},
			expectedCount: 2,
			topScore:      90, // Pure API score
		},
		{
			name: "admin panels",
			assets: []*discovery.Asset{
				{Value: "https://example.com/admin"},
				{Value: "https://example.com/dashboard"},
			},
			expectedCount: 2,
			topScore:      85,
		},
		{
			name: "payment endpoints",
			assets: []*discovery.Asset{
				{Value: "https://example.com/payment"},
				{Value: "https://example.com/checkout"},
			},
			expectedCount: 2,
			topScore:      85,
		},
		{
			name: "low value assets filtered out",
			assets: []*discovery.Asset{
				{Value: "https://example.com/static/logo.png"},
				{Value: "https://example.com/css/style.css"},
			},
			expectedCount: 0, // These should be filtered (score 0)
			topScore:      0,
		},
		{
			name: "mixed priority assets",
			assets: []*discovery.Asset{
				{Value: "https://example.com/signin"},       // 100 auth only
				{Value: "https://example.com/graphql"},      // 90 API only
				{Value: "https://example.com/account"},      // 70 user data only
				{Value: "https://example.com/static/js.js"}, // 0 - filtered
			},
			expectedCount: 3,
			topScore:      100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PrioritizeAssetsForBugBounty(tt.assets, log)

			if len(result) != tt.expectedCount {
				t.Errorf("Expected %d prioritized assets, got %d", tt.expectedCount, len(result))
			}

			if len(result) > 0 && result[0].Score < tt.topScore {
				t.Errorf("Expected top score >= %d, got %d", tt.topScore, result[0].Score)
			}
		})
	}
}

func TestPrioritizeAssetsOrdering(t *testing.T) {
	log, _ := logger.New(config.LoggerConfig{Level: "error", Format: "console"})

	assets := []*discovery.Asset{
		{Value: "https://example.com/profile"},  // 70
		{Value: "https://example.com/login"},    // 100
		{Value: "https://example.com/api/data"}, // 90
		{Value: "https://example.com/upload"},   // 75
	}

	result := PrioritizeAssetsForBugBounty(assets, log)

	// Verify descending order by score
	for i := 0; i < len(result)-1; i++ {
		if result[i].Score < result[i+1].Score {
			t.Errorf("Assets not properly sorted: asset[%d] score %d < asset[%d] score %d",
				i, result[i].Score, i+1, result[i+1].Score)
		}
	}

	// Verify highest score is first
	if len(result) > 0 && result[0].Score != 100 {
		t.Errorf("Expected highest score 100 first, got %d", result[0].Score)
	}
}

func TestAssetFeatures(t *testing.T) {
	log, _ := logger.New(config.LoggerConfig{Level: "error", Format: "console"})

	tests := []struct {
		name     string
		assetURL string
		features AssetFeatures
	}{
		{
			name:     "authentication features",
			assetURL: "https://example.com/login",
			features: AssetFeatures{HasAuthentication: true},
		},
		{
			name:     "API features",
			assetURL: "https://example.com/api/v1",
			features: AssetFeatures{HasAPI: true},
		},
		{
			name:     "payment features",
			assetURL: "https://example.com/payment",
			features: AssetFeatures{HasPayment: true},
		},
		{
			name:     "user data features",
			assetURL: "https://example.com/profile",
			features: AssetFeatures{HasUserData: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assets := []*discovery.Asset{{Value: tt.assetURL}}
			result := PrioritizeAssetsForBugBounty(assets, log)

			if len(result) == 0 {
				t.Fatal("Expected at least one result")
			}

			if tt.features.HasAuthentication && !result[0].Features.HasAuthentication {
				t.Error("Expected HasAuthentication to be true")
			}
			if tt.features.HasAPI && !result[0].Features.HasAPI {
				t.Error("Expected HasAPI to be true")
			}
			if tt.features.HasPayment && !result[0].Features.HasPayment {
				t.Error("Expected HasPayment to be true")
			}
			if tt.features.HasUserData && !result[0].Features.HasUserData {
				t.Error("Expected HasUserData to be true")
			}
		})
	}
}

func TestDisplayTopBugBountyTargets(t *testing.T) {
	log, _ := logger.New(config.LoggerConfig{Level: "error", Format: "console"})

	assets := []*discovery.Asset{
		{Value: "https://example.com/login"},
		{Value: "https://example.com/api/users"},
	}

	prioritized := PrioritizeAssetsForBugBounty(assets, log)

	// Test that display function doesn't panic
	t.Run("displays without panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("DisplayTopBugBountyTargets panicked: %v", r)
			}
		}()

		DisplayTopBugBountyTargets(prioritized)
	})

	t.Run("handles empty list", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("DisplayTopBugBountyTargets panicked with empty input: %v", r)
			}
		}()

		DisplayTopBugBountyTargets([]*BugBountyAssetPriority{})
	})
}

func TestPrioritizeReasonsGenerated(t *testing.T) {
	log, _ := logger.New(config.LoggerConfig{Level: "error", Format: "console"})

	assets := []*discovery.Asset{
		{Value: "https://example.com/login"},
	}

	result := PrioritizeAssetsForBugBounty(assets, log)

	if len(result) == 0 {
		t.Fatal("Expected at least one result")
	}

	if len(result[0].Reasons) == 0 {
		t.Error("Expected reasons to be generated for high-value asset")
	}

	// Check that reason makes sense
	hasAuthReason := false
	for _, reason := range result[0].Reasons {
		if reason == "Authentication endpoint" {
			hasAuthReason = true
			break
		}
	}

	if !hasAuthReason {
		t.Errorf("Expected 'Authentication endpoint' reason, got: %v", result[0].Reasons)
	}
}
