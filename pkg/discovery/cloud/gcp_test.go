package cloud

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

func TestGCPDiscovery(t *testing.T) {
	// Create test logger
	log, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "json",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create GCP discovery client
	gcp := NewGCPDiscovery(log)

	// Test context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test cases
	testCases := []struct {
		name   string
		domain string
		test   func(t *testing.T)
	}{
		{
			name:   "Test GCS bucket name generation",
			domain: "example.com",
			test: func(t *testing.T) {
				names := gcp.generateBucketNames("example", "example.com")
				if len(names) == 0 {
					t.Error("Expected bucket names to be generated")
				}

				// Check some expected patterns
				expectedPatterns := []string{
					"example",
					"example-backup",
					"example-logs",
					"example-static",
				}

				nameMap := make(map[string]bool)
				for _, name := range names {
					nameMap[name] = true
				}

				for _, expected := range expectedPatterns {
					if !nameMap[expected] {
						t.Errorf("Expected bucket name %s not found", expected)
					}
				}
			},
		},
		{
			name:   "Test project ID generation",
			domain: "acme-corp.com",
			test: func(t *testing.T) {
				projectIDs := gcp.generateProjectIDs("acme-corp", "acme-corp.com")
				if len(projectIDs) == 0 {
					t.Error("Expected project IDs to be generated")
				}

				// Check for valid project IDs
				for _, id := range projectIDs {
					if !isValidProjectID(id) {
						t.Errorf("Invalid project ID generated: %s", id)
					}
				}
			},
		},
		{
			name:   "Test Firebase URL patterns",
			domain: "test-app.com",
			test: func(t *testing.T) {
				apps, err := gcp.DiscoverFirebaseApps(ctx, "test-app.com")
				if err != nil {
					t.Errorf("DiscoverFirebaseApps failed: %v", err)
				}

				// Check that URLs are properly formatted
				for _, app := range apps {
					if app.URL == "" {
						t.Error("Firebase app URL should not be empty")
					}
					if app.ProjectID == "" {
						t.Error("Firebase project ID should not be empty")
					}
				}
			},
		},
		{
			name:   "Test comprehensive discovery",
			domain: "google.com",
			test: func(t *testing.T) {
				assets, err := gcp.DiscoverAll(ctx, "google.com", []string{})
				if err != nil {
					t.Errorf("DiscoverAll failed: %v", err)
				}

				// Check that discovery attempted various services
				if assets == nil {
					t.Error("Expected assets to be returned")
				}

				// Log summary for debugging
				t.Logf("Discovery summary for %s:", "google.com")
				t.Logf("  Project IDs: %d", len(assets.ProjectIDs))
				t.Logf("  GCS Buckets: %d", len(assets.GCSBuckets))
				t.Logf("  App Engine Apps: %d", len(assets.AppEngineApps))
				t.Logf("  Cloud Run Services: %d", len(assets.CloudRunServices))
				t.Logf("  Cloud Functions: %d", len(assets.CloudFunctions))
				t.Logf("  Firebase Apps: %d", len(assets.FirebaseApps))
				t.Logf("  Service Accounts: %d", len(assets.ServiceAccounts))
			},
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, tc.test)
	}
}

func TestGCPBucketNameValidation(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Valid simple name", "my-bucket", true},
		{"Valid with numbers", "bucket123", true},
		{"Valid with dots", "my.bucket.name", true},
		{"Valid with underscores", "my_bucket_name", true},
		{"Too short", "ab", false},
		{"Too long", "this-is-a-very-long-bucket-name-that-exceeds-the-maximum-allowed-length-for-gcs", false},
		{"Starts with hyphen", "-bucket", false},
		{"Ends with hyphen", "bucket-", false},
		{"Contains uppercase", "MyBucket", false},
		{"Contains spaces", "my bucket", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidGCSBucketName(tc.input)
			if result != tc.expected {
				t.Errorf("isValidGCSBucketName(%s) = %v, expected %v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestGCPProjectIDValidation(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Valid simple ID", "my-project", true},
		{"Valid with numbers", "project123", true},
		{"Valid complex", "my-project-123", true},
		{"Too short", "proj", false},
		{"Too long", "this-is-a-very-long-project-id-exceeding-limit", false},
		{"Starts with number", "123project", false},
		{"Starts with hyphen", "-project", false},
		{"Ends with hyphen", "project-", false},
		{"Contains uppercase", "MyProject", false},
		{"Contains underscore", "my_project", false},
		{"Contains spaces", "my project", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidProjectID(tc.input)
			if result != tc.expected {
				t.Errorf("isValidProjectID(%s) = %v, expected %v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestExtractProjectIDFromJSON(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Valid Firebase config",
			input:    `{"projectId": "my-firebase-project", "apiKey": "AIzaSyD..."}`,
			expected: "my-firebase-project",
		},
		{
			name:     "Project ID with spaces",
			input:    `{ "projectId" : "another-project" , "other": "data"}`,
			expected: "another-project",
		},
		{
			name:     "No project ID",
			input:    `{"apiKey": "AIzaSyD...", "authDomain": "example.firebaseapp.com"}`,
			expected: "",
		},
		{
			name:     "Empty JSON",
			input:    `{}`,
			expected: "",
		},
		{
			name:     "Invalid JSON",
			input:    `not json at all`,
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := extractProjectIDFromJSON(tc.input)
			if result != tc.expected {
				t.Errorf("extractProjectIDFromJSON() = %v, expected %v", result, tc.expected)
			}
		})
	}
}

func TestDeduplicateStrings(t *testing.T) {
	testCases := []struct {
		name     string
		input    []string
		expected int // expected count after deduplication
	}{
		{
			name:     "No duplicates",
			input:    []string{"a", "b", "c"},
			expected: 3,
		},
		{
			name:     "With duplicates",
			input:    []string{"a", "b", "a", "c", "b", "a"},
			expected: 3,
		},
		{
			name:     "All duplicates",
			input:    []string{"test", "test", "test"},
			expected: 1,
		},
		{
			name:     "Empty slice",
			input:    []string{},
			expected: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := deduplicateStrings(tc.input)
			if len(result) != tc.expected {
				t.Errorf("deduplicateStrings() returned %d items, expected %d", len(result), tc.expected)
			}
		})
	}
}
