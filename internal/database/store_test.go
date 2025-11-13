package database

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test generateFindingFingerprint with various metadata fields
func TestGenerateFindingFingerprint_MetadataExtraction(t *testing.T) {
	tests := []struct {
		name        string
		finding     types.Finding
		expectSame  bool
		description string
	}{
		{
			name: "target field in metadata",
			finding: types.Finding{
				Tool:  "nmap",
				Type:  "open_port",
				Title: "Port 443 Open",
				Metadata: map[string]interface{}{
					"target": "example.com",
				},
			},
			expectSame:  true,
			description: "Should extract target from metadata['target']",
		},
		{
			name: "endpoint field in metadata",
			finding: types.Finding{
				Tool:  "nikto",
				Type:  "web_vuln",
				Title: "SQL Injection",
				Metadata: map[string]interface{}{
					"endpoint": "/api/users",
				},
			},
			expectSame:  true,
			description: "Should extract target from metadata['endpoint']",
		},
		{
			name: "url field in metadata",
			finding: types.Finding{
				Tool:  "burp",
				Type:  "xss",
				Title: "Reflected XSS",
				Metadata: map[string]interface{}{
					"url": "https://example.com/search",
				},
			},
			expectSame:  true,
			description: "Should extract target from metadata['url']",
		},
		{
			name: "hostname field in metadata",
			finding: types.Finding{
				Tool:  "ssl",
				Type:  "cert_vuln",
				Title: "Expired Certificate",
				Metadata: map[string]interface{}{
					"hostname": "api.example.com",
				},
			},
			expectSame:  true,
			description: "Should extract target from metadata['hostname']",
		},
		{
			name: "ip field in metadata",
			finding: types.Finding{
				Tool:  "nmap",
				Type:  "port_scan",
				Title: "SSH Open",
				Metadata: map[string]interface{}{
					"ip": "192.168.1.100",
				},
			},
			expectSame:  true,
			description: "Should extract target from metadata['ip']",
		},
		{
			name: "empty metadata",
			finding: types.Finding{
				Tool:     "test",
				Type:     "vuln",
				Title:    "Test Vulnerability",
				Metadata: map[string]interface{}{},
			},
			expectSame:  false,
			description: "Should create weak fingerprint when no target available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fingerprint := generateFindingFingerprint(tt.finding)

			// Fingerprint should never be empty
			assert.NotEmpty(t, fingerprint, "Fingerprint should never be empty")

			// Fingerprint should be consistent
			fingerprint2 := generateFindingFingerprint(tt.finding)
			assert.Equal(t, fingerprint, fingerprint2, "Same finding should produce same fingerprint")
		})
	}
}

// Test generateFindingFingerprint with evidence parsing
func TestGenerateFindingFingerprint_EvidenceParsing(t *testing.T) {
	tests := []struct {
		name        string
		finding     types.Finding
		shouldMatch bool
		description string
	}{
		{
			name: "HTTP method in evidence",
			finding: types.Finding{
				Tool:     "burp",
				Type:     "xss",
				Title:    "XSS Vulnerability",
				Evidence: "GET /api/search?q=<script>alert(1)</script> HTTP/1.1\nHost: example.com",
			},
			shouldMatch: true,
			description: "Should extract /api/search from evidence",
		},
		{
			name: "URL in evidence",
			finding: types.Finding{
				Tool:     "nikto",
				Type:     "web_vuln",
				Title:    "Directory Listing",
				Evidence: "https://example.com/admin/\nStatus: 200 OK",
			},
			shouldMatch: true,
			description: "Should extract URL from evidence",
		},
		{
			name: "URL: prefix in evidence",
			finding: types.Finding{
				Tool:     "scanner",
				Type:     "vuln",
				Title:    "Vulnerability Found",
				Evidence: "URL: https://api.example.com/users\nSeverity: High",
			},
			shouldMatch: true,
			description: "Should extract URL from URL: prefix",
		},
		{
			name: "Target: prefix in evidence",
			finding: types.Finding{
				Tool:     "scanner",
				Type:     "vuln",
				Title:    "SQL Injection",
				Evidence: "Target: /api/login\nPayload: ' OR '1'='1",
			},
			shouldMatch: true,
			description: "Should extract target from Target: prefix",
		},
		{
			name: "No parseable evidence",
			finding: types.Finding{
				Tool:     "scanner",
				Type:     "vuln",
				Title:    "Vulnerability",
				Evidence: "Some random text without URL or path",
			},
			shouldMatch: false,
			description: "Should create weak fingerprint when evidence can't be parsed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fingerprint := generateFindingFingerprint(tt.finding)
			assert.NotEmpty(t, fingerprint, "Fingerprint should never be empty")
		})
	}
}

// Test that same vulnerability at different locations gets different fingerprints
func TestGenerateFindingFingerprint_DifferentLocations(t *testing.T) {
	finding1 := types.Finding{
		Tool:  "scanner",
		Type:  "sql_injection",
		Title: "SQL Injection",
		Metadata: map[string]interface{}{
			"endpoint": "/api/users",
		},
	}

	finding2 := types.Finding{
		Tool:  "scanner",
		Type:  "sql_injection",
		Title: "SQL Injection",
		Metadata: map[string]interface{}{
			"endpoint": "/api/products",
		},
	}

	fp1 := generateFindingFingerprint(finding1)
	fp2 := generateFindingFingerprint(finding2)

	assert.NotEqual(t, fp1, fp2, "Same vulnerability type at different endpoints should have different fingerprints")
}

// Test that same vulnerability across scans gets same fingerprint
func TestGenerateFindingFingerprint_CrossScanConsistency(t *testing.T) {
	// Scan 1
	finding1 := types.Finding{
		ID:     "finding-1",
		ScanID: "scan-1",
		Tool:   "nmap",
		Type:   "open_port",
		Title:  "Port 443 Open",
		Metadata: map[string]interface{}{
			"target": "example.com",
			"port":   "443",
		},
	}

	// Scan 2 (different IDs, different scan, but same vulnerability)
	finding2 := types.Finding{
		ID:     "finding-2",
		ScanID: "scan-2",
		Tool:   "nmap",
		Type:   "open_port",
		Title:  "Port 443 Open",
		Metadata: map[string]interface{}{
			"target": "example.com",
			"port":   "443",
		},
	}

	fp1 := generateFindingFingerprint(finding1)
	fp2 := generateFindingFingerprint(finding2)

	assert.Equal(t, fp1, fp2, "Same vulnerability across different scans should have identical fingerprints")
}

// Test UpdateFindingStatus method
func TestUpdateFindingStatus(t *testing.T) {
	// Create in-memory test database
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create a test scan
	scan := &types.ScanRequest{
		ID:     "test-scan-1",
		Target: "example.com",
		Type:   types.ScanTypeWeb,
		Status: types.ScanStatusRunning,
	}
	err := store.SaveScan(ctx, scan)
	require.NoError(t, err)

	// Create a test finding
	finding := types.Finding{
		ID:          "test-finding-1",
		ScanID:      "test-scan-1",
		Tool:        "test",
		Type:        "test_vuln",
		Severity:    types.SeverityHigh,
		Title:       "Test Vulnerability",
		Description: "Test Description",
		Status:      types.FindingStatusNew,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	err = store.SaveFindings(ctx, []types.Finding{finding})
	require.NoError(t, err)

	// Update status to fixed
	err = store.UpdateFindingStatus(ctx, "test-finding-1", types.FindingStatusFixed)
	assert.NoError(t, err, "Should successfully update finding status")

	// Verify status was updated
	findings, err := store.GetFindings(ctx, "test-scan-1")
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, types.FindingStatusFixed, findings[0].Status)

	// Try to update non-existent finding
	err = store.UpdateFindingStatus(ctx, "non-existent", types.FindingStatusFixed)
	assert.Error(t, err, "Should fail when finding doesn't exist")
}

// Test MarkFindingVerified method
func TestMarkFindingVerified(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create test scan and finding
	scan := &types.ScanRequest{
		ID:     "test-scan-2",
		Target: "example.com",
		Type:   types.ScanTypeWeb,
		Status: types.ScanStatusRunning,
	}
	err := store.SaveScan(ctx, scan)
	require.NoError(t, err)

	finding := types.Finding{
		ID:        "test-finding-2",
		ScanID:    "test-scan-2",
		Tool:      "test",
		Type:      "test_vuln",
		Severity:  types.SeverityMedium,
		Title:     "Test Vulnerability",
		Verified:  false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err = store.SaveFindings(ctx, []types.Finding{finding})
	require.NoError(t, err)

	// Mark as verified
	err = store.MarkFindingVerified(ctx, "test-finding-2", true)
	assert.NoError(t, err)

	// Verify flag was set
	findings, err := store.GetFindings(ctx, "test-scan-2")
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.True(t, findings[0].Verified)

	// Unmark verification
	err = store.MarkFindingVerified(ctx, "test-finding-2", false)
	assert.NoError(t, err)

	findings, err = store.GetFindings(ctx, "test-scan-2")
	require.NoError(t, err)
	assert.False(t, findings[0].Verified)
}

// Test MarkFindingFalsePositive method
func TestMarkFindingFalsePositive(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create test scan and finding
	scan := &types.ScanRequest{
		ID:     "test-scan-3",
		Target: "example.com",
		Type:   types.ScanTypeWeb,
		Status: types.ScanStatusRunning,
	}
	err := store.SaveScan(ctx, scan)
	require.NoError(t, err)

	finding := types.Finding{
		ID:            "test-finding-3",
		ScanID:        "test-scan-3",
		Tool:          "test",
		Type:          "test_vuln",
		Severity:      types.SeverityLow,
		Title:         "Test Vulnerability",
		FalsePositive: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	err = store.SaveFindings(ctx, []types.Finding{finding})
	require.NoError(t, err)

	// Mark as false positive
	err = store.MarkFindingFalsePositive(ctx, "test-finding-3", true)
	assert.NoError(t, err)

	// Verify flag was set
	findings, err := store.GetFindings(ctx, "test-scan-3")
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.True(t, findings[0].FalsePositive)

	// Remove false positive flag
	err = store.MarkFindingFalsePositive(ctx, "test-finding-3", false)
	assert.NoError(t, err)

	findings, err = store.GetFindings(ctx, "test-scan-3")
	require.NoError(t, err)
	assert.False(t, findings[0].FalsePositive)
}

// Helper function to set up a test store
func setupTestStore(t *testing.T) (*sqlStore, func()) {
	// Create logger
	log, err := logger.New(logger.Config{
		Level:  "info",
		Format: "json",
	})
	require.NoError(t, err)

	// Create in-memory SQLite database
	store, err := NewResultStore(Config{
		Type:     "sqlite",
		Host:     ":memory:",
		Database: "test",
	}, log)
	require.NoError(t, err)

	sqlStore, ok := store.(*sqlStore)
	require.True(t, ok)

	cleanup := func() {
		_ = store.Close()
	}

	return sqlStore, cleanup
}
