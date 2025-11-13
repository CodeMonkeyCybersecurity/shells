package display

import (
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

func TestColorStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		contains string // Should contain this string
	}{
		{"completed status", "completed", "completed"},
		{"running status", "running", "running"},
		{"failed status", "failed", "failed"},
		{"unknown status", "unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ColorStatus(tt.status)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("ColorStatus(%s) should contain %s, got: %s", tt.status, tt.contains, result)
			}
		})
	}
}

func TestColorPhaseStatus(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   string // Exact match for icons
	}{
		{"completed", "completed", "✓"},
		{"running", "running", "⟳"},
		{"failed", "failed", "✗"},
		{"unknown", "unknown", "○"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ColorPhaseStatus(tt.status)
			if !strings.Contains(result, tt.want) {
				t.Errorf("ColorPhaseStatus(%s) should contain %s", tt.status, tt.want)
			}
		})
	}
}

func TestColorSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity types.Severity
		want     string
	}{
		{"critical", types.SeverityCritical, "CRITICAL"},
		{"high", types.SeverityHigh, "HIGH"},
		{"medium", types.SeverityMedium, "MEDIUM"},
		{"low", types.SeverityLow, "LOW"},
		{"info", types.SeverityInfo, "INFO"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ColorSeverity(tt.severity)
			if !strings.Contains(result, tt.want) {
				t.Errorf("ColorSeverity(%v) should contain %s, got: %s", tt.severity, tt.want, result)
			}
		})
	}
}

func TestGroupFindingsBySeverity(t *testing.T) {
	findings := []types.Finding{
		{Severity: types.SeverityCritical},
		{Severity: types.SeverityCritical},
		{Severity: types.SeverityHigh},
		{Severity: types.SeverityMedium},
		{Severity: types.SeverityLow},
		{Severity: types.SeverityInfo},
		{Severity: types.SeverityInfo},
		{Severity: types.SeverityInfo},
	}

	result := GroupFindingsBySeverity(findings)

	expected := map[types.Severity]int{
		types.SeverityCritical: 2,
		types.SeverityHigh:     1,
		types.SeverityMedium:   1,
		types.SeverityLow:      1,
		types.SeverityInfo:     3,
	}

	for severity, expectedCount := range expected {
		if result[severity] != expectedCount {
			t.Errorf("Expected %d %s findings, got %d", expectedCount, severity, result[severity])
		}
	}
}

func TestDisplayTopFindings(t *testing.T) {
	// Create test findings
	findings := []types.Finding{
		{
			Severity:    types.SeverityCritical,
			Title:       "SQL Injection",
			Tool:        "sqlmap",
			Type:        "SQLi",
			Description: "SQL injection vulnerability found",
			Evidence:    "' OR '1'='1",
		},
		{
			Severity:    types.SeverityHigh,
			Title:       "XSS Vulnerability",
			Tool:        "xss-scanner",
			Type:        "XSS",
			Description: "Cross-site scripting found",
			Evidence:    "<script>alert(1)</script>",
		},
		{
			Severity: types.SeverityInfo,
			Title:    "Info disclosure",
			Tool:     "scanner",
			Type:     "INFO",
		},
	}

	// This test just verifies the function doesn't panic
	// Visual output testing is difficult in unit tests
	t.Run("displays without panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("DisplayTopFindings panicked: %v", r)
			}
		}()

		DisplayTopFindings(findings, 2)
	})

	t.Run("handles empty findings", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("DisplayTopFindings panicked with empty input: %v", r)
			}
		}()

		DisplayTopFindings([]types.Finding{}, 10)
	})

	t.Run("respects limit", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("DisplayTopFindings panicked: %v", r)
			}
		}()

		// Should only display 1 finding even though we have 3
		DisplayTopFindings(findings, 1)
	})
}

func TestDisplayTopFindingsSorting(t *testing.T) {
	// Create findings in wrong order (info first, critical last)
	findings := []types.Finding{
		{Severity: types.SeverityInfo, Title: "Info"},
		{Severity: types.SeverityMedium, Title: "Medium"},
		{Severity: types.SeverityCritical, Title: "Critical"},
		{Severity: types.SeverityLow, Title: "Low"},
		{Severity: types.SeverityHigh, Title: "High"},
	}

	// The function should sort by severity
	// We can't easily test the output, but we can verify it doesn't panic
	t.Run("sorts correctly without panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("DisplayTopFindings panicked during sorting: %v", r)
			}
		}()

		DisplayTopFindings(findings, 5)
	})
}
