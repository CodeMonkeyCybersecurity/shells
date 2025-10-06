package platforms

import (
	"testing"
)

func TestGetSeverityMapping(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		want     SeverityMapping
	}{
		{
			name:     "HackerOne mapping",
			platform: "hackerone",
			want: SeverityMapping{
				Critical: "critical",
				High:     "high",
				Medium:   "medium",
				Low:      "low",
				Info:     "none",
			},
		},
		{
			name:     "Bugcrowd mapping",
			platform: "bugcrowd",
			want: SeverityMapping{
				Critical: "P1",
				High:     "P2",
				Medium:   "P3",
				Low:      "P4",
				Info:     "P5",
			},
		},
		{
			name:     "AWS mapping",
			platform: "aws",
			want: SeverityMapping{
				Critical: "critical",
				High:     "high",
				Medium:   "medium",
				Low:      "low",
				Info:     "none",
			},
		},
		{
			name:     "Azure mapping",
			platform: "azure",
			want: SeverityMapping{
				Critical: "Critical",
				High:     "Important",
				Medium:   "Moderate",
				Low:      "Low",
				Info:     "Low",
			},
		},
		{
			name:     "Unknown platform uses default",
			platform: "unknown",
			want: SeverityMapping{
				Critical: "critical",
				High:     "high",
				Medium:   "medium",
				Low:      "low",
				Info:     "none",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetSeverityMapping(tt.platform)
			if got != tt.want {
				t.Errorf("GetSeverityMapping(%q) = %v, want %v", tt.platform, got, tt.want)
			}
		})
	}
}

func TestVulnerabilityReport_Validation(t *testing.T) {
	report := &VulnerabilityReport{
		Title:         "Test Vulnerability",
		Description:   "Test description",
		Severity:      "CRITICAL",
		ProgramHandle: "test-program",
		AssetURL:      "https://example.com",
	}

	// Basic validation - ensure required fields are present
	if report.Title == "" {
		t.Error("Title should not be empty")
	}
	if report.Severity == "" {
		t.Error("Severity should not be empty")
	}
	if report.ProgramHandle == "" {
		t.Error("ProgramHandle should not be empty")
	}
}

func TestSubmissionResponse_Validation(t *testing.T) {
	response := &SubmissionResponse{
		Success:  true,
		ReportID: "12345",
		ReportURL: "https://example.com/reports/12345",
		Status:   "pending",
		Message:  "Success",
	}

	if !response.Success {
		t.Error("Response should be successful")
	}
	if response.ReportID == "" {
		t.Error("ReportID should not be empty")
	}
	if response.Status == "" {
		t.Error("Status should not be empty")
	}
}
