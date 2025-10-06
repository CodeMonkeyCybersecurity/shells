package platforms

import (
	"context"
	"fmt"
	"time"
)

// Platform represents a bug bounty platform integration
type Platform interface {
	// Name returns the platform name
	Name() string

	// Submit submits a vulnerability report to the platform
	Submit(ctx context.Context, report *VulnerabilityReport) (*SubmissionResponse, error)

	// GetPrograms lists available bug bounty programs
	GetPrograms(ctx context.Context) ([]*Program, error)

	// GetProgramByHandle retrieves a specific program by handle/identifier
	GetProgramByHandle(ctx context.Context, handle string) (*Program, error)

	// ValidateCredentials validates the API credentials
	ValidateCredentials(ctx context.Context) error
}

// VulnerabilityReport represents a standardized vulnerability report
type VulnerabilityReport struct {
	// Basic information
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	CVSSScore   float64 `json:"cvss_score,omitempty"`
	CWE         string  `json:"cwe,omitempty"`

	// Target information
	ProgramHandle string `json:"program_handle"`
	AssetURL      string `json:"asset_url"`
	AssetType     string `json:"asset_type,omitempty"` // domain, ip, mobile_app, etc.

	// Technical details
	ProofOfConcept string   `json:"proof_of_concept"`
	ReproSteps     []string `json:"repro_steps"`
	Impact         string   `json:"impact"`
	Remediation    string   `json:"remediation,omitempty"`

	// Supporting data
	Attachments []Attachment `json:"attachments,omitempty"`
	References  []string     `json:"references,omitempty"`

	// Metadata
	DiscoveredAt time.Time `json:"discovered_at"`
	ScanID       string    `json:"scan_id,omitempty"`
	ToolName     string    `json:"tool_name,omitempty"`

	// Platform-specific fields
	PlatformData map[string]interface{} `json:"platform_data,omitempty"`
}

// Validate checks if the vulnerability report has all required fields
func (r *VulnerabilityReport) Validate() error {
	if r.Title == "" {
		return fmt.Errorf("report title is required")
	}
	if r.Description == "" {
		return fmt.Errorf("report description is required")
	}
	if r.ProgramHandle == "" {
		return fmt.Errorf("program handle is required")
	}
	if r.Severity == "" {
		return fmt.Errorf("severity is required")
	}
	if r.CVSSScore < 0 || r.CVSSScore > 10 {
		return fmt.Errorf("CVSS score must be between 0.0 and 10.0, got %.1f", r.CVSSScore)
	}
	return nil
}

// Attachment represents a file attachment
type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Data        []byte `json:"data"`
	URL         string `json:"url,omitempty"` // For remote attachments
}

// SubmissionResponse represents the response from submitting a report
type SubmissionResponse struct {
	Success      bool                   `json:"success"`
	ReportID     string                 `json:"report_id"`
	ReportURL    string                 `json:"report_url"`
	Status       string                 `json:"status"` // draft, pending, accepted, etc.
	Message      string                 `json:"message,omitempty"`
	SubmittedAt  time.Time              `json:"submitted_at"`
	PlatformData map[string]interface{} `json:"platform_data,omitempty"`
}

// Program represents a bug bounty program
type Program struct {
	Handle      string   `json:"handle"`
	Name        string   `json:"name"`
	Platform    string   `json:"platform"`
	URL         string   `json:"url"`
	IsActive    bool     `json:"is_active"`
	Scope       []Asset  `json:"scope"`
	OutOfScope  []Asset  `json:"out_of_scope"`
	Rewards     *Rewards `json:"rewards,omitempty"`
	Description string   `json:"description,omitempty"`
}

// Asset represents an in-scope or out-of-scope asset
type Asset struct {
	Type        string `json:"type"` // domain, ip_range, mobile_app, etc.
	Identifier  string `json:"identifier"`
	Description string `json:"description,omitempty"`
	MaxSeverity string `json:"max_severity,omitempty"`
}

// Rewards represents the reward structure for a program
type Rewards struct {
	Currency string             `json:"currency"`
	Bounties map[string]float64 `json:"bounties"` // severity -> amount
}

// SeverityMapping maps shells severity levels to platform-specific severities
type SeverityMapping struct {
	Critical string
	High     string
	Medium   string
	Low      string
	Info     string
}

// GetSeverityMapping returns platform-specific severity mappings
func GetSeverityMapping(platform string) SeverityMapping {
	mappings := map[string]SeverityMapping{
		"hackerone": {
			Critical: "critical",
			High:     "high",
			Medium:   "medium",
			Low:      "low",
			Info:     "none",
		},
		"bugcrowd": {
			Critical: "P1",
			High:     "P2",
			Medium:   "P3",
			Low:      "P4",
			Info:     "P5",
		},
		"aws": {
			Critical: "critical",
			High:     "high",
			Medium:   "medium",
			Low:      "low",
			Info:     "none",
		},
		"azure": {
			Critical: "Critical",
			High:     "Important",
			Medium:   "Moderate",
			Low:      "Low",
			Info:     "Low",
		},
	}

	if mapping, ok := mappings[platform]; ok {
		return mapping
	}

	// Default mapping
	return mappings["hackerone"]
}
