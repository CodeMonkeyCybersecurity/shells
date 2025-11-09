package types

import (
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type ScanType string

const (
	ScanTypePort      ScanType = "port"
	ScanTypeSSL       ScanType = "ssl"
	ScanTypeWeb       ScanType = "web"
	ScanTypeVuln      ScanType = "vulnerability"
	ScanTypeDNS       ScanType = "dns"
	ScanTypeDirectory ScanType = "directory"
	ScanTypeSCIM      ScanType = "scim"
	ScanTypeSmuggling ScanType = "smuggling"
	ScanTypeAuth      ScanType = "auth"
	ScanTypeSAML      ScanType = "saml"
	ScanTypeOAuth2    ScanType = "oauth2"
	ScanTypeWebAuthn  ScanType = "webauthn"
)

type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
)

type FindingStatus string

const (
	FindingStatusNew      FindingStatus = "new"
	FindingStatusActive   FindingStatus = "active"
	FindingStatusFixed    FindingStatus = "fixed"
	FindingStatusDuplicate FindingStatus = "duplicate"
	FindingStatusReopened FindingStatus = "reopened"
)

type Finding struct {
	ID            string                 `json:"id" db:"id"`
	ScanID        string                 `json:"scan_id" db:"scan_id"`
	Tool          string                 `json:"tool" db:"tool"`
	Type          string                 `json:"type" db:"type"`
	Severity      Severity               `json:"severity" db:"severity"`
	Title         string                 `json:"title" db:"title"`
	Description   string                 `json:"description" db:"description"`
	Evidence      string                 `json:"evidence,omitempty" db:"evidence"`
	Solution      string                 `json:"solution,omitempty" db:"solution"`
	References    []string               `json:"references,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	Fingerprint   string                 `json:"fingerprint,omitempty" db:"fingerprint"`       // Hash for deduplication across scans
	FirstScanID   string                 `json:"first_scan_id,omitempty" db:"first_scan_id"`   // Scan ID where first detected
	Status        FindingStatus          `json:"status,omitempty" db:"status"`                 // new, active, fixed, duplicate, reopened
	Verified      bool                   `json:"verified" db:"verified"`                       // Manually verified
	FalsePositive bool                   `json:"false_positive" db:"false_positive"`           // Marked as false positive
	CreatedAt     time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at" db:"updated_at"`
}

type CorrelationResult struct {
	ID              string                 `json:"id" db:"id"`
	ScanID          string                 `json:"scan_id" db:"scan_id"`
	InsightType     string                 `json:"insight_type" db:"insight_type"`       // attack_chain, infrastructure_correlation, temporal_pattern, technology_vulnerability
	Severity        Severity               `json:"severity" db:"severity"`
	Title           string                 `json:"title" db:"title"`
	Description     string                 `json:"description,omitempty" db:"description"`
	Confidence      float64                `json:"confidence" db:"confidence"`           // 0.0-1.0
	RelatedFindings []string               `json:"related_findings,omitempty"`           // Array of finding IDs
	AttackPath      []map[string]interface{} `json:"attack_path,omitempty"`              // Step-by-step attack chain
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt       time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at" db:"updated_at"`
}

type ScanRequest struct {
	ID           string                 `json:"id" db:"id"`
	Target       string                 `json:"target" db:"target"`
	Type         ScanType               `json:"type" db:"type"`
	Profile      string                 `json:"profile,omitempty" db:"profile"`
	Options      map[string]string      `json:"options,omitempty"`
	ScheduledAt  *time.Time             `json:"scheduled_at,omitempty" db:"scheduled_at"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
	StartedAt    *time.Time             `json:"started_at,omitempty" db:"started_at"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty" db:"completed_at"`
	Status       ScanStatus             `json:"status" db:"status"`
	ErrorMessage string                 `json:"error_message,omitempty" db:"error_message"`
	WorkerID     string                 `json:"worker_id,omitempty" db:"worker_id"`
	Config       map[string]interface{} `json:"config,omitempty" db:"config"`       // Scan configuration (timeouts, enabled scanners)
	Result       map[string]interface{} `json:"result,omitempty" db:"result"`       // Scan results summary (assets, phases, findings count)
	Checkpoint   map[string]interface{} `json:"checkpoint,omitempty" db:"checkpoint"` // Checkpoint data for resumable scans
}

type ScanResult struct {
	ScanID      string    `json:"scan_id"`
	Findings    []Finding `json:"findings"`
	Summary     Summary   `json:"summary"`
	CompletedAt time.Time `json:"completed_at"`
}

type Summary struct {
	Total      int              `json:"total"`
	BySeverity map[Severity]int `json:"by_severity"`
	ByTool     map[string]int   `json:"by_tool"`
}

type Job struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Payload   map[string]interface{} `json:"payload"`
	Status    string                 `json:"status"`
	Priority  int                    `json:"priority"`
	Retries   int                    `json:"retries"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

type WorkerStatus struct {
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname"`
	Status       string    `json:"status"`
	CurrentJob   string    `json:"current_job,omitempty"`
	JobsComplete int       `json:"jobs_complete"`
	LastPing     time.Time `json:"last_ping"`
}

type ScanProfile struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	ScanTypes   []ScanType        `json:"scan_types"`
	Options     map[string]string `json:"options"`
	RateLimit   int               `json:"rate_limit"`
	Timeout     time.Duration     `json:"timeout"`
}

// DiscoveryTarget represents a target for discovery with all possible identifiers
type DiscoveryTarget struct {
	Identifier    string                 `json:"identifier"` // Original input
	Type          string                 `json:"type"`       // Type of identifier
	Confidence    float64                `json:"confidence"` // Classification confidence
	PrimaryDomain string                 `json:"primary_domain,omitempty"`
	PrimaryIP     string                 `json:"primary_ip,omitempty"`
	IPRange       string                 `json:"ip_range,omitempty"`
	CompanyName   string                 `json:"company_name,omitempty"`
	ASN           string                 `json:"asn,omitempty"`
	GitHubOrg     string                 `json:"github_org,omitempty"`
	AWSAccountID  string                 `json:"aws_account_id,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}
