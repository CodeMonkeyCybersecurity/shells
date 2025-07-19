package prowler

import (
	"context"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// Config represents Prowler configuration
type Config struct {
	NomadAddr    string        `yaml:"nomad_addr"`
	DockerImage  string        `yaml:"docker_image"`
	OutputFormat string        `yaml:"output_format"`
	ParallelJobs int           `yaml:"parallel_jobs"`
	Timeout      time.Duration `yaml:"timeout"`
	AWSProfile   string        `yaml:"aws_profile"`
	CacheDir     string        `yaml:"cache_dir"`
}

// ProwlerFinding represents a finding from Prowler JSON output
type ProwlerFinding struct {
	Provider     string              `json:"Provider"`
	CheckID      string              `json:"CheckID"`
	CheckTitle   string              `json:"CheckTitle"`
	ServiceName  string              `json:"ServiceName"`
	Status       string              `json:"Status"`
	Severity     string              `json:"Severity"`
	ResourceArn  string              `json:"ResourceArn"`
	ResourceUID  string              `json:"ResourceUID,omitempty"`
	ResourceName string              `json:"ResourceName,omitempty"`
	Region       string              `json:"Region"`
	Description  string              `json:"Description,omitempty"`
	Risk         string              `json:"Risk,omitempty"`
	Remediation  string              `json:"Remediation,omitempty"`
	Compliance   map[string][]string `json:"Compliance,omitempty"`
	Categories   []string            `json:"Categories,omitempty"`
	Timestamp    string              `json:"Timestamp,omitempty"`
}

// Check represents an available Prowler check
type Check struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Service     string   `json:"service"`
	Severity    string   `json:"severity"`
	Categories  []string `json:"categories,omitempty"`
	Compliance  []string `json:"compliance,omitempty"`
}

// ScanResult represents the result of a Prowler scan
type ScanResult struct {
	JobID       string           `json:"job_id"`
	Profile     string           `json:"profile"`
	StartTime   time.Time        `json:"start_time"`
	EndTime     time.Time        `json:"end_time"`
	Duration    time.Duration    `json:"duration"`
	TotalChecks int              `json:"total_checks"`
	Passed      int              `json:"passed"`
	Failed      int              `json:"failed"`
	Findings    []ProwlerFinding `json:"findings"`
	Summary     ScanSummary      `json:"summary"`
}

// ScanSummary provides aggregated scan statistics
type ScanSummary struct {
	TotalChecks      int                 `json:"total_checks"`
	PassedChecks     int                 `json:"passed_checks"`
	FailedChecks     int                 `json:"failed_checks"`
	CriticalFindings int                 `json:"critical_findings"`
	HighFindings     int                 `json:"high_findings"`
	MediumFindings   int                 `json:"medium_findings"`
	LowFindings      int                 `json:"low_findings"`
	ServiceBreakdown map[string]int      `json:"service_breakdown"`
	RegionBreakdown  map[string]int      `json:"region_breakdown"`
	SeverityTrend    []SeverityDataPoint `json:"severity_trend,omitempty"`
}

// SeverityDataPoint represents severity data over time
type SeverityDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Critical  int       `json:"critical"`
	High      int       `json:"high"`
	Medium    int       `json:"medium"`
	Low       int       `json:"low"`
}

// ProwlerConfig represents Prowler execution configuration
type ProwlerConfig struct {
	Profile       string            `json:"profile"`
	Groups        []string          `json:"groups,omitempty"`
	Checks        []string          `json:"checks,omitempty"`
	ExcludeGroups []string          `json:"exclude_groups,omitempty"`
	ExcludeChecks []string          `json:"exclude_checks,omitempty"`
	Regions       []string          `json:"regions,omitempty"`
	Services      []string          `json:"services,omitempty"`
	Severity      []string          `json:"severity,omitempty"`
	OutputDir     string            `json:"output_dir,omitempty"`
	Quiet         bool              `json:"quiet"`
	Parallel      int               `json:"parallel"`
	Environment   map[string]string `json:"environment,omitempty"`
}

// CheckGroup represents a group of related Prowler checks
type CheckGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Service     string   `json:"service"`
	Checks      []string `json:"checks"`
	Categories  []string `json:"categories"`
}

// ComplianceFramework represents compliance framework mappings
type ComplianceFramework struct {
	Framework   string            `json:"framework"`
	Version     string            `json:"version"`
	Controls    map[string]string `json:"controls"`
	Description string            `json:"description"`
}

// AWSService represents an AWS service with available checks
type AWSService struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Description string   `json:"description"`
	Checks      []string `json:"checks"`
	Categories  []string `json:"categories"`
	Regions     []string `json:"regions,omitempty"`
}

// ProwlerReport represents a comprehensive Prowler assessment report
type ProwlerReport struct {
	Metadata        ReportMetadata      `json:"metadata"`
	Summary         ScanSummary         `json:"summary"`
	Findings        []ProwlerFinding    `json:"findings"`
	Services        []ServiceSummary    `json:"services"`
	Regions         []RegionSummary     `json:"regions"`
	Compliance      []ComplianceSummary `json:"compliance"`
	Trends          []TrendAnalysis     `json:"trends,omitempty"`
	Recommendations []Recommendation    `json:"recommendations"`
}

// ReportMetadata contains report generation information
type ReportMetadata struct {
	GeneratedAt    time.Time     `json:"generated_at"`
	ProwlerVersion string        `json:"prowler_version"`
	AWSProfile     string        `json:"aws_profile"`
	ScanDuration   time.Duration `json:"scan_duration"`
	TotalResources int           `json:"total_resources"`
	AccountID      string        `json:"account_id,omitempty"`
	Regions        []string      `json:"regions"`
}

// ServiceSummary provides per-service analysis
type ServiceSummary struct {
	Service         string  `json:"service"`
	TotalChecks     int     `json:"total_checks"`
	PassedChecks    int     `json:"passed_checks"`
	FailedChecks    int     `json:"failed_checks"`
	CriticalIssues  int     `json:"critical_issues"`
	HighIssues      int     `json:"high_issues"`
	MediumIssues    int     `json:"medium_issues"`
	LowIssues       int     `json:"low_issues"`
	ComplianceScore float64 `json:"compliance_score"`
}

// RegionSummary provides per-region analysis
type RegionSummary struct {
	Region         string   `json:"region"`
	TotalChecks    int      `json:"total_checks"`
	PassedChecks   int      `json:"passed_checks"`
	FailedChecks   int      `json:"failed_checks"`
	CriticalIssues int      `json:"critical_issues"`
	HighIssues     int      `json:"high_issues"`
	MediumIssues   int      `json:"medium_issues"`
	LowIssues      int      `json:"low_issues"`
	Services       []string `json:"services"`
}

// ComplianceSummary provides compliance framework analysis
type ComplianceSummary struct {
	Framework       string   `json:"framework"`
	TotalControls   int      `json:"total_controls"`
	PassingControls int      `json:"passing_controls"`
	FailingControls int      `json:"failing_controls"`
	ComplianceScore float64  `json:"compliance_score"`
	CriticalGaps    []string `json:"critical_gaps"`
}

// TrendAnalysis provides historical trend data
type TrendAnalysis struct {
	Date             time.Time `json:"date"`
	TotalFindings    int       `json:"total_findings"`
	NewFindings      int       `json:"new_findings"`
	ResolvedFindings int       `json:"resolved_findings"`
	CriticalTrend    int       `json:"critical_trend"`
	HighTrend        int       `json:"high_trend"`
	ComplianceScore  float64   `json:"compliance_score"`
}

// Recommendation provides actionable remediation advice
type Recommendation struct {
	Priority       string   `json:"priority"`
	Service        string   `json:"service"`
	Category       string   `json:"category"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Remediation    string   `json:"remediation"`
	Impact         string   `json:"impact"`
	Effort         string   `json:"effort"`
	References     []string `json:"references"`
	AffectedChecks []string `json:"affected_checks"`
}

// ProwlerJobStatus represents the status of a Prowler scan job
type ProwlerJobStatus struct {
	JobID       string    `json:"job_id"`
	Status      string    `json:"status"`
	StartTime   time.Time `json:"start_time"`
	Progress    float64   `json:"progress"`
	CurrentTask string    `json:"current_task"`
	Message     string    `json:"message,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// ProwlerClientInterface defines the contract for Prowler operations
type ProwlerClientInterface interface {
	// Scan operations
	RunAllChecks(ctx context.Context, profile string) ([]types.Finding, error)
	RunChecksByGroup(ctx context.Context, profile string, groups []string) ([]types.Finding, error)
	RunSpecificChecks(ctx context.Context, profile string, checkIDs []string) ([]types.Finding, error)

	// Discovery operations
	GetAvailableChecks(ctx context.Context) ([]Check, error)
	GetCheckGroups(ctx context.Context) ([]CheckGroup, error)
	GetServices(ctx context.Context) ([]AWSService, error)

	// Job management
	GetJobStatus(ctx context.Context, jobID string) (*ProwlerJobStatus, error)
	CancelJob(ctx context.Context, jobID string) error

	// Health and diagnostics
	Health(ctx context.Context) error
	Version(ctx context.Context) (string, error)
}

// Default check groups commonly used in security assessments
var DefaultCheckGroups = map[string][]string{
	"iam": {
		"iam_password_policy_minimum_length_14",
		"iam_password_policy_reuse_24",
		"iam_password_policy_expires_passwords_within_90_days_or_less",
		"iam_user_mfa_enabled_console_access",
		"iam_root_access_key_check",
		"iam_mfa_enabled_for_root",
		"iam_policy_no_administrative_privileges",
	},
	"s3": {
		"s3_bucket_public_access_block",
		"s3_bucket_secure_transport_policy",
		"s3_bucket_ssl_requests_only",
		"s3_bucket_default_encryption",
		"s3_bucket_public_read_prohibited",
		"s3_bucket_public_write_prohibited",
	},
	"ec2": {
		"ec2_instance_public_ip",
		"ec2_securitygroup_default_restrict_traffic",
		"ec2_securitygroup_allow_ingress_from_internet_to_any_port",
		"ec2_networkacl_allow_ingress_any_port",
		"ec2_ebs_encryption_by_default",
	},
	"cloudtrail": {
		"cloudtrail_multi_region_enabled",
		"cloudtrail_log_file_validation_enabled",
		"cloudtrail_cloudwatch_logging_enabled",
		"cloudtrail_encryption_enabled",
	},
	"vpc": {
		"vpc_flow_logs_enabled",
		"vpc_peering_route_tables_with_least_privilege",
		"vpc_endpoint_connections_trust_boundaries",
		"vpc_network_acl_unrestricted_access",
	},
}

// Compliance framework mappings
var ComplianceFrameworks = map[string]ComplianceFramework{
	"CIS": {
		Framework:   "CIS AWS Foundations Benchmark",
		Version:     "1.4.0",
		Description: "Center for Internet Security AWS Foundations Benchmark",
		Controls: map[string]string{
			"1.1": "iam_root_access_key_check",
			"1.2": "iam_mfa_enabled_for_root",
			"1.3": "iam_user_unused_credentials_disabled",
			"1.4": "iam_user_access_key_unused",
			"2.1": "cloudtrail_multi_region_enabled",
			"2.2": "cloudtrail_log_file_validation_enabled",
			"2.3": "s3_bucket_public_access_block",
		},
	},
	"SOC2": {
		Framework:   "SOC 2 Type II",
		Version:     "2017",
		Description: "Service Organization Control 2 Type II",
		Controls: map[string]string{
			"CC6.1": "iam_policy_no_administrative_privileges",
			"CC6.2": "iam_user_mfa_enabled_console_access",
			"CC6.3": "ec2_securitygroup_default_restrict_traffic",
			"CC7.1": "cloudtrail_multi_region_enabled",
			"CC7.2": "cloudtrail_encryption_enabled",
		},
	},
	"PCI-DSS": {
		Framework:   "PCI Data Security Standard",
		Version:     "4.0",
		Description: "Payment Card Industry Data Security Standard",
		Controls: map[string]string{
			"2.1":  "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
			"3.4":  "s3_bucket_default_encryption",
			"8.2":  "iam_password_policy_minimum_length_14",
			"10.1": "cloudtrail_multi_region_enabled",
		},
	},
}
