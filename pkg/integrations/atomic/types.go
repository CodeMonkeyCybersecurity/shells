package atomic

import (
	"context"
	"time"
)

// AtomicTest represents an Atomic Red Team test definition
type AtomicTest struct {
	AttackTechnique    string   `yaml:"attack_technique"`
	DisplayName        string   `yaml:"display_name"`
	AtomicTests        []Test   `yaml:"atomic_tests"`
	AttackLink         string   `yaml:"attack_link"`
	SupportedPlatforms []string `yaml:"supported_platforms"`
}

// Test represents a single atomic test
type Test struct {
	Name               string              `yaml:"name"`
	Description        string              `yaml:"description"`
	SupportedPlatforms []string            `yaml:"supported_platforms"`
	InputArguments     map[string]InputArg `yaml:"input_arguments"`
	Executor           Executor            `yaml:"executor"`
	Dependencies       []Dependency        `yaml:"dependencies"`
	DependencyExecutor string              `yaml:"dependency_executor_name"`
}

// InputArg represents test input arguments
type InputArg struct {
	Description  string `yaml:"description"`
	Type         string `yaml:"type"`
	DefaultValue string `yaml:"default"`
}

// Executor represents test execution configuration
type Executor struct {
	Name              string `yaml:"name"`
	ElevationRequired bool   `yaml:"elevation_required"`
	Command           string `yaml:"command"`
	CleanupCommand    string `yaml:"cleanup_command"`
}

// Dependency represents test dependencies
type Dependency struct {
	Description      string `yaml:"description"`
	PrereqCommand    string `yaml:"prereq_command"`
	GetPrereqCommand string `yaml:"get_prereq_command"`
}

// TestResult represents execution results
type TestResult struct {
	Technique   string        `json:"technique"`
	TestName    string        `json:"test_name"`
	Success     bool          `json:"success"`
	Output      string        `json:"output"`
	Error       string        `json:"error,omitempty"`
	Duration    time.Duration `json:"duration"`
	Evidence    []Evidence    `json:"evidence"`
	SafetyCheck bool          `json:"safety_check"`
}

// Evidence represents proof of technique execution
type Evidence struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Data        string    `json:"data"`
	Command     string    `json:"command,omitempty"`
	Output      string    `json:"output,omitempty"`
	JobID       string    `json:"job_id,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// DemoResult represents demonstration execution results
type DemoResult struct {
	Technique string        `json:"technique"`
	TestName  string        `json:"test_name"`
	Target    string        `json:"target"`
	Success   bool          `json:"success"`
	Evidence  []Evidence    `json:"evidence"`
	MITRELink string        `json:"mitre_link"`
	Impact    string        `json:"impact"`
	Severity  string        `json:"severity"`
	Duration  time.Duration `json:"duration"`
}

// ImpactReport represents comprehensive impact analysis
type ImpactReport struct {
	Vulnerability    string          `json:"vulnerability"`
	ATTACKChain      []string        `json:"attack_chain"`
	Demonstrations   []Demonstration `json:"demonstrations"`
	ExecutiveSummary string          `json:"executive_summary"`
	Mitigations      []string        `json:"mitigations"`
	GeneratedAt      time.Time       `json:"generated_at"`
}

// Demonstration represents a single technique demonstration
type Demonstration struct {
	Technique   string        `json:"technique"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Result      string        `json:"result"`
	Finding     string        `json:"finding"`
	Severity    string        `json:"severity"`
	Evidence    []Evidence    `json:"evidence"`
	Duration    time.Duration `json:"duration"`
}

// ATTACKReport represents MITRE ATT&CK mapped report
type ATTACKReport struct {
	Metadata         ReportMetadata `json:"metadata"`
	ExecutiveSummary string         `json:"executive_summary"`
	AttackChain      []AttackStep   `json:"attack_chain"`
	Navigator        NavigatorLayer `json:"navigator"`
	Mitigations      []Mitigation   `json:"mitigations"`
	Findings         []Finding      `json:"findings"`
}

// ReportMetadata contains report generation information
type ReportMetadata struct {
	GeneratedAt        time.Time `json:"generated_at"`
	Scope              string    `json:"scope"`
	Target             string    `json:"target"`
	TotalTechniques    int       `json:"total_techniques"`
	HighRiskTechniques int       `json:"high_risk_techniques"`
}

// AttackStep represents a step in the attack chain
type AttackStep struct {
	Order       int    `json:"order"`
	Technique   string `json:"technique"`
	Tactic      string `json:"tactic"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Evidence    string `json:"evidence"`
}

// NavigatorLayer represents MITRE ATT&CK Navigator layer
type NavigatorLayer struct {
	Name        string           `json:"name"`
	Version     string           `json:"version"`
	Description string           `json:"description"`
	Domain      string           `json:"domain"`
	Techniques  []TechniqueLayer `json:"techniques"`
}

// TechniqueLayer represents a technique in the navigator layer
type TechniqueLayer struct {
	TechniqueID string `json:"techniqueID"`
	Color       string `json:"color"`
	Comment     string `json:"comment"`
	Enabled     bool   `json:"enabled"`
	Score       int    `json:"score"`
}

// Mitigation represents defensive recommendations
type Mitigation struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Techniques  []string `json:"techniques"`
	Priority    string   `json:"priority"`
	References  []string `json:"references"`
}

// Finding represents a security finding
type Finding struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Target      string `json:"target"`
}

// SafetyRule represents a safety constraint
type SafetyRule struct {
	Name        string                                    `json:"name"`
	Description string                                    `json:"description"`
	Check       func(cmd string) bool                     `json:"-"`
	Enforce     func(ctx context.Context) context.Context `json:"-"`
}

// Config represents atomic client configuration
type Config struct {
	AtomicsPath       string        `yaml:"atomics_path"`
	SafetyMode        bool          `yaml:"safety_mode"`
	DryRun            bool          `yaml:"dry_run"`
	Timeout           time.Duration `yaml:"timeout"`
	SandboxMode       bool          `yaml:"sandbox"`
	DockerImage       string        `yaml:"docker_image"`
	MemoryLimit       string        `yaml:"memory_limit"`
	CPULimit          string        `yaml:"cpu_limit"`
	NomadAddr         string        `yaml:"nomad_addr"`
	AllowedTechniques []string      `yaml:"allowed_techniques"`
}

// Target represents a test target
type Target struct {
	URL    string            `json:"url"`
	Type   string            `json:"type"`
	Params map[string]string `json:"params"`
}
