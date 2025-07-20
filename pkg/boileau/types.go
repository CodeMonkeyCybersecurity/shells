package boileau

import (
	"time"
)

// Config holds configuration for boileau tools
type Config struct {
	UseDocker      bool
	UseNomad       bool
	OutputDir      string
	Timeout        time.Duration
	MaxConcurrency int
	DockerImages   map[string]string
}

// ToolResult represents the result of running a single tool
type ToolResult struct {
	Tool      string                 `json:"tool"`
	Target    string                 `json:"target"`
	Success   bool                   `json:"success"`
	StartTime time.Time              `json:"start_time"`
	EndTime   time.Time              `json:"end_time"`
	Duration  time.Duration          `json:"duration"`
	Output    string                 `json:"output,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Findings  []ToolFinding          `json:"findings,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// ToolFinding represents a finding from a boileau tool
type ToolFinding struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description,omitempty"`
	Evidence    string                 `json:"evidence,omitempty"`
	Solution    string                 `json:"solution,omitempty"`
	References  []string               `json:"references,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Logger interface for boileau tools
type Logger interface {
	Info(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
}

// ToolTypes defines categories for tools
const (
	ToolTypeVisualRecon        = "visual_recon"
	ToolTypePortScanner        = "port_scanner"
	ToolTypeXSSScanner         = "xss_scanner"
	ToolTypeSQLInjection       = "sql_injection"
	ToolTypeTemplateInjection  = "template_injection"
	ToolTypeSSRFScanner        = "ssrf_scanner"
	ToolTypeSSRFExploitation   = "ssrf_exploitation"
	ToolTypeNoSQLInjection     = "nosql_injection"
	ToolTypeCommandInjection   = "command_injection"
	ToolTypeCORSMisconfig      = "cors_misconfiguration"
	ToolTypeParameterDiscovery = "parameter_discovery"
)

// Severity levels
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)
