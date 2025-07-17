package atomic

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/nomad"
)

// AtomicExecutor handles safe execution of atomic tests
type AtomicExecutor struct {
	config      ExecutorConfig
	safetyCheck bool
	nomadClient *nomad.Client
}

// NewAtomicExecutor creates a new atomic executor with safety constraints
func NewAtomicExecutor(config ExecutorConfig) (*AtomicExecutor, error) {
	// Validate configuration
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}
	
	if config.DockerImage == "" {
		config.DockerImage = "atomicredteam/atomic-red-team-execution:latest"
	}
	
	if config.MemoryLimit == "" {
		config.MemoryLimit = "512m"
	}
	
	if config.CPULimit == "" {
		config.CPULimit = "0.5"
	}

	// Initialize Nomad client for sandboxed execution
	var nomadClient *nomad.Client
	if config.SandboxMode {
		nomadClient = nomad.NewClient(config.NomadAddr)
		if !nomadClient.IsAvailable() {
			return nil, fmt.Errorf("Nomad cluster is not available at %s", config.NomadAddr)
		}
	}
	
	return &AtomicExecutor{
		config:      config,
		safetyCheck: true,
		nomadClient: nomadClient,
	}, nil
}

// ExecuteWithConstraints executes a test with comprehensive safety constraints
func (e *AtomicExecutor) ExecuteWithConstraints(test Test, target Target) (*ExecutionResult, error) {
	result := &ExecutionResult{
		Test:      test,
		Target:    target,
		StartTime: time.Now(),
		Evidence:  []Evidence{},
		Success:   false,
	}
	
	// Pre-execution safety check
	if err := e.validateExecution(test, target); err != nil {
		result.Error = err.Error()
		result.EndTime = time.Now()
		return result, err
	}
	
	// Prepare command with parameter substitution
	command, err := e.prepareCommand(test, target)
	if err != nil {
		result.Error = err.Error()
		result.EndTime = time.Now()
		return result, err
	}
	
	// Create execution context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
	defer cancel()
	
	// Execute based on mode
	if e.config.DryRun {
		return e.executeDryRun(ctx, test, command, result)
	} else if e.config.SandboxMode {
		return e.executeInNomadSandbox(ctx, test, command, target, result)
	} else {
		return e.executeLocal(ctx, test, command, result)
	}
}

// validateExecution performs pre-execution safety validation
func (e *AtomicExecutor) validateExecution(test Test, target Target) error {
	// Check if platform is supported
	if !e.isPlatformSupported(test.SupportedPlatforms) {
		return fmt.Errorf("test not supported on platform %s", runtime.GOOS)
	}
	
	// Validate command safety
	if e.containsUnsafeOperations(test.Executor.Command) {
		return fmt.Errorf("command contains unsafe operations")
	}
	
	// Check elevation requirements (should always be false for bug bounties)
	if test.Executor.ElevationRequired {
		return fmt.Errorf("test requires elevation - not allowed in bug bounty context")
	}
	
	// Validate dependencies
	for _, dep := range test.Dependencies {
		if err := e.validateDependency(dep); err != nil {
			return fmt.Errorf("dependency validation failed: %v", err)
		}
	}
	
	return nil
}

// prepareCommand substitutes parameters and prepares command for execution
func (e *AtomicExecutor) prepareCommand(test Test, target Target) (string, error) {
	command := test.Executor.Command
	
	// Substitute input arguments with safe defaults or target parameters
	for argName, argDef := range test.InputArguments {
		placeholder := fmt.Sprintf("{{%s}}", argName)
		
		var value string
		if targetValue, exists := target.Params[argName]; exists {
			value = targetValue
		} else {
			value = e.getSafeDefault(argName, argDef)
		}
		
		// Sanitize value to prevent injection
		value = e.sanitizeValue(value)
		command = strings.ReplaceAll(command, placeholder, value)
	}
	
	// Replace common target placeholders
	if target.URL != "" {
		command = strings.ReplaceAll(command, "{{target_url}}", target.URL)
		command = strings.ReplaceAll(command, "{{target}}", target.URL)
	}
	
	// Final safety check on prepared command
	if e.containsUnsafeOperations(command) {
		return "", fmt.Errorf("prepared command contains unsafe operations: %s", command)
	}
	
	return command, nil
}

// executeDryRun simulates execution without actually running commands
func (e *AtomicExecutor) executeDryRun(ctx context.Context, test Test, command string, result *ExecutionResult) (*ExecutionResult, error) {
	result.Success = true
	result.Output = fmt.Sprintf("[DRY RUN] Would execute: %s", command)
	result.EndTime = time.Now()
	
	// Add demonstration evidence
	result.Evidence = append(result.Evidence, Evidence{
		Type:        "DRY_RUN_SIMULATION",
		Description: "Simulated execution of atomic test",
		Data:        command,
		Command:     command,
		Timestamp:   time.Now(),
	})
	
	// Simulate potential impact
	result.Evidence = append(result.Evidence, Evidence{
		Type:        "POTENTIAL_IMPACT",
		Description: fmt.Sprintf("This test could demonstrate: %s", test.Description),
		Data:        test.Name,
		Timestamp:   time.Now(),
	})
	
	return result, nil
}

// executeInNomadSandbox executes command in Nomad sandbox for safety
func (e *AtomicExecutor) executeInNomadSandbox(ctx context.Context, test Test, command string, target Target, result *ExecutionResult) (*ExecutionResult, error) {
	// Check if Nomad is available
	if e.nomadClient == nil || !e.nomadClient.IsAvailable() {
		return e.executeLocal(ctx, test, command, result)
	}
	
	// Generate job ID
	jobID := fmt.Sprintf("atomic-test-%d", time.Now().UnixNano())
	
	// Create Nomad job specification
	jobSpec := e.createAtomicJobSpec(jobID, command, test, target)
	
	// Register the job
	if err := e.nomadClient.RegisterJob(ctx, jobID, jobSpec); err != nil {
		result.Error = fmt.Sprintf("Failed to register Nomad job: %v", err)
		result.Success = false
		result.EndTime = time.Now()
		return result, err
	}
	
	// Submit the job
	dispatchedJobID, err := e.nomadClient.SubmitScan(ctx, "atomic-test", target.URL, jobID, map[string]string{
		"command": command,
		"test_name": test.Name,
		"technique": test.Name, // Assuming test name contains technique info
	})
	if err != nil {
		result.Error = fmt.Sprintf("Failed to submit Nomad job: %v", err)
		result.Success = false
		result.EndTime = time.Now()
		return result, err
	}
	
	// Wait for completion
	status, err := e.nomadClient.WaitForCompletion(ctx, dispatchedJobID, e.config.Timeout)
	if err != nil {
		result.Error = fmt.Sprintf("Job execution failed: %v", err)
		result.Success = false
		result.EndTime = time.Now()
		return result, err
	}
	
	// Get job logs
	logs, err := e.nomadClient.GetJobLogs(ctx, dispatchedJobID)
	if err != nil {
		logs = fmt.Sprintf("Failed to retrieve logs: %v", err)
	}
	
	result.Output = logs
	result.EndTime = time.Now()
	result.Success = (status.Status == "complete")
	
	if !result.Success {
		result.Error = fmt.Sprintf("Job completed with status: %s", status.Status)
	}
	
	// Add execution evidence
	result.Evidence = append(result.Evidence, Evidence{
		Type:        "NOMAD_SANDBOXED_EXECUTION",
		Description: "Executed in Nomad sandbox with resource constraints",
		Command:     command,
		Output:      result.Output,
		Timestamp:   time.Now(),
		JobID:       dispatchedJobID,
	})
	
	return result, nil
}

// executeLocal executes command locally with constraints
func (e *AtomicExecutor) executeLocal(ctx context.Context, test Test, command string, result *ExecutionResult) (*ExecutionResult, error) {
	// Determine shell based on platform
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	default:
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}
	
	// Set environment restrictions
	cmd.Env = e.getRestrictedEnvironment()
	
	// Execute with timeout
	output, err := cmd.CombinedOutput()
	result.Output = string(output)
	result.EndTime = time.Now()
	
	if err != nil {
		result.Error = err.Error()
		result.Success = false
	} else {
		result.Success = true
	}
	
	// Add execution evidence
	result.Evidence = append(result.Evidence, Evidence{
		Type:        "LOCAL_EXECUTION",
		Description: "Executed locally with safety constraints",
		Command:     command,
		Output:      result.Output,
		Timestamp:   time.Now(),
	})
	
	return result, nil
}

// Helper methods

func (e *AtomicExecutor) isPlatformSupported(platforms []string) bool {
	if len(platforms) == 0 {
		return true // No platform restriction
	}
	
	currentPlatform := runtime.GOOS
	for _, platform := range platforms {
		switch strings.ToLower(platform) {
		case "linux", "macos", "windows":
			if strings.ToLower(platform) == currentPlatform || 
			   (platform == "macos" && currentPlatform == "darwin") {
				return true
			}
		}
	}
	
	return false
}

func (e *AtomicExecutor) containsUnsafeOperations(command string) bool {
	unsafePatterns := []string{
		"rm -rf", "del /f", "format", "fdisk",
		"shutdown", "reboot", "kill -9", "chmod 777",
		"useradd", "userdel", "passwd", "chpasswd",
		"iptables", "route add", "netsh", "sc create",
		"reg add", "reg delete", "schtasks /create",
		"sudo", "su -", "runas", "elevation",
	}
	
	cmdLower := strings.ToLower(command)
	for _, pattern := range unsafePatterns {
		if strings.Contains(cmdLower, pattern) {
			return true
		}
	}
	
	return false
}

func (e *AtomicExecutor) validateDependency(dep Dependency) error {
	// Check if prerequisite command is safe
	if dep.PrereqCommand != "" && e.containsUnsafeOperations(dep.PrereqCommand) {
		return fmt.Errorf("prerequisite command contains unsafe operations")
	}
	
	// Check if dependency installation command is safe
	if dep.GetPrereqCommand != "" && e.containsUnsafeOperations(dep.GetPrereqCommand) {
		return fmt.Errorf("dependency installation command contains unsafe operations")
	}
	
	return nil
}

func (e *AtomicExecutor) getSafeDefault(argName string, argDef InputArg) string {
	// Provide safe defaults for common argument types
	safeDefaults := map[string]string{
		"file_path":    "/tmp/test.txt",
		"directory":    "/tmp",
		"process_name": "notepad.exe",
		"service_name": "test-service",
		"registry_key": "HKCU\\Software\\Test",
		"url":          "https://httpbin.org/get",
		"domain":       "example.com",
		"username":     "testuser",
		"output_file":  "/tmp/output.txt",
	}
	
	// Check for safe default by argument name
	if defaultValue, exists := safeDefaults[strings.ToLower(argName)]; exists {
		return defaultValue
	}
	
	// Use provided default if it exists and is safe
	if argDef.DefaultValue != "" && !e.containsUnsafeOperations(argDef.DefaultValue) {
		return argDef.DefaultValue
	}
	
	// Return safe fallback
	return "safe-test-value"
}

func (e *AtomicExecutor) sanitizeValue(value string) string {
	// Remove potentially dangerous characters
	value = strings.ReplaceAll(value, ";", "")
	value = strings.ReplaceAll(value, "&", "")
	value = strings.ReplaceAll(value, "|", "")
	value = strings.ReplaceAll(value, "`", "")
	value = strings.ReplaceAll(value, "$", "")
	value = strings.ReplaceAll(value, "$(", "")
	value = strings.ReplaceAll(value, ")", "")
	
	// Limit length to prevent buffer overflow attempts
	if len(value) > 256 {
		value = value[:256]
	}
	
	return value
}

func (e *AtomicExecutor) isDockerAvailable() bool {
	cmd := exec.Command("docker", "--version")
	return cmd.Run() == nil
}

// createAtomicJobSpec creates a Nomad job specification for atomic test execution
func (e *AtomicExecutor) createAtomicJobSpec(jobID, command string, test Test, target Target) string {
	// Create a secure Nomad job specification for atomic test execution
	jobSpec := fmt.Sprintf(`
job "%s" {
  type = "batch"
  datacenters = ["dc1"]
  
  group "atomic-test" {
    count = 1
    
    restart {
      attempts = 0
      mode = "fail"
    }
    
    task "execute" {
      driver = "exec"
      
      config {
        command = "/bin/sh"
        args = ["-c", "%s"]
      }
      
      env {
        ATOMIC_TEST_MODE = "safe"
        ATOMIC_TEST_TARGET = "%s"
        ATOMIC_TEST_NAME = "%s"
      }
      
      resources {
        cpu = %s
        memory = %s
      }
      
      # Security constraints
      constraint {
        attribute = "${node.class}"
        operator = "="
        value = "atomic-test"
      }
      
      # Timeout
      kill_timeout = "%s"
      
      # Logging
      logs {
        max_files = 1
        max_file_size = 1
      }
    }
  }
}`, 
		jobID, 
		e.escapeCommand(command), 
		target.URL, 
		test.Name,
		e.parseCPULimit(e.config.CPULimit),
		e.parseMemoryLimit(e.config.MemoryLimit),
		e.config.Timeout.String(),
	)
	
	return jobSpec
}

// escapeCommand escapes shell command for safe execution in Nomad
func (e *AtomicExecutor) escapeCommand(command string) string {
	// Escape quotes and special characters
	escaped := strings.ReplaceAll(command, `"`, `\"`)
	escaped = strings.ReplaceAll(escaped, `$`, `\$`)
	escaped = strings.ReplaceAll(escaped, "`", "\\`")
	return escaped
}

// parseCPULimit converts CPU limit to Nomad format (MHz)
func (e *AtomicExecutor) parseCPULimit(limit string) string {
	// Convert from Docker format (e.g., "0.5") to Nomad MHz
	// Default to 500 MHz for 0.5 CPU
	if limit == "0.5" {
		return "500"
	}
	if limit == "1.0" || limit == "1" {
		return "1000"
	}
	// Default fallback
	return "500"
}

// parseMemoryLimit converts memory limit to Nomad format (MB)
func (e *AtomicExecutor) parseMemoryLimit(limit string) string {
	// Convert from Docker format (e.g., "512m") to Nomad MB
	if strings.HasSuffix(limit, "m") || strings.HasSuffix(limit, "M") {
		return strings.TrimSuffix(strings.TrimSuffix(limit, "m"), "M")
	}
	if strings.HasSuffix(limit, "g") || strings.HasSuffix(limit, "G") {
		// Convert GB to MB
		gbStr := strings.TrimSuffix(strings.TrimSuffix(limit, "g"), "G")
		if gbStr == "1" {
			return "1024"
		}
		if gbStr == "2" {
			return "2048"
		}
	}
	// Default fallback
	return "512"
}

func (e *AtomicExecutor) getRestrictedEnvironment() []string {
	// Provide minimal, safe environment variables
	safeEnv := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/tmp",
		"USER=atomic-test",
		"SHELL=/bin/sh",
	}
	
	// Add current OS environment for compatibility if safe
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "LANG=") || strings.HasPrefix(env, "LC_") {
			safeEnv = append(safeEnv, env)
		}
	}
	
	return safeEnv
}

// ExecutionResult represents the result of test execution
type ExecutionResult struct {
	Test      Test          `json:"test"`
	Target    Target        `json:"target"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	Success   bool          `json:"success"`
	Output    string        `json:"output"`
	Error     string        `json:"error,omitempty"`
	Evidence  []Evidence    `json:"evidence"`
}

// BugBountyExecutor provides bug bounty specific atomic test execution
type BugBountyExecutor struct {
	client   *AtomicClient
	mapper   *VulnToAttackMapper
	reporter *AtomicReporter
}

// NewBugBountyExecutor creates a new bug bounty focused executor
func NewBugBountyExecutor(config Config) (*BugBountyExecutor, error) {
	client, err := NewAtomicClient(config)
	if err != nil {
		return nil, err
	}
	
	return &BugBountyExecutor{
		client:   client,
		mapper:   NewVulnToAttackMapper(),
		reporter: NewAtomicReporter(),
	}, nil
}

// DemonstrateVulnerabilityImpact demonstrates the impact of a vulnerability using ATT&CK techniques
func (b *BugBountyExecutor) DemonstrateVulnerabilityImpact(finding Finding, target Target) (*ImpactReport, error) {
	report := &ImpactReport{
		Vulnerability:   finding.Type,
		ATTACKChain:     []string{},
		Demonstrations:  []Demonstration{},
		GeneratedAt:     time.Now(),
	}
	
	// Get relevant ATT&CK techniques
	techniques := b.mapper.GetTechniques(finding.Type)
	
	for _, technique := range techniques {
		// Get atomic test for technique
		test, err := b.client.GetSafeTest(technique)
		if err != nil {
			continue // Skip if test not available
		}
		
		// Demonstrate technique
		demo, err := b.client.DemonstrateImpact(technique, target)
		if err != nil {
			continue // Skip on error
		}
		
		demonstration := Demonstration{
			Technique:   technique,
			Name:        test.DisplayName,
			Description: b.mapper.GetDescription(technique),
			Result:      demo.Impact,
			Finding:     finding.Title,
			Severity:    demo.Severity,
			Evidence:    demo.Evidence,
			Duration:    demo.Duration,
		}
		
		report.Demonstrations = append(report.Demonstrations, demonstration)
		report.ATTACKChain = append(report.ATTACKChain, technique)
	}
	
	// Generate executive summary
	report.ExecutiveSummary = b.generateExecutiveSummary(finding, report)
	
	// Get defensive mitigations
	report.Mitigations = b.getMitigations(techniques)
	
	return report, nil
}

// generateExecutiveSummary creates executive summary for impact report
func (b *BugBountyExecutor) generateExecutiveSummary(finding Finding, report *ImpactReport) string {
	techniqueCount := len(report.Demonstrations)
	
	if techniqueCount == 0 {
		return fmt.Sprintf("The %s vulnerability was identified but no atomic demonstrations were available.", finding.Type)
	}
	
	return fmt.Sprintf(
		"The %s vulnerability enables %d distinct ATT&CK techniques, demonstrating significant attack potential. "+
		"Successful exploitation could lead to %s and enable adversaries to %s.",
		strings.ReplaceAll(finding.Type, "_", " "),
		techniqueCount,
		finding.Impact,
		"establish persistence and move laterally within the environment",
	)
}

// getMitigations provides defensive recommendations based on techniques
func (b *BugBountyExecutor) getMitigations(techniques []string) []string {
	mitigationMap := map[string]string{
		"T1552": "Implement credential scanning and secure storage practices",
		"T1530": "Apply proper cloud storage access controls and monitoring",
		"T1190": "Implement input validation and patch management",
		"T1078": "Deploy multi-factor authentication and account monitoring",
		"T1003": "Enable credential guard and privilege access management",
		"T1087": "Implement network segmentation and access logging",
		"T1083": "Deploy file integrity monitoring and access controls",
	}
	
	mitigations := []string{}
	seen := make(map[string]bool)
	
	for _, technique := range techniques {
		if mitigation, exists := mitigationMap[technique]; exists && !seen[mitigation] {
			mitigations = append(mitigations, mitigation)
			seen[mitigation] = true
		}
	}
	
	// Add general recommendations
	generalMitigations := []string{
		"Implement comprehensive logging and monitoring",
		"Deploy endpoint detection and response (EDR) solutions",
		"Conduct regular security assessments and penetration testing",
		"Maintain an incident response plan and practice procedures",
	}
	
	for _, mitigation := range generalMitigations {
		if !seen[mitigation] {
			mitigations = append(mitigations, mitigation)
		}
	}
	
	return mitigations
}