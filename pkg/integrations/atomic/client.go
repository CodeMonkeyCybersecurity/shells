package atomic

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// AtomicClient provides safe interface to Atomic Red Team tests
type AtomicClient struct {
	atomicsPath  string
	safetyFilter *SafetyFilter
	executor     *AtomicExecutor
	config       Config
	allowedTests map[string]AtomicTest
}

// NewAtomicClient creates a new atomic client with safety constraints
func NewAtomicClient(config Config) (*AtomicClient, error) {
	client := &AtomicClient{
		atomicsPath:  config.AtomicsPath,
		safetyFilter: NewSafetyFilter(),
		config:       config,
		allowedTests: make(map[string]AtomicTest),
	}

	// Initialize executor with safety constraints
	executorConfig := ExecutorConfig{
		Timeout:           config.Timeout,
		SandboxMode:       config.SandboxMode,
		DryRun:            config.DryRun,
		DockerImage:       config.DockerImage,
		MemoryLimit:       config.MemoryLimit,
		CPULimit:          config.CPULimit,
		NomadAddr:         config.NomadAddr,
		UseSecureExecutor: true, // Enable secure execution by default
	}

	var err error
	client.executor, err = NewAtomicExecutor(executorConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create executor: %w", err)
	}

	// Load and validate safe tests
	if err := client.loadSafeTests(); err != nil {
		return nil, fmt.Errorf("failed to load safe tests: %w", err)
	}

	return client, nil
}

// loadSafeTests loads only whitelisted and safe atomic tests
func (a *AtomicClient) loadSafeTests() error {
	for _, technique := range a.safetyFilter.allowedTechniques {
		testPath := filepath.Join(a.atomicsPath, technique, technique+".yaml")

		// Check if test file exists
		if _, err := os.Stat(testPath); os.IsNotExist(err) {
			// Try alternative path structure
			testPath = filepath.Join(a.atomicsPath, technique+".yaml")
			if _, err := os.Stat(testPath); os.IsNotExist(err) {
				continue // Skip if test doesn't exist
			}
		}

		test, err := a.loadTest(testPath)
		if err != nil {
			continue // Skip invalid tests
		}

		// Safety validation
		if a.safetyFilter.IsSafe(*test) {
			a.allowedTests[technique] = *test
		}
	}

	return nil
}

// loadTest loads and parses an atomic test file
func (a *AtomicClient) loadTest(testPath string) (*AtomicTest, error) {
	data, err := os.ReadFile(testPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read test file %s: %w", testPath, err)
	}

	var test AtomicTest
	if err := yaml.Unmarshal(data, &test); err != nil {
		return nil, fmt.Errorf("failed to parse test file %s: %w", testPath, err)
	}

	return &test, nil
}

// GetSafeTest retrieves a validated safe test by technique ID
func (a *AtomicClient) GetSafeTest(technique string) (*AtomicTest, error) {
	test, exists := a.allowedTests[technique]
	if !exists {
		return nil, fmt.Errorf("technique %s not found or not safe for bug bounty testing", technique)
	}

	return &test, nil
}

// ListSafeTechniques returns all available safe techniques
func (a *AtomicClient) ListSafeTechniques() []string {
	techniques := make([]string, 0, len(a.allowedTests))
	for technique := range a.allowedTests {
		techniques = append(techniques, technique)
	}
	return techniques
}

// ExecuteSafeTest executes a technique with full safety validation
func (a *AtomicClient) ExecuteSafeTest(technique string, testName string, target Target) (*TestResult, error) {
	// 1. Retrieve validated test
	test, err := a.GetSafeTest(technique)
	if err != nil {
		return nil, err
	}

	// 2. Additional safety validation with target context
	if err := a.safetyFilter.ValidateTest(*test, target); err != nil {
		return nil, fmt.Errorf("safety validation failed: %w", err)
	}

	// 3. Find specific atomic test
	var selectedTest *Test
	for _, atomicTest := range test.AtomicTests {
		if testName == "" || atomicTest.Name == testName {
			selectedTest = &atomicTest
			break
		}
	}

	if selectedTest == nil {
		return nil, fmt.Errorf("test %s not found in technique %s", testName, technique)
	}

	// 4. Execute with safety constraints
	result := &TestResult{
		Technique:   technique,
		TestName:    selectedTest.Name,
		SafetyCheck: true,
		Evidence:    []Evidence{},
	}

	startTime := time.Now()

	// Execute the test
	execResult, err := a.executor.ExecuteWithConstraints(*selectedTest, target)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result, nil
	}

	result.Success = execResult.Success
	result.Output = execResult.Output
	result.Evidence = execResult.Evidence

	return result, nil
}

// DemonstrateImpact runs safe demonstration of technique impact
func (a *AtomicClient) DemonstrateImpact(technique string, target Target) (*DemoResult, error) {
	test, err := a.GetSafeTest(technique)
	if err != nil {
		return nil, err
	}

	result := &DemoResult{
		Technique: technique,
		TestName:  test.DisplayName,
		Target:    target.URL,
		MITRELink: test.AttackLink,
		Evidence:  []Evidence{},
	}

	startTime := time.Now()

	// For demonstrations, we often want to show potential impact
	if a.config.DryRun {
		result.Evidence = append(result.Evidence, Evidence{
			Type:        "POTENTIAL_IMPACT",
			Description: fmt.Sprintf("Could execute: %s", test.DisplayName),
			Data:        test.AtomicTests[0].Description,
			Timestamp:   time.Now(),
		})
		result.Success = true
		result.Impact = a.assessImpact(technique)
		result.Severity = a.assessSeverity(technique)
	} else {
		// Execute first safe test for demonstration
		if len(test.AtomicTests) > 0 {
			execResult, err := a.executor.ExecuteWithConstraints(test.AtomicTests[0], target)
			if err != nil {
				result.Evidence = append(result.Evidence, Evidence{
					Type:        "EXECUTION_ERROR",
					Description: "Failed to execute demonstration",
					Data:        err.Error(),
					Timestamp:   time.Now(),
				})
			} else {
				result.Success = execResult.Success
				result.Evidence = execResult.Evidence
				result.Impact = a.assessImpact(technique)
				result.Severity = a.assessSeverity(technique)
			}
		}
	}

	result.Duration = time.Since(startTime)
	return result, nil
}

// GetTechniquesForVulnerability maps vulnerability types to relevant techniques
func (a *AtomicClient) GetTechniquesForVulnerability(vulnType string) []string {
	mapper := NewVulnToAttackMapper()
	return mapper.GetTechniques(vulnType)
}

// ValidateTestSafety performs comprehensive safety check
func (a *AtomicClient) ValidateTestSafety(technique string) (*SafetyReport, error) {
	test, err := a.GetSafeTest(technique)
	if err != nil {
		return nil, err
	}

	report := a.safetyFilter.GetSafetyReport(*test)
	return &report, nil
}

// assessImpact determines the potential impact of a technique
func (a *AtomicClient) assessImpact(technique string) string {
	impactMap := map[string]string{
		"T1552": "Credential exposure could lead to account takeover",
		"T1530": "Unauthorized access to cloud storage data",
		"T1190": "Initial foothold in target environment",
		"T1078": "Persistence through valid account access",
		"T1003": "Credential harvesting for lateral movement",
		"T1087": "Information gathering for targeted attacks",
		"T1083": "Sensitive file discovery and enumeration",
		"T1057": "Process information for privilege escalation",
		"T1069": "Permission mapping for escalation paths",
		"T1018": "Network reconnaissance for lateral movement",
	}

	if impact, exists := impactMap[technique]; exists {
		return impact
	}

	return "Potential security impact requires further analysis"
}

// assessSeverity determines the severity rating for a technique
func (a *AtomicClient) assessSeverity(technique string) string {
	severityMap := map[string]string{
		"T1552": "HIGH",
		"T1530": "HIGH",
		"T1190": "CRITICAL",
		"T1078": "HIGH",
		"T1003": "CRITICAL",
		"T1087": "MEDIUM",
		"T1083": "MEDIUM",
		"T1057": "LOW",
		"T1069": "MEDIUM",
		"T1018": "MEDIUM",
	}

	if severity, exists := severityMap[technique]; exists {
		return severity
	}

	return "MEDIUM"
}

// CreateCustomTest creates a bug bounty specific test
func (a *AtomicClient) CreateCustomTest(name string, technique string, description string, command string) (*AtomicTest, error) {
	// Validate command is safe
	if a.safetyFilter.containsBlockedCommand(command) {
		return nil, fmt.Errorf("command contains blocked operations")
	}

	customTest := &AtomicTest{
		AttackTechnique: technique,
		DisplayName:     name,
		AtomicTests: []Test{
			{
				Name:        name,
				Description: description,
				Executor: Executor{
					Name:    "sh",
					Command: command,
				},
				SupportedPlatforms: []string{"linux", "macos", "windows"},
			},
		},
		SupportedPlatforms: []string{"linux", "macos", "windows"},
	}

	// Validate the custom test
	if !a.safetyFilter.IsSafe(*customTest) {
		return nil, fmt.Errorf("custom test failed safety validation")
	}

	return customTest, nil
}

// GenerateTestReport creates comprehensive test execution report
func (a *AtomicClient) GenerateTestReport(results []TestResult) *TestReport {
	report := &TestReport{
		GeneratedAt:     time.Now(),
		TotalTests:      len(results),
		SuccessfulTests: 0,
		FailedTests:     0,
		Results:         results,
		Summary:         "",
	}

	// Calculate statistics
	for _, result := range results {
		if result.Success {
			report.SuccessfulTests++
		} else {
			report.FailedTests++
		}
	}

	// Generate executive summary
	report.Summary = fmt.Sprintf(
		"Executed %d atomic tests with %d successful and %d failed demonstrations. "+
			"All tests were validated for bug bounty safety compliance.",
		report.TotalTests, report.SuccessfulTests, report.FailedTests,
	)

	return report
}

// TestReport represents comprehensive test execution report
type TestReport struct {
	GeneratedAt     time.Time    `json:"generated_at"`
	TotalTests      int          `json:"total_tests"`
	SuccessfulTests int          `json:"successful_tests"`
	FailedTests     int          `json:"failed_tests"`
	Results         []TestResult `json:"results"`
	Summary         string       `json:"summary"`
}

// ExecutorConfig represents executor configuration
type ExecutorConfig struct {
	Timeout           time.Duration `json:"timeout"`
	SandboxMode       bool          `json:"sandbox_mode"`
	DryRun            bool          `json:"dry_run"`
	DockerImage       string        `json:"docker_image"`
	MemoryLimit       string        `json:"memory_limit"`
	CPULimit          string        `json:"cpu_limit"`
	NomadAddr         string        `json:"nomad_addr"`
	UseSecureExecutor bool          `json:"use_secure_executor"`
}
