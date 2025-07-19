package atomic

import (
	"fmt"
	"strings"
	"time"
)

// BugBountyAtomic provides bug bounty specific atomic test implementations
type BugBountyAtomic struct {
	client   *AtomicClient
	executor *AtomicExecutor
	mapper   *VulnToAttackMapper
}

// NewBugBountyAtomic creates a new bug bounty atomic instance
func NewBugBountyAtomic(config Config) (*BugBountyAtomic, error) {
	client, err := NewAtomicClient(config)
	if err != nil {
		return nil, err
	}

	executorConfig := ExecutorConfig{
		Timeout:     config.Timeout,
		SandboxMode: config.SandboxMode,
		DryRun:      config.DryRun,
		DockerImage: config.DockerImage,
		MemoryLimit: config.MemoryLimit,
		CPULimit:    config.CPULimit,
	}

	executor, err := NewAtomicExecutor(executorConfig)
	if err != nil {
		return nil, err
	}

	return &BugBountyAtomic{
		client:   client,
		executor: executor,
		mapper:   NewVulnToAttackMapper(),
	}, nil
}

// Custom atomic tests specifically designed for bug bounty scenarios
var BugBountyCustomTests = []AtomicTest{
	{
		AttackTechnique: "T1552.001",
		DisplayName:     "Check for Exposed Credentials in Web Application",
		AtomicTests: []Test{
			{
				Name:               "Search for API keys in JavaScript files",
				Description:        "Demonstrate exposed credentials in client-side code",
				SupportedPlatforms: []string{"linux", "macos", "windows"},
				InputArguments: map[string]InputArg{
					"target_url": {
						Description:  "Target web application URL",
						Type:         "url",
						DefaultValue: "https://httpbin.org/get",
					},
				},
				Executor: Executor{
					Name:    "sh",
					Command: `curl -s "{{target_url}}" | grep -E "(api[_-]?key|apikey|api_token|access[_-]?token|secret[_-]?key)" -i || echo "No obvious credentials found in response"`,
				},
			},
			{
				Name:               "Check for exposed environment variables",
				Description:        "Look for exposed environment variables in error pages",
				SupportedPlatforms: []string{"linux", "macos", "windows"},
				InputArguments: map[string]InputArg{
					"target_url": {
						Description:  "Target web application URL",
						Type:         "url",
						DefaultValue: "https://httpbin.org/status/500",
					},
				},
				Executor: Executor{
					Name:    "sh",
					Command: `curl -s "{{target_url}}" | grep -E "(DATABASE_URL|AWS_ACCESS_KEY|SECRET_KEY|PRIVATE_KEY)" -i || echo "No environment variables exposed"`,
				},
			},
		},
		SupportedPlatforms: []string{"linux", "macos", "windows"},
		AttackLink:         "https://attack.mitre.org/techniques/T1552/001/",
	},
	{
		AttackTechnique: "T1530",
		DisplayName:     "Access Public Cloud Storage Buckets",
		AtomicTests: []Test{
			{
				Name:               "List public S3 bucket contents",
				Description:        "Demonstrate ability to access public S3 bucket contents",
				SupportedPlatforms: []string{"linux", "macos", "windows"},
				InputArguments: map[string]InputArg{
					"bucket_name": {
						Description:  "S3 bucket name to test",
						Type:         "string",
						DefaultValue: "example-public-bucket",
					},
				},
				Executor: Executor{
					Name:    "sh",
					Command: `aws s3 ls s3://{{bucket_name}} --no-sign-request --region us-east-1 2>/dev/null || echo "Bucket not accessible or does not exist"`,
				},
			},
			{
				Name:               "Check for public Azure blob storage",
				Description:        "Test access to public Azure blob storage containers",
				SupportedPlatforms: []string{"linux", "macos", "windows"},
				InputArguments: map[string]InputArg{
					"storage_account": {
						Description:  "Azure storage account name",
						Type:         "string",
						DefaultValue: "examplestorageaccount",
					},
					"container": {
						Description:  "Container name to test",
						Type:         "string",
						DefaultValue: "public",
					},
				},
				Executor: Executor{
					Name:    "sh",
					Command: `curl -s "https://{{storage_account}}.blob.core.windows.net/{{container}}?restype=container&comp=list" | grep -o "<Name>[^<]*</Name>" | head -5 || echo "Container not accessible"`,
				},
			},
		},
		SupportedPlatforms: []string{"linux", "macos", "windows"},
		AttackLink:         "https://attack.mitre.org/techniques/T1530/",
	},
	{
		AttackTechnique: "T1190",
		DisplayName:     "Web Application Vulnerability Discovery",
		AtomicTests: []Test{
			{
				Name:               "Basic web application fingerprinting",
				Description:        "Identify web application technologies and versions",
				SupportedPlatforms: []string{"linux", "macos", "windows"},
				InputArguments: map[string]InputArg{
					"target_url": {
						Description:  "Target web application URL",
						Type:         "url",
						DefaultValue: "https://httpbin.org",
					},
				},
				Executor: Executor{
					Name:    "sh",
					Command: `curl -I -s "{{target_url}}" | grep -E "(Server|X-Powered-By|X-Generator)" || echo "No obvious technology headers found"`,
				},
			},
			{
				Name:               "Check for common vulnerable endpoints",
				Description:        "Test for common vulnerable or informative endpoints",
				SupportedPlatforms: []string{"linux", "macos", "windows"},
				InputArguments: map[string]InputArg{
					"target_url": {
						Description:  "Target web application base URL",
						Type:         "url",
						DefaultValue: "https://httpbin.org",
					},
				},
				Executor: Executor{
					Name:    "sh",
					Command: `for path in /admin /api/v1 /.git/config /robots.txt /.env; do echo "Testing {{target_url}}$path"; curl -s -o /dev/null -w "%{http_code}" "{{target_url}}$path"; echo; done`,
				},
			},
		},
		SupportedPlatforms: []string{"linux", "macos", "windows"},
		AttackLink:         "https://attack.mitre.org/techniques/T1190/",
	},
	{
		AttackTechnique: "T1087.004",
		DisplayName:     "Cloud Account Discovery",
		AtomicTests: []Test{
			{
				Name:               "Enumerate cloud service accounts",
				Description:        "Discover cloud service accounts and permissions",
				SupportedPlatforms: []string{"linux", "macos", "windows"},
				InputArguments: map[string]InputArg{
					"cloud_provider": {
						Description:  "Cloud provider (aws, azure, gcp)",
						Type:         "string",
						DefaultValue: "aws",
					},
				},
				Executor: Executor{
					Name:    "sh",
					Command: `if [ "{{cloud_provider}}" = "aws" ]; then aws sts get-caller-identity 2>/dev/null || echo "No AWS credentials configured"; elif [ "{{cloud_provider}}" = "azure" ]; then az account show 2>/dev/null || echo "No Azure credentials configured"; else echo "Unsupported cloud provider"; fi`,
				},
			},
		},
		SupportedPlatforms: []string{"linux", "macos", "windows"},
		AttackLink:         "https://attack.mitre.org/techniques/T1087/004/",
	},
	{
		AttackTechnique: "T1083",
		DisplayName:     "Web Directory and File Discovery",
		AtomicTests: []Test{
			{
				Name:               "Common file discovery via web",
				Description:        "Discover common sensitive files through web requests",
				SupportedPlatforms: []string{"linux", "macos", "windows"},
				InputArguments: map[string]InputArg{
					"target_url": {
						Description:  "Target web application base URL",
						Type:         "url",
						DefaultValue: "https://httpbin.org",
					},
				},
				Executor: Executor{
					Name:    "sh",
					Command: `for file in robots.txt sitemap.xml .htaccess web.config; do status=$(curl -s -o /dev/null -w "%{http_code}" "{{target_url}}/$file"); echo "$file: $status"; done`,
				},
			},
			{
				Name:               "Backup file discovery",
				Description:        "Look for common backup file patterns",
				SupportedPlatforms: []string{"linux", "macos", "windows"},
				InputArguments: map[string]InputArg{
					"target_url": {
						Description:  "Target web application base URL",
						Type:         "url",
						DefaultValue: "https://httpbin.org",
					},
				},
				Executor: Executor{
					Name:    "sh",
					Command: `for ext in .bak .backup .old .tmp; do status=$(curl -s -o /dev/null -w "%{http_code}" "{{target_url}}/index${ext}"); echo "index${ext}: $status"; done`,
				},
			},
		},
		SupportedPlatforms: []string{"linux", "macos", "windows"},
		AttackLink:         "https://attack.mitre.org/techniques/T1083/",
	},
}

// GetCustomTestByTechnique retrieves a custom bug bounty test by technique
func (b *BugBountyAtomic) GetCustomTestByTechnique(technique string) *AtomicTest {
	for _, test := range BugBountyCustomTests {
		if test.AttackTechnique == technique {
			return &test
		}
	}
	return nil
}

// DemonstrateImpact demonstrates vulnerability impact using custom and standard tests
func (b *BugBountyAtomic) DemonstrateImpact(vulnType string, target Target) (*ImpactReport, error) {
	report := &ImpactReport{
		Vulnerability:  vulnType,
		ATTACKChain:    []string{},
		Demonstrations: []Demonstration{},
		GeneratedAt:    time.Now(),
	}

	// Get relevant techniques for the vulnerability
	techniques := b.mapper.GetTechniques(vulnType)

	for _, technique := range techniques {
		var test *AtomicTest
		var isCustom bool

		// Try custom tests first
		if customTest := b.GetCustomTestByTechnique(technique); customTest != nil {
			test = customTest
			isCustom = true
		} else {
			// Fall back to standard atomic tests
			standardTest, err := b.client.GetSafeTest(technique)
			if err != nil {
				continue // Skip if no test available
			}
			test = standardTest
			isCustom = false
		}

		// Execute demonstration
		demo, err := b.executeDemonstration(*test, target, isCustom)
		if err != nil {
			continue // Skip failed demonstrations
		}

		report.Demonstrations = append(report.Demonstrations, *demo)
		report.ATTACKChain = append(report.ATTACKChain, technique)
	}

	// Generate executive summary and mitigations
	report.ExecutiveSummary = b.generateExecutiveSummary(vulnType, report)
	report.Mitigations = b.generateMitigations(techniques)

	return report, nil
}

// executeDemonstration executes a demonstration test safely
func (b *BugBountyAtomic) executeDemonstration(test AtomicTest, target Target, isCustom bool) (*Demonstration, error) {
	demonstration := &Demonstration{
		Technique:   test.AttackTechnique,
		Name:        test.DisplayName,
		Description: b.mapper.GetDescription(test.AttackTechnique),
		Evidence:    []Evidence{},
	}

	startTime := time.Now()

	// Execute first atomic test as demonstration
	if len(test.AtomicTests) > 0 {
		atomicTest := test.AtomicTests[0]

		// Prepare target parameters
		targetWithParams := target
		if targetWithParams.Params == nil {
			targetWithParams.Params = make(map[string]string)
		}
		targetWithParams.Params["target_url"] = target.URL

		result, err := b.executor.ExecuteWithConstraints(atomicTest, targetWithParams)
		demonstration.Duration = time.Since(startTime)

		if err != nil {
			demonstration.Result = fmt.Sprintf("Demonstration failed: %v", err)
			demonstration.Severity = "LOW"
			demonstration.Evidence = append(demonstration.Evidence, Evidence{
				Type:        "EXECUTION_ERROR",
				Description: "Test execution failed",
				Data:        err.Error(),
				Timestamp:   time.Now(),
			})
		} else {
			demonstration.Result = b.assessDemonstrationResult(result.Output, test.AttackTechnique)
			demonstration.Severity = b.assessSeverity(test.AttackTechnique, result.Success)
			demonstration.Evidence = result.Evidence

			// Add custom evidence for bug bounty context
			if isCustom {
				demonstration.Evidence = append(demonstration.Evidence, Evidence{
					Type:        "BUG_BOUNTY_CUSTOM",
					Description: "Custom bug bounty test execution",
					Data:        "Executed specialized test for bug bounty demonstration",
					Timestamp:   time.Now(),
				})
			}
		}
	} else {
		demonstration.Result = "No executable tests available for this technique"
		demonstration.Severity = "INFO"
		demonstration.Duration = time.Since(startTime)
	}

	return demonstration, nil
}

// assessDemonstrationResult analyzes execution output to determine result
func (b *BugBountyAtomic) assessDemonstrationResult(output, technique string) string {
	output = strings.ToLower(output)

	// Technique-specific result assessment
	switch technique {
	case "T1552.001":
		if strings.Contains(output, "api") || strings.Contains(output, "key") || strings.Contains(output, "token") {
			return "Potential credentials detected in application responses"
		}
		return "No obvious credentials found in accessible content"

	case "T1530":
		if strings.Contains(output, "<name>") || strings.Contains(output, "lastmodified") {
			return "Cloud storage bucket contents successfully enumerated"
		}
		return "Cloud storage not accessible or properly secured"

	case "T1190":
		if strings.Contains(output, "server:") || strings.Contains(output, "x-powered-by") {
			return "Web application technology stack identified"
		}
		return "Limited technology fingerprinting information available"

	case "T1087.004":
		if strings.Contains(output, "account") || strings.Contains(output, "user") {
			return "Cloud account information accessible"
		}
		return "No cloud account information accessible"

	case "T1083":
		if strings.Contains(output, "200") {
			return "Sensitive files or directories discovered"
		}
		return "No sensitive files found in common locations"

	default:
		if strings.Contains(output, "error") || strings.Contains(output, "failed") {
			return "Technique execution encountered errors"
		}
		return "Technique executed successfully with standard output"
	}
}

// assessSeverity determines severity based on technique and execution success
func (b *BugBountyAtomic) assessSeverity(technique string, success bool) string {
	if !success {
		return "LOW"
	}

	// High-impact techniques for bug bounties
	highImpactTechniques := []string{
		"T1552.001", // Credentials in Files
		"T1530",     // Data from Cloud Storage
		"T1190",     // Exploit Public-Facing Application
		"T1078",     // Valid Accounts
	}

	for _, highImpact := range highImpactTechniques {
		if technique == highImpact {
			return "HIGH"
		}
	}

	return "MEDIUM"
}

// generateExecutiveSummary creates executive summary for impact report
func (b *BugBountyAtomic) generateExecutiveSummary(vulnType string, report *ImpactReport) string {
	techniqueCount := len(report.Demonstrations)
	successfulDemos := 0

	for _, demo := range report.Demonstrations {
		if demo.Severity != "LOW" {
			successfulDemos++
		}
	}

	return fmt.Sprintf(
		"Impact analysis for %s vulnerability revealed %d applicable ATT&CK techniques, "+
			"with %d successful demonstrations. This vulnerability provides multiple attack "+
			"vectors that could be exploited by adversaries to achieve initial access, "+
			"credential harvesting, and data exfiltration objectives.",
		strings.ReplaceAll(vulnType, "_", " "),
		techniqueCount,
		successfulDemos,
	)
}

// generateMitigations provides defensive recommendations
func (b *BugBountyAtomic) generateMitigations(techniques []string) []string {
	mitigationMap := map[string]string{
		"T1552.001": "Implement secure credential storage and scanning",
		"T1530":     "Apply proper cloud storage access controls",
		"T1190":     "Implement input validation and security testing",
		"T1087.004": "Use least privilege access and monitoring",
		"T1083":     "Deploy file integrity monitoring and access controls",
		"T1078":     "Implement multi-factor authentication",
	}

	var mitigations []string
	seen := make(map[string]bool)

	for _, technique := range techniques {
		if mitigation, exists := mitigationMap[technique]; exists && !seen[mitigation] {
			mitigations = append(mitigations, mitigation)
			seen[mitigation] = true
		}
	}

	// Add general bug bounty specific mitigations
	generalMitigations := []string{
		"Conduct regular security assessments and penetration testing",
		"Implement comprehensive logging and monitoring",
		"Deploy web application firewalls and security controls",
		"Maintain an incident response plan for security findings",
	}

	for _, mitigation := range generalMitigations {
		if !seen[mitigation] {
			mitigations = append(mitigations, mitigation)
		}
	}

	return mitigations
}

// CreateCustomBugBountyTest creates a custom test for specific bug bounty scenarios
func (b *BugBountyAtomic) CreateCustomBugBountyTest(name, technique, description, command string, vulnType string) (*AtomicTest, error) {
	// Validate the technique is safe
	safe := false
	for _, safeTech := range BugBountySafeTechniques {
		if technique == safeTech {
			safe = true
			break
		}
	}

	if !safe {
		return nil, fmt.Errorf("technique %s not approved for bug bounty testing", technique)
	}

	// Create custom test
	customTest := &AtomicTest{
		AttackTechnique: technique,
		DisplayName:     name,
		AtomicTests: []Test{
			{
				Name:        name,
				Description: description,
				InputArguments: map[string]InputArg{
					"target_url": {
						Description:  "Target URL for testing",
						Type:         "url",
						DefaultValue: "https://httpbin.org/get",
					},
				},
				Executor: Executor{
					Name:    "sh",
					Command: command,
				},
				SupportedPlatforms: []string{"linux", "macos", "windows"},
			},
		},
		SupportedPlatforms: []string{"linux", "macos", "windows"},
		AttackLink:         fmt.Sprintf("https://attack.mitre.org/techniques/%s/", technique),
	}

	// Validate the custom test
	safetyFilter := NewSafetyFilter()
	if !safetyFilter.IsSafe(*customTest) {
		return nil, fmt.Errorf("custom test failed safety validation")
	}

	return customTest, nil
}

// GetBugBountyRecommendations provides specific recommendations for bug bounty testing
func (b *BugBountyAtomic) GetBugBountyRecommendations() *BugBountyRecommendations {
	return &BugBountyRecommendations{
		SafetyGuidelines: []string{
			"Always use dry-run mode for initial testing",
			"Execute tests in Docker sandbox when possible",
			"Limit test execution to authorized targets only",
			"Monitor resource usage during test execution",
			"Document all test activities for compliance",
		},
		RecommendedWorkflow: []string{
			"1. Validate findings against bug bounty scope",
			"2. Map vulnerabilities to ATT&CK techniques",
			"3. Select appropriate safe demonstration tests",
			"4. Execute tests in sandbox environment",
			"5. Generate comprehensive impact report",
			"6. Include defensive recommendations",
		},
		ComplianceNotes: []string{
			"All tests filtered for bug bounty safety compliance",
			"No destructive or system-modifying operations",
			"Resource-limited execution environment",
			"Comprehensive logging and audit trail",
			"Alignment with responsible disclosure practices",
		},
	}
}

// BugBountyRecommendations provides guidance for bug bounty testing
type BugBountyRecommendations struct {
	SafetyGuidelines    []string `json:"safety_guidelines"`
	RecommendedWorkflow []string `json:"recommended_workflow"`
	ComplianceNotes     []string `json:"compliance_notes"`
}
