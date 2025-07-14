package atomic

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"
)

// AtomicReporter generates comprehensive ATT&CK reports
type AtomicReporter struct {
	navigatorVersion string
	domain          string
}

// NewAtomicReporter creates a new atomic reporter
func NewAtomicReporter() *AtomicReporter {
	return &AtomicReporter{
		navigatorVersion: "4.9.1",
		domain:          "enterprise-attack",
	}
}

// GenerateATTACKReport creates comprehensive ATT&CK mapped report
func (r *AtomicReporter) GenerateATTACKReport(findings []Finding, demonstrations []Demonstration) *ATTACKReport {
	report := &ATTACKReport{
		Metadata: ReportMetadata{
			GeneratedAt:        time.Now(),
			Scope:              "Bug Bounty Findings with ATT&CK Mapping",
			TotalTechniques:    len(demonstrations),
			HighRiskTechniques: r.countHighRiskTechniques(demonstrations),
		},
		ExecutiveSummary: r.generateExecutiveSummary(findings, demonstrations),
		AttackChain:      r.buildAttackChain(demonstrations),
		Navigator:        r.generateNavigatorLayer(demonstrations),
		Mitigations:      r.generateMitigations(demonstrations),
		Findings:         findings,
	}
	
	// Set target if available
	if len(findings) > 0 {
		report.Metadata.Target = findings[0].Target
	}
	
	return report
}

// generateExecutiveSummary creates executive summary for the report
func (r *AtomicReporter) generateExecutiveSummary(findings []Finding, demonstrations []Demonstration) string {
	if len(findings) == 0 {
		return "No security findings were analyzed in this assessment."
	}
	
	findingCount := len(findings)
	techniqueCount := len(demonstrations)
	
	// Count findings by severity
	severityCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}
	
	for _, finding := range findings {
		severityCounts[finding.Severity]++
	}
	
	// Count techniques by tactic
	tacticCounts := make(map[string]int)
	mapper := NewVulnToAttackMapper()
	
	for _, demo := range demonstrations {
		tactic := mapper.GetTactic(demo.Technique)
		tacticCounts[tactic]++
	}
	
	summary := fmt.Sprintf(
		"This assessment identified %d security findings that map to %d distinct MITRE ATT&CK techniques. "+
		"The findings include %d critical, %d high, %d medium, and %d low severity vulnerabilities. ",
		findingCount, techniqueCount,
		severityCounts["CRITICAL"], severityCounts["HIGH"],
		severityCounts["MEDIUM"], severityCounts["LOW"],
	)
	
	if len(tacticCounts) > 0 {
		topTactic := r.getTopTactic(tacticCounts)
		summary += fmt.Sprintf(
			"The most prevalent attack tactic is %s, indicating potential for %s activities. ",
			topTactic, strings.ToLower(topTactic),
		)
	}
	
	summary += "Immediate remediation is recommended for critical and high severity findings to reduce attack surface and prevent potential compromise."
	
	return summary
}

// buildAttackChain creates attack chain visualization
func (r *AtomicReporter) buildAttackChain(demonstrations []Demonstration) []AttackStep {
	chain := []AttackStep{}
	mapper := NewVulnToAttackMapper()
	
	// Group techniques by tactic order
	tacticOrder := []string{
		"Initial Access", "Execution", "Persistence", "Privilege Escalation",
		"Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
		"Collection", "Command and Control", "Exfiltration", "Impact",
	}
	
	// Map demonstrations to tactics
	tacticDemos := make(map[string][]Demonstration)
	for _, demo := range demonstrations {
		tactic := mapper.GetTactic(demo.Technique)
		tacticDemos[tactic] = append(tacticDemos[tactic], demo)
	}
	
	// Build ordered chain
	order := 1
	for _, tactic := range tacticOrder {
		if demos, exists := tacticDemos[tactic]; exists {
			for _, demo := range demos {
				step := AttackStep{
					Order:       order,
					Technique:   demo.Technique,
					Tactic:      tactic,
					Description: demo.Description,
					Impact:      demo.Result,
					Evidence:    demo.Finding,
				}
				chain = append(chain, step)
				order++
			}
		}
	}
	
	return chain
}

// generateNavigatorLayer creates MITRE ATT&CK Navigator layer
func (r *AtomicReporter) generateNavigatorLayer(demonstrations []Demonstration) NavigatorLayer {
	layer := NavigatorLayer{
		Name:        fmt.Sprintf("Bug Bounty Assessment - %s", time.Now().Format("2006-01-02")),
		Version:     r.navigatorVersion,
		Description: "ATT&CK techniques demonstrated from bug bounty findings",
		Domain:      r.domain,
		Techniques:  []TechniqueLayer{},
	}
	
	// Create technique layer for each demonstration
	for _, demo := range demonstrations {
		technique := TechniqueLayer{
			TechniqueID: demo.Technique,
			Color:       r.getSeverityColor(demo.Severity),
			Comment:     fmt.Sprintf("%s - %s", demo.Name, demo.Finding),
			Enabled:     true,
			Score:       r.getSeverityScore(demo.Severity),
		}
		layer.Techniques = append(layer.Techniques, technique)
	}
	
	return layer
}

// generateMitigations creates defensive recommendations
func (r *AtomicReporter) generateMitigations(demonstrations []Demonstration) []Mitigation {
	mitigations := []Mitigation{}
	
	// MITRE D3FEND mitigations mapped to ATT&CK techniques
	mitigationMap := map[string]Mitigation{
		"T1552": {
			ID:          "M1017",
			Name:        "User Training",
			Description: "Train users to identify social engineering techniques and suspicious activity",
			Techniques:  []string{"T1552"},
			Priority:    "HIGH",
			References:  []string{"https://attack.mitre.org/mitigations/M1017/"},
		},
		"T1530": {
			ID:          "M1022",
			Name:        "Restrict File and Directory Permissions",
			Description: "Restrict access to sensitive files and directories with proper access controls",
			Techniques:  []string{"T1530"},
			Priority:    "HIGH",
			References:  []string{"https://attack.mitre.org/mitigations/M1022/"},
		},
		"T1190": {
			ID:          "M1016",
			Name:        "Vulnerability Scanning",
			Description: "Regularly scan for vulnerabilities and apply security patches",
			Techniques:  []string{"T1190"},
			Priority:    "CRITICAL",
			References:  []string{"https://attack.mitre.org/mitigations/M1016/"},
		},
		"T1078": {
			ID:          "M1032",
			Name:        "Multi-factor Authentication",
			Description: "Implement multi-factor authentication for all user accounts",
			Techniques:  []string{"T1078"},
			Priority:    "HIGH",
			References:  []string{"https://attack.mitre.org/mitigations/M1032/"},
		},
		"T1003": {
			ID:          "M1027",
			Name:        "Password Policies",
			Description: "Implement strong password policies and credential management",
			Techniques:  []string{"T1003"},
			Priority:    "HIGH",
			References:  []string{"https://attack.mitre.org/mitigations/M1027/"},
		},
	}
	
	// Collect unique mitigations
	seen := make(map[string]bool)
	for _, demo := range demonstrations {
		if mitigation, exists := mitigationMap[demo.Technique]; exists && !seen[mitigation.ID] {
			mitigations = append(mitigations, mitigation)
			seen[mitigation.ID] = true
		}
	}
	
	// Add general security mitigations
	generalMitigations := []Mitigation{
		{
			ID:          "M1049",
			Name:        "Antivirus/Antimalware",
			Description: "Deploy and maintain updated antivirus/antimalware solutions",
			Priority:    "MEDIUM",
			References:  []string{"https://attack.mitre.org/mitigations/M1049/"},
		},
		{
			ID:          "M1018",
			Name:        "User Account Management",
			Description: "Implement proper user account lifecycle management",
			Priority:    "HIGH",
			References:  []string{"https://attack.mitre.org/mitigations/M1018/"},
		},
		{
			ID:          "M1030",
			Name:        "Network Segmentation", 
			Description: "Implement network segmentation to limit lateral movement",
			Priority:    "HIGH",
			References:  []string{"https://attack.mitre.org/mitigations/M1030/"},
		},
	}
	
	for _, mitigation := range generalMitigations {
		if !seen[mitigation.ID] {
			mitigations = append(mitigations, mitigation)
		}
	}
	
	return mitigations
}

// SaveNavigatorLayer saves ATT&CK Navigator layer to file
func (r *AtomicReporter) SaveNavigatorLayer(layer NavigatorLayer, filename string) error {
	data, err := json.MarshalIndent(layer, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal navigator layer: %v", err)
	}
	
	return os.WriteFile(filename, data, 0644)
}

// GenerateHTMLReport creates HTML report with ATT&CK visualization
func (r *AtomicReporter) GenerateHTMLReport(report *ATTACKReport, filename string) error {
	tmpl := template.Must(template.New("report").Parse(htmlReportTemplate))
	
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %v", err)
	}
	defer file.Close()
	
	return tmpl.Execute(file, report)
}

// Helper methods

func (r *AtomicReporter) countHighRiskTechniques(demonstrations []Demonstration) int {
	count := 0
	for _, demo := range demonstrations {
		if demo.Severity == "CRITICAL" || demo.Severity == "HIGH" {
			count++
		}
	}
	return count
}

func (r *AtomicReporter) getTopTactic(tacticCounts map[string]int) string {
	maxCount := 0
	topTactic := ""
	
	for tactic, count := range tacticCounts {
		if count > maxCount {
			maxCount = count
			topTactic = tactic
		}
	}
	
	return topTactic
}

func (r *AtomicReporter) getSeverityColor(severity string) string {
	colors := map[string]string{
		"CRITICAL": "#ff0000", // Red
		"HIGH":     "#ff6600", // Orange
		"MEDIUM":   "#ffcc00", // Yellow
		"LOW":      "#00cc00", // Green
	}
	
	if color, exists := colors[severity]; exists {
		return color
	}
	return "#808080" // Gray default
}

func (r *AtomicReporter) getSeverityScore(severity string) int {
	scores := map[string]int{
		"CRITICAL": 100,
		"HIGH":     75,
		"MEDIUM":   50,
		"LOW":      25,
	}
	
	if score, exists := scores[severity]; exists {
		return score
	}
	return 0
}

// HTML report template
const htmlReportTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ATT&CK Mapped Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { background-color: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .finding { border-left: 4px solid #3498db; padding: 10px; margin: 10px 0; background-color: #ecf0f1; }
        .finding.critical { border-left-color: #e74c3c; }
        .finding.high { border-left-color: #f39c12; }
        .finding.medium { border-left-color: #f1c40f; }
        .finding.low { border-left-color: #27ae60; }
        .technique { background-color: #34495e; color: white; padding: 5px 10px; border-radius: 3px; margin: 2px; display: inline-block; }
        .attack-chain { display: flex; flex-wrap: wrap; gap: 10px; }
        .chain-step { background-color: #3498db; color: white; padding: 10px; border-radius: 5px; text-align: center; min-width: 150px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #34495e; color: white; }
        .mitigation { background-color: #d5f4e6; border-left: 4px solid #27ae60; padding: 10px; margin: 5px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ ATT&CK Mapped Security Assessment Report</h1>
        <p>Generated: {{.Metadata.GeneratedAt.Format "2006-01-02 15:04:05"}}</p>
        <p>Target: {{.Metadata.Target}}</p>
        <p>Total Techniques: {{.Metadata.TotalTechniques}} | High Risk: {{.Metadata.HighRiskTechniques}}</p>
    </div>

    <div class="section">
        <h2>📋 Executive Summary</h2>
        <p>{{.ExecutiveSummary}}</p>
    </div>

    <div class="section">
        <h2>🔍 Security Findings</h2>
        {{range .Findings}}
        <div class="finding {{.Severity | lower}}">
            <h3>{{.Title}}</h3>
            <p><strong>Type:</strong> {{.Type}} | <strong>Severity:</strong> {{.Severity}}</p>
            <p>{{.Description}}</p>
            <p><strong>Impact:</strong> {{.Impact}}</p>
        </div>
        {{end}}
    </div>

    <div class="section">
        <h2>⚔️ Attack Chain Analysis</h2>
        <div class="attack-chain">
            {{range .AttackChain}}
            <div class="chain-step">
                <strong>{{.Order}}. {{.Technique}}</strong><br>
                <small>{{.Tactic}}</small><br>
                {{.Description}}
            </div>
            {{end}}
        </div>
    </div>

    <div class="section">
        <h2>🎯 ATT&CK Techniques</h2>
        <table>
            <tr>
                <th>Technique ID</th>
                <th>Tactic</th>
                <th>Comment</th>
                <th>Score</th>
            </tr>
            {{range .Navigator.Techniques}}
            <tr>
                <td><span class="technique">{{.TechniqueID}}</span></td>
                <td>{{.Comment}}</td>
                <td>{{.Comment}}</td>
                <td>{{.Score}}</td>
            </tr>
            {{end}}
        </table>
    </div>

    <div class="section">
        <h2>🛡️ Recommended Mitigations</h2>
        {{range .Mitigations}}
        <div class="mitigation">
            <h4>{{.ID}}: {{.Name}}</h4>
            <p>{{.Description}}</p>
            <p><strong>Priority:</strong> {{.Priority}}</p>
            {{if .References}}
            <p><strong>References:</strong> 
                {{range .References}}
                <a href="{{.}}" target="_blank">{{.}}</a>
                {{end}}
            </p>
            {{end}}
        </div>
        {{end}}
    </div>

    <div class="section">
        <h2>📊 Navigator Layer</h2>
        <p>Import the following JSON into the <a href="https://mitre-attack.github.io/attack-navigator/" target="_blank">MITRE ATT&CK Navigator</a> for interactive visualization:</p>
        <pre style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto;">{{.Navigator | json}}</pre>
    </div>

    <div class="section">
        <h2>🔗 Additional Resources</h2>
        <ul>
            <li><a href="https://attack.mitre.org/" target="_blank">MITRE ATT&CK Framework</a></li>
            <li><a href="https://github.com/redcanaryco/atomic-red-team" target="_blank">Atomic Red Team</a></li>
            <li><a href="https://mitre-attack.github.io/attack-navigator/" target="_blank">ATT&CK Navigator</a></li>
            <li><a href="https://d3fend.mitre.org/" target="_blank">MITRE D3FEND</a></li>
        </ul>
    </div>
</body>
</html>
`

// BugBountyReporter provides bug bounty specific reporting
type BugBountyReporter struct {
	reporter *AtomicReporter
}

// NewBugBountyReporter creates bug bounty focused reporter
func NewBugBountyReporter() *BugBountyReporter {
	return &BugBountyReporter{
		reporter: NewAtomicReporter(),
	}
}

// GenerateBugBountyReport creates bug bounty specific report
func (b *BugBountyReporter) GenerateBugBountyReport(findings []Finding, demonstrations []Demonstration) *BugBountyReport {
	return &BugBountyReport{
		ATTACKReport: *b.reporter.GenerateATTACKReport(findings, demonstrations),
		BugBountyContext: BugBountyContext{
			ProgramScope:     "Authorized bug bounty testing scope",
			TestingApproach:  "Non-destructive security assessment",
			ComplianceNotes:  "All tests performed within authorized scope and bug bounty guidelines",
			SafetyMeasures:   "Atomic tests filtered for bug bounty safety compliance",
		},
		ImpactAssessment: b.generateImpactAssessment(findings, demonstrations),
		RecommendedActions: b.generateRecommendedActions(findings),
	}
}

// generateImpactAssessment creates impact assessment for bug bounty context
func (b *BugBountyReporter) generateImpactAssessment(findings []Finding, demonstrations []Demonstration) ImpactAssessment {
	assessment := ImpactAssessment{
		OverallRisk:     "MEDIUM",
		BusinessImpact:  "Potential unauthorized access and data exposure",
		AttackComplexity: "MEDIUM",
		ExploitabilityScore: 0.0,
	}
	
	// Calculate overall risk based on findings
	criticalCount := 0
	highCount := 0
	
	for _, finding := range findings {
		switch finding.Severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		}
	}
	
	if criticalCount > 0 {
		assessment.OverallRisk = "CRITICAL"
		assessment.ExploitabilityScore = 9.0
	} else if highCount > 2 {
		assessment.OverallRisk = "HIGH"
		assessment.ExploitabilityScore = 7.5
	} else if highCount > 0 {
		assessment.OverallRisk = "MEDIUM"
		assessment.ExploitabilityScore = 5.5
	} else {
		assessment.OverallRisk = "LOW"
		assessment.ExploitabilityScore = 3.0
	}
	
	// Assess attack complexity based on demonstrated techniques
	if len(demonstrations) > 5 {
		assessment.AttackComplexity = "LOW"
	} else if len(demonstrations) > 2 {
		assessment.AttackComplexity = "MEDIUM"
	} else {
		assessment.AttackComplexity = "HIGH"
	}
	
	return assessment
}

// generateRecommendedActions creates recommended actions for bug bounty report
func (b *BugBountyReporter) generateRecommendedActions(findings []Finding) []RecommendedAction {
	actions := []RecommendedAction{}
	
	// Immediate actions for critical/high findings
	for _, finding := range findings {
		if finding.Severity == "CRITICAL" || finding.Severity == "HIGH" {
			action := RecommendedAction{
				Priority:    finding.Severity,
				Action:      fmt.Sprintf("Address %s vulnerability", finding.Type),
				Timeline:    "Immediate (24-48 hours)",
				Description: fmt.Sprintf("Remediate the %s vulnerability to prevent potential exploitation", finding.Title),
			}
			actions = append(actions, action)
		}
	}
	
	// General security improvements
	generalActions := []RecommendedAction{
		{
			Priority:    "HIGH",
			Action:      "Implement Security Monitoring",
			Timeline:    "1-2 weeks",
			Description: "Deploy comprehensive security monitoring to detect attack techniques demonstrated in this assessment",
		},
		{
			Priority:    "MEDIUM",
			Action:      "Conduct Security Training",
			Timeline:    "1 month",
			Description: "Train security teams on MITRE ATT&CK framework and demonstrated attack techniques",
		},
		{
			Priority:    "MEDIUM",
			Action:      "Regular Security Assessments",
			Timeline:    "Ongoing",
			Description: "Implement regular security assessments using atomic testing and ATT&CK mapping",
		},
	}
	
	actions = append(actions, generalActions...)
	
	return actions
}

// BugBountyReport extends ATT&CK report with bug bounty context
type BugBountyReport struct {
	ATTACKReport       `json:"attack_report"`
	BugBountyContext   BugBountyContext   `json:"bug_bounty_context"`
	ImpactAssessment   ImpactAssessment   `json:"impact_assessment"`
	RecommendedActions []RecommendedAction `json:"recommended_actions"`
}

// BugBountyContext provides bug bounty specific context
type BugBountyContext struct {
	ProgramScope    string `json:"program_scope"`
	TestingApproach string `json:"testing_approach"`
	ComplianceNotes string `json:"compliance_notes"`
	SafetyMeasures  string `json:"safety_measures"`
}

// ImpactAssessment provides business impact analysis
type ImpactAssessment struct {
	OverallRisk         string  `json:"overall_risk"`
	BusinessImpact      string  `json:"business_impact"`
	AttackComplexity    string  `json:"attack_complexity"`
	ExploitabilityScore float64 `json:"exploitability_score"`
}

// RecommendedAction represents actionable recommendations
type RecommendedAction struct {
	Priority    string `json:"priority"`
	Action      string `json:"action"`
	Timeline    string `json:"timeline"`
	Description string `json:"description"`
}