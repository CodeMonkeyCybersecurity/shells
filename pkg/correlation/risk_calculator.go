// pkg/correlation/risk_calculator.go
package correlation

import (
	"math"
	"strings"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// RiskCalculator calculates risk scores for correlated insights
type RiskCalculator struct {
	logger *logger.Logger
}

// NewRiskCalculator creates a new risk calculator
func NewRiskCalculator() *RiskCalculator {
	cfg := config.LoggerConfig{Level: "info", Format: "json"}
	log, _ := logger.New(cfg)
	return &RiskCalculator{
		logger: log.WithComponent("risk-calculator"),
	}
}

// CalculateRiskScore calculates overall risk score for a set of findings
func (rc *RiskCalculator) CalculateRiskScore(findings []types.Finding) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	// Base score from individual findings
	baseScore := rc.calculateBaseScore(findings)

	// Risk multipliers
	exposureMultiplier := rc.calculateExposureMultiplier(findings)
	exploitabilityMultiplier := rc.calculateExploitabilityMultiplier(findings)
	businessImpactMultiplier := rc.calculateBusinessImpactMultiplier(findings)
	attackChainMultiplier := rc.calculateAttackChainMultiplier(findings)

	// Calculate final score
	riskScore := baseScore * exposureMultiplier * exploitabilityMultiplier *
		businessImpactMultiplier * attackChainMultiplier

	// Cap at 10.0
	if riskScore > 10.0 {
		riskScore = 10.0
	}

	rc.logger.Infow("Risk score calculated",
		"base_score", baseScore,
		"exposure_multiplier", exposureMultiplier,
		"exploitability_multiplier", exploitabilityMultiplier,
		"business_impact_multiplier", businessImpactMultiplier,
		"attack_chain_multiplier", attackChainMultiplier,
		"final_score", riskScore)

	return riskScore
}

// CalculateBusinessImpact assesses potential business impact
func (rc *RiskCalculator) CalculateBusinessImpact(findings []types.Finding) BusinessImpact {
	impact := BusinessImpact{
		FinancialImpact:    rc.assessFinancialImpact(findings),
		OperationalImpact:  rc.assessOperationalImpact(findings),
		ReputationalImpact: rc.assessReputationalImpact(findings),
		ComplianceImpact:   rc.assessComplianceImpact(findings),
		OverallScore:       0.0,
	}

	// Calculate weighted overall score
	impact.OverallScore = (impact.FinancialImpact*0.3 +
		impact.OperationalImpact*0.25 +
		impact.ReputationalImpact*0.25 +
		impact.ComplianceImpact*0.2)

	return impact
}

// CalculateExploitability assesses how easily findings can be exploited
func (rc *RiskCalculator) CalculateExploitability(findings []types.Finding) ExploitabilityAssessment {
	assessment := ExploitabilityAssessment{
		SkillRequired:       rc.assessSkillLevel(findings),
		ToolsRequired:       rc.assessToolRequirement(findings),
		TimeRequired:        rc.assessTimeRequirement(findings),
		AccessRequired:      rc.assessAccessRequirement(findings),
		DetectionLikelihood: rc.assessDetectionLikelihood(findings),
	}

	// Calculate overall exploitability score (lower is easier to exploit)
	assessment.OverallScore = (assessment.SkillRequired*0.25 +
		assessment.ToolsRequired*0.2 +
		assessment.TimeRequired*0.2 +
		assessment.AccessRequired*0.25 +
		assessment.DetectionLikelihood*0.1)

	return assessment
}

// Private methods for base calculations

func (rc *RiskCalculator) calculateBaseScore(findings []types.Finding) float64 {
	var totalScore float64
	severityWeights := map[types.Severity]float64{
		types.SeverityInfo:     1.0,
		types.SeverityLow:      2.0,
		types.SeverityMedium:   4.0,
		types.SeverityHigh:     7.0,
		types.SeverityCritical: 9.0,
	}

	for _, finding := range findings {
		if weight, exists := severityWeights[finding.Severity]; exists {
			totalScore += weight
		}
	}

	// Average score
	return totalScore / float64(len(findings))
}

func (rc *RiskCalculator) calculateExposureMultiplier(findings []types.Finding) float64 {
	multiplier := 1.0

	for _, finding := range findings {
		// Check for external exposure indicators
		if rc.isExternallyExposed(finding) {
			multiplier *= 1.5
		}

		// Check for authentication bypass
		if rc.isAuthenticationBypass(finding) {
			multiplier *= 1.8
		}

		// Check for privilege escalation
		if rc.isPrivilegeEscalation(finding) {
			multiplier *= 1.6
		}
	}

	// Cap multiplier
	if multiplier > 3.0 {
		multiplier = 3.0
	}

	return multiplier
}

func (rc *RiskCalculator) calculateExploitabilityMultiplier(findings []types.Finding) float64 {
	multiplier := 1.0

	for _, finding := range findings {
		// Check for remote code execution
		if rc.isRemoteCodeExecution(finding) {
			multiplier *= 2.0
		}

		// Check for SQL injection
		if rc.isSQLInjection(finding) {
			multiplier *= 1.7
		}

		// Check for known CVEs
		if rc.hasKnownExploit(finding) {
			multiplier *= 1.5
		}
	}

	// Cap multiplier
	if multiplier > 2.5 {
		multiplier = 2.5
	}

	return multiplier
}

func (rc *RiskCalculator) calculateBusinessImpactMultiplier(findings []types.Finding) float64 {
	multiplier := 1.0

	for _, finding := range findings {
		// Check for data exposure
		if rc.isDataExposure(finding) {
			multiplier *= 1.8
		}

		// Check for payment systems
		if rc.affectsPaymentSystems(finding) {
			multiplier *= 2.0
		}

		// Check for customer data
		if rc.affectsCustomerData(finding) {
			multiplier *= 1.6
		}
	}

	// Cap multiplier
	if multiplier > 2.5 {
		multiplier = 2.5
	}

	return multiplier
}

func (rc *RiskCalculator) calculateAttackChainMultiplier(findings []types.Finding) float64 {
	// More findings that can be chained together increase risk
	if len(findings) == 1 {
		return 1.0
	}

	// Log scale for attack chain complexity
	chainLength := float64(len(findings))
	multiplier := 1.0 + math.Log(chainLength)/math.Log(10)*0.5

	// Cap multiplier
	if multiplier > 2.0 {
		multiplier = 2.0
	}

	return multiplier
}

// Risk assessment helpers

func (rc *RiskCalculator) isExternallyExposed(finding types.Finding) bool {
	keywords := []string{"exposed", "public", "internet", "external", "0.0.0.0"}
	content := strings.ToLower(finding.Description + " " + finding.Evidence)

	for _, keyword := range keywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	return false
}

func (rc *RiskCalculator) isAuthenticationBypass(finding types.Finding) bool {
	keywords := []string{"auth", "login", "bypass", "unauthenticated", "anonymous"}
	content := strings.ToLower(finding.Type + " " + finding.Description)

	for _, keyword := range keywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	return false
}

func (rc *RiskCalculator) isPrivilegeEscalation(finding types.Finding) bool {
	keywords := []string{"privilege", "escalation", "admin", "root", "sudo", "elevation"}
	content := strings.ToLower(finding.Type + " " + finding.Description)

	for _, keyword := range keywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	return false
}

func (rc *RiskCalculator) isRemoteCodeExecution(finding types.Finding) bool {
	keywords := []string{"rce", "code execution", "command injection", "shell", "exec"}
	content := strings.ToLower(finding.Type + " " + finding.Description)

	for _, keyword := range keywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	return false
}

func (rc *RiskCalculator) isSQLInjection(finding types.Finding) bool {
	keywords := []string{"sql", "injection", "sqli", "database"}
	content := strings.ToLower(finding.Type + " " + finding.Description)

	for _, keyword := range keywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	return false
}

func (rc *RiskCalculator) hasKnownExploit(finding types.Finding) bool {
	keywords := []string{"cve-", "exploit", "metasploit", "poc"}
	content := strings.ToLower(finding.Evidence + " " + finding.Description)

	for _, keyword := range keywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	return false
}

func (rc *RiskCalculator) isDataExposure(finding types.Finding) bool {
	keywords := []string{"data", "leak", "exposure", "dump", "backup", "database"}
	content := strings.ToLower(finding.Type + " " + finding.Description)

	for _, keyword := range keywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	return false
}

func (rc *RiskCalculator) affectsPaymentSystems(finding types.Finding) bool {
	keywords := []string{"payment", "card", "billing", "transaction", "stripe", "paypal"}
	content := strings.ToLower(finding.Description + " " + finding.Evidence)

	for _, keyword := range keywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	return false
}

func (rc *RiskCalculator) affectsCustomerData(finding types.Finding) bool {
	keywords := []string{"customer", "user", "personal", "pii", "gdpr", "ccpa"}
	content := strings.ToLower(finding.Description + " " + finding.Evidence)

	for _, keyword := range keywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	return false
}

// Business impact assessment methods

func (rc *RiskCalculator) assessFinancialImpact(findings []types.Finding) float64 {
	score := 5.0 // Base score

	for _, finding := range findings {
		if rc.affectsPaymentSystems(finding) {
			score += 3.0
		}
		if rc.isDataExposure(finding) {
			score += 2.0
		}
		if finding.Severity == types.SeverityCritical {
			score += 1.5
		}
	}

	if score > 10.0 {
		score = 10.0
	}
	return score
}

func (rc *RiskCalculator) assessOperationalImpact(findings []types.Finding) float64 {
	score := 5.0 // Base score

	for _, finding := range findings {
		if rc.isRemoteCodeExecution(finding) {
			score += 3.0
		}
		if rc.isExternallyExposed(finding) {
			score += 2.0
		}
		if finding.Severity == types.SeverityCritical {
			score += 1.5
		}
	}

	if score > 10.0 {
		score = 10.0
	}
	return score
}

func (rc *RiskCalculator) assessReputationalImpact(findings []types.Finding) float64 {
	score := 5.0 // Base score

	for _, finding := range findings {
		if rc.affectsCustomerData(finding) {
			score += 3.0
		}
		if rc.isDataExposure(finding) {
			score += 2.5
		}
		if rc.isExternallyExposed(finding) {
			score += 2.0
		}
	}

	if score > 10.0 {
		score = 10.0
	}
	return score
}

func (rc *RiskCalculator) assessComplianceImpact(findings []types.Finding) float64 {
	score := 5.0 // Base score

	for _, finding := range findings {
		if rc.affectsCustomerData(finding) {
			score += 3.0
		}
		if rc.affectsPaymentSystems(finding) {
			score += 2.5
		}
		if rc.isDataExposure(finding) {
			score += 2.0
		}
	}

	if score > 10.0 {
		score = 10.0
	}
	return score
}

// Exploitability assessment methods

func (rc *RiskCalculator) assessSkillLevel(findings []types.Finding) float64 {
	score := 5.0 // Medium skill required by default

	for _, finding := range findings {
		if rc.hasKnownExploit(finding) {
			score -= 2.0 // Lower skill needed
		}
		if rc.isRemoteCodeExecution(finding) {
			score -= 1.0
		}
		if strings.Contains(strings.ToLower(finding.Description), "complex") {
			score += 2.0 // Higher skill needed
		}
	}

	if score < 1.0 {
		score = 1.0
	}
	if score > 10.0 {
		score = 10.0
	}
	return score
}

func (rc *RiskCalculator) assessToolRequirement(findings []types.Finding) float64 {
	score := 5.0 // Standard tools by default

	for _, finding := range findings {
		if rc.hasKnownExploit(finding) {
			score -= 2.0 // Common tools available
		}
		if strings.Contains(strings.ToLower(finding.Description), "custom") {
			score += 3.0 // Custom tools needed
		}
	}

	if score < 1.0 {
		score = 1.0
	}
	if score > 10.0 {
		score = 10.0
	}
	return score
}

func (rc *RiskCalculator) assessTimeRequirement(findings []types.Finding) float64 {
	score := 5.0 // Medium time by default

	for _, finding := range findings {
		if rc.hasKnownExploit(finding) {
			score -= 2.0 // Quick exploitation
		}
		if rc.isAuthenticationBypass(finding) {
			score -= 1.0
		}
		if strings.Contains(strings.ToLower(finding.Description), "brute") {
			score += 3.0 // Time-intensive
		}
	}

	if score < 1.0 {
		score = 1.0
	}
	if score > 10.0 {
		score = 10.0
	}
	return score
}

func (rc *RiskCalculator) assessAccessRequirement(findings []types.Finding) float64 {
	score := 5.0 // Some access required by default

	for _, finding := range findings {
		if rc.isExternallyExposed(finding) {
			score -= 3.0 // No special access needed
		}
		if rc.isAuthenticationBypass(finding) {
			score -= 2.0
		}
		if strings.Contains(strings.ToLower(finding.Description), "internal") {
			score += 3.0 // Internal access required
		}
	}

	if score < 1.0 {
		score = 1.0
	}
	if score > 10.0 {
		score = 10.0
	}
	return score
}

func (rc *RiskCalculator) assessDetectionLikelihood(findings []types.Finding) float64 {
	score := 5.0 // Medium detection likelihood by default

	for _, finding := range findings {
		if strings.Contains(strings.ToLower(finding.Description), "stealth") {
			score -= 2.0 // Low detection
		}
		if strings.Contains(strings.ToLower(finding.Description), "log") {
			score += 2.0 // High detection
		}
	}

	if score < 1.0 {
		score = 1.0
	}
	if score > 10.0 {
		score = 10.0
	}
	return score
}

// Supporting types

type BusinessImpact struct {
	FinancialImpact    float64
	OperationalImpact  float64
	ReputationalImpact float64
	ComplianceImpact   float64
	OverallScore       float64
}

type ExploitabilityAssessment struct {
	SkillRequired       float64 // 1-10, lower means easier
	ToolsRequired       float64 // 1-10, lower means common tools
	TimeRequired        float64 // 1-10, lower means faster
	AccessRequired      float64 // 1-10, lower means less access needed
	DetectionLikelihood float64 // 1-10, lower means harder to detect
	OverallScore        float64 // Composite score
}
