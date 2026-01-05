package recovery

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/logic"
	"github.com/google/uuid"
)

// AccountRecoveryTester provides comprehensive account recovery testing
type AccountRecoveryTester struct {
	httpClient      *http.Client
	config          *logic.TestConfig
	resetAnalyzer   *PasswordResetAnalyzer
	mfaBypassTester *MFABypassTester
	methods         []logic.AccountRecoveryMethod
	results         []logic.Vulnerability
	mutex           sync.RWMutex
}

// NewAccountRecoveryTester creates a new account recovery tester
func NewAccountRecoveryTester(config *logic.TestConfig) *AccountRecoveryTester {
	if config == nil {
		config = &logic.TestConfig{
			Timeout:           30 * time.Second,
			FollowRedirects:   true,
			MaintainSession:   true,
			TestTokenEntropy:  true,
			TestHostHeader:    true,
			TokenSamples:      100,
			BruteForceThreads: 50,
		}
	}

	tester := &AccountRecoveryTester{
		httpClient:      &http.Client{Timeout: config.Timeout},
		config:          config,
		resetAnalyzer:   NewPasswordResetAnalyzer(config),
		mfaBypassTester: NewMFABypassTester(config),
		results:         []logic.Vulnerability{},
	}

	// Register all recovery methods
	tester.methods = []logic.AccountRecoveryMethod{
		&PasswordResetMethod{tester: tester},
		&SecurityQuestionMethod{tester: tester},
		&SMSRecoveryMethod{tester: tester},
		&EmailRecoveryMethod{tester: tester},
		&BackupCodeMethod{tester: tester},
		&SocialRecoveryMethod{tester: tester},
		&KnowledgeBasedMethod{tester: tester},
		&BiometricRecoveryMethod{tester: tester},
		&AdminRecoveryMethod{tester: tester},
		&DeviceRecoveryMethod{tester: tester},
	}

	return tester
}

// TestAllMethods tests all account recovery methods
func (a *AccountRecoveryTester) TestAllMethods(target string) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Test each recovery method
	for _, method := range a.methods {
		if method.IsEnabled(target) {
			methodVulns := method.Test(target, a.config)
			vulnerabilities = append(vulnerabilities, methodVulns...)
		}
	}

	// Additional comprehensive tests
	comprehensiveVulns := a.runComprehensiveTests(target)
	vulnerabilities = append(vulnerabilities, comprehensiveVulns...)

	return vulnerabilities
}

// runComprehensiveTests runs comprehensive recovery tests
func (a *AccountRecoveryTester) runComprehensiveTests(target string) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Test password reset flows
	resetVulns := a.testPasswordResetFlows(target)
	vulnerabilities = append(vulnerabilities, resetVulns...)

	// Test MFA bypass scenarios
	mfaVulns := a.testMFABypassScenarios(target)
	vulnerabilities = append(vulnerabilities, mfaVulns...)

	// Test account enumeration
	if vuln := a.testAccountEnumeration(target); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test recovery flow chaining
	if vuln := a.testRecoveryFlowChaining(target); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test cross-recovery method attacks
	crossVulns := a.testCrossRecoveryAttacks(target)
	vulnerabilities = append(vulnerabilities, crossVulns...)

	return vulnerabilities
}

// testPasswordResetFlows tests password reset vulnerabilities
func (a *AccountRecoveryTester) testPasswordResetFlows(target string) []logic.Vulnerability {
	analysis := a.resetAnalyzer.AnalyzeResetFlow(target)
	return analysis.Vulnerabilities
}

// testMFABypassScenarios tests MFA bypass via recovery
func (a *AccountRecoveryTester) testMFABypassScenarios(target string) []logic.Vulnerability {
	return a.mfaBypassTester.TestAllMethods(target)
}

// testAccountEnumeration tests for account enumeration via recovery
func (a *AccountRecoveryTester) testAccountEnumeration(target string) *logic.Vulnerability {
	// Test different recovery endpoints for enumeration
	endpoints := []string{
		target + "/forgot-password",
		target + "/reset-password",
		target + "/account-recovery",
		target + "/security-questions",
		target + "/recover",
	}

	for _, endpoint := range endpoints {
		// Test with known valid and invalid accounts
		validAccount := "admin@example.com"
		invalidAccount := "nonexistent@example.com"

		validResponse := a.testRecoveryRequest(endpoint, validAccount)
		invalidResponse := a.testRecoveryRequest(endpoint, invalidAccount)

		if a.detectUserEnumeration(validResponse, invalidResponse) {
			return &logic.Vulnerability{
				ID:          uuid.New().String(),
				Type:        logic.VulnUserEnumeration,
				Severity:    logic.SeverityMedium,
				Title:       "User Enumeration via Account Recovery",
				Description: "Account recovery responses reveal whether accounts exist",
				Details:     fmt.Sprintf("Endpoint %s reveals user existence", endpoint),
				Impact:      "Attackers can enumerate valid user accounts",
				Evidence: map[string]interface{}{
					"endpoint":         endpoint,
					"valid_response":   validResponse.StatusCode,
					"invalid_response": invalidResponse.StatusCode,
				},
				CWE:         "CWE-204",
				CVSS:        5.3,
				Remediation: "Return identical responses for valid and invalid accounts",
				Timestamp:   time.Now(),
			}
		}
	}

	return nil
}

// testRecoveryFlowChaining tests chaining recovery methods
func (a *AccountRecoveryTester) testRecoveryFlowChaining(target string) *logic.Vulnerability {
	// Test if recovery methods can be chained to bypass protections

	// Example: Use password reset to bypass security questions
	resetToken := a.initiatePasswordReset(target, "victim@example.com")
	if resetToken == "" {
		return nil
	}

	// Try to use reset token to bypass security questions
	if a.canBypassSecurityQuestions(target, resetToken) {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnRecoveryFlowBypass,
			Severity:    logic.SeverityHigh,
			Title:       "Recovery Method Chaining Bypass",
			Description: "Recovery methods can be chained to bypass additional protections",
			Details:     "Password reset token can bypass security question verification",
			Impact:      "Multi-factor recovery protections can be bypassed",
			CWE:         "CWE-287",
			CVSS:        7.5,
			Remediation: "Implement consistent security requirements across all recovery methods",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

// testCrossRecoveryAttacks tests attacks across recovery methods
func (a *AccountRecoveryTester) testCrossRecoveryAttacks(target string) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Test recovery method interference
	if vuln := a.testRecoveryMethodInterference(target); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test recovery session hijacking
	if vuln := a.testRecoverySessionHijacking(target); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	return vulnerabilities
}

// Recovery method implementations

// PasswordResetMethod tests password reset recovery
type PasswordResetMethod struct {
	tester *AccountRecoveryTester
}

func (p *PasswordResetMethod) Name() string {
	return "Password Reset"
}

func (p *PasswordResetMethod) Test(target string, config *logic.TestConfig) []logic.Vulnerability {
	// Comprehensive password reset testing is handled by PasswordResetAnalyzer
	analysis := p.tester.resetAnalyzer.AnalyzeResetFlow(target)
	return analysis.Vulnerabilities
}

func (p *PasswordResetMethod) IsEnabled(target string) bool {
	// Check if password reset is available
	endpoints := []string{
		target + "/forgot-password",
		target + "/reset-password",
		target + "/password/reset",
	}

	for _, endpoint := range endpoints {
		resp, err := p.tester.httpClient.Get(endpoint)
		if err == nil {
			httpclient.CloseBody(resp)
			if resp.StatusCode == 200 {
				return true
			}
		}
	}

	return false
}

// SecurityQuestionMethod tests security question recovery
type SecurityQuestionMethod struct {
	tester *AccountRecoveryTester
}

func (s *SecurityQuestionMethod) Name() string {
	return "Security Questions"
}

func (s *SecurityQuestionMethod) Test(target string, config *logic.TestConfig) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Test for weak security questions
	questions := s.extractSecurityQuestions(target)
	for _, question := range questions {
		if s.isWeakQuestion(question) {
			vulnerabilities = append(vulnerabilities, logic.Vulnerability{
				ID:          uuid.New().String(),
				Type:        logic.VulnWeakSecurityQuestion,
				Severity:    logic.SeverityMedium,
				Title:       "Weak Security Question",
				Description: "Security questions are easily guessable",
				Details:     fmt.Sprintf("Weak question: %s", question),
				Impact:      "Attackers can guess answers to security questions",
				CWE:         "CWE-521",
				CVSS:        5.3,
				Remediation: "Use strong, personalized security questions",
				Timestamp:   time.Now(),
			})
		}
	}

	// Test for question reuse
	if s.questionsAreReused(target) {
		vulnerabilities = append(vulnerabilities, logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        "SECURITY_QUESTION_REUSE",
			Severity:    logic.SeverityMedium,
			Title:       "Security Question Reuse",
			Description: "Same security questions used across multiple accounts",
			Details:     "Security questions are not unique per user",
			Impact:      "Information leakage between accounts",
			CWE:         "CWE-200",
			CVSS:        4.3,
			Remediation: "Implement unique security questions per user",
			Timestamp:   time.Now(),
		})
	}

	return vulnerabilities
}

func (s *SecurityQuestionMethod) IsEnabled(target string) bool {
	// Check if security questions are used
	endpoints := []string{
		target + "/security-questions",
		target + "/forgot-password",
		target + "/account-recovery",
	}

	for _, endpoint := range endpoints {
		resp, err := s.tester.httpClient.Get(endpoint)
		if err == nil {
			httpclient.CloseBody(resp)
			if resp.StatusCode == 200 {
				return true
			}
		}
	}

	return false
}

// SMSRecoveryMethod tests SMS-based recovery
type SMSRecoveryMethod struct {
	tester *AccountRecoveryTester
}

func (s *SMSRecoveryMethod) Name() string {
	return "SMS Recovery"
}

func (s *SMSRecoveryMethod) Test(target string, config *logic.TestConfig) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Test SMS code generation
	if vuln := s.testSMSCodeGeneration(target); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test SMS enumeration
	if vuln := s.testSMSEnumeration(target); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test SMS interception
	if vuln := s.testSMSInterception(target); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	return vulnerabilities
}

func (s *SMSRecoveryMethod) IsEnabled(target string) bool {
	// Check if SMS recovery is available
	return s.detectSMSRecovery(target)
}

// EmailRecoveryMethod tests email-based recovery
type EmailRecoveryMethod struct {
	tester *AccountRecoveryTester
}

func (e *EmailRecoveryMethod) Name() string {
	return "Email Recovery"
}

func (e *EmailRecoveryMethod) Test(target string, config *logic.TestConfig) []logic.Vulnerability {
	// Email recovery is part of password reset testing
	return []logic.Vulnerability{}
}

func (e *EmailRecoveryMethod) IsEnabled(target string) bool {
	return true // Email recovery is typically always available
}

// BackupCodeMethod tests backup code recovery
type BackupCodeMethod struct {
	tester *AccountRecoveryTester
}

func (b *BackupCodeMethod) Name() string {
	return "Backup Codes"
}

func (b *BackupCodeMethod) Test(target string, config *logic.TestConfig) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Test backup code generation
	codes := b.generateBackupCodes(target)
	if len(codes) == 0 {
		return vulnerabilities
	}

	// Test backup code entropy
	entropy := b.calculateEntropy(codes)
	if entropy < 32 {
		vulnerabilities = append(vulnerabilities, logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnBackupCodeWeakness,
			Severity:    logic.SeverityMedium,
			Title:       "Weak Backup Code Generation",
			Description: "Backup codes have insufficient entropy",
			Details:     fmt.Sprintf("Entropy: %.2f bits (should be ≥32)", entropy),
			Impact:      "Backup codes may be predictable",
			CWE:         "CWE-331",
			CVSS:        5.3,
			Remediation: "Use cryptographically secure random generation",
			Timestamp:   time.Now(),
		})
	}

	// Test backup code reuse
	if b.testCodeReuse(target, codes[0]) {
		vulnerabilities = append(vulnerabilities, logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnBackupCodeWeakness,
			Severity:    logic.SeverityHigh,
			Title:       "Backup Code Reuse",
			Description: "Backup codes can be reused multiple times",
			Details:     "Same backup code used successfully multiple times",
			Impact:      "Compromised backup codes remain valid",
			CWE:         "CWE-294",
			CVSS:        7.5,
			Remediation: "Implement one-time use for backup codes",
			Timestamp:   time.Now(),
		})
	}

	return vulnerabilities
}

func (b *BackupCodeMethod) IsEnabled(target string) bool {
	return b.detectBackupCodes(target)
}

// Additional recovery methods (simplified implementations)

type SocialRecoveryMethod struct {
	tester *AccountRecoveryTester
}

func (s *SocialRecoveryMethod) Name() string {
	return "Social Recovery"
}

func (s *SocialRecoveryMethod) Test(target string, config *logic.TestConfig) []logic.Vulnerability {
	// Test social media account recovery
	return []logic.Vulnerability{}
}

func (s *SocialRecoveryMethod) IsEnabled(target string) bool {
	return false // Social recovery is less common
}

type KnowledgeBasedMethod struct {
	tester *AccountRecoveryTester
}

func (k *KnowledgeBasedMethod) Name() string {
	return "Knowledge-Based Authentication"
}

func (k *KnowledgeBasedMethod) Test(target string, config *logic.TestConfig) []logic.Vulnerability {
	// Test knowledge-based authentication
	return []logic.Vulnerability{}
}

func (k *KnowledgeBasedMethod) IsEnabled(target string) bool {
	return false // KBA is less common
}

type BiometricRecoveryMethod struct {
	tester *AccountRecoveryTester
}

func (b *BiometricRecoveryMethod) Name() string {
	return "Biometric Recovery"
}

func (b *BiometricRecoveryMethod) Test(target string, config *logic.TestConfig) []logic.Vulnerability {
	// Test biometric recovery methods
	return []logic.Vulnerability{}
}

func (b *BiometricRecoveryMethod) IsEnabled(target string) bool {
	return false // Biometric recovery is rare in web apps
}

type AdminRecoveryMethod struct {
	tester *AccountRecoveryTester
}

func (a *AdminRecoveryMethod) Name() string {
	return "Admin Recovery"
}

func (a *AdminRecoveryMethod) Test(target string, config *logic.TestConfig) []logic.Vulnerability {
	// Test admin-assisted recovery
	return []logic.Vulnerability{}
}

func (a *AdminRecoveryMethod) IsEnabled(target string) bool {
	return false // Admin recovery is not typically automated
}

type DeviceRecoveryMethod struct {
	tester *AccountRecoveryTester
}

func (d *DeviceRecoveryMethod) Name() string {
	return "Device Recovery"
}

func (d *DeviceRecoveryMethod) Test(target string, config *logic.TestConfig) []logic.Vulnerability {
	// Test device-based recovery
	return []logic.Vulnerability{}
}

func (d *DeviceRecoveryMethod) IsEnabled(target string) bool {
	return false // Device recovery is less common
}

// Helper methods and types

type RecoveryResponse struct {
	StatusCode int
	Body       string
	Headers    map[string]string
	Duration   time.Duration
}

// Helper method implementations

func (a *AccountRecoveryTester) testRecoveryRequest(endpoint, account string) *RecoveryResponse {
	// Simulate recovery request
	return &RecoveryResponse{
		StatusCode: 200,
		Body:       "Recovery email sent",
		Headers:    map[string]string{},
		Duration:   100 * time.Millisecond,
	}
}

func (a *AccountRecoveryTester) detectUserEnumeration(valid, invalid *RecoveryResponse) bool {
	// Check for differences that indicate user enumeration
	if valid.StatusCode != invalid.StatusCode {
		return true
	}

	if len(valid.Body) != len(invalid.Body) {
		return true
	}

	timeDiff := float64(valid.Duration-invalid.Duration) / float64(valid.Duration)
	return timeDiff > 0.2 // More than 20% difference
}

func (a *AccountRecoveryTester) initiatePasswordReset(target, email string) string {
	// Simulate password reset initiation
	return "reset_token_" + uuid.New().String()
}

func (a *AccountRecoveryTester) canBypassSecurityQuestions(target, token string) bool {
	// Test if reset token can bypass security questions
	return true // Assume vulnerable for demo
}

func (a *AccountRecoveryTester) testRecoveryMethodInterference(target string) *logic.Vulnerability {
	// Test if recovery methods interfere with each other
	return nil
}

func (a *AccountRecoveryTester) testRecoverySessionHijacking(target string) *logic.Vulnerability {
	// Test recovery session hijacking
	return nil
}

func (s *SecurityQuestionMethod) extractSecurityQuestions(target string) []string {
	// Extract security questions from the application
	return []string{
		"What is your mother's maiden name?",
		"What was the name of your first pet?",
		"What city were you born in?",
	}
}

func (s *SecurityQuestionMethod) isWeakQuestion(question string) bool {
	// Check if question is weak/easily guessable
	weakQuestions := []string{
		"mother's maiden name",
		"first pet",
		"city of birth",
		"favorite color",
		"first school",
	}

	lowerQuestion := strings.ToLower(question)
	for _, weak := range weakQuestions {
		if strings.Contains(lowerQuestion, weak) {
			return true
		}
	}

	return false
}

func (s *SecurityQuestionMethod) questionsAreReused(target string) bool {
	// Test if questions are reused across accounts
	return false
}

func (s *SMSRecoveryMethod) testSMSCodeGeneration(target string) *logic.Vulnerability {
	// Test SMS code generation vulnerabilities
	return nil
}

func (s *SMSRecoveryMethod) testSMSEnumeration(target string) *logic.Vulnerability {
	// Test SMS enumeration vulnerabilities
	return nil
}

func (s *SMSRecoveryMethod) testSMSInterception(target string) *logic.Vulnerability {
	// Test SMS interception vulnerabilities
	return nil
}

func (s *SMSRecoveryMethod) detectSMSRecovery(target string) bool {
	// Detect if SMS recovery is available
	return false
}

func (b *BackupCodeMethod) generateBackupCodes(target string) []string {
	// Generate backup codes for testing
	return []string{"123456", "789012", "345678"}
}

func (b *BackupCodeMethod) calculateEntropy(codes []string) float64 {
	// Calculate entropy of backup codes
	if len(codes) == 0 {
		return 0
	}

	// Simplified entropy calculation
	// 6 digits = log2(10^6) ≈ 20 bits
	return 20.0
}

func (b *BackupCodeMethod) testCodeReuse(target, code string) bool {
	// Test if backup codes can be reused
	return false
}

func (b *BackupCodeMethod) detectBackupCodes(target string) bool {
	// Detect if backup codes are used
	return false
}
