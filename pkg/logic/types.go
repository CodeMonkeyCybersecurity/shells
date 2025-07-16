package logic

import (
	"net/http"
	"time"
)

// Core types for business logic testing

// Vulnerability represents a business logic vulnerability
type Vulnerability struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Details     string                 `json:"details"`
	Impact      string                 `json:"impact"`
	PoC         string                 `json:"poc,omitempty"`
	Evidence    map[string]interface{} `json:"evidence,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	CVSS        float64                `json:"cvss,omitempty"`
	CWE         string                 `json:"cwe,omitempty"`
	References  []string               `json:"references,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

// TestCase represents a business logic test case
type TestCase struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Severity    string                 `json:"severity"`
	Impact      string                 `json:"impact"`
	Method      string                 `json:"method"`
	Parameters  map[string]interface{} `json:"parameters"`
	Expected    string                 `json:"expected"`
	Remediation string                 `json:"remediation"`
}

// WorkflowState represents a state in a business workflow
type WorkflowState struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Parameters  map[string]string `json:"parameters"`
	Headers     map[string]string `json:"headers"`
	Cookies     []*http.Cookie    `json:"cookies"`
	StatusCode  int               `json:"status_code"`
	Response    string            `json:"response"`
	Transitions []string          `json:"transitions"`
	IsTerminal  bool              `json:"is_terminal"`
	Timestamp   time.Time         `json:"timestamp"`
}

// Workflow represents a complete business workflow
type Workflow struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	StartURL    string                    `json:"start_url"`
	States      map[string]*WorkflowState `json:"states"`
	Transitions map[string][]string       `json:"transitions"`
	CurrentState string                   `json:"current_state"`
	Session     *http.Client              `json:"-"`
	Depth       int                       `json:"depth"`
	MaxDepth    int                       `json:"max_depth"`
}

// RaceConditionTest represents a race condition test
type RaceConditionTest struct {
	Name        string        `json:"name"`
	Endpoint    string        `json:"endpoint"`
	Method      string        `json:"method"`
	Payload     string        `json:"payload"`
	Workers     int           `json:"workers"`
	Duration    time.Duration `json:"duration"`
	Successful  int           `json:"successful"`
	Failed      int           `json:"failed"`
	Vulnerable  bool          `json:"vulnerable"`
	Impact      string        `json:"impact"`
	Evidence    []string      `json:"evidence"`
}

// TokenAnalysis represents analysis of security tokens
type TokenAnalysis struct {
	Tokens        []string  `json:"tokens"`
	Entropy       float64   `json:"entropy"`
	IsPredictable bool      `json:"is_predictable"`
	Pattern       string    `json:"pattern,omitempty"`
	Algorithm     string    `json:"algorithm,omitempty"`
	Collisions    int       `json:"collisions"`
	Timestamp     time.Time `json:"timestamp"`
}

// MFABypassMethod represents an MFA bypass technique
type MFABypassMethod interface {
	Name() string
	Description() string
	Test(target string, config *TestConfig) *Vulnerability
	Category() string
	Severity() string
}

// AccountRecoveryMethod represents an account recovery method
type AccountRecoveryMethod interface {
	Name() string
	Test(target string, config *TestConfig) []Vulnerability
	IsEnabled(target string) bool
}

// BusinessLogicPattern represents a business logic vulnerability pattern
type BusinessLogicPattern interface {
	Name() string
	Test(workflow *Workflow) *Vulnerability
	Category() string
	Risk() string
}

// TestConfig holds configuration for business logic tests
type TestConfig struct {
	Target           string            `json:"target"`
	MaxWorkers       int               `json:"max_workers"`
	Timeout          time.Duration     `json:"timeout"`
	FollowRedirects  bool              `json:"follow_redirects"`
	MaintainSession  bool              `json:"maintain_session"`
	TestHostHeader   bool              `json:"test_host_header"`
	TestTokenEntropy bool              `json:"test_token_entropy"`
	TokenSamples     int               `json:"token_samples"`
	BruteForceThreads int              `json:"brute_force_threads"`
	RequestDelay     time.Duration     `json:"request_delay"`
	UserAgent        string            `json:"user_agent"`
	Headers          map[string]string `json:"headers"`
	Proxies          []string          `json:"proxies"`
	VerboseOutput    bool              `json:"verbose_output"`
}

// BusinessLogicReport represents the complete business logic testing report
type BusinessLogicReport struct {
	Metadata        ReportMetadata        `json:"metadata"`
	Executive       ExecutiveSummary      `json:"executive"`
	Workflows       []WorkflowAnalysis    `json:"workflows"`
	Vulnerabilities []Vulnerability       `json:"vulnerabilities"`
	PasswordReset   ResetFlowReport       `json:"password_reset"`
	AccountRecovery AccountRecoveryReport `json:"account_recovery"`
	RaceConditions  RaceConditionReport   `json:"race_conditions"`
	MFABypasses     MFAReport             `json:"mfa_bypasses"`
	BusinessImpact  BusinessImpact        `json:"business_impact"`
	Recommendations []Recommendation      `json:"recommendations"`
}

// ReportMetadata contains report generation metadata
type ReportMetadata struct {
	Target           string    `json:"target"`
	GeneratedAt      time.Time `json:"generated_at"`
	TestDuration     time.Duration `json:"test_duration"`
	TotalTests       int       `json:"total_tests"`
	VulnsFound       int       `json:"vulns_found"`
	CriticalCount    int       `json:"critical_count"`
	HighCount        int       `json:"high_count"`
	MediumCount      int       `json:"medium_count"`
	LowCount         int       `json:"low_count"`
	TestsPerformed   []string  `json:"tests_performed"`
}

// ExecutiveSummary provides high-level findings summary
type ExecutiveSummary struct {
	Overview        string   `json:"overview"`
	KeyFindings     []string `json:"key_findings"`
	BusinessRisk    string   `json:"business_risk"`
	ImmediateActions []string `json:"immediate_actions"`
	EstimatedImpact string   `json:"estimated_impact"`
}

// WorkflowAnalysis represents analysis of a business workflow
type WorkflowAnalysis struct {
	Workflow        *Workflow       `json:"workflow"`
	States          int             `json:"states"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Diagram         string          `json:"diagram"`
	Summary         string          `json:"summary"`
}

// ResetFlowReport contains password reset flow analysis
type ResetFlowReport struct {
	EndpointsFound  []string        `json:"endpoints_found"`
	TokenAnalysis   TokenAnalysis   `json:"token_analysis"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	SecurityScore   int             `json:"security_score"`
	Recommendations []string        `json:"recommendations"`
}

// AccountRecoveryReport contains account recovery analysis
type AccountRecoveryReport struct {
	MethodsFound    []string        `json:"methods_found"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	WeakMethods     []string        `json:"weak_methods"`
	SecurityScore   int             `json:"security_score"`
}

// RaceConditionReport contains race condition testing results
type RaceConditionReport struct {
	TestsPerformed  []RaceConditionTest `json:"tests_performed"`
	Vulnerabilities []Vulnerability     `json:"vulnerabilities"`
	EndpointsTested int                 `json:"endpoints_tested"`
	VulnEndpoints   int                 `json:"vuln_endpoints"`
}

// MFAReport contains MFA bypass testing results
type MFAReport struct {
	MethodsTested   []string        `json:"methods_tested"`
	BypassesFound   []Vulnerability `json:"bypasses_found"`
	SecurityScore   int             `json:"security_score"`
	Recommendations []string        `json:"recommendations"`
}

// BusinessImpact represents the business impact of findings
type BusinessImpact struct {
	FinancialImpact     string  `json:"financial_impact"`
	DataExposureRisk    string  `json:"data_exposure_risk"`
	UsersAffected       int     `json:"users_affected"`
	ReputationImpact    string  `json:"reputation_impact"`
	ComplianceViolation bool    `json:"compliance_violation"`
	EstimatedLoss       float64 `json:"estimated_loss"`
	RecoveryTime        string  `json:"recovery_time"`
}

// Recommendation represents a security recommendation
type Recommendation struct {
	Priority    string `json:"priority"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Timeline    string `json:"timeline"`
	Effort      string `json:"effort"`
	Impact      string `json:"impact"`
}

// Common vulnerability types for business logic
const (
	// Authentication & Authorization
	VulnPasswordResetHijack        = "PASSWORD_RESET_HIJACK"
	VulnHostHeaderInjection        = "HOST_HEADER_INJECTION"
	VulnMFABypass                  = "MFA_BYPASS"
	VulnAccountTakeover            = "ACCOUNT_TAKEOVER"
	VulnPrivilegeEscalation        = "PRIVILEGE_ESCALATION"
	VulnIDOR                       = "INSECURE_DIRECT_OBJECT_REFERENCE"
	
	// Business Logic Flaws
	VulnRaceCondition              = "RACE_CONDITION"
	VulnWorkflowBypass             = "WORKFLOW_BYPASS"
	VulnPriceManipulation          = "PRICE_MANIPULATION"
	VulnNegativeValue              = "NEGATIVE_VALUE_LOGIC_FLAW"
	VulnStateMachineManipulation   = "STATE_MACHINE_MANIPULATION"
	VulnTimeOfCheckTimeOfUse       = "TOCTOU_RACE_CONDITION"
	
	// Token & Session Issues
	VulnWeakToken                  = "WEAK_TOKEN_GENERATION"
	VulnPredictableToken           = "PREDICTABLE_TOKEN"
	VulnTokenReuse                 = "TOKEN_REUSE_VULNERABILITY"
	VulnSessionFixation            = "SESSION_FIXATION"
	
	// Recovery & Reset Issues
	VulnUserEnumeration            = "USER_ENUMERATION"
	VulnWeakSecurityQuestion       = "WEAK_SECURITY_QUESTION"
	VulnRecoveryFlowBypass         = "RECOVERY_FLOW_BYPASS"
	VulnBackupCodeWeakness         = "WEAK_BACKUP_CODES"
	VulnMissingRateLimit           = "MISSING_RATE_LIMIT"
	VulnPasswordChangeNoToken      = "PASSWORD_CHANGE_NO_TOKEN"
	
	// Payment & Financial
	VulnCurrencyConfusion          = "CURRENCY_CONFUSION"
	VulnCouponStacking             = "COUPON_STACKING"
	VulnPaymentBypass              = "PAYMENT_BYPASS"
	VulnRefundManipulation         = "REFUND_MANIPULATION"
)

// Severity levels
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// Test categories
const (
	CategoryAuthentication = "AUTHENTICATION"
	CategoryAuthorization  = "AUTHORIZATION"
	CategoryBusinessLogic  = "BUSINESS_LOGIC"
	CategoryPayment        = "PAYMENT"
	CategoryWorkflow       = "WORKFLOW"
	CategoryRaceCondition  = "RACE_CONDITION"
	CategoryTemporal       = "TEMPORAL"
)