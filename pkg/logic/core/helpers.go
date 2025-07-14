package core

import (
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/logic"
)

// StateTracker tracks workflow state transitions
type StateTracker struct {
	states     map[string]*StateTransition
	mutex      sync.RWMutex
	maxHistory int
}

// StateTransition represents a state transition
type StateTransition struct {
	FromState   string                 `json:"from_state"`
	ToState     string                 `json:"to_state"`
	Timestamp   time.Time              `json:"timestamp"`
	Parameters  map[string]interface{} `json:"parameters"`
	UserID      string                 `json:"user_id,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	Success     bool                   `json:"success"`
	ErrorReason string                 `json:"error_reason,omitempty"`
}

// NewStateTracker creates a new state tracker
func NewStateTracker() *StateTracker {
	return &StateTracker{
		states:     make(map[string]*StateTransition),
		maxHistory: 1000,
	}
}

// RecordTransition records a state transition
func (s *StateTracker) RecordTransition(transition *StateTransition) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	key := transition.FromState + "->" + transition.ToState
	s.states[key] = transition

	// Clean up old transitions if we exceed max history
	if len(s.states) > s.maxHistory {
		s.cleanupOldTransitions()
	}
}

// GetTransition gets a recorded transition
func (s *StateTracker) GetTransition(fromState, toState string) *StateTransition {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	key := fromState + "->" + toState
	return s.states[key]
}

// GetAllTransitions returns all recorded transitions
func (s *StateTracker) GetAllTransitions() []*StateTransition {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	transitions := make([]*StateTransition, 0, len(s.states))
	for _, transition := range s.states {
		transitions = append(transitions, transition)
	}

	return transitions
}

// cleanupOldTransitions removes oldest transitions
func (s *StateTracker) cleanupOldTransitions() {
	// Simple cleanup - remove random entries to get under limit
	// In production, this should remove oldest entries
	count := 0
	for key := range s.states {
		if count >= 100 {
			break
		}
		delete(s.states, key)
		count++
	}
}

// SequenceAnalyzer analyzes workflow sequences for patterns
type SequenceAnalyzer struct {
	sequences map[string]*SequencePattern
	mutex     sync.RWMutex
}

// SequencePattern represents a workflow sequence pattern
type SequencePattern struct {
	ID           string    `json:"id"`
	States       []string  `json:"states"`
	Frequency    int       `json:"frequency"`
	LastSeen     time.Time `json:"last_seen"`
	IsValid      bool      `json:"is_valid"`
	IsSuspicious bool      `json:"is_suspicious"`
}

// NewSequenceAnalyzer creates a new sequence analyzer
func NewSequenceAnalyzer() *SequenceAnalyzer {
	return &SequenceAnalyzer{
		sequences: make(map[string]*SequencePattern),
	}
}

// AnalyzeSequence analyzes a sequence of states
func (s *SequenceAnalyzer) AnalyzeSequence(states []string) *SequencePattern {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Generate sequence ID
	sequenceID := generateSequenceID(states)

	// Check if pattern exists
	if pattern, exists := s.sequences[sequenceID]; exists {
		pattern.Frequency++
		pattern.LastSeen = time.Now()
		return pattern
	}

	// Create new pattern
	pattern := &SequencePattern{
		ID:        sequenceID,
		States:    states,
		Frequency: 1,
		LastSeen:  time.Now(),
		IsValid:   s.validateSequence(states),
	}

	pattern.IsSuspicious = s.detectSuspiciousPattern(pattern)
	s.sequences[sequenceID] = pattern

	return pattern
}

// validateSequence validates if a sequence is legitimate
func (s *SequenceAnalyzer) validateSequence(states []string) bool {
	// Simple validation rules
	if len(states) == 0 {
		return false
	}

	// Check for circular references
	stateMap := make(map[string]bool)
	for _, state := range states {
		if stateMap[state] {
			return false // Circular reference detected
		}
		stateMap[state] = true
	}

	return true
}

// detectSuspiciousPattern detects suspicious sequence patterns
func (s *SequenceAnalyzer) detectSuspiciousPattern(pattern *SequencePattern) bool {
	// Check for suspicious patterns
	suspiciousPatterns := [][]string{
		{"login", "admin", "delete"},
		{"register", "payment", "cancel"},
		{"cart", "checkout", "back", "checkout"}, // Double checkout
	}

	for _, suspicious := range suspiciousPatterns {
		if s.containsSubsequence(pattern.States, suspicious) {
			return true
		}
	}

	return false
}

// containsSubsequence checks if states contain a subsequence
func (s *SequenceAnalyzer) containsSubsequence(states, subsequence []string) bool {
	if len(subsequence) > len(states) {
		return false
	}

	for i := 0; i <= len(states)-len(subsequence); i++ {
		match := true
		for j, target := range subsequence {
			if states[i+j] != target {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}

	return false
}

// generateSequenceID generates a unique ID for a sequence
func generateSequenceID(states []string) string {
	// Simple concatenation for demo purposes
	// In production, use a proper hash function
	result := ""
	for i, state := range states {
		if i > 0 {
			result += "->"
		}
		result += state
	}
	return result
}

// Pattern represents a business logic vulnerability pattern
type Pattern struct {
	Name        string                                              `json:"name"`
	Description string                                              `json:"description"`
	Category    string                                              `json:"category"`
	Severity    string                                              `json:"severity"`
	Test        func(workflow *logic.Workflow) *logic.Vulnerability `json:"-"`
}

// Common business logic vulnerability patterns
var BusinessLogicPatterns = []Pattern{
	{
		Name:        "Time-of-check Time-of-use (TOCTOU)",
		Description: "Race condition between validation and use",
		Category:    "Race Condition",
		Severity:    "HIGH",
		Test:        testTOCTOU,
	},
	{
		Name:        "Integer Overflow in Calculations",
		Description: "Integer overflow leading to unexpected behavior",
		Category:    "Value Manipulation",
		Severity:    "MEDIUM",
		Test:        testIntegerOverflow,
	},
	{
		Name:        "Race Condition in Resource Allocation",
		Description: "Concurrent access to limited resources",
		Category:    "Race Condition",
		Severity:    "HIGH",
		Test:        testResourceRace,
	},
	{
		Name:        "State Machine Manipulation",
		Description: "Unauthorized state transitions",
		Category:    "State Management",
		Severity:    "HIGH",
		Test:        testStateMachine,
	},
	{
		Name:        "Inconsistent State Validation",
		Description: "Different validation rules across states",
		Category:    "Validation",
		Severity:    "MEDIUM",
		Test:        testInconsistentValidation,
	},
	{
		Name:        "Privilege Escalation Through Workflow",
		Description: "Gaining higher privileges through workflow manipulation",
		Category:    "Authorization",
		Severity:    "CRITICAL",
		Test:        testWorkflowPrivilegeEscalation,
	},
	{
		Name:        "Business Logic Bypass",
		Description: "Bypassing business rules and constraints",
		Category:    "Business Logic",
		Severity:    "HIGH",
		Test:        testBusinessLogicBypass,
	},
}

// Pattern test implementations

// testTOCTOU tests for Time-of-check Time-of-use vulnerabilities
func testTOCTOU(workflow *logic.Workflow) *logic.Vulnerability {
	// Look for patterns where a check is performed and then an action is taken
	// This is a simplified implementation

	for stateID, state := range workflow.States {
		// Look for states that might have TOCTOU issues
		stateName := state.Name
		if containsAny(stateName, []string{"balance", "check", "verify", "validate"}) {
			// Look for subsequent states that might use the checked value
			if transitions, exists := workflow.Transitions[stateID]; exists {
				for _, transition := range transitions {
					targetID := generateStateID(transition)
					if targetState, exists := workflow.States[targetID]; exists {
						if containsAny(targetState.Name, []string{"withdraw", "deduct", "transfer", "purchase"}) {
							return &logic.Vulnerability{
								ID:          "toctou-" + stateID,
								Type:        logic.VulnTimeOfCheckTimeOfUse,
								Severity:    logic.SeverityHigh,
								Title:       "Potential TOCTOU Race Condition",
								Description: "Time gap between check and use may allow race conditions",
								Details:     "Check in " + state.Name + " followed by action in " + targetState.Name,
								Impact:      "Race conditions may allow bypassing security checks",
								Remediation: "Implement atomic check-and-use operations",
								Timestamp:   time.Now(),
							}
						}
					}
				}
			}
		}
	}

	return nil
}

// testIntegerOverflow tests for integer overflow vulnerabilities
func testIntegerOverflow(workflow *logic.Workflow) *logic.Vulnerability {
	// Look for numeric operations that might overflow
	for _, state := range workflow.States {
		// Check for parameters that might be vulnerable to overflow
		for paramName := range state.Parameters {
			if containsAny(paramName, []string{"amount", "quantity", "count", "price", "total"}) {
				return &logic.Vulnerability{
					ID:          "overflow-" + state.ID,
					Type:        "INTEGER_OVERFLOW",
					Severity:    logic.SeverityMedium,
					Title:       "Potential Integer Overflow",
					Description: "Numeric parameter may be vulnerable to integer overflow",
					Details:     "Parameter '" + paramName + "' in state " + state.Name,
					Impact:      "Integer overflow may lead to unexpected calculations",
					Remediation: "Implement proper bounds checking for numeric inputs",
					Timestamp:   time.Now(),
				}
			}
		}
	}

	return nil
}

// testResourceRace tests for race conditions in resource allocation
func testResourceRace(workflow *logic.Workflow) *logic.Vulnerability {
	// Look for states that allocate or modify shared resources
	for _, state := range workflow.States {
		if containsAny(state.Name, []string{"allocate", "reserve", "book", "claim", "acquire"}) {
			return &logic.Vulnerability{
				ID:          "race-" + state.ID,
				Type:        logic.VulnRaceCondition,
				Severity:    logic.SeverityHigh,
				Title:       "Resource Allocation Race Condition",
				Description: "Concurrent access to shared resources may cause race conditions",
				Details:     "Resource allocation in state: " + state.Name,
				Impact:      "Race conditions may lead to double-booking or resource conflicts",
				Remediation: "Implement proper locking mechanisms for resource allocation",
				Timestamp:   time.Now(),
			}
		}
	}

	return nil
}

// testStateMachine tests for state machine manipulation vulnerabilities
func testStateMachine(workflow *logic.Workflow) *logic.Vulnerability {
	// Look for states that can be accessed out of order
	for stateID, transitions := range workflow.Transitions {
		state := workflow.States[stateID]

		// Check for states with many incoming transitions (potential for manipulation)
		incomingCount := 0
		for _, otherTransitions := range workflow.Transitions {
			for _, transition := range otherTransitions {
				if generateStateID(transition) == stateID {
					incomingCount++
				}
			}
		}

		if incomingCount > 3 && len(transitions) > 0 {
			return &logic.Vulnerability{
				ID:          "statemachine-" + stateID,
				Type:        logic.VulnStateMachineManipulation,
				Severity:    logic.SeverityHigh,
				Title:       "State Machine Manipulation",
				Description: "State can be reached from multiple paths, potentially bypassing controls",
				Details:     "State '" + state.Name + "' has " + string(rune(incomingCount)) + " incoming transitions",
				Impact:      "Attackers may manipulate state transitions to bypass business logic",
				Remediation: "Implement strict state transition validation",
				Timestamp:   time.Now(),
			}
		}
	}

	return nil
}

// testInconsistentValidation tests for inconsistent validation across states
func testInconsistentValidation(workflow *logic.Workflow) *logic.Vulnerability {
	// Look for similar parameters with potentially different validation rules
	parameterStates := make(map[string][]*logic.WorkflowState)

	for _, state := range workflow.States {
		for paramName := range state.Parameters {
			parameterStates[paramName] = append(parameterStates[paramName], state)
		}
	}

	// Check for parameters that appear in multiple states
	for paramName, states := range parameterStates {
		if len(states) > 1 {
			return &logic.Vulnerability{
				ID:          "validation-" + paramName,
				Type:        "INCONSISTENT_VALIDATION",
				Severity:    logic.SeverityMedium,
				Title:       "Inconsistent Parameter Validation",
				Description: "Parameter appears in multiple states with potentially different validation",
				Details:     "Parameter '" + paramName + "' found in " + string(rune(len(states))) + " states",
				Impact:      "Inconsistent validation may allow bypassing security controls",
				Remediation: "Standardize validation rules across all states",
				Timestamp:   time.Now(),
			}
		}
	}

	return nil
}

// testWorkflowPrivilegeEscalation tests for privilege escalation through workflows
func testWorkflowPrivilegeEscalation(workflow *logic.Workflow) *logic.Vulnerability {
	// Look for privilege-related state transitions
	for stateID, state := range workflow.States {
		if containsAny(state.Name, []string{"admin", "privilege", "elevate", "sudo", "root"}) {
			// Check what states lead to this privileged state
			for otherStateID, transitions := range workflow.Transitions {
				for _, transition := range transitions {
					if generateStateID(transition) == stateID {
						otherState := workflow.States[otherStateID]
						if !containsAny(otherState.Name, []string{"admin", "auth", "login"}) {
							return &logic.Vulnerability{
								ID:          "privesc-" + stateID,
								Type:        logic.VulnPrivilegeEscalation,
								Severity:    logic.SeverityCritical,
								Title:       "Privilege Escalation Through Workflow",
								Description: "Non-privileged state can transition to privileged state",
								Details:     "Transition from '" + otherState.Name + "' to '" + state.Name + "'",
								Impact:      "Attackers may gain unauthorized administrative privileges",
								Remediation: "Implement proper authorization checks for privilege transitions",
								Timestamp:   time.Now(),
							}
						}
					}
				}
			}
		}
	}

	return nil
}

// testBusinessLogicBypass tests for business logic bypass vulnerabilities
func testBusinessLogicBypass(workflow *logic.Workflow) *logic.Vulnerability {
	// Look for states that might bypass business logic
	for stateID, state := range workflow.States {
		// Look for payment or checkout bypasses
		if containsAny(state.Name, []string{"payment", "checkout", "purchase", "buy"}) {
			// Check if there are ways to skip this state
			canBeSkipped := false

			// Look for alternative paths that bypass this state
			for otherStateID, transitions := range workflow.Transitions {
				if otherStateID != stateID {
					for _, transition := range transitions {
						targetID := generateStateID(transition)
						if targetState, exists := workflow.States[targetID]; exists {
							if containsAny(targetState.Name, []string{"complete", "success", "confirm", "done"}) {
								canBeSkipped = true
								break
							}
						}
					}
				}
				if canBeSkipped {
					break
				}
			}

			if canBeSkipped {
				return &logic.Vulnerability{
					ID:          "bypass-" + stateID,
					Type:        "BUSINESS_LOGIC_BYPASS",
					Severity:    logic.SeverityHigh,
					Title:       "Business Logic Bypass",
					Description: "Critical business logic state can be bypassed",
					Details:     "State '" + state.Name + "' can be skipped in workflow",
					Impact:      "Attackers may bypass payment or other critical business logic",
					Remediation: "Ensure all critical states are mandatory in the workflow",
					Timestamp:   time.Now(),
				}
			}
		}
	}

	return nil
}

// Helper function to check if a string contains any of the given substrings
func containsAny(str string, substrings []string) bool {
	lowerStr := strings.ToLower(str)
	for _, substring := range substrings {
		if strings.Contains(lowerStr, strings.ToLower(substring)) {
			return true
		}
	}
	return false
}

// LogicTest represents a business logic test
type LogicTest struct {
	Name string
	Test func(target string) *logic.Vulnerability
}

// Common high-value logic tests for bug bounties
var HighValueLogicTests = []logic.TestCase{
	{
		Name:        "Password Reset Token Hijack",
		Description: "Account takeover via host header injection in password reset",
		Category:    logic.CategoryAuthentication,
		Severity:    logic.SeverityCritical,
		Impact:      "Complete account takeover",
		Method:      "POST",
		Expected:    "Host header injection leads to token hijack",
		Remediation: "Validate Host header and use absolute URLs",
	},
	{
		Name:        "Race Condition in Payment Processing",
		Description: "Purchase items for free or reduced price via race condition",
		Category:    logic.CategoryPayment,
		Severity:    logic.SeverityCritical,
		Impact:      "Financial loss due to free purchases",
		Method:      "POST",
		Expected:    "Concurrent requests bypass payment validation",
		Remediation: "Implement proper synchronization for payment processing",
	},
	{
		Name:        "MFA Bypass via Recovery Flow",
		Description: "Complete MFA bypass leading to account takeover",
		Category:    logic.CategoryAuthentication,
		Severity:    logic.SeverityCritical,
		Impact:      "Account takeover bypassing MFA protection",
		Method:      "POST",
		Expected:    "Recovery flow bypasses MFA requirement",
		Remediation: "Ensure MFA is required for all sensitive operations",
	},
	{
		Name:        "IDOR in Password Reset",
		Description: "Reset any user's password via insecure direct object reference",
		Category:    logic.CategoryAuthorization,
		Severity:    logic.SeverityCritical,
		Impact:      "Mass account takeover",
		Method:      "POST",
		Expected:    "Password reset tokens not bound to specific users",
		Remediation: "Bind reset tokens to specific user accounts",
	},
	{
		Name:        "Shopping Cart Price Manipulation",
		Description: "Purchase items at arbitrary prices via parameter manipulation",
		Category:    logic.CategoryPayment,
		Severity:    logic.SeverityHigh,
		Impact:      "Financial loss due to price manipulation",
		Method:      "POST",
		Expected:    "Price parameters can be manipulated client-side",
		Remediation: "Validate all pricing server-side",
	},
	{
		Name:        "Workflow State Bypass",
		Description: "Skip payment or verification steps in multi-step processes",
		Category:    logic.CategoryWorkflow,
		Severity:    logic.SeverityHigh,
		Impact:      "Bypass of critical business logic controls",
		Method:      "GET/POST",
		Expected:    "Direct access to final states without completing prerequisites",
		Remediation: "Implement proper state validation and flow control",
	},
	{
		Name:        "Negative Quantity Logic Flaw",
		Description: "Add negative quantities to cart for credit/refund",
		Category:    logic.CategoryBusinessLogic,
		Severity:    logic.SeverityHigh,
		Impact:      "Financial loss due to negative pricing",
		Method:      "POST",
		Expected:    "Negative quantities result in negative total prices",
		Remediation: "Validate quantity inputs to ensure positive values",
	},
	{
		Name:        "Coupon Stacking Vulnerability",
		Description: "Apply multiple coupons or discounts beyond intended limits",
		Category:    logic.CategoryPayment,
		Severity:    logic.SeverityMedium,
		Impact:      "Financial loss due to excessive discounts",
		Method:      "POST",
		Expected:    "Multiple discount codes can be applied simultaneously",
		Remediation: "Implement proper coupon validation and limits",
	},
	{
		Name:        "Time-based Logic Manipulation",
		Description: "Manipulate timestamps to bypass time-based restrictions",
		Category:    logic.CategoryTemporal,
		Severity:    logic.SeverityMedium,
		Impact:      "Bypass of time-based business rules",
		Method:      "POST",
		Expected:    "Client-provided timestamps are trusted without validation",
		Remediation: "Use server-side timestamps for all time-based logic",
	},
	{
		Name:        "Session Fixation in Workflow",
		Description: "Fix user session during privilege escalation workflows",
		Category:    logic.CategoryAuthentication,
		Severity:    logic.SeverityHigh,
		Impact:      "Account takeover via session fixation",
		Method:      "GET/POST",
		Expected:    "Session ID remains same across privilege changes",
		Remediation: "Regenerate session IDs during privilege escalation",
	},
}
