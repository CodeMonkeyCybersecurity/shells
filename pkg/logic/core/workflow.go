package core

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/logic"
	"github.com/google/uuid"
)

// WorkflowAnalyzer analyzes multi-step business workflows for vulnerabilities
type WorkflowAnalyzer struct {
	httpClient   *http.Client
	stateTracker *StateTracker
	sequencer    *SequenceAnalyzer
	config       *logic.TestConfig
	workflows    map[string]*logic.Workflow
	mutex        sync.RWMutex
}

// NewWorkflowAnalyzer creates a new workflow analyzer
func NewWorkflowAnalyzer(config *logic.TestConfig) *WorkflowAnalyzer {
	if config == nil {
		config = &logic.TestConfig{
			MaxWorkers:      10,
			Timeout:         60 * time.Second,
			FollowRedirects: true,
			MaintainSession: true,
		}
	}

	return &WorkflowAnalyzer{
		httpClient:   &http.Client{Timeout: config.Timeout},
		stateTracker: NewStateTracker(),
		sequencer:    NewSequenceAnalyzer(),
		config:       config,
		workflows:    make(map[string]*logic.Workflow),
	}
}

// BusinessLogicTests represents all possible business logic vulnerabilities
type BusinessLogicTests struct {
	// State manipulation
	SkipSteps     bool `json:"skip_steps"`
	ReorderSteps  bool `json:"reorder_steps"`
	RepeatSteps   bool `json:"repeat_steps"`
	ParallelSteps bool `json:"parallel_steps"`

	// Value manipulation
	NegativeValues  bool `json:"negative_values"`
	ExtremeValues   bool `json:"extreme_values"`
	TypeConfusion   bool `json:"type_confusion"`
	IntegerOverflow bool `json:"integer_overflow"`

	// Time manipulation
	ExpiredActions    bool `json:"expired_actions"`
	FutureActions     bool `json:"future_actions"`
	TimezoneConfusion bool `json:"timezone_confusion"`

	// Authorization
	CrossUserActions      bool `json:"cross_user_actions"`
	PrivilegeEscalation   bool `json:"privilege_escalation"`
	DirectObjectReference bool `json:"direct_object_reference"`

	// Flow manipulation
	StateRevert         bool `json:"state_revert"`
	ConditionBypass     bool `json:"condition_bypass"`
	ValidationBypass    bool `json:"validation_bypass"`
	WorkflowTermination bool `json:"workflow_termination"`
}

// WorkflowAnalysis represents the complete workflow analysis
type WorkflowAnalysis struct {
	Workflow        *logic.Workflow        `json:"workflow"`
	States          []logic.WorkflowState  `json:"states"`
	Vulnerabilities []logic.Vulnerability  `json:"vulnerabilities"`
	BusinessLogic   BusinessLogicTests     `json:"business_logic"`
	Diagram         string                 `json:"diagram"`
	Summary         string                 `json:"summary"`
	SecurityScore   int                    `json:"security_score"`
	TestDuration    time.Duration          `json:"test_duration"`
	Recommendations []logic.Recommendation `json:"recommendations"`
}

// AnalyzeWorkflow performs comprehensive workflow analysis
func (w *WorkflowAnalyzer) AnalyzeWorkflow(startURL string) *WorkflowAnalysis {
	startTime := time.Now()

	// 1. Map the complete workflow
	workflow := w.mapWorkflow(startURL)

	// 2. Identify all states and transitions
	states := w.identifyStates(workflow)

	analysis := &WorkflowAnalysis{
		Workflow:        workflow,
		States:          states,
		Vulnerabilities: []logic.Vulnerability{},
		BusinessLogic:   BusinessLogicTests{},
		TestDuration:    time.Since(startTime),
	}

	// 3. Test state manipulation vulnerabilities
	stateVulns := w.testStateManipulation(workflow)
	analysis.Vulnerabilities = append(analysis.Vulnerabilities, stateVulns...)

	// 4. Test sequence breaking vulnerabilities
	sequenceVulns := w.testSequenceBreaking(workflow)
	analysis.Vulnerabilities = append(analysis.Vulnerabilities, sequenceVulns...)

	// 5. Test business constraint violations
	constraintVulns := w.testBusinessConstraints(workflow)
	analysis.Vulnerabilities = append(analysis.Vulnerabilities, constraintVulns...)

	// 6. Test value manipulation
	valueVulns := w.testValueManipulation(workflow)
	analysis.Vulnerabilities = append(analysis.Vulnerabilities, valueVulns...)

	// 7. Test authorization flaws
	authVulns := w.testAuthorizationFlaws(workflow)
	analysis.Vulnerabilities = append(analysis.Vulnerabilities, authVulns...)

	// 8. Test time-based vulnerabilities
	timeVulns := w.testTimeBasedVulnerabilities(workflow)
	analysis.Vulnerabilities = append(analysis.Vulnerabilities, timeVulns...)

	// 9. Generate analysis artifacts
	analysis.Diagram = w.generateWorkflowDiagram(workflow)
	analysis.Summary = w.generateWorkflowSummary(workflow, analysis.Vulnerabilities)
	analysis.SecurityScore = w.calculateSecurityScore(analysis.Vulnerabilities)
	analysis.Recommendations = w.generateRecommendations(analysis.Vulnerabilities)

	return analysis
}

// mapWorkflow discovers and maps the complete workflow
func (w *WorkflowAnalyzer) mapWorkflow(startURL string) *logic.Workflow {
	workflow := &logic.Workflow{
		ID:          uuid.New().String(),
		Name:        fmt.Sprintf("Workflow_%s", extractDomainFromURL(startURL)),
		StartURL:    startURL,
		States:      make(map[string]*logic.WorkflowState),
		Transitions: make(map[string][]string),
		Session:     w.httpClient,
		MaxDepth:    10,
	}

	// Start workflow discovery
	visited := make(map[string]bool)
	queue := []string{startURL}

	for len(queue) > 0 && workflow.Depth < workflow.MaxDepth {
		currentURL := queue[0]
		queue = queue[1:]

		if visited[currentURL] {
			continue
		}
		visited[currentURL] = true

		// Create state for current URL
		state := w.createStateFromURL(currentURL, workflow)
		if state == nil {
			continue
		}

		workflow.States[state.ID] = state

		// Find transitions from this state
		transitions := w.findTransitions(state)
		workflow.Transitions[state.ID] = transitions

		// Add new URLs to queue
		for _, transition := range transitions {
			if !visited[transition] {
				queue = append(queue, transition)
			}
		}

		workflow.Depth++
	}

	return workflow
}

// createStateFromURL creates a workflow state from a URL
func (w *WorkflowAnalyzer) createStateFromURL(urlStr string, workflow *logic.Workflow) *logic.WorkflowState {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil
	}

	resp, err := workflow.Session.Do(req)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	body, _ := io.ReadAll(resp.Body)

	state := &logic.WorkflowState{
		ID:         generateStateID(urlStr),
		Name:       extractPageName(urlStr),
		URL:        urlStr,
		Method:     "GET",
		StatusCode: resp.StatusCode,
		Response:   string(body),
		Timestamp:  time.Now(),
	}

	// Extract parameters and headers
	state.Parameters = w.extractParameters(string(body))
	state.Headers = make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			state.Headers[key] = values[0]
		}
	}

	// Extract cookies
	state.Cookies = resp.Cookies()

	return state
}

// findTransitions finds possible transitions from a state
func (w *WorkflowAnalyzer) findTransitions(state *logic.WorkflowState) []string {
	transitions := []string{}

	// Extract links from HTML
	links := w.extractLinks(state.Response)
	for _, link := range links {
		if isValidTransition(link, state.URL) {
			transitions = append(transitions, link)
		}
	}

	// Extract form actions
	forms := w.extractForms(state.Response)
	for _, form := range forms {
		if isValidTransition(form.Action, state.URL) {
			transitions = append(transitions, form.Action)
		}
	}

	// Extract AJAX endpoints
	ajaxEndpoints := w.extractAjaxEndpoints(state.Response)
	for _, endpoint := range ajaxEndpoints {
		if isValidTransition(endpoint, state.URL) {
			transitions = append(transitions, endpoint)
		}
	}

	return transitions
}

// identifyStates extracts all states from workflow
func (w *WorkflowAnalyzer) identifyStates(workflow *logic.Workflow) []logic.WorkflowState {
	states := []logic.WorkflowState{}
	for _, state := range workflow.States {
		states = append(states, *state)
	}
	return states
}

// testStateManipulation tests for state manipulation vulnerabilities
func (w *WorkflowAnalyzer) testStateManipulation(workflow *logic.Workflow) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Test step skipping
	if vuln := w.testStepSkipping(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test step reordering
	if vuln := w.testStepReordering(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test step repetition
	if vuln := w.testStepRepetition(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test parallel execution
	if vuln := w.testParallelExecution(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	return vulnerabilities
}

// testStepSkipping tests if workflow steps can be skipped
func (w *WorkflowAnalyzer) testStepSkipping(workflow *logic.Workflow) *logic.Vulnerability {
	// Find sequential states
	sequences := w.findSequentialStates(workflow)

	for _, sequence := range sequences {
		if len(sequence) < 3 {
			continue
		}

		// Try to skip middle steps
		firstState := sequence[0]
		lastState := sequence[len(sequence)-1]

		// Attempt to access final state directly
		if w.canAccessStateDirectly(firstState, lastState, workflow) {
			return &logic.Vulnerability{
				ID:          uuid.New().String(),
				Type:        logic.VulnWorkflowBypass,
				Severity:    logic.SeverityHigh,
				Title:       "Workflow Step Skipping",
				Description: "Required workflow steps can be bypassed",
				Details:     fmt.Sprintf("Can skip from %s directly to %s", firstState.Name, lastState.Name),
				Impact:      "Attackers can bypass business logic controls and validations",
				Evidence: map[string]interface{}{
					"skipped_from":   firstState.URL,
					"skipped_to":     lastState.URL,
					"bypassed_steps": len(sequence) - 2,
				},
				CWE:         "CWE-841",
				CVSS:        7.5,
				Remediation: "Implement proper state validation and enforce sequential workflow execution",
				Timestamp:   time.Now(),
			}
		}
	}

	return nil
}

// testStepReordering tests if workflow steps can be executed out of order
func (w *WorkflowAnalyzer) testStepReordering(workflow *logic.Workflow) *logic.Vulnerability {
	sequences := w.findSequentialStates(workflow)

	for _, sequence := range sequences {
		if len(sequence) < 3 {
			continue
		}

		// Try to execute steps in reverse order
		reversed := make([]*logic.WorkflowState, len(sequence))
		for i, state := range sequence {
			reversed[len(sequence)-1-i] = state
		}

		if w.canExecuteSequence(reversed, workflow) {
			return &logic.Vulnerability{
				ID:          uuid.New().String(),
				Type:        logic.VulnStateMachineManipulation,
				Severity:    logic.SeverityMedium,
				Title:       "Workflow Step Reordering",
				Description: "Workflow steps can be executed in arbitrary order",
				Details:     "Steps can be executed in reverse order successfully",
				Impact:      "Business logic constraints can be violated",
				CWE:         "CWE-840",
				CVSS:        5.3,
				Remediation: "Implement strict state transition validation",
				Timestamp:   time.Now(),
			}
		}
	}

	return nil
}

// testStepRepetition tests if workflow steps can be repeated
func (w *WorkflowAnalyzer) testStepRepetition(workflow *logic.Workflow) *logic.Vulnerability {
	for _, state := range workflow.States {
		// Try to repeat the same step multiple times
		if w.canRepeatState(state, workflow, 5) {
			return &logic.Vulnerability{
				ID:          uuid.New().String(),
				Type:        "WORKFLOW_STEP_REPETITION",
				Severity:    logic.SeverityMedium,
				Title:       "Workflow Step Repetition",
				Description: "Workflow steps can be repeated multiple times",
				Details:     fmt.Sprintf("State %s can be repeated without limits", state.Name),
				Impact:      "May lead to resource exhaustion or business logic violations",
				CWE:         "CWE-770",
				CVSS:        5.3,
				Remediation: "Implement state transition tracking and prevent unauthorized repetition",
				Timestamp:   time.Now(),
			}
		}
	}

	return nil
}

// testParallelExecution tests if steps can be executed in parallel
func (w *WorkflowAnalyzer) testParallelExecution(workflow *logic.Workflow) *logic.Vulnerability {
	// Find states that should be mutually exclusive
	exclusiveStates := w.findMutuallyExclusiveStates(workflow)

	for _, pair := range exclusiveStates {
		if w.canExecuteInParallel(pair[0], pair[1], workflow) {
			return &logic.Vulnerability{
				ID:          uuid.New().String(),
				Type:        logic.VulnRaceCondition,
				Severity:    logic.SeverityHigh,
				Title:       "Parallel Workflow Execution",
				Description: "Mutually exclusive workflow states can be executed in parallel",
				Details:     fmt.Sprintf("States %s and %s can be executed simultaneously", pair[0].Name, pair[1].Name),
				Impact:      "Race conditions may lead to inconsistent application state",
				CWE:         "CWE-362",
				CVSS:        7.5,
				Remediation: "Implement proper synchronization and mutual exclusion controls",
				Timestamp:   time.Now(),
			}
		}
	}

	return nil
}

// testSequenceBreaking tests for sequence manipulation vulnerabilities
func (w *WorkflowAnalyzer) testSequenceBreaking(workflow *logic.Workflow) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Test forced state transitions
	if vuln := w.testForcedStateTransitions(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test invalid state access
	if vuln := w.testInvalidStateAccess(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	return vulnerabilities
}

// testBusinessConstraints tests for business constraint violations
func (w *WorkflowAnalyzer) testBusinessConstraints(workflow *logic.Workflow) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Test constraint bypass
	if vuln := w.testConstraintBypass(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test validation bypass
	if vuln := w.testValidationBypass(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	return vulnerabilities
}

// testValueManipulation tests for value manipulation vulnerabilities
func (w *WorkflowAnalyzer) testValueManipulation(workflow *logic.Workflow) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Test negative values
	if vuln := w.testNegativeValues(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test extreme values
	if vuln := w.testExtremeValues(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test integer overflow
	if vuln := w.testIntegerOverflow(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test type confusion
	if vuln := w.testTypeConfusion(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	return vulnerabilities
}

// testAuthorizationFlaws tests for authorization vulnerabilities
func (w *WorkflowAnalyzer) testAuthorizationFlaws(workflow *logic.Workflow) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Test privilege escalation
	if vuln := w.testPrivilegeEscalation(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test IDOR
	if vuln := w.testInsecureDirectObjectReference(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test cross-user actions
	if vuln := w.testCrossUserActions(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	return vulnerabilities
}

// testTimeBasedVulnerabilities tests for time-based vulnerabilities
func (w *WorkflowAnalyzer) testTimeBasedVulnerabilities(workflow *logic.Workflow) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	// Test expired actions
	if vuln := w.testExpiredActions(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test future actions
	if vuln := w.testFutureActions(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test timezone confusion
	if vuln := w.testTimezoneConfusion(workflow); vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	return vulnerabilities
}

// Helper methods for workflow analysis

func (w *WorkflowAnalyzer) findSequentialStates(workflow *logic.Workflow) [][]*logic.WorkflowState {
	sequences := [][]*logic.WorkflowState{}

	// Simple implementation - find linear paths
	for stateID, transitions := range workflow.Transitions {
		if len(transitions) == 1 {
			sequence := []*logic.WorkflowState{workflow.States[stateID]}
			current := transitions[0]

			for len(workflow.Transitions[generateStateID(current)]) == 1 && len(sequence) < 5 {
				if state, exists := workflow.States[generateStateID(current)]; exists {
					sequence = append(sequence, state)
					current = workflow.Transitions[generateStateID(current)][0]
				} else {
					break
				}
			}

			if len(sequence) >= 3 {
				sequences = append(sequences, sequence)
			}
		}
	}

	return sequences
}

func (w *WorkflowAnalyzer) canAccessStateDirectly(from, to *logic.WorkflowState, workflow *logic.Workflow) bool {
	// Try to access the target state directly from the source state
	req, err := http.NewRequest("GET", to.URL, nil)
	if err != nil {
		return false
	}

	// Copy session cookies from the workflow
	for _, cookie := range from.Cookies {
		req.AddCookie(cookie)
	}

	resp, err := workflow.Session.Do(req)
	if err != nil {
		return false
	}
	defer httpclient.CloseBody(resp)

	// If we get a successful response, the state can be accessed directly
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func (w *WorkflowAnalyzer) canExecuteSequence(sequence []*logic.WorkflowState, workflow *logic.Workflow) bool {
	// Try to execute the sequence in the given order
	for i, state := range sequence {
		req, err := http.NewRequest(state.Method, state.URL, nil)
		if err != nil {
			return false
		}

		// Apply parameters if it's a POST request
		if state.Method == "POST" && len(state.Parameters) > 0 {
			values := url.Values{}
			for key, value := range state.Parameters {
				values.Set(key, value)
			}
			req, _ = http.NewRequest("POST", state.URL, strings.NewReader(values.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}

		resp, err := workflow.Session.Do(req)
		if err != nil {
			return false
		}
		httpclient.CloseBody(resp)

		// If any step fails, sequence execution failed
		if resp.StatusCode >= 400 {
			return false
		}

		// For the last step, don't continue
		if i == len(sequence)-1 {
			break
		}
	}

	return true
}

func (w *WorkflowAnalyzer) canRepeatState(state *logic.WorkflowState, workflow *logic.Workflow, times int) bool {
	for i := 0; i < times; i++ {
		req, err := http.NewRequest(state.Method, state.URL, nil)
		if err != nil {
			return false
		}

		resp, err := workflow.Session.Do(req)
		if err != nil {
			return false
		}
		httpclient.CloseBody(resp)

		// If repetition is blocked, return false
		if resp.StatusCode >= 400 {
			return false
		}
	}

	return true
}

func (w *WorkflowAnalyzer) findMutuallyExclusiveStates(workflow *logic.Workflow) [][]*logic.WorkflowState {
	pairs := [][]*logic.WorkflowState{}

	// Simple heuristic: states with conflicting actions
	conflictPatterns := [][]string{
		{"buy", "cancel"},
		{"approve", "reject"},
		{"accept", "decline"},
		{"enable", "disable"},
		{"create", "delete"},
	}

	states := []*logic.WorkflowState{}
	for _, state := range workflow.States {
		states = append(states, state)
	}

	for _, pattern := range conflictPatterns {
		var state1, state2 *logic.WorkflowState

		for _, state := range states {
			stateName := strings.ToLower(state.Name)
			if strings.Contains(stateName, pattern[0]) {
				state1 = state
			} else if strings.Contains(stateName, pattern[1]) {
				state2 = state
			}
		}

		if state1 != nil && state2 != nil {
			pairs = append(pairs, []*logic.WorkflowState{state1, state2})
		}
	}

	return pairs
}

func (w *WorkflowAnalyzer) canExecuteInParallel(state1, state2 *logic.WorkflowState, workflow *logic.Workflow) bool {
	// Execute both states simultaneously
	results := make(chan bool, 2)

	// Execute state1
	go func() {
		req, err := http.NewRequest(state1.Method, state1.URL, nil)
		if err != nil {
			results <- false
			return
		}

		resp, err := workflow.Session.Do(req)
		if err != nil {
			results <- false
			return
		}
		defer httpclient.CloseBody(resp)

		results <- resp.StatusCode < 400
	}()

	// Execute state2
	go func() {
		req, err := http.NewRequest(state2.Method, state2.URL, nil)
		if err != nil {
			results <- false
			return
		}

		resp, err := workflow.Session.Do(req)
		if err != nil {
			results <- false
			return
		}
		defer httpclient.CloseBody(resp)

		results <- resp.StatusCode < 400
	}()

	// Check if both succeeded
	success1 := <-results
	success2 := <-results

	return success1 && success2
}

// Placeholder implementations for other test methods
func (w *WorkflowAnalyzer) testForcedStateTransitions(workflow *logic.Workflow) *logic.Vulnerability {
	// Test if state transitions can be forced through parameter manipulation
	return nil
}

func (w *WorkflowAnalyzer) testInvalidStateAccess(workflow *logic.Workflow) *logic.Vulnerability {
	// Test access to states that should not be accessible
	return nil
}

func (w *WorkflowAnalyzer) testConstraintBypass(workflow *logic.Workflow) *logic.Vulnerability {
	// Test if business constraints can be bypassed
	return nil
}

func (w *WorkflowAnalyzer) testValidationBypass(workflow *logic.Workflow) *logic.Vulnerability {
	// Test if input validation can be bypassed
	return nil
}

func (w *WorkflowAnalyzer) testNegativeValues(workflow *logic.Workflow) *logic.Vulnerability {
	// Test negative value handling
	return nil
}

func (w *WorkflowAnalyzer) testExtremeValues(workflow *logic.Workflow) *logic.Vulnerability {
	// Test extreme value handling
	return nil
}

func (w *WorkflowAnalyzer) testIntegerOverflow(workflow *logic.Workflow) *logic.Vulnerability {
	// Test integer overflow conditions
	return nil
}

func (w *WorkflowAnalyzer) testTypeConfusion(workflow *logic.Workflow) *logic.Vulnerability {
	// Test type confusion vulnerabilities
	return nil
}

func (w *WorkflowAnalyzer) testPrivilegeEscalation(workflow *logic.Workflow) *logic.Vulnerability {
	// Test privilege escalation through workflow manipulation
	return nil
}

func (w *WorkflowAnalyzer) testInsecureDirectObjectReference(workflow *logic.Workflow) *logic.Vulnerability {
	// Test IDOR vulnerabilities in workflow
	return nil
}

func (w *WorkflowAnalyzer) testCrossUserActions(workflow *logic.Workflow) *logic.Vulnerability {
	// Test if actions can be performed on behalf of other users
	return nil
}

func (w *WorkflowAnalyzer) testExpiredActions(workflow *logic.Workflow) *logic.Vulnerability {
	// Test if expired actions can still be performed
	return nil
}

func (w *WorkflowAnalyzer) testFutureActions(workflow *logic.Workflow) *logic.Vulnerability {
	// Test if future-dated actions can be performed
	return nil
}

func (w *WorkflowAnalyzer) testTimezoneConfusion(workflow *logic.Workflow) *logic.Vulnerability {
	// Test timezone-related vulnerabilities
	return nil
}

// Utility functions

func (w *WorkflowAnalyzer) extractParameters(html string) map[string]string {
	params := make(map[string]string)

	// Extract form inputs
	inputRegex := regexp.MustCompile(`<input[^>]*name\s*=\s*["']([^"']+)["'][^>]*>`)
	matches := inputRegex.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params[match[1]] = ""
		}
	}

	return params
}

func (w *WorkflowAnalyzer) extractLinks(html string) []string {
	links := []string{}

	linkRegex := regexp.MustCompile(`<a[^>]*href\s*=\s*["']([^"']+)["'][^>]*>`)
	matches := linkRegex.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			links = append(links, match[1])
		}
	}

	return links
}

type FormInfo struct {
	Action string            `json:"action"`
	Method string            `json:"method"`
	Fields map[string]string `json:"fields"`
}

func (w *WorkflowAnalyzer) extractForms(html string) []FormInfo {
	forms := []FormInfo{}

	formRegex := regexp.MustCompile(`<form[^>]*action\s*=\s*["']([^"']+)["'][^>]*>(.*?)</form>`)
	matches := formRegex.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) > 2 {
			form := FormInfo{
				Action: match[1],
				Method: "POST",
				Fields: make(map[string]string),
			}

			// Extract method if specified
			if strings.Contains(match[0], "method") {
				methodRegex := regexp.MustCompile(`method\s*=\s*["']([^"']+)["']`)
				methodMatch := methodRegex.FindStringSubmatch(match[0])
				if len(methodMatch) > 1 {
					form.Method = strings.ToUpper(methodMatch[1])
				}
			}

			forms = append(forms, form)
		}
	}

	return forms
}

func (w *WorkflowAnalyzer) extractAjaxEndpoints(html string) []string {
	endpoints := []string{}

	// Look for AJAX URLs in JavaScript
	patterns := []string{
		`\$\.ajax\(\s*\{\s*url\s*:\s*["']([^"']+)["']`,
		`\$\.post\(\s*["']([^"']+)["']`,
		`\$\.get\(\s*["']([^"']+)["']`,
		`fetch\(\s*["']([^"']+)["']`,
		`XMLHttpRequest.*open\(\s*["']POST["']\s*,\s*["']([^"']+)["']`,
	}

	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllStringSubmatch(html, -1)
		for _, match := range matches {
			if len(match) > 1 {
				endpoints = append(endpoints, match[1])
			}
		}
	}

	return endpoints
}

func (w *WorkflowAnalyzer) generateWorkflowDiagram(workflow *logic.Workflow) string {
	diagram := "Workflow Diagram:\n"
	diagram += "==================\n\n"

	for stateID, state := range workflow.States {
		diagram += fmt.Sprintf("[%s] %s\n", stateID, state.Name)

		if transitions, exists := workflow.Transitions[stateID]; exists {
			for _, transition := range transitions {
				targetID := generateStateID(transition)
				if targetState, exists := workflow.States[targetID]; exists {
					diagram += fmt.Sprintf("  └─> %s\n", targetState.Name)
				}
			}
		}
		diagram += "\n"
	}

	return diagram
}

func (w *WorkflowAnalyzer) generateWorkflowSummary(workflow *logic.Workflow, vulnerabilities []logic.Vulnerability) string {
	summary := fmt.Sprintf("Workflow Analysis Summary:\n")
	summary += fmt.Sprintf("- Total States: %d\n", len(workflow.States))
	summary += fmt.Sprintf("- Total Transitions: %d\n", len(workflow.Transitions))
	summary += fmt.Sprintf("- Vulnerabilities Found: %d\n", len(vulnerabilities))

	if len(vulnerabilities) > 0 {
		summary += "\nVulnerability Breakdown:\n"
		severityCount := make(map[string]int)
		for _, vuln := range vulnerabilities {
			severityCount[vuln.Severity]++
		}

		for severity, count := range severityCount {
			summary += fmt.Sprintf("- %s: %d\n", severity, count)
		}
	}

	return summary
}

func (w *WorkflowAnalyzer) calculateSecurityScore(vulnerabilities []logic.Vulnerability) int {
	score := 100

	for _, vuln := range vulnerabilities {
		switch vuln.Severity {
		case logic.SeverityCritical:
			score -= 25
		case logic.SeverityHigh:
			score -= 15
		case logic.SeverityMedium:
			score -= 8
		case logic.SeverityLow:
			score -= 3
		}
	}

	if score < 0 {
		score = 0
	}

	return score
}

func (w *WorkflowAnalyzer) generateRecommendations(vulnerabilities []logic.Vulnerability) []logic.Recommendation {
	recommendations := []logic.Recommendation{}

	vulnTypes := make(map[string]bool)
	for _, vuln := range vulnerabilities {
		vulnTypes[vuln.Type] = true
	}

	if vulnTypes[logic.VulnWorkflowBypass] {
		recommendations = append(recommendations, logic.Recommendation{
			Priority:    "HIGH",
			Category:    "Business Logic",
			Title:       "Implement Workflow State Validation",
			Description: "Add proper state validation to prevent workflow step bypassing",
			Timeline:    "2 weeks",
			Effort:      "Medium",
			Impact:      "High",
		})
	}

	if vulnTypes[logic.VulnRaceCondition] {
		recommendations = append(recommendations, logic.Recommendation{
			Priority:    "HIGH",
			Category:    "Concurrency",
			Title:       "Add Synchronization Controls",
			Description: "Implement proper synchronization to prevent race conditions",
			Timeline:    "1 week",
			Effort:      "Medium",
			Impact:      "High",
		})
	}

	return recommendations
}

// Utility functions

func extractDomainFromURL(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "unknown"
	}
	return u.Host
}

func extractPageName(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "unknown"
	}

	path := strings.Trim(u.Path, "/")
	if path == "" {
		return "home"
	}

	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

func generateStateID(urlStr string) string {
	h := md5.New()
	h.Write([]byte(urlStr))
	return hex.EncodeToString(h.Sum(nil))[:8]
}

func isValidTransition(link, baseURL string) bool {
	// Skip external links, anchors, and javascript
	if strings.HasPrefix(link, "http") && !strings.Contains(link, extractDomainFromURL(baseURL)) {
		return false
	}
	if strings.HasPrefix(link, "#") || strings.HasPrefix(link, "javascript:") {
		return false
	}
	if strings.HasPrefix(link, "mailto:") || strings.HasPrefix(link, "tel:") {
		return false
	}

	return true
}
