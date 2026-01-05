package core

import (
	"bytes"
	"encoding/json"
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

// RaceConditionTester provides comprehensive race condition testing
type RaceConditionTester struct {
	httpClient    *http.Client
	config        *logic.TestConfig
	results       []logic.RaceConditionTest
	mutex         sync.Mutex
	endpointTests map[string][]RaceTestFunc
}

// RaceTestFunc represents a race condition test function
type RaceTestFunc func(endpoint string, tester *RaceConditionTester) *logic.Vulnerability

// NewRaceConditionTester creates a new race condition tester
func NewRaceConditionTester(config *logic.TestConfig) *RaceConditionTester {
	if config == nil {
		config = &logic.TestConfig{
			MaxWorkers:   20,
			Timeout:      30 * time.Second,
			RequestDelay: 0,
		}
	}

	tester := &RaceConditionTester{
		httpClient: &http.Client{
			Timeout: config.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects for race testing
			},
		},
		config:        config,
		results:       []logic.RaceConditionTest{},
		endpointTests: make(map[string][]RaceTestFunc),
	}

	// Register race condition tests
	tester.registerRaceTests()

	return tester
}

// registerRaceTests registers all race condition test functions
func (r *RaceConditionTester) registerRaceTests() {
	// Authentication race tests
	authTests := []RaceTestFunc{
		r.testLoginRaceCondition,
		r.testPasswordResetRace,
		r.testAccountCreationRace,
		r.testSessionFixationRace,
		r.testMFABypassRace,
	}

	// Payment race tests
	paymentTests := []RaceTestFunc{
		r.testPaymentProcessingRace,
		r.testCartManipulationRace,
		r.testCouponRace,
		r.testRefundRace,
		r.testBalanceRace,
	}

	// Business logic race tests
	businessTests := []RaceTestFunc{
		r.testResourceAllocationRace,
		r.testLimitBypassRace,
		r.testStateTransitionRace,
		r.testFileUploadRace,
		r.testVotingRace,
	}

	// Resource management race tests
	resourceTests := []RaceTestFunc{
		r.testInventoryRace,
		r.testQuotaRace,
		r.testBookingRace,
		r.testLockingRace,
	}

	r.endpointTests["auth"] = authTests
	r.endpointTests["payment"] = paymentTests
	r.endpointTests["business"] = businessTests
	r.endpointTests["resource"] = resourceTests
}

// TestAllEndpoints tests all discovered endpoints for race conditions
func (r *RaceConditionTester) TestAllEndpoints(target string) []logic.RaceConditionTest {
	// Discover endpoints
	endpoints := r.discoverEndpoints(target)

	// Test each endpoint category
	for category, tests := range r.endpointTests {
		relevantEndpoints := r.filterEndpointsByCategory(endpoints, category)

		for _, endpoint := range relevantEndpoints {
			for _, testFunc := range tests {
				if vuln := testFunc(endpoint, r); vuln != nil {
					raceTest := logic.RaceConditionTest{
						Name:       vuln.Title,
						Endpoint:   endpoint,
						Vulnerable: true,
						Impact:     vuln.Impact,
						Evidence:   []string{vuln.Details},
					}
					r.addResult(raceTest)
				}
			}
		}
	}

	return r.results
}

// testLoginRaceCondition tests for race conditions in login process
func (r *RaceConditionTester) testLoginRaceCondition(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test concurrent login attempts
	workers := r.config.MaxWorkers
	results := make(chan LoginResult, workers)

	var wg sync.WaitGroup

	// Prepare login credentials
	credentials := map[string]string{
		"username": "testuser",
		"password": "testpass",
		"email":    "test@example.com",
	}

	startTime := time.Now()

	// Launch concurrent login attempts
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			result := r.attemptLogin(endpoint, credentials, workerID)
			results <- result
		}(i)
	}

	wg.Wait()
	close(results)

	// Analyze results
	successCount := 0
	failureCount := 0
	responses := []LoginResult{}

	for result := range results {
		responses = append(responses, result)
		if result.Success {
			successCount++
		} else {
			failureCount++
		}
	}

	duration := time.Since(startTime)

	// Check for suspicious patterns
	if r.detectLoginRaceVulnerability(responses) {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnRaceCondition,
			Severity:    logic.SeverityHigh,
			Title:       "Login Race Condition",
			Description: "Concurrent login attempts reveal race condition vulnerability",
			Details:     fmt.Sprintf("Workers: %d, Success: %d, Failures: %d, Duration: %v", workers, successCount, failureCount, duration),
			Impact:      "Race conditions in login may lead to authentication bypass",
			Evidence: map[string]interface{}{
				"concurrent_requests": workers,
				"successful_logins":   successCount,
				"failed_logins":       failureCount,
				"response_times":      r.extractResponseTimes(responses),
			},
			CWE:         "CWE-362",
			CVSS:        7.5,
			Remediation: "Implement proper synchronization for authentication processes",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

// testPasswordResetRace tests for race conditions in password reset
func (r *RaceConditionTester) testPasswordResetRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	email := "victim@example.com"
	workers := r.config.MaxWorkers

	tokens := make(chan string, workers)
	var wg sync.WaitGroup

	// Send concurrent reset requests
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			token := r.requestPasswordReset(endpoint, email)
			if token != "" {
				tokens <- token
			}
		}()
	}

	wg.Wait()
	close(tokens)

	// Check if multiple valid tokens were generated
	validTokens := []string{}
	uniqueTokens := make(map[string]bool)

	for token := range tokens {
		if token != "" && !uniqueTokens[token] {
			validTokens = append(validTokens, token)
			uniqueTokens[token] = true
		}
	}

	if len(validTokens) > 1 {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnRaceCondition,
			Severity:    logic.SeverityHigh,
			Title:       "Password Reset Race Condition",
			Description: "Multiple valid reset tokens can be generated simultaneously",
			Details:     fmt.Sprintf("Generated %d valid tokens for single email", len(validTokens)),
			Impact:      "Attackers can generate multiple valid tokens for account takeover",
			Evidence:    map[string]interface{}{"tokens": validTokens},
			CWE:         "CWE-362",
			CVSS:        7.5,
			Remediation: "Implement token invalidation and proper synchronization",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

// testPaymentProcessingRace tests for race conditions in payment processing
func (r *RaceConditionTester) testPaymentProcessingRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test concurrent payment processing
	workers := 10
	amount := "100.00"

	paymentData := map[string]string{
		"amount":       amount,
		"currency":     "USD",
		"card_number":  "4111111111111111",
		"expiry_month": "12",
		"expiry_year":  "2025",
		"cvv":          "123",
	}

	results := make(chan PaymentResult, workers)
	var wg sync.WaitGroup

	// Launch concurrent payment attempts
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			result := r.processPayment(endpoint, paymentData, workerID)
			results <- result
		}(i)
	}

	wg.Wait()
	close(results)

	// Analyze payment results
	successCount := 0
	totalCharged := 0.0

	for result := range results {
		if result.Success {
			successCount++
			totalCharged += result.Amount
		}
	}

	expectedTotal := 100.0 // Should only charge once

	if successCount > 1 || totalCharged > expectedTotal {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnRaceCondition,
			Severity:    logic.SeverityCritical,
			Title:       "Payment Processing Race Condition",
			Description: "Concurrent payment processing allows multiple charges",
			Details:     fmt.Sprintf("Successful payments: %d, Total charged: $%.2f", successCount, totalCharged),
			Impact:      "Double charging customers due to race conditions",
			Evidence: map[string]interface{}{
				"successful_payments": successCount,
				"total_charged":       totalCharged,
				"expected_charge":     expectedTotal,
			},
			CWE:         "CWE-362",
			CVSS:        9.1,
			Remediation: "Implement idempotency keys and proper payment synchronization",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

// testCartManipulationRace tests for race conditions in shopping cart
func (r *RaceConditionTester) testCartManipulationRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test concurrent cart operations
	workers := 15
	productID := "12345"
	initialQuantity := 5

	results := make(chan CartResult, workers)
	var wg sync.WaitGroup

	// Add initial item to cart
	r.addToCart(endpoint, productID, initialQuantity)

	// Launch concurrent cart operations
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			var result CartResult
			if workerID%2 == 0 {
				// Add items
				result = r.addToCart(endpoint, productID, 1)
				result.Operation = "ADD"
			} else {
				// Remove items
				result = r.removeFromCart(endpoint, productID, 1)
				result.Operation = "REMOVE"
			}

			results <- result
		}(i)
	}

	wg.Wait()
	close(results)

	// Check final cart state
	finalCart := r.getCartContents(endpoint)

	// Calculate expected quantity
	addCount := 0
	removeCount := 0

	for result := range results {
		if result.Success {
			if result.Operation == "ADD" {
				addCount++
			} else {
				removeCount++
			}
		}
	}

	expectedQuantity := initialQuantity + addCount - removeCount

	if finalCart.Quantity != expectedQuantity {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnRaceCondition,
			Severity:    logic.SeverityMedium,
			Title:       "Shopping Cart Race Condition",
			Description: "Concurrent cart operations lead to inconsistent state",
			Details:     fmt.Sprintf("Expected quantity: %d, Actual: %d", expectedQuantity, finalCart.Quantity),
			Impact:      "Cart inconsistencies may lead to pricing errors",
			Evidence: map[string]interface{}{
				"expected_quantity": expectedQuantity,
				"actual_quantity":   finalCart.Quantity,
				"add_operations":    addCount,
				"remove_operations": removeCount,
			},
			CWE:         "CWE-362",
			CVSS:        5.3,
			Remediation: "Implement atomic cart operations with proper locking",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

// testResourceAllocationRace tests for race conditions in resource allocation
func (r *RaceConditionTester) testResourceAllocationRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test concurrent resource allocation (e.g., booking seats, reserving items)
	workers := 20
	resourceID := "resource_123"

	results := make(chan AllocationResult, workers)
	var wg sync.WaitGroup

	// Launch concurrent allocation attempts
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			result := r.allocateResource(endpoint, resourceID, workerID)
			results <- result
		}(i)
	}

	wg.Wait()
	close(results)

	// Count successful allocations
	successCount := 0
	allocatedIDs := []string{}

	for result := range results {
		if result.Success {
			successCount++
			allocatedIDs = append(allocatedIDs, result.AllocationID)
		}
	}

	// If more than one allocation succeeded for the same resource, it's a race condition
	if successCount > 1 {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnRaceCondition,
			Severity:    logic.SeverityHigh,
			Title:       "Resource Allocation Race Condition",
			Description: "Same resource can be allocated multiple times concurrently",
			Details:     fmt.Sprintf("Resource allocated %d times simultaneously", successCount),
			Impact:      "Double-booking or over-allocation of limited resources",
			Evidence: map[string]interface{}{
				"successful_allocations": successCount,
				"allocation_ids":         allocatedIDs,
				"resource_id":            resourceID,
			},
			CWE:         "CWE-362",
			CVSS:        7.5,
			Remediation: "Implement proper resource locking and atomic allocation",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

// testLimitBypassRace tests for race conditions that bypass rate limits
func (r *RaceConditionTester) testLimitBypassRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test concurrent requests to bypass rate limits
	workers := 50

	results := make(chan LimitTestResult, workers)
	var wg sync.WaitGroup

	startTime := time.Now()

	// Launch concurrent requests
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			result := r.makeRateLimitedRequest(endpoint, workerID)
			results <- result
		}(i)
	}

	wg.Wait()
	close(results)

	duration := time.Since(startTime)

	// Count successful requests
	successCount := 0
	for result := range results {
		if result.Success {
			successCount++
		}
	}

	// If most requests succeeded simultaneously, rate limiting may be bypassed
	successRate := float64(successCount) / float64(workers)

	if successRate > 0.8 && duration < 5*time.Second {
		return &logic.Vulnerability{
			ID:          uuid.New().String(),
			Type:        logic.VulnRaceCondition,
			Severity:    logic.SeverityMedium,
			Title:       "Rate Limit Bypass via Race Condition",
			Description: "Concurrent requests can bypass rate limiting controls",
			Details:     fmt.Sprintf("Success rate: %.2f%%, Duration: %v", successRate*100, duration),
			Impact:      "Rate limiting can be bypassed, allowing abuse of functionality",
			Evidence: map[string]interface{}{
				"success_rate":        successRate,
				"successful_requests": successCount,
				"total_requests":      workers,
				"duration_seconds":    duration.Seconds(),
			},
			CWE:         "CWE-362",
			CVSS:        5.3,
			Remediation: "Implement proper rate limiting with atomic counters",
			Timestamp:   time.Now(),
		}
	}

	return nil
}

// Helper structures and methods

type LoginResult struct {
	Success      bool          `json:"success"`
	StatusCode   int           `json:"status_code"`
	ResponseTime time.Duration `json:"response_time"`
	SessionToken string        `json:"session_token,omitempty"`
	WorkerID     int           `json:"worker_id"`
}

type PaymentResult struct {
	Success       bool    `json:"success"`
	Amount        float64 `json:"amount"`
	TransactionID string  `json:"transaction_id,omitempty"`
	StatusCode    int     `json:"status_code"`
	WorkerID      int     `json:"worker_id"`
}

type CartResult struct {
	Success   bool   `json:"success"`
	Operation string `json:"operation"`
	Quantity  int    `json:"quantity"`
	WorkerID  int    `json:"worker_id"`
}

type CartContents struct {
	ProductID string  `json:"product_id"`
	Quantity  int     `json:"quantity"`
	Price     float64 `json:"price"`
}

type AllocationResult struct {
	Success      bool   `json:"success"`
	AllocationID string `json:"allocation_id,omitempty"`
	ResourceID   string `json:"resource_id"`
	WorkerID     int    `json:"worker_id"`
}

type LimitTestResult struct {
	Success    bool          `json:"success"`
	StatusCode int           `json:"status_code"`
	Response   string        `json:"response"`
	Duration   time.Duration `json:"duration"`
	WorkerID   int           `json:"worker_id"`
}

// Implementation of helper methods

func (r *RaceConditionTester) attemptLogin(endpoint string, credentials map[string]string, workerID int) LoginResult {
	startTime := time.Now()

	// Prepare login request
	values := url.Values{}
	for key, value := range credentials {
		values.Set(key, value)
	}

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return LoginResult{Success: false, WorkerID: workerID}
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return LoginResult{Success: false, WorkerID: workerID}
	}
	defer httpclient.CloseBody(resp)

	responseTime := time.Since(startTime)

	// Extract session token if present
	sessionToken := ""
	if cookie := r.extractSessionCookie(resp); cookie != nil {
		sessionToken = cookie.Value
	}

	return LoginResult{
		Success:      resp.StatusCode == 200 || resp.StatusCode == 302,
		StatusCode:   resp.StatusCode,
		ResponseTime: responseTime,
		SessionToken: sessionToken,
		WorkerID:     workerID,
	}
}

func (r *RaceConditionTester) requestPasswordReset(endpoint string, email string) string {
	values := url.Values{}
	values.Set("email", email)

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return ""
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer httpclient.CloseBody(resp)

	// Extract token from response (simplified)
	body, _ := io.ReadAll(resp.Body)
	return r.extractToken(string(body))
}

func (r *RaceConditionTester) processPayment(endpoint string, paymentData map[string]string, workerID int) PaymentResult {
	// Convert payment data to JSON
	jsonData, _ := json.Marshal(paymentData)

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return PaymentResult{Success: false, WorkerID: workerID}
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return PaymentResult{Success: false, WorkerID: workerID}
	}
	defer httpclient.CloseBody(resp)

	// Parse response
	body, _ := io.ReadAll(resp.Body)

	result := PaymentResult{
		Success:    resp.StatusCode == 200,
		StatusCode: resp.StatusCode,
		WorkerID:   workerID,
	}

	if result.Success {
		// Extract transaction details (simplified)
		result.Amount = 100.0 // Assuming successful payment
		result.TransactionID = r.extractTransactionID(string(body))
	}

	return result
}

func (r *RaceConditionTester) addToCart(endpoint string, productID string, quantity int) CartResult {
	values := url.Values{}
	values.Set("product_id", productID)
	values.Set("quantity", fmt.Sprintf("%d", quantity))

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return CartResult{Success: false}
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return CartResult{Success: false}
	}
	defer httpclient.CloseBody(resp)

	return CartResult{
		Success:  resp.StatusCode == 200,
		Quantity: quantity,
	}
}

func (r *RaceConditionTester) removeFromCart(endpoint string, productID string, quantity int) CartResult {
	// Similar to addToCart but for removal
	values := url.Values{}
	values.Set("product_id", productID)
	values.Set("quantity", fmt.Sprintf("-%d", quantity))

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return CartResult{Success: false}
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return CartResult{Success: false}
	}
	defer httpclient.CloseBody(resp)

	return CartResult{
		Success:  resp.StatusCode == 200,
		Quantity: quantity,
	}
}

func (r *RaceConditionTester) getCartContents(endpoint string) CartContents {
	// Get current cart contents
	req, err := http.NewRequest("GET", endpoint+"/cart", nil)
	if err != nil {
		return CartContents{}
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return CartContents{}
	}
	defer httpclient.CloseBody(resp)

	body, _ := io.ReadAll(resp.Body)

	// Parse cart contents (simplified)
	quantity := r.extractQuantityFromCart(string(body))

	return CartContents{
		Quantity: quantity,
	}
}

func (r *RaceConditionTester) allocateResource(endpoint string, resourceID string, workerID int) AllocationResult {
	values := url.Values{}
	values.Set("resource_id", resourceID)
	values.Set("user_id", fmt.Sprintf("user_%d", workerID))

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return AllocationResult{Success: false, WorkerID: workerID}
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return AllocationResult{Success: false, WorkerID: workerID}
	}
	defer httpclient.CloseBody(resp)

	result := AllocationResult{
		Success:    resp.StatusCode == 200,
		ResourceID: resourceID,
		WorkerID:   workerID,
	}

	if result.Success {
		body, _ := io.ReadAll(resp.Body)
		result.AllocationID = r.extractAllocationID(string(body))
	}

	return result
}

func (r *RaceConditionTester) makeRateLimitedRequest(endpoint string, workerID int) LimitTestResult {
	startTime := time.Now()

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return LimitTestResult{Success: false, WorkerID: workerID}
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return LimitTestResult{Success: false, WorkerID: workerID}
	}
	defer httpclient.CloseBody(resp)

	body, _ := io.ReadAll(resp.Body)
	duration := time.Since(startTime)

	return LimitTestResult{
		Success:    resp.StatusCode == 200,
		StatusCode: resp.StatusCode,
		Response:   string(body),
		Duration:   duration,
		WorkerID:   workerID,
	}
}

// Additional helper methods and placeholder implementations for remaining tests

func (r *RaceConditionTester) testAccountCreationRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test concurrent account creation with same email/username
	return nil
}

func (r *RaceConditionTester) testSessionFixationRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test race conditions in session management
	return nil
}

func (r *RaceConditionTester) testMFABypassRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test race conditions in MFA verification
	return nil
}

func (r *RaceConditionTester) testCouponRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test concurrent coupon usage
	return nil
}

func (r *RaceConditionTester) testRefundRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test concurrent refund processing
	return nil
}

func (r *RaceConditionTester) testBalanceRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test race conditions in balance operations
	return nil
}

func (r *RaceConditionTester) testStateTransitionRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test race conditions in state transitions
	return nil
}

func (r *RaceConditionTester) testFileUploadRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test concurrent file uploads
	return nil
}

func (r *RaceConditionTester) testVotingRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test race conditions in voting systems
	return nil
}

func (r *RaceConditionTester) testInventoryRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test inventory management race conditions
	return nil
}

func (r *RaceConditionTester) testQuotaRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test quota enforcement race conditions
	return nil
}

func (r *RaceConditionTester) testBookingRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test booking system race conditions
	return nil
}

func (r *RaceConditionTester) testLockingRace(endpoint string, tester *RaceConditionTester) *logic.Vulnerability {
	// Test locking mechanism race conditions
	return nil
}

// Utility methods

func (r *RaceConditionTester) discoverEndpoints(target string) []string {
	// Simplified endpoint discovery
	endpoints := []string{
		target + "/login",
		target + "/register",
		target + "/reset",
		target + "/payment",
		target + "/cart",
		target + "/booking",
		target + "/api/allocate",
		target + "/api/vote",
		target + "/upload",
	}
	return endpoints
}

func (r *RaceConditionTester) filterEndpointsByCategory(endpoints []string, category string) []string {
	var filtered []string

	categoryKeywords := map[string][]string{
		"auth":     {"login", "register", "reset", "auth"},
		"payment":  {"payment", "pay", "checkout", "billing"},
		"business": {"cart", "vote", "upload", "allocate"},
		"resource": {"booking", "reserve", "inventory", "quota"},
	}

	keywords := categoryKeywords[category]
	if keywords == nil {
		return endpoints
	}

	for _, endpoint := range endpoints {
		for _, keyword := range keywords {
			if strings.Contains(strings.ToLower(endpoint), keyword) {
				filtered = append(filtered, endpoint)
				break
			}
		}
	}

	return filtered
}

func (r *RaceConditionTester) detectLoginRaceVulnerability(responses []LoginResult) bool {
	// Analyze login responses for race condition indicators
	successCount := 0
	uniqueTokens := make(map[string]bool)

	for _, response := range responses {
		if response.Success {
			successCount++
			if response.SessionToken != "" {
				uniqueTokens[response.SessionToken] = true
			}
		}
	}

	// If multiple logins succeeded with different tokens, it might indicate a race condition
	return successCount > 1 && len(uniqueTokens) > 1
}

func (r *RaceConditionTester) extractResponseTimes(responses []LoginResult) []float64 {
	times := []float64{}
	for _, response := range responses {
		times = append(times, response.ResponseTime.Seconds())
	}
	return times
}

func (r *RaceConditionTester) extractSessionCookie(resp *http.Response) *http.Cookie {
	for _, cookie := range resp.Cookies() {
		if strings.Contains(strings.ToLower(cookie.Name), "session") ||
			strings.Contains(strings.ToLower(cookie.Name), "auth") {
			return cookie
		}
	}
	return nil
}

func (r *RaceConditionTester) extractToken(body string) string {
	// Extract token using regex (simplified)
	re := regexp.MustCompile(`token["\s]*[:=]["\s]*([a-zA-Z0-9\-_\.]+)`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (r *RaceConditionTester) extractTransactionID(body string) string {
	// Extract transaction ID from response
	re := regexp.MustCompile(`transaction[_-]?id["\s]*[:=]["\s]*([a-zA-Z0-9\-_\.]+)`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return fmt.Sprintf("txn_%d", time.Now().Unix())
}

func (r *RaceConditionTester) extractQuantityFromCart(body string) int {
	// Extract quantity from cart response
	re := regexp.MustCompile(`quantity["\s]*[:=]["\s]*(\d+)`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		if qty, err := fmt.Sscanf(matches[1], "%d", new(int)); err == nil && qty == 1 {
			return *new(int)
		}
	}
	return 0
}

func (r *RaceConditionTester) extractAllocationID(body string) string {
	// Extract allocation ID from response
	re := regexp.MustCompile(`allocation[_-]?id["\s]*[:=]["\s]*([a-zA-Z0-9\-_\.]+)`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return fmt.Sprintf("alloc_%d", time.Now().Unix())
}

func (r *RaceConditionTester) addResult(result logic.RaceConditionTest) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.results = append(r.results, result)
}
