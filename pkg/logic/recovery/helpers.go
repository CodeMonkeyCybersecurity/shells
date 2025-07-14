package recovery

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
	
	"github.com/CodeMonkeyCybersecurity/shells/pkg/logic"
)

// EmailChecker simulates email checking functionality
type EmailChecker struct {
	emails map[string]*EmailMessage
	mutex  sync.RWMutex
}

// EmailMessage represents an email message
type EmailMessage struct {
	To        string    `json:"to"`
	Subject   string    `json:"subject"`
	Body      string    `json:"body"`
	Timestamp time.Time `json:"timestamp"`
}

// NewEmailChecker creates a new email checker
func NewEmailChecker() *EmailChecker {
	return &EmailChecker{
		emails: make(map[string]*EmailMessage),
	}
}

// GetLastEmail retrieves the last email for a given address
func (e *EmailChecker) GetLastEmail(email string) *EmailMessage {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	
	// In a real implementation, this would check an email service
	// For testing purposes, we simulate email reception
	if msg, exists := e.emails[email]; exists {
		return msg
	}
	
	// Simulate receiving an email with a token
	if strings.Contains(email, "@example.com") {
		token, _ := generateRandomToken(32)
		msg := &EmailMessage{
			To:      email,
			Subject: "Password Reset Request",
			Body:    "Please click the following link to reset your password: https://example.com/reset?token=" + token,
			Timestamp: time.Now(),
		}
		e.emails[email] = msg
		return msg
	}
	
	return nil
}

// AddEmail adds an email to the checker (for testing)
func (e *EmailChecker) AddEmail(email string, subject, body string) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	
	e.emails[email] = &EmailMessage{
		To:        email,
		Subject:   subject,
		Body:      body,
		Timestamp: time.Now(),
	}
}

// TokenAnalyzer analyzes security tokens for patterns and entropy
type TokenAnalyzer struct{}

// NewTokenAnalyzer creates a new token analyzer
func NewTokenAnalyzer() *TokenAnalyzer {
	return &TokenAnalyzer{}
}

// AnalyzeTokens performs comprehensive token analysis
func (t *TokenAnalyzer) AnalyzeTokens(tokens []string) logic.TokenAnalysis {
	if len(tokens) == 0 {
		return logic.TokenAnalysis{}
	}

	analysis := logic.TokenAnalysis{
		Tokens:        tokens,
		Entropy:       t.calculateEntropy(tokens),
		IsPredictable: t.detectPredictablePattern(tokens),
		Collisions:    t.countCollisions(tokens),
		Timestamp:     time.Now(),
	}

	if analysis.IsPredictable {
		analysis.Pattern = t.identifyPattern(tokens)
		analysis.Algorithm = t.guessAlgorithm(tokens)
	}

	return analysis
}

// calculateEntropy calculates the entropy of token set
func (t *TokenAnalyzer) calculateEntropy(tokens []string) float64 {
	if len(tokens) == 0 {
		return 0
	}

	// Calculate character frequency
	charFreq := make(map[rune]int)
	totalChars := 0

	for _, token := range tokens {
		for _, char := range token {
			charFreq[char]++
			totalChars++
		}
	}

	// Calculate Shannon entropy
	entropy := 0.0
	for _, freq := range charFreq {
		if freq > 0 {
			p := float64(freq) / float64(totalChars)
			entropy -= p * math.Log2(p)
		}
	}

	// Estimate total entropy based on token length
	if len(tokens) > 0 {
		avgLength := 0
		for _, token := range tokens {
			avgLength += len(token)
		}
		avgLength /= len(tokens)
		
		// Entropy per character × average length
		totalEntropy := entropy * float64(avgLength)
		return totalEntropy
	}

	return entropy
}

// detectPredictablePattern checks if tokens follow a predictable pattern
func (t *TokenAnalyzer) detectPredictablePattern(tokens []string) bool {
	if len(tokens) < 3 {
		return false
	}

	// Check for various predictable patterns
	patterns := []func([]string) bool{
		t.isSequential,
		t.isTimeBased,
		t.isUserIDBased,
		t.hasLowVariance,
		t.hasRepeatingStructure,
	}

	for _, pattern := range patterns {
		if pattern(tokens) {
			return true
		}
	}

	return false
}

// isSequential checks if tokens are sequential
func (t *TokenAnalyzer) isSequential(tokens []string) bool {
	// Convert tokens to numbers if possible
	numbers := []int{}
	for _, token := range tokens {
		if num := t.extractNumber(token); num != -1 {
			numbers = append(numbers, num)
		}
	}

	if len(numbers) < 3 {
		return false
	}

	// Check if numbers are sequential
	sequential := 0
	for i := 1; i < len(numbers); i++ {
		if numbers[i] == numbers[i-1]+1 {
			sequential++
		}
	}

	// If more than 70% are sequential, consider it predictable
	return float64(sequential)/float64(len(numbers)-1) > 0.7
}

// isTimeBased checks if tokens are time-based
func (t *TokenAnalyzer) isTimeBased(tokens []string) bool {
	// Look for timestamp patterns
	timePatterns := []string{
		`\d{10}`,      // Unix timestamp
		`\d{13}`,      // Unix timestamp (milliseconds)
		`\d{8}`,       // YYYYMMDD
		`\d{14}`,      // YYYYMMDDHHMMSS
	}

	matches := 0
	for _, token := range tokens {
		for _, pattern := range timePatterns {
			if matched, _ := regexp.MatchString(pattern, token); matched {
				matches++
				break
			}
		}
	}

	// If more than 50% match time patterns, consider time-based
	return float64(matches)/float64(len(tokens)) > 0.5
}

// isUserIDBased checks if tokens contain user IDs
func (t *TokenAnalyzer) isUserIDBased(tokens []string) bool {
	// Look for user ID patterns
	userPatterns := []string{
		`user\d+`,
		`id\d+`,
		`\d+@`,
		`uid\d+`,
	}

	matches := 0
	for _, token := range tokens {
		lowerToken := strings.ToLower(token)
		for _, pattern := range userPatterns {
			if matched, _ := regexp.MatchString(pattern, lowerToken); matched {
				matches++
				break
			}
		}
	}

	// If more than 30% match user patterns, consider user ID based
	return float64(matches)/float64(len(tokens)) > 0.3
}

// hasLowVariance checks if tokens have low variance (similar structure)
func (t *TokenAnalyzer) hasLowVariance(tokens []string) bool {
	if len(tokens) < 5 {
		return false
	}

	// Check length variance
	lengths := make([]int, len(tokens))
	totalLength := 0
	for i, token := range tokens {
		lengths[i] = len(token)
		totalLength += lengths[i]
	}

	avgLength := float64(totalLength) / float64(len(tokens))
	variance := 0.0
	for _, length := range lengths {
		variance += math.Pow(float64(length)-avgLength, 2)
	}
	variance /= float64(len(tokens))

	// Low variance in length
	if variance < 1.0 {
		return true
	}

	// Check character set variance
	charSets := make([]map[rune]bool, len(tokens))
	for i, token := range tokens {
		charSet := make(map[rune]bool)
		for _, char := range token {
			charSet[char] = true
		}
		charSets[i] = charSet
	}

	// Calculate Jaccard similarity between character sets
	similarities := 0
	comparisons := 0
	for i := 0; i < len(charSets); i++ {
		for j := i + 1; j < len(charSets); j++ {
			similarity := t.jaccardSimilarity(charSets[i], charSets[j])
			if similarity > 0.8 {
				similarities++
			}
			comparisons++
		}
	}

	// High character set similarity
	return float64(similarities)/float64(comparisons) > 0.7
}

// hasRepeatingStructure checks for repeating structural patterns
func (t *TokenAnalyzer) hasRepeatingStructure(tokens []string) bool {
	if len(tokens) < 3 {
		return false
	}

	// Extract structure patterns (e.g., "LLLDDDLLL" for letter-digit patterns)
	structures := make([]string, len(tokens))
	for i, token := range tokens {
		structures[i] = t.extractStructure(token)
	}

	// Count unique structures
	uniqueStructures := make(map[string]int)
	for _, structure := range structures {
		uniqueStructures[structure]++
	}

	// If there are very few unique structures, it's predictable
	uniqueRatio := float64(len(uniqueStructures)) / float64(len(tokens))
	return uniqueRatio < 0.3
}

// extractStructure converts token to structural pattern
func (t *TokenAnalyzer) extractStructure(token string) string {
	structure := ""
	for _, char := range token {
		if char >= '0' && char <= '9' {
			structure += "D"
		} else if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') {
			structure += "L"
		} else {
			structure += "S"
		}
	}
	return structure
}

// jaccardSimilarity calculates Jaccard similarity between two sets
func (t *TokenAnalyzer) jaccardSimilarity(set1, set2 map[rune]bool) float64 {
	intersection := 0
	union := make(map[rune]bool)

	for char := range set1 {
		union[char] = true
		if set2[char] {
			intersection++
		}
	}

	for char := range set2 {
		union[char] = true
	}

	if len(union) == 0 {
		return 0
	}

	return float64(intersection) / float64(len(union))
}

// extractNumber extracts numeric portion from token
func (t *TokenAnalyzer) extractNumber(token string) int {
	re := regexp.MustCompile(`\d+`)
	matches := re.FindAllString(token, -1)
	if len(matches) > 0 {
		// Try to parse the largest number found
		maxNum := -1
		for _, match := range matches {
			if num := parseInt(match); num > maxNum {
				maxNum = num
			}
		}
		return maxNum
	}
	return -1
}

// parseInt safely parses integer
func parseInt(s string) int {
	num := 0
	for _, char := range s {
		if char >= '0' && char <= '9' {
			num = num*10 + int(char-'0')
		} else {
			return -1
		}
	}
	return num
}

// countCollisions counts duplicate tokens
func (t *TokenAnalyzer) countCollisions(tokens []string) int {
	seen := make(map[string]int)
	collisions := 0

	for _, token := range tokens {
		seen[token]++
		if seen[token] > 1 && seen[token] == 2 {
			collisions++
		}
	}

	return collisions
}

// identifyPattern identifies the specific pattern type
func (t *TokenAnalyzer) identifyPattern(tokens []string) string {
	if t.isSequential(tokens) {
		return "Sequential numeric pattern"
	}
	if t.isTimeBased(tokens) {
		return "Time-based pattern"
	}
	if t.isUserIDBased(tokens) {
		return "User ID based pattern"
	}
	if t.hasLowVariance(tokens) {
		return "Low variance structure"
	}
	if t.hasRepeatingStructure(tokens) {
		return "Repeating structural pattern"
	}
	return "Unknown predictable pattern"
}

// guessAlgorithm attempts to guess the token generation algorithm
func (t *TokenAnalyzer) guessAlgorithm(tokens []string) string {
	// Analyze token characteristics to guess algorithm
	if len(tokens) == 0 {
		return "Unknown"
	}

	firstToken := tokens[0]
	tokenLength := len(firstToken)

	// Check for common algorithm signatures
	switch {
	case tokenLength == 32 && t.isHexString(firstToken):
		return "MD5 hash"
	case tokenLength == 40 && t.isHexString(firstToken):
		return "SHA1 hash"
	case tokenLength == 64 && t.isHexString(firstToken):
		return "SHA256 hash"
	case t.isBase64String(firstToken):
		return "Base64 encoded"
	case t.isUUIDString(firstToken):
		return "UUID"
	case t.containsOnlyDigits(firstToken):
		return "Numeric sequence"
	case t.isTimeBased(tokens):
		return "Timestamp-based"
	default:
		return "Custom algorithm"
	}
}

// isHexString checks if string contains only hex characters
func (t *TokenAnalyzer) isHexString(s string) bool {
	matched, _ := regexp.MatchString(`^[a-fA-F0-9]+$`, s)
	return matched
}

// isBase64String checks if string is base64 encoded
func (t *TokenAnalyzer) isBase64String(s string) bool {
	matched, _ := regexp.MatchString(`^[A-Za-z0-9+/]+=*$`, s)
	return matched && len(s)%4 == 0
}

// isUUIDString checks if string is a UUID
func (t *TokenAnalyzer) isUUIDString(s string) bool {
	matched, _ := regexp.MatchString(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`, s)
	return matched
}

// containsOnlyDigits checks if string contains only digits
func (t *TokenAnalyzer) containsOnlyDigits(s string) bool {
	matched, _ := regexp.MatchString(`^[0-9]+$`, s)
	return matched
}

// generateRandomToken generates a random token for testing
func generateRandomToken(length int) (string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// RaceConditionTester provides race condition testing utilities
type RaceConditionTester struct {
	workers int
	timeout time.Duration
}

// NewRaceConditionTester creates a new race condition tester
func NewRaceConditionTester(workers int) *RaceConditionTester {
	return &RaceConditionTester{
		workers: workers,
		timeout: 30 * time.Second,
	}
}

// RaceTest represents a race condition test
type RaceTest struct {
	Name string
	Test func(endpoint string) *logic.Vulnerability
}

// TestPasswordResetRace tests for race conditions in password reset
func (r *RaceConditionTester) TestPasswordResetRace(endpoint string) []logic.Vulnerability {
	vulnerabilities := []logic.Vulnerability{}

	tests := []RaceTest{
		{
			Name: "Multiple token generation",
			Test: r.testMultipleTokenGeneration,
		},
		{
			Name: "Token use after reset",
			Test: r.testTokenUseAfterReset,
		},
		{
			Name: "Concurrent password changes",
			Test: r.testConcurrentPasswordChanges,
		},
		{
			Name: "Session invalidation race",
			Test: r.testSessionInvalidationRace,
		},
	}

	for _, test := range tests {
		if vuln := test.Test(endpoint); vuln != nil {
			vulnerabilities = append(vulnerabilities, *vuln)
		}
	}

	return vulnerabilities
}

// Placeholder implementations for race condition tests
func (r *RaceConditionTester) testMultipleTokenGeneration(endpoint string) *logic.Vulnerability {
	// Implementation would be similar to the one in reset.go
	return nil
}

func (r *RaceConditionTester) testTokenUseAfterReset(endpoint string) *logic.Vulnerability {
	// Test if tokens can be used after being consumed
	return nil
}

func (r *RaceConditionTester) testConcurrentPasswordChanges(endpoint string) *logic.Vulnerability {
	// Test concurrent password changes with same token
	return nil
}

func (r *RaceConditionTester) testSessionInvalidationRace(endpoint string) *logic.Vulnerability {
	// Test if sessions are properly invalidated during reset
	return nil
}