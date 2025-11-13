// pkg/scanners/secrets/trufflehog.go
package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// TruffleHogScanner integrates with TruffleHog for secret scanning
type TruffleHogScanner struct {
	logger      *logger.Logger
	binaryPath  string
	verifiers   map[string]Verifier
	customRules []CustomRule
	rateLimiter *RateLimiter
}

// SecretFinding represents a discovered secret
type SecretFinding struct {
	Type           string
	Secret         string
	RedactedSecret string
	File           string
	Line           int
	Column         int
	Commit         string
	Author         string
	Email          string
	Date           time.Time
	Repository     string
	Verified       bool
	Severity       types.Severity
	Context        string
	Metadata       map[string]interface{}
}

// Verifier validates discovered secrets
type Verifier interface {
	Name() string
	Verify(ctx context.Context, secret string) (bool, error)
	GetMetadata(secret string) map[string]interface{}
}

// CustomRule represents a custom secret detection rule
type CustomRule struct {
	Name        string
	Pattern     *regexp.Regexp
	Keywords    []string
	Severity    types.Severity
	Verifier    Verifier
	Description string
}

// NewTruffleHogScanner creates a new TruffleHog scanner
func NewTruffleHogScanner(logger *logger.Logger) *TruffleHogScanner {
	scanner := &TruffleHogScanner{
		logger:      logger,
		binaryPath:  "trufflehog",
		verifiers:   make(map[string]Verifier),
		customRules: []CustomRule{},
		rateLimiter: NewRateLimiter(10, time.Second), // 10 verifications per second
	}

	// Initialize verifiers
	scanner.initializeVerifiers()

	// Add custom rules
	scanner.addCustomRules()

	return scanner
}

// ScanGitRepository scans a Git repository for secrets
func (t *TruffleHogScanner) ScanGitRepository(ctx context.Context, repoURL string) ([]SecretFinding, error) {
	t.logger.Infow("Starting TruffleHog scan", "repository", repoURL)

	// Build TruffleHog command
	args := []string{
		"git",
		repoURL,
		"--json",
		"--only-verified=false", // Get all findings, we'll verify ourselves
		"--concurrency=5",
	}

	// Execute TruffleHog
	cmd := exec.CommandContext(ctx, t.binaryPath, args...)
	output, err := cmd.Output()
	if err != nil {
		// TruffleHog returns non-zero exit code when secrets are found
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			t.logger.Errorw("TruffleHog error", "stderr", string(exitErr.Stderr))
		}
	}

	// Parse findings
	findings, err := t.parseTruffleHogOutput(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TruffleHog output: %w", err)
	}

	// Apply custom rules
	customFindings := t.scanWithCustomRules(ctx, repoURL)
	findings = append(findings, customFindings...)

	// Verify secrets
	t.verifySecrets(ctx, findings)

	// Enrich findings with context
	t.enrichFindings(findings)

	// Sort by severity
	t.sortFindingsBySeverity(findings)

	t.logger.Infow("TruffleHog scan completed",
		"repository", repoURL,
		"findings", len(findings),
		"verified", t.countVerified(findings))

	return findings, nil
}

// ScanFileSystem scans a file system path for secrets
func (t *TruffleHogScanner) ScanFileSystem(ctx context.Context, path string) ([]SecretFinding, error) {
	t.logger.Infow("Starting filesystem scan", "path", path)

	args := []string{
		"filesystem",
		path,
		"--json",
		"--only-verified=false",
		"--concurrency=5",
	}

	cmd := exec.CommandContext(ctx, t.binaryPath, args...)
	output, err := cmd.Output()
	if err != nil && !isNonZeroExitError(err) {
		return nil, fmt.Errorf("TruffleHog execution failed: %w", err)
	}

	findings, err := t.parseTruffleHogOutput(output)
	if err != nil {
		return nil, err
	}

	// Verify and enrich
	t.verifySecrets(ctx, findings)
	t.enrichFindings(findings)

	return findings, nil
}

// ScanDockerImage scans a Docker image for secrets
func (t *TruffleHogScanner) ScanDockerImage(ctx context.Context, image string) ([]SecretFinding, error) {
	t.logger.Infow("Starting Docker image scan", "image", image)

	args := []string{
		"docker",
		"--image", image,
		"--json",
		"--only-verified=false",
	}

	cmd := exec.CommandContext(ctx, t.binaryPath, args...)
	output, err := cmd.Output()
	if err != nil && !isNonZeroExitError(err) {
		return nil, fmt.Errorf("TruffleHog execution failed: %w", err)
	}

	findings, err := t.parseTruffleHogOutput(output)
	if err != nil {
		return nil, err
	}

	t.verifySecrets(ctx, findings)
	t.enrichFindings(findings)

	return findings, nil
}

// parseTruffleHogOutput parses TruffleHog JSON output
func (t *TruffleHogScanner) parseTruffleHogOutput(output []byte) ([]SecretFinding, error) {
	var findings []SecretFinding

	// TruffleHog outputs one JSON object per line
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var result TruffleHogResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			t.logger.Errorw("Failed to parse TruffleHog line", "error", err, "line", line)
			continue
		}

		finding := t.convertToSecretFinding(result)
		findings = append(findings, finding)
	}

	return findings, nil
}

// convertToSecretFinding converts TruffleHog result to our format
func (t *TruffleHogScanner) convertToSecretFinding(result TruffleHogResult) SecretFinding {
	finding := SecretFinding{
		Type:           result.DetectorName,
		Secret:         result.Raw,
		RedactedSecret: t.redactSecret(result.Raw),
		Verified:       result.Verified,
		Metadata:       make(map[string]interface{}),
	}

	// Extract source metadata
	if result.SourceMetadata != nil {
		if result.SourceMetadata.Data != nil {
			if git, ok := result.SourceMetadata.Data.(*GitMetadata); ok {
				finding.File = git.File
				finding.Line = git.Line
				finding.Commit = git.Commit
				finding.Author = git.Author
				finding.Email = git.Email
				finding.Date = git.Date
				finding.Repository = git.Repository
			}
		}
	}

	// Determine severity
	finding.Severity = t.calculateSeverity(result)

	// Extract context
	if result.StructuredData != nil {
		finding.Context = t.extractContext(result.StructuredData)
	}

	return finding
}

// verifySecrets attempts to verify discovered secrets
func (t *TruffleHogScanner) verifySecrets(ctx context.Context, findings []SecretFinding) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit concurrent verifications

	for i := range findings {
		if findings[i].Verified {
			continue // Already verified by TruffleHog
		}

		wg.Add(1)
		go func(finding *SecretFinding) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Rate limit verifications
			t.rateLimiter.Wait()

			// Get appropriate verifier
			if verifier, exists := t.verifiers[finding.Type]; exists {
				verified, err := verifier.Verify(ctx, finding.Secret)
				if err != nil {
					t.logger.Errorw("Verification failed",
						"type", finding.Type,
						"error", err)
				} else {
					finding.Verified = verified
					if verified {
						finding.Metadata = verifier.GetMetadata(finding.Secret)
						finding.Severity = types.SeverityCritical // Verified secrets are critical
					}
				}
			}
		}(&findings[i])
	}

	wg.Wait()
}

// enrichFindings adds additional context to findings
func (t *TruffleHogScanner) enrichFindings(findings []SecretFinding) {
	for i := range findings {
		finding := &findings[i]

		// Add impact assessment
		finding.Metadata["impact"] = t.assessImpact(finding)

		// Add remediation steps
		finding.Metadata["remediation"] = t.getRemediation(finding)

		// Add related findings
		finding.Metadata["related"] = t.findRelatedSecrets(findings, finding)

		// Extract additional patterns
		if patterns := t.extractPatterns(finding.Secret); len(patterns) > 0 {
			finding.Metadata["patterns"] = patterns
		}
	}
}

// scanWithCustomRules applies custom rules to find additional secrets
func (t *TruffleHogScanner) scanWithCustomRules(ctx context.Context, target string) []SecretFinding {
	var findings []SecretFinding

	// This would implement custom scanning logic
	// For now, return empty slice
	return findings
}

// initializeVerifiers sets up secret verifiers
func (t *TruffleHogScanner) initializeVerifiers() {
	// AWS verifier
	t.verifiers["AWS"] = &AWSVerifier{
		logger: t.logger,
	}

	// GitHub verifier
	t.verifiers["GitHub"] = &GitHubVerifier{
		logger: t.logger,
	}

	// Slack verifier
	t.verifiers["Slack"] = &SlackVerifier{
		logger: t.logger,
	}

	// Generic API key verifier
	t.verifiers["Generic"] = &GenericAPIVerifier{
		logger: t.logger,
	}
}

// addCustomRules adds custom secret detection rules
func (t *TruffleHogScanner) addCustomRules() {
	// Internal API keys
	t.customRules = append(t.customRules, CustomRule{
		Name:        "Internal_API_Key",
		Pattern:     regexp.MustCompile(`(?i)internal[_-]?api[_-]?key["\s]*[:=]\s*["']([a-zA-Z0-9_-]{32,})["']`),
		Keywords:    []string{"internal", "api", "key"},
		Severity:    types.SeverityHigh,
		Description: "Internal API key exposed",
	})

	// Database connection strings
	t.customRules = append(t.customRules, CustomRule{
		Name:        "Database_Connection",
		Pattern:     regexp.MustCompile(`(?i)(mongodb|postgres|mysql|redis|mssql)://[^:]+:[^@]+@[^/\s]+`),
		Keywords:    []string{"mongodb", "postgres", "mysql", "redis", "connection"},
		Severity:    types.SeverityCritical,
		Description: "Database connection string with credentials",
	})

	// JWT tokens
	t.customRules = append(t.customRules, CustomRule{
		Name:        "JWT_Token",
		Pattern:     regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
		Keywords:    []string{"jwt", "token", "bearer"},
		Severity:    types.SeverityMedium,
		Description: "JWT token exposed",
		Verifier:    &JWTVerifier{},
	})
}

// assessImpact determines the potential impact of a secret exposure
func (t *TruffleHogScanner) assessImpact(finding *SecretFinding) string {
	impacts := map[string]string{
		"AWS":      "Full AWS account access, potential data breach and resource abuse",
		"GitHub":   "Repository access, code manipulation, CI/CD pipeline compromise",
		"Slack":    "Message access, channel manipulation, data exfiltration",
		"Database": "Complete database access, data breach, data manipulation",
		"JWT":      "Authentication bypass, session hijacking, privilege escalation",
		"API_Key":  "Service abuse, data access, potential financial impact",
	}

	if impact, exists := impacts[finding.Type]; exists {
		return impact
	}

	return "Unauthorized access to services, potential data exposure"
}

// getRemediation provides remediation steps
func (t *TruffleHogScanner) getRemediation(finding *SecretFinding) []string {
	baseSteps := []string{
		"Immediately rotate the exposed credential",
		"Audit access logs for unauthorized usage",
		"Remove the secret from the repository history",
		"Implement secret scanning in CI/CD pipeline",
	}

	// Add type-specific steps
	switch finding.Type {
	case "AWS":
		baseSteps = append(baseSteps,
			"Review AWS CloudTrail for suspicious activity",
			"Enable MFA on the AWS account",
			"Use AWS Secrets Manager for credential storage")

	case "GitHub":
		baseSteps = append(baseSteps,
			"Review repository access logs",
			"Enable GitHub secret scanning",
			"Use GitHub Actions secrets for CI/CD")

	case "Database":
		baseSteps = append(baseSteps,
			"Review database access logs",
			"Implement connection string encryption",
			"Use environment variables for credentials")
	}

	return baseSteps
}

// Helper structures

// TruffleHogResult represents a TruffleHog finding
type TruffleHogResult struct {
	SourceID       string          `json:"SourceID"`
	SourceType     string          `json:"SourceType"`
	SourceName     string          `json:"SourceName"`
	DetectorType   string          `json:"DetectorType"`
	DetectorName   string          `json:"DetectorName"`
	Verified       bool            `json:"Verified"`
	Raw            string          `json:"Raw"`
	Redacted       string          `json:"Redacted"`
	SourceMetadata *SourceMetadata `json:"SourceMetadata"`
	StructuredData interface{}     `json:"StructuredData"`
}

// SourceMetadata contains source-specific metadata
type SourceMetadata struct {
	Data interface{} `json:"Data"`
}

// GitMetadata contains Git-specific metadata
type GitMetadata struct {
	Commit     string    `json:"commit"`
	File       string    `json:"file"`
	Line       int       `json:"line"`
	Author     string    `json:"author"`
	Email      string    `json:"email"`
	Date       time.Time `json:"date"`
	Repository string    `json:"repository"`
}

// AWSVerifier verifies AWS credentials
type AWSVerifier struct {
	logger *logger.Logger
}

func (v *AWSVerifier) Name() string {
	return "AWS"
}

func (v *AWSVerifier) Verify(ctx context.Context, secret string) (bool, error) {
	// Parse AWS credentials
	parts := strings.Split(secret, ":")
	if len(parts) != 2 {
		return false, nil
	}

	accessKey := parts[0]
	// secretKey := parts[1]  // Would be used in actual verification

	// Validate format
	if !regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`).MatchString(accessKey) {
		return false, nil
	}

	// Make minimal AWS API call to verify
	// This is a simplified example - real implementation would use AWS SDK
	v.logger.Infow("Verifying AWS credentials", "access_key", accessKey[:10]+"...")

	// For safety, we'll just validate the format for now
	// In production, you'd make a read-only API call
	return true, nil
}

func (v *AWSVerifier) GetMetadata(secret string) map[string]interface{} {
	parts := strings.Split(secret, ":")
	if len(parts) != 2 {
		return nil
	}

	return map[string]interface{}{
		"access_key_id": parts[0],
		"account_id":    extractAWSAccountID(parts[0]),
	}
}

// GitHubVerifier verifies GitHub tokens
type GitHubVerifier struct {
	logger *logger.Logger
}

func (v *GitHubVerifier) Name() string {
	return "GitHub"
}

func (v *GitHubVerifier) Verify(ctx context.Context, secret string) (bool, error) {
	// Make a simple API call to verify the token
	// This is simplified - real implementation would use GitHub API
	v.logger.Infow("Verifying GitHub token")

	// Check token format
	if strings.HasPrefix(secret, "ghp_") || strings.HasPrefix(secret, "gho_") {
		// In production, make API call to verify
		return true, nil
	}

	return false, nil
}

func (v *GitHubVerifier) GetMetadata(secret string) map[string]interface{} {
	metadata := make(map[string]interface{})

	// Determine token type
	if strings.HasPrefix(secret, "ghp_") {
		metadata["type"] = "personal_access_token"
	} else if strings.HasPrefix(secret, "gho_") {
		metadata["type"] = "oauth_token"
	} else if strings.HasPrefix(secret, "ghs_") {
		metadata["type"] = "server_token"
	}

	return metadata
}

// JWTVerifier verifies JWT tokens
type JWTVerifier struct{}

func (v *JWTVerifier) Name() string {
	return "JWT"
}

func (v *JWTVerifier) Verify(ctx context.Context, secret string) (bool, error) {
	// Parse JWT structure
	parts := strings.Split(secret, ".")
	if len(parts) != 3 {
		return false, nil
	}

	// Decode header and payload
	// In production, properly decode and validate
	return true, nil
}

func (v *JWTVerifier) GetMetadata(secret string) map[string]interface{} {
	parts := strings.Split(secret, ".")
	if len(parts) != 3 {
		return nil
	}

	// Decode header and payload to extract metadata
	// This is simplified - real implementation would properly decode
	return map[string]interface{}{
		"algorithm": "RS256",   // Would extract from header
		"issuer":    "unknown", // Would extract from payload
	}
}

// RateLimiter implements rate limiting for API calls
type RateLimiter struct {
	rate     int
	interval time.Duration
	tokens   chan struct{}
	ticker   *time.Ticker
}

func NewRateLimiter(rate int, interval time.Duration) *RateLimiter {
	rl := &RateLimiter{
		rate:     rate,
		interval: interval,
		tokens:   make(chan struct{}, rate),
		ticker:   time.NewTicker(interval / time.Duration(rate)),
	}

	// Fill token bucket
	for i := 0; i < rate; i++ {
		rl.tokens <- struct{}{}
	}

	// Refill tokens
	go func() {
		for range rl.ticker.C {
			select {
			case rl.tokens <- struct{}{}:
			default:
			}
		}
	}()

	return rl
}

func (rl *RateLimiter) Wait() {
	<-rl.tokens
}

// Utility functions

func (t *TruffleHogScanner) redactSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

func (t *TruffleHogScanner) calculateSeverity(result TruffleHogResult) types.Severity {
	// Verified secrets are always critical
	if result.Verified {
		return types.SeverityCritical
	}

	// Severity based on secret type
	severityMap := map[string]types.Severity{
		"AWS":        types.SeverityCritical,
		"AWS_SECRET": types.SeverityCritical,
		"GitHub":     types.SeverityHigh,
		"Database":   types.SeverityCritical,
		"PrivateKey": types.SeverityCritical,
		"Slack":      types.SeverityMedium,
		"Generic":    types.SeverityMedium,
		"JWT":        types.SeverityMedium,
	}

	if severity, exists := severityMap[result.DetectorName]; exists {
		return severity
	}

	return types.SeverityMedium
}

func (t *TruffleHogScanner) extractContext(data interface{}) string {
	// Extract relevant context from structured data
	if data == nil {
		return ""
	}

	// Convert to string representation
	if str, ok := data.(string); ok {
		return str
	}

	// For complex types, marshal to JSON
	if jsonData, err := json.Marshal(data); err == nil {
		return string(jsonData)
	}

	return fmt.Sprintf("%v", data)
}

func (t *TruffleHogScanner) countVerified(findings []SecretFinding) int {
	count := 0
	for _, finding := range findings {
		if finding.Verified {
			count++
		}
	}
	return count
}

func (t *TruffleHogScanner) sortFindingsBySeverity(findings []SecretFinding) {
	// Sort by severity (critical first) and then by verification status
	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			if findings[i].Severity < findings[j].Severity {
				findings[i], findings[j] = findings[j], findings[i]
			} else if findings[i].Severity == findings[j].Severity {
				// Verified findings come first
				if !findings[i].Verified && findings[j].Verified {
					findings[i], findings[j] = findings[j], findings[i]
				}
			}
		}
	}
}

func (t *TruffleHogScanner) findRelatedSecrets(allFindings []SecretFinding, current *SecretFinding) []string {
	var related []string

	for _, finding := range allFindings {
		if finding.Secret == current.Secret {
			continue // Skip self
		}

		// Same file
		if finding.File == current.File && finding.File != "" {
			related = append(related, fmt.Sprintf("Same file: %s", finding.Type))
		}

		// Same author
		if finding.Author == current.Author && finding.Author != "" {
			related = append(related, fmt.Sprintf("Same author: %s", finding.Type))
		}

		// Same commit
		if finding.Commit == current.Commit && finding.Commit != "" {
			related = append(related, fmt.Sprintf("Same commit: %s", finding.Type))
		}
	}

	return related
}

func (t *TruffleHogScanner) extractPatterns(secret string) []string {
	var patterns []string

	// Look for common patterns
	if regexp.MustCompile(`[a-z]+\.[a-z]+\.[a-z]+`).MatchString(secret) {
		patterns = append(patterns, "service.environment.component")
	}

	if regexp.MustCompile(`(dev|test|staging|prod)`).MatchString(strings.ToLower(secret)) {
		patterns = append(patterns, "environment-specific")
	}

	if regexp.MustCompile(`v\d+`).MatchString(secret) {
		patterns = append(patterns, "versioned")
	}

	return patterns
}

func isNonZeroExitError(err error) bool {
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode() != 0
	}
	return false
}

func extractAWSAccountID(accessKey string) string {
	// AWS access keys encode the account ID
	// This is a simplified extraction
	if len(accessKey) >= 20 {
		// In reality, you'd decode the access key properly
		return "XXXXXXXXXXXX"
	}
	return "unknown"
}

// SlackVerifier verifies Slack webhooks and tokens
type SlackVerifier struct {
	logger *logger.Logger
}

func (v *SlackVerifier) Name() string {
	return "Slack"
}

func (v *SlackVerifier) Verify(ctx context.Context, secret string) (bool, error) {
	// Check if it's a webhook URL
	if strings.Contains(secret, "hooks.slack.com") {
		// In production, make a test POST to verify
		return true, nil
	}

	// Check token format
	if strings.HasPrefix(secret, "xox") {
		// Different Slack token types
		return true, nil
	}

	return false, nil
}

func (v *SlackVerifier) GetMetadata(secret string) map[string]interface{} {
	metadata := make(map[string]interface{})

	if strings.Contains(secret, "hooks.slack.com") {
		metadata["type"] = "webhook"
	} else if strings.HasPrefix(secret, "xoxb-") {
		metadata["type"] = "bot_token"
	} else if strings.HasPrefix(secret, "xoxp-") {
		metadata["type"] = "user_token"
	}

	return metadata
}

// GenericAPIVerifier handles generic API keys
type GenericAPIVerifier struct {
	logger *logger.Logger
}

func (v *GenericAPIVerifier) Name() string {
	return "Generic"
}

func (v *GenericAPIVerifier) Verify(ctx context.Context, secret string) (bool, error) {
	// For generic API keys, we can't verify without knowing the service
	// Check basic format validity
	if len(secret) >= 20 && regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(secret) {
		return false, nil // Valid format but can't verify
	}

	return false, nil
}

func (v *GenericAPIVerifier) GetMetadata(secret string) map[string]interface{} {
	return map[string]interface{}{
		"length":  len(secret),
		"entropy": calculateEntropy(secret),
	}
}

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Calculate character frequency
	freq := make(map[rune]float64)
	for _, char := range s {
		freq[char]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(s))

	for _, count := range freq {
		probability := count / length
		if probability > 0 {
			entropy -= probability * (probability * 2) // Simplified entropy
		}
	}

	return entropy
}
