// pkg/passive/coderepo.go
package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// CodeIntel provides code repository intelligence gathering
type CodeIntel struct {
	logger         *logger.Logger
	httpClient     *http.Client
	githubToken    string
	gitlabToken    string
	bitbucketToken string
	strategies     []SearchStrategy
	secretScanner  *SecretScanner
	configAnalyzer *ConfigAnalyzer
}

// SearchStrategy represents a code search strategy
type SearchStrategy interface {
	Name() string
	Search(ctx context.Context, target string) ([]CodeSearchResult, error)
	Priority() int
}

// CodeSearchResult represents a result from code search
type CodeSearchResult struct {
	Platform    string
	Repository  string
	FilePath    string
	LineNumber  int
	Content     string
	CommitHash  string
	Author      string
	AuthorEmail string
	Timestamp   time.Time
	URL         string
	IsPrivate   bool
}

// NewCodeIntel creates a new code repository intelligence module
func NewCodeIntel(logger *logger.Logger, githubToken, gitlabToken, bitbucketToken string) *CodeIntel {
	ci := &CodeIntel{
		logger:         logger,
		httpClient:     &http.Client{Timeout: 30 * time.Second},
		githubToken:    githubToken,
		gitlabToken:    gitlabToken,
		bitbucketToken: bitbucketToken,
		secretScanner:  NewSecretScanner(),
		configAnalyzer: NewConfigAnalyzer(),
	}

	// Initialize search strategies
	ci.strategies = []SearchStrategy{
		NewDomainMentionStrategy(ci),
		NewAPIKeyPatternStrategy(ci),
		NewEmployeeCommitStrategy(ci),
		NewConfigFileStrategy(ci),
		NewInfrastructureStrategy(ci),
		NewHardcodedCredsStrategy(ci),
		NewInternalURLStrategy(ci),
	}

	return ci
}

// AnalyzeRepository performs deep analysis on a discovered repository
func (c *CodeIntel) AnalyzeRepository(repo Repository) []Finding {
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Get repository content
	files, err := c.getRepositoryFiles(repo)
	if err != nil {
		c.logger.Error("Failed to get repository files", "repo", repo.Name, "error", err)
		return findings
	}

	// Analyze files in parallel
	for _, file := range files {
		wg.Add(1)
		go func(f RepositoryFile) {
			defer wg.Done()

			// Skip binary files
			if c.isBinaryFile(f.Path) {
				return
			}

			// Get file content
			content, err := c.getFileContent(repo, f)
			if err != nil {
				return
			}

			// Run analyzers
			fileFindings := c.analyzeFile(repo, f, content)

			mu.Lock()
			findings = append(findings, fileFindings...)
			mu.Unlock()
		}(file)

		// Limit concurrent analysis
		if len(files) > 50 && len(files)%10 == 0 {
			wg.Wait()
		}
	}

	wg.Wait()

	// Deduplicate and enrich findings
	findings = c.deduplicateFindings(findings)
	c.enrichFindings(findings, repo)

	return findings
}

// SearchAllPlatforms searches across multiple code platforms
func (c *CodeIntel) SearchAllPlatforms(ctx context.Context, target string) ([]CodeSearchResult, error) {
	var allResults []CodeSearchResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Execute all search strategies
	for _, strategy := range c.strategies {
		wg.Add(1)
		go func(s SearchStrategy) {
			defer wg.Done()

			results, err := s.Search(ctx, target)
			if err != nil {
				c.logger.Error("Search strategy failed",
					"strategy", s.Name(),
					"target", target,
					"error", err)
				return
			}

			mu.Lock()
			allResults = append(allResults, results...)
			mu.Unlock()

			c.logger.Info("Search strategy completed",
				"strategy", s.Name(),
				"results", len(results))
		}(strategy)
	}

	wg.Wait()

	// Sort by relevance
	c.sortResultsByRelevance(allResults)

	return allResults, nil
}

// analyzeFile performs comprehensive analysis on a single file
func (c *CodeIntel) analyzeFile(repo Repository, file RepositoryFile, content string) []Finding {
	var findings []Finding

	// Secret scanning
	secrets := c.secretScanner.ScanContent(content, file.Path)
	for _, secret := range secrets {
		findings = append(findings, Finding{
			Type:        "exposed_secret",
			Severity:    secret.Severity,
			Title:       fmt.Sprintf("%s found in %s", secret.Type, file.Path),
			Description: fmt.Sprintf("Exposed %s in repository %s", secret.Type, repo.Name),
			Evidence: map[string]interface{}{
				"secret_type": secret.Type,
				"file_path":   file.Path,
				"line_number": secret.LineNumber,
				"commit_hash": file.LastCommit,
				"redacted":    secret.RedactedValue,
			},
			Repository: repo.Name,
			URL:        file.URL,
			Timestamp:  time.Now(),
		})
	}

	// Configuration analysis
	if c.isConfigFile(file.Path) {
		configFindings := c.configAnalyzer.AnalyzeConfig(content, file.Path)
		for _, cf := range configFindings {
			findings = append(findings, Finding{
				Type:        "configuration_issue",
				Severity:    cf.Severity,
				Title:       cf.Title,
				Description: cf.Description,
				Evidence: map[string]interface{}{
					"file_path":   file.Path,
					"issue_type":  cf.Type,
					"line_number": cf.LineNumber,
					"context":     cf.Context,
				},
				Repository: repo.Name,
				URL:        file.URL,
				Timestamp:  time.Now(),
			})
		}
	}

	// Infrastructure disclosure
	infraFindings := c.findInfrastructureInfo(content, file.Path)
	findings = append(findings, infraFindings...)

	// Internal URLs and endpoints
	urlFindings := c.findInternalURLs(content, file.Path)
	findings = append(findings, urlFindings...)

	// Database connection strings
	dbFindings := c.findDatabaseConnections(content, file.Path)
	findings = append(findings, dbFindings...)

	return findings
}

// DomainMentionStrategy searches for domain mentions in code
type DomainMentionStrategy struct {
	codeIntel *CodeIntel
}

func NewDomainMentionStrategy(ci *CodeIntel) *DomainMentionStrategy {
	return &DomainMentionStrategy{codeIntel: ci}
}

func (d *DomainMentionStrategy) Name() string {
	return "domain_mentions"
}

func (d *DomainMentionStrategy) Priority() int {
	return 90
}

func (d *DomainMentionStrategy) Search(ctx context.Context, target string) ([]CodeSearchResult, error) {
	var results []CodeSearchResult

	// GitHub search
	if d.codeIntel.githubToken != "" {
		githubResults, err := d.searchGitHub(ctx, target)
		if err == nil {
			results = append(results, githubResults...)
		}
	}

	// GitLab search
	if d.codeIntel.gitlabToken != "" {
		gitlabResults, err := d.searchGitLab(ctx, target)
		if err == nil {
			results = append(results, gitlabResults...)
		}
	}

	// Public Gists
	gistResults, err := d.searchGists(ctx, target)
	if err == nil {
		results = append(results, gistResults...)
	}

	return results, nil
}

func (d *DomainMentionStrategy) searchGitHub(ctx context.Context, domain string) ([]CodeSearchResult, error) {
	var results []CodeSearchResult

	// Search for domain mentions
	queries := []string{
		fmt.Sprintf(`"%s"`, domain),
		fmt.Sprintf(`"%s" password`, domain),
		fmt.Sprintf(`"%s" api_key`, domain),
		fmt.Sprintf(`"%s" token`, domain),
		fmt.Sprintf(`"%s" secret`, domain),
		fmt.Sprintf(`host:"%s"`, domain),
		fmt.Sprintf(`hostname:"%s"`, domain),
	}

	for _, query := range queries {
		searchURL := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=100",
			strings.ReplaceAll(query, " ", "+"))

		req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("Authorization", "token "+d.codeIntel.githubToken)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := d.codeIntel.httpClient.Do(req)
		if err != nil {
			continue
		}
		defer httpclient.CloseBody(resp)

		if resp.StatusCode == 403 {
			// Rate limited
			d.codeIntel.logger.Warn("GitHub rate limit hit")
			break
		}

		var searchResponse GitHubSearchResponse
		if err := json.NewDecoder(resp.Body).Decode(&searchResponse); err != nil {
			continue
		}

		for _, item := range searchResponse.Items {
			result := CodeSearchResult{
				Platform:   "github",
				Repository: item.Repository.FullName,
				FilePath:   item.Path,
				URL:        item.HTMLURL,
				Content:    d.getCodeSnippet(item),
			}

			// Get additional details
			if details, err := d.getFileDetails(ctx, item); err == nil {
				result.CommitHash = details.CommitHash
				result.Author = details.Author
				result.AuthorEmail = details.AuthorEmail
				result.Timestamp = details.Timestamp
			}

			results = append(results, result)
		}
	}

	return results, nil
}

// SecretScanner scans for secrets in code
type SecretScanner struct {
	patterns []SecretPattern
}

func NewSecretScanner() *SecretScanner {
	return &SecretScanner{
		patterns: getSecretPatterns(),
	}
}

func (s *SecretScanner) ScanContent(content, filePath string) []DetectedSecret {
	var secrets []DetectedSecret
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		// Skip comments
		if s.isComment(line, filePath) {
			continue
		}

		for _, pattern := range s.patterns {
			if matches := pattern.Regex.FindStringSubmatch(line); len(matches) > 0 {
				secret := DetectedSecret{
					Type:          pattern.Name,
					Value:         matches[len(matches)-1], // Last capture group
					RedactedValue: s.redactSecret(matches[len(matches)-1]),
					FilePath:      filePath,
					LineNumber:    lineNum + 1,
					Line:          line,
					Severity:      pattern.Severity,
					Confidence:    s.calculateConfidence(matches[len(matches)-1], pattern),
				}

				// Skip low confidence matches
				if secret.Confidence > 0.6 {
					secrets = append(secrets, secret)
				}
			}
		}
	}

	return secrets
}

func (s *SecretScanner) isComment(line, filePath string) bool {
	trimmed := strings.TrimSpace(line)

	// Language-specific comment detection
	ext := strings.ToLower(getFileExtension(filePath))

	switch ext {
	case ".go":
		return strings.HasPrefix(trimmed, "//")
	case ".py":
		return strings.HasPrefix(trimmed, "#")
	case ".js", ".ts":
		return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*")
	case ".java", ".c", ".cpp":
		return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*")
	case ".rb":
		return strings.HasPrefix(trimmed, "#")
	case ".php":
		return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*")
	default:
		return strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//")
	}
}

// ConfigAnalyzer analyzes configuration files
type ConfigAnalyzer struct {
	patterns []ConfigPattern
}

type ConfigPattern struct {
	Name        string
	FilePattern *regexp.Regexp
	Issues      []ConfigIssue
}

type ConfigIssue struct {
	Pattern     *regexp.Regexp
	Type        string
	Title       string
	Description string
	Severity    string
}

func NewConfigAnalyzer() *ConfigAnalyzer {
	return &ConfigAnalyzer{
		patterns: getConfigPatterns(),
	}
}

func (c *ConfigAnalyzer) AnalyzeConfig(content, filePath string) []ConfigFinding {
	var findings []ConfigFinding

	// Determine config type
	configType := c.detectConfigType(filePath, content)

	// Apply relevant patterns
	for _, pattern := range c.patterns {
		if pattern.FilePattern.MatchString(filePath) {
			for _, issue := range pattern.Issues {
				if matches := issue.Pattern.FindAllStringIndex(content, -1); len(matches) > 0 {
					for _, match := range matches {
						lineNumber := c.getLineNumber(content, match[0])
						context := c.extractContext(content, match[0], match[1])

						findings = append(findings, ConfigFinding{
							Type:        issue.Type,
							Title:       issue.Title,
							Description: issue.Description,
							Severity:    issue.Severity,
							FilePath:    filePath,
							LineNumber:  lineNumber,
							Context:     context,
							ConfigType:  configType,
						})
					}
				}
			}
		}
	}

	// Check for specific misconfigurations
	findings = append(findings, c.checkDatabaseConfigs(content, filePath)...)
	findings = append(findings, c.checkAPIConfigs(content, filePath)...)
	findings = append(findings, c.checkSecurityHeaders(content, filePath)...)
	findings = append(findings, c.checkCloudConfigs(content, filePath)...)

	return findings
}

// Helper structures and functions

type GitHubSearchResponse struct {
	TotalCount int                `json:"total_count"`
	Items      []GitHubSearchItem `json:"items"`
}

type GitHubSearchItem struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	HTMLURL    string `json:"html_url"`
	Repository struct {
		FullName string `json:"full_name"`
		Private  bool   `json:"private"`
	} `json:"repository"`
	TextMatches []TextMatch `json:"text_matches"`
}

type TextMatch struct {
	Fragment string `json:"fragment"`
	Matches  []struct {
		Text    string `json:"text"`
		Indices []int  `json:"indices"`
	} `json:"matches"`
}

type Repository struct {
	Name        string
	Platform    string
	Owner       string
	IsPrivate   bool
	URL         string
	CloneURL    string
	Language    string
	LastUpdated time.Time
}

type RepositoryFile struct {
	Path       string
	Size       int64
	LastCommit string
	URL        string
}

type Finding struct {
	Type        string
	Severity    string
	Title       string
	Description string
	Evidence    map[string]interface{}
	Repository  string
	URL         string
	Timestamp   time.Time
}

type DetectedSecret struct {
	Type          string
	Value         string
	RedactedValue string
	FilePath      string
	LineNumber    int
	Line          string
	Severity      string
	Confidence    float64
}

type ConfigFinding struct {
	Type        string
	Title       string
	Description string
	Severity    string
	FilePath    string
	LineNumber  int
	Context     string
	ConfigType  string
}

type SecretPattern struct {
	Name     string
	Regex    *regexp.Regexp
	Severity string
	Entropy  float64
}

// getSecretPatterns returns patterns for detecting secrets
func getSecretPatterns() []SecretPattern {
	return []SecretPattern{
		{
			Name:     "aws_access_key",
			Regex:    regexp.MustCompile(`(?i)aws[_\-\s]*access[_\-\s]*key[_\-\s]*id[^:=]*[:=][^A-Z0-9]*([A-Z0-9]{20})`),
			Severity: "CRITICAL",
			Entropy:  3.5,
		},
		{
			Name:     "aws_secret_key",
			Regex:    regexp.MustCompile(`(?i)aws[_\-\s]*secret[_\-\s]*access[_\-\s]*key[^:=]*[:=][^A-Za-z0-9+/]*([A-Za-z0-9+/]{40})`),
			Severity: "CRITICAL",
			Entropy:  4.0,
		},
		{
			Name:     "github_token",
			Regex:    regexp.MustCompile(`(?i)github[_\-\s]*token[^:=]*[:=][^a-zA-Z0-9]*([a-zA-Z0-9]{40})`),
			Severity: "HIGH",
			Entropy:  3.5,
		},
		{
			Name:     "private_key",
			Regex:    regexp.MustCompile(`-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----`),
			Severity: "CRITICAL",
			Entropy:  0.0,
		},
		{
			Name:     "api_key_generic",
			Regex:    regexp.MustCompile(`(?i)api[_\-\s]*key[^:=]*[:=][^a-zA-Z0-9]*([a-zA-Z0-9_\-]{20,})`),
			Severity: "HIGH",
			Entropy:  3.0,
		},
		{
			Name:     "slack_webhook",
			Regex:    regexp.MustCompile(`(https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+)`),
			Severity: "MEDIUM",
			Entropy:  0.0,
		},
		{
			Name:     "google_api_key",
			Regex:    regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
			Severity: "HIGH",
			Entropy:  3.5,
		},
		{
			Name:     "stripe_key",
			Regex:    regexp.MustCompile(`(?i)stripe[^:=]*[:=][^a-zA-Z0-9]*(sk_live_[a-zA-Z0-9]{24,}|pk_live_[a-zA-Z0-9]{24,})`),
			Severity: "CRITICAL",
			Entropy:  3.5,
		},
		{
			Name:     "jwt_token",
			Regex:    regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
			Severity: "MEDIUM",
			Entropy:  0.0,
		},
		{
			Name:     "database_connection",
			Regex:    regexp.MustCompile(`(?i)(mongodb|postgres|mysql|redis)://[^:]+:[^@]+@[^/\s]+`),
			Severity: "CRITICAL",
			Entropy:  0.0,
		},
	}
}

// getConfigPatterns returns patterns for configuration issues
func getConfigPatterns() []ConfigPattern {
	return []ConfigPattern{
		{
			Name:        "docker_compose",
			FilePattern: regexp.MustCompile(`docker-compose.*\.ya?ml$`),
			Issues: []ConfigIssue{
				{
					Pattern:     regexp.MustCompile(`(?i)ports:\s*\n\s*-\s*["']?3306:3306`),
					Type:        "exposed_database",
					Title:       "MySQL Database Exposed to Internet",
					Description: "MySQL port 3306 is exposed to 0.0.0.0, making it accessible from the internet",
					Severity:    "CRITICAL",
				},
				{
					Pattern:     regexp.MustCompile(`(?i)MYSQL_ROOT_PASSWORD:\s*["']?[^"'\s]+`),
					Type:        "hardcoded_password",
					Title:       "Hardcoded MySQL Root Password",
					Description: "MySQL root password is hardcoded in configuration file",
					Severity:    "HIGH",
				},
			},
		},
		{
			Name:        "kubernetes",
			FilePattern: regexp.MustCompile(`.*\.ya?ml$`),
			Issues: []ConfigIssue{
				{
					Pattern:     regexp.MustCompile(`(?i)kind:\s*Secret[\s\S]*?data:`),
					Type:        "base64_secret",
					Title:       "Base64 Encoded Secrets",
					Description: "Secrets are only base64 encoded, not encrypted",
					Severity:    "MEDIUM",
				},
				{
					Pattern:     regexp.MustCompile(`(?i)privileged:\s*true`),
					Type:        "privileged_container",
					Title:       "Privileged Container",
					Description: "Container runs in privileged mode with full host access",
					Severity:    "HIGH",
				},
			},
		},
		{
			Name:        "terraform",
			FilePattern: regexp.MustCompile(`.*\.tf$`),
			Issues: []ConfigIssue{
				{
					Pattern:     regexp.MustCompile(`(?i)access_key\s*=\s*"[^"]+"`),
					Type:        "hardcoded_credentials",
					Title:       "Hardcoded AWS Credentials",
					Description: "AWS access keys are hardcoded in Terraform configuration",
					Severity:    "CRITICAL",
				},
				{
					Pattern:     regexp.MustCompile(`(?i)ingress\s*{\s*from_port\s*=\s*0\s*to_port\s*=\s*65535`),
					Type:        "overly_permissive_sg",
					Title:       "Overly Permissive Security Group",
					Description: "Security group allows all traffic from all ports",
					Severity:    "HIGH",
				},
			},
		},
	}
}

// Utility functions

func (c *CodeIntel) redactSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

func (c *CodeIntel) calculateConfidence(value string, pattern SecretPattern) float64 {
	confidence := 0.5

	// Check entropy if required
	if pattern.Entropy > 0 {
		entropy := c.calculateEntropy(value)
		if entropy >= pattern.Entropy {
			confidence += 0.3
		}
	}

	// Check for obvious test/example values
	testPatterns := []string{
		"test", "example", "demo", "sample", "dummy",
		"xxx", "placeholder", "changeme", "your-",
	}

	valueLower := strings.ToLower(value)
	for _, test := range testPatterns {
		if strings.Contains(valueLower, test) {
			confidence -= 0.5
			break
		}
	}

	// Boost confidence for production indicators
	if strings.Contains(valueLower, "prod") || strings.Contains(valueLower, "live") {
		confidence += 0.2
	}

	return confidence
}

func (c *CodeIntel) calculateEntropy(s string) float64 {
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
			entropy -= probability * (probability * 2) // Simplified entropy calculation
		}
	}

	return entropy
}

func getFileExtension(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) > 1 {
		return "." + parts[len(parts)-1]
	}
	return ""
}

// Missing strategy implementations

// APIKeyPatternStrategy searches for API key patterns
type APIKeyPatternStrategy struct {
	codeIntel *CodeIntel
}

func NewAPIKeyPatternStrategy(ci *CodeIntel) *APIKeyPatternStrategy {
	return &APIKeyPatternStrategy{codeIntel: ci}
}

func (a *APIKeyPatternStrategy) Name() string {
	return "api_key_pattern"
}

func (a *APIKeyPatternStrategy) Priority() int {
	return 90
}

func (a *APIKeyPatternStrategy) Search(ctx context.Context, target string) ([]CodeSearchResult, error) {
	return []CodeSearchResult{}, nil
}

// EmployeeCommitStrategy searches for commits by known employees
type EmployeeCommitStrategy struct {
	codeIntel *CodeIntel
}

func NewEmployeeCommitStrategy(ci *CodeIntel) *EmployeeCommitStrategy {
	return &EmployeeCommitStrategy{codeIntel: ci}
}

func (e *EmployeeCommitStrategy) Name() string {
	return "employee_commit"
}

func (e *EmployeeCommitStrategy) Priority() int {
	return 80
}

func (e *EmployeeCommitStrategy) Search(ctx context.Context, target string) ([]CodeSearchResult, error) {
	return []CodeSearchResult{}, nil
}

// ConfigFileStrategy searches for configuration files
type ConfigFileStrategy struct {
	codeIntel *CodeIntel
}

func NewConfigFileStrategy(ci *CodeIntel) *ConfigFileStrategy {
	return &ConfigFileStrategy{codeIntel: ci}
}

func (c *ConfigFileStrategy) Name() string {
	return "config_file"
}

func (c *ConfigFileStrategy) Priority() int {
	return 70
}

func (c *ConfigFileStrategy) Search(ctx context.Context, target string) ([]CodeSearchResult, error) {
	return []CodeSearchResult{}, nil
}

// InfrastructureStrategy searches for infrastructure-related code
type InfrastructureStrategy struct {
	codeIntel *CodeIntel
}

func NewInfrastructureStrategy(ci *CodeIntel) *InfrastructureStrategy {
	return &InfrastructureStrategy{codeIntel: ci}
}

func (i *InfrastructureStrategy) Name() string {
	return "infrastructure"
}

func (i *InfrastructureStrategy) Priority() int {
	return 60
}

func (i *InfrastructureStrategy) Search(ctx context.Context, target string) ([]CodeSearchResult, error) {
	return []CodeSearchResult{}, nil
}

// HardcodedCredsStrategy searches for hardcoded credentials
type HardcodedCredsStrategy struct {
	codeIntel *CodeIntel
}

func NewHardcodedCredsStrategy(ci *CodeIntel) *HardcodedCredsStrategy {
	return &HardcodedCredsStrategy{codeIntel: ci}
}

func (h *HardcodedCredsStrategy) Name() string {
	return "hardcoded_creds"
}

func (h *HardcodedCredsStrategy) Priority() int {
	return 95
}

func (h *HardcodedCredsStrategy) Search(ctx context.Context, target string) ([]CodeSearchResult, error) {
	return []CodeSearchResult{}, nil
}

// InternalURLStrategy searches for internal URLs
type InternalURLStrategy struct {
	codeIntel *CodeIntel
}

func NewInternalURLStrategy(ci *CodeIntel) *InternalURLStrategy {
	return &InternalURLStrategy{codeIntel: ci}
}

func (i *InternalURLStrategy) Name() string {
	return "internal_url"
}

func (i *InternalURLStrategy) Priority() int {
	return 50
}

func (i *InternalURLStrategy) Search(ctx context.Context, target string) ([]CodeSearchResult, error) {
	return []CodeSearchResult{}, nil
}

// Missing method implementations

func (s *SecretScanner) redactSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

func (s *SecretScanner) calculateConfidence(value string, pattern SecretPattern) float64 {
	confidence := 0.5

	// Check entropy if required
	if pattern.Entropy > 0 {
		entropy := s.calculateEntropy(value)
		if entropy >= pattern.Entropy {
			confidence += 0.3
		}
	}

	// Check for obvious test/example values
	testPatterns := []string{
		"test", "example", "demo", "sample", "dummy",
		"xxx", "placeholder", "changeme", "your-",
	}

	valueLower := strings.ToLower(value)
	for _, test := range testPatterns {
		if strings.Contains(valueLower, test) {
			confidence -= 0.5
			break
		}
	}

	// Boost confidence for production indicators
	if strings.Contains(valueLower, "prod") || strings.Contains(valueLower, "live") {
		confidence += 0.2
	}

	return confidence
}

func (s *SecretScanner) calculateEntropy(str string) float64 {
	if len(str) == 0 {
		return 0
	}

	// Calculate character frequency
	freq := make(map[rune]float64)
	for _, char := range str {
		freq[char]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(str))

	for _, count := range freq {
		probability := count / length
		if probability > 0 {
			entropy -= probability * (probability * 2) // Simplified entropy calculation
		}
	}

	return entropy
}

func (c *CodeIntel) getFileContent(repo Repository, file RepositoryFile) (string, error) {
	// Placeholder implementation for getting file content
	return "", nil
}

func (c *CodeIntel) deduplicateFindings(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var unique []Finding

	for _, finding := range findings {
		key := fmt.Sprintf("%s-%s-%s", finding.Type, finding.Repository, finding.URL)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, finding)
		}
	}

	return unique
}

func (c *CodeIntel) enrichFindings(findings []Finding, repo Repository) {
	// Placeholder for finding enrichment
}

func (c *CodeIntel) sortResultsByRelevance(results []CodeSearchResult) {
	// Simple sort by platform priority
	// Implementation would be more sophisticated in practice
}

func (c *CodeIntel) isConfigFile(path string) bool {
	configFiles := []string{
		".yml", ".yaml", ".json", ".toml", ".ini", ".cfg",
		".conf", ".config", "dockerfile", ".tf", ".env",
	}

	pathLower := strings.ToLower(path)
	for _, ext := range configFiles {
		if strings.HasSuffix(pathLower, ext) || strings.Contains(pathLower, ext) {
			return true
		}
	}

	return false
}

func (c *CodeIntel) findInfrastructureInfo(content, filePath string) []Finding {
	return []Finding{}
}

func (c *CodeIntel) findInternalURLs(content, filePath string) []Finding {
	return []Finding{}
}

func (c *CodeIntel) findDatabaseConnections(content, filePath string) []Finding {
	return []Finding{}
}

func (c *ConfigAnalyzer) detectConfigType(filePath, content string) string {
	if strings.HasSuffix(filePath, ".yml") || strings.HasSuffix(filePath, ".yaml") {
		return "yaml"
	} else if strings.HasSuffix(filePath, ".json") {
		return "json"
	} else if strings.HasSuffix(filePath, ".toml") {
		return "toml"
	}
	return "unknown"
}

func (c *ConfigAnalyzer) getLineNumber(content string, position int) int {
	return strings.Count(content[:position], "\n") + 1
}

func (c *ConfigAnalyzer) extractContext(content string, start, end int) string {
	contextStart := start - 50
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := end + 50
	if contextEnd > len(content) {
		contextEnd = len(content)
	}
	return content[contextStart:contextEnd]
}

func (c *ConfigAnalyzer) checkDatabaseConfigs(content, filePath string) []ConfigFinding {
	return []ConfigFinding{}
}

func (c *ConfigAnalyzer) checkAPIConfigs(content, filePath string) []ConfigFinding {
	return []ConfigFinding{}
}

func (c *ConfigAnalyzer) checkSecurityHeaders(content, filePath string) []ConfigFinding {
	return []ConfigFinding{}
}

func (c *ConfigAnalyzer) checkCloudConfigs(content, filePath string) []ConfigFinding {
	return []ConfigFinding{}
}

func (d *DomainMentionStrategy) searchGitLab(ctx context.Context, target string) ([]CodeSearchResult, error) {
	return []CodeSearchResult{}, nil
}

func (d *DomainMentionStrategy) searchGists(ctx context.Context, target string) ([]CodeSearchResult, error) {
	return []CodeSearchResult{}, nil
}

func (d *DomainMentionStrategy) getCodeSnippet(item GitHubSearchItem) string {
	if len(item.TextMatches) > 0 {
		return item.TextMatches[0].Fragment
	}
	return ""
}

func (d *DomainMentionStrategy) getFileDetails(ctx context.Context, item GitHubSearchItem) (struct {
	CommitHash  string
	Author      string
	AuthorEmail string
	Timestamp   time.Time
}, error) {
	return struct {
		CommitHash  string
		Author      string
		AuthorEmail string
		Timestamp   time.Time
	}{}, nil
}
