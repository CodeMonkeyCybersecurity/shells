// pkg/fuzzing/scanner.go
package fuzzing

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// Scanner implements the fuzzing scanner for shells
type Scanner struct {
	fuzzer *SmartFuzzer
	config ScannerConfig
	logger Logger
}

// ScannerConfig holds scanner configuration
type ScannerConfig struct {
	Mode           string // directory, parameter, vhost, subdomain
	Wordlist       string
	Threads        int
	Timeout        time.Duration
	Extensions     []string
	StatusCodes    []int
	RateLimit      int
	SmartMode      bool
	RecursionDepth int
	CustomHeaders  map[string]string
}

// NewScanner creates a new fuzzing scanner
func NewScanner(config ScannerConfig, logger Logger) *Scanner {
	fuzzerConfig := FuzzerConfig{
		Threads:           config.Threads,
		Timeout:           config.Timeout,
		Extensions:        config.Extensions,
		StatusCodeFilters: config.StatusCodes,
		RateLimit:         config.RateLimit,
		SmartMode:         config.SmartMode,
		RecursionDepth:    config.RecursionDepth,
		CustomHeaders:     config.CustomHeaders,
		WordlistDir:       "/opt/shells/wordlists",
		UserAgent:         "shells-fuzzer/1.0",
		FollowRedirects:   true,
	}

	return &Scanner{
		fuzzer: NewSmartFuzzer(fuzzerConfig, logger),
		config: config,
		logger: logger,
	}
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return "fuzzer"
}

// Scan performs fuzzing against the target
func (s *Scanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	s.logger.Info("Starting fuzzing scan", "target", target, "mode", s.config.Mode)

	var findings []types.Finding

	switch s.config.Mode {
	case "directory":
		results, err := s.scanDirectories(ctx, target)
		if err != nil {
			return nil, err
		}
		findings = s.convertToFindings(results, "DIRECTORY_DISCOVERY")

	case "parameter":
		results, err := s.scanParameters(ctx, target)
		if err != nil {
			return nil, err
		}
		findings = s.convertToFindings(results, "PARAMETER_DISCOVERY")

	case "vhost":
		results, err := s.scanVHosts(ctx, target)
		if err != nil {
			return nil, err
		}
		findings = s.convertToFindings(results, "VHOST_DISCOVERY")

	default:
		return nil, fmt.Errorf("unsupported fuzzing mode: %s", s.config.Mode)
	}

	s.logger.Info("Fuzzing scan completed", "target", target, "findings", len(findings))
	return findings, nil
}

func (s *Scanner) scanDirectories(ctx context.Context, target string) ([]FuzzResult, error) {
	// Use default wordlist for directory fuzzing
	fuzzer := NewFuzzer(s.fuzzer.config, s.logger)
	return fuzzer.DirectoryFuzzing(ctx, target, "")
}

func (s *Scanner) scanParameters(ctx context.Context, target string) ([]FuzzResult, error) {
	// Use default wordlist for parameter fuzzing
	fuzzer := NewFuzzer(s.fuzzer.config, s.logger)
	return fuzzer.ParameterFuzzing(ctx, target, "")
}

func (s *Scanner) scanVHosts(ctx context.Context, target string) ([]FuzzResult, error) {
	// Use default wordlist for vhost fuzzing
	fuzzer := NewFuzzer(s.fuzzer.config, s.logger)
	return fuzzer.VHostFuzzing(ctx, target, "")
}

func (s *Scanner) loadWordlist() ([]string, error) {
	// Default wordlists based on mode
	wordlistFile := s.config.Wordlist
	if wordlistFile == "" {
		switch s.config.Mode {
		case "directory":
			wordlistFile = filepath.Join(s.fuzzer.config.WordlistDir, "directories.txt")
		case "parameter":
			wordlistFile = filepath.Join(s.fuzzer.config.WordlistDir, "parameters.txt")
		case "vhost":
			wordlistFile = filepath.Join(s.fuzzer.config.WordlistDir, "subdomains.txt")
		default:
			wordlistFile = filepath.Join(s.fuzzer.config.WordlistDir, "common.txt")
		}
	}

	// Return default wordlist if file doesn't exist
	return s.getDefaultWordlist(), nil
}

func (s *Scanner) getDefaultWordlist() []string {
	switch s.config.Mode {
	case "directory":
		return []string{
			"admin", "api", "app", "assets", "backup", "config", "data",
			"dev", "docs", "downloads", "files", "images", "logs", "media",
			"public", "scripts", "src", "static", "temp", "test", "tmp",
			"uploads", "vendor", "wp-admin", "wp-content", "wp-includes",
		}
	case "parameter":
		return []string{
			"id", "user", "admin", "page", "file", "dir", "action", "cmd",
			"exec", "query", "search", "filter", "sort", "order", "limit",
			"offset", "token", "key", "secret", "password", "username",
		}
	case "vhost":
		return []string{
			"www", "mail", "ftp", "admin", "api", "app", "dev", "test",
			"staging", "prod", "demo", "blog", "shop", "store", "support",
		}
	default:
		return []string{"admin", "api", "test", "dev", "staging"}
	}
}

func (s *Scanner) convertToFindings(results []FuzzResult, findingType string) []types.Finding {
	var findings []types.Finding

	for _, result := range results {
		severity := s.getSeverity(result)

		finding := types.Finding{
			Tool:        "fuzzer",
			Type:        findingType,
			Severity:    severity,
			Title:       s.getTitle(result, findingType),
			Description: s.getDescription(result, findingType),
			Evidence:    fmt.Sprintf("Status: %d, Size: %d, Response Time: %v", result.StatusCode, result.Size, result.ResponseTime),
			Metadata: map[string]interface{}{
				"url":           result.URL,
				"method":        result.Method,
				"status_code":   result.StatusCode,
				"size":          result.Size,
				"words":         result.Words,
				"lines":         result.Lines,
				"response_time": result.ResponseTime.String(),
				"redirect_url":  result.RedirectURL,
				"headers":       result.Headers,
				"parameters":    result.Parameters,
				"type":          result.Type,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		findings = append(findings, finding)
	}

	return findings
}

func (s *Scanner) getSeverity(result FuzzResult) types.Severity {
	switch result.StatusCode {
	case 200:
		return types.SeverityMedium
	case 301, 302:
		return types.SeverityLow
	case 403:
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}

func (s *Scanner) getTitle(result FuzzResult, findingType string) string {
	switch findingType {
	case "DIRECTORY_DISCOVERY":
		return fmt.Sprintf("Directory Found: %s", result.URL)
	case "PARAMETER_DISCOVERY":
		return fmt.Sprintf("Parameter Discovery: %s", result.URL)
	case "VHOST_DISCOVERY":
		return fmt.Sprintf("Virtual Host Found: %s", result.URL)
	default:
		return fmt.Sprintf("Fuzzing Result: %s", result.URL)
	}
}

func (s *Scanner) getDescription(result FuzzResult, findingType string) string {
	switch findingType {
	case "DIRECTORY_DISCOVERY":
		return fmt.Sprintf("Discovered accessible directory or file: %s (Status: %d)", result.URL, result.StatusCode)
	case "PARAMETER_DISCOVERY":
		return fmt.Sprintf("Discovered potential HTTP parameter endpoint: %s (Status: %d)", result.URL, result.StatusCode)
	case "VHOST_DISCOVERY":
		return fmt.Sprintf("Discovered virtual host: %s (Status: %d)", result.URL, result.StatusCode)
	default:
		return fmt.Sprintf("Fuzzing discovered: %s", result.URL)
	}
}
