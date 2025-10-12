// cmd/fuzz.go
package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/cmd/internal/adapters"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/fuzzing"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/spf13/cobra"
)

// fuzzCmd represents the fuzz command
var fuzzCmd = &cobra.Command{
	Use:   "fuzz",
	Short: "Advanced fuzzing capabilities",
	Long: `Comprehensive fuzzing toolkit for web application testing.

This command provides advanced fuzzing capabilities including:
- Directory and file discovery with smart recursion
- Parameter mining with ML-based prediction
- Virtual host enumeration
- Subdomain discovery via fuzzing
- HTTP Parameter Pollution testing
- Type confusion detection
- Context-aware content discovery

The fuzzer uses multiple techniques:
- Custom wordlist generation
- Pattern analysis from responses
- Heuristic-based path generation
- Machine learning for parameter prediction
- Framework-specific optimizations

Examples:
  shells fuzz dir https://example.com
  shells fuzz param https://example.com/api --smart
  shells fuzz vhost https://example.com --wordlist vhosts.txt
  shells fuzz subdomain example.com --threads 50`,
}

// fuzzDirCmd performs directory fuzzing
var fuzzDirCmd = &cobra.Command{
	Use:   "dir [target]",
	Short: "Fuzz directories and files",
	Long: `Discover hidden directories and files through fuzzing.

This command performs intelligent directory and file discovery with:
- Multiple wordlist support
- Extension fuzzing (.php, .bak, .old, etc.)
- Smart recursion for discovered directories
- Framework detection and optimization
- Custom status code filtering
- Response size filtering

Examples:
  shells fuzz dir https://example.com
  shells fuzz dir https://example.com --wordlist custom.txt
  shells fuzz dir https://example.com --extensions .php,.asp,.jsp
  shells fuzz dir https://example.com --recursive --depth 3
  shells fuzz dir https://example.com --smart --threads 50`,
	Args: cobra.ExactArgs(1),
	RunE: runFuzzDir,
}

// fuzzParamCmd performs parameter fuzzing
var fuzzParamCmd = &cobra.Command{
	Use:   "param [target]",
	Short: "Discover hidden parameters",
	Long: `Discover hidden parameters using advanced techniques.

This command finds hidden parameters through:
- Traditional parameter fuzzing
- JavaScript analysis for parameter extraction
- ML-based parameter prediction
- HTTP Parameter Pollution testing
- Parameter type confusion detection
- Array parameter discovery
- JSON parameter testing

Smart mode enables:
- Automatic JavaScript parsing
- Machine learning predictions
- Context-based parameter generation
- Advanced pollution techniques

Examples:
  shells fuzz param https://example.com/api/endpoint
  shells fuzz param https://example.com/search --smart
  shells fuzz param https://example.com --methods GET,POST,PUT
  shells fuzz param https://example.com --wordlist params.txt --threads 20`,
	Args: cobra.ExactArgs(1),
	RunE: runFuzzParam,
}

// fuzzVhostCmd performs virtual host fuzzing
var fuzzVhostCmd = &cobra.Command{
	Use:   "vhost [target]",
	Short: "Enumerate virtual hosts",
	Long: `Discover virtual hosts through fuzzing.

This command identifies virtual hosts by:
- Testing Host header variations
- Using baseline comparison
- Detecting response differences
- Supporting custom vhost wordlists

Examples:
  shells fuzz vhost https://example.com
  shells fuzz vhost https://192.168.1.1 --domain example.com
  shells fuzz vhost https://example.com --wordlist vhosts-large.txt`,
	Args: cobra.ExactArgs(1),
	RunE: runFuzzVhost,
}

// fuzzSubdomainCmd performs subdomain fuzzing
var fuzzSubdomainCmd = &cobra.Command{
	Use:   "subdomain [domain]",
	Short: "Enumerate subdomains via fuzzing",
	Long: `Discover subdomains through DNS and HTTP fuzzing.

This command finds subdomains using:
- DNS resolution checks
- HTTP/HTTPS validation
- Smart permutation generation
- Pattern-based subdomain creation

Examples:
  shells fuzz subdomain example.com
  shells fuzz subdomain example.com --wordlist subdomains-10k.txt
  shells fuzz subdomain example.com --smart --threads 100`,
	Args: cobra.ExactArgs(1),
	RunE: runFuzzSubdomain,
}

func init() {
	rootCmd.AddCommand(fuzzCmd)
	fuzzCmd.AddCommand(fuzzDirCmd)
	fuzzCmd.AddCommand(fuzzParamCmd)
	fuzzCmd.AddCommand(fuzzVhostCmd)
	fuzzCmd.AddCommand(fuzzSubdomainCmd)

	// Common flags
	fuzzCmd.PersistentFlags().String("wordlist", "", "Path to wordlist file")
	fuzzCmd.PersistentFlags().Int("threads", 20, "Number of concurrent threads")
	fuzzCmd.PersistentFlags().Duration("timeout", 10*time.Second, "HTTP request timeout")
	fuzzCmd.PersistentFlags().Int("rate", 0, "Rate limit (requests per second, 0=unlimited)")
	fuzzCmd.PersistentFlags().Bool("smart", false, "Enable smart fuzzing with ML and heuristics")
	fuzzCmd.PersistentFlags().StringSlice("headers", nil, "Custom headers (format: 'Name:Value')")
	fuzzCmd.PersistentFlags().String("output", "", "Output file for results")
	fuzzCmd.PersistentFlags().Bool("verbose", false, "Verbose output")

	// Directory fuzzing specific flags
	fuzzDirCmd.Flags().StringSlice("extensions", nil, "File extensions to test (e.g., .php,.bak)")
	fuzzDirCmd.Flags().IntSlice("status-codes", []int{200, 301, 302, 401, 403}, "Valid status codes")
	fuzzDirCmd.Flags().IntSlice("exclude-size", nil, "Exclude responses of specific sizes")
	fuzzDirCmd.Flags().Bool("recursive", false, "Enable recursive fuzzing")
	fuzzDirCmd.Flags().Int("depth", 2, "Maximum recursion depth")
	fuzzDirCmd.Flags().Bool("follow-redirects", false, "Follow HTTP redirects")

	// Parameter fuzzing specific flags
	fuzzParamCmd.Flags().StringSlice("methods", []string{"GET", "POST"}, "HTTP methods to test")
	fuzzParamCmd.Flags().Bool("json", false, "Test JSON parameter acceptance")
	fuzzParamCmd.Flags().Bool("pollution", true, "Test parameter pollution")
	fuzzParamCmd.Flags().Bool("type-confusion", true, "Test parameter type confusion")

	// Vhost fuzzing specific flags
	fuzzVhostCmd.Flags().String("domain", "", "Base domain for vhost fuzzing")
	fuzzVhostCmd.Flags().Bool("port-scan", false, "Also scan common ports")

	// Subdomain fuzzing specific flags
	fuzzSubdomainCmd.Flags().Bool("dns-only", false, "Only check DNS resolution")
	fuzzSubdomainCmd.Flags().Bool("permutations", true, "Generate smart permutations")
}

func runFuzzDir(cmd *cobra.Command, args []string) error {
	target := args[0]
	wordlist, _ := cmd.Flags().GetString("wordlist")
	threads, _ := cmd.Flags().GetInt("threads")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	rate, _ := cmd.Flags().GetInt("rate")
	smart, _ := cmd.Flags().GetBool("smart")
	headers, _ := cmd.Flags().GetStringSlice("headers")
	output, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Directory specific flags
	extensions, _ := cmd.Flags().GetStringSlice("extensions")
	statusCodes, _ := cmd.Flags().GetIntSlice("status-codes")
	//excludeSize, _ := cmd.Flags().GetIntSlice("exclude-size") // TODO: implement exclude-size filtering
	recursive, _ := cmd.Flags().GetBool("recursive")
	depth, _ := cmd.Flags().GetInt("depth")
	//followRedirects, _ := cmd.Flags().GetBool("follow-redirects") // TODO: implement follow-redirects

	// Default wordlist
	if wordlist == "" {
		wordlist = "common.txt"
	}

	fmt.Printf(" Starting directory fuzzing against: %s\n", target)
	if verbose {
		fmt.Printf(" Configuration:\n")
		fmt.Printf("   Wordlist: %s\n", wordlist)
		fmt.Printf("   Threads: %d\n", threads)
		fmt.Printf("   Extensions: %v\n", extensions)
		fmt.Printf("   Smart mode: %v\n", smart)
		fmt.Printf("   Recursive: %v (depth: %d)\n", recursive, depth)
	}

	// Parse custom headers
	customHeaders := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Create scanner config
	config := fuzzing.ScannerConfig{
		Mode:           "directory",
		Wordlist:       wordlist,
		Threads:        threads,
		Timeout:        timeout,
		Extensions:     extensions,
		StatusCodes:    statusCodes,
		RateLimit:      rate,
		SmartMode:      smart,
		RecursionDepth: depth,
		CustomHeaders:  customHeaders,
	}

	if recursive {
		config.RecursionDepth = depth
	} else {
		config.RecursionDepth = 0
	}

	// Create scanner
	scanner := fuzzing.NewScanner(config, adapters.NewFuzzingLogger(GetLogger()))

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Run scan
	start := time.Now()
	findings, err := scanner.Scan(ctx, target, nil)
	if err != nil {
		return fmt.Errorf("fuzzing failed: %w", err)
	}
	duration := time.Since(start)

	fmt.Printf("\n Fuzzing completed in %s\n", duration.Round(time.Second))

	// Display results
	displayFuzzResults(findings, verbose)

	// Save results if output specified
	if output != "" {
		if err := saveFuzzResults(findings, output); err != nil {
			return fmt.Errorf("failed to save results: %w", err)
		}
		fmt.Printf("\n Results saved to: %s\n", output)
	}

	return nil
}

func runFuzzParam(cmd *cobra.Command, args []string) error {
	target := args[0]
	wordlist, _ := cmd.Flags().GetString("wordlist")
	threads, _ := cmd.Flags().GetInt("threads")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	smart, _ := cmd.Flags().GetBool("smart")
	methods, _ := cmd.Flags().GetStringSlice("methods")
	testJSON, _ := cmd.Flags().GetBool("json")
	testPollution, _ := cmd.Flags().GetBool("pollution")
	//testTypeConfusion, _ := cmd.Flags().GetBool("type-confusion") // TODO: implement type confusion testing
	output, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Default wordlist
	if wordlist == "" {
		wordlist = "parameters.txt"
	}

	fmt.Printf(" Starting parameter fuzzing against: %s\n", target)
	if verbose {
		fmt.Printf(" Configuration:\n")
		fmt.Printf("   Wordlist: %s\n", wordlist)
		fmt.Printf("   Methods: %v\n", methods)
		fmt.Printf("   Smart mode: %v\n", smart)
		fmt.Printf("   Test JSON: %v\n", testJSON)
		fmt.Printf("   Test pollution: %v\n", testPollution)
	}

	// Create scanner config
	config := fuzzing.ScannerConfig{
		Mode:      "parameter",
		Wordlist:  wordlist,
		Threads:   threads,
		Timeout:   timeout,
		SmartMode: smart,
	}

	// Create scanner
	scanner := fuzzing.NewScanner(config, adapters.NewFuzzingLogger(GetLogger()))

	// Add methods to options
	options := map[string]string{
		"methods": strings.Join(methods, ","),
	}

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Run scan
	start := time.Now()
	findings, err := scanner.Scan(ctx, target, options)
	if err != nil {
		return fmt.Errorf("parameter fuzzing failed: %w", err)
	}
	duration := time.Since(start)

	fmt.Printf("\n Parameter fuzzing completed in %s\n", duration.Round(time.Second))

	// Display results
	displayFuzzResults(findings, verbose)

	// Save results if output specified
	if output != "" {
		if err := saveFuzzResults(findings, output); err != nil {
			return fmt.Errorf("failed to save results: %w", err)
		}
		fmt.Printf("\n Results saved to: %s\n", output)
	}

	return nil
}

func runFuzzVhost(cmd *cobra.Command, args []string) error {
	target := args[0]
	wordlist, _ := cmd.Flags().GetString("wordlist")
	domain, _ := cmd.Flags().GetString("domain")
	threads, _ := cmd.Flags().GetInt("threads")
	output, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Default wordlist
	if wordlist == "" {
		wordlist = "vhosts.txt"
	}

	fmt.Printf(" Starting vhost fuzzing against: %s\n", target)
	if domain != "" {
		fmt.Printf("   Base domain: %s\n", domain)
	}

	// Create scanner config
	config := fuzzing.ScannerConfig{
		Mode:     "vhost",
		Wordlist: wordlist,
		Threads:  threads,
	}

	// Create scanner
	scanner := fuzzing.NewScanner(config, adapters.NewFuzzingLogger(GetLogger()))

	// Add domain to options if specified
	options := make(map[string]string)
	if domain != "" {
		options["domain"] = domain
	}

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Run scan
	start := time.Now()
	findings, err := scanner.Scan(ctx, target, options)
	if err != nil {
		return fmt.Errorf("vhost fuzzing failed: %w", err)
	}
	duration := time.Since(start)

	fmt.Printf("\n Vhost fuzzing completed in %s\n", duration.Round(time.Second))

	// Display results
	displayFuzzResults(findings, verbose)

	// Save results if output specified
	if output != "" {
		if err := saveFuzzResults(findings, output); err != nil {
			return fmt.Errorf("failed to save results: %w", err)
		}
		fmt.Printf("\n Results saved to: %s\n", output)
	}

	return nil
}

func runFuzzSubdomain(cmd *cobra.Command, args []string) error {
	domain := args[0]
	wordlist, _ := cmd.Flags().GetString("wordlist")
	threads, _ := cmd.Flags().GetInt("threads")
	dnsOnly, _ := cmd.Flags().GetBool("dns-only")
	permutations, _ := cmd.Flags().GetBool("permutations")
	smart, _ := cmd.Flags().GetBool("smart")
	output, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Default wordlist
	if wordlist == "" {
		wordlist = "subdomains.txt"
	}

	fmt.Printf(" Starting subdomain fuzzing for: %s\n", domain)
	if verbose {
		fmt.Printf(" Configuration:\n")
		fmt.Printf("   Wordlist: %s\n", wordlist)
		fmt.Printf("   Threads: %d\n", threads)
		fmt.Printf("   DNS only: %v\n", dnsOnly)
		fmt.Printf("   Permutations: %v\n", permutations)
	}

	// Create scanner config
	config := fuzzing.ScannerConfig{
		Mode:      "subdomain",
		Wordlist:  wordlist,
		Threads:   threads,
		SmartMode: smart || permutations,
	}

	// Create scanner
	scanner := fuzzing.NewScanner(config, adapters.NewFuzzingLogger(GetLogger()))

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Run scan
	start := time.Now()
	findings, err := scanner.Scan(ctx, domain, nil)
	if err != nil {
		return fmt.Errorf("subdomain fuzzing failed: %w", err)
	}
	duration := time.Since(start)

	fmt.Printf("\n Subdomain fuzzing completed in %s\n", duration.Round(time.Second))

	// Display results
	displayFuzzResults(findings, verbose)

	// Save results if output specified
	if output != "" {
		if err := saveFuzzResults(findings, output); err != nil {
			return fmt.Errorf("failed to save results: %w", err)
		}
		fmt.Printf("\n Results saved to: %s\n", output)
	}

	return nil
}

// Helper functions

func displayFuzzResults(findings []types.Finding, verbose bool) {
	// Find summary
	var summary *types.Finding
	discovered := []types.Finding{}

	for _, finding := range findings {
		if finding.Type == "FUZZ_SUMMARY" {
			summary = &finding
		} else {
			discovered = append(discovered, finding)
		}
	}

	// Display summary
	if summary != nil {
		fmt.Printf("\n Fuzzing Summary:\n")
		if summary.Metadata != nil {
			if totalFound, ok := summary.Metadata["total_found"]; ok {
				fmt.Printf("   Total discovered: %v\n", totalFound)
			}

			if breakdown, ok := summary.Metadata["breakdown"].(map[string]int); ok {
				fmt.Printf("   Breakdown:\n")
				for itemType, count := range breakdown {
					fmt.Printf("     %s: %d\n", itemType, count)
				}
			}
		}
	}

	// Group by severity
	bySeverity := map[types.Severity][]types.Finding{
		types.SeverityHigh:   {},
		types.SeverityMedium: {},
		types.SeverityLow:    {},
		types.SeverityInfo:   {},
	}

	for _, finding := range discovered {
		bySeverity[finding.Severity] = append(bySeverity[finding.Severity], finding)
	}

	// Display findings by severity
	for _, severity := range []types.Severity{types.SeverityHigh, types.SeverityMedium, types.SeverityLow, types.SeverityInfo} {
		if len(bySeverity[severity]) > 0 {
			emoji := map[types.Severity]string{
				types.SeverityHigh:   "",
				types.SeverityMedium: "🟡",
				types.SeverityLow:    "🔵",
				types.SeverityInfo:   "⚪",
			}[severity]

			fmt.Printf("\n%s %s Severity (%d):\n", emoji, string(severity), len(bySeverity[severity]))

			// Limit display if not verbose
			displayCount := len(bySeverity[severity])
			if !verbose && displayCount > 10 {
				displayCount = 10
			}

			for i := 0; i < displayCount; i++ {
				finding := bySeverity[severity][i]
				fmt.Printf("   • %s\n", finding.Title)

				if verbose && finding.Metadata != nil {
					if statusCode, ok := finding.Metadata["status_code"]; ok {
						fmt.Printf("     Status: %v", statusCode)
					}
					if size, ok := finding.Metadata["size"]; ok {
						fmt.Printf(", Size: %v bytes", size)
					}
					fmt.Println()
				}
			}

			if !verbose && len(bySeverity[severity]) > 10 {
				fmt.Printf("   ... and %d more\n", len(bySeverity[severity])-10)
			}
		}
	}
}

func saveFuzzResults(findings []types.Finding, output string) error {
	// Create output directory if needed
	dir := filepath.Dir(output)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Create simple text report
	file, err := os.Create(output)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close report file: %v\n", err)
		}
	}()

	if _, err := fmt.Fprintf(file, "Fuzzing Results Report\n"); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}
	if _, err := fmt.Fprintf(file, "Generated: %s\n", time.Now().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}
	if _, err := fmt.Fprintf(file, "=====================================\n\n"); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	for _, finding := range findings {
		if _, err := fmt.Fprintf(file, "Title: %s\n", finding.Title); err != nil {
			return fmt.Errorf("failed to write finding: %w", err)
		}
		if _, err := fmt.Fprintf(file, "Severity: %s\n", finding.Severity); err != nil {
			return fmt.Errorf("failed to write finding: %w", err)
		}
		if target, ok := finding.Metadata["target"]; ok {
			if _, err := fmt.Fprintf(file, "Target: %s\n", target); err != nil {
				return fmt.Errorf("failed to write finding: %w", err)
			}
		}
		if _, err := fmt.Fprintf(file, "Description: %s\n", finding.Description); err != nil {
			return fmt.Errorf("failed to write finding: %w", err)
		}

		if finding.Solution != "" {
			if _, err := fmt.Fprintf(file, "Solution: %s\n", finding.Solution); err != nil {
				return fmt.Errorf("failed to write finding: %w", err)
			}
		}

		if _, err := fmt.Fprintf(file, "\n---\n\n"); err != nil {
			return fmt.Errorf("failed to write finding: %w", err)
		}
	}

	return nil
}

// FuzzingLogger moved to cmd/internal/adapters package
