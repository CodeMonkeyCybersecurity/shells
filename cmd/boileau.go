// cmd/boileau.go
package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/boileau"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/spf13/cobra"
)

// boileauCmd represents the boileau command
var boileauCmd = &cobra.Command{
	Use:   "boileau",
	Short: "Heavy boileau security tools",
	Long: `Execute powerful security testing tools for comprehensive vulnerability assessment.

This command provides access to specialized security tools:
- aquatone: Visual website inspection and screenshot capture
- masscan: High-speed port scanning
- xsstrike: Advanced XSS detection
- tplmap: Template injection testing
- gopherus: SSRF exploitation payload generation
- ssrfmap: SSRF vulnerability scanning
- nosqlmap: NoSQL injection testing
- corscanner: CORS misconfiguration detection
- sqlmap: SQL injection testing
- commix: Command injection testing
- arjun: HTTP parameter discovery

These tools provide deep vulnerability analysis beyond basic scanning.

Examples:
  shells boileau run xsstrike --target https://example.com
  shells boileau run masscan --target 192.168.1.0/24 --ports 1-65535
  shells boileau batch --target https://example.com --tools xsstrike,tplmap,corscanner
  shells boileau list`,
}

// boileauRunCmd runs a specific tool
var boileauRunCmd = &cobra.Command{
	Use:   "run [tool] --target [target]",
	Short: "Run a specific security tool",
	Long: `Execute a specific heavy boileau security tool.

Available tools:
- aquatone: Website screenshotting and visual analysis
- masscan: Fast port scanner (requires root/sudo)
- xsstrike: XSS vulnerability scanner
- tplmap: Server-side template injection scanner
- gopherus: SSRF exploitation payload generator
- ssrfmap: SSRF vulnerability scanner
- nosqlmap: NoSQL injection scanner
- corscanner: CORS misconfiguration scanner
- sqlmap: SQL injection scanner
- commix: Command injection scanner
- arjun: Parameter discovery tool

Examples:
  shells boileau run xsstrike --target https://example.com/page?id=1
  shells boileau run aquatone --target https://example.com --ports medium
  shells boileau run masscan --target 10.0.0.0/24 --ports 80,443,8080
  shells boileau run sqlmap --target https://example.com/page?id=1 --data "username=admin"`,
	Args: cobra.ExactArgs(1),
	RunE: runboileauTool,
}

// boileauBatchCmd runs multiple tools
var boileauBatchCmd = &cobra.Command{
	Use:   "batch --target [target] --tools [tool1,tool2,...]",
	Short: "Run multiple tools in batch",
	Long: `Execute multiple security tools against the same target.

This command runs selected tools in parallel (where safe) or sequentially,
collecting all results into a comprehensive report.

Tool categories:
- Web scanners: xsstrike, tplmap, sqlmap, commix, corscanner
- Network scanners: masscan
- Discovery tools: aquatone, arjun
- Exploitation tools: gopherus, ssrfmap, nosqlmap

Examples:
  shells boileau batch --target https://example.com --tools xsstrike,sqlmap,tplmap
  shells boileau batch --target https://example.com --category web
  shells boileau batch --target 192.168.1.0/24 --tools masscan,aquatone`,
	RunE: runboileauBatch,
}

// boileauListCmd lists available tools
var boileauListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available security tools",
	Long:  `Display all available heavy boileau security tools with descriptions.`,
	RunE:  runboileauList,
}

func init() {
	rootCmd.AddCommand(boileauCmd)
	boileauCmd.AddCommand(boileauRunCmd)
	boileauCmd.AddCommand(boileauBatchCmd)
	boileauCmd.AddCommand(boileauListCmd)

	// Common flags
	boileauCmd.PersistentFlags().String("output", "", "Output directory for results")
	boileauCmd.PersistentFlags().Bool("docker", true, "Run tools in Docker containers")
	boileauCmd.PersistentFlags().Bool("nomad", false, "Run tools as Nomad jobs")
	boileauCmd.PersistentFlags().Duration("timeout", 30*time.Minute, "Maximum execution time per tool")
	boileauCmd.PersistentFlags().Bool("verbose", false, "Verbose output")

	// Run command flags
	boileauRunCmd.Flags().String("target", "", "Target URL or IP (required)")
	boileauRunCmd.Flags().StringSlice("options", nil, "Tool-specific options (key=value)")
	boileauRunCmd.MarkFlagRequired("target")

	// Tool-specific flags
	boileauRunCmd.Flags().String("ports", "", "Ports to scan (for masscan/aquatone)")
	boileauRunCmd.Flags().String("rate", "", "Scan rate (for masscan)")
	boileauRunCmd.Flags().String("data", "", "POST data (for sqlmap/commix)")
	boileauRunCmd.Flags().String("cookie", "", "Cookie header")
	boileauRunCmd.Flags().String("method", "", "HTTP method")
	boileauRunCmd.Flags().Bool("crawl", false, "Enable crawling (for xsstrike)")

	// Batch command flags
	boileauBatchCmd.Flags().String("target", "", "Target URL or IP (required)")
	boileauBatchCmd.Flags().StringSlice("tools", nil, "Tools to run")
	boileauBatchCmd.Flags().String("category", "", "Tool category (web, network, discovery)")
	boileauBatchCmd.Flags().Int("parallel", 3, "Maximum parallel tool executions")
	boileauBatchCmd.MarkFlagRequired("target")
}

func runboileauTool(cmd *cobra.Command, args []string) error {
	toolName := args[0]
	target, _ := cmd.Flags().GetString("target")
	outputDir, _ := cmd.Flags().GetString("output")
	useDocker, _ := cmd.Flags().GetBool("docker")
	useNomad, _ := cmd.Flags().GetBool("nomad")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Tool-specific options
	options := make(map[string]string)

	// Add common options
	if ports, _ := cmd.Flags().GetString("ports"); ports != "" {
		options["ports"] = ports
	}
	if rate, _ := cmd.Flags().GetString("rate"); rate != "" {
		options["rate"] = rate
	}
	if data, _ := cmd.Flags().GetString("data"); data != "" {
		options["data"] = data
	}
	if cookie, _ := cmd.Flags().GetString("cookie"); cookie != "" {
		options["cookie"] = cookie
	}
	if method, _ := cmd.Flags().GetString("method"); method != "" {
		options["method"] = method
	}
	if crawl, _ := cmd.Flags().GetBool("crawl"); crawl {
		options["crawl"] = "true"
	}

	// Parse additional options
	if opts, _ := cmd.Flags().GetStringSlice("options"); len(opts) > 0 {
		for _, opt := range opts {
			parts := strings.SplitN(opt, "=", 2)
			if len(parts) == 2 {
				options[parts[0]] = parts[1]
			}
		}
	}

	// Default output directory
	if outputDir == "" {
		outputDir = fmt.Sprintf("boileau-%s-%d", toolName, time.Now().Unix())
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
	}
	options["output_dir"] = outputDir

	fmt.Printf("🎯 Running %s against %s\n", toolName, target)
	if verbose {
		fmt.Printf("📋 Configuration:\n")
		fmt.Printf("   Output: %s\n", outputDir)
		fmt.Printf("   Docker: %v\n", useDocker)
		fmt.Printf("   Timeout: %s\n", timeout)
		if len(options) > 0 {
			fmt.Printf("   Options:\n")
			for k, v := range options {
				if k != "output_dir" {
					fmt.Printf("     %s: %s\n", k, v)
				}
			}
		}
	}

	// Create scanner config
	config := boileau.Config{
		UseDocker: useDocker,
		UseNomad:  useNomad,
		OutputDir: outputDir,
		Timeout:   timeout,
		DockerImages: map[string]string{
			"aquatone":   "shells/aquatone:latest",
			"masscan":    "shells/masscan:latest",
			"xsstrike":   "shells/xsstrike:latest",
			"sqlmap":     "shells/sqlmap:latest",
			"tplmap":     "shells/tplmap:latest",
			"ssrfmap":    "shells/ssrfmap:latest",
			"nosqlmap":   "shells/nosqlmap:latest",
			"corscanner": "shells/corscanner:latest",
			"commix":     "shells/commix:latest",
			"arjun":      "shells/arjun:latest",
			"gopherus":   "shells/gopherus:latest",
		},
	}

	// Create scanner
	boileauLogger := &BoileauLogger{log: log}
	scanner := boileau.NewScanner(config, boileauLogger)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Run tool
	start := time.Now()
	result, err := scanner.RunTool(ctx, toolName, target, options)
	if err != nil {
		return fmt.Errorf("tool execution failed: %w", err)
	}
	duration := time.Since(start)

	// Display results
	fmt.Printf("\n✅ %s completed in %s\n", toolName, duration.Round(time.Second))

	if result.Success {
		fmt.Printf("📊 Results:\n")
		fmt.Printf("   Status: Success\n")
		fmt.Printf("   Findings: %d\n", len(result.Findings))

		if verbose && result.Output != "" {
			fmt.Printf("\n📄 Tool Output:\n")
			fmt.Println(result.Output)
		}

		// Display findings
		if len(result.Findings) > 0 {
			fmt.Printf("\n🔍 Findings:\n")
			for i, finding := range result.Findings {
				emoji := getBoileauSeverityEmoji(finding.Severity)
				fmt.Printf("\n%d. %s %s\n", i+1, emoji, finding.Title)
				fmt.Printf("   Type: %s\n", finding.Type)
				fmt.Printf("   Severity: %s\n", finding.Severity)
				if finding.Description != "" {
					fmt.Printf("   Description: %s\n", finding.Description)
				}
				if verbose && finding.Evidence != "" {
					fmt.Printf("   Evidence: %s\n", finding.Evidence)
				}
			}
		}

		// Convert to standard findings
		// findings := scanner.ConvertToFindings([]*boileau.ToolResult{result})

		// Save results
		if err := saveboileauResults(result, outputDir); err != nil {
			log.Error("Failed to save results", "error", err)
		}
	} else {
		fmt.Printf("❌ Tool execution failed\n")
		if result.Error != "" {
			fmt.Printf("   Error: %s\n", result.Error)
		}
	}

	fmt.Printf("\n📁 Results saved to: %s\n", outputDir)

	return nil
}

func runboileauBatch(cmd *cobra.Command, args []string) error {
	target, _ := cmd.Flags().GetString("target")
	tools, _ := cmd.Flags().GetStringSlice("tools")
	category, _ := cmd.Flags().GetString("category")
	parallel, _ := cmd.Flags().GetInt("parallel")
	outputDir, _ := cmd.Flags().GetString("output")
	useDocker, _ := cmd.Flags().GetBool("docker")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	// verbose, _ := cmd.Flags().GetBool("verbose")

	// Determine tools to run
	if category != "" {
		tools = getToolsByCategory(category)
	}

	if len(tools) == 0 {
		return fmt.Errorf("no tools specified. Use --tools or --category")
	}

	// Default output directory
	if outputDir == "" {
		outputDir = fmt.Sprintf("boileau-batch-%d", time.Now().Unix())
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
	}

	fmt.Printf("🎯 Running %d tools against %s\n", len(tools), target)
	fmt.Printf("🛠️  Tools: %s\n", strings.Join(tools, ", "))

	// Create scanner config
	config := boileau.Config{
		UseDocker:      useDocker,
		OutputDir:      outputDir,
		Timeout:        timeout,
		MaxConcurrency: parallel,
	}

	// Create scanner
	boileauLogger := &BoileauLogger{log: log}
	scanner := boileau.NewScanner(config, boileauLogger)

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Duration(len(tools)))
	defer cancel()

	// Run tools
	start := time.Now()
	results, err := scanner.RunMultipleTools(ctx, tools, target, map[string]string{
		"output_dir": outputDir,
	})
	if err != nil {
		log.Error("Batch execution error", "error", err)
	}
	duration := time.Since(start)

	fmt.Printf("\n✅ Batch completed in %s\n", duration.Round(time.Second))

	// Display summary
	successCount := 0
	totalFindings := 0
	for _, result := range results {
		if result.Success {
			successCount++
			totalFindings += len(result.Findings)
		}
	}

	fmt.Printf("📊 Summary:\n")
	fmt.Printf("   Tools executed: %d/%d\n", len(results), len(tools))
	fmt.Printf("   Successful: %d\n", successCount)
	fmt.Printf("   Total findings: %d\n", totalFindings)

	// Display findings by tool
	if totalFindings > 0 {
		fmt.Printf("\n🔍 Findings by Tool:\n")
		for _, result := range results {
			if result.Success && len(result.Findings) > 0 {
				fmt.Printf("\n%s (%d findings):\n", result.Tool, len(result.Findings))
				for _, finding := range result.Findings {
					emoji := getBoileauSeverityEmoji(finding.Severity)
					fmt.Printf("   %s %s - %s\n", emoji, finding.Severity, finding.Title)
				}
			}
		}
	}

	// Convert to standard findings
	findings := scanner.ConvertToFindings(results)

	// Save batch results
	if err := saveBatchResults(results, findings, outputDir); err != nil {
		log.Error("Failed to save batch results", "error", err)
	}

	fmt.Printf("\n📁 Results saved to: %s\n", outputDir)

	return nil
}

func runboileauList(cmd *cobra.Command, args []string) error {
	// Create scanner to get tool list
	config := boileau.Config{}
	boileauLogger := &BoileauLogger{log: log}
	scanner := boileau.NewScanner(config, boileauLogger)

	tools := scanner.GetAvailableTools()

	fmt.Printf("🛠️  Available Heavy boileau Tools:\n\n")

	// Tool descriptions
	descriptions := map[string]string{
		"aquatone":   "Visual website inspection - captures screenshots and analyzes web technologies",
		"masscan":    "High-speed port scanner - quickly discovers open ports across large networks",
		"xsstrike":   "Advanced XSS scanner - detects cross-site scripting vulnerabilities",
		"tplmap":     "Template injection scanner - finds server-side template injection flaws",
		"gopherus":   "SSRF payload generator - creates gopher:// payloads for SSRF exploitation",
		"ssrfmap":    "SSRF vulnerability scanner - detects and exploits server-side request forgery",
		"nosqlmap":   "NoSQL injection scanner - tests for NoSQL database injection vulnerabilities",
		"corscanner": "CORS misconfiguration scanner - identifies cross-origin resource sharing issues",
		"sqlmap":     "SQL injection scanner - comprehensive SQL injection detection and exploitation",
		"commix":     "Command injection scanner - detects OS command injection vulnerabilities",
		"arjun":      "Parameter discovery tool - finds hidden HTTP parameters",
	}

	// Group by type
	byType := make(map[string][]string)
	for name, toolType := range tools {
		byType[toolType] = append(byType[toolType], name)
	}

	// Display by category
	categories := []string{"visual_recon", "port_scanner", "xss_scanner", "sql_injection",
		"template_injection", "ssrf_scanner", "ssrf_exploitation", "nosql_injection",
		"command_injection", "cors_misconfiguration", "parameter_discovery"}

	for _, category := range categories {
		if toolNames, ok := byType[category]; ok {
			fmt.Printf("📌 %s:\n", formatCategory(category))
			for _, name := range toolNames {
				desc := descriptions[name]
				fmt.Printf("   • %-12s - %s\n", name, desc)
			}
			fmt.Println()
		}
	}

	fmt.Printf("💡 Usage:\n")
	fmt.Printf("   shells boileau run [tool] --target [target]\n")
	fmt.Printf("   shells boileau batch --target [target] --tools tool1,tool2\n")

	return nil
}

// Helper functions

func getToolsByCategory(category string) []string {
	categories := map[string][]string{
		"web":       {"xsstrike", "tplmap", "sqlmap", "commix", "corscanner", "arjun"},
		"network":   {"masscan"},
		"discovery": {"aquatone", "arjun"},
		"injection": {"sqlmap", "nosqlmap", "commix", "tplmap", "xsstrike"},
		"ssrf":      {"ssrfmap", "gopherus"},
	}

	if tools, ok := categories[category]; ok {
		return tools
	}

	return []string{}
}

func getBoileauSeverityEmoji(severity string) string {
	emojis := map[string]string{
		"CRITICAL": "🔴",
		"HIGH":     "🟠",
		"MEDIUM":   "🟡",
		"LOW":      "🔵",
		"INFO":     "⚪",
	}

	if emoji, ok := emojis[severity]; ok {
		return emoji
	}
	return "⚪"
}

func formatCategory(category string) string {
	formatted := strings.ReplaceAll(category, "_", " ")
	return strings.Title(formatted)
}

func saveboileauResults(result *boileau.ToolResult, outputDir string) error {
	// Save raw output
	if result.Output != "" {
		outputFile := fmt.Sprintf("%s_output.txt", result.Tool)
		if err := os.WriteFile(filepath.Join(outputDir, outputFile), []byte(result.Output), 0644); err != nil {
			return err
		}
	}

	// Save structured results
	resultFile := fmt.Sprintf("%s_results.json", result.Tool)
	return boileau.SaveJSON(outputDir, resultFile, result)
}

func saveBatchResults(results []*boileau.ToolResult, findings []types.Finding, outputDir string) error {
	// Save individual tool results
	for _, result := range results {
		if err := saveboileauResults(result, outputDir); err != nil {
			return err
		}
	}

	// Save combined report
	report := map[string]interface{}{
		"summary": map[string]interface{}{
			"total_tools":    len(results),
			"total_findings": len(findings),
			"scan_time":      time.Now(),
		},
		"tools":    results,
		"findings": findings,
	}

	return boileau.SaveJSON(outputDir, "batch_report.json", report)
}

// BoileauLogger adapts the internal logger for boileau package
type BoileauLogger struct {
	log *logger.Logger
}

func (b *BoileauLogger) Info(msg string, fields ...interface{}) {
	if b.log != nil {
		args := []interface{}{msg}
		args = append(args, fields...)
		b.log.Info(args...)
	}
}

func (b *BoileauLogger) Error(msg string, fields ...interface{}) {
	if b.log != nil {
		args := []interface{}{msg}
		args = append(args, fields...)
		b.log.Error(args...)
	}
}

func (b *BoileauLogger) Debug(msg string, fields ...interface{}) {
	if b.log != nil {
		args := []interface{}{msg}
		args = append(args, fields...)
		b.log.Debug(args...)
	}
}

func (b *BoileauLogger) Warn(msg string, fields ...interface{}) {
	if b.log != nil {
		args := []interface{}{msg}
		args = append(args, fields...)
		b.log.Warn(args...)
	}
}
