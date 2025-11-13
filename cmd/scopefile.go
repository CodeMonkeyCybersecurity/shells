package cmd

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/validation"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var scopeFileCmd = &cobra.Command{
	Use:   "scopefile",
	Short: "Manage local scope files for authorized targets",
	Long: `Scope files define which targets are authorized for scanning.

A scope file contains:
- [in-scope] section: Authorized targets (domains, IPs, ranges)
- [out-of-scope] section: Explicitly excluded targets

Example scope file:
  # Bug Bounty Program Scope
  [in-scope]
  example.com
  *.example.com
  api.example.com
  192.168.1.0/24

  [out-of-scope]
  *.internal.example.com
  admin.example.com

Usage:
  shells scopefile generate example.scope example.com *.example.com
  shells --scope example.scope example.com`,
}

var scopeFileGenerateCmd = &cobra.Command{
	Use:   "generate [output-file] [targets...]",
	Short: "Generate a scope file from targets",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		outputFile := args[0]
		targets := args[1:]

		// Check if file exists
		if _, err := os.Stat(outputFile); err == nil {
			overwrite, _ := cmd.Flags().GetBool("overwrite")
			if !overwrite {
				return fmt.Errorf("file %s already exists (use --overwrite to replace)", outputFile)
			}
		}

		// Generate scope file
		if err := validation.GenerateScopeFile(outputFile, targets); err != nil {
			return fmt.Errorf("failed to generate scope file: %w", err)
		}

		color.Green("✓ Scope file generated: %s\n", outputFile)
		fmt.Printf("  Targets: %d\n", len(targets))
		fmt.Printf("\nEdit the file to add/remove targets, then use:\n")
		fmt.Printf("  shells --scope %s <target>\n", outputFile)

		return nil
	},
}

var scopeFileValidateCmd = &cobra.Command{
	Use:   "validate [scope-file] [target]",
	Short: "Validate a target against a scope file",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		scopeFile := args[0]
		target := args[1]

		result, err := validation.ValidateWithScope(target, scopeFile)
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}

		if result.Valid {
			color.Green("✓ Target is IN SCOPE\n")
			fmt.Printf("  Target: %s\n", target)
			fmt.Printf("  Type: %s\n", result.TargetType)
			fmt.Printf("  Normalized: %s\n", result.NormalizedURL)

			if len(result.Warnings) > 0 {
				color.Yellow("\n  Warnings:\n")
				for _, warning := range result.Warnings {
					fmt.Printf("   • %s\n", warning)
				}
			}
		} else {
			color.Red("✗ Target is OUT OF SCOPE\n")
			fmt.Printf("  Target: %s\n", target)
			if result.Error != nil {
				fmt.Printf("  Reason: %s\n", result.Error)
			}

			if len(result.Warnings) > 0 {
				for _, warning := range result.Warnings {
					fmt.Printf("  %s\n", warning)
				}
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(scopeFileCmd)
	scopeFileCmd.AddCommand(scopeFileGenerateCmd)
	scopeFileCmd.AddCommand(scopeFileValidateCmd)

	scopeFileGenerateCmd.Flags().Bool("overwrite", false, "Overwrite existing scope file")
}
