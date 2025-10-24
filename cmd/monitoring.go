package cmd

import (
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// TASK 12: Monitoring Query Commands

var monitoringCmd = &cobra.Command{
	Use:   "monitoring",
	Short: "Query monitoring data (alerts, DNS changes, certificates)",
	Long: `Access monitoring data stored in the database.

Available subcommands:
  alerts         - List monitoring alerts
  dns-changes    - Show DNS record changes for a target
  certificates   - Show certificate expiry information
  git-changes    - Show Git repository changes
  web-changes    - Show website change detection

Examples:
  shells monitoring alerts
  shells monitoring alerts --target example.com --severity critical
  shells monitoring dns-changes example.com
  shells monitoring certificates expiring --days 30`,
}

func init() {
	rootCmd.AddCommand(monitoringCmd)

	// Add subcommands
	monitoringCmd.AddCommand(monitoringAlertsCmd)
	monitoringCmd.AddCommand(monitoringDNSChangesCmd)
	monitoringCmd.AddCommand(monitoringCertificatesCmd)
	monitoringCmd.AddCommand(monitoringGitChangesCmd)
	monitoringCmd.AddCommand(monitoringWebChangesCmd)
}

// monitoringAlertsCmd lists monitoring alerts
var monitoringAlertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "List monitoring alerts",
	Long: `List all monitoring alerts or filter by target/severity.

Examples:
  shells monitoring alerts
  shells monitoring alerts --target example.com
  shells monitoring alerts --severity critical
  shells monitoring alerts --since 7d`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		severity, _ := cmd.Flags().GetString("severity")
		sinceDuration, _ := cmd.Flags().GetString("since")
		limit, _ := cmd.Flags().GetInt("limit")
		output, _ := cmd.Flags().GetString("output")

		store := GetStore()
		if store == nil {
			return fmt.Errorf("database not initialized")
		}

		ctx := GetContext()

		// Calculate time window
		var since time.Time
		if sinceDuration != "" {
			duration, err := parseDuration(sinceDuration)
			if err != nil {
				return fmt.Errorf("invalid duration: %w", err)
			}
			since = time.Now().Add(-duration)
		}

		// Query alerts from database
		// Note: This requires implementing GetMonitoringAlerts in ResultStore interface
		// For now, show a placeholder message
		fmt.Println()
		color.Cyan("═══ Monitoring Alerts ═══")
		
		if target != "" {
			fmt.Printf("  Target: %s\n", target)
		}
		if severity != "" {
			fmt.Printf("  Severity: %s\n", severity)
		}
		if sinceDuration != "" {
			fmt.Printf("  Since: %s (from %s)\n", sinceDuration, since.Format("2006-01-02"))
		}
		fmt.Println()

		// TODO: Implement actual database query when monitoring_alerts table is populated
		color.Yellow("  Note: Monitoring alerts table exists but no query method implemented yet.\n")
		color.Yellow("  This feature will be available once monitoring is actively running.\n")
		fmt.Println()

		_ = ctx
		_ = limit
		_ = output

		return nil
	},
}

// monitoringDNSChangesCmd shows DNS changes for a target
var monitoringDNSChangesCmd = &cobra.Command{
	Use:   "dns-changes <target>",
	Short: "Show DNS record changes for a target",
	Long: `Display DNS record changes detected for a target.

Examples:
  shells monitoring dns-changes example.com
  shells monitoring dns-changes example.com --since 30d
  shells monitoring dns-changes example.com --record-type A`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		sinceDuration, _ := cmd.Flags().GetString("since")
		recordType, _ := cmd.Flags().GetString("record-type")
		output, _ := cmd.Flags().GetString("output")

		store := GetStore()
		if store == nil {
			return fmt.Errorf("database not initialized")
		}

		ctx := GetContext()

		var since time.Time
		if sinceDuration != "" {
			duration, err := parseDuration(sinceDuration)
			if err != nil {
				return fmt.Errorf("invalid duration: %w", err)
			}
			since = time.Now().Add(-duration)
		}

		fmt.Println()
		color.Cyan("═══ DNS Changes: %s ═══", target)
		
		if sinceDuration != "" {
			fmt.Printf("  Since: %s (from %s)\n", sinceDuration, since.Format("2006-01-02"))
		}
		if recordType != "" {
			fmt.Printf("  Record Type: %s\n", recordType)
		}
		fmt.Println()

		// TODO: Implement actual database query
		color.Yellow("  Note: DNS monitoring table exists but no query method implemented yet.\n")
		color.Yellow("  This feature will be available once monitoring is actively running.\n")
		fmt.Println()

		_ = ctx
		_ = output

		return nil
	},
}

// monitoringCertificatesCmd shows certificate expiry information
var monitoringCertificatesCmd = &cobra.Command{
	Use:   "certificates",
	Short: "Show certificate expiry information",
	Long: `Display SSL/TLS certificates and their expiry status.

Examples:
  shells monitoring certificates expiring --days 30
  shells monitoring certificates --domain example.com
  shells monitoring certificates --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, _ := cmd.Flags().GetString("domain")
		days, _ := cmd.Flags().GetInt("days")
		expiring, _ := cmd.Flags().GetBool("expiring")
		output, _ := cmd.Flags().GetString("output")

		store := GetStore()
		if store == nil {
			return fmt.Errorf("database not initialized")
		}

		ctx := GetContext()

		fmt.Println()
		color.Cyan("═══ SSL/TLS Certificates ═══")
		
		if domain != "" {
			fmt.Printf("  Domain: %s\n", domain)
		}
		if expiring {
			fmt.Printf("  Expiring within: %d days\n", days)
		}
		fmt.Println()

		// TODO: Implement actual database query
		color.Yellow("  Note: Certificate monitoring table exists but no query method implemented yet.\n")
		color.Yellow("  This feature will be available once monitoring is actively running.\n")
		fmt.Println()

		_ = ctx
		_ = output

		return nil
	},
}

// monitoringGitChangesCmd shows Git repository changes
var monitoringGitChangesCmd = &cobra.Command{
	Use:   "git-changes <repo-url>",
	Short: "Show Git repository changes",
	Long: `Display changes detected in Git repositories.

Examples:
  shells monitoring git-changes https://github.com/example/repo
  shells monitoring git-changes https://github.com/example/repo --since 7d`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		repoURL := args[0]
		sinceDuration, _ := cmd.Flags().GetString("since")
		output, _ := cmd.Flags().GetString("output")

		store := GetStore()
		if store == nil {
			return fmt.Errorf("database not initialized")
		}

		ctx := GetContext()

		var since time.Time
		if sinceDuration != "" {
			duration, err := parseDuration(sinceDuration)
			if err != nil {
				return fmt.Errorf("invalid duration: %w", err)
			}
			since = time.Now().Add(-duration)
		}

		fmt.Println()
		color.Cyan("═══ Git Changes: %s ═══", repoURL)
		
		if sinceDuration != "" {
			fmt.Printf("  Since: %s (from %s)\n", sinceDuration, since.Format("2006-01-02"))
		}
		fmt.Println()

		// TODO: Implement actual database query
		color.Yellow("  Note: Git monitoring table exists but no query method implemented yet.\n")
		color.Yellow("  This feature will be available once monitoring is actively running.\n")
		fmt.Println()

		_ = ctx
		_ = output

		return nil
	},
}

// monitoringWebChangesCmd shows website change detection
var monitoringWebChangesCmd = &cobra.Command{
	Use:   "web-changes <url>",
	Short: "Show website change detection",
	Long: `Display changes detected on websites.

Examples:
  shells monitoring web-changes https://example.com
  shells monitoring web-changes https://example.com --since 7d`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		url := args[0]
		sinceDuration, _ := cmd.Flags().GetString("since")
		output, _ := cmd.Flags().GetString("output")

		store := GetStore()
		if store == nil {
			return fmt.Errorf("database not initialized")
		}

		ctx := GetContext()

		var since time.Time
		if sinceDuration != "" {
			duration, err := parseDuration(sinceDuration)
			if err != nil {
				return fmt.Errorf("invalid duration: %w", err)
			}
			since = time.Now().Add(-duration)
		}

		fmt.Println()
		color.Cyan("═══ Web Changes: %s ═══", url)
		
		if sinceDuration != "" {
			fmt.Printf("  Since: %s (from %s)\n", sinceDuration, since.Format("2006-01-02"))
		}
		fmt.Println()

		// TODO: Implement actual database query
		color.Yellow("  Note: Web monitoring table exists but no query method implemented yet.\n")
		color.Yellow("  This feature will be available once monitoring is actively running.\n")
		fmt.Println()

		_ = ctx
		_ = output

		return nil
	},
}

func init() {
	// Alerts command flags
	monitoringAlertsCmd.Flags().String("target", "", "Filter by target")
	monitoringAlertsCmd.Flags().String("severity", "", "Filter by severity (critical, high, medium, low)")
	monitoringAlertsCmd.Flags().String("since", "", "Show alerts since duration (e.g., 7d, 24h)")
	monitoringAlertsCmd.Flags().Int("limit", 100, "Maximum number of alerts to show")
	monitoringAlertsCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")

	// DNS changes command flags
	monitoringDNSChangesCmd.Flags().String("since", "", "Show changes since duration")
	monitoringDNSChangesCmd.Flags().String("record-type", "", "Filter by DNS record type (A, AAAA, MX, TXT, etc.)")
	monitoringDNSChangesCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")

	// Certificates command flags
	monitoringCertificatesCmd.Flags().String("domain", "", "Filter by domain")
	monitoringCertificatesCmd.Flags().Bool("expiring", false, "Show only expiring certificates")
	monitoringCertificatesCmd.Flags().Int("days", 30, "Days until expiry (with --expiring)")
	monitoringCertificatesCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")

	// Git changes command flags
	monitoringGitChangesCmd.Flags().String("since", "", "Show changes since duration")
	monitoringGitChangesCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")

	// Web changes command flags
	monitoringWebChangesCmd.Flags().String("since", "", "Show changes since duration")
	monitoringWebChangesCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")
}
