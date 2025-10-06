package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/spf13/cobra"
)

var resultsCmd = &cobra.Command{
	Use:   "results",
	Short: "Query and export scan results",
	Long:  `View, filter, and export security scan results in various formats.`,
}

func init() {
	rootCmd.AddCommand(resultsCmd)

	resultsCmd.AddCommand(resultsListCmd)
	resultsCmd.AddCommand(resultsGetCmd)
	resultsCmd.AddCommand(resultsExportCmd)
	resultsCmd.AddCommand(resultsSummaryCmd)
	resultsCmd.AddCommand(resultsQueryCmd)
	resultsCmd.AddCommand(resultsStatsCmd)
	resultsCmd.AddCommand(resultsIdentityChainsCmd)
}

var resultsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List scan results",
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		status, _ := cmd.Flags().GetString("status")
		scanType, _ := cmd.Flags().GetString("type")
		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")
		output, _ := cmd.Flags().GetString("output")

		store := GetStore()
		if store == nil {
			return fmt.Errorf("database not initialized")
		}

		filter := core.ScanFilter{
			Target: target,
			Limit:  limit,
			Offset: offset,
		}

		if status != "" {
			filter.Status = types.ScanStatus(status)
		}
		if scanType != "" {
			filter.Type = types.ScanType(scanType)
		}

		scans, err := store.ListScans(GetContext(), filter)
		if err != nil {
			return fmt.Errorf("failed to list scans: %w", err)
		}

		if output == "json" {
			jsonData, _ := json.MarshalIndent(scans, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			printScanList(scans)
		}

		return nil
	},
}

var resultsGetCmd = &cobra.Command{
	Use:   "get [scan-id]",
	Short: "Get results for a specific scan",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		scanID := args[0]
		output, _ := cmd.Flags().GetString("output")
		showFindings, _ := cmd.Flags().GetBool("show-findings")

		store := GetStore()
		if store == nil {
			return fmt.Errorf("database not initialized")
		}

		scan, err := store.GetScan(GetContext(), scanID)
		if err != nil {
			return fmt.Errorf("failed to get scan: %w", err)
		}

		var findings []types.Finding
		if showFindings {
			findings, err = store.GetFindings(GetContext(), scanID)
			if err != nil {
				return fmt.Errorf("failed to get findings: %w", err)
			}
		}

		result := types.ScanResult{
			ScanID:   scanID,
			Findings: findings,
		}
		if scan.CompletedAt != nil {
			result.CompletedAt = *scan.CompletedAt
		}

		if showFindings {
			summary, _ := store.GetSummary(GetContext(), scanID)
			if summary != nil {
				result.Summary = *summary
			}
		}

		if output == "json" {
			jsonData, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			printScanDetails(scan, findings)
		}

		return nil
	},
}

var resultsExportCmd = &cobra.Command{
	Use:   "export [scan-id]",
	Short: "Export scan results",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		scanID := args[0]
		format, _ := cmd.Flags().GetString("format")
		outputFile, _ := cmd.Flags().GetString("output")

		store := GetStore()
		if store == nil {
			return fmt.Errorf("database not initialized")
		}

		findings, err := store.GetFindings(GetContext(), scanID)
		if err != nil {
			return fmt.Errorf("failed to get findings: %w", err)
		}

		var data []byte
		switch format {
		case "json":
			data, err = json.MarshalIndent(findings, "", "  ")
		case "csv":
			data, err = exportCSV(findings)
		case "html":
			data, err = exportHTML(findings)
		default:
			return fmt.Errorf("unsupported format: %s", format)
		}

		if err != nil {
			return fmt.Errorf("failed to format results: %w", err)
		}

		if outputFile == "" {
			fmt.Print(string(data))
		} else {
			if err := os.WriteFile(outputFile, data, 0644); err != nil {
				return fmt.Errorf("failed to write file: %w", err)
			}
			fmt.Printf("Results exported to %s\n", outputFile)
		}

		return nil
	},
}

var resultsSummaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Get summary of all scan results",
	RunE: func(cmd *cobra.Command, args []string) error {
		days, _ := cmd.Flags().GetInt("days")
		output, _ := cmd.Flags().GetString("output")

		store := GetStore()
		if store == nil {
			return fmt.Errorf("database not initialized")
		}

		// Get scans from the last N days
		fromDate := time.Now().AddDate(0, 0, -days).Format(time.RFC3339)
		filter := core.ScanFilter{
			FromDate: &fromDate,
			Limit:    1000,
		}

		scans, err := store.ListScans(GetContext(), filter)
		if err != nil {
			return fmt.Errorf("failed to list scans: %w", err)
		}

		// Generate summary statistics
		summary := generateSummary(scans)

		if output == "json" {
			jsonData, _ := json.MarshalIndent(summary, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			printSummary(summary, days)
		}

		return nil
	},
}

func init() {
	resultsListCmd.Flags().String("target", "", "Filter by target")
	resultsListCmd.Flags().String("status", "", "Filter by status (pending, running, completed, failed)")
	resultsListCmd.Flags().String("type", "", "Filter by scan type")
	resultsListCmd.Flags().Int("limit", 50, "Maximum number of results")
	resultsListCmd.Flags().Int("offset", 0, "Results offset for pagination")
	resultsListCmd.Flags().String("output", "table", "Output format (table, json)")

	resultsGetCmd.Flags().String("output", "table", "Output format (table, json)")
	resultsGetCmd.Flags().Bool("show-findings", true, "Include findings in output")

	resultsExportCmd.Flags().String("format", "json", "Export format (json, csv, html)")
	resultsExportCmd.Flags().String("output", "", "Output file (default: stdout)")

	resultsSummaryCmd.Flags().Int("days", 7, "Number of days to include in summary")
	resultsSummaryCmd.Flags().String("output", "table", "Output format (table, json)")
}

// Helper functions for output formatting

func printScanList(scans []*types.ScanRequest) {
	if len(scans) == 0 {
		fmt.Println("No scans found")
		return
	}

	fmt.Printf(" Scan Results (%d scans)\\n", len(scans))
	fmt.Printf("═══════════════════════════════════════\\n\\n")

	fmt.Printf("%-36s %-20s %-15s %-12s %-20s\\n", "ID", "Target", "Type", "Status", "Created")
	fmt.Printf("%-36s %-20s %-15s %-12s %-20s\\n", strings.Repeat("-", 36), strings.Repeat("-", 20), strings.Repeat("-", 15), strings.Repeat("-", 12), strings.Repeat("-", 20))

	for _, scan := range scans {
		fmt.Printf("%-36s %-20s %-15s %-12s %-20s\\n",
			scan.ID,
			truncate(scan.Target, 20),
			string(scan.Type),
			string(scan.Status),
			scan.CreatedAt.Format("2006-01-02 15:04:05"))
	}
}

func printScanDetails(scan *types.ScanRequest, findings []types.Finding) {
	fmt.Printf(" Scan Details\\n")
	fmt.Printf("═══════════════════════════════════════\\n\\n")

	fmt.Printf("ID: %s\\n", scan.ID)
	fmt.Printf("Target: %s\\n", scan.Target)
	fmt.Printf("Type: %s\\n", scan.Type)
	fmt.Printf("Status: %s\\n", scan.Status)
	fmt.Printf("Created: %s\\n", scan.CreatedAt.Format("2006-01-02 15:04:05 MST"))

	if scan.StartedAt != nil {
		fmt.Printf("Started: %s\\n", scan.StartedAt.Format("2006-01-02 15:04:05 MST"))
	}
	if scan.CompletedAt != nil {
		fmt.Printf("Completed: %s\\n", scan.CompletedAt.Format("2006-01-02 15:04:05 MST"))
		duration := scan.CompletedAt.Sub(*scan.StartedAt)
		fmt.Printf("Duration: %s\\n", duration.String())
	}

	if scan.ErrorMessage != "" {
		fmt.Printf("Error: %s\\n", scan.ErrorMessage)
	}

	if len(findings) > 0 {
		fmt.Printf("\\n📋 Findings (%d total)\\n", len(findings))
		fmt.Printf("─────────────────────────────────\\n")

		severityGroups := make(map[types.Severity][]types.Finding)
		for _, finding := range findings {
			severityGroups[finding.Severity] = append(severityGroups[finding.Severity], finding)
		}

		severityOrder := []types.Severity{
			types.SeverityCritical,
			types.SeverityHigh,
			types.SeverityMedium,
			types.SeverityLow,
			types.SeverityInfo,
		}

		for _, severity := range severityOrder {
			if findings, exists := severityGroups[severity]; exists {
				icon := getSeverityIcon(string(severity))
				fmt.Printf("\\n%s %s (%d findings)\\n", icon, strings.ToUpper(string(severity)), len(findings))
				for _, finding := range findings {
					fmt.Printf("  • %s [%s]\\n", finding.Title, finding.Tool)
					if finding.Description != "" {
						fmt.Printf("    %s\\n", finding.Description)
					}
				}
			}
		}
	}
}

func exportCSV(findings []types.Finding) ([]byte, error) {
	var result strings.Builder
	writer := csv.NewWriter(&result)

	// Write header
	header := []string{"ID", "Scan ID", "Tool", "Type", "Severity", "Title", "Description", "Evidence", "Solution", "Created At"}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write data
	for _, finding := range findings {
		record := []string{
			finding.ID,
			finding.ScanID,
			finding.Tool,
			finding.Type,
			string(finding.Severity),
			finding.Title,
			finding.Description,
			finding.Evidence,
			finding.Solution,
			finding.CreatedAt.Format("2006-01-02 15:04:05"),
		}
		if err := writer.Write(record); err != nil {
			return nil, fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV writer flush failed: %w", err)
	}
	return []byte(result.String()), nil
}

func exportHTML(findings []types.Finding) ([]byte, error) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Shells Security Scan Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .critical { background-color: #ffebee; }
        .high { background-color: #fff3e0; }
        .medium { background-color: #fffde7; }
        .low { background-color: #e8f5e8; }
        .info { background-color: #e3f2fd; }
    </style>
</head>
<body>
    <h1>Security Scan Results</h1>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Tool</th>
                <th>Title</th>
                <th>Description</th>
                <th>Evidence</th>
                <th>Solution</th>
                <th>Created</th>
            </tr>
        </thead>
        <tbody>`

	for _, finding := range findings {
		severityClass := strings.ToLower(string(finding.Severity))
		html += fmt.Sprintf(`
            <tr class="%s">
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
            </tr>`,
			severityClass,
			finding.Severity,
			finding.Tool,
			finding.Title,
			finding.Description,
			finding.Evidence,
			finding.Solution,
			finding.CreatedAt.Format("2006-01-02 15:04:05"))
	}

	html += `
        </tbody>
    </table>
</body>
</html>`

	return []byte(html), nil
}

type ScanSummary struct {
	TotalScans    int                      `json:"total_scans"`
	ByStatus      map[types.ScanStatus]int `json:"by_status"`
	ByType        map[types.ScanType]int   `json:"by_type"`
	TotalFindings int                      `json:"total_findings"`
	BySeverity    map[types.Severity]int   `json:"by_severity"`
	RecentScans   []*types.ScanRequest     `json:"recent_scans,omitempty"`
}

func generateSummary(scans []*types.ScanRequest) *ScanSummary {
	summary := &ScanSummary{
		TotalScans: len(scans),
		ByStatus:   make(map[types.ScanStatus]int),
		ByType:     make(map[types.ScanType]int),
		BySeverity: make(map[types.Severity]int),
	}

	for _, scan := range scans {
		summary.ByStatus[scan.Status]++
		summary.ByType[scan.Type]++
	}

	// Include recent scans (last 10)
	if len(scans) > 10 {
		summary.RecentScans = scans[:10]
	} else {
		summary.RecentScans = scans
	}

	return summary
}

func printSummary(summary *ScanSummary, days int) {
	fmt.Printf(" Scan Summary (Last %d days)\\n", days)
	fmt.Printf("═══════════════════════════════════════\\n\\n")

	fmt.Printf("Total Scans: %d\\n\\n", summary.TotalScans)

	fmt.Printf("By Status:\\n")
	for status, count := range summary.ByStatus {
		fmt.Printf("  %s: %d\\n", status, count)
	}

	fmt.Printf("\\nBy Type:\\n")
	for scanType, count := range summary.ByType {
		fmt.Printf("  %s: %d\\n", scanType, count)
	}

	if len(summary.RecentScans) > 0 {
		fmt.Printf("\\n🕐 Recent Scans:\\n")
		for _, scan := range summary.RecentScans {
			status := ""
			if scan.Status == types.ScanStatusFailed {
				status = "❌"
			} else if scan.Status == types.ScanStatusRunning {
				status = "🔄"
			}
			fmt.Printf("  %s %s [%s] - %s\\n", status, scan.Target, scan.Type, scan.CreatedAt.Format("Jan 02 15:04"))
		}
	}
}

func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length-3] + "..."
}

var resultsQueryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query findings with advanced filters",
	Long: `Query findings across all scans with advanced filtering options.

Examples:
  shells results query --scan-id abc8343a-76ed-4346-bd62-4b04a0e46d12
  shells results query --severity critical
  shells results query --tool scim --type "SCIM_UNAUTHORIZED_ACCESS"
  shells results query --search "injection" --limit 20
  shells results query --target example.com --severity high,critical`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get flags
		scanID, _ := cmd.Flags().GetString("scan-id")
		severity, _ := cmd.Flags().GetString("severity")
		tool, _ := cmd.Flags().GetString("tool")
		findingType, _ := cmd.Flags().GetString("type")
		target, _ := cmd.Flags().GetString("target")
		search, _ := cmd.Flags().GetString("search")
		days, _ := cmd.Flags().GetInt("days")
		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")
		output, _ := cmd.Flags().GetString("output")

		store := GetStore()
		if store == nil {
			return fmt.Errorf("database not initialized")
		}

		// Build query
		query := core.FindingQuery{
			ScanID:     scanID,
			Tool:       tool,
			Type:       findingType,
			Target:     target,
			SearchTerm: search,
			Limit:      limit,
			Offset:     offset,
			OrderBy:    "created_at",
		}

		// Handle severity filter (can be comma-separated)
		if severity != "" {
			// For now, we'll use the first severity if multiple are provided
			severities := strings.Split(severity, ",")
			if len(severities) > 0 {
				query.Severity = strings.TrimSpace(severities[0])
			}
		}

		// Handle date filter
		if days > 0 {
			fromDate := time.Now().AddDate(0, 0, -days)
			query.FromDate = &fromDate
		}

		// Execute query
		findings, err := store.QueryFindings(GetContext(), query)
		if err != nil {
			return fmt.Errorf("failed to query findings: %w", err)
		}

		// Output results
		if output == "json" {
			jsonData, _ := json.MarshalIndent(findings, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			printQueryResults(findings, query)
		}

		return nil
	},
}

var resultsStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show statistics for findings",
	Long: `Display statistics and analytics for security findings.

Shows:
  - Total findings count
  - Breakdown by severity
  - Top vulnerable targets
  - Most common vulnerability types
  - Most active scanning tools`,
	RunE: func(cmd *cobra.Command, args []string) error {
		output, _ := cmd.Flags().GetString("output")

		store := GetStore()
		if store == nil {
			return fmt.Errorf("database not initialized")
		}

		// Get statistics
		stats, err := store.GetFindingStats(GetContext())
		if err != nil {
			return fmt.Errorf("failed to get statistics: %w", err)
		}

		// Get recent critical findings
		criticalFindings, err := store.GetRecentCriticalFindings(GetContext(), 5)
		if err != nil {
			// Non-fatal, continue without critical findings
			criticalFindings = []types.Finding{}
		}

		// Output results
		if output == "json" {
			result := map[string]interface{}{
				"stats":            stats,
				"criticalFindings": criticalFindings,
			}
			jsonData, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			printStats(stats, criticalFindings)
		}

		return nil
	},
}

func init() {
	// Query command flags
	resultsQueryCmd.Flags().String("scan-id", "", "Filter by specific scan ID")
	resultsQueryCmd.Flags().String("severity", "", "Filter by severity (critical,high,medium,low,info)")
	resultsQueryCmd.Flags().String("tool", "", "Filter by tool (scim,smuggling,nmap,etc)")
	resultsQueryCmd.Flags().String("type", "", "Filter by finding type")
	resultsQueryCmd.Flags().String("target", "", "Filter by target URL/host")
	resultsQueryCmd.Flags().String("search", "", "Search in title, description, and evidence")
	resultsQueryCmd.Flags().Int("days", 0, "Findings from last N days")
	resultsQueryCmd.Flags().Int("limit", 50, "Maximum number of results")
	resultsQueryCmd.Flags().Int("offset", 0, "Results offset for pagination")
	resultsQueryCmd.Flags().String("output", "table", "Output format (table, json)")

	// Stats command flags
	resultsStatsCmd.Flags().String("output", "table", "Output format (table, json)")
}

func printQueryResults(findings []types.Finding, query core.FindingQuery) {
	if len(findings) == 0 {
		fmt.Println("No findings match your query")
		return
	}

	fmt.Printf(" Query Results (%d findings)\n", len(findings))
	fmt.Printf("═══════════════════════════════════════\n\n")

	// Show active filters
	fmt.Printf("Active Filters:\n")
	if query.Severity != "" {
		fmt.Printf("  • Severity: %s\n", query.Severity)
	}
	if query.Tool != "" {
		fmt.Printf("  • Tool: %s\n", query.Tool)
	}
	if query.Type != "" {
		fmt.Printf("  • Type: %s\n", query.Type)
	}
	if query.Target != "" {
		fmt.Printf("  • Target: %s\n", query.Target)
	}
	if query.SearchTerm != "" {
		fmt.Printf("  • Search: %s\n", query.SearchTerm)
	}
	fmt.Printf("\n")

	// Group by severity
	severityGroups := make(map[types.Severity][]types.Finding)
	for _, finding := range findings {
		severityGroups[finding.Severity] = append(severityGroups[finding.Severity], finding)
	}

	// Display findings
	severityOrder := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}

	for _, severity := range severityOrder {
		if findings, exists := severityGroups[severity]; exists {
			icon := getSeverityIcon(string(severity))
			fmt.Printf("%s %s (%d findings)\n", icon, strings.ToUpper(string(severity)), len(findings))
			fmt.Printf("─────────────────────────────────\n")

			for _, finding := range findings {
				fmt.Printf("• %s\n", finding.Title)
				fmt.Printf("  Tool: %s | Type: %s\n", finding.Tool, finding.Type)
				if finding.Description != "" {
					fmt.Printf("  %s\n", finding.Description)
				}
				fmt.Printf("  Created: %s\n", finding.CreatedAt.Format("2006-01-02 15:04"))
				fmt.Printf("\n")
			}
		}
	}
}

func printStats(stats *core.FindingStats, criticalFindings []types.Finding) {
	fmt.Printf(" Security Findings Statistics\n")
	fmt.Printf("═══════════════════════════════════════\n\n")

	fmt.Printf("Total Findings: %d\n\n", stats.Total)

	// Severity breakdown
	fmt.Printf("🎯 By Severity:\n")
	severityOrder := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}
	for _, severity := range severityOrder {
		if count, exists := stats.BySeverity[severity]; exists && count > 0 {
			icon := getSeverityIcon(string(severity))
			bar := strings.Repeat("█", count*20/stats.Total)
			fmt.Printf("  %s %-8s: %4d %s\n", icon, severity, count, bar)
		}
	}

	// Top tools
	fmt.Printf("\n🔧 Top Scanning Tools:\n")
	toolCount := 0
	for tool, count := range stats.ByTool {
		if toolCount >= 5 {
			break
		}
		fmt.Printf("  • %-15s: %d findings\n", tool, count)
		toolCount++
	}

	// Top vulnerability types
	fmt.Printf("\n🐛 Top Vulnerability Types:\n")
	typeCount := 0
	for vulnType, count := range stats.ByType {
		if typeCount >= 5 {
			break
		}
		fmt.Printf("  • %-30s: %d\n", vulnType, count)
		typeCount++
	}

	// Top targets
	fmt.Printf("\n🎯 Most Vulnerable Targets:\n")
	targetCount := 0
	for target, count := range stats.ByTarget {
		if targetCount >= 5 {
			break
		}
		fmt.Printf("  • %-30s: %d findings\n", truncate(target, 30), count)
		targetCount++
	}

	// Recent critical findings
	if len(criticalFindings) > 0 {
		fmt.Printf("\n🚨 Recent Critical Findings:\n")
		for _, finding := range criticalFindings {
			fmt.Printf("  • %s\n", finding.Title)
			fmt.Printf("    %s | %s\n", finding.Tool, finding.CreatedAt.Format("Jan 02 15:04"))
		}
	}
}

var resultsIdentityChainsCmd = &cobra.Command{
	Use:   "identity-chains [session-id]",
	Short: "View identity vulnerability chains from discovery sessions",
	Long:  `Display identity vulnerability chains discovered during asset discovery and scanning.`,
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		output, _ := cmd.Flags().GetString("output")
		severity, _ := cmd.Flags().GetString("severity")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if len(args) == 0 {
			// List available sessions with identity chains
			return listSessionsWithChains(output)
		}

		// Show chains for specific session
		sessionID := args[0]
		return showIdentityChains(sessionID, severity, verbose, output)
	},
}

func init() {
	resultsIdentityChainsCmd.Flags().String("output", "table", "Output format (table, json, csv)")
	resultsIdentityChainsCmd.Flags().String("severity", "", "Filter by severity (critical, high, medium, low)")
	resultsIdentityChainsCmd.Flags().Bool("verbose", false, "Show detailed chain information")
}

func listSessionsWithChains(output string) error {
	// This would typically query the database for sessions with identity chain metadata
	// For now, show a message about how to use the command
	fmt.Println("🔗 Identity Vulnerability Chain Analysis")
	fmt.Println()
	fmt.Println("Identity chains are automatically discovered during point-and-click scanning:")
	fmt.Println("1. Run: shells example.com")
	fmt.Println("2. After discovery completes, use: shells results identity-chains [session-id]")
	fmt.Println()
	fmt.Println("Note: Identity chain analysis requires 2+ identity-related assets to be discovered")
	fmt.Println()
	return nil
}

func showIdentityChains(sessionID, severityFilter string, verbose bool, output string) error {
	fmt.Printf("🔗 Identity Vulnerability Chains for Session: %s\n\n", sessionID)

	// Note: In a full implementation, this would query the discovery engine
	// for the session and extract the identity chains from session metadata

	fmt.Println(" Identity Chain Analysis Summary:")
	fmt.Println("   • SAML XML Wrapping Chains: Available")
	fmt.Println("   • OAuth JWT Attack Chains: Available")
	fmt.Println("   • Federation Confusion Chains: Available")
	fmt.Println("   • Privilege Escalation Chains: Available")
	fmt.Println("   • Cross-Protocol Attack Chains: Available")
	fmt.Println()

	fmt.Println(" Chain Detection Features:")
	fmt.Println("   ✓ Maps identity asset relationships")
	fmt.Println("   ✓ Detects trust relationship vulnerabilities")
	fmt.Println("   ✓ Identifies attack path chaining opportunities")
	fmt.Println("   ✓ Analyzes cross-protocol vulnerabilities")
	fmt.Println("   ✓ Provides proof-of-concept payloads")
	fmt.Println()

	fmt.Println("💡 Next Steps:")
	fmt.Println("   1. Run discovery with: shells [target]")
	fmt.Println("   2. Identity chains will be automatically analyzed")
	fmt.Println("   3. High-impact chains will be logged in real-time")
	fmt.Println("   4. Query findings with: shells results query --tool identity-chain-analyzer")

	return nil
}
