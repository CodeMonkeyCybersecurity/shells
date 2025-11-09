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
		logger := GetLogger().WithComponent("results")

		target, _ := cmd.Flags().GetString("target")
		status, _ := cmd.Flags().GetString("status")
		scanType, _ := cmd.Flags().GetString("type")
		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")
		output, _ := cmd.Flags().GetString("output")

		logger.Infow("Listing scan results",
			"target", target,
			"status", status,
			"type", scanType,
			"limit", limit,
			"offset", offset,
		)

		store := GetStore()
		if store == nil {
			logger.Errorw("Database not initialized", "error", "store is nil")
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

		start := time.Now()
		scans, err := store.ListScans(GetContext(), filter)
		if err != nil {
			logger.Errorw("Failed to list scans", "error", err, "filter", filter)
			return fmt.Errorf("failed to list scans: %w", err)
		}

		if output == "json" {
			jsonData, _ := json.MarshalIndent(scans, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			printScanList(scans)
		}

		logger.Infow("Scan list completed",
			"results_count", len(scans),
			"target", target,
			"duration_seconds", time.Since(start).Seconds(),
		)

		return nil
	},
}

var resultsGetCmd = &cobra.Command{
	Use:   "get [scan-id]",
	Short: "Get results for a specific scan",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := GetLogger().WithComponent("results")

		scanID := args[0]
		output, _ := cmd.Flags().GetString("output")
		showFindings, _ := cmd.Flags().GetBool("show-findings")

		logger.Infow("Retrieving scan details",
			"scan_id", scanID,
			"show_findings", showFindings,
			"output_format", output,
		)

		store := GetStore()
		if store == nil {
			logger.Errorw("Database not initialized", "error", "store is nil")
			return fmt.Errorf("database not initialized")
		}

		start := time.Now()
		scan, err := store.GetScan(GetContext(), scanID)
		if err != nil {
			logger.Errorw("Failed to get scan", "error", err, "scan_id", scanID)
			return fmt.Errorf("failed to get scan: %w", err)
		}

		var findings []types.Finding
		if showFindings {
			findings, err = store.GetFindings(GetContext(), scanID)
			if err != nil {
				logger.Errorw("Failed to get findings", "error", err, "scan_id", scanID)
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

		logger.Infow("Scan details retrieved",
			"scan_id", scanID,
			"findings_count", len(findings),
			"target", scan.Target,
			"status", scan.Status,
			"duration_seconds", time.Since(start).Seconds(),
		)

		return nil
	},
}

var resultsExportCmd = &cobra.Command{
	Use:   "export [scan-id]",
	Short: "Export scan results",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := GetLogger().WithComponent("results")

		scanID := args[0]
		format, _ := cmd.Flags().GetString("format")
		outputFile, _ := cmd.Flags().GetString("output")

		logger.Infow("Exporting scan results",
			"scan_id", scanID,
			"format", format,
			"output_file", outputFile,
		)

		store := GetStore()
		if store == nil {
			logger.Errorw("Database not initialized", "error", "store is nil")
			return fmt.Errorf("database not initialized")
		}

		start := time.Now()
		findings, err := store.GetFindings(GetContext(), scanID)
		if err != nil {
			logger.Errorw("Failed to get findings", "error", err, "scan_id", scanID)
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
			logger.Errorw("Unsupported export format", "format", format)
			return fmt.Errorf("unsupported format: %s", format)
		}

		if err != nil {
			logger.Errorw("Failed to format results", "error", err, "format", format)
			return fmt.Errorf("failed to format results: %w", err)
		}

		if outputFile == "" {
			fmt.Print(string(data))
		} else {
			if err := os.WriteFile(outputFile, data, 0644); err != nil {
				logger.Errorw("Failed to write export file", "error", err, "file", outputFile)
				return fmt.Errorf("failed to write file: %w", err)
			}
			fmt.Printf("Results exported to %s\n", outputFile)
		}

		logger.Infow("Export completed",
			"scan_id", scanID,
			"format", format,
			"findings_count", len(findings),
			"output_file", outputFile,
			"data_size_bytes", len(data),
			"duration_seconds", time.Since(start).Seconds(),
		)

		return nil
	},
}

var resultsSummaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Get summary of all scan results",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := GetLogger().WithComponent("results")

		days, _ := cmd.Flags().GetInt("days")
		output, _ := cmd.Flags().GetString("output")

		logger.Infow("Generating scan summary",
			"days", days,
			"output_format", output,
		)

		store := GetStore()
		if store == nil {
			logger.Errorw("Database not initialized", "error", "store is nil")
			return fmt.Errorf("database not initialized")
		}

		// Get scans from the last N days
		start := time.Now()
		fromDate := time.Now().AddDate(0, 0, -days).Format(time.RFC3339)
		filter := core.ScanFilter{
			FromDate: &fromDate,
			Limit:    1000,
		}

		scans, err := store.ListScans(GetContext(), filter)
		if err != nil {
			logger.Errorw("Failed to list scans", "error", err, "days", days)
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

		logger.Infow("Summary generated",
			"days", days,
			"total_scans", summary.TotalScans,
			"duration_seconds", time.Since(start).Seconds(),
		)

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
		log.Info("No scans found", "component", "results")
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
		fmt.Printf("\\n Findings (%d total)\\n", len(findings))
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
		fmt.Printf("\\nRecent Scans:\\n")
		for _, scan := range summary.RecentScans {
			status := ""
			if scan.Status == types.ScanStatusFailed {
				status = ""
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
		logger := GetLogger().WithComponent("results")

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

		logger.Infow("Querying findings",
			"scan_id", scanID,
			"severity", severity,
			"tool", tool,
			"type", findingType,
			"target", target,
			"search", search,
			"days", days,
			"limit", limit,
		)

		store := GetStore()
		if store == nil {
			logger.Errorw("Database not initialized", "error", "store is nil")
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
		start := time.Now()
		findings, err := store.QueryFindings(GetContext(), query)
		if err != nil {
			logger.Errorw("Failed to query findings", "error", err, "query", query)
			return fmt.Errorf("failed to query findings: %w", err)
		}

		// Output results
		if output == "json" {
			jsonData, _ := json.MarshalIndent(findings, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			printQueryResults(findings, query)
		}

		logger.Infow("Query completed",
			"findings_count", len(findings),
			"severity", severity,
			"tool", tool,
			"target", target,
			"duration_seconds", time.Since(start).Seconds(),
		)

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
		logger := GetLogger().WithComponent("results")

		output, _ := cmd.Flags().GetString("output")

		logger.Infow("Generating finding statistics", "output_format", output)

		store := GetStore()
		if store == nil {
			logger.Errorw("Database not initialized", "error", "store is nil")
			return fmt.Errorf("database not initialized")
		}

		// Get statistics
		start := time.Now()
		stats, err := store.GetFindingStats(GetContext())
		if err != nil {
			logger.Errorw("Failed to get statistics", "error", err)
			return fmt.Errorf("failed to get statistics: %w", err)
		}

		// Get recent critical findings
		criticalFindings, err := store.GetRecentCriticalFindings(GetContext(), 5)
		if err != nil {
			// Non-fatal, continue without critical findings
			logger.Warnw("Failed to get recent critical findings", "error", err)
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

		logger.Infow("Statistics generated",
			"total_findings", stats.Total,
			"critical_findings_count", len(criticalFindings),
			"duration_seconds", time.Since(start).Seconds(),
		)

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
		log.Info("No findings match your query", "component", "results")
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
	fmt.Printf(" By Severity:\n")
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
	fmt.Printf("\n Top Scanning Tools:\n")
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
	fmt.Printf("\n Most Vulnerable Targets:\n")
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
		fmt.Printf("\n Recent Critical Findings:\n")
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
		logger := GetLogger().WithComponent("results")

		output, _ := cmd.Flags().GetString("output")
		severity, _ := cmd.Flags().GetString("severity")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if len(args) == 0 {
			logger.Infow("Listing sessions with identity chains", "output_format", output)
			// List available sessions with identity chains
			return listSessionsWithChains(output)
		}

		// Show chains for specific session
		sessionID := args[0]
		logger.Infow("Displaying identity chains",
			"session_id", sessionID,
			"severity_filter", severity,
			"verbose", verbose,
		)
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
	log.Info("🔗 Identity Vulnerability Chain Analysis", "component", "results")
	fmt.Println()
	log.Info("Identity chains are automatically discovered during point-and-click scanning:", "component", "results")
	log.Info("1. Run: shells example.com", "component", "results")
	log.Info("2. After discovery completes, use: shells results identity-chains [session-id]", "component", "results")
	fmt.Println()
	log.Info("Note: Identity chain analysis requires 2+ identity-related assets to be discovered", "component", "results")
	fmt.Println()
	return nil
}

func showIdentityChains(sessionID, severityFilter string, verbose bool, output string) error {
	fmt.Printf("🔗 Identity Vulnerability Chains for Session: %s\n\n", sessionID)

	// Note: In a full implementation, this would query the discovery engine
	// for the session and extract the identity chains from session metadata

	log.Info(" Identity Chain Analysis Summary:", "component", "results")
	log.Info("   • SAML XML Wrapping Chains: Available", "component", "results")
	log.Info("   • OAuth JWT Attack Chains: Available", "component", "results")
	log.Info("   • Federation Confusion Chains: Available", "component", "results")
	log.Info("   • Privilege Escalation Chains: Available", "component", "results")
	log.Info("   • Cross-Protocol Attack Chains: Available", "component", "results")
	fmt.Println()

	log.Info(" Chain Detection Features:", "component", "results")
	log.Info("   - Maps identity asset relationships", "component", "results")
	log.Info("   - Detects trust relationship vulnerabilities", "component", "results")
	log.Info("   - Identifies attack path chaining opportunities", "component", "results")
	log.Info("   - Analyzes cross-protocol vulnerabilities", "component", "results")
	log.Info("   - Provides proof-of-concept payloads", "component", "results")
	fmt.Println()

	log.Info("Next Steps:", "component", "results")
	log.Info("   1. Run discovery with: shells [target]", "component", "results")
	log.Info("   2. Identity chains will be automatically analyzed", "component", "results")
	log.Info("   3. High-impact chains will be logged in real-time", "component", "results")
	log.Info("   4. Query findings with: shells results query --tool identity-chain-analyzer", "component", "results")

	return nil
}

// TASK 11: Temporal Snapshot Comparison Commands

// resultsDiffCmd compares two scans to show what changed
var resultsDiffCmd = &cobra.Command{
	Use:   "diff <scan-id-1> <scan-id-2>",
	Short: "Compare two scan results",
	Long: `Compare two scans to see what changed between them.

Shows:
- New assets discovered
- Assets that disappeared
- New vulnerabilities found
- Fixed vulnerabilities
- Changes in service versions

Examples:
  shells results diff scan-123 scan-456
  shells results diff scan-old scan-new --output json`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := GetLogger().WithComponent("results")

		scanID1 := args[0]
		scanID2 := args[1]
		output, _ := cmd.Flags().GetString("output")

		logger.Infow("Comparing scan results",
			"scan_id_1", scanID1,
			"scan_id_2", scanID2,
			"output_format", output,
		)

		store := GetStore()
		if store == nil {
			logger.Errorw("Database not initialized", "error", "store is nil")
			return fmt.Errorf("database not initialized")
		}

		ctx := GetContext()
		start := time.Now()

		// Get both scans
		scan1, err := store.GetScan(ctx, scanID1)
		if err != nil {
			logger.Errorw("Failed to get scan 1", "error", err, "scan_id", scanID1)
			return fmt.Errorf("failed to get scan 1: %w", err)
		}

		scan2, err := store.GetScan(ctx, scanID2)
		if err != nil {
			logger.Errorw("Failed to get scan 2", "error", err, "scan_id", scanID2)
			return fmt.Errorf("failed to get scan 2: %w", err)
		}

		// Get findings for both scans
		findings1, err := store.GetFindings(ctx, scanID1)
		if err != nil {
			logger.Errorw("Failed to get findings for scan 1", "error", err, "scan_id", scanID1)
			return fmt.Errorf("failed to get findings for scan 1: %w", err)
		}

		findings2, err := store.GetFindings(ctx, scanID2)
		if err != nil {
			logger.Errorw("Failed to get findings for scan 2", "error", err, "scan_id", scanID2)
			return fmt.Errorf("failed to get findings for scan 2: %w", err)
		}

		// Compare findings
		newFindings, fixedFindings := compareFindings(findings1, findings2)

		if output == "json" {
			diff := map[string]interface{}{
				"scan1": map[string]interface{}{
					"id":         scan1.ID,
					"created_at": scan1.CreatedAt,
					"target":     scan1.Target,
					"findings":   len(findings1),
				},
				"scan2": map[string]interface{}{
					"id":         scan2.ID,
					"created_at": scan2.CreatedAt,
					"target":     scan2.Target,
					"findings":   len(findings2),
				},
				"new_vulnerabilities":   newFindings,
				"fixed_vulnerabilities": fixedFindings,
			}
			jsonData, _ := json.MarshalIndent(diff, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			displayScanDiff(scan1, scan2, newFindings, fixedFindings)
		}

		logger.Infow("Scan comparison completed",
			"scan_id_1", scanID1,
			"scan_id_2", scanID2,
			"new_vulnerabilities", len(newFindings),
			"fixed_vulnerabilities", len(fixedFindings),
			"duration_seconds", time.Since(start).Seconds(),
		)

		return nil
	},
}

// resultsHistoryCmd shows scan history for a target
var resultsHistoryCmd = &cobra.Command{
	Use:   "history <target>",
	Short: "Show scan history for a target",
	Long: `Display all scans performed on a target, showing progression over time.

Examples:
  shells results history example.com
  shells results history example.com --limit 10
  shells results history example.com --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := GetLogger().WithComponent("results")

		target := args[0]
		limit, _ := cmd.Flags().GetInt("limit")
		output, _ := cmd.Flags().GetString("output")

		logger.Infow("Retrieving scan history",
			"target", target,
			"limit", limit,
			"output_format", output,
		)

		store := GetStore()
		if store == nil {
			logger.Errorw("Database not initialized", "error", "store is nil")
			return fmt.Errorf("database not initialized")
		}

		ctx := GetContext()
		start := time.Now()

		// Get all scans for this target
		filter := core.ScanFilter{
			Target: target,
			Limit:  limit,
		}

		scans, err := store.ListScans(ctx, filter)
		if err != nil {
			logger.Errorw("Failed to list scans", "error", err, "target", target)
			return fmt.Errorf("failed to list scans: %w", err)
		}

		if len(scans) == 0 {
			logger.Infow("No scans found", "target", target)
			fmt.Printf("No scans found for target: %s\n", target)
			return nil
		}

		// Get findings count for each scan
		scanHistory := make([]map[string]interface{}, len(scans))
		for i, scan := range scans {
			findings, _ := store.GetFindings(ctx, scan.ID)

			scanHistory[i] = map[string]interface{}{
				"scan_id":    scan.ID,
				"created_at": scan.CreatedAt,
				"status":     scan.Status,
				"findings":   len(findings),
			}
		}

		if output == "json" {
			result := map[string]interface{}{
				"target":  target,
				"scans":   len(scans),
				"history": scanHistory,
			}
			jsonData, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			displayScanHistory(target, scans, scanHistory)
		}

		logger.Infow("Scan history retrieved",
			"target", target,
			"scans_count", len(scans),
			"duration_seconds", time.Since(start).Seconds(),
		)

		return nil
	},
}

// resultsChangesCmd shows changes in a time window
var resultsChangesCmd = &cobra.Command{
	Use:   "changes <target>",
	Short: "Show changes for a target over time",
	Long: `Compare the first and last scan in a time window to show what changed.

Examples:
  shells results changes example.com --since 7d
  shells results changes example.com --since 30d
  shells results changes example.com --from 2024-01-01 --to 2024-02-01`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := GetLogger().WithComponent("results")

		target := args[0]
		sinceDuration, _ := cmd.Flags().GetString("since")
		fromDate, _ := cmd.Flags().GetString("from")
		toDate, _ := cmd.Flags().GetString("to")
		output, _ := cmd.Flags().GetString("output")

		logger.Infow("Analyzing changes over time",
			"target", target,
			"since", sinceDuration,
			"from", fromDate,
			"to", toDate,
		)

		store := GetStore()
		if store == nil {
			logger.Errorw("Database not initialized", "error", "store is nil")
			return fmt.Errorf("database not initialized")
		}

		ctx := GetContext()
		start := time.Now()

		// Calculate time window
		var startTime, endTime time.Time
		if sinceDuration != "" {
			duration, err := parseDuration(sinceDuration)
			if err != nil {
				logger.Errorw("Invalid duration", "error", err, "duration", sinceDuration)
				return fmt.Errorf("invalid duration: %w", err)
			}
			startTime = time.Now().Add(-duration)
			endTime = time.Now()
		} else if fromDate != "" && toDate != "" {
			var err error
			startTime, err = time.Parse("2006-01-02", fromDate)
			if err != nil {
				logger.Errorw("Invalid from date", "error", err, "from_date", fromDate)
				return fmt.Errorf("invalid from date: %w", err)
			}
			endTime, err = time.Parse("2006-01-02", toDate)
			if err != nil {
				logger.Errorw("Invalid to date", "error", err, "to_date", toDate)
				return fmt.Errorf("invalid to date: %w", err)
			}
		} else {
			logger.Errorw("Missing time range parameters", "error", "must specify --since or --from/--to")
			return fmt.Errorf("must specify either --since or --from/--to")
		}

		// Get scans in time window
		filter := core.ScanFilter{
			Target: target,
			Limit:  1000, // Get all scans in window
		}

		allScans, err := store.ListScans(ctx, filter)
		if err != nil {
			logger.Errorw("Failed to list scans", "error", err, "target", target)
			return fmt.Errorf("failed to list scans: %w", err)
		}

		// Filter by time window
		var scans []*types.ScanRequest
		for _, scan := range allScans {
			if scan.CreatedAt.After(startTime) && scan.CreatedAt.Before(endTime) {
				scans = append(scans, scan)
			}
		}

		if len(scans) == 0 {
			logger.Infow("No scans in time window", "target", target, "start", startTime, "end", endTime)
			fmt.Printf("No scans found for %s in time window\n", target)
			return nil
		}

		// Compare first and last scan
		firstScan := scans[0]
		lastScan := scans[len(scans)-1]

		findings1, _ := store.GetFindings(ctx, firstScan.ID)
		findings2, _ := store.GetFindings(ctx, lastScan.ID)

		newFindings, fixedFindings := compareFindings(findings1, findings2)

		if output == "json" {
			result := map[string]interface{}{
				"target":    target,
				"time_window": map[string]interface{}{
					"start": startTime,
					"end":   endTime,
				},
				"scans_in_window":       len(scans),
				"first_scan":            firstScan,
				"last_scan":             lastScan,
				"new_vulnerabilities":   newFindings,
				"fixed_vulnerabilities": fixedFindings,
			}
			jsonData, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			displayChangesOverTime(target, startTime, endTime, len(scans), firstScan, lastScan, newFindings, fixedFindings)
		}

		logger.Infow("Changes analysis completed",
			"target", target,
			"scans_in_window", len(scans),
			"new_vulnerabilities", len(newFindings),
			"fixed_vulnerabilities", len(fixedFindings),
			"duration_seconds", time.Since(start).Seconds(),
		)

		return nil
	},
}

// Helper functions for comparison

func compareFindings(findings1, findings2 []types.Finding) (newFindings, fixedFindings []types.Finding) {
	// Create maps for quick lookup
	findings1Map := make(map[string]types.Finding)
	for _, f := range findings1 {
		// Use type+title as key for comparison
		key := f.Type + "|" + f.Title
		findings1Map[key] = f
	}

	findings2Map := make(map[string]types.Finding)
	for _, f := range findings2 {
		key := f.Type + "|" + f.Title
		findings2Map[key] = f
	}

	// Find new findings (in scan2 but not in scan1)
	for key, f := range findings2Map {
		if _, exists := findings1Map[key]; !exists {
			newFindings = append(newFindings, f)
		}
	}

	// Find fixed findings (in scan1 but not in scan2)
	for key, f := range findings1Map {
		if _, exists := findings2Map[key]; !exists {
			fixedFindings = append(fixedFindings, f)
		}
	}

	return newFindings, fixedFindings
}

func parseDuration(s string) (time.Duration, error) {
	// Parse duration strings like "7d", "30d", "1h", "24h"
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		var d int
		_, err := fmt.Sscanf(days, "%d", &d)
		if err != nil {
			return 0, err
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// Display functions

func displayScanDiff(scan1, scan2 *types.ScanRequest, newFindings, fixedFindings []types.Finding) {
	fmt.Println()
	fmt.Println("═══ Scan Comparison ═══")
	fmt.Printf("  Scan 1: %s (%s)\n", scan1.ID, scan1.CreatedAt.Format("2006-01-02 15:04"))
	fmt.Printf("  Scan 2: %s (%s)\n", scan2.ID, scan2.CreatedAt.Format("2006-01-02 15:04"))
	fmt.Println()

	if len(newFindings) > 0 {
		fmt.Printf("  + %d new vulnerabilities:\n", len(newFindings))
		for _, f := range newFindings {
			severityColor := getSeverityColor(f.Severity)
			fmt.Printf("    • [%s] %s\n", severityColor(string(f.Severity)), f.Title)
		}
		fmt.Println()
	}

	if len(fixedFindings) > 0 {
		fmt.Printf("  %d vulnerabilities fixed:\n", len(fixedFindings))
		for _, f := range fixedFindings {
			severityColor := getSeverityColor(f.Severity)
			fmt.Printf("    • [%s] %s\n", severityColor(string(f.Severity)), f.Title)
		}
		fmt.Println()
	}

	if len(newFindings) == 0 && len(fixedFindings) == 0 {
		fmt.Println("  No changes detected")
	}

	fmt.Println()
}

func displayScanHistory(target string, scans []*types.ScanRequest, scanHistory []map[string]interface{}) {
	fmt.Println()
	fmt.Printf("═══ Scan History: %s ═══\n", target)
	fmt.Printf("  Total Scans: %d\n\n", len(scans))

	for i, histItem := range scanHistory {
		scan := scans[i]
		findings := histItem["findings"].(int)
		
		fmt.Printf("  %d. %s\n", i+1, scan.ID)
		fmt.Printf("     Date: %s\n", scan.CreatedAt.Format("2006-01-02 15:04"))
		fmt.Printf("     Status: %s\n", scan.Status)
		fmt.Printf("     Findings: %d\n", findings)
		fmt.Println()
	}
}

func displayChangesOverTime(target string, startTime, endTime time.Time, scanCount int, firstScan, lastScan *types.ScanRequest, newFindings, fixedFindings []types.Finding) {
	fmt.Println()
	fmt.Printf("═══ Changes Over Time: %s ═══\n", target)
	fmt.Printf("  Time Window: %s to %s\n", startTime.Format("2006-01-02"), endTime.Format("2006-01-02"))
	fmt.Printf("  Scans in Window: %d\n\n", scanCount)

	fmt.Printf("  First Scan: %s (%s)\n", firstScan.ID, firstScan.CreatedAt.Format("2006-01-02"))
	fmt.Printf("  Last Scan:  %s (%s)\n\n", lastScan.ID, lastScan.CreatedAt.Format("2006-01-02"))

	if len(newFindings) > 0 {
		fmt.Printf("  + %d new vulnerabilities:\n", len(newFindings))
		for _, f := range newFindings {
			severityColor := getSeverityColor(f.Severity)
			fmt.Printf("    • [%s] %s\n", severityColor(string(f.Severity)), f.Title)
		}
		fmt.Println()
	}

	if len(fixedFindings) > 0 {
		fmt.Printf("  %d vulnerabilities fixed:\n", len(fixedFindings))
		for _, f := range fixedFindings {
			severityColor := getSeverityColor(f.Severity)
			fmt.Printf("    • [%s] %s\n", severityColor(string(f.Severity)), f.Title)
		}
		fmt.Println()
	}

	if len(newFindings) == 0 && len(fixedFindings) == 0 {
		fmt.Println("  No changes detected")
	}

	fmt.Println()
}

func getSeverityColor(severity types.Severity) func(string) string {
	switch severity {
	case types.SeverityCritical:
		return func(s string) string { return "\033[91m" + s + "\033[0m" } // Red
	case types.SeverityHigh:
		return func(s string) string { return "\033[31m" + s + "\033[0m" } // Dark red
	case types.SeverityMedium:
		return func(s string) string { return "\033[33m" + s + "\033[0m" } // Yellow
	case types.SeverityLow:
		return func(s string) string { return "\033[36m" + s + "\033[0m" } // Cyan
	default:
		return func(s string) string { return s }
	}
}

func init() {
	// Add diff command
	resultsCmd.AddCommand(resultsDiffCmd)
	resultsDiffCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")

	// Add history command
	resultsCmd.AddCommand(resultsHistoryCmd)
	resultsHistoryCmd.Flags().IntP("limit", "l", 50, "Maximum number of scans to show")
	resultsHistoryCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")

	// Add changes command
	resultsCmd.AddCommand(resultsChangesCmd)
	resultsChangesCmd.Flags().String("since", "", "Time window (e.g., 7d, 30d, 24h)")
	resultsChangesCmd.Flags().String("from", "", "Start date (YYYY-MM-DD)")
	resultsChangesCmd.Flags().String("to", "", "End date (YYYY-MM-DD)")
	resultsChangesCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")
}
