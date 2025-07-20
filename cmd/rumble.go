// cmd/rumble.go
package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/integrations/rumble"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rumbleCmd = &cobra.Command{
	Use:   "rumble",
	Short: "Advanced asset discovery using rumble",
	Long: `Integrate with rumble (formerly Rumble) for comprehensive asset discovery and network fingerprinting.

rumble provides deep network discovery capabilities including:
- Unauthenticated asset discovery
- Service fingerprinting and version detection
- Operating system detection
- Certificate extraction and analysis
- Network topology mapping
- Vulnerability correlation

This integration requires a rumble API key. Set it via:
  export rumble_API_KEY="your-api-key"
Or in your config file under rumble.api_key

Examples:
  shells rumble discover 192.168.1.0/24
  shells rumble discover example.com
  shells rumble scan --deep --vuln-scan 10.0.0.0/16
  shells rumble assets --filter "os:windows"
  shells rumble export --format json --output assets.json`,
}

var rumbleDiscoverCmd = &cobra.Command{
	Use:   "discover [target]",
	Short: "Perform network discovery",
	Long: `Discover assets in a network range or for a specific target.

This performs a fast network discovery scan to identify:
- Live hosts and their IP addresses
- Basic service detection
- Operating system fingerprinting
- Network device identification

Examples:
  shells rumble discover 192.168.1.0/24
  shells rumble discover 10.0.0.0/8 --rate 5000
  shells rumble discover example.com`,
	Args: cobra.ExactArgs(1),
	RunE: runrumbleDiscover,
}

var rumbleScanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Perform detailed asset scanning",
	Long: `Perform comprehensive scanning with service detection and fingerprinting.

This performs a deeper scan including:
- Detailed service enumeration
- Version detection
- Certificate extraction
- Screenshot capture for web services
- Vulnerability correlation

Examples:
  shells rumble scan 192.168.1.0/24 --deep
  shells rumble scan webserver.local --vuln-scan
  shells rumble scan 10.0.0.0/16 --exclude 10.0.1.0/24`,
	Args: cobra.ExactArgs(1),
	RunE: runrumbleScan,
}

var rumbleAssetsCmd = &cobra.Command{
	Use:   "assets",
	Short: "List discovered assets",
	Long: `List and filter previously discovered assets.

Filter assets by various criteria:
- Operating system
- Service type
- Network range
- Discovery date
- Tags

Examples:
  shells rumble assets
  shells rumble assets --filter "os:windows"
  shells rumble assets --filter "service:ssh"
  shells rumble assets --filter "ip:192.168.1.0/24"`,
	RunE: runrumbleAssets,
}

var rumbleExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export asset data",
	Long: `Export discovered asset data in various formats.

Supported formats:
- JSON: Full asset data with all attributes
- CSV: Simplified tabular format
- JSONL: JSON Lines for streaming processing

Examples:
  shells rumble export --format json --output assets.json
  shells rumble export --format csv --output assets.csv
  shells rumble export --filter "os:linux" --format jsonl`,
	RunE: runrumbleExport,
}

func init() {
	rootCmd.AddCommand(rumbleCmd)
	rumbleCmd.AddCommand(rumbleDiscoverCmd)
	rumbleCmd.AddCommand(rumbleScanCmd)
	rumbleCmd.AddCommand(rumbleAssetsCmd)
	rumbleCmd.AddCommand(rumbleExportCmd)

	// Global flags
	rumbleCmd.PersistentFlags().String("api-key", "", "rumble API key (overrides env/config)")
	rumbleCmd.PersistentFlags().Bool("verbose", false, "Enable verbose output")

	// Discover command flags
	rumbleDiscoverCmd.Flags().Int("rate", 1000, "Scan rate in packets per second")
	rumbleDiscoverCmd.Flags().Duration("timeout", 30*time.Minute, "Scan timeout")
	rumbleDiscoverCmd.Flags().StringSlice("exclude", nil, "Exclude targets (CIDR or IP)")

	// Scan command flags
	rumbleScanCmd.Flags().Bool("deep", false, "Enable deep scanning")
	rumbleScanCmd.Flags().Bool("vuln-scan", false, "Enable vulnerability scanning")
	rumbleScanCmd.Flags().Int("rate", 500, "Scan rate in packets per second")
	rumbleScanCmd.Flags().StringSlice("exclude", nil, "Exclude targets")
	rumbleScanCmd.Flags().Duration("timeout", 1*time.Hour, "Scan timeout")

	// Assets command flags
	rumbleAssetsCmd.Flags().StringSlice("filter", nil, "Filter assets (e.g., 'os:windows', 'service:ssh')")
	rumbleAssetsCmd.Flags().String("sort", "address", "Sort by field (address, hostname, first_seen, last_seen)")
	rumbleAssetsCmd.Flags().Int("limit", 100, "Limit number of results")

	// Export command flags
	rumbleExportCmd.Flags().String("format", "json", "Export format (json, csv, jsonl)")
	rumbleExportCmd.Flags().String("output", "", "Output file (default: stdout)")
	rumbleExportCmd.Flags().StringSlice("filter", nil, "Filter assets before export")
	rumbleExportCmd.Flags().StringSlice("fields", nil, "Fields to include in export")
}

func runrumbleDiscover(cmd *cobra.Command, args []string) error {
	target := args[0]
	rate, _ := cmd.Flags().GetInt("rate")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	excludes, _ := cmd.Flags().GetStringSlice("exclude")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Get API key
	apiKey := getrumbleAPIKey(cmd)
	if apiKey == "" {
		return fmt.Errorf("rumble API key not found. Set rumble_API_KEY or use --api-key")
	}

	// Create logger adapter for rumble
	rumbleLogger := &RumbleLoggerAdapter{logger: log}

	// Create scanner
	config := rumble.ScannerConfig{
		APIKey:   apiKey,
		ScanRate: rate,
		Timeout:  timeout,
	}

	scanner, err := rumble.NewScanner(config, rumbleLogger)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}

	// Validate target
	if err := scanner.Validate(target); err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	fmt.Printf("🔍 Starting rumble discovery of %s\n", target)
	if verbose {
		fmt.Printf("   Rate: %d pps\n", rate)
		fmt.Printf("   Timeout: %s\n", timeout)
		if len(excludes) > 0 {
			fmt.Printf("   Excludes: %s\n", strings.Join(excludes, ", "))
		}
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Prepare options
	options := map[string]string{
		"scan_type": "discovery",
		"excludes":  strings.Join(excludes, ","),
	}

	// Run scan
	start := time.Now()
	findings, err := scanner.Scan(ctx, target, options)
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	duration := time.Since(start)

	// Display results
	fmt.Printf("\n✅ Discovery completed in %s\n", duration.Round(time.Second))
	fmt.Printf("📊 Results:\n")

	// Group findings by type
	findingsByType := make(map[string][]types.Finding)
	for _, finding := range findings {
		findingsByType[finding.Type] = append(findingsByType[finding.Type], finding)
	}

	// Display summary
	assetCount := len(findingsByType["ASSET_DISCOVERED"])
	serviceCount := len(findingsByType["SERVICE_EXPOSED"])

	fmt.Printf("   Assets discovered: %d\n", assetCount)
	fmt.Printf("   Services found: %d\n", serviceCount)

	if verbose {
		fmt.Printf("\n📋 Detailed Findings:\n")
		for _, finding := range findings {
			printrumbleFinding(finding)
		}
	} else {
		// Show summary of assets
		fmt.Printf("\n📋 Discovered Assets:\n")
		for _, finding := range findingsByType["ASSET_DISCOVERED"] {
			var targetStr string
			if target, ok := finding.Metadata["target"].(string); ok {
				targetStr = target
			}
			fmt.Printf("   • %s", targetStr)
			if hostname, ok := finding.Metadata["hostname"].(string); ok && hostname != "" {
				fmt.Printf(" (%s)", hostname)
			}
			if os, ok := finding.Metadata["os"].(string); ok && os != "" {
				fmt.Printf(" - %s", os)
			}
			fmt.Println()
		}

		if serviceCount > 0 {
			fmt.Printf("\n⚠️  Found %d exposed services. Use --verbose for details.\n", serviceCount)
		}
	}

	// Store results if database is available
	if store := GetStore(); store != nil {
		// Create scan record
		scanRecord := &types.ScanRequest{
			ID:          uuid.New().String(),
			Target:      target,
			Type:        types.ScanType("rumble_discovery"),
			Status:      types.ScanStatusCompleted,
			CreatedAt:   start,
			StartedAt:   &start,
			CompletedAt: &[]time.Time{time.Now()}[0],
		}
		if err := store.SaveScan(ctx, scanRecord); err != nil {
			log.Error("Failed to store scan results", "error", err)
		} else {
			// Set scan ID for findings and save them
			for i := range findings {
				findings[i].ID = uuid.New().String()
				findings[i].ScanID = scanRecord.ID
				findings[i].Tool = "rumble"
			}
			if err := store.SaveFindings(ctx, findings); err != nil {
				log.Error("Failed to store findings", "error", err)
			}
		}
	}

	return nil
}

func runrumbleScan(cmd *cobra.Command, args []string) error {
	target := args[0]
	deep, _ := cmd.Flags().GetBool("deep")
	vulnScan, _ := cmd.Flags().GetBool("vuln-scan")
	rate, _ := cmd.Flags().GetInt("rate")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	excludes, _ := cmd.Flags().GetStringSlice("exclude")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Get API key
	apiKey := getrumbleAPIKey(cmd)
	if apiKey == "" {
		return fmt.Errorf("rumble API key not found. Set rumble_API_KEY or use --api-key")
	}

	// Create logger adapter for rumble
	rumbleLogger := &RumbleLoggerAdapter{logger: log}

	// Create scanner
	config := rumble.ScannerConfig{
		APIKey:         apiKey,
		ScanRate:       rate,
		Timeout:        timeout,
		DeepScan:       deep,
		EnableVulnScan: vulnScan,
	}

	scanner, err := rumble.NewScanner(config, rumbleLogger)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}

	// Validate target
	if err := scanner.Validate(target); err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	fmt.Printf("🔍 Starting rumble comprehensive scan of %s\n", target)
	if verbose {
		fmt.Printf("   Rate: %d pps\n", rate)
		fmt.Printf("   Timeout: %s\n", timeout)
		fmt.Printf("   Deep scan: %v\n", deep)
		fmt.Printf("   Vulnerability scan: %v\n", vulnScan)
	}

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Prepare options
	options := map[string]string{
		"scan_type": "service",
		"excludes":  strings.Join(excludes, ","),
	}

	// Run scan
	start := time.Now()
	findings, err := scanner.Scan(ctx, target, options)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	duration := time.Since(start)

	// Display results
	fmt.Printf("\n✅ Scan completed in %s\n", duration.Round(time.Second))

	// Analyze findings
	summary := analyzerumbleFindings(findings)

	fmt.Printf("📊 Summary:\n")
	fmt.Printf("   Total findings: %d\n", len(findings))
	fmt.Printf("   Critical: %d\n", summary["CRITICAL"])
	fmt.Printf("   High: %d\n", summary["HIGH"])
	fmt.Printf("   Medium: %d\n", summary["MEDIUM"])
	fmt.Printf("   Low: %d\n", summary["LOW"])
	fmt.Printf("   Info: %d\n", summary["INFO"])

	// Show critical and high findings
	criticalAndHigh := filterFindingsBySeverity(findings, []string{"CRITICAL", "HIGH"})
	if len(criticalAndHigh) > 0 {
		fmt.Printf("\n🚨 Critical and High Severity Findings:\n")
		for _, finding := range criticalAndHigh {
			printrumbleFinding(finding)
		}
	}

	if verbose {
		fmt.Printf("\n📋 All Findings:\n")
		for _, finding := range findings {
			printrumbleFinding(finding)
		}
	}

	return nil
}

func runrumbleAssets(cmd *cobra.Command, args []string) error {
	filters, _ := cmd.Flags().GetStringSlice("filter")
	limit, _ := cmd.Flags().GetInt("limit")

	// Get API key
	apiKey := getrumbleAPIKey(cmd)
	if apiKey == "" {
		return fmt.Errorf("rumble API key not found")
	}

	// Create logger adapter for rumble
	rumbleLogger := &RumbleLoggerAdapter{logger: log}

	// Create client
	client := rumble.NewClient(rumble.Config{
		APIKey: apiKey,
	}, rumbleLogger)

	// Parse filters
	filterMap := make(map[string]string)
	for _, filter := range filters {
		parts := strings.SplitN(filter, ":", 2)
		if len(parts) == 2 {
			filterMap[parts[0]] = parts[1]
		}
	}

	// Get assets
	ctx := context.Background()
	assets, err := client.GetAssets(ctx, filterMap)
	if err != nil {
		return fmt.Errorf("failed to get assets: %w", err)
	}

	// Display assets
	fmt.Printf("📋 Assets (showing up to %d):\n", limit)
	displayed := 0
	for _, asset := range assets {
		if displayed >= limit {
			break
		}

		fmt.Printf("\n• %s", asset.Address)
		if asset.Hostname != "" {
			fmt.Printf(" (%s)", asset.Hostname)
		}
		fmt.Printf("\n  OS: %s\n", asset.OS)
		fmt.Printf("  Services: ")

		serviceNames := []string{}
		for _, service := range asset.Services {
			serviceNames = append(serviceNames, fmt.Sprintf("%s:%d", service.Service, service.Port))
		}
		fmt.Printf("%s\n", strings.Join(serviceNames, ", "))

		fmt.Printf("  First seen: %s\n", asset.FirstSeen.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Last seen: %s\n", asset.LastSeen.Format("2006-01-02 15:04:05"))

		displayed++
	}

	if len(assets) > limit {
		fmt.Printf("\n... and %d more assets\n", len(assets)-limit)
	}

	return nil
}

func runrumbleExport(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	output, _ := cmd.Flags().GetString("output")
	filters, _ := cmd.Flags().GetStringSlice("filter")
	fields, _ := cmd.Flags().GetStringSlice("fields")

	// Get API key
	apiKey := getrumbleAPIKey(cmd)
	if apiKey == "" {
		return fmt.Errorf("rumble API key not found")
	}

	// Create logger adapter for rumble
	rumbleLogger := &RumbleLoggerAdapter{logger: log}

	// Create client
	client := rumble.NewClient(rumble.Config{
		APIKey: apiKey,
	}, rumbleLogger)

	// Parse filters
	filterMap := make(map[string]string)
	for _, filter := range filters {
		parts := strings.SplitN(filter, ":", 2)
		if len(parts) == 2 {
			filterMap[parts[0]] = parts[1]
		}
	}

	// Get assets
	ctx := context.Background()
	assets, err := client.GetAssets(ctx, filterMap)
	if err != nil {
		return fmt.Errorf("failed to get assets: %w", err)
	}

	// Export based on format
	var exportData []byte
	switch format {
	case "json":
		exportData, err = exportrumbleJSON(assets, fields)
	case "csv":
		exportData, err = exportrumbleCSV(assets, fields)
	case "jsonl":
		exportData, err = exportrumbleJSONL(assets, fields)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	// Write output
	if output == "" {
		fmt.Print(string(exportData))
	} else {
		if err := os.WriteFile(output, exportData, 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Printf("✅ Exported %d assets to %s\n", len(assets), output)
	}

	return nil
}

// Helper functions
func getrumbleAPIKey(cmd *cobra.Command) string {
	// Check command flag
	if apiKey, _ := cmd.Flags().GetString("api-key"); apiKey != "" {
		return apiKey
	}

	// Check environment
	if apiKey := os.Getenv("rumble_API_KEY"); apiKey != "" {
		return apiKey
	}

	// Check config
	return viper.GetString("rumble.api_key")
}

func printrumbleFinding(finding types.Finding) {
	severityEmoji := map[string]string{
		"critical": "🔴",
		"high":     "🟠",
		"medium":   "🟡",
		"low":      "🔵",
		"info":     "⚪",
	}

	emoji := severityEmoji[string(finding.Severity)]
	if emoji == "" {
		emoji = "⚪"
	}

	fmt.Printf("\n%s %s\n", emoji, finding.Title)
	fmt.Printf("   Type: %s\n", finding.Type)
	if target, ok := finding.Metadata["target"].(string); ok {
		fmt.Printf("   Target: %s\n", target)
	}
	fmt.Printf("   Description: %s\n", finding.Description)

	if finding.Metadata != nil {
		fmt.Printf("   Details:\n")
		for k, v := range finding.Metadata {
			if k != "target" { // Skip target since we already displayed it
				fmt.Printf("     %s: %v\n", k, v)
			}
		}
	}
}

func analyzerumbleFindings(findings []types.Finding) map[string]int {
	summary := make(map[string]int)
	for _, finding := range findings {
		summary[string(finding.Severity)]++
	}
	return summary
}

func filterFindingsBySeverity(findings []types.Finding, severities []string) []types.Finding {
	sevMap := make(map[string]bool)
	for _, sev := range severities {
		sevMap[sev] = true
	}

	var filtered []types.Finding
	for _, finding := range findings {
		if sevMap[string(finding.Severity)] {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

// RumbleLoggerAdapter adapts the shells logger to match rumble.Logger interface
type RumbleLoggerAdapter struct {
	logger *logger.Logger
}

func (a *RumbleLoggerAdapter) Info(msg string, keysAndValues ...interface{}) {
	a.logger.Infow(msg, keysAndValues...)
}

func (a *RumbleLoggerAdapter) Error(msg string, keysAndValues ...interface{}) {
	a.logger.Errorw(msg, keysAndValues...)
}

func (a *RumbleLoggerAdapter) Debug(msg string, keysAndValues ...interface{}) {
	a.logger.Debugw(msg, keysAndValues...)
}

// Export functions
func exportrumbleJSON(assets []rumble.Asset, fields []string) ([]byte, error) {
	if len(fields) == 0 {
		return json.MarshalIndent(assets, "", "  ")
	}

	// Filter fields if specified
	filtered := make([]map[string]interface{}, len(assets))
	for i, asset := range assets {
		assetMap := make(map[string]interface{})
		for _, field := range fields {
			switch field {
			case "id":
				assetMap["id"] = asset.ID
			case "address":
				assetMap["address"] = asset.Address
			case "hostname":
				assetMap["hostname"] = asset.Hostname
			case "os":
				assetMap["os"] = asset.OS
			case "services":
				assetMap["services"] = asset.Services
			case "first_seen":
				assetMap["first_seen"] = asset.FirstSeen
			case "last_seen":
				assetMap["last_seen"] = asset.LastSeen
			case "alive":
				assetMap["alive"] = asset.Alive
			case "tags":
				assetMap["tags"] = asset.Tags
			}
		}
		filtered[i] = assetMap
	}

	return json.MarshalIndent(filtered, "", "  ")
}

func exportrumbleCSV(assets []rumble.Asset, fields []string) ([]byte, error) {
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Default fields if none specified
	if len(fields) == 0 {
		fields = []string{"address", "hostname", "os", "alive", "first_seen", "last_seen"}
	}

	// Write header
	if err := writer.Write(fields); err != nil {
		return nil, err
	}

	// Write data
	for _, asset := range assets {
		row := make([]string, len(fields))
		for i, field := range fields {
			switch field {
			case "id":
				row[i] = asset.ID
			case "address":
				row[i] = asset.Address
			case "hostname":
				row[i] = asset.Hostname
			case "os":
				row[i] = asset.OS
			case "alive":
				row[i] = fmt.Sprintf("%t", asset.Alive)
			case "first_seen":
				row[i] = asset.FirstSeen.Format("2006-01-02 15:04:05")
			case "last_seen":
				row[i] = asset.LastSeen.Format("2006-01-02 15:04:05")
			case "services":
				serviceNames := make([]string, len(asset.Services))
				for j, service := range asset.Services {
					serviceNames[j] = fmt.Sprintf("%s:%d", service.Service, service.Port)
				}
				row[i] = strings.Join(serviceNames, ";")
			case "tags":
				row[i] = strings.Join(asset.Tags, ";")
			default:
				row[i] = ""
			}
		}
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	return []byte(buf.String()), writer.Error()
}

func exportrumbleJSONL(assets []rumble.Asset, fields []string) ([]byte, error) {
	var buf strings.Builder

	for _, asset := range assets {
		var data interface{} = asset

		// Filter fields if specified
		if len(fields) > 0 {
			assetMap := make(map[string]interface{})
			for _, field := range fields {
				switch field {
				case "id":
					assetMap["id"] = asset.ID
				case "address":
					assetMap["address"] = asset.Address
				case "hostname":
					assetMap["hostname"] = asset.Hostname
				case "os":
					assetMap["os"] = asset.OS
				case "services":
					assetMap["services"] = asset.Services
				case "first_seen":
					assetMap["first_seen"] = asset.FirstSeen
				case "last_seen":
					assetMap["last_seen"] = asset.LastSeen
				case "alive":
					assetMap["alive"] = asset.Alive
				case "tags":
					assetMap["tags"] = asset.Tags
				}
			}
			data = assetMap
		}

		line, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	return []byte(buf.String()), nil
}
