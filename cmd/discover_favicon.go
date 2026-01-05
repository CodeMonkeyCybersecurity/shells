package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/favicon"
	"github.com/spf13/cobra"
)

var (
	hosts          []string
	hostsFile      string
	faviconTimeout time.Duration
	userAgent      string
	cacheDir       string
	shodanAPIKey   string
	maxConcurrency int
	enableShodan   bool
	enableCache    bool
	customDatabase string
	faviconOutput  string
	faviconFormat  string
	addHash        string
	addTechnology  string
	addCategory    string
	addConfidence  float64
	exportFormat   string
	exportFile     string
	searchTech     string
	validateOnly   bool
	hashOnly       bool
	noTechMatch    bool
)

// discoverFaviconCmd represents the favicon discovery command
var discoverFaviconCmd = &cobra.Command{
	Use:   "favicon",
	Short: "Identify technologies via favicon hashing",
	Long: `Discover and identify web technologies by analyzing favicon hashes.

This tool downloads favicons from target hosts, calculates multiple hash variants
(MD5, SHA256, MMH3), and matches them against a comprehensive database of known
technology fingerprints. It can also search Shodan for hosts with matching favicons.

The scanner supports multiple hash formats including Shodan's MMH3 format for
maximum compatibility with existing tools and databases.

Examples:
  shells discover favicon --hosts example.com,test.com
  shells discover favicon --hosts-file targets.txt --enable-shodan
  shells discover favicon --hosts example.com --hash-only --format json
  shells discover favicon --hosts target.com --add-hash 123456789 --add-tech "Custom App"`,
	RunE: runFaviconDiscovery,
}

// faviconHashCmd calculates favicon hashes
var faviconHashCmd = &cobra.Command{
	Use:   "hash",
	Short: "Calculate favicon hashes for URLs",
	Long: `Calculate multiple hash variants for favicon URLs.

This command downloads favicons and calculates MD5, SHA256, and MMH3 hashes
without performing technology identification. Useful for building custom
databases or integrating with other tools.`,
	Example: `  shells discover favicon hash --hosts example.com
  shells discover favicon hash --hosts-file urls.txt --format json`,
	RunE: runFaviconHash,
}

// faviconSearchCmd searches for technologies
var faviconSearchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search for technologies in favicon database",
	Long: `Search the favicon database for specific technologies or patterns.

This command allows you to explore the built-in technology database and
search for specific technologies, categories, or hash values.`,
	Example: `  shells discover favicon search --tech wordpress
  shells discover favicon search --tech jenkins --format json`,
	RunE: runFaviconSearch,
}

// faviconDatabaseCmd manages the favicon database
var faviconDatabaseCmd = &cobra.Command{
	Use:   "database",
	Short: "Manage favicon technology database",
	Long: `Manage the favicon technology database.

This command provides utilities for managing the technology database,
including adding custom entries, exporting data, and viewing statistics.`,
}

// faviconAddCmd adds custom hash mappings
var faviconAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add custom favicon hash to technology mapping",
	Long: `Add a custom favicon hash to technology mapping to the database.

This allows you to extend the technology detection capabilities with
your own discovered favicon hashes.`,
	Example: `  shells discover favicon database add --hash 123456789 --tech "My App" --category custom --confidence 0.9`,
	RunE:    runFaviconAdd,
}

// faviconExportCmd exports database
var faviconExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export favicon database",
	Long: `Export the favicon database to a file.

This command allows you to backup or share your favicon database,
including any custom entries you've added.`,
	Example: `  shells discover favicon database export --format json --file favicon-db.json
  shells discover favicon database export --format csv --file favicon-db.csv`,
	RunE: runFaviconExport,
}

// faviconStatsCmd shows database statistics
var faviconStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show favicon database statistics",
	Long: `Display statistics about the favicon database.

Shows information about the number of entries, technologies, categories,
and other database metrics.`,
	RunE: runFaviconStats,
}

func init() {
	// Add favicon command to discover
	discoverCmd.AddCommand(discoverFaviconCmd)

	// Add subcommands
	discoverFaviconCmd.AddCommand(faviconHashCmd, faviconSearchCmd, faviconDatabaseCmd)
	faviconDatabaseCmd.AddCommand(faviconAddCmd, faviconExportCmd, faviconStatsCmd)

	// Global favicon flags
	discoverFaviconCmd.PersistentFlags().DurationVar(&faviconTimeout, "timeout", 10*time.Second, "Request timeout")
	discoverFaviconCmd.PersistentFlags().StringVar(&userAgent, "user-agent", "", "Custom User-Agent string")
	discoverFaviconCmd.PersistentFlags().StringVar(&cacheDir, "cache-dir", "", "Cache directory for favicon data")
	discoverFaviconCmd.PersistentFlags().BoolVar(&enableCache, "enable-cache", true, "Enable favicon caching")
	discoverFaviconCmd.PersistentFlags().StringVar(&customDatabase, "custom-db", "", "Path to custom favicon database")

	// Discovery flags
	discoverFaviconCmd.Flags().StringSliceVar(&hosts, "hosts", []string{}, "Target hosts to scan (comma-separated)")
	discoverFaviconCmd.Flags().StringVar(&hostsFile, "hosts-file", "", "File containing list of hosts to scan")
	discoverFaviconCmd.Flags().IntVar(&maxConcurrency, "concurrency", 10, "Maximum concurrent requests")
	discoverFaviconCmd.Flags().StringVar(&shodanAPIKey, "shodan-api-key", "", "Shodan API key for enhanced search")
	discoverFaviconCmd.Flags().BoolVar(&enableShodan, "enable-shodan", false, "Enable Shodan integration")
	discoverFaviconCmd.Flags().BoolVar(&hashOnly, "hash-only", false, "Only calculate hashes, skip technology identification")
	discoverFaviconCmd.Flags().BoolVar(&noTechMatch, "no-tech-match", false, "Skip technology matching")
	discoverFaviconCmd.Flags().BoolVar(&validateOnly, "validate-only", false, "Only validate favicon availability")

	// Output flags
	discoverFaviconCmd.Flags().StringVar(&faviconOutput, "output", "", "Output file for results")
	discoverFaviconCmd.Flags().StringVar(&faviconFormat, "format", "table", "Output format (table, json, csv)")

	// Hash command flags
	faviconHashCmd.Flags().StringSliceVar(&hosts, "hosts", []string{}, "Target hosts to hash")
	faviconHashCmd.Flags().StringVar(&hostsFile, "hosts-file", "", "File containing hosts to hash")
	faviconHashCmd.Flags().StringVar(&faviconFormat, "format", "table", "Output format (table, json, csv)")

	// Search command flags
	faviconSearchCmd.Flags().StringVar(&searchTech, "tech", "", "Technology name to search for")
	faviconSearchCmd.Flags().StringVar(&faviconFormat, "format", "table", "Output format (table, json)")

	// Add command flags
	faviconAddCmd.Flags().StringVar(&addHash, "hash", "", "Favicon hash value")
	faviconAddCmd.Flags().StringVar(&addTechnology, "tech", "", "Technology name")
	faviconAddCmd.Flags().StringVar(&addCategory, "category", "", "Technology category")
	faviconAddCmd.Flags().Float64Var(&addConfidence, "confidence", 0.8, "Confidence score (0.0-1.0)")

	// Export command flags
	faviconExportCmd.Flags().StringVar(&exportFormat, "format", "json", "Export format (json, csv)")
	faviconExportCmd.Flags().StringVar(&exportFile, "file", "", "Output file for export")

	// Mark required flags
	faviconAddCmd.MarkFlagRequired("hash")
	faviconAddCmd.MarkFlagRequired("tech")
	faviconAddCmd.MarkFlagRequired("category")
}

func runFaviconDiscovery(cmd *cobra.Command, args []string) error {
	ctx := GetContext()
	_ = GetLogger() // logger available if needed

	// Load target hosts
	targetHosts, err := loadTargetHosts(hosts, hostsFile)
	if err != nil {
		return fmt.Errorf("failed to load target hosts: %w", err)
	}

	if len(targetHosts) == 0 {
		return fmt.Errorf("no target hosts specified. Use --hosts or --hosts-file")
	}

	// Create favicon scanner configuration
	config := favicon.Config{
		Timeout:        faviconTimeout,
		UserAgent:      userAgent,
		CacheDir:       cacheDir,
		ShodanAPIKey:   shodanAPIKey,
		MaxConcurrency: maxConcurrency,
		EnableShodan:   enableShodan,
		EnableCache:    enableCache,
		CustomDatabase: customDatabase,
	}

	// Initialize scanner
	scanner, err := favicon.NewScanner(config)
	if err != nil {
		return fmt.Errorf("failed to initialize favicon scanner: %w", err)
	}

	fmt.Printf(" Starting favicon discovery scan\n")
	fmt.Printf("Targets: %d hosts\n", len(targetHosts))
	fmt.Printf("Concurrency: %d\n", maxConcurrency)
	if enableShodan {
		fmt.Printf("Shodan integration: enabled\n")
	}
	fmt.Println()

	start := time.Now()

	// Scan hosts
	results, err := scanner.ScanHosts(ctx, targetHosts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	duration := time.Since(start)

	// Filter successful results
	var successfulResults []*favicon.FaviconResult
	for _, result := range results {
		if result.Error == "" && len(result.Favicons) > 0 {
			successfulResults = append(successfulResults, result)
		}
	}

	fmt.Printf(" Scan completed in %s\n", duration)
	fmt.Printf(" Found favicons on %d/%d hosts\n\n", len(successfulResults), len(targetHosts))

	// Output results
	switch faviconFormat {
	case "json":
		return outputFaviconJSON(results, faviconOutput)
	case "csv":
		return outputFaviconCSV(results, faviconOutput)
	case "table":
		return outputFaviconTable(results)
	default:
		return fmt.Errorf("unsupported format: %s", faviconFormat)
	}
}

func runFaviconHash(cmd *cobra.Command, args []string) error {
	_ = GetContext() // context available if needed

	// Load target hosts
	targetHosts, err := loadTargetHosts(hosts, hostsFile)
	if err != nil {
		return fmt.Errorf("failed to load target hosts: %w", err)
	}

	if len(targetHosts) == 0 {
		return fmt.Errorf("no target hosts specified")
	}

	// Create hasher
	hasher := favicon.NewHasher(faviconTimeout, userAgent)

	var allResults []*favicon.HashResult

	for _, host := range targetHosts {
		fmt.Printf(" Processing %s...\n", host)

		results, err := hasher.ScanHost(host)
		if err != nil {
			fmt.Printf(" Failed to process %s: %v\n", host, err)
			continue
		}

		allResults = append(allResults, results...)
	}

	fmt.Printf("\n Processed %d favicon(s) from %d host(s)\n\n", len(allResults), len(targetHosts))

	// Output hash results
	return outputHashResults(allResults, faviconFormat)
}

func runFaviconSearch(cmd *cobra.Command, args []string) error {
	if searchTech == "" {
		return fmt.Errorf("--tech flag is required")
	}

	// Create database
	database := favicon.NewDatabase()

	// Search for technology
	entries := database.SearchByTechnology(searchTech)

	if len(entries) == 0 {
		fmt.Printf("No entries found for technology: %s\n", searchTech)
		return nil
	}

	fmt.Printf(" Found %d entries for '%s'\n\n", len(entries), searchTech)

	// Output search results
	switch faviconFormat {
	case "json":
		data, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	case "table":
		for i, entry := range entries {
			fmt.Printf("%d. %s (%s)\n", i+1, entry.Name, entry.Category)
			fmt.Printf("   Hash: %s (%s)\n", entry.Hash, entry.HashType)
			fmt.Printf("   Confidence: %.2f\n", entry.Confidence)
			if entry.Description != "" {
				fmt.Printf("   Description: %s\n", entry.Description)
			}
			fmt.Println()
		}
	default:
		return fmt.Errorf("unsupported format: %s", faviconFormat)
	}

	return nil
}

func runFaviconAdd(cmd *cobra.Command, args []string) error {
	// Create database
	database := favicon.NewDatabase()

	// Create new entry
	entry := favicon.TechnologyEntry{
		Hash:       addHash,
		HashType:   "mmh3", // Default to MMH3
		Name:       addTechnology,
		Category:   addCategory,
		Confidence: addConfidence,
		Source:     "custom",
	}

	// Add entry
	if err := database.AddEntry(entry); err != nil {
		return fmt.Errorf("failed to add entry: %w", err)
	}

	fmt.Printf(" Added favicon hash mapping:\n")
	fmt.Printf("   Hash: %s\n", addHash)
	fmt.Printf("   Technology: %s\n", addTechnology)
	fmt.Printf("   Category: %s\n", addCategory)
	fmt.Printf("   Confidence: %.2f\n", addConfidence)

	// Save to custom database if specified
	if customDatabase != "" {
		if err := database.SaveToFile(customDatabase); err != nil {
			fmt.Printf("  Warning: Failed to save to custom database: %v\n", err)
		} else {
			fmt.Printf(" Saved to custom database: %s\n", customDatabase)
		}
	}

	return nil
}

func runFaviconExport(cmd *cobra.Command, args []string) error {
	// Create database
	database := favicon.NewDatabase()

	// Load custom database if specified
	if customDatabase != "" {
		if err := database.LoadFromFile(customDatabase); err != nil {
			return fmt.Errorf("failed to load custom database: %w", err)
		}
	}

	// Export database
	data, err := database.ExportDatabase(exportFormat)
	if err != nil {
		return fmt.Errorf("failed to export database: %w", err)
	}

	if exportFile != "" {
		if err := os.WriteFile(exportFile, data, 0644); err != nil {
			return fmt.Errorf("failed to write export file: %w", err)
		}
		fmt.Printf("📄 Database exported to: %s\n", exportFile)
	} else {
		fmt.Println(string(data))
	}

	return nil
}

func runFaviconStats(cmd *cobra.Command, args []string) error {
	// Create database
	database := favicon.NewDatabase()

	// Load custom database if specified
	if customDatabase != "" {
		if err := database.LoadFromFile(customDatabase); err != nil {
			return fmt.Errorf("failed to load custom database: %w", err)
		}
	}

	// Get statistics
	stats := database.GetStatistics()
	technologies := database.GetAllTechnologies()

	fmt.Printf(" Favicon Database Statistics\n")
	fmt.Printf("═══════════════════════════════\n\n")
	fmt.Printf("Total Entries: %d\n", stats.TotalEntries)
	fmt.Printf("Unique Hashes: %d\n", stats.UniqueHashes)
	fmt.Printf("Technologies: %d\n", len(technologies))
	fmt.Printf("Total Scans: %d\n", stats.TotalScans)

	// Show top technologies
	fmt.Printf("\n Available Technologies (sample):\n")
	for i, tech := range technologies {
		if i >= 10 { // Show first 10
			fmt.Printf("... and %d more\n", len(technologies)-10)
			break
		}
		fmt.Printf("  - %s\n", tech)
	}

	return nil
}

// Helper functions

func loadTargetHosts(hostList []string, filename string) ([]string, error) {
	var hosts []string

	// Add hosts from command line
	hosts = append(hosts, hostList...)

	// Add hosts from file
	if filename != "" {
		data, err := os.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to read hosts file: %w", err)
		}

		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				hosts = append(hosts, line)
			}
		}
	}

	// Remove duplicates
	hostSet := make(map[string]bool)
	var uniqueHosts []string
	for _, host := range hosts {
		if !hostSet[host] {
			hostSet[host] = true
			uniqueHosts = append(uniqueHosts, host)
		}
	}

	return uniqueHosts, nil
}

func outputFaviconJSON(results []*favicon.FaviconResult, filename string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	if filename != "" {
		if err := os.WriteFile(filename, data, 0644); err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		fmt.Printf("📄 Results saved to: %s\n", filename)
	} else {
		fmt.Println(string(data))
	}

	return nil
}

func outputFaviconCSV(results []*favicon.FaviconResult, filename string) error {
	// Create scanner for CSV export
	scanner, err := favicon.NewScanner(favicon.Config{})
	if err != nil {
		return err
	}

	data, err := scanner.ExportResults(results, "csv")
	if err != nil {
		return fmt.Errorf("failed to export CSV: %w", err)
	}

	if filename != "" {
		if err := os.WriteFile(filename, data, 0644); err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		fmt.Printf("📄 Results saved to: %s\n", filename)
	} else {
		fmt.Println(string(data))
	}

	return nil
}

func outputFaviconTable(results []*favicon.FaviconResult) error {
	successCount := 0
	totalTechnologies := 0

	for _, result := range results {
		if result.Error == "" {
			successCount++
			totalTechnologies += len(result.Technologies)
		}
	}

	fmt.Printf(" Favicon Discovery Results\n")
	fmt.Printf("═══════════════════════════\n")
	fmt.Printf("Hosts scanned: %d\n", len(results))
	fmt.Printf("Successful: %d\n", successCount)
	fmt.Printf("Technologies found: %d\n\n", totalTechnologies)

	// Display detailed results
	for _, result := range results {
		if result.Error != "" {
			fmt.Printf(" %s: %s\n", result.Host, result.Error)
			continue
		}

		if len(result.Favicons) == 0 {
			fmt.Printf("⚪ %s: No favicons found\n", result.Host)
			continue
		}

		fmt.Printf(" %s (%d favicon(s))\n", result.Host, len(result.Favicons))

		if len(result.Technologies) > 0 {
			for _, tech := range result.Technologies {
				confidenceIcon := getConfidenceIcon(tech.Confidence)
				fmt.Printf("   %s %s (%s) - %.1f%% confidence\n",
					confidenceIcon, tech.Technology, tech.Category, tech.Confidence*100)
			}
		} else {
			fmt.Printf("   ⚪ No technologies identified\n")
		}

		// Show hash summary
		if len(result.Favicons) > 0 {
			fmt.Printf("   🔑 Hash: %s\n", result.Favicons[0].MMH3)
		}

		fmt.Println()
	}

	return nil
}

func outputHashResults(results []*favicon.HashResult, format string) error {
	switch format {
	case "json":
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	case "table":
		fmt.Printf("🔑 Favicon Hash Results\n")
		fmt.Printf("═══════════════════════\n\n")

		for i, result := range results {
			fmt.Printf("%d. %s\n", i+1, result.URL)
			fmt.Printf("   Size: %d bytes\n", result.Size)
			fmt.Printf("   Content-Type: %s\n", result.ContentType)
			fmt.Printf("   MD5: %s\n", result.MD5)
			fmt.Printf("   SHA256: %s\n", result.SHA256)
			fmt.Printf("   MMH3: %s\n", result.MMH3)
			fmt.Printf("   MMH3 (signed): %s\n", result.MMH3Signed)
			fmt.Println()
		}
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	return nil
}

func getConfidenceIcon(confidence float64) string {
	if confidence >= 0.9 {
		return ""
	} else if confidence >= 0.7 {
		return "🟡"
	} else if confidence >= 0.5 {
		return "🟠"
	} else {
		return ""
	}
}
