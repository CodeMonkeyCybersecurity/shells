package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/database"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scope"
	"github.com/spf13/cobra"
)

var scopeCmd = &cobra.Command{
	Use:   "scope",
	Short: "Manage bug bounty program scopes",
	Long: `Manage bug bounty program scopes from various platforms.

This command allows you to:
- Import programs from HackerOne, Bugcrowd, Intigriti, YesWeHack
- Validate assets against program scopes
- Monitor scope changes
- Export scope data

Examples:
  shells scope import hackerone my-program
  shells scope validate example.com
  shells scope list
  shells scope sync --all`,
}

var scopeImportCmd = &cobra.Command{
	Use:   "import [platform] [handle]",
	Short: "Import a bug bounty program",
	Long: `Import a bug bounty program from a platform.

Supported platforms:
- hackerone (h1)
- bugcrowd (bc)
- intigriti
- yeswehack (ywh)
- custom (import from file)

Examples:
  shells scope import hackerone github
  shells scope import bugcrowd tesla
  shells scope import custom ./my-program.json`,
	Args: cobra.ExactArgs(2),
	RunE: runScopeImport,
}

var scopeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all programs",
	Long:  `List all imported bug bounty programs and their scope counts.`,
	RunE:  runScopeList,
}

var scopeShowCmd = &cobra.Command{
	Use:   "show [program-id]",
	Short: "Show detailed program scope",
	Long:  `Show detailed scope information for a specific program.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runScopeShow,
}

var scopeValidateCmd = &cobra.Command{
	Use:   "validate [asset]",
	Short: "Validate if an asset is in scope",
	Long: `Validate if an asset is in scope for any program.

The asset can be:
- Domain: example.com
- URL: https://example.com/api
- IP: 192.168.1.1
- IP Range: 192.168.1.0/24

Examples:
  shells scope validate example.com
  shells scope validate 192.168.1.1
  shells scope validate https://api.example.com/v2`,
	Args: cobra.ExactArgs(1),
	RunE: runScopeValidate,
}

var scopeSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync program scopes",
	Long: `Sync program scopes from their platforms.

Examples:
  shells scope sync --all
  shells scope sync --program h1_github`,
	RunE: runScopeSync,
}

var scopeMonitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Monitor scope changes",
	Long: `Start monitoring for scope changes in real-time.

This will periodically check all active programs for scope updates
and notify when changes are detected.`,
	RunE: runScopeMonitor,
}

var scopeExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export scope data",
	Long: `Export all scope data to various formats.

Supported formats:
- json: JSON format
- csv: CSV format
- txt: Plain text (one per line)

Examples:
  shells scope export --format json --output scopes.json
  shells scope export --format csv --in-scope-only`,
	RunE: runScopeExport,
}

func init() {
	rootCmd.AddCommand(scopeCmd)

	// Add subcommands
	scopeCmd.AddCommand(scopeImportCmd)
	scopeCmd.AddCommand(scopeListCmd)
	scopeCmd.AddCommand(scopeShowCmd)
	scopeCmd.AddCommand(scopeValidateCmd)
	scopeCmd.AddCommand(scopeSyncCmd)
	scopeCmd.AddCommand(scopeMonitorCmd)
	scopeCmd.AddCommand(scopeExportCmd)

	// Flags for import
	scopeImportCmd.Flags().StringP("api-key", "k", "", "API key for the platform")
	scopeImportCmd.Flags().StringP("username", "u", "", "Username for the platform")
	scopeImportCmd.Flags().BoolP("active", "a", true, "Mark program as active")

	// Flags for validate
	scopeValidateCmd.Flags().BoolP("verbose", "v", false, "Show detailed validation info")
	scopeValidateCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")

	// Flags for sync
	scopeSyncCmd.Flags().BoolP("all", "a", false, "Sync all programs")
	scopeSyncCmd.Flags().StringP("program", "p", "", "Sync specific program")

	// Flags for monitor
	scopeMonitorCmd.Flags().DurationP("interval", "i", 30*time.Minute, "Check interval")

	// Flags for export
	scopeExportCmd.Flags().StringP("format", "f", "json", "Export format (json, csv, txt)")
	scopeExportCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	scopeExportCmd.Flags().BoolP("in-scope-only", "i", false, "Export only in-scope items")
}

func runScopeImport(cmd *cobra.Command, args []string) error {
	platform := args[0]
	handle := args[1]

	// Get flags
	apiKey, _ := cmd.Flags().GetString("api-key")
	username, _ := cmd.Flags().GetString("username")
	active, _ := cmd.Flags().GetBool("active")

	// Create scope manager
	scopeManager := createScopeManager()

	// Configure platform client if needed
	switch platform {
	case "hackerone", "h1":
		platform = string(scope.PlatformHackerOne)
		if client, ok := scopeManager.(*scope.Manager).GetPlatformClient(scope.PlatformHackerOne).(*scope.HackerOneClient); ok {
			if username != "" && apiKey != "" {
				client.Configure(username, apiKey)
			}
		}
	case "bugcrowd", "bc":
		platform = string(scope.PlatformBugcrowd)
		if client, ok := scopeManager.(*scope.Manager).GetPlatformClient(scope.PlatformBugcrowd).(*scope.BugcrowdClient); ok {
			if apiKey != "" {
				client.Configure(apiKey)
			}
		}
	case "custom":
		// Handle custom import from file
		return importCustomProgram(scopeManager, handle)
	}

	log.Info("Importing program", "platform", platform, "handle", handle)

	// Create a basic program structure and sync it
	program := &scope.Program{
		ID:         fmt.Sprintf("%s_%s", strings.ToLower(platform[:2]), handle),
		Platform:   scope.Platform(platform),
		Handle:     handle,
		Name:       handle,
		Active:     active,
		LastSynced: time.Time{}, // Will trigger sync
	}

	// Add program first
	if err := scopeManager.AddProgram(program); err != nil {
		return fmt.Errorf("failed to add program: %w", err)
	}

	// Then sync to get actual data
	if err := scopeManager.SyncProgram(program.ID); err != nil {
		log.Warn("Failed to sync program, using placeholder", "error", err)
	}

	// Get the updated program
	updatedProgram, err := scopeManager.GetProgram(program.ID)
	if err != nil {
		return fmt.Errorf("failed to get updated program: %w", err)
	}

	fmt.Printf("✅ Successfully imported program: %s\n", updatedProgram.Name)
	fmt.Printf("   Platform: %s\n", updatedProgram.Platform)
	fmt.Printf("   In Scope: %d items\n", len(updatedProgram.Scope))
	fmt.Printf("   Out of Scope: %d items\n", len(updatedProgram.OutOfScope))

	return nil
}

func runScopeList(cmd *cobra.Command, args []string) error {
	scopeManager := createScopeManager()

	programs, err := scopeManager.ListPrograms()
	if err != nil {
		return err
	}

	if len(programs) == 0 {
		fmt.Println("No programs imported yet. Use 'shells scope import' to add programs.")
		return nil
	}

	// Create table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tPLATFORM\tIN SCOPE\tOUT OF SCOPE\tACTIVE\tLAST SYNCED")
	fmt.Fprintln(w, "──\t────\t────────\t────────\t────────────\t──────\t───────────")

	for _, program := range programs {
		active := "❌"
		if program.Active {
			active = "✅"
		}

		lastSync := "Never"
		if !program.LastSynced.IsZero() {
			lastSync = program.LastSynced.Format("2006-01-02 15:04")
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\t%s\n",
			program.ID,
			truncate(program.Name, 20),
			program.Platform,
			len(program.Scope),
			len(program.OutOfScope),
			active,
			lastSync,
		)
	}

	w.Flush()

	return nil
}

func runScopeShow(cmd *cobra.Command, args []string) error {
	programID := args[0]

	scopeManager := createScopeManager()

	program, err := scopeManager.GetProgram(programID)
	if err != nil {
		return err
	}

	fmt.Printf("Program: %s\n", program.Name)
	fmt.Printf("Platform: %s\n", program.Platform)
	fmt.Printf("Handle: %s\n", program.Handle)
	fmt.Printf("URL: %s\n", program.URL)
	if program.MaxBounty > 0 {
		fmt.Printf("Max Bounty: $%.2f\n", program.MaxBounty)
	}
	fmt.Printf("Active: %v\n", program.Active)
	fmt.Printf("VPN Required: %v\n", program.VPNRequired)
	fmt.Println()

	if len(program.Scope) > 0 {
		fmt.Println("📋 IN SCOPE:")
		for _, item := range program.Scope {
			fmt.Printf("   • %s (%s)", item.Value, item.Type)
			if item.Description != "" {
				fmt.Printf(" - %s", item.Description)
			}
			if len(item.Restrictions) > 0 {
				fmt.Printf("\n     Restrictions: %s", strings.Join(item.Restrictions, ", "))
			}
			fmt.Println()
		}
		fmt.Println()
	}

	if len(program.OutOfScope) > 0 {
		fmt.Println("🚫 OUT OF SCOPE:")
		for _, item := range program.OutOfScope {
			fmt.Printf("   • %s (%s)", item.Value, item.Type)
			if item.Description != "" {
				fmt.Printf(" - %s", item.Description)
			}
			fmt.Println()
		}
		fmt.Println()
	}

	if len(program.Rules) > 0 {
		fmt.Println("📏 RULES:")
		for _, rule := range program.Rules {
			fmt.Printf("   • %s: %s\n", rule.Type, rule.Description)
		}
		fmt.Println()
	}

	if program.TestingGuidelines != "" {
		fmt.Println("📖 TESTING GUIDELINES:")
		fmt.Println(wrapText(program.TestingGuidelines, 80))
	}

	return nil
}

func runScopeValidate(cmd *cobra.Command, args []string) error {
	asset := args[0]
	verbose, _ := cmd.Flags().GetBool("verbose")
	output, _ := cmd.Flags().GetString("output")

	scopeManager := createScopeManager()

	result, err := scopeManager.ValidateAsset(asset)
	if err != nil {
		return err
	}

	if output == "json" {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	// Text output
	switch result.Status {
	case scope.ScopeStatusInScope:
		fmt.Printf("✅ %s is IN SCOPE\n", asset)
	case scope.ScopeStatusOutOfScope:
		fmt.Printf("❌ %s is OUT OF SCOPE\n", asset)
	default:
		fmt.Printf("❓ %s scope is UNKNOWN\n", asset)
	}

	if result.Program != nil {
		fmt.Printf("   Program: %s (%s)\n", result.Program.Name, result.Program.Platform)
	}

	if result.MatchedItem != nil {
		fmt.Printf("   Matched: %s (%s)\n", result.MatchedItem.Value, result.MatchedItem.Type)
	}

	if result.Reason != "" {
		fmt.Printf("   Reason: %s\n", result.Reason)
	}

	if len(result.Restrictions) > 0 {
		fmt.Printf("   Restrictions: %s\n", strings.Join(result.Restrictions, ", "))
	}

	if verbose && len(result.ApplicableRules) > 0 {
		fmt.Println("   Applicable Rules:")
		for _, rule := range result.ApplicableRules {
			fmt.Printf("     • %s: %s\n", rule.Type, rule.Description)
		}
	}

	return nil
}

func runScopeSync(cmd *cobra.Command, args []string) error {
	all, _ := cmd.Flags().GetBool("all")
	programID, _ := cmd.Flags().GetString("program")

	scopeManager := createScopeManager()

	if all {
		fmt.Println("🔄 Syncing all programs...")
		if err := scopeManager.SyncAllPrograms(); err != nil {
			return err
		}
		fmt.Println("✅ Sync completed")
	} else if programID != "" {
		fmt.Printf("🔄 Syncing program %s...\n", programID)
		if err := scopeManager.SyncProgram(programID); err != nil {
			return err
		}
		fmt.Println("✅ Sync completed")
	} else {
		return fmt.Errorf("specify --all or --program")
	}

	return nil
}

func runScopeMonitor(cmd *cobra.Command, args []string) error {
	interval, _ := cmd.Flags().GetDuration("interval")

	scopeManager := createScopeManager()

	fmt.Printf("👁️  Starting scope monitoring (interval: %s)\n", interval)
	fmt.Println("Press Ctrl+C to stop")

	// Update config with interval
	if manager, ok := scopeManager.(*scope.Manager); ok {
		manager.SetMonitorInterval(interval)
	}

	if err := scopeManager.StartMonitoring(); err != nil {
		return err
	}

	// Wait for interrupt
	select {}
}

func runScopeExport(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	outputFile, _ := cmd.Flags().GetString("output")
	inScopeOnly, _ := cmd.Flags().GetBool("in-scope-only")

	scopeManager := createScopeManager()

	// Get all scope items
	var items []scope.ScopeItem

	programs, err := scopeManager.ListPrograms()
	if err != nil {
		return err
	}

	for _, program := range programs {
		if !program.Active {
			continue
		}

		items = append(items, program.Scope...)
		if !inScopeOnly {
			items = append(items, program.OutOfScope...)
		}
	}

	// Format output
	var output []byte

	switch format {
	case "json":
		output, err = json.MarshalIndent(items, "", "  ")
	case "csv":
		output = []byte(formatAsCSV(items))
	case "txt":
		output = []byte(formatAsText(items))
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		return err
	}

	// Write output
	if outputFile != "" {
		return os.WriteFile(outputFile, output, 0644)
	}

	fmt.Print(string(output))
	return nil
}

// Helper function to create scope manager
func createScopeManager() scope.ScopeManager {
	// Get the database from the store
	sqlxDB := store.(*database.Store).DB()

	config := &scope.Config{
		AutoSync:         true,
		SyncInterval:     30 * time.Minute,
		CacheTTL:         1 * time.Hour,
		ValidateWorkers:  10,
		StrictMode:       false,
		EnableMonitoring: true,
		MonitorInterval:  30 * time.Minute,
	}

	return scope.NewManager(sqlxDB, log, config)
}

func wrapText(text string, width int) string {
	// Simple text wrapping
	words := strings.Fields(text)
	var lines []string
	var currentLine []string
	currentLength := 0

	for _, word := range words {
		if currentLength+len(word)+1 > width && currentLength > 0 {
			lines = append(lines, strings.Join(currentLine, " "))
			currentLine = []string{word}
			currentLength = len(word)
		} else {
			currentLine = append(currentLine, word)
			currentLength += len(word) + 1
		}
	}

	if len(currentLine) > 0 {
		lines = append(lines, strings.Join(currentLine, " "))
	}

	return strings.Join(lines, "\n")
}

func formatAsCSV(items []scope.ScopeItem) string {
	var csv strings.Builder
	csv.WriteString("Type,Value,Status,Description,Restrictions\n")

	for _, item := range items {
		csv.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s\n",
			item.Type,
			item.Value,
			item.Status,
			item.Description,
			strings.Join(item.Restrictions, ";")))
	}

	return csv.String()
}

func formatAsText(items []scope.ScopeItem) string {
	var text strings.Builder

	for _, item := range items {
		text.WriteString(item.Value + "\n")
	}

	return text.String()
}

func importCustomProgram(manager scope.ScopeManager, filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var program scope.Program
	if err := json.Unmarshal(data, &program); err != nil {
		return err
	}

	program.Platform = scope.PlatformCustom
	program.LastSynced = time.Now()

	return manager.AddProgram(&program)
}
