package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/database"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/platforms"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/platforms/aws"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/platforms/azure"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/platforms/bugcrowd"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/platforms/hackerone"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/spf13/cobra"
)

var platformCmd = &cobra.Command{
	Use:   "platform",
	Short: "Manage bug bounty platform integrations",
	Long: `Integrate with bug bounty platforms like HackerOne, Bugcrowd, AWS VRP, and Azure bounty programs.

Examples:
  # List programs from HackerOne
  shells platform programs --platform hackerone

  # Submit a finding to Bugcrowd
  shells platform submit <finding-id> --platform bugcrowd --program example-program

  # Validate platform credentials
  shells platform validate --platform hackerone

  # Auto-submit critical findings to all enabled platforms
  shells platform auto-submit --severity CRITICAL`,
}

var platformProgramsCmd = &cobra.Command{
	Use:   "programs",
	Short: "List available bug bounty programs",
	RunE: func(cmd *cobra.Command, args []string) error {
		// P0-2: TODO: Fix silent error suppression - check flag parsing errors
		platform, _ := cmd.Flags().GetString("platform")
		output, _ := cmd.Flags().GetString("output")

		client, err := getPlatformClient(platform)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		programs, err := client.GetPrograms(ctx)
		if err != nil {
			return fmt.Errorf("failed to get programs: %w", err)
		}

		if output == "json" {
			// P0-3: TODO: Fix silent error suppression - check JSON marshaling errors
			jsonData, _ := json.MarshalIndent(programs, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			printPrograms(programs)
		}

		return nil
	},
}

var platformSubmitCmd = &cobra.Command{
	Use:   "submit [finding-id]",
	Short: "Submit a finding to a bug bounty platform",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		findingID := args[0]
		// P0-2: TODO: Fix silent error suppression - check flag parsing errors
		platform, _ := cmd.Flags().GetString("platform")
		programHandle, _ := cmd.Flags().GetString("program")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		store := GetStore()
		if store == nil {
			return fmt.Errorf("database not initialized")
		}

		// Get finding from database
		// Note: FindingQuery doesn't have FindingID field, so we need to get by ID differently
		var findings []types.Finding
		// For now, query all and filter (TODO: add GetFindingByID method to store)
		allFindings, err := store.QueryFindings(GetContext(), core.FindingQuery{
			Limit: 1000,
		})
		if err == nil {
			for _, f := range allFindings {
				if f.ID == findingID {
					findings = []types.Finding{f}
					break
				}
			}
		}
		if err != nil || len(findings) == 0 {
			return fmt.Errorf("finding not found: %s", findingID)
		}
		finding := findings[0]

		// Convert finding to vulnerability report
		report := convertFindingToReport(&finding, programHandle)

		if dryRun {
			log.Info("DRY RUN - Report would be submitted:", "component", "platform")
			reportJSON, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println(string(reportJSON))
			return nil
		}

		// Get platform client
		client, err := getPlatformClient(platform)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Submit report
		response, err := client.Submit(ctx, report)
		if err != nil {
			return fmt.Errorf("failed to submit report: %w", err)
		}

		fmt.Printf(" Successfully submitted to %s\n", client.Name())
		fmt.Printf("Report ID: %s\n", response.ReportID)
		fmt.Printf("URL: %s\n", response.ReportURL)
		fmt.Printf("Status: %s\n", response.Status)

		// Store submission in database (convert store interface to concrete type)
		if dbStore, ok := store.(*database.Store); ok {
			err = storeSubmission(dbStore, findingID, platform, response)
		} else {
			err = fmt.Errorf("database store type assertion failed")
		}
		if err != nil {
			fmt.Printf("Warning: Failed to record submission in database: %v\n", err)
		}

		return nil
	},
}

var platformValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate platform credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		platform, _ := cmd.Flags().GetString("platform")

		client, err := getPlatformClient(platform)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := client.ValidateCredentials(ctx); err != nil {
			return fmt.Errorf("❌ Credentials invalid: %w", err)
		}

		fmt.Printf(" Credentials valid for %s\n", client.Name())
		return nil
	},
}

var platformAutoSubmitCmd = &cobra.Command{
	Use:   "auto-submit",
	Short: "Automatically submit findings to configured platforms",
	Long: `Auto-submit findings based on severity and platform configuration.

This command will:
1. Query findings matching the criteria
2. For each enabled platform, check if auto-submit is enabled
3. Submit findings that meet the minimum severity threshold
4. Record submissions in the database`,
	RunE: func(cmd *cobra.Command, args []string) error {
		severity, _ := cmd.Flags().GetString("severity")
		scanID, _ := cmd.Flags().GetString("scan-id")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		store := GetStore()
		if store == nil {
			return fmt.Errorf("database not initialized")
		}

		// Query findings
		query := core.FindingQuery{
			Severity: severity,
			Limit:    100,
		}
		if scanID != "" {
			query.ScanID = scanID
		}

		findings, err := store.QueryFindings(GetContext(), query)
		if err != nil {
			return fmt.Errorf("failed to query findings: %w", err)
		}

		if len(findings) == 0 {
			log.Info("No findings match the criteria", "component", "platform")
			return nil
		}

		fmt.Printf("Found %d findings to process\n", len(findings))

		// Get configuration
		cfg := GetConfig()
		submitted := 0
		errors := 0

		// Process each enabled platform
		platforms := getEnabledPlatforms(cfg)
		for _, platformName := range platforms {
			client, err := getPlatformClient(platformName)
			if err != nil {
				fmt.Printf("  Skipping %s: %v\n", platformName, err)
				continue
			}

			platformCfg := getPlatformConfig(cfg, platformName)
			if !shouldAutoSubmit(platformCfg) {
				fmt.Printf("⏭️  Skipping %s: auto-submit disabled\n", platformName)
				continue
			}

			fmt.Printf("\n📤 Processing %s...\n", client.Name())

			for _, finding := range findings {
				// Check severity threshold
				if !meetsSeverityThreshold(string(finding.Severity), platformCfg) {
					continue
				}

				// Check if already submitted
				dbStore, ok := store.(*database.Store)
				if !ok {
					fmt.Printf("    Database type assertion failed, skipping duplicate check\n")
					continue
				}
				alreadySubmitted, _ := checkAlreadySubmitted(dbStore, finding.ID, platformName)
				if alreadySubmitted {
					continue
				}

				report := convertFindingToReport(&finding, "")

				if dryRun {
					fmt.Printf("  [DRY RUN] Would submit: %s\n", finding.Title)
					continue
				}

				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				response, err := client.Submit(ctx, report)
				cancel()

				if err != nil {
					fmt.Printf("  ❌ Failed to submit %s: %v\n", finding.Title, err)
					errors++
					continue
				}

				fmt.Printf("   Submitted: %s (ID: %s)\n", finding.Title, response.ReportID)
				storeSubmission(dbStore, finding.ID, platformName, response)
				submitted++
			}
		}

		fmt.Printf("\n Summary: %d submitted, %d errors\n", submitted, errors)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(platformCmd)

	platformCmd.AddCommand(platformProgramsCmd)
	platformCmd.AddCommand(platformSubmitCmd)
	platformCmd.AddCommand(platformValidateCmd)
	platformCmd.AddCommand(platformAutoSubmitCmd)

	// Common flags
	for _, cmd := range []*cobra.Command{platformProgramsCmd, platformSubmitCmd, platformValidateCmd} {
		cmd.Flags().String("platform", "", "Platform name (hackerone, bugcrowd, aws, azure)")
		cmd.MarkFlagRequired("platform")
	}

	platformProgramsCmd.Flags().String("output", "table", "Output format (table, json)")

	platformSubmitCmd.Flags().String("program", "", "Program handle/identifier")
	platformSubmitCmd.Flags().Bool("dry-run", false, "Show what would be submitted without actually submitting")

	platformAutoSubmitCmd.Flags().String("severity", "CRITICAL", "Minimum severity to submit")
	platformAutoSubmitCmd.Flags().String("scan-id", "", "Only submit findings from specific scan")
	platformAutoSubmitCmd.Flags().Bool("dry-run", false, "Show what would be submitted without actually submitting")
}

// getPlatformClient returns a platform client based on name
func getPlatformClient(name string) (platforms.Platform, error) {
	cfg := GetConfig()

	switch strings.ToLower(name) {
	case "hackerone", "h1":
		if !cfg.Platforms.HackerOne.Enabled {
			return nil, fmt.Errorf("HackerOne integration not enabled in config")
		}
		return hackerone.NewClient(cfg.Platforms.HackerOne), nil
	case "bugcrowd", "bc":
		if !cfg.Platforms.Bugcrowd.Enabled {
			return nil, fmt.Errorf("Bugcrowd integration not enabled in config")
		}
		return bugcrowd.NewClient(cfg.Platforms.Bugcrowd), nil
	case "aws":
		if !cfg.Platforms.AWS.Enabled {
			return nil, fmt.Errorf("AWS VRP integration not enabled in config")
		}
		return aws.NewClient(cfg.Platforms.AWS), nil
	case "azure":
		if !cfg.Platforms.Azure.Enabled {
			return nil, fmt.Errorf("Azure bounty integration not enabled in config")
		}
		return azure.NewClient(cfg.Platforms.Azure), nil
	default:
		return nil, fmt.Errorf("unknown platform: %s", name)
	}
}

// convertFindingToReport converts a shells finding to a platform vulnerability report
func convertFindingToReport(finding *types.Finding, programHandle string) *platforms.VulnerabilityReport {
	// Extract additional metadata if available
	var cwe string
	var cvssScore float64
	var impact string
	var assetURL string

	if finding.Metadata != nil {
		if c, ok := finding.Metadata["cwe"].(string); ok {
			cwe = c
		}
		if score, ok := finding.Metadata["cvss_score"].(float64); ok {
			cvssScore = score
		}
		if imp, ok := finding.Metadata["impact"].(string); ok {
			impact = imp
		}
		if url, ok := finding.Metadata["asset_url"].(string); ok {
			assetURL = url
		}
	}

	// If no asset URL in metadata, try to derive from scan target
	if assetURL == "" && finding.Metadata != nil {
		if target, ok := finding.Metadata["target"].(string); ok {
			assetURL = target
		}
	}

	return &platforms.VulnerabilityReport{
		Title:          finding.Title,
		Description:    finding.Description,
		Severity:       string(finding.Severity),
		CVSSScore:      cvssScore,
		CWE:            cwe,
		ProgramHandle:  programHandle,
		AssetURL:       assetURL,
		ProofOfConcept: finding.Evidence,
		Impact:         impact,
		Remediation:    finding.Solution,
		DiscoveredAt:   finding.CreatedAt,
		ScanID:         finding.ScanID,
		ToolName:       finding.Tool,
	}
}

// getEnabledPlatforms returns list of enabled platform names
func getEnabledPlatforms(cfg *config.Config) []string {
	var enabled []string
	if cfg.Platforms.HackerOne.Enabled {
		enabled = append(enabled, "hackerone")
	}
	if cfg.Platforms.Bugcrowd.Enabled {
		enabled = append(enabled, "bugcrowd")
	}
	if cfg.Platforms.AWS.Enabled {
		enabled = append(enabled, "aws")
	}
	if cfg.Platforms.Azure.Enabled {
		enabled = append(enabled, "azure")
	}
	return enabled
}

// getPlatformConfig returns config for a platform
func getPlatformConfig(cfg *config.Config, platform string) interface{} {
	switch platform {
	case "hackerone":
		return cfg.Platforms.HackerOne
	case "bugcrowd":
		return cfg.Platforms.Bugcrowd
	case "aws":
		return cfg.Platforms.AWS
	case "azure":
		return cfg.Platforms.Azure
	default:
		return nil
	}
}

// shouldAutoSubmit checks if platform has auto-submit enabled
func shouldAutoSubmit(cfg interface{}) bool {
	switch c := cfg.(type) {
	case config.HackerOneConfig:
		return c.AutoSubmit
	case config.BugcrowdConfig:
		return c.AutoSubmit
	case config.AWSBountyConfig:
		return c.AutoSubmit
	case config.AzureBountyConfig:
		return c.AutoSubmit
	default:
		return false
	}
}

// meetsSeverityThreshold checks if finding meets platform severity threshold
func meetsSeverityThreshold(severity string, cfg interface{}) bool {
	var threshold string
	switch c := cfg.(type) {
	case config.HackerOneConfig:
		threshold = c.MinimumSeverity
	case config.BugcrowdConfig:
		threshold = c.MinimumSeverity
	case config.AWSBountyConfig:
		threshold = c.MinimumSeverity
	case config.AzureBountyConfig:
		threshold = c.MinimumSeverity
	default:
		return false
	}

	severityLevels := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
		"INFO":     0,
	}

	findingSev := severityLevels[severity]
	thresholdSev := severityLevels[strings.ToUpper(threshold)]

	return findingSev >= thresholdSev
}

// checkAlreadySubmitted checks if finding was already submitted to platform
func checkAlreadySubmitted(store *database.Store, findingID, platform string) (bool, error) {
	return store.CheckSubmissionExists(context.Background(), findingID, platform)
}

// storeSubmission records a submission in the database
func storeSubmission(store *database.Store, findingID, platform string, response *platforms.SubmissionResponse) error {
	// Marshal platform data to JSON
	platformDataJSON := ""
	if response.PlatformData != nil {
		data, err := json.Marshal(response.PlatformData)
		if err == nil {
			platformDataJSON = string(data)
		}
	}

	submission := &database.PlatformSubmission{
		FindingID:     findingID,
		Platform:      platform,
		ProgramHandle: "", // Would be extracted from response if available
		ReportID:      response.ReportID,
		ReportURL:     response.ReportURL,
		Status:        response.Status,
		PlatformData:  platformDataJSON,
	}

	err := store.CreateSubmission(context.Background(), submission)
	if err != nil {
		return fmt.Errorf("failed to record submission: %w", err)
	}

	fmt.Printf("📝 Recorded submission in database: id=%s\n", submission.ID)
	return nil
}

// printPrograms prints programs in a table format
func printPrograms(programs []*platforms.Program) {
	log.Info("\nBug Bounty Programs:", "component", "platform")
	fmt.Println(strings.Repeat("=", 80))
	for _, p := range programs {
		fmt.Printf("\n📋 %s (%s)\n", p.Name, p.Handle)
		fmt.Printf("   Platform: %s\n", p.Platform)
		fmt.Printf("   URL: %s\n", p.URL)
		fmt.Printf("   Active: %v\n", p.IsActive)
		if len(p.Scope) > 0 {
			fmt.Printf("   In Scope: %d assets\n", len(p.Scope))
		}
		if p.Rewards != nil {
			fmt.Printf("   Rewards: %s %.0f-%.0f\n",
				p.Rewards.Currency,
				getMinReward(p.Rewards),
				getMaxReward(p.Rewards))
		}
	}
	fmt.Println()
}

func getMinReward(rewards *platforms.Rewards) float64 {
	min := 999999999.0
	for _, v := range rewards.Bounties {
		if v < min {
			min = v
		}
	}
	return min
}

func getMaxReward(rewards *platforms.Rewards) float64 {
	max := 0.0
	for _, v := range rewards.Bounties {
		if v > max {
			max = v
		}
	}
	return max
}
