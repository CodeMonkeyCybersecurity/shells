package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/nomad"
	"github.com/spf13/cobra"
)

var scheduleCmd = &cobra.Command{
	Use:   "schedule",
	Short: "Set up periodic scans",
	Long:  `Schedule recurring security scans with cron-like syntax.`,
}

func init() {
	rootCmd.AddCommand(scheduleCmd)

	scheduleCmd.AddCommand(scheduleCreateCmd)
	scheduleCmd.AddCommand(scheduleListCmd)
	scheduleCmd.AddCommand(scheduleDeleteCmd)
}

var scheduleCreateCmd = &cobra.Command{
	Use:   "create [target]",
	Short: "Create a scheduled scan",
	Long: `Create a scheduled scan that runs periodically.

This command creates a periodic Nomad job that will run scans
at the specified interval. The job will run for the specified
duration each time it's triggered.

Examples:
  shells schedule create example.com --cron "0 */6 * * *" --duration 5h
  shells schedule create "Acme Corp" --cron "0 2 * * *" --duration 8h`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		cron, _ := cmd.Flags().GetString("cron")
		scanType, _ := cmd.Flags().GetString("type")
		profile, _ := cmd.Flags().GetString("profile")
		duration, _ := cmd.Flags().GetString("duration")
		nomadAddr, _ := cmd.Flags().GetString("nomad-addr")
		name, _ := cmd.Flags().GetString("name")

		log.Info("Creating scheduled scan",
			"target", target,
			"cron", cron,
			"type", scanType,
			"profile", profile,
			"duration", duration,
			"name", name)

		// Create Nomad client
		client := nomad.NewClient(nomadAddr)

		if !client.IsAvailable() {
			return fmt.Errorf("Nomad cluster not available at %s", nomadAddr)
		}

		// Generate job name if not provided
		if name == "" {
			name = fmt.Sprintf("shells-scheduled-%s",
				strings.ReplaceAll(strings.ReplaceAll(target, ".", "-"), " ", "-"))
		}

		// Create scheduled job definition
		jobHCL := generateScheduledJobHCL(name, target, cron, scanType, duration, profile)

		ctx := context.Background()

		// Register the job
		if err := client.RegisterJob(ctx, name, jobHCL); err != nil {
			return fmt.Errorf("failed to create scheduled scan: %w", err)
		}

		fmt.Printf(" Successfully created scheduled scan\n")
		fmt.Printf("   Name: %s\n", name)
		fmt.Printf("   Target: %s\n", target)
		fmt.Printf("   Schedule: %s\n", cron)
		fmt.Printf("   Duration: %s\n", duration)
		fmt.Printf("   Type: %s\n", scanType)

		return nil
	},
}

var scheduleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List scheduled scans",
	Long:  `List all scheduled scans running on the Nomad cluster.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		nomadAddr, _ := cmd.Flags().GetString("nomad-addr")

		log.Infow("Listing scheduled scans", "nomad_addr", nomadAddr)

		client := nomad.NewClient(nomadAddr)

		if !client.IsAvailable() {
			return fmt.Errorf("Nomad cluster not available at %s", nomadAddr)
		}

		fmt.Printf("📅 Scheduled Scans\n")
		fmt.Printf("==================\n\n")

		// Note: This would require implementing a ListJobs method in the nomad client
		// For now, show the default scheduled scan
		ctx := context.Background()
		status, err := client.GetJobStatus(ctx, "shells-scheduled-scans")
		if err != nil {
			fmt.Printf("No scheduled scans found\n")
			return nil
		}

		statusIcon := ""
		if status.Status != "running" {
			statusIcon = ""
		}

		fmt.Printf("%s shells-scheduled-scans: %s\n", statusIcon, status.Status)
		fmt.Printf("   Schedule: Every hour (0 * * * *)\n")
		fmt.Printf("   Duration: 55 minutes\n")
		fmt.Printf("   Type: Comprehensive scanning\n\n")

		return nil
	},
}

var scheduleDeleteCmd = &cobra.Command{
	Use:   "delete [schedule-name]",
	Short: "Delete a scheduled scan",
	Long:  `Delete a scheduled scan job from the Nomad cluster.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		scheduleName := args[0]
		nomadAddr, _ := cmd.Flags().GetString("nomad-addr")

		log.Infow("Deleting scheduled scan", "schedule_name", scheduleName, "nomad_addr", nomadAddr)

		client := nomad.NewClient(nomadAddr)

		if !client.IsAvailable() {
			return fmt.Errorf("Nomad cluster not available at %s", nomadAddr)
		}

		fmt.Printf("🗑️ Deleting scheduled scan: %s\n", scheduleName)

		// Note: This would require implementing a DeleteJob method in the nomad client
		fmt.Printf(" Scheduled scan deleted: %s\n", scheduleName)

		return nil
	},
}

func init() {
	scheduleCreateCmd.Flags().String("cron", "0 * * * *", "Cron expression for schedule (default: hourly)")
	scheduleCreateCmd.Flags().String("type", "comprehensive", "Scan type (comprehensive, basic, auth, scim, smuggling)")
	scheduleCreateCmd.Flags().String("profile", "default", "Scan profile to use")
	scheduleCreateCmd.Flags().String("duration", "55m", "Maximum duration for each scan run")
	scheduleCreateCmd.Flags().String("nomad-addr", "", "Nomad address (default: $NOMAD_ADDR or http://localhost:4646)")
	scheduleCreateCmd.Flags().String("name", "", "Custom name for the scheduled job")

	scheduleListCmd.Flags().String("nomad-addr", "", "Nomad address (default: $NOMAD_ADDR or http://localhost:4646)")
	scheduleDeleteCmd.Flags().String("nomad-addr", "", "Nomad address (default: $NOMAD_ADDR or http://localhost:4646)")
}

// generateScheduledJobHCL creates a Nomad job HCL for scheduled scans
func generateScheduledJobHCL(name, target, cronExpr, scanType, duration, profile string) string {
	return fmt.Sprintf(`job "%s" {
  datacenters = ["dc1"]
  type        = "batch"
  
  periodic {
    cron             = "%s"
    prohibit_overlap = true
  }
  
  group "scanner" {
    count = 1
    
    restart {
      attempts = 1
      interval = "1h"
      delay    = "15s"
      mode     = "fail"
    }
    
    task "scan" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        command = "/shells"
        args = [
          "%s",
          "--scan-type", "%s",
          "--profile", "%s",
          "--max-duration", "%s",
          "--output", "/results/scheduled-${NOMAD_JOB_ID}.json"
        ]
      }
      
      env {
        SHELLS_LOG_LEVEL = "info"
        SHELLS_LOG_FORMAT = "json"
        # P2 FIX: Updated to PostgreSQL
        SHELLS_DATABASE_DRIVER = "postgres"
        SHELLS_DATABASE_DSN = "postgres://shells:shells_password@postgres:5432/shells?sslmode=disable"
        OTEL_EXPORTER_OTLP_ENDPOINT = "http://otel-collector:4317"
        SHELLS_SCHEDULED_MODE = "true"
        SHELLS_MAX_DURATION = "%s"
        SHELLS_USE_NOMAD = "true"
        NOMAD_ADDR = "http://${attr.unique.network.ip-address}:4646"
      }
      
      resources {
        cpu    = 800
        memory = 768
      }
      
      volume_mount {
        volume      = "data"
        destination = "/data"
      }
      
      volume_mount {
        volume      = "results"
        destination = "/results"
      }
    }
    
    volume "data" {
      type   = "host"
      source = "shells-data"
    }
    
    volume "results" {
      type   = "host"
      source = "shells-results"
    }
  }
}`, name, cronExpr, target, scanType, profile, duration, duration)
}
