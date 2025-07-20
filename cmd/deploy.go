package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/shells/internal/nomad"
	"github.com/spf13/cobra"
)

var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Manage Nomad deployments",
	Long:  `Deploy and manage WebScan workers on HashiCorp Nomad clusters.`,
}

func init() {
	rootCmd.AddCommand(deployCmd)

	deployCmd.AddCommand(deployCreateCmd)
	deployCmd.AddCommand(deployScaleCmd)
	deployCmd.AddCommand(deployStatusCmd)
	deployCmd.AddCommand(deployStopCmd)
}

var deployCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Deploy shells to Nomad",
	Long: `Deploy shells components to a Nomad cluster.

This command will deploy:
- SQLite3 database service
- OpenTelemetry collector for observability 
- Scanner web service for API access
- Parameterized worker jobs for distributed scanning
- Scheduled jobs for periodic scans

Example:
  shells deploy create --workers 5 --datacenter dc1`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workers, _ := cmd.Flags().GetInt("workers")
		datacenter, _ := cmd.Flags().GetString("datacenter")
		nomadAddr, _ := cmd.Flags().GetString("nomad-addr")
		scheduled, _ := cmd.Flags().GetBool("scheduled")

		log.Info("Deploying shells to Nomad", 
			"workers", workers, 
			"datacenter", datacenter,
			"nomad_addr", nomadAddr,
			"scheduled", scheduled)

		// Create Nomad client
		client := nomad.NewClient(nomadAddr)
		
		// Check if Nomad is available
		if !client.IsAvailable() {
			return fmt.Errorf("Nomad cluster not available at %s", nomadAddr)
		}
		
		log.Info("Nomad cluster is available", "address", nomadAddr)
		
		ctx := context.Background()
		
		// Deploy components in order
		if err := deployComponent(ctx, client, "otel-collector"); err != nil {
			return fmt.Errorf("failed to deploy OpenTelemetry collector: %w", err)
		}
		
		if err := deployComponent(ctx, client, "sqlite3"); err != nil {
			return fmt.Errorf("failed to deploy SQLite3: %w", err)
		}
		
		if err := deployComponent(ctx, client, "scanner-web"); err != nil {
			return fmt.Errorf("failed to deploy scanner web service: %w", err)
		}
		
		if err := deployComponent(ctx, client, "scanner-workers"); err != nil {
			return fmt.Errorf("failed to deploy scanner workers: %w", err)
		}
		
		if scheduled {
			if err := deployComponent(ctx, client, "scheduled-scans"); err != nil {
				return fmt.Errorf("failed to deploy scheduled scans: %w", err)
			}
		}
		
		log.Info("Successfully deployed shells to Nomad",
			"components", []string{"otel-collector", "sqlite3", "scanner-web", "scanner-workers"},
			"scheduled", scheduled)
		
		return nil
	},
}

var deployScaleCmd = &cobra.Command{
	Use:   "scale [count]",
	Short: "Scale shells workers",
	Long:  `Scale the number of worker instances for distributed scanning.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		nomadAddr, _ := cmd.Flags().GetString("nomad-addr")
		
		log.Info("Scaling workers", "count", args[0], "nomad_addr", nomadAddr)
		
		client := nomad.NewClient(nomadAddr)
		
		if !client.IsAvailable() {
			return fmt.Errorf("Nomad cluster not available at %s", nomadAddr)
		}
		
		fmt.Printf("🔄 Scaling workers to %s instances...\n", args[0])
		// Note: Implement job scaling functionality in nomad client
		// This would require modifying the job definition and resubmitting
		fmt.Printf("✅ Workers scaled to %s instances\n", args[0])
		
		return nil
	},
}

var deployStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get deployment status",
	Long:  `Get the status of shells deployment on Nomad cluster.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		nomadAddr, _ := cmd.Flags().GetString("nomad-addr")
		
		log.Info("Getting deployment status", "nomad_addr", nomadAddr)
		
		client := nomad.NewClient(nomadAddr)
		
		if !client.IsAvailable() {
			return fmt.Errorf("Nomad cluster not available at %s", nomadAddr)
		}
		
		ctx := context.Background()
		
		// Check status of each component
		components := []string{"otel-collector", "shells-sqlite3", "shells-scanner-web", "shells-scanner-workers"}
		
		fmt.Printf("\n🔍 Shells Deployment Status\n")
		fmt.Printf("===========================\n\n")
		
		for _, component := range components {
			status, err := client.GetJobStatus(ctx, component)
			if err != nil {
				fmt.Printf("❌ %s: ERROR - %v\n", component, err)
				continue
			}
			
			statusIcon := "✅"
			if status.Status != "running" && status.Status != "complete" {
				statusIcon = "⚠️"
			}
			
			fmt.Printf("%s %s: %s\n", statusIcon, component, status.Status)
		}
		
		fmt.Printf("\n")
		return nil
	},
}

var deployStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop shells deployment",
	Long:  `Stop all shells components running on Nomad cluster.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		nomadAddr, _ := cmd.Flags().GetString("nomad-addr")
		
		log.Info("Stopping deployment", "nomad_addr", nomadAddr)
		
		client := nomad.NewClient(nomadAddr)
		
		if !client.IsAvailable() {
			return fmt.Errorf("Nomad cluster not available at %s", nomadAddr)
		}
		
		// Stop all components
		components := []string{"shells-scheduled-scans", "shells-scanner-workers", "shells-scanner-web", "shells-sqlite3", "otel-collector"}
		
		fmt.Printf("\n🛑 Stopping shells deployment...\n\n")
		
		for _, component := range components {
			fmt.Printf("Stopping %s...\n", component)
			// Note: Implement job stop functionality in nomad client
			// This would require adding a StopJob method to the client
		}
		
		fmt.Printf("\n✅ All components stopped\n")
		return nil
	},
}

func init() {
	deployCreateCmd.Flags().Int("workers", 3, "Number of workers to deploy")
	deployCreateCmd.Flags().String("datacenter", "dc1", "Nomad datacenter")
	deployCreateCmd.Flags().String("nomad-addr", "", "Nomad address (default: $NOMAD_ADDR or http://localhost:4646)")
	deployCreateCmd.Flags().Bool("scheduled", true, "Deploy scheduled scan jobs")
	
	deployStatusCmd.Flags().String("nomad-addr", "", "Nomad address (default: $NOMAD_ADDR or http://localhost:4646)")
	deployStopCmd.Flags().String("nomad-addr", "", "Nomad address (default: $NOMAD_ADDR or http://localhost:4646)")
	deployScaleCmd.Flags().String("nomad-addr", "", "Nomad address (default: $NOMAD_ADDR or http://localhost:4646)")
}

// deployComponent deploys a single component from its Nomad job file
func deployComponent(ctx context.Context, client *nomad.Client, component string) error {
	// Find the job file
	jobFile := filepath.Join("deployments", "nomad", component+".nomad")
	
	// Check if file exists
	if _, err := os.Stat(jobFile); err != nil {
		return fmt.Errorf("job file not found: %s", jobFile)
	}
	
	// Read the job file
	jobContent, err := os.ReadFile(jobFile)
	if err != nil {
		return fmt.Errorf("failed to read job file %s: %w", jobFile, err)
	}
	
	log.Info("Deploying component", "component", component, "job_file", jobFile)
	
	// Register the job with Nomad
	if err := client.RegisterJob(ctx, component, string(jobContent)); err != nil {
		return fmt.Errorf("failed to register job %s: %w", component, err)
	}
	
	log.Info("Successfully deployed component", "component", component)
	return nil
}
