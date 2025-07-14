package cmd

import (
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
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		cron, _ := cmd.Flags().GetString("cron")
		scanType, _ := cmd.Flags().GetString("type")
		profile, _ := cmd.Flags().GetString("profile")

		log.Info("Creating schedule", "target", target, "cron", cron, "type", scanType, "profile", profile)

		return nil
	},
}

var scheduleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List scheduled scans",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Info("Listing schedules")
		return nil
	},
}

var scheduleDeleteCmd = &cobra.Command{
	Use:   "delete [schedule-id]",
	Short: "Delete a scheduled scan",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		scheduleID := args[0]

		log.Info("Deleting schedule", "scheduleID", scheduleID)

		return nil
	},
}

func init() {
	scheduleCreateCmd.Flags().String("cron", "0 0 * * *", "Cron expression for schedule")
	scheduleCreateCmd.Flags().String("type", "full", "Scan type")
	scheduleCreateCmd.Flags().String("profile", "default", "Scan profile to use")
}
