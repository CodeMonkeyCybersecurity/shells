package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/database"
	"github.com/spf13/cobra"
)

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Database management commands",
	Long:  `Commands for managing the shells database, including migrations and maintenance.`,
}

var dbMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run pending database migrations",
	Long: `Run all pending database migrations to update the schema.

This command will:
1. Connect to the PostgreSQL database
2. Check for pending migrations
3. Apply migrations in order
4. Track migration status

The database connection can be configured via:
- Config file (.shells.yaml)
- Environment variables (SHELLS_DB_HOST, SHELLS_DB_PORT, etc.)`,
	RunE: runDBMigrate,
}

var dbStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show database migration status",
	Long:  `Display the current status of database migrations including version and pending migrations.`,
	RunE:  runDBStatus,
}

var dbRollbackCmd = &cobra.Command{
	Use:   "rollback [version]",
	Short: "Rollback a specific migration",
	Long: `Rollback a specific migration version.

Warning: This will undo changes made by the migration. Use with caution.`,
	Args: cobra.ExactArgs(1),
	RunE: runDBRollback,
}

func init() {
	rootCmd.AddCommand(dbCmd)
	dbCmd.AddCommand(dbMigrateCmd)
	dbCmd.AddCommand(dbStatusCmd)
	dbCmd.AddCommand(dbRollbackCmd)
}

func runDBMigrate(cmd *cobra.Command, args []string) error {
	log.Infow("Starting database migration",
		"component", "db_migrate",
	)

	// Connect to database
	store, err := database.NewStore(cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer store.Close()

	// Get underlying sqlx.DB
	sqlStore, ok := store.(*database.Store)
	if !ok {
		return fmt.Errorf("failed to get database connection")
	}

	// Run migrations
	runner := database.NewMigrationRunner(sqlStore.DB(), log)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := runner.RunMigrations(ctx); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	log.Infow("Database migration completed successfully",
		"component", "db_migrate",
	)

	return nil
}

func runDBStatus(cmd *cobra.Command, args []string) error {
	log.Infow("Checking database migration status",
		"component", "db_status",
	)

	// Connect to database
	store, err := database.NewStore(cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer store.Close()

	// Get underlying sqlx.DB
	sqlStore, ok := store.(*database.Store)
	if !ok {
		return fmt.Errorf("failed to get database connection")
	}

	// Get status
	runner := database.NewMigrationRunner(sqlStore.DB(), log)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	status, err := runner.GetMigrationStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get migration status: %w", err)
	}

	// Display status
	fmt.Println("Database Migration Status")
	fmt.Println("=========================")
	fmt.Printf("Current Version:  %d\n", status["current_version"])
	fmt.Printf("Latest Version:   %d\n", status["latest_version"])
	fmt.Printf("Applied:          %d migrations\n", status["applied_count"])
	fmt.Printf("Available:        %d migrations\n", status["available_count"])
	fmt.Printf("Pending:          %d migrations\n", status["pending_count"])

	if status["is_up_to_date"].(bool) {
		fmt.Println("\nStatus: Database is up to date")
	} else {
		fmt.Println("\nStatus: Pending migrations need to be applied")
		fmt.Println("\nRun 'shells db migrate' to apply pending migrations")
	}

	return nil
}

func runDBRollback(cmd *cobra.Command, args []string) error {
	version := 0
	if _, err := fmt.Sscanf(args[0], "%d", &version); err != nil {
		return fmt.Errorf("invalid version number: %s", args[0])
	}

	log.Warnw("Rolling back database migration",
		"component", "db_rollback",
		"version", version,
	)

	fmt.Printf("WARNING: You are about to rollback migration version %d\n", version)
	fmt.Printf("This will undo changes made by this migration.\n")
	fmt.Printf("\nPress Enter to continue or Ctrl+C to cancel...")
	fmt.Scanln()

	// Connect to database
	store, err := database.NewStore(cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer store.Close()

	// Get underlying sqlx.DB
	sqlStore, ok := store.(*database.Store)
	if !ok {
		return fmt.Errorf("failed to get database connection")
	}

	// Rollback migration
	runner := database.NewMigrationRunner(sqlStore.DB(), log)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := runner.RollbackMigration(ctx, version); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	log.Infow("Migration rolled back successfully",
		"component", "db_rollback",
		"version", version,
	)

	fmt.Printf("Migration %d rolled back successfully\n", version)
	return nil
}
