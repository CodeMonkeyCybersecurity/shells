// cmd/orchestrator_main.go - THIN ORCHESTRATION LAYER
//
// REFACTORED 2025-10-30: All business logic moved to pkg/cli/commands/bounty.go
// This file now ONLY contains CLI orchestration: flag parsing and delegating to pkg/cli

package cmd

import (
	"context"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/cli/commands"
	"github.com/spf13/cobra"
)

// runIntelligentOrchestrator is the main entry point - THIN WRAPPER
// Business logic is in pkg/cli/commands/bounty.go
func runIntelligentOrchestrator(ctx context.Context, target string, cmd *cobra.Command, log *logger.Logger, store core.ResultStore) error {
	// Build configuration from flags
	config := commands.BuildConfigFromFlags(cmd)

	// Delegate to business logic layer
	return commands.RunBountyHunt(ctx, target, config, log, store)
}
