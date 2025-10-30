// internal/orchestrator/scanners/graphql.go
//
// GraphQL Scanner - GraphQL introspection and vulnerability testing
//
// REFACTORING CONTEXT:
// Extracted from bounty_engine.go runGraphQLTests() (lines 3068-3175, ~107 lines)
// Tests GraphQL endpoints for introspection, injection, DoS, batching attacks

package scanners

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// GraphQLScanner tests GraphQL endpoints
type GraphQLScanner struct {
	scanner core.Scanner
	logger  *logger.Logger
}

// NewGraphQLScanner creates a new GraphQL scanner
func NewGraphQLScanner(scanner core.Scanner, logger *logger.Logger) *GraphQLScanner {
	return &GraphQLScanner{
		scanner: scanner,
		logger:  logger.WithComponent("graphql-scanner"),
	}
}

// Name returns the scanner name
func (s *GraphQLScanner) Name() string {
	return "GraphQL Scanner"
}

// Type returns the scanner type
func (s *GraphQLScanner) Type() string {
	return "api"
}

// Priority returns execution priority (3 = runs with API testing)
func (s *GraphQLScanner) Priority() int {
	return 3
}

// CanHandle determines if this scanner can test the asset
func (s *GraphQLScanner) CanHandle(asset *AssetPriority) bool {
	// Check for GraphQL URL patterns
	url := asset.Asset.Value
	if url == "" && asset.Asset.Domain != "" {
		url = fmt.Sprintf("https://%s", asset.Asset.Domain)
	}

	return strings.Contains(url, "/graphql") ||
		strings.Contains(url, "/gql") ||
		asset.Features.HasAPIEndpoints // GraphQL is an API
}

// Execute runs GraphQL testing against prioritized assets
func (s *GraphQLScanner) Execute(ctx context.Context, assets []*AssetPriority) ([]types.Finding, error) {
	startTime := time.Now()
	allFindings := []types.Finding{}

	s.logger.Infow("Starting GraphQL security testing",
		"asset_count", len(assets),
	)

	// Find GraphQL endpoints
	graphqlEndpoints := s.extractGraphQLEndpoints(assets)

	if len(graphqlEndpoints) == 0 {
		s.logger.Infow("No GraphQL endpoints found")
		return allFindings, nil
	}

	s.logger.Infow("GraphQL endpoints identified",
		"count", len(graphqlEndpoints),
	)

	// Test each GraphQL endpoint
	for _, endpoint := range graphqlEndpoints {
		select {
		case <-ctx.Done():
			return allFindings, ctx.Err()
		default:
		}

		s.logger.Infow("Testing GraphQL endpoint",
			"endpoint", endpoint,
		)

		findings, err := s.scanner.Scan(ctx, endpoint, nil)
		if err != nil {
			s.logger.Warnw("GraphQL scan failed",
				"error", err,
				"endpoint", endpoint,
			)
			continue
		}

		allFindings = append(allFindings, findings...)

		s.logger.Infow("GraphQL scan completed",
			"endpoint", endpoint,
			"findings", len(findings),
		)
	}

	duration := time.Since(startTime)
	s.logger.Infow("GraphQL testing completed",
		"total_findings", len(allFindings),
		"duration", duration.String(),
	)

	return allFindings, nil
}

// extractGraphQLEndpoints finds GraphQL endpoints from assets
func (s *GraphQLScanner) extractGraphQLEndpoints(assets []*AssetPriority) []string {
	endpoints := []string{}
	seen := make(map[string]bool)

	for _, asset := range assets {
		url := asset.Asset.Value
		if url == "" && asset.Asset.Domain != "" {
			url = fmt.Sprintf("https://%s", asset.Asset.Domain)
		}

		if url != "" && !seen[url] {
			// Look for GraphQL patterns
			if strings.Contains(url, "/graphql") ||
				strings.Contains(url, "/gql") {
				endpoints = append(endpoints, url)
				seen[url] = true
			}
		}
	}

	return endpoints
}
