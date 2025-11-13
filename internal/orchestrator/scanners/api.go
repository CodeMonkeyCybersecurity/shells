// internal/orchestrator/scanners/api.go
//
// API Scanner - Tests REST API security
//
// REFACTORING CONTEXT:
// Extracted from bounty_engine.go runAPITests() (lines 2659-2751, ~92 lines)
// Tests REST API endpoints for authentication bypass, IDOR, mass assignment, CORS

package scanners

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/core"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// APIScanner tests REST API endpoints
type APIScanner struct {
	scanner core.Scanner
	logger  *logger.Logger
}

// NewAPIScanner creates a new API scanner
func NewAPIScanner(scanner core.Scanner, logger *logger.Logger) *APIScanner {
	return &APIScanner{
		scanner: scanner,
		logger:  logger.WithComponent("api-scanner"),
	}
}

// Name returns the scanner name
func (s *APIScanner) Name() string {
	return "REST API Scanner"
}

// Type returns the scanner type
func (s *APIScanner) Type() string {
	return "api"
}

// Priority returns execution priority (3 = runs after auth)
func (s *APIScanner) Priority() int {
	return 3
}

// CanHandle determines if this scanner can test the asset
func (s *APIScanner) CanHandle(asset *AssetPriority) bool {
	// Check if asset has API characteristics
	if asset.Features.HasAPIEndpoints {
		return true
	}

	// Check URL patterns
	url := asset.Asset.Value
	if url == "" && asset.Asset.Domain != "" {
		url = fmt.Sprintf("https://%s", asset.Asset.Domain)
	}

	return strings.Contains(url, "/api/") ||
		strings.Contains(url, "/graphql") ||
		strings.Contains(url, "/swagger") ||
		strings.Contains(url, "/openapi")
}

// Execute runs API testing against prioritized assets
func (s *APIScanner) Execute(ctx context.Context, assets []*AssetPriority) ([]types.Finding, error) {
	startTime := time.Now()
	allFindings := []types.Finding{}

	s.logger.Infow("Starting REST API security testing",
		"asset_count", len(assets),
	)

	// Find API endpoints from discovered assets
	apiEndpoints := s.extractAPIEndpoints(assets)

	if len(apiEndpoints) == 0 {
		s.logger.Infow("No API endpoints found")
		return allFindings, nil
	}

	s.logger.Infow("API endpoints identified",
		"count", len(apiEndpoints),
	)

	// Test each API endpoint
	for _, endpoint := range apiEndpoints {
		select {
		case <-ctx.Done():
			return allFindings, ctx.Err()
		default:
		}

		s.logger.Debugw("Testing REST API endpoint",
			"endpoint", endpoint,
		)

		apiFindings, err := s.scanner.Scan(ctx, endpoint, nil)
		if err != nil {
			s.logger.Warnw("REST API scan failed",
				"error", err,
				"endpoint", endpoint,
			)
			continue
		}

		allFindings = append(allFindings, apiFindings...)

		s.logger.Infow("REST API scan completed",
			"endpoint", endpoint,
			"findings", len(apiFindings),
		)
	}

	duration := time.Since(startTime)
	s.logger.Infow("REST API testing completed",
		"total_findings", len(allFindings),
		"duration", duration.String(),
	)

	return allFindings, nil
}

// extractAPIEndpoints finds API endpoints from assets
func (s *APIScanner) extractAPIEndpoints(assets []*AssetPriority) []string {
	endpoints := []string{}
	seen := make(map[string]bool)

	for _, asset := range assets {
		url := asset.Asset.Value
		if url == "" && asset.Asset.Domain != "" {
			url = fmt.Sprintf("https://%s", asset.Asset.Domain)
		}

		if url != "" && !seen[url] {
			// Look for API patterns
			if strings.Contains(url, "/api/") ||
				strings.Contains(url, "/graphql") ||
				strings.Contains(url, "/swagger") ||
				strings.Contains(url, "/openapi") ||
				asset.Features.HasAPIEndpoints {
				endpoints = append(endpoints, url)
				seen[url] = true
			}
		}
	}

	return endpoints
}
