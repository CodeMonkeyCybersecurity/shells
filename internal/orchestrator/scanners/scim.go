// internal/orchestrator/scanners/scim.go
//
// SCIM Scanner - Tests SCIM provisioning vulnerabilities
//
// REFACTORING CONTEXT:
// Extracted from bounty_engine.go runSCIMTests() (lines 2563-2657, ~95 lines)
// Tests SCIM endpoints for unauthorized provisioning, filter injection, bulk operations

package scanners

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// SCIMScanner tests SCIM provisioning endpoints
type SCIMScanner struct {
	scanner core.Scanner
	logger  *logger.Logger
	config  SCIMConfig
}

// SCIMConfig contains SCIM scanner configuration
type SCIMConfig struct {
	MaxWorkers int
	Timeout    time.Duration
}

// NewSCIMScanner creates a new SCIM scanner
func NewSCIMScanner(scanner core.Scanner, logger *logger.Logger, config SCIMConfig) *SCIMScanner {
	if config.MaxWorkers == 0 {
		config.MaxWorkers = 5
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	return &SCIMScanner{
		scanner: scanner,
		logger:  logger.WithComponent("scim-scanner"),
		config:  config,
	}
}

// Name returns the scanner name
func (s *SCIMScanner) Name() string {
	return "SCIM Scanner"
}

// Type returns the scanner type
func (s *SCIMScanner) Type() string {
	return "access-control"
}

// Priority returns execution priority (4 = runs after auth and API)
func (s *SCIMScanner) Priority() int {
	return 4
}

// CanHandle determines if this scanner can test the asset
func (s *SCIMScanner) CanHandle(asset *AssetPriority) bool {
	return asset.Features.HasSCIMEndpoint
}

// Execute runs SCIM testing against prioritized assets
func (s *SCIMScanner) Execute(ctx context.Context, assets []*AssetPriority) ([]types.Finding, error) {
	startTime := time.Now()
	var findings []types.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	s.logger.Infow("Starting SCIM testing",
		"asset_count", len(assets),
	)

	// Worker pool for parallel SCIM testing
	semaphore := make(chan struct{}, s.config.MaxWorkers)

	// Test each SCIM endpoint in parallel
	for _, asset := range assets {
		target := s.getTargetURL(asset)
		if target == "" {
			continue
		}

		wg.Add(1)
		semaphore <- struct{}{} // Acquire worker slot

		go func(targetURL string) {
			defer func() {
				// Panic recovery - graceful error handling
				if r := recover(); r != nil {
					s.logger.Errorw("SCIM scanner panicked - recovered gracefully",
						"url", targetURL,
						"panic", r,
					)
				}
				<-semaphore // Release worker slot
				wg.Done()
			}()

			s.logger.Infow("Testing SCIM endpoint",
				"url", targetURL,
			)

			// Run SCIM vulnerability tests with timeout protection
			scanCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
			defer cancel()

			scimOptions := make(map[string]string)
			scimOptions["test_all"] = "true"

			scimFindings, err := s.scanner.Scan(scanCtx, targetURL, scimOptions)
			if err != nil {
				s.logger.Warnw("SCIM scan failed",
					"url", targetURL,
					"error", err,
				)
				return
			}

			// Thread-safe append of findings
			mu.Lock()
			findings = append(findings, scimFindings...)
			mu.Unlock()

			s.logger.Infow("SCIM scan completed",
				"url", targetURL,
				"findings", len(scimFindings),
			)
		}(target)
	}

	// Wait for all SCIM scans to complete
	wg.Wait()

	duration := time.Since(startTime)
	s.logger.Infow("SCIM testing completed",
		"total_findings", len(findings),
		"duration", duration.String(),
	)

	return findings, nil
}

// getTargetURL extracts URL from asset
func (s *SCIMScanner) getTargetURL(asset *AssetPriority) string {
	if asset.Asset.Value != "" {
		return asset.Asset.Value
	}
	if asset.Asset.Domain != "" {
		return fmt.Sprintf("https://%s/scim/v2", asset.Asset.Domain)
	}
	return ""
}
