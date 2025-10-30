// internal/orchestrator/scanners/idor.go
//
// IDOR Scanner - Insecure Direct Object Reference testing
//
// REFACTORING CONTEXT:
// Extracted from bounty_engine.go runIDORTests() (lines 3176-3353, ~177 lines)
// Tests for IDOR vulnerabilities: sequential IDs, UUID analysis, horizontal privilege escalation

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

// IDORScanner tests for Insecure Direct Object Reference vulnerabilities
type IDORScanner struct {
	scanner core.Scanner
	logger  *logger.Logger
	config  IDORConfig
}

// IDORConfig contains IDOR scanner configuration
type IDORConfig struct {
	MaxWorkers int
	Timeout    time.Duration
}

// NewIDORScanner creates a new IDOR scanner
func NewIDORScanner(scanner core.Scanner, logger *logger.Logger, config IDORConfig) *IDORScanner {
	if config.MaxWorkers == 0 {
		config.MaxWorkers = 10
	}
	if config.Timeout == 0 {
		config.Timeout = 2 * time.Minute
	}

	return &IDORScanner{
		scanner: scanner,
		logger:  logger.WithComponent("idor-scanner"),
		config:  config,
	}
}

// Name returns the scanner name
func (s *IDORScanner) Name() string {
	return "IDOR Scanner"
}

// Type returns the scanner type
func (s *IDORScanner) Type() string {
	return "access-control"
}

// Priority returns execution priority (4 = runs after auth and API)
func (s *IDORScanner) Priority() int {
	return 4
}

// CanHandle determines if this scanner can test the asset
func (s *IDORScanner) CanHandle(asset *AssetPriority) bool {
	// IDOR scanner can test any web asset with authenticated endpoints
	return asset.Asset.Type == "web" ||
		asset.Asset.Value != "" ||
		asset.Features.HasAuthentication
}

// Execute runs IDOR testing against prioritized assets
func (s *IDORScanner) Execute(ctx context.Context, assets []*AssetPriority) ([]types.Finding, error) {
	startTime := time.Now()
	var findings []types.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	s.logger.Infow("Starting IDOR vulnerability testing",
		"asset_count", len(assets),
	)

	// Worker pool for parallel testing
	semaphore := make(chan struct{}, s.config.MaxWorkers)

	// Test each asset for IDOR
	for _, asset := range assets {
		target := s.getTargetURL(asset)
		if target == "" {
			continue
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(targetURL string) {
			defer func() {
				if r := recover(); r != nil {
					s.logger.Errorw("IDOR scanner panicked",
						"url", targetURL,
						"panic", r,
					)
				}
				<-semaphore
				wg.Done()
			}()

			s.logger.Infow("Testing URL for IDOR vulnerabilities",
				"url", targetURL,
			)

			scanCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
			defer cancel()

			idorFindings, err := s.scanner.Scan(scanCtx, targetURL, nil)
			if err != nil {
				s.logger.Warnw("IDOR scan failed",
					"url", targetURL,
					"error", err,
				)
				return
			}

			mu.Lock()
			findings = append(findings, idorFindings...)
			mu.Unlock()

			s.logger.Infow("IDOR scan completed",
				"url", targetURL,
				"findings", len(idorFindings),
			)
		}(target)
	}

	wg.Wait()

	duration := time.Since(startTime)
	s.logger.Infow("IDOR testing completed",
		"total_findings", len(findings),
		"duration", duration.String(),
	)

	return findings, nil
}

// getTargetURL extracts URL from asset
func (s *IDORScanner) getTargetURL(asset *AssetPriority) string {
	if asset.Asset.Value != "" {
		return asset.Asset.Value
	}
	if asset.Asset.Domain != "" {
		return fmt.Sprintf("https://%s", asset.Asset.Domain)
	}
	if asset.Asset.IP != "" {
		return fmt.Sprintf("https://%s", asset.Asset.IP)
	}
	return ""
}
