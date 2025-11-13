// internal/orchestrator/scanners/nuclei.go
//
// Nuclei Scanner - CVE and misconfiguration detection
//
// REFACTORING CONTEXT:
// Extracted from bounty_engine.go runNucleiScans() (lines 2938-3067, ~129 lines)
// Runs Nuclei vulnerability templates against discovered web assets

package scanners

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/core"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// NucleiScanner runs Nuclei vulnerability templates
type NucleiScanner struct {
	scanner core.Scanner
	logger  *logger.Logger
	config  NucleiConfig
}

// NucleiConfig contains Nuclei scanner configuration
type NucleiConfig struct {
	MaxWorkers int
	Timeout    time.Duration
}

// NewNucleiScanner creates a new Nuclei scanner
func NewNucleiScanner(scanner core.Scanner, logger *logger.Logger, config NucleiConfig) *NucleiScanner {
	if config.MaxWorkers == 0 {
		config.MaxWorkers = 10
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Minute
	}

	return &NucleiScanner{
		scanner: scanner,
		logger:  logger.WithComponent("nuclei-scanner"),
		config:  config,
	}
}

// Name returns the scanner name
func (s *NucleiScanner) Name() string {
	return "Nuclei Scanner"
}

// Type returns the scanner type
func (s *NucleiScanner) Type() string {
	return "infrastructure"
}

// Priority returns execution priority (1 = runs early with infrastructure)
func (s *NucleiScanner) Priority() int {
	return 1
}

// CanHandle determines if this scanner can test the asset
func (s *NucleiScanner) CanHandle(asset *AssetPriority) bool {
	// Nuclei can scan any web asset
	return asset.Asset.Type == "web" || asset.Asset.Value != "" || asset.Asset.Domain != ""
}

// Execute runs Nuclei scanning against prioritized assets
func (s *NucleiScanner) Execute(ctx context.Context, assets []*AssetPriority) ([]types.Finding, error) {
	startTime := time.Now()
	var findings []types.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	s.logger.Infow("Starting Nuclei vulnerability scanning",
		"asset_count", len(assets),
	)

	// Worker pool for parallel scanning
	semaphore := make(chan struct{}, s.config.MaxWorkers)

	// Scan each web asset
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
					s.logger.Errorw("Nuclei scanner panicked",
						"url", targetURL,
						"panic", r,
					)
				}
				<-semaphore
				wg.Done()
			}()

			s.logger.Infow("Scanning URL with Nuclei",
				"url", targetURL,
			)

			scanCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
			defer cancel()

			nucleiFindings, err := s.scanner.Scan(scanCtx, targetURL, nil)
			if err != nil {
				s.logger.Warnw("Nuclei scan failed",
					"url", targetURL,
					"error", err,
				)
				return
			}

			mu.Lock()
			findings = append(findings, nucleiFindings...)
			mu.Unlock()

			s.logger.Infow("Nuclei scan completed",
				"url", targetURL,
				"findings", len(nucleiFindings),
			)
		}(target)
	}

	wg.Wait()

	duration := time.Since(startTime)
	s.logger.Infow("Nuclei scanning completed",
		"total_findings", len(findings),
		"duration", duration.String(),
	)

	return findings, nil
}

// getTargetURL extracts URL from asset
func (s *NucleiScanner) getTargetURL(asset *AssetPriority) string {
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
