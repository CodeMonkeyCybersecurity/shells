// internal/orchestrator/scanners/nmap.go
//
// Nmap Scanner - Port scanning and service fingerprinting
//
// REFACTORING CONTEXT:
// Extracted from bounty_engine.go runNmapScans() (lines 2789-2937, ~148 lines)
// Performs port scanning and service version detection on discovered assets

package scanners

import (
	"context"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/core"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// NmapScanner performs port scanning and service fingerprinting
type NmapScanner struct {
	scanner core.Scanner
	logger  *logger.Logger
	config  NmapConfig
}

// NmapConfig contains Nmap scanner configuration
type NmapConfig struct {
	MaxWorkers int
	Timeout    time.Duration
}

// NewNmapScanner creates a new Nmap scanner
func NewNmapScanner(scanner core.Scanner, logger *logger.Logger, config NmapConfig) *NmapScanner {
	if config.MaxWorkers == 0 {
		config.MaxWorkers = 10
	}
	if config.Timeout == 0 {
		config.Timeout = 2 * time.Minute
	}

	return &NmapScanner{
		scanner: scanner,
		logger:  logger.WithComponent("nmap-scanner"),
		config:  config,
	}
}

// Name returns the scanner name
func (s *NmapScanner) Name() string {
	return "Nmap Scanner"
}

// Type returns the scanner type
func (s *NmapScanner) Type() string {
	return "infrastructure"
}

// Priority returns execution priority (1 = runs first)
func (s *NmapScanner) Priority() int {
	return 1 // Infrastructure scanning should run first
}

// CanHandle determines if this scanner can test the asset
func (s *NmapScanner) CanHandle(asset *AssetPriority) bool {
	// Nmap can scan any asset with IP or domain
	return asset.Asset.IP != "" || asset.Asset.Domain != ""
}

// Execute runs Nmap scanning against prioritized assets
func (s *NmapScanner) Execute(ctx context.Context, assets []*AssetPriority) ([]types.Finding, error) {
	startTime := time.Now()
	var findings []types.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	s.logger.Infow("Starting Nmap port scanning",
		"asset_count", len(assets),
	)

	// Worker pool for parallel scanning
	semaphore := make(chan struct{}, s.config.MaxWorkers)

	// Scan each asset
	for _, asset := range assets {
		target := s.getTarget(asset)
		if target == "" {
			continue
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(targetHost string) {
			defer func() {
				if r := recover(); r != nil {
					s.logger.Errorw("Nmap scanner panicked",
						"target", targetHost,
						"panic", r,
					)
				}
				<-semaphore
				wg.Done()
			}()

			s.logger.Infow("Scanning target with Nmap",
				"target", targetHost,
			)

			scanCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
			defer cancel()

			nmapFindings, err := s.scanner.Scan(scanCtx, targetHost, nil)
			if err != nil {
				s.logger.Warnw("Nmap scan failed",
					"target", targetHost,
					"error", err,
				)
				return
			}

			mu.Lock()
			findings = append(findings, nmapFindings...)
			mu.Unlock()

			s.logger.Infow("Nmap scan completed",
				"target", targetHost,
				"findings", len(nmapFindings),
			)
		}(target)
	}

	wg.Wait()

	duration := time.Since(startTime)
	s.logger.Infow("Nmap scanning completed",
		"total_findings", len(findings),
		"duration", duration.String(),
	)

	return findings, nil
}

// getTarget extracts target (IP or domain) from asset
func (s *NmapScanner) getTarget(asset *AssetPriority) string {
	if asset.Asset.IP != "" {
		return asset.Asset.IP
	}
	if asset.Asset.Domain != "" {
		return asset.Asset.Domain
	}
	return ""
}
