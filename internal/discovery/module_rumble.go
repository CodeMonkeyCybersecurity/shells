// internal/discovery/module_rumble.go
//
// Rumble.run (runZero) Integration Module for Asset Discovery
//
// INTEGRATION: Wires Rumble network discovery into Phase 1 (Asset Discovery)
// ENABLED: When rumble.enabled = true and rumble.api_key is configured
//
// This module provides enterprise-grade network discovery capabilities:
// - Unauthenticated asset discovery across network ranges
// - Service fingerprinting and version detection
// - Operating system identification
// - Certificate extraction and analysis
// - Network topology mapping
// - Automatic conversion to Artemis asset format

package discovery

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/integrations/rumble"
)

// RumbleModule integrates Rumble network discovery
type RumbleModule struct {
	client  *rumble.Client
	logger  *logger.Logger
	enabled bool
}

// RumbleConfig contains Rumble integration configuration
type RumbleConfig struct {
	Enabled    bool
	APIKey     string
	BaseURL    string
	Timeout    time.Duration
	MaxRetries int
	ScanRate   int  // Packets per second
	DeepScan   bool // Enable deep scanning
}

// NewRumbleModule creates a new Rumble discovery module
func NewRumbleModule(config RumbleConfig, log *logger.Logger) *RumbleModule {
	if !config.Enabled || config.APIKey == "" {
		return &RumbleModule{
			enabled: false,
			logger:  log,
		}
	}

	rumbleConfig := rumble.Config{
		APIKey:     config.APIKey,
		BaseURL:    config.BaseURL,
		Timeout:    config.Timeout,
		MaxRetries: config.MaxRetries,
	}

	client := rumble.NewClient(rumbleConfig, log)

	log.Infow("Rumble discovery module initialized",
		"enabled", true,
		"base_url", config.BaseURL,
	)

	return &RumbleModule{
		client:  client,
		logger:  log,
		enabled: true,
	}
}

// Name returns the module name
func (m *RumbleModule) Name() string {
	return "RumbleDiscovery"
}

// IsEnabled returns whether the module is enabled
func (m *RumbleModule) IsEnabled() bool {
	return m.enabled
}

// Discover performs Rumble-based asset discovery
func (m *RumbleModule) Discover(ctx context.Context, target string) ([]*Asset, error) {
	if !m.enabled {
		m.logger.Debugw("Rumble module disabled - skipping")
		return nil, nil
	}

	m.logger.Infow("Starting Rumble network discovery",
		"target", target,
		"module", m.Name(),
	)

	start := time.Now()

	// Query Rumble for assets in the target range
	rumbleAssets, err := m.client.QueryAssets(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("rumble asset query failed: %w", err)
	}

	// Convert Rumble assets to Artemis asset format
	assets := m.convertRumbleAssets(rumbleAssets)

	duration := time.Since(start)
	m.logger.Infow("Rumble discovery completed",
		"target", target,
		"assets_discovered", len(assets),
		"duration", duration.String(),
	)

	return assets, nil
}

// convertRumbleAssets converts Rumble assets to Artemis asset format
func (m *RumbleModule) convertRumbleAssets(rumbleAssets []rumble.Asset) []*Asset {
	var assets []*Asset

	for _, ra := range rumbleAssets {
		// Create asset for the host itself
		asset := &Asset{
			Type:        AssetTypeIPAddress,
			Value:       ra.Address,
			Source:      "rumble",
			Confidence:  95, // Rumble provides high-confidence data
			DiscoveredAt: time.Now(),
			Metadata: map[string]interface{}{
				"rumble_id":   ra.ID,
				"os":          ra.OS,
				"hostname":    ra.Hostname,
				"mac":         ra.NetworkInfo.MAC,
				"vendor":      ra.NetworkInfo.Vendor,
				"first_seen":  ra.FirstSeen,
				"last_seen":   ra.LastSeen,
				"alive":       ra.Alive,
				"tags":        ra.Tags,
			},
		}

		// Add hostname as separate asset if available
		if ra.Hostname != "" {
			assets = append(assets, &Asset{
				Type:        AssetTypeDomain,
				Value:       ra.Hostname,
				Source:      "rumble",
				Confidence:  90,
				DiscoveredAt: time.Now(),
				Metadata: map[string]interface{}{
					"rumble_id":       ra.ID,
					"ip_address":      ra.Address,
					"os":              ra.OS,
					"source":          "rumble_hostname",
				},
			})
		}

		// Add DNS names as separate assets
		for _, dnsName := range ra.NetworkInfo.DNSNames {
			assets = append(assets, &Asset{
				Type:        AssetTypeDomain,
				Value:       dnsName,
				Source:      "rumble",
				Confidence:  85,
				DiscoveredAt: time.Now(),
				Metadata: map[string]interface{}{
					"rumble_id":       ra.ID,
					"ip_address":      ra.Address,
					"source":          "rumble_dns",
				},
			})
		}

		// Convert services to assets
		for _, svc := range ra.Services {
			serviceAsset := &Asset{
				Type:        AssetTypeService,
				Value:       fmt.Sprintf("%s:%d/%s", ra.Address, svc.Port, svc.Protocol),
				Source:      "rumble",
				Confidence:  int(svc.Confidence),
				DiscoveredAt: time.Now(),
				Metadata: map[string]interface{}{
					"port":      svc.Port,
					"protocol":  svc.Protocol,
					"service":   svc.Service,
					"product":   svc.Product,
					"version":   svc.Version,
					"banner":    svc.Banner,
					"rumble_id": ra.ID,
				},
			}

			// Add certificate information if available
			if svc.Certificate != nil {
				serviceAsset.Metadata["certificate"] = map[string]interface{}{
					"subject":       svc.Certificate.Subject,
					"issuer":        svc.Certificate.Issuer,
					"not_before":    svc.Certificate.NotBefore,
					"not_after":     svc.Certificate.NotAfter,
					"serial_number": svc.Certificate.SerialNumber,
					"san_dns":       svc.Certificate.SANs,
				}

				// Add SAN DNS names as separate domain assets
				for _, san := range svc.Certificate.SANs {
					assets = append(assets, &Asset{
						Type:        AssetTypeDomain,
						Value:       san,
						Source:      "rumble",
						Confidence:  80,
						DiscoveredAt: time.Now(),
						Metadata: map[string]interface{}{
							"source":     "rumble_certificate_san",
							"ip_address": ra.Address,
							"port":       svc.Port,
							"rumble_id":  ra.ID,
						},
					})
				}
			}

			assets = append(assets, serviceAsset)
		}

		// Add the primary asset
		assets = append(assets, asset)
	}

	return assets
}

// Priority returns the module's execution priority (lower = earlier)
// Rumble runs early in discovery for comprehensive network visibility
func (m *RumbleModule) Priority() int {
	return 20 // Run after basic DNS but before deep enumeration
}

// ShouldRun determines if this module should run for a given target
func (m *RumbleModule) ShouldRun(target string) bool {
	if !m.enabled {
		return false
	}

	// Rumble is optimized for network ranges
	// Run for IP addresses, IP ranges, and domains
	return true
}
