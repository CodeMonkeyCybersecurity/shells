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
// - Automatic conversion to Shells asset format

package discovery

import (
	"context"
	"fmt"
	"strconv"
	"strings"
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

// rumbleLoggerAdapter bridges *logger.Logger to the rumble.Logger interface
type rumbleLoggerAdapter struct {
	l *logger.Logger
}

func (a *rumbleLoggerAdapter) Info(msg string, keysAndValues ...interface{}) {
	if a.l != nil {
		a.l.Infow(msg, keysAndValues...)
	}
}

func (a *rumbleLoggerAdapter) Error(msg string, keysAndValues ...interface{}) {
	if a.l != nil {
		a.l.Errorw(msg, keysAndValues...)
	}
}

func (a *rumbleLoggerAdapter) Debug(msg string, keysAndValues ...interface{}) {
	if a.l != nil {
		a.l.Debugw(msg, keysAndValues...)
	}
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

	var rumbleLog rumble.Logger
	if log != nil {
		rumbleLog = &rumbleLoggerAdapter{l: log}
	}

	client := rumble.NewClient(rumbleConfig, rumbleLog)

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
func (m *RumbleModule) Discover(ctx context.Context, target *Target, session *DiscoverySession) (*DiscoveryResult, error) {
	if !m.enabled {
		m.logger.Debugw("Rumble module disabled - skipping")
		return nil, nil
	}

	if target == nil {
		return nil, fmt.Errorf("nil discovery target provided to rumble module")
	}

	targetValue := strings.TrimSpace(target.Value)
	sessionID := ""
	if session != nil {
		sessionID = session.ID
	}

	m.logger.Infow("Starting Rumble network discovery",
		"target", targetValue,
		"target_type", target.Type,
		"session_id", sessionID,
		"module", m.Name(),
	)

	start := time.Now()

	filters := map[string]string{}
	if targetValue != "" {
		filters["search"] = targetValue
	}

	rumbleAssets, err := m.client.GetAssets(ctx, filters)
	if err != nil {
		return nil, fmt.Errorf("rumble asset query failed: %w", err)
	}

	// Convert Rumble assets to Shells asset format
	assets := m.convertRumbleAssets(rumbleAssets)

	result := &DiscoveryResult{
		Source:        m.Name(),
		Assets:        assets,
		Relationships: []*Relationship{},
		Duration:      time.Since(start),
	}

	m.logger.Infow("Rumble discovery completed",
		"target", targetValue,
		"session_id", sessionID,
		"assets_discovered", len(assets),
		"duration", result.Duration.String(),
	)

	return result, nil
}

// convertRumbleAssets converts Rumble assets to Shells asset format
func (m *RumbleModule) convertRumbleAssets(rumbleAssets []rumble.Asset) []*Asset {
	var assets []*Asset

	for _, ra := range rumbleAssets {
		// Create asset for the host itself
		asset := &Asset{
			Type:         AssetTypeIP,
			Value:        ra.Address,
			Source:       "rumble",
			Confidence:   0.95, // Rumble provides high-confidence data
			DiscoveredAt: time.Now(),
			Metadata: map[string]string{
				"rumble_id":  ra.ID,
				"os":         ra.OS,
				"hostname":   ra.Hostname,
				"mac":        ra.NetworkInfo.MAC,
				"vendor":     ra.NetworkInfo.Vendor,
				"first_seen": ra.FirstSeen.Format(time.RFC3339),
				"last_seen":  ra.LastSeen.Format(time.RFC3339),
				"alive":      strconv.FormatBool(ra.Alive),
				"tags":       strings.Join(ra.Tags, ","),
			},
		}

		// Add hostname as separate asset if available
		if ra.Hostname != "" {
			assets = append(assets, &Asset{
				Type:         AssetTypeDomain,
				Value:        ra.Hostname,
				Source:       "rumble",
				Confidence:   0.9,
				DiscoveredAt: time.Now(),
				Metadata: map[string]string{
					"rumble_id":  ra.ID,
					"ip_address": ra.Address,
					"os":         ra.OS,
					"source":     "rumble_hostname",
				},
			})
		}

		// Add DNS names as separate assets
		for _, dnsName := range ra.NetworkInfo.DNSNames {
			assets = append(assets, &Asset{
				Type:         AssetTypeDomain,
				Value:        dnsName,
				Source:       "rumble",
				Confidence:   0.85,
				DiscoveredAt: time.Now(),
				Metadata: map[string]string{
					"rumble_id":  ra.ID,
					"ip_address": ra.Address,
					"source":     "rumble_dns",
				},
			})
		}

		// Convert services to assets
		for _, svc := range ra.Services {
			serviceAsset := &Asset{
				Type:         AssetTypeService,
				Value:        fmt.Sprintf("%s:%d/%s", ra.Address, svc.Port, svc.Protocol),
				Source:       "rumble",
				Confidence:   svc.Confidence,
				DiscoveredAt: time.Now(),
				Metadata: map[string]string{
					"port":      strconv.Itoa(svc.Port),
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
				serviceAsset.Metadata["cert_subject"] = svc.Certificate.Subject
				serviceAsset.Metadata["cert_issuer"] = svc.Certificate.Issuer
				serviceAsset.Metadata["cert_not_before"] = svc.Certificate.NotBefore.Format(time.RFC3339)
				serviceAsset.Metadata["cert_not_after"] = svc.Certificate.NotAfter.Format(time.RFC3339)
				serviceAsset.Metadata["cert_serial"] = svc.Certificate.SerialNumber
				serviceAsset.Metadata["cert_sans"] = strings.Join(svc.Certificate.SubjectAltName, ",")

				// Add SAN DNS names as separate domain assets
				for _, san := range svc.Certificate.SubjectAltName {
					assets = append(assets, &Asset{
						Type:         AssetTypeDomain,
						Value:        san,
						Source:       "rumble",
						Confidence:   0.8,
						DiscoveredAt: time.Now(),
						Metadata: map[string]string{
							"source":     "rumble_certificate_san",
							"ip_address": ra.Address,
							"port":       strconv.Itoa(svc.Port),
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

// CanHandle determines if this module should process the provided discovery target
func (m *RumbleModule) CanHandle(target *Target) bool {
	if !m.enabled || target == nil {
		return false
	}

	switch target.Type {
	case TargetTypeIP, TargetTypeIPRange, TargetTypeNetwork, TargetTypeDomain, TargetTypeSubdomain:
		return true
	default:
		return false
	}
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
