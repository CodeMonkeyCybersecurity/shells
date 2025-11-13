// pkg/integrations/rumble/scanner.go
package rumble

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// Scanner implements the rumble scanner for shells
type Scanner struct {
	client *Client
	config ScannerConfig
	logger Logger
}

// ScannerConfig holds scanner configuration
type ScannerConfig struct {
	APIKey         string
	ScanRate       int
	Timeout        time.Duration
	MaxConcurrency int
	EnableVulnScan bool
	DeepScan       bool
}

// NewScanner creates a new rumble scanner
func NewScanner(config ScannerConfig, logger Logger) (*Scanner, error) {
	if config.APIKey == "" {
		return nil, fmt.Errorf("rumble API key is required")
	}

	clientConfig := Config{
		APIKey:  config.APIKey,
		Timeout: config.Timeout,
	}

	client := NewClient(clientConfig, logger)

	return &Scanner{
		client: client,
		config: config,
		logger: logger,
	}, nil
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return "rumble"
}

// Type returns the scan type
func (s *Scanner) Type() types.ScanType {
	return types.ScanType("asset_discovery")
}

// Validate validates the target
func (s *Scanner) Validate(target string) error {
	// Check if it's a valid IP, CIDR, or hostname
	if net.ParseIP(target) != nil {
		return nil
	}

	if _, _, err := net.ParseCIDR(target); err == nil {
		return nil
	}

	// Basic hostname validation
	if len(target) > 0 && len(target) < 256 {
		return nil
	}

	return fmt.Errorf("invalid target format: %s", target)
}

// Scan performs the asset discovery scan
func (s *Scanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	s.logger.Info("Starting rumble scan", "target", target)

	// Determine scan type based on target
	var assets []Asset
	var err error

	if _, _, cidrErr := net.ParseCIDR(target); cidrErr == nil {
		// Network discovery for CIDR
		assets, err = s.client.DiscoverNetwork(ctx, target)
	} else {
		// Service discovery for single target
		assets, err = s.client.ServiceDiscovery(ctx, []string{target})
	}

	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// Convert to findings
	findings := ConvertToFindings(assets)

	// Perform additional analysis
	findings = append(findings, s.analyzeAssets(assets)...)

	// If deep scan is enabled, perform additional enumeration
	if s.config.DeepScan {
		deepFindings, err := s.performDeepScan(ctx, assets)
		if err != nil {
			s.logger.Error("Deep scan failed", "error", err)
		} else {
			findings = append(findings, deepFindings...)
		}
	}

	s.logger.Info("rumble scan completed",
		"target", target,
		"assets_found", len(assets),
		"findings", len(findings))

	return findings, nil
}

// analyzeAssets performs additional analysis on discovered assets
func (s *Scanner) analyzeAssets(assets []Asset) []types.Finding {
	var findings []types.Finding

	// Network segmentation analysis
	subnets := make(map[string][]Asset)
	for _, asset := range assets {
		if ip := net.ParseIP(asset.Address); ip != nil {
			subnet := getSubnet(ip)
			subnets[subnet] = append(subnets[subnet], asset)
		}
	}

	// Check for segmentation issues
	for subnet, subnetAssets := range subnets {
		services := make(map[string]int)
		for _, asset := range subnetAssets {
			for _, service := range asset.Services {
				services[service.Service]++
			}
		}

		// Check for mixed services in same subnet
		if hasMixedServices(services) {
			finding := types.Finding{
				Tool:        "rumble",
				Type:        "NETWORK_SEGMENTATION_ISSUE",
				Severity:    types.SeverityMedium,
				Title:       fmt.Sprintf("Poor Network Segmentation in %s", subnet),
				Description: "Multiple service types found in same network segment, indicating poor segmentation",
				Solution:    "Implement proper network segmentation with VLANs or subnets to isolate different service types",
				Metadata: map[string]interface{}{
					"subnet":        subnet,
					"asset_count":   len(subnetAssets),
					"service_types": services,
					"target":        subnet,
					"confidence":    "MEDIUM",
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for outdated services
	for _, asset := range assets {
		for _, service := range asset.Services {
			if isOutdated(service) {
				finding := types.Finding{
					Tool:        "rumble",
					Type:        "OUTDATED_SERVICE",
					Severity:    types.SeverityMedium,
					Title:       fmt.Sprintf("Outdated %s on %s", service.Product, asset.Address),
					Description: fmt.Sprintf("Running outdated version %s of %s", service.Version, service.Product),
					Solution:    "Update the service to the latest stable version to address known security vulnerabilities",
					Metadata: map[string]interface{}{
						"product":    service.Product,
						"version":    service.Version,
						"service":    service.Service,
						"target":     fmt.Sprintf("%s:%d", asset.Address, service.Port),
						"confidence": "HIGH",
					},
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	// Mass service exposure check
	serviceCount := make(map[string]int)
	for _, asset := range assets {
		for _, service := range asset.Services {
			key := fmt.Sprintf("%s:%d", service.Service, service.Port)
			serviceCount[key]++
		}
	}

	for service, count := range serviceCount {
		if count > 10 { // Threshold for mass exposure
			finding := types.Finding{
				Tool:        "rumble",
				Type:        "MASS_SERVICE_EXPOSURE",
				Severity:    types.SeverityHigh,
				Title:       fmt.Sprintf("Mass Exposure of %s", service),
				Description: fmt.Sprintf("%d instances of %s exposed across network", count, service),
				Solution:    "Review exposed services and implement proper network segmentation and access controls",
				Metadata: map[string]interface{}{
					"service":    service,
					"count":      count,
					"target":     "network-wide",
					"confidence": "HIGH",
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// performDeepScan performs additional deep scanning
func (s *Scanner) performDeepScan(ctx context.Context, assets []Asset) ([]types.Finding, error) {
	var findings []types.Finding

	// Group assets by service type for targeted scanning
	serviceGroups := make(map[string][]Asset)
	for _, asset := range assets {
		for _, service := range asset.Services {
			serviceGroups[service.Service] = append(serviceGroups[service.Service], asset)
		}
	}

	// Perform service-specific deep scans
	for service, serviceAssets := range serviceGroups {
		switch service {
		case "http", "https":
			webFindings := s.deepScanWeb(ctx, serviceAssets)
			findings = append(findings, webFindings...)
		case "ssh":
			sshFindings := s.deepScanSSH(ctx, serviceAssets)
			findings = append(findings, sshFindings...)
		case "smb", "netbios":
			smbFindings := s.deepScanSMB(ctx, serviceAssets)
			findings = append(findings, smbFindings...)
		}
	}

	return findings, nil
}

// deepScanWeb performs deep scanning of web services
func (s *Scanner) deepScanWeb(ctx context.Context, assets []Asset) []types.Finding {
	var findings []types.Finding

	for _, asset := range assets {
		for _, service := range asset.Services {
			if service.Service == "http" || service.Service == "https" {
				// Check for common misconfigurations
				if service.Banner != "" && containsServerInfo(service.Banner) {
					finding := types.Finding{
						Tool:        "rumble",
						Type:        "INFORMATION_DISCLOSURE",
						Severity:    types.SeverityLow,
						Title:       fmt.Sprintf("Server Version Disclosure on %s:%d", asset.Address, service.Port),
						Description: "Web server banner discloses version information",
						Solution:    "Configure web server to hide version information in HTTP headers and error pages",
						Evidence:    service.Banner,
						Metadata: map[string]interface{}{
							"banner":     service.Banner,
							"target":     fmt.Sprintf("%s:%d", asset.Address, service.Port),
							"confidence": "HIGH",
						},
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// deepScanSSH performs deep scanning of SSH services
func (s *Scanner) deepScanSSH(ctx context.Context, assets []Asset) []types.Finding {
	var findings []types.Finding

	for _, asset := range assets {
		for _, service := range asset.Services {
			if service.Service == "ssh" {
				// Check SSH version
				if service.Version != "" && isOldSSH(service.Version) {
					finding := types.Finding{
						Tool:        "rumble",
						Type:        "OUTDATED_SSH",
						Severity:    types.SeverityMedium,
						Title:       fmt.Sprintf("Outdated SSH Version on %s", asset.Address),
						Description: fmt.Sprintf("SSH server running outdated version: %s", service.Version),
						Solution:    "Update OpenSSH to the latest stable version to address known security vulnerabilities",
						Evidence:    service.Version,
						Metadata: map[string]interface{}{
							"version":    service.Version,
							"target":     fmt.Sprintf("%s:%d", asset.Address, service.Port),
							"confidence": "HIGH",
						},
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// deepScanSMB performs deep scanning of SMB services
func (s *Scanner) deepScanSMB(ctx context.Context, assets []Asset) []types.Finding {
	var findings []types.Finding

	for _, asset := range assets {
		for _, service := range asset.Services {
			if service.Service == "smb" || service.Service == "netbios" {
				finding := types.Finding{
					Tool:        "rumble",
					Type:        "SMB_EXPOSED",
					Severity:    types.SeverityHigh,
					Title:       fmt.Sprintf("SMB Service Exposed on %s", asset.Address),
					Description: "SMB/NetBIOS service exposed to network",
					Solution:    "Restrict SMB access to internal networks only and disable if not needed",
					Metadata: map[string]interface{}{
						"service":    service.Service,
						"port":       service.Port,
						"target":     fmt.Sprintf("%s:%d", asset.Address, service.Port),
						"confidence": "HIGH",
					},
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// Helper functions
func getSubnet(ip net.IP) string {
	// Get /24 subnet
	ip = ip.To4()
	if ip == nil {
		return "unknown"
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
}

func hasMixedServices(services map[string]int) bool {
	hasDatabase := false
	hasWeb := false
	hasAdmin := false

	for service := range services {
		switch service {
		case "mysql", "postgresql", "mongodb", "redis", "elasticsearch":
			hasDatabase = true
		case "http", "https":
			hasWeb = true
		case "ssh", "rdp", "vnc":
			hasAdmin = true
		}
	}

	// Mixed services indicate poor segmentation
	count := 0
	if hasDatabase {
		count++
	}
	if hasWeb {
		count++
	}
	if hasAdmin {
		count++
	}

	return count > 1
}

func isOutdated(service Service) bool {
	// Check for known outdated versions
	outdatedVersions := map[string][]string{
		"Apache":  {"2.2.", "2.0.", "1."},
		"nginx":   {"1.0.", "1.1.", "1.2.", "1.3.", "1.4.", "1.5.", "1.6.", "1.7.", "1.8.", "1.9.", "1.10.", "1.11.", "1.12.", "1.13.", "1.14."},
		"OpenSSH": {"4.", "5.", "6."},
		"PHP":     {"5.", "7.0", "7.1", "7.2"},
	}

	for product, versions := range outdatedVersions {
		if strings.Contains(service.Product, product) {
			for _, oldVersion := range versions {
				if strings.HasPrefix(service.Version, oldVersion) {
					return true
				}
			}
		}
	}

	return false
}

func containsServerInfo(banner string) bool {
	serverTokens := []string{
		"Apache/", "nginx/", "IIS/", "PHP/",
		"OpenSSL/", "mod_", "Ubuntu", "Debian",
	}

	banner = strings.ToLower(banner)
	for _, token := range serverTokens {
		if strings.Contains(banner, strings.ToLower(token)) {
			return true
		}
	}

	return false
}

func isOldSSH(version string) bool {
	oldVersions := []string{"4.", "5.", "6."}
	for _, old := range oldVersions {
		if strings.HasPrefix(version, "OpenSSH_"+old) {
			return true
		}
	}
	return false
}
