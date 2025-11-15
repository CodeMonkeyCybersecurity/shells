// pkg/integrations/rumble/client.go
package rumble

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// Client represents a runZero API client
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	logger     Logger
}

// Logger interface for logging
type Logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}

// Config holds runZero client configuration
type Config struct {
	APIKey     string
	BaseURL    string
	Timeout    time.Duration
	MaxRetries int
}

// NewClient creates a new runZero client
func NewClient(config Config, logger Logger) *Client {
	if config.BaseURL == "" {
		config.BaseURL = "https://console.runzero.com/api/v1.0"
	}

	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	return &Client{
		apiKey:  config.APIKey,
		baseURL: config.BaseURL,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		logger: logger,
	}
}

// Asset represents a discovered asset
type Asset struct {
	ID              string                 `json:"id"`
	Address         string                 `json:"address"`
	Hostname        string                 `json:"hostname"`
	OS              string                 `json:"os"`
	Services        []Service              `json:"services"`
	Attributes      map[string]interface{} `json:"attributes"`
	FirstSeen       time.Time              `json:"first_seen"`
	LastSeen        time.Time              `json:"last_seen"`
	Alive           bool                   `json:"alive"`
	Tags            []string               `json:"tags"`
	NetworkInfo     NetworkInfo            `json:"network_info"`
	Vulnerabilities []Vulnerability        `json:"vulnerabilities"`
}

// Service represents a discovered service
type Service struct {
	Port        int                    `json:"port"`
	Protocol    string                 `json:"protocol"`
	Service     string                 `json:"service"`
	Product     string                 `json:"product"`
	Version     string                 `json:"version"`
	Banner      string                 `json:"banner"`
	Confidence  float64                `json:"confidence"`
	Attributes  map[string]interface{} `json:"attributes"`
	Certificate *Certificate           `json:"certificate,omitempty"`
}

// NetworkInfo contains network-related information
type NetworkInfo struct {
	MAC          string   `json:"mac"`
	Vendor       string   `json:"vendor"`
	Hops         int      `json:"hops"`
	RTT          int      `json:"rtt"`
	VLAN         int      `json:"vlan"`
	DNSNames     []string `json:"dns_names"`
	NetBIOSNames []string `json:"netbios_names"`
}

// Certificate represents SSL certificate information
type Certificate struct {
	Subject        string    `json:"subject"`
	Issuer         string    `json:"issuer"`
	SerialNumber   string    `json:"serial_number"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	SignatureAlgo  string    `json:"signature_algorithm"`
	KeyAlgorithm   string    `json:"key_algorithm"`
	KeySize        int       `json:"key_size"`
	SubjectAltName []string  `json:"subject_alt_names"`
	Fingerprint    string    `json:"fingerprint"`
}

// Vulnerability represents a detected vulnerability
type Vulnerability struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	CVE         string   `json:"cve"`
	CVSS        float64  `json:"cvss"`
	Description string   `json:"description"`
	Solution    string   `json:"solution"`
	References  []string `json:"references"`
}

// ScanRequest represents a scan request
type ScanRequest struct {
	Targets  []string          `json:"targets"`
	ScanType string            `json:"scan_type"`
	Rate     int               `json:"rate"`
	Excludes []string          `json:"excludes"`
	Tags     []string          `json:"tags"`
	Options  map[string]string `json:"options"`
}

// ScanResponse represents a scan response
type ScanResponse struct {
	TaskID      string    `json:"task_id"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Progress    float64   `json:"progress"`
	AssetsFound int       `json:"assets_found"`
}

// CreateScan initiates a new scan
func (c *Client) CreateScan(ctx context.Context, req ScanRequest) (*ScanResponse, error) {
	c.logger.Info("Creating runZero scan", "targets", req.Targets)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/org/scans", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("scan creation failed: %s", string(body))
	}

	var scanResp ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &scanResp, nil
}

// GetScanStatus gets the status of a scan
func (c *Client) GetScanStatus(ctx context.Context, taskID string) (*ScanResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/org/scans/"+taskID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status check failed: %s", string(body))
	}

	var scanResp ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &scanResp, nil
}

// GetAssets retrieves discovered assets
func (c *Client) GetAssets(ctx context.Context, filters map[string]string) ([]Asset, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/org/assets", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add filters as query parameters
	q := req.URL.Query()
	for k, v := range filters {
		q.Add(k, v)
	}
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get assets failed: %s", string(body))
	}

	var assets []Asset
	if err := json.NewDecoder(resp.Body).Decode(&assets); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return assets, nil
}

// DiscoverNetwork performs network discovery
func (c *Client) DiscoverNetwork(ctx context.Context, cidr string) ([]Asset, error) {
	c.logger.Info("Starting network discovery", "cidr", cidr)

	// Create scan
	scanReq := ScanRequest{
		Targets:  []string{cidr},
		ScanType: "discovery",
		Rate:     1000, // packets per second
		Options: map[string]string{
			"scan_unresponsive": "true",
			"scan_speed":        "fast",
			"probe_types":       "icmp,tcp,udp",
		},
	}

	scan, err := c.CreateScan(ctx, scanReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}

	// Wait for completion
	assets, err := c.waitForScan(ctx, scan.TaskID)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	return assets, nil
}

// ServiceDiscovery performs detailed service discovery
func (c *Client) ServiceDiscovery(ctx context.Context, targets []string) ([]Asset, error) {
	c.logger.Info("Starting service discovery", "targets", targets)

	scanReq := ScanRequest{
		Targets:  targets,
		ScanType: "service",
		Rate:     500,
		Options: map[string]string{
			"scan_unresponsive":    "false",
			"scan_speed":           "normal",
			"service_probes":       "true",
			"screenshot_services":  "true",
			"extract_certificates": "true",
		},
	}

	scan, err := c.CreateScan(ctx, scanReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}

	assets, err := c.waitForScan(ctx, scan.TaskID)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	return assets, nil
}

// waitForScan waits for a scan to complete and returns assets
func (c *Client) waitForScan(ctx context.Context, taskID string) ([]Asset, error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			status, err := c.GetScanStatus(ctx, taskID)
			if err != nil {
				return nil, err
			}

			c.logger.Debug("Scan progress", "task_id", taskID, "progress", status.Progress)

			if status.Status == "completed" {
				// Get assets discovered in this scan
				filters := map[string]string{
					"search": fmt.Sprintf("task_id:%s", taskID),
				}
				return c.GetAssets(ctx, filters)
			} else if status.Status == "failed" || status.Status == "cancelled" {
				return nil, fmt.Errorf("scan %s: %s", status.Status, taskID)
			}
		}
	}
}

// ConvertToFindings converts runZero assets to standard findings
func ConvertToFindings(assets []Asset) []types.Finding {
	var findings []types.Finding

	for _, asset := range assets {
		// Base finding for the asset
		finding := types.Finding{
			Type:        "ASSET_DISCOVERED",
			Severity:    types.SeverityInfo,
			Title:       fmt.Sprintf("Asset Discovered: %s", asset.Address),
			Description: fmt.Sprintf("Discovered %s (%s) running %s", asset.Address, asset.Hostname, asset.OS),
			Metadata: map[string]interface{}{
				"hostname":     asset.Hostname,
				"os":           asset.OS,
				"first_seen":   asset.FirstSeen,
				"last_seen":    asset.LastSeen,
				"network_info": asset.NetworkInfo,
				"target":       asset.Address,
				"confidence":   "HIGH",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		findings = append(findings, finding)

		// Service findings
		for _, service := range asset.Services {
			severity := types.SeverityInfo
			if isHighRiskService(service) {
				severity = types.SeverityHigh
			} else if isMediumRiskService(service) {
				severity = types.SeverityMedium
			}

			serviceFinding := types.Finding{
				Type:     "SERVICE_EXPOSED",
				Severity: severity,
				Title:    fmt.Sprintf("Service Exposed: %s on %s:%d", service.Service, asset.Address, service.Port),
				Description: fmt.Sprintf("%s %s %s exposed on port %d",
					service.Service, service.Product, service.Version, service.Port),
				Metadata: map[string]interface{}{
					"service":    service.Service,
					"product":    service.Product,
					"version":    service.Version,
					"banner":     service.Banner,
					"protocol":   service.Protocol,
					"confidence": service.Confidence,
					"target":     fmt.Sprintf("%s:%d", asset.Address, service.Port),
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}

			// Add certificate findings
			if service.Certificate != nil {
				serviceFinding.Metadata["certificate"] = service.Certificate

				// Check for certificate issues
				if service.Certificate.NotAfter.Before(time.Now()) {
					certFinding := types.Finding{
						Type:        "CERTIFICATE_EXPIRED",
						Severity:    types.SeverityHigh,
						Title:       fmt.Sprintf("Expired Certificate on %s:%d", asset.Address, service.Port),
						Description: fmt.Sprintf("Certificate expired on %s", service.Certificate.NotAfter),
						Metadata: map[string]interface{}{
							"subject":      service.Certificate.Subject,
							"issuer":       service.Certificate.Issuer,
							"not_after":    service.Certificate.NotAfter,
							"expired_days": int(time.Since(service.Certificate.NotAfter).Hours() / 24),
							"target":       fmt.Sprintf("%s:%d", asset.Address, service.Port),
							"confidence":   "HIGH",
						},
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					}
					findings = append(findings, certFinding)
				}
			}

			findings = append(findings, serviceFinding)
		}

		// Vulnerability findings
		for _, vuln := range asset.Vulnerabilities {
			// Convert string severity to types.Severity
			var severity types.Severity
			switch strings.ToLower(vuln.Severity) {
			case "critical":
				severity = types.SeverityCritical
			case "high":
				severity = types.SeverityHigh
			case "medium":
				severity = types.SeverityMedium
			case "low":
				severity = types.SeverityLow
			default:
				severity = types.SeverityInfo
			}

			vulnFinding := types.Finding{
				Type:        "VULNERABILITY_DETECTED",
				Severity:    severity,
				Title:       fmt.Sprintf("%s on %s", vuln.Name, asset.Address),
				Description: vuln.Description,
				Solution:    vuln.Solution,
				References:  vuln.References,
				Metadata: map[string]interface{}{
					"cve":        vuln.CVE,
					"cvss":       vuln.CVSS,
					"target":     asset.Address,
					"confidence": "HIGH",
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			findings = append(findings, vulnFinding)
		}
	}

	return findings
}

// Helper functions
func isHighRiskService(service Service) bool {
	highRiskServices := []string{
		"telnet", "ftp", "vnc", "rdp", "smb", "netbios",
		"mysql", "postgresql", "mongodb", "redis", "elasticsearch",
		"docker", "kubernetes", "etcd",
	}

	for _, risk := range highRiskServices {
		if service.Service == risk {
			return true
		}
	}
	return false
}

func isMediumRiskService(service Service) bool {
	mediumRiskServices := []string{
		"ssh", "snmp", "ldap", "dns", "ntp", "smtp",
	}

	for _, risk := range mediumRiskServices {
		if service.Service == risk {
			return true
		}
	}
	return false
}
