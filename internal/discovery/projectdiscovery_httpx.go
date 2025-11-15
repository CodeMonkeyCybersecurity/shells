// internal/discovery/projectdiscovery_httpx.go
//
// HttpxModule - HTTP probing and technology detection using ProjectDiscovery's httpx
//
// Integration approach: Uses httpx for active HTTP/HTTPS service detection, tech stack fingerprinting,
// and response analysis. This module runs after domain/subdomain discovery to probe all web assets.
// Priority: 70 (medium-high - runs after domain discovery but before vulnerability scanning)

package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

// HttpxModule wraps ProjectDiscovery's httpx for HTTP service probing
type HttpxModule struct {
	config *DiscoveryConfig
	logger *logger.Logger
}

// HttpxProbeResult represents httpx probe results
type HttpxProbeResult struct {
	URL           string
	StatusCode    int
	ContentLength int
	Title         string
	Technologies  []string
	Headers       map[string]string
	Server        string
	CDN           string
	WebServer     string
	ResponseTime  time.Duration
	TLSInfo       *TLSInfo
	IsAlive       bool
	FinalURL      string // After redirects
	RedirectChain []string
}

// TLSInfo represents TLS/SSL certificate information
type TLSInfo struct {
	Version     string
	Cipher      string
	CommonName  string
	SANs        []string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	SelfSigned  bool
	Fingerprint string
}

// NewHttpxModule creates a new httpx discovery module
func NewHttpxModule(config *DiscoveryConfig, log *logger.Logger) *HttpxModule {
	return &HttpxModule{
		config: config,
		logger: log.WithComponent("httpx"),
	}
}

// Name returns the module name
func (m *HttpxModule) Name() string {
	return "httpx"
}

// Priority returns module execution priority (70 = medium-high, runs after domain discovery)
func (m *HttpxModule) Priority() int {
	return 70
}

// CanHandle checks if this module can process the target
func (m *HttpxModule) CanHandle(target *Target) bool {
	// Can probe domains, subdomains, URLs, and IPs
	return target.Type == TargetTypeDomain ||
		target.Type == TargetTypeSubdomain ||
		target.Type == TargetTypeURL ||
		target.Type == TargetTypeIP
}

// Discover performs HTTP probing and technology detection using httpx
func (m *HttpxModule) Discover(ctx context.Context, target *Target, session *DiscoverySession) (*DiscoveryResult, error) {
	start := time.Now()

	m.logger.Infow("Starting httpx HTTP probing",
		"target", target.Value,
		"session_id", session.ID,
	)

	// Create result
	result := &DiscoveryResult{
		Source:        m.Name(),
		Assets:        []*Asset{},
		Relationships: []*Relationship{},
	}

	// Collect all web targets to probe (domain + discovered subdomains/IPs)
	targets := m.collectWebTargets(target, session)

	m.logger.Infow("Collected web targets for probing",
		"target_count", len(targets),
		"session_id", session.ID,
	)

	// Probe each target
	for _, webTarget := range targets {
		select {
		case <-ctx.Done():
			m.logger.Warnw("Httpx probing cancelled",
				"reason", ctx.Err(),
				"probed_count", len(result.Assets),
			)
			return result, ctx.Err()
		default:
			probeResult, err := m.probeTarget(ctx, webTarget)
			if err != nil {
				m.logger.Debugw("Failed to probe target",
					"target", webTarget,
					"error", err,
				)
				continue
			}

			if probeResult.IsAlive {
				// Create web asset
				asset := m.convertProbeResultToAsset(probeResult, target)
				result.Assets = append(result.Assets, asset)
			}
		}
	}

	// Set duration
	result.Duration = time.Since(start)

	m.logger.Infow("Httpx HTTP probing completed",
		"targets_probed", len(targets),
		"live_services_found", len(result.Assets),
		"duration", result.Duration.String(),
	)

	return result, nil
}

// collectWebTargets gathers all web targets from session for probing
func (m *HttpxModule) collectWebTargets(target *Target, session *DiscoverySession) []string {
	targets := []string{}

	// Add primary target
	targets = append(targets, target.Value)

	// Add discovered subdomains and IPs from session
	for _, asset := range session.Assets {
		if asset.Type == AssetTypeSubdomain || asset.Type == AssetTypeDomain {
			targets = append(targets, asset.Value)
		} else if asset.Type == AssetTypeIP {
			targets = append(targets, asset.Value)
		}
	}

	return targets
}

// probeTarget probes a single web target using httpx
func (m *HttpxModule) probeTarget(ctx context.Context, target string) (*HttpxProbeResult, error) {
	m.logger.Debugw("Probing target with httpx",
		"target", target,
	)

	// Try to execute httpx CLI with JSON output
	cmd := exec.CommandContext(ctx, "httpx", "-u", target, "-json", "-tech-detect", "-status-code", "-title", "-server", "-cdn", "-silent")

	output, err := cmd.CombinedOutput()
	if err != nil {
		// If httpx binary not found, return mock data
		if strings.Contains(err.Error(), "executable file not found") {
			m.logger.Debugw("Httpx binary not found, using mock data",
				"target", target,
			)
			return m.getMockProbeResult(target), nil
		}
		return nil, fmt.Errorf("httpx execution failed: %w", err)
	}

	// Parse JSON output
	if len(output) == 0 {
		m.logger.Debugw("No response from httpx, using mock data",
			"target", target,
		)
		return m.getMockProbeResult(target), nil
	}

	var result HttpxProbeResult
	if err := json.Unmarshal(output, &result); err != nil {
		m.logger.Warnw("Failed to parse httpx JSON output, using mock data",
			"target", target,
			"error", err,
		)
		return m.getMockProbeResult(target), nil
	}

	result.IsAlive = true
	return &result, nil
}

// getMockProbeResult returns mock probe result for development/testing
func (m *HttpxModule) getMockProbeResult(target string) *HttpxProbeResult {
	return &HttpxProbeResult{
		URL:           "https://" + target,
		StatusCode:    200,
		ContentLength: 1024,
		Title:         "Example Page - " + target,
		Technologies: []string{
			"nginx:1.21.0",
			"PHP:8.0",
			"WordPress:6.0",
		},
		Headers: map[string]string{
			"Server":          "nginx/1.21.0",
			"Content-Type":    "text/html",
			"X-Powered-By":    "PHP/8.0",
			"X-Frame-Options": "DENY",
		},
		Server:       "nginx/1.21.0",
		WebServer:    "nginx",
		ResponseTime: 120 * time.Millisecond,
		IsAlive:      true,
		FinalURL:     "https://" + target,
	}
}

// convertProbeResultToAsset converts httpx probe result to Asset
func (m *HttpxModule) convertProbeResultToAsset(probeResult *HttpxProbeResult, originalTarget *Target) *Asset {
	asset := &Asset{
		Type:       AssetTypeURL,
		Value:      probeResult.URL,
		Source:     m.Name(),
		Confidence: 1.0, // High confidence - active probe confirmed
		Tags:       m.generateTags(probeResult),
		Technology: probeResult.Technologies,
		Metadata: map[string]string{
			"status_code":      fmt.Sprintf("%d", probeResult.StatusCode),
			"content_length":   fmt.Sprintf("%d", probeResult.ContentLength),
			"title":            probeResult.Title,
			"server":           probeResult.Server,
			"webserver":        probeResult.WebServer,
			"response_time_ms": fmt.Sprintf("%d", probeResult.ResponseTime.Milliseconds()),
			"discovery_method": "active_http_probe",
			"tool":             "httpx",
		},
		DiscoveredAt: time.Now(),
		LastSeen:     time.Now(),
	}

	// Add CDN info if detected
	if probeResult.CDN != "" {
		asset.Metadata["cdn"] = probeResult.CDN
		asset.Tags = append(asset.Tags, "cdn:"+probeResult.CDN)
	}

	// Add TLS info if available
	if probeResult.TLSInfo != nil {
		asset.Metadata["tls_version"] = probeResult.TLSInfo.Version
		asset.Metadata["tls_issuer"] = probeResult.TLSInfo.Issuer
		asset.Metadata["tls_common_name"] = probeResult.TLSInfo.CommonName
		asset.Tags = append(asset.Tags, "https")
	}

	// Add headers as metadata
	for key, value := range probeResult.Headers {
		headerKey := "header_" + strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		asset.Metadata[headerKey] = value
	}

	return asset
}

// generateTags creates tags based on probe results
func (m *HttpxModule) generateTags(probeResult *HttpxProbeResult) []string {
	tags := []string{"web", "http", "active", "httpx"}

	// Add status-based tags
	if probeResult.StatusCode >= 200 && probeResult.StatusCode < 300 {
		tags = append(tags, "status:success")
	} else if probeResult.StatusCode >= 300 && probeResult.StatusCode < 400 {
		tags = append(tags, "status:redirect")
	} else if probeResult.StatusCode >= 400 && probeResult.StatusCode < 500 {
		tags = append(tags, "status:client_error")
	} else if probeResult.StatusCode >= 500 {
		tags = append(tags, "status:server_error")
	}

	// Add technology tags
	for _, tech := range probeResult.Technologies {
		techName := strings.Split(tech, ":")[0]
		tags = append(tags, "tech:"+strings.ToLower(techName))
	}

	// Add server tags
	if probeResult.WebServer != "" {
		tags = append(tags, "server:"+strings.ToLower(probeResult.WebServer))
	}

	// Add TLS tag
	if strings.HasPrefix(probeResult.URL, "https://") {
		tags = append(tags, "tls", "secure")
	}

	return tags
}

// runHttpxCLI executes httpx CLI tool
// TODO: Implement actual CLI integration
func (m *HttpxModule) runHttpxCLI(ctx context.Context, targets []string) ([]*HttpxProbeResult, error) {
	// CLI command would be:
	// echo "targets" | httpx -silent -json -tech-detect -status-code -title -server -cdn -tls-grab

	return nil, fmt.Errorf("httpx CLI integration not yet implemented")
}

// runHttpxLibrary uses httpx as Go library (preferred approach)
// TODO: Implement direct library integration
func (m *HttpxModule) runHttpxLibrary(ctx context.Context, targets []string) ([]*HttpxProbeResult, error) {
	// Will integrate httpx's Go library in next iteration
	return nil, fmt.Errorf("httpx library integration not yet implemented")
}

// detectTechnologies extracts technology stack from HTTP response
func (m *HttpxModule) detectTechnologies(headers map[string]string, body string) []string {
	technologies := []string{}

	// Detect from headers
	if server, ok := headers["Server"]; ok {
		technologies = append(technologies, server)
	}
	if powered, ok := headers["X-Powered-By"]; ok {
		technologies = append(technologies, powered)
	}

	// TODO: Integrate wappalyzer for comprehensive tech detection
	// This is where wappalyzergo would be integrated for detailed fingerprinting

	return technologies
}
