// internal/discovery/projectdiscovery_katana.go
//
// KatanaModule - Deep web crawling using ProjectDiscovery's katana
//
// Integration approach: Uses katana for next-gen web crawling to discover endpoints, forms, APIs
// Priority: 60 (medium - runs after service discovery to crawl discovered web apps)

package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

// KatanaModule wraps ProjectDiscovery's katana for web crawling
type KatanaModule struct {
	config *DiscoveryConfig
	logger *logger.Logger
}

// CrawlResult represents katana crawl results
type CrawlResult struct {
	URL           string
	Endpoint      string
	Method        string // GET, POST, etc.
	StatusCode    int
	ContentType   string
	Parameters    []string
	Forms         []FormInfo
	APIEndpoints  []string
	JSFiles       []string
	Technologies  []string
	Depth         int
	Source        string // Link source
}

// FormInfo represents discovered forms
type FormInfo struct {
	Action     string
	Method     string
	Fields     []FormField
	HasFile    bool
	HasCaptcha bool
}

// FormField represents form input fields
type FormField struct {
	Name        string
	Type        string
	Required    bool
	Placeholder string
}

// NewKatanaModule creates a new katana discovery module
func NewKatanaModule(config *DiscoveryConfig, log *logger.Logger) *KatanaModule {
	return &KatanaModule{
		config: config,
		logger: log.WithComponent("katana"),
	}
}

// Name returns the module name
func (m *KatanaModule) Name() string {
	return "katana"
}

// Priority returns module execution priority (60 = medium, runs after service discovery)
func (m *KatanaModule) Priority() int {
	return 60
}

// CanHandle checks if this module can process the target
func (m *KatanaModule) CanHandle(target *Target) bool {
	return target.Type == TargetTypeURL ||
		target.Type == TargetTypeDomain ||
		target.Type == TargetTypeSubdomain
}

// Discover performs deep web crawling using katana
func (m *KatanaModule) Discover(ctx context.Context, target *Target, session *DiscoverySession) (*DiscoveryResult, error) {
	start := time.Now()

	m.logger.Infow("Starting katana web crawling",
		"target", target.Value,
		"max_depth", m.config.MaxDepth,
		"session_id", session.ID,
	)

	result := &DiscoveryResult{
		Source:        m.Name(),
		Assets:        []*Asset{},
		Relationships: []*Relationship{},
	}

	// Collect web targets to crawl
	webTargets := m.collectWebTargets(target, session)

	m.logger.Infow("Collected web targets for crawling",
		"target_count", len(webTargets),
	)

	// Crawl each target
	for _, webTarget := range webTargets {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
			crawlResults, err := m.crawlTarget(ctx, webTarget)
			if err != nil {
				m.logger.Debugw("Failed to crawl target",
					"target", webTarget,
					"error", err,
				)
				continue
			}

			// Convert crawl results to assets
			for _, crawlResult := range crawlResults {
				asset := m.convertCrawlResultToAsset(crawlResult, target)
				result.Assets = append(result.Assets, asset)
			}
		}
	}

	result.Duration = time.Since(start)

	m.logger.Infow("Katana web crawling completed",
		"targets_crawled", len(webTargets),
		"endpoints_discovered", len(result.Assets),
		"duration", result.Duration.String(),
	)

	return result, nil
}

// collectWebTargets gathers web targets from session
func (m *KatanaModule) collectWebTargets(target *Target, session *DiscoverySession) []string {
	targets := []string{}

	// Add web assets from session
	for _, asset := range session.Assets {
		if asset.Type == AssetTypeURL {
			targets = append(targets, asset.Value)
		} else if asset.Type == AssetTypeDomain || asset.Type == AssetTypeSubdomain {
			// Check if web service is alive (from httpx results)
			if m.hasLiveWebService(asset) {
				targets = append(targets, "https://"+asset.Value)
			}
		}
	}

	// If no web targets found, try primary target
	if len(targets) == 0 {
		if target.Type == TargetTypeURL {
			targets = append(targets, target.Value)
		} else {
			targets = append(targets, "https://"+target.Value)
		}
	}

	return targets
}

// hasLiveWebService checks if asset has a live web service (from httpx)
func (m *KatanaModule) hasLiveWebService(asset *Asset) bool {
	// Check if asset has web-related tags from httpx
	for _, tag := range asset.Tags {
		if tag == "web" || tag == "http" || tag == "httpx" {
			return true
		}
	}
	return false
}

// crawlTarget crawls a single web target
func (m *KatanaModule) crawlTarget(ctx context.Context, url string) ([]*CrawlResult, error) {
	// TODO: Implement actual katana integration

	m.logger.Debugw("Crawling target (mock implementation)",
		"url", url,
		"note", "Will integrate katana Go library in next iteration",
	)

	// Mock crawl results
	mockResults := []*CrawlResult{
		{
			URL:          url + "/api/v1/users",
			Endpoint:     "/api/v1/users",
			Method:       "GET",
			StatusCode:   200,
			ContentType:  "application/json",
			APIEndpoints: []string{"/api/v1/users", "/api/v1/auth"},
			Depth:        1,
		},
		{
			URL:        url + "/login",
			Endpoint:   "/login",
			Method:     "GET",
			StatusCode: 200,
			Forms: []FormInfo{
				{
					Action: "/auth/login",
					Method: "POST",
					Fields: []FormField{
						{Name: "username", Type: "text", Required: true},
						{Name: "password", Type: "password", Required: true},
					},
				},
			},
			Depth: 1,
		},
	}

	return mockResults, nil
}

// convertCrawlResultToAsset converts katana crawl result to Asset
func (m *KatanaModule) convertCrawlResultToAsset(crawlResult *CrawlResult, originalTarget *Target) *Asset {
	assetType := m.determineAssetType(crawlResult)

	asset := &Asset{
		Type:       assetType,
		Value:      crawlResult.URL,
		Source:     m.Name(),
		Confidence: 0.95, // High confidence - directly crawled
		Tags:       m.generateTags(crawlResult),
		Technology: crawlResult.Technologies,
		Metadata: map[string]string{
			"endpoint":         crawlResult.Endpoint,
			"http_method":      crawlResult.Method,
			"status_code":      fmt.Sprintf("%d", crawlResult.StatusCode),
			"content_type":     crawlResult.ContentType,
			"crawl_depth":      fmt.Sprintf("%d", crawlResult.Depth),
			"discovery_method": "web_crawling",
			"tool":             "katana",
		},
		DiscoveredAt: time.Now(),
		LastSeen:     time.Now(),
	}

	// Add form info
	if len(crawlResult.Forms) > 0 {
		asset.Metadata["has_forms"] = "true"
		asset.Metadata["form_count"] = fmt.Sprintf("%d", len(crawlResult.Forms))
		asset.Tags = append(asset.Tags, "form")
	}

	// Add API info
	if len(crawlResult.APIEndpoints) > 0 {
		asset.Metadata["has_api"] = "true"
		asset.Metadata["api_count"] = fmt.Sprintf("%d", len(crawlResult.APIEndpoints))
		asset.Tags = append(asset.Tags, "api")
	}

	return asset
}

// determineAssetType determines asset type from crawl result
func (m *KatanaModule) determineAssetType(crawlResult *CrawlResult) AssetType {
	// Check if API endpoint
	if strings.Contains(crawlResult.Endpoint, "/api/") ||
		strings.Contains(crawlResult.ContentType, "application/json") {
		return AssetTypeAPI
	}

	// Check if has forms (likely login/registration)
	if len(crawlResult.Forms) > 0 {
		for _, form := range crawlResult.Forms {
			if strings.Contains(strings.ToLower(form.Action), "login") ||
				strings.Contains(strings.ToLower(form.Action), "auth") {
				return AssetTypeURL // Login pages are high-value URLs
			}
		}
	}

	return AssetTypeURL
}

// generateTags creates tags based on crawl results
func (m *KatanaModule) generateTags(crawlResult *CrawlResult) []string {
	tags := []string{"web", "crawled", "katana"}

	// Add endpoint type tags
	endpoint := strings.ToLower(crawlResult.Endpoint)
	if strings.Contains(endpoint, "/api/") {
		tags = append(tags, "api", "endpoint")
	}
	if strings.Contains(endpoint, "/login") || strings.Contains(endpoint, "/auth") {
		tags = append(tags, "auth", "login")
	}
	if strings.Contains(endpoint, "/admin") {
		tags = append(tags, "admin", "privileged")
	}
	if strings.Contains(endpoint, "/upload") {
		tags = append(tags, "upload", "file_upload")
	}

	// Add form tags
	if len(crawlResult.Forms) > 0 {
		tags = append(tags, "form")
		for _, form := range crawlResult.Forms {
			if form.HasFile {
				tags = append(tags, "file_upload")
			}
		}
	}

	// Add method tags
	if crawlResult.Method != "" {
		tags = append(tags, "method:"+strings.ToLower(crawlResult.Method))
	}

	return tags
}

// runKatanaCLI executes katana CLI tool
// TODO: Implement actual CLI integration
// Example: katana -u <url> -d <depth> -jc -json -form -api
func (m *KatanaModule) runKatanaCLI(ctx context.Context, urls []string) ([]*CrawlResult, error) {
	return nil, fmt.Errorf("katana CLI integration not yet implemented")
}
