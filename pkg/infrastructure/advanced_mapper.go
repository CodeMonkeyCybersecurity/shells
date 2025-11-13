package infrastructure

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

// AdvancedInfrastructureMapper provides comprehensive infrastructure discovery
type AdvancedInfrastructureMapper struct {
	logger         *logger.Logger
	config         *DiscoveryConfig
	dnsResolver    *DNSResolver
	portScanner    *PortScanner
	sslAnalyzer    *SSLAnalyzer
	cloudDetectors map[CloudProvider]CloudDetector
	cdnDetector    *CDNDetector
	asnAnalyzer    *ASNAnalyzer
	techDetector   *TechDetector
	threatIntel    *ThreatIntelCollector
	assetGraph     *AssetGraph
	cache          *DiscoveryCache
}

// NewAdvancedInfrastructureMapper creates a new infrastructure mapper
func NewAdvancedInfrastructureMapper(logger *logger.Logger, config *DiscoveryConfig) *AdvancedInfrastructureMapper {
	if config == nil {
		config = DefaultDiscoveryConfig()
	}

	mapper := &AdvancedInfrastructureMapper{
		logger:         logger,
		config:         config,
		dnsResolver:    NewDNSResolver(logger, config),
		portScanner:    NewPortScanner(logger, config),
		sslAnalyzer:    NewSSLAnalyzer(logger, config),
		cloudDetectors: make(map[CloudProvider]CloudDetector),
		cdnDetector:    NewCDNDetector(logger, config),
		asnAnalyzer:    NewASNAnalyzer(logger, config),
		techDetector:   NewTechDetector(logger, config),
		threatIntel:    NewThreatIntelCollector(logger, config),
		assetGraph:     NewAssetGraph(),
		cache:          NewDiscoveryCache(logger),
	}

	// Initialize cloud detectors
	mapper.cloudDetectors[CloudProviderAWS] = NewAWSDetector(logger, config)
	mapper.cloudDetectors[CloudProviderAzure] = NewAzureDetector(logger, config)
	mapper.cloudDetectors[CloudProviderGCP] = NewGCPDetector(logger, config)
	mapper.cloudDetectors[CloudProviderCloudflare] = NewCloudflareDetector(logger, config)

	return mapper
}

// DiscoverInfrastructure performs comprehensive infrastructure discovery
func (m *AdvancedInfrastructureMapper) DiscoverInfrastructure(ctx context.Context, target string) (*InfrastructureReport, error) {
	startTime := time.Now()

	m.logger.Info("Starting advanced infrastructure discovery",
		"target", target,
		"max_depth", m.config.MaxDepth,
		"max_assets", m.config.MaxAssets)

	report := &InfrastructureReport{
		Target:        target,
		Assets:        []InfrastructureAsset{},
		Organizations: []OrganizationInfo{},
		Relationships: []AssetRelationship{},
		Statistics:    InfrastructureStats{AssetsByType: make(map[string]int)},
		DiscoveredAt:  startTime,
	}

	// Create worker pool for parallel discovery
	workChan := make(chan discoveryTask, m.config.Workers*2)
	resultsChan := make(chan discoveryResult, m.config.Workers*2)

	var wg sync.WaitGroup
	var resultsMutex sync.RWMutex

	// Start workers
	for i := 0; i < m.config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.discoveryWorker(ctx, workChan, resultsChan)
		}()
	}

	// Results collector
	go func() {
		for result := range resultsChan {
			resultsMutex.Lock()
			if result.asset != nil {
				report.Assets = append(report.Assets, *result.asset)
				m.assetGraph.AddAsset(*result.asset)
				report.Statistics.AssetsByType[string(result.asset.Type)]++
			}
			if result.organization != nil {
				report.Organizations = append(report.Organizations, *result.organization)
			}
			if len(result.relationships) > 0 {
				report.Relationships = append(report.Relationships, result.relationships...)
			}
			resultsMutex.Unlock()
		}
	}()

	// Phase 1: Initial target analysis
	m.logger.Info("Phase 1: Analyzing initial target")
	initialAssets := m.analyzeInitialTarget(ctx, target)

	for _, asset := range initialAssets {
		workChan <- discoveryTask{
			taskType: "full_analysis",
			target:   asset.Value,
			asset:    &asset,
			depth:    0,
		}
	}

	// Phase 2: DNS enumeration and subdomain discovery
	if m.config.EnableDNSEnumeration {
		m.logger.Info("Phase 2: DNS enumeration and subdomain discovery")
		dnsTask := discoveryTask{
			taskType: "dns_enumeration",
			target:   target,
			depth:    0,
		}
		workChan <- dnsTask
	}

	// Phase 3: ASN analysis for related infrastructure
	if m.config.EnableASNAnalysis {
		m.logger.Info("Phase 3: ASN and BGP analysis")
		asnTask := discoveryTask{
			taskType: "asn_analysis",
			target:   target,
			depth:    0,
		}
		workChan <- asnTask
	}

	// Phase 4: Cloud asset discovery
	if m.config.EnableCloudDiscovery {
		m.logger.Info("Phase 4: Cloud asset discovery")
		for provider := range m.cloudDetectors {
			cloudTask := discoveryTask{
				taskType: "cloud_discovery",
				target:   target,
				metadata: map[string]interface{}{"provider": provider},
				depth:    0,
			}
			workChan <- cloudTask
		}
	}

	// Close work channel and wait for completion
	close(workChan)
	wg.Wait()
	close(resultsChan)

	// Phase 5: Relationship analysis
	m.logger.Info("Phase 5: Analyzing asset relationships")
	relationships := m.analyzeRelationships(report.Assets)
	report.Relationships = append(report.Relationships, relationships...)

	// Phase 6: Supply chain analysis
	if m.config.EnableSupplyChainAnalysis {
		m.logger.Info("Phase 6: Supply chain analysis")
		report.SupplyChain = m.analyzeSupplyChain(ctx, report.Assets)
	}

	// Phase 7: Threat intelligence
	if m.config.EnableThreatIntel {
		m.logger.Info("Phase 7: Threat intelligence collection")
		report.ThreatIntel = m.collectThreatIntelligence(ctx, report.Assets)
	}

	// Calculate final statistics
	report.Statistics = m.calculateStatistics(report)
	report.DiscoveryTime = time.Since(startTime)

	// Sort assets by priority
	sort.Slice(report.Assets, func(i, j int) bool {
		return report.Assets[i].Priority > report.Assets[j].Priority
	})

	// Limit results if configured
	if m.config.MaxAssets > 0 && len(report.Assets) > m.config.MaxAssets {
		report.Assets = report.Assets[:m.config.MaxAssets]
	}

	m.logger.Info("Infrastructure discovery completed",
		"target", target,
		"assets_discovered", len(report.Assets),
		"organizations", len(report.Organizations),
		"relationships", len(report.Relationships),
		"duration", report.DiscoveryTime)

	return report, nil
}

// discoveryTask represents a unit of work for the discovery workers
type discoveryTask struct {
	taskType string
	target   string
	asset    *InfrastructureAsset
	depth    int
	metadata map[string]interface{}
}

// discoveryResult represents the result of a discovery task
type discoveryResult struct {
	asset         *InfrastructureAsset
	organization  *OrganizationInfo
	relationships []AssetRelationship
	error         error
}

// discoveryWorker processes discovery tasks
func (m *AdvancedInfrastructureMapper) discoveryWorker(ctx context.Context, workChan <-chan discoveryTask, resultsChan chan<- discoveryResult) {
	for task := range workChan {
		select {
		case <-ctx.Done():
			return
		default:
		}

		result := m.processDiscoveryTask(ctx, task)
		resultsChan <- result
	}
}

// processDiscoveryTask processes a single discovery task
func (m *AdvancedInfrastructureMapper) processDiscoveryTask(ctx context.Context, task discoveryTask) discoveryResult {
	switch task.taskType {
	case "full_analysis":
		return m.performFullAssetAnalysis(ctx, task)
	case "dns_enumeration":
		return m.performDNSEnumeration(ctx, task)
	case "asn_analysis":
		return m.performASNAnalysis(ctx, task)
	case "cloud_discovery":
		return m.performCloudDiscovery(ctx, task)
	case "ssl_analysis":
		return m.performFullAssetAnalysis(ctx, task)
	case "port_scan":
		return m.performFullAssetAnalysis(ctx, task)
	default:
		return discoveryResult{error: fmt.Errorf("unknown task type: %s", task.taskType)}
	}
}

// analyzeInitialTarget performs initial analysis of the target
func (m *AdvancedInfrastructureMapper) analyzeInitialTarget(ctx context.Context, target string) []InfrastructureAsset {
	assets := []InfrastructureAsset{}

	// Determine target type and create initial asset
	targetType := m.determineTargetType(target)

	baseAsset := InfrastructureAsset{
		ID:           generateAssetID(targetType, target),
		Type:         targetType,
		Value:        target,
		Source:       "initial_target",
		Confidence:   1.0,
		Priority:     PriorityHigh,
		Tags:         []string{"primary_target"},
		Metadata:     make(map[string]interface{}),
		DiscoveredAt: time.Now(),
	}

	// Add HTTP/HTTPS variants for domains
	if targetType == AssetTypeDomain {
		// Add the domain asset
		assets = append(assets, baseAsset)

		// Add URL variants
		httpAsset := baseAsset
		httpAsset.ID = generateAssetID(AssetTypeURL, "http://"+target)
		httpAsset.Type = AssetTypeURL
		httpAsset.Value = "http://" + target
		httpAsset.Tags = append(httpAsset.Tags, "http")
		assets = append(assets, httpAsset)

		httpsAsset := baseAsset
		httpsAsset.ID = generateAssetID(AssetTypeURL, "https://"+target)
		httpsAsset.Type = AssetTypeURL
		httpsAsset.Value = "https://" + target
		httpsAsset.Tags = append(httpsAsset.Tags, "https")
		assets = append(assets, httpsAsset)
	} else {
		assets = append(assets, baseAsset)
	}

	return assets
}

// determineTargetType determines the type of target
func (m *AdvancedInfrastructureMapper) determineTargetType(target string) AssetType {
	// Check if it's an IP address
	if net.ParseIP(target) != nil {
		return AssetTypeIP
	}

	// Check if it's a URL
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return AssetTypeURL
	}

	// Check if it's an email
	if strings.Contains(target, "@") {
		return AssetTypeEmail
	}

	// Default to domain
	return AssetTypeDomain
}

// performFullAssetAnalysis performs comprehensive analysis of an asset
func (m *AdvancedInfrastructureMapper) performFullAssetAnalysis(ctx context.Context, task discoveryTask) discoveryResult {
	if task.asset == nil {
		return discoveryResult{error: fmt.Errorf("asset is nil")}
	}

	asset := *task.asset
	relationships := []AssetRelationship{}

	// SSL analysis for HTTPS URLs and domains
	if asset.Type == AssetTypeURL && strings.HasPrefix(asset.Value, "https://") ||
		asset.Type == AssetTypeDomain {

		if sslInfo := m.analyzeSSL(ctx, asset.Value); sslInfo != nil {
			asset.SSLInfo = sslInfo
			asset.Tags = append(asset.Tags, "ssl_enabled")

			// Extract additional domains from SSL certificate
			for _, san := range sslInfo.SANs {
				if san != asset.Value && !strings.HasPrefix(san, "*.") {
					sanAsset := InfrastructureAsset{
						ID:           generateAssetID(AssetTypeDomain, san),
						Type:         AssetTypeDomain,
						Value:        san,
						Source:       "ssl_certificate",
						Confidence:   0.9,
						Priority:     PriorityMedium,
						Tags:         []string{"ssl_san"},
						Metadata:     make(map[string]interface{}),
						DiscoveredAt: time.Now(),
					}

					relationships = append(relationships, AssetRelationship{
						SourceAssetID: asset.ID,
						TargetAssetID: sanAsset.ID,
						RelationType:  RelationTypeSharedSSL,
						Confidence:    0.9,
						Evidence:      []string{"shared SSL certificate"},
					})
				}
			}
		}
	}

	// CDN detection
	if m.config.EnableCDNDetection && (asset.Type == AssetTypeURL || asset.Type == AssetTypeDomain) {
		if cdnInfo := m.detectCDN(ctx, asset.Value); cdnInfo != nil {
			asset.CDNInfo = cdnInfo
			asset.Tags = append(asset.Tags, "cdn_protected")

			// If origin server is discovered, add as related asset
			if cdnInfo.OriginServer != "" {
				originAsset := InfrastructureAsset{
					ID:           generateAssetID(AssetTypeDomain, cdnInfo.OriginServer),
					Type:         AssetTypeDomain,
					Value:        cdnInfo.OriginServer,
					Source:       "cdn_origin",
					Confidence:   0.8,
					Priority:     PriorityHigh, // Origin servers are high value
					Tags:         []string{"origin_server"},
					Metadata:     make(map[string]interface{}),
					DiscoveredAt: time.Now(),
				}

				relationships = append(relationships, AssetRelationship{
					SourceAssetID: asset.ID,
					TargetAssetID: originAsset.ID,
					RelationType:  RelationTypeCDNOrigin,
					Confidence:    0.8,
					Evidence:      []string{"CDN origin server"},
				})
			}
		}
	}

	// Technology detection
	if m.config.EnableTechDetection && (asset.Type == AssetTypeURL || asset.Type == AssetTypeDomain) {
		technologies := m.detectTechnologies(ctx, asset.Value)
		asset.Technologies = technologies

		// Tag based on detected technologies
		for _, tech := range technologies {
			if isHighValueTech(tech.Name) {
				asset.Priority = max(asset.Priority, PriorityHigh)
				asset.Tags = append(asset.Tags, "high_value_tech")
			}
		}
	}

	// Network information for IP addresses
	if asset.Type == AssetTypeIP {
		if networkInfo := m.getNetworkInfo(ctx, asset.Value); networkInfo != nil {
			asset.NetworkInfo = networkInfo
			asset.Tags = append(asset.Tags, "network_analyzed")
		}
	}

	return discoveryResult{
		asset:         &asset,
		relationships: relationships,
	}
}

// performDNSEnumeration performs DNS enumeration and subdomain discovery
func (m *AdvancedInfrastructureMapper) performDNSEnumeration(ctx context.Context, task discoveryTask) discoveryResult {
	assets := []InfrastructureAsset{}
	relationships := []AssetRelationship{}

	domain := task.target
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		domain = extractDomain(domain)
	}

	// DNS enumeration
	dnsResults := m.dnsResolver.EnumerateSubdomains(ctx, domain)

	for _, subdomain := range dnsResults.Subdomains {
		subAsset := InfrastructureAsset{
			ID:           generateAssetID(AssetTypeSubdomain, subdomain),
			Type:         AssetTypeSubdomain,
			Value:        subdomain,
			Source:       "dns_enumeration",
			Confidence:   dnsResults.Confidence,
			Priority:     PriorityMedium,
			Tags:         []string{"subdomain"},
			Metadata:     make(map[string]interface{}),
			DiscoveredAt: time.Now(),
		}

		// Resolve IP addresses
		if ips := m.dnsResolver.ResolveDomain(ctx, subdomain); len(ips) > 0 {
			for _, ip := range ips {
				ipAsset := InfrastructureAsset{
					ID:           generateAssetID(AssetTypeIP, ip),
					Type:         AssetTypeIP,
					Value:        ip,
					Source:       "dns_resolution",
					Confidence:   0.9,
					Priority:     PriorityMedium,
					Tags:         []string{"resolved_ip"},
					Metadata:     make(map[string]interface{}),
					DiscoveredAt: time.Now(),
				}

				assets = append(assets, ipAsset)

				relationships = append(relationships, AssetRelationship{
					SourceAssetID: subAsset.ID,
					TargetAssetID: ipAsset.ID,
					RelationType:  RelationTypePointsTo,
					Confidence:    0.9,
					Evidence:      []string{"DNS A/AAAA record"},
				})
			}
		}

		assets = append(assets, subAsset)

		relationships = append(relationships, AssetRelationship{
			SourceAssetID: generateAssetID(AssetTypeDomain, domain),
			TargetAssetID: subAsset.ID,
			RelationType:  RelationTypeHostedOn,
			Confidence:    0.8,
			Evidence:      []string{"subdomain relationship"},
		})
	}

	// Return first asset if any found
	if len(assets) > 0 {
		return discoveryResult{
			asset:         &assets[0],
			relationships: relationships,
		}
	}

	return discoveryResult{relationships: relationships}
}

// performASNAnalysis performs ASN and BGP analysis
func (m *AdvancedInfrastructureMapper) performASNAnalysis(ctx context.Context, task discoveryTask) discoveryResult {
	target := task.target

	// Get target IP if it's a domain
	var targetIP string
	if net.ParseIP(target) != nil {
		targetIP = target
	} else {
		ips := m.dnsResolver.ResolveDomain(ctx, target)
		if len(ips) > 0 {
			targetIP = ips[0]
		} else {
			return discoveryResult{error: fmt.Errorf("could not resolve target to IP")}
		}
	}

	// Get ASN information
	asnInfo := m.asnAnalyzer.GetASNInfo(ctx, targetIP)
	if asnInfo == nil {
		return discoveryResult{error: fmt.Errorf("could not get ASN info for %s", targetIP)}
	}

	// Create organization info
	org := &OrganizationInfo{
		Name:       asnInfo.ASNName,
		ASN:        asnInfo.ASN,
		IPRanges:   asnInfo.IPRanges,
		Confidence: 0.8,
		Source:     "asn_analysis",
		Metadata:   make(map[string]string),
	}

	// Find related IP addresses in the same ASN
	relationships := []AssetRelationship{}
	relatedIPs := m.asnAnalyzer.FindRelatedIPs(ctx, asnInfo.ASN)

	for _, ip := range relatedIPs {
		if ip != targetIP {
			ipAsset := InfrastructureAsset{
				ID:           generateAssetID(AssetTypeIP, ip),
				Type:         AssetTypeIP,
				Value:        ip,
				Source:       "asn_analysis",
				Confidence:   0.7,
				Priority:     PriorityMedium,
				Tags:         []string{"same_asn"},
				NetworkInfo:  &NetworkInfo{ASN: asnInfo.ASN, ASNName: asnInfo.ASNName},
				Metadata:     make(map[string]interface{}),
				DiscoveredAt: time.Now(),
			}

			relationships = append(relationships, AssetRelationship{
				SourceAssetID: generateAssetID(AssetTypeIP, targetIP),
				TargetAssetID: ipAsset.ID,
				RelationType:  RelationTypeSameASN,
				Confidence:    0.7,
				Evidence:      []string{fmt.Sprintf("same ASN: %d", asnInfo.ASN)},
			})
		}
	}

	return discoveryResult{
		organization:  org,
		relationships: relationships,
	}
}

// performCloudDiscovery performs cloud asset discovery
func (m *AdvancedInfrastructureMapper) performCloudDiscovery(ctx context.Context, task discoveryTask) discoveryResult {
	provider, ok := task.metadata["provider"].(CloudProvider)
	if !ok {
		return discoveryResult{error: fmt.Errorf("no cloud provider specified")}
	}

	detector, exists := m.cloudDetectors[provider]
	if !exists {
		return discoveryResult{error: fmt.Errorf("no detector for provider %s", provider)}
	}

	cloudAssets := detector.DiscoverAssets(ctx, task.target)
	relationships := []AssetRelationship{}

	// Return first asset if any found
	if len(cloudAssets) > 0 {
		// Create relationships between cloud assets and original target
		for _, cloudAsset := range cloudAssets[1:] {
			relationships = append(relationships, AssetRelationship{
				SourceAssetID: generateAssetID(AssetTypeDomain, task.target),
				TargetAssetID: cloudAsset.ID,
				RelationType:  RelationTypeHostedOn,
				Confidence:    cloudAsset.Confidence,
				Evidence:      []string{fmt.Sprintf("hosted on %s", provider)},
			})
		}

		return discoveryResult{
			asset:         &cloudAssets[0],
			relationships: relationships,
		}
	}

	return discoveryResult{}
}

// Implement additional helper methods...

// analyzeSSL analyzes SSL certificate information
func (m *AdvancedInfrastructureMapper) analyzeSSL(ctx context.Context, target string) *SSLInfo {
	return m.sslAnalyzer.AnalyzeSSL(ctx, target)
}

// detectCDN detects CDN usage and configuration
func (m *AdvancedInfrastructureMapper) detectCDN(ctx context.Context, target string) *CDNInfo {
	return m.cdnDetector.DetectCDN(ctx, target)
}

// detectTechnologies detects technologies used by the target
func (m *AdvancedInfrastructureMapper) detectTechnologies(ctx context.Context, target string) []Technology {
	return m.techDetector.DetectTechnologies(ctx, target)
}

// getNetworkInfo gets network information for an IP address
func (m *AdvancedInfrastructureMapper) getNetworkInfo(ctx context.Context, ip string) *NetworkInfo {
	return m.asnAnalyzer.GetNetworkInfo(ctx, ip)
}

// analyzeRelationships analyzes relationships between discovered assets
func (m *AdvancedInfrastructureMapper) analyzeRelationships(assets []InfrastructureAsset) []AssetRelationship {
	relationships := []AssetRelationship{}

	// Analyze shared technologies
	techGroups := make(map[string][]string) // technology -> asset IDs

	for _, asset := range assets {
		for _, tech := range asset.Technologies {
			techGroups[tech.Name] = append(techGroups[tech.Name], asset.ID)
		}
	}

	// Create relationships for shared technologies
	for tech, assetIDs := range techGroups {
		if len(assetIDs) > 1 {
			for i := 0; i < len(assetIDs)-1; i++ {
				for j := i + 1; j < len(assetIDs); j++ {
					relationships = append(relationships, AssetRelationship{
						SourceAssetID: assetIDs[i],
						TargetAssetID: assetIDs[j],
						RelationType:  RelationTypeSameTech,
						Confidence:    0.6,
						Evidence:      []string{fmt.Sprintf("shared technology: %s", tech)},
					})
				}
			}
		}
	}

	return relationships
}

// analyzeSupplyChain performs supply chain analysis
func (m *AdvancedInfrastructureMapper) analyzeSupplyChain(ctx context.Context, assets []InfrastructureAsset) *SupplyChainInfo {
	supplyChain := &SupplyChainInfo{
		JavaScript:    []JSLibrary{},
		APIs:          []ThirdPartyAPI{},
		CDNs:          []CDNService{},
		Analytics:     []AnalyticsService{},
		CloudServices: []CloudService{},
		Dependencies:  []Dependency{},
		Risks:         []SupplyChainRisk{},
	}

	// Analyze each web asset for supply chain components
	for _, asset := range assets {
		if asset.Type == AssetTypeURL {
			m.analyzeWebAssetSupplyChain(ctx, asset, supplyChain)
		}
	}

	return supplyChain
}

// analyzeWebAssetSupplyChain analyzes supply chain for a web asset
func (m *AdvancedInfrastructureMapper) analyzeWebAssetSupplyChain(ctx context.Context, asset InfrastructureAsset, supplyChain *SupplyChainInfo) {
	// This would integrate with tools like:
	// - Retire.js for JavaScript library analysis
	// - Wappalyzer for technology detection
	// - Custom parsers for third-party APIs

	// For now, implement basic analysis based on technologies
	for _, tech := range asset.Technologies {
		if isJavaScriptFramework(tech.Name) {
			jsLib := JSLibrary{
				Name:    tech.Name,
				Version: tech.Version,
				Source:  asset.Value,
			}
			supplyChain.JavaScript = append(supplyChain.JavaScript, jsLib)
		}

		if isCDNService(tech.Name) {
			cdnService := CDNService{
				Provider: tech.Name,
				Domains:  []string{asset.Value},
			}
			supplyChain.CDNs = append(supplyChain.CDNs, cdnService)
		}
	}
}

// collectThreatIntelligence collects threat intelligence for assets
func (m *AdvancedInfrastructureMapper) collectThreatIntelligence(ctx context.Context, assets []InfrastructureAsset) *ThreatIntelligence {
	return m.threatIntel.CollectIntelligence(ctx, assets)
}

// calculateStatistics calculates comprehensive statistics
func (m *AdvancedInfrastructureMapper) calculateStatistics(report *InfrastructureReport) InfrastructureStats {
	stats := InfrastructureStats{
		TotalAssets:  len(report.Assets),
		AssetsByType: make(map[string]int),
	}

	uniqueIPs := make(map[string]bool)
	uniqueDomains := make(map[string]bool)
	cloudAssets := 0
	cdnProtected := 0
	sslCertificates := 0
	openPorts := 0
	technologies := 0
	highRiskAssets := 0
	exposedServices := 0

	for _, asset := range report.Assets {
		stats.AssetsByType[string(asset.Type)]++

		if asset.Type == AssetTypeIP {
			uniqueIPs[asset.Value] = true
		}
		if asset.Type == AssetTypeDomain || asset.Type == AssetTypeSubdomain {
			uniqueDomains[asset.Value] = true
		}
		if asset.CloudInfo != nil {
			cloudAssets++
			if asset.CloudInfo.PublicAccess {
				exposedServices++
			}
		}
		if asset.CDNInfo != nil {
			cdnProtected++
		}
		if asset.SSLInfo != nil {
			sslCertificates++
		}
		if asset.NetworkInfo != nil && len(asset.NetworkInfo.OpenPorts) > 0 {
			openPorts += len(asset.NetworkInfo.OpenPorts)
		}
		if len(asset.Technologies) > 0 {
			technologies += len(asset.Technologies)
		}
		if asset.Priority >= PriorityHigh {
			highRiskAssets++
		}
	}

	stats.UniqueIPs = len(uniqueIPs)
	stats.UniqueDomains = len(uniqueDomains)
	stats.CloudAssets = cloudAssets
	stats.CDNProtected = cdnProtected
	stats.SSLCertificates = sslCertificates
	stats.OpenPorts = openPorts
	stats.Technologies = technologies
	stats.Organizations = len(report.Organizations)
	stats.HighRiskAssets = highRiskAssets
	stats.ExposedServices = exposedServices

	if report.SupplyChain != nil {
		stats.SupplyChainRisks = len(report.SupplyChain.Risks)
	}

	return stats
}

// Helper functions

func generateAssetID(assetType AssetType, value string) string {
	return fmt.Sprintf("%s:%s", assetType, value)
}

func extractDomain(url string) string {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	parts := strings.Split(url, "/")
	return parts[0]
}

func isHighValueTech(techName string) bool {
	highValueTechs := []string{
		"admin", "dashboard", "panel", "phpmyadmin", "adminer",
		"grafana", "kibana", "jenkins", "gitlab", "jira",
		"confluence", "sonarqube", "nexus", "artifactory",
	}

	techLower := strings.ToLower(techName)
	for _, hvt := range highValueTechs {
		if strings.Contains(techLower, hvt) {
			return true
		}
	}
	return false
}

func isJavaScriptFramework(techName string) bool {
	jsFrameworks := []string{
		"react", "angular", "vue", "jquery", "bootstrap",
		"lodash", "moment", "axios", "express", "webpack",
	}

	techLower := strings.ToLower(techName)
	for _, framework := range jsFrameworks {
		if strings.Contains(techLower, framework) {
			return true
		}
	}
	return false
}

func isCDNService(techName string) bool {
	cdnServices := []string{
		"cloudflare", "fastly", "cloudfront", "akamai",
		"maxcdn", "jsdelivr", "unpkg", "cdnjs",
	}

	techLower := strings.ToLower(techName)
	for _, cdn := range cdnServices {
		if strings.Contains(techLower, cdn) {
			return true
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// DefaultDiscoveryConfig returns default configuration for discovery
func DefaultDiscoveryConfig() *DiscoveryConfig {
	return &DiscoveryConfig{
		MaxDepth:                  3,
		MaxAssets:                 1000,
		Timeout:                   30 * time.Minute,
		Workers:                   10,
		RateLimitPerSecond:        50,
		EnableDNSEnumeration:      true,
		EnableSubdomainBrute:      true,
		EnablePortScanning:        true,
		EnableSSLAnalysis:         true,
		EnableCloudDiscovery:      true,
		EnableCDNDetection:        true,
		EnableASNAnalysis:         true,
		EnableTechDetection:       true,
		EnableSupplyChainAnalysis: true,
		EnableThreatIntel:         false, // Requires API keys
		CustomPorts:               []int{80, 443, 8080, 8443, 3000, 5000, 8000, 9000},
	}
}
