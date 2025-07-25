package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/asn"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/dns"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/external"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/search"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/web"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/whois"
)

// EnhancedDiscovery performs comprehensive asset discovery
type EnhancedDiscovery struct {
	config          *DiscoveryConfig
	logger          *logger.Logger
	searchEngine    *search.SearchEngineDiscovery
	dnsbruteforcer  *dns.DNSBruteforcer
	webSpider       *web.WebSpider
	whoisClient     *whois.WhoisClient
	asnClient       *asn.ASNClient
	shodanClient    *external.ShodanClient
	censysClient    *external.CensysClient
	discoveredAssets map[string]bool
	assetLock       sync.RWMutex
	recursionDepth  int
	maxRecursion    int
}

// NewEnhancedDiscovery creates enhanced discovery module
func NewEnhancedDiscovery(config *DiscoveryConfig, logger *logger.Logger, cfg *config.Config) *EnhancedDiscovery {
	// Initialize clients with API keys from config
	var shodanClient *external.ShodanClient
	var censysClient *external.CensysClient
	
	if cfg != nil {
		if cfg.ShodanAPIKey != "" {
			shodanClient = external.NewShodanClient(cfg.ShodanAPIKey, logger)
		}
		if cfg.CensysAPIKey != "" && cfg.CensysSecret != "" {
			censysClient = external.NewCensysClient(cfg.CensysAPIKey, cfg.CensysSecret, logger)
		}
	}

	return &EnhancedDiscovery{
		config:          config,
		logger:          logger,
		searchEngine:    search.NewSearchEngineDiscovery(logger),
		dnsbruteforcer:  dns.NewDNSBruteforcer(logger),
		webSpider:       web.NewWebSpider(logger),
		whoisClient:     whois.NewWhoisClient(logger),
		asnClient:       asn.NewASNClient(logger),
		shodanClient:    shodanClient,
		censysClient:    censysClient,
		discoveredAssets: make(map[string]bool),
		maxRecursion:    3,
	}
}

func (e *EnhancedDiscovery) Name() string  { return "enhanced_discovery" }
func (e *EnhancedDiscovery) Priority() int { return 100 } // Highest priority

func (e *EnhancedDiscovery) CanHandle(target *Target) bool {
	// Can handle all target types
	return true
}

// Discover performs comprehensive discovery
func (e *EnhancedDiscovery) Discover(ctx context.Context, target *Target, session *DiscoverySession) (*DiscoveryResult, error) {
	result := &DiscoveryResult{
		Assets:        []*Asset{},
		Relationships: []*Relationship{},
		Source:        e.Name(),
	}

	e.logger.Info("Starting enhanced discovery", 
		"target", target.Value,
		"type", target.Type,
		"recursion_depth", e.recursionDepth)

	// Track this target as discovered
	e.markAsDiscovered(target.Value)

	// Run discovery based on target type
	switch target.Type {
	case TargetTypeDomain:
		e.discoverDomain(ctx, target.Value, result)
	case TargetTypeIP:
		e.discoverIP(ctx, target.Value, result)
	case TargetTypeIPRange:
		e.discoverIPRange(ctx, target.Value, result)
	case TargetTypeCompany:
		e.discoverCompany(ctx, target.Value, result)
	case TargetTypeEmail:
		e.discoverEmail(ctx, target.Value, result)
	case TargetTypeASN:
		e.discoverASN(ctx, target.Value, result)
	}

	// Recursive discovery on new assets
	if e.recursionDepth < e.maxRecursion {
		e.recursiveDiscovery(ctx, result)
	}

	e.logger.Info("Enhanced discovery completed",
		"target", target.Value,
		"assets_found", len(result.Assets),
		"relationships", len(result.Relationships))

	return result, nil
}

// discoverDomain performs comprehensive domain discovery
func (e *EnhancedDiscovery) discoverDomain(ctx context.Context, domain string, result *DiscoveryResult) {
	var wg sync.WaitGroup
	
	// DNS brute-forcing
	if e.config.EnableDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.dnsBruteforce(ctx, domain, result)
		}()
	}

	// Search engine discovery
	if e.config.EnableSearch {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.searchEngineDiscovery(ctx, domain, result)
		}()
	}

	// Web crawling
	if e.config.EnableWebCrawl {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.webCrawl(ctx, "https://"+domain, result)
		}()
	}

	// WHOIS lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.whoisLookup(ctx, domain, result)
	}()

	// External API searches
	if e.shodanClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.shodanSearch(ctx, domain, result)
		}()
	}

	if e.censysClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.censysSearch(ctx, domain, result)
		}()
	}

	wg.Wait()
}

// dnsBruteforce performs DNS subdomain enumeration
func (e *EnhancedDiscovery) dnsBruteforce(ctx context.Context, domain string, result *DiscoveryResult) {
	subdomains, err := e.dnsbruteforcer.Bruteforce(ctx, domain)
	if err != nil {
		e.logger.Error("DNS brute-force failed", "domain", domain, "error", err)
		return
	}

	for _, sub := range subdomains {
		if !e.isAlreadyDiscovered(sub.Subdomain) {
			asset := &Asset{
				Type:       AssetTypeSubdomain,
				Value:      sub.Subdomain,
				Domain:     domain,
				IP:         strings.Join(sub.IPs, ","), // Store multiple IPs as comma-separated
				Source:     "dns_bruteforce",
				Confidence: 0.9,
				DiscoveredAt: time.Now(),
				LastSeen:   time.Now(),
				Metadata:   make(map[string]string),
			}
			
			if sub.CNAME != "" {
				asset.Metadata["cname"] = sub.CNAME
			}
			
			if sub.Wildcard {
				asset.Metadata["wildcard"] = "true"
				asset.Confidence = 0.5
			}

			result.Assets = append(result.Assets, asset)
			e.markAsDiscovered(sub.Subdomain)
		}
	}
}

// searchEngineDiscovery uses search engines to find assets
func (e *EnhancedDiscovery) searchEngineDiscovery(ctx context.Context, domain string, result *DiscoveryResult) {
	domains, err := e.searchEngine.DiscoverAssets(ctx, domain)
	if err != nil {
		e.logger.Error("Search engine discovery failed", "domain", domain, "error", err)
		return
	}

	for _, d := range domains {
		if !e.isAlreadyDiscovered(d) {
			assetType := AssetTypeDomain
			if strings.HasSuffix(d, domain) && d != domain {
				assetType = AssetTypeSubdomain
			}

			asset := &Asset{
				Type:       assetType,
				Value:      d,
				Domain:     domain,
				Source:     "search_engine",
				Confidence: 0.7,
				DiscoveredAt: time.Now(),
				LastSeen:   time.Now(),
				Metadata:   map[string]string{"discovery_method": "google_dork"},
			}

			result.Assets = append(result.Assets, asset)
			e.markAsDiscovered(d)
		}
	}
}

// webCrawl performs web spidering
func (e *EnhancedDiscovery) webCrawl(ctx context.Context, url string, result *DiscoveryResult) {
	crawlResults, err := e.webSpider.Crawl(ctx, url)
	if err != nil {
		e.logger.Error("Web crawl failed", "url", url, "error", err)
		return
	}

	for _, crawl := range crawlResults {
		// Add URL as asset
		if !e.isAlreadyDiscovered(crawl.URL) {
			asset := &Asset{
				Type:       AssetTypeURL,
				Value:      crawl.URL,
				Title:      crawl.Title,
				Technology: crawl.Technologies,
				Source:     "web_crawler",
				Confidence: 0.95,
				DiscoveredAt: time.Now(),
				LastSeen:   time.Now(),
				Metadata:   map[string]string{
					"status_code": fmt.Sprintf("%d", crawl.StatusCode),
				},
			}

			result.Assets = append(result.Assets, asset)
			e.markAsDiscovered(crawl.URL)
		}

		// Add discovered subdomains
		for _, subdomain := range crawl.Subdomains {
			if !e.isAlreadyDiscovered(subdomain) {
				asset := &Asset{
					Type:       AssetTypeSubdomain,
					Value:      subdomain,
					Source:     "web_crawler",
					Confidence: 0.8,
					DiscoveredAt: time.Now(),
					LastSeen:   time.Now(),
					Metadata:   map[string]string{"found_on": crawl.URL},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(subdomain)
			}
		}

		// Add APIs
		for _, api := range crawl.APIs {
			if !e.isAlreadyDiscovered(api) {
				asset := &Asset{
					Type:       AssetTypeAPI,
					Value:      api,
					Source:     "web_crawler",
					Confidence: 0.85,
					DiscoveredAt: time.Now(),
					LastSeen:   time.Now(),
					Metadata:   map[string]string{"found_on": crawl.URL},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(api)
			}
		}

		// Add emails
		for _, email := range crawl.Emails {
			if !e.isAlreadyDiscovered(email) {
				asset := &Asset{
					Type:       AssetTypeEmail,
					Value:      email,
					Source:     "web_crawler",
					Confidence: 0.9,
					DiscoveredAt: time.Now(),
					LastSeen:   time.Now(),
					Metadata:   map[string]string{"found_on": crawl.URL},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(email)
			}
		}
	}
}

// whoisLookup performs WHOIS queries
func (e *EnhancedDiscovery) whoisLookup(ctx context.Context, domain string, result *DiscoveryResult) {
	whoisResult, err := e.whoisClient.LookupDomain(ctx, domain)
	if err != nil {
		e.logger.Error("WHOIS lookup failed", "domain", domain, "error", err)
		return
	}

	// Add related domains
	for _, related := range whoisResult.RelatedDomains {
		if !e.isAlreadyDiscovered(related) {
			asset := &Asset{
				Type:       AssetTypeDomain,
				Value:      related,
				Source:     "whois",
				Confidence: 0.75,
				DiscoveredAt: time.Now(),
				LastSeen:   time.Now(),
				Metadata: map[string]string{
					"registrant_org": whoisResult.RegistrantOrg,
					"registrar": whoisResult.Registrar,
				},
			}

			result.Assets = append(result.Assets, asset)
			e.markAsDiscovered(related)
		}
	}

	// Add emails
	for _, email := range whoisResult.RelatedEmails {
		if !e.isAlreadyDiscovered(email) {
			asset := &Asset{
				Type:       AssetTypeEmail,
				Value:      email,
				Source:     "whois",
				Confidence: 0.9,
				DiscoveredAt: time.Now(),
				LastSeen:   time.Now(),
				Metadata: map[string]string{
					"domain": domain,
					"registrant_org": whoisResult.RegistrantOrg,
				},
			}

			result.Assets = append(result.Assets, asset)
			e.markAsDiscovered(email)
		}
	}
}

// shodanSearch uses Shodan API
func (e *EnhancedDiscovery) shodanSearch(ctx context.Context, domain string, result *DiscoveryResult) {
	hosts, err := e.shodanClient.SearchDomain(ctx, domain)
	if err != nil {
		e.logger.Error("Shodan search failed", "domain", domain, "error", err)
		return
	}

	for _, host := range hosts {
		// Add IP
		if !e.isAlreadyDiscovered(host.IP) {
			asset := &Asset{
				Type:       AssetTypeIP,
				Value:      host.IP,
				Domain:     domain,
				IP:         host.IP,
				Source:     "shodan",
				Confidence: 0.95,
				DiscoveredAt: time.Now(),
				LastSeen:   time.Now(),
				Metadata: map[string]string{
					"asn": host.ASN,
					"isp": host.ISP,
					"org": host.Org,
					"country": host.Country,
					"city": host.City,
				},
			}

			if host.OS != "" {
				asset.Metadata["os"] = host.OS
			}

			if len(host.Vulns) > 0 {
				asset.Metadata["vulns"] = strings.Join(host.Vulns, ",")
				asset.Tags = append(asset.Tags, "has_vulns")
			}

			result.Assets = append(result.Assets, asset)
			e.markAsDiscovered(host.IP)
		}

		// Add hostnames
		for _, hostname := range host.Hostnames {
			if !e.isAlreadyDiscovered(hostname) {
				assetType := AssetTypeDomain
				if strings.HasSuffix(hostname, domain) && hostname != domain {
					assetType = AssetTypeSubdomain
				}

				asset := &Asset{
					Type:       assetType,
					Value:      hostname,
					Domain:     domain,
					IP:         host.IP,
					Source:     "shodan",
					Confidence: 0.9,
					DiscoveredAt: time.Now(),
					LastSeen:   time.Now(),
					Metadata: map[string]string{
						"ip": host.IP,
					},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(hostname)
			}
		}
	}
}

// censysSearch uses Censys API
func (e *EnhancedDiscovery) censysSearch(ctx context.Context, domain string, result *DiscoveryResult) {
	hits, err := e.censysClient.SearchDomain(ctx, domain)
	if err != nil {
		e.logger.Error("Censys search failed", "domain", domain, "error", err)
		return
	}

	for _, hit := range hits {
		if !e.isAlreadyDiscovered(hit.IP) {
			asset := &Asset{
				Type:       AssetTypeIP,
				Value:      hit.IP,
				Domain:     domain,
				IP:         hit.IP,
				Source:     "censys",
				Confidence: 0.95,
				DiscoveredAt: time.Now(),
				LastSeen:   time.Now(),
				Metadata: map[string]string{
					"asn": fmt.Sprintf("%d", hit.AutonomousSystem.ASN),
					"as_name": hit.AutonomousSystem.Name,
					"country": hit.Location.Country,
					"city": hit.Location.City,
				},
			}

			// Add services
			var services []string
			for _, svc := range hit.Services {
				services = append(services, fmt.Sprintf("%d/%s", svc.Port, svc.ServiceName))
			}
			if len(services) > 0 {
				asset.Metadata["services"] = strings.Join(services, ",")
			}

			result.Assets = append(result.Assets, asset)
			e.markAsDiscovered(hit.IP)
		}
	}
}

// discoverIP performs discovery starting from an IP
func (e *EnhancedDiscovery) discoverIP(ctx context.Context, ip string, result *DiscoveryResult) {
	// IP WHOIS
	ipWhois, err := e.whoisClient.LookupIP(ctx, ip)
	if err == nil {
		// Add organization info
		if ipWhois.Organization != "" {
			asset := &Asset{
				Type:       AssetTypeOrganization,
				Value:      ipWhois.Organization,
				Source:     "whois",
				Confidence: 0.8,
				DiscoveredAt: time.Now(),
				LastSeen:   time.Now(),
				Metadata: map[string]string{
					"ip": ip,
					"asn": ipWhois.ASN,
					"netblock": ipWhois.NetBlock,
				},
			}
			result.Assets = append(result.Assets, asset)
		}

		// Add ASN for expansion
		if ipWhois.ASN != "" {
			e.discoverASN(ctx, ipWhois.ASN, result)
		}
	}

	// Reverse DNS
	names, err := net.LookupAddr(ip)
	if err == nil {
		for _, name := range names {
			name = strings.TrimSuffix(name, ".")
			if !e.isAlreadyDiscovered(name) {
				asset := &Asset{
					Type:       AssetTypeDomain,
					Value:      name,
					IP:         ip,
					Source:     "reverse_dns",
					Confidence: 0.9,
					DiscoveredAt: time.Now(),
					LastSeen:   time.Now(),
					Metadata: map[string]string{"ip": ip},
				}
				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(name)
			}
		}
	}

	// Shodan lookup
	if e.shodanClient != nil {
		host, err := e.shodanClient.SearchIP(ctx, ip)
		if err == nil {
			for _, hostname := range host.Hostnames {
				if !e.isAlreadyDiscovered(hostname) {
					asset := &Asset{
						Type:       AssetTypeDomain,
						Value:      hostname,
						IP:         ip,
						Source:     "shodan",
						Confidence: 0.9,
						DiscoveredAt: time.Now(),
						LastSeen:   time.Now(),
					}
					result.Assets = append(result.Assets, asset)
					e.markAsDiscovered(hostname)
				}
			}
		}
	}
}

// discoverASN expands an ASN to find all assets
func (e *EnhancedDiscovery) discoverASN(ctx context.Context, asnStr string, result *DiscoveryResult) {
	// Parse ASN number
	var asn int
	fmt.Sscanf(asnStr, "AS%d", &asn)
	if asn == 0 {
		fmt.Sscanf(asnStr, "%d", &asn)
	}

	if asn == 0 {
		return
	}

	// Get ASN info
	asnInfo, err := e.asnClient.LookupASN(ctx, asn)
	if err != nil {
		e.logger.Error("ASN lookup failed", "asn", asn, "error", err)
		return
	}

	// Add organization
	if asnInfo.Organization != "" && !e.isAlreadyDiscovered(asnInfo.Organization) {
		asset := &Asset{
			Type:       AssetTypeOrganization,
			Value:      asnInfo.Organization,
			Source:     "asn",
			Confidence: 0.85,
			DiscoveredAt: time.Now(),
			LastSeen:   time.Now(),
			Metadata: map[string]string{
				"asn": fmt.Sprintf("AS%d", asn),
				"country": asnInfo.Country,
			},
		}
		result.Assets = append(result.Assets, asset)
		e.markAsDiscovered(asnInfo.Organization)
	}

	// Add IP ranges
	for _, prefix := range asnInfo.Prefixes {
		if !e.isAlreadyDiscovered(prefix) {
			asset := &Asset{
				Type:       AssetTypeIPRange,
				Value:      prefix,
				Source:     "asn",
				Confidence: 0.95,
				DiscoveredAt: time.Now(),
				LastSeen:   time.Now(),
				Metadata: map[string]string{
					"asn": fmt.Sprintf("AS%d", asn),
					"org": asnInfo.Organization,
				},
			}
			result.Assets = append(result.Assets, asset)
			e.markAsDiscovered(prefix)
		}
	}
}

// discoverCompany performs company-based discovery
func (e *EnhancedDiscovery) discoverCompany(ctx context.Context, company string, result *DiscoveryResult) {
	// Search for ASNs
	asns, err := e.asnClient.FindRelatedASNs(ctx, company)
	if err == nil {
		for _, asn := range asns {
			e.discoverASN(ctx, fmt.Sprintf("AS%d", asn), result)
		}
	}

	// Search engine discovery
	if e.config.EnableSearch {
		domains, _ := e.searchEngine.DiscoverAssets(ctx, company)
		for _, domain := range domains {
			if !e.isAlreadyDiscovered(domain) {
				asset := &Asset{
					Type:       AssetTypeDomain,
					Value:      domain,
					Source:     "search_engine",
					Confidence: 0.6,
					DiscoveredAt: time.Now(),
					LastSeen:   time.Now(),
					Metadata: map[string]string{"company": company},
				}
				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(domain)
			}
		}
	}

	// Shodan organization search
	if e.shodanClient != nil {
		hosts, err := e.shodanClient.SearchOrg(ctx, company)
		if err == nil {
			for _, host := range hosts {
				if !e.isAlreadyDiscovered(host.IP) {
					asset := &Asset{
						Type:       AssetTypeIP,
						Value:      host.IP,
						IP:         host.IP,
						Source:     "shodan",
						Confidence: 0.8,
						DiscoveredAt: time.Now(),
						LastSeen:   time.Now(),
						Metadata: map[string]string{
							"org": host.Org,
							"company_search": company,
						},
					}
					result.Assets = append(result.Assets, asset)
					e.markAsDiscovered(host.IP)
				}
			}
		}
	}
}

// discoverEmail performs email-based discovery
func (e *EnhancedDiscovery) discoverEmail(ctx context.Context, email string, result *DiscoveryResult) {
	// Extract domain from email
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return
	}

	domain := parts[1]
	
	// Discover the domain
	e.discoverDomain(ctx, domain, result)

	// Add the domain itself
	if !e.isAlreadyDiscovered(domain) {
		asset := &Asset{
			Type:       AssetTypeDomain,
			Value:      domain,
			Source:     "email",
			Confidence: 0.95,
			DiscoveredAt: time.Now(),
			LastSeen:   time.Now(),
			Metadata: map[string]string{"email": email},
		}
		result.Assets = append(result.Assets, asset)
		e.markAsDiscovered(domain)
	}
}

// discoverIPRange performs discovery on IP ranges
func (e *EnhancedDiscovery) discoverIPRange(ctx context.Context, ipRange string, result *DiscoveryResult) {
	// For now, just add the range itself
	// In a full implementation, this would scan the range
	asset := &Asset{
		Type:       AssetTypeIPRange,
		Value:      ipRange,
		Source:     "input",
		Confidence: 1.0,
		DiscoveredAt: time.Now(),
		LastSeen:   time.Now(),
	}
	result.Assets = append(result.Assets, asset)
}

// recursiveDiscovery performs discovery on newly found assets
func (e *EnhancedDiscovery) recursiveDiscovery(ctx context.Context, result *DiscoveryResult) {
	e.recursionDepth++
	defer func() { e.recursionDepth-- }()

	// Create new targets from discovered assets
	var newTargets []*Target
	
	for _, asset := range result.Assets {
		// Skip if already fully discovered
		if e.isFullyDiscovered(asset.Value) {
			continue
		}

		var targetType TargetType
		switch asset.Type {
		case AssetTypeDomain, AssetTypeSubdomain:
			targetType = TargetTypeDomain
		case AssetTypeIP:
			targetType = TargetTypeIP
		case AssetTypeIPRange:
			targetType = TargetTypeIPRange
		case AssetTypeASN:
			targetType = TargetTypeASN
		case AssetTypeOrganization:
			targetType = TargetTypeCompany
		case AssetTypeEmail:
			targetType = TargetTypeEmail
		default:
			continue
		}

		newTargets = append(newTargets, &Target{
			Type:       targetType,
			Value:      asset.Value,
			Confidence: asset.Confidence,
		})
	}

	// Discover new targets
	for _, target := range newTargets {
		subResult := &DiscoveryResult{
			Assets:        []*Asset{},
			Relationships: []*Relationship{},
		}

		// Run discovery based on type
		switch target.Type {
		case TargetTypeDomain:
			e.discoverDomain(ctx, target.Value, subResult)
		case TargetTypeIP:
			e.discoverIP(ctx, target.Value, subResult)
		case TargetTypeASN:
			e.discoverASN(ctx, target.Value, subResult)
		}

		// Merge results
		result.Assets = append(result.Assets, subResult.Assets...)
		result.Relationships = append(result.Relationships, subResult.Relationships...)
	}
}

// Helper methods

func (e *EnhancedDiscovery) markAsDiscovered(value string) {
	e.assetLock.Lock()
	defer e.assetLock.Unlock()
	e.discoveredAssets[value] = true
}

func (e *EnhancedDiscovery) isAlreadyDiscovered(value string) bool {
	e.assetLock.RLock()
	defer e.assetLock.RUnlock()
	return e.discoveredAssets[value]
}

func (e *EnhancedDiscovery) isFullyDiscovered(value string) bool {
	// In a real implementation, track discovery depth per asset
	return false
}

// SetOrganizationContext implements organization context awareness
func (e *EnhancedDiscovery) SetOrganizationContext(orgContext *OrganizationContext) {
	if orgContext == nil {
		return
	}

	// Use organization context to guide discovery
	e.logger.Info("Organization context set",
		"org", orgContext.OrgName,
		"domains", len(orgContext.KnownDomains),
		"ip_ranges", len(orgContext.KnownIPRanges))

	// Pre-populate known assets
	for _, domain := range orgContext.KnownDomains {
		e.markAsDiscovered(domain)
	}
}