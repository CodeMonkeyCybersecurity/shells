package discovery

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/credentials"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/asn"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/cache"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/certlogs"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/cloud"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/dns"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/external"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/ipv6"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/passivedns"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/portscan"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/ratelimit"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/search"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/takeover"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/techstack"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/vulnerability"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/web"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/whois"
)

// EnhancedDiscovery performs comprehensive asset discovery
type EnhancedDiscovery struct {
	config            *DiscoveryConfig
	logger            *logger.Logger
	searchEngine      *search.SearchEngineDiscovery
	dnsbruteforcer    *dns.DNSBruteforcer
	webSpider         *web.WebSpider
	whoisClient       *whois.WhoisClient
	asnClient         *asn.ASNClient
	shodanClient      *external.ShodanClient
	censysClient      *external.CensysClient
	awsClient         *cloud.AWSDiscovery
	azureClient       *cloud.AzureDiscovery
	gcpClient         *cloud.GCPDiscovery
	takeoverDetector  *takeover.TakeoverDetector
	portScanner       *portscan.PortScanner
	vulnCorrelator    *vulnerability.VulnerabilityCorrelator
	ctLogClient       *certlogs.CTLogClient
	techFingerprinter *techstack.TechFingerprinter
	passiveDNSClient  *passivedns.PassiveDNSClient
	ipv6Discoverer    *ipv6.IPv6Discoverer
	discoveredAssets  map[string]bool
	assetLock         sync.RWMutex
	recursionDepth    int
	maxRecursion      int
	cache             *cache.APICache
	rateLimiter       *ratelimit.RateLimiter
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

	// Initialize cache directory
	cacheDir := filepath.Join("/tmp", "shells_cache")
	apiCache, err := cache.NewAPICache(cacheDir, 24*time.Hour, logger)
	if err != nil {
		logger.Error("Failed to initialize cache", "error", err)
		apiCache = nil
	}

	// Initialize rate limiter
	rateLimiter := ratelimit.GetGlobalRateLimiter(logger)

	// Initialize cloud discovery modules
	awsDiscovery := cloud.NewAWSDiscovery(logger)
	azureDiscovery := cloud.NewAzureDiscovery(logger)
	gcpDiscovery := cloud.NewGCPDiscovery(logger)

	// Initialize takeover detector
	takeoverDetector := takeover.NewTakeoverDetector(logger)

	// Initialize port scanner
	portScanner := portscan.NewPortScanner(logger)

	// Initialize vulnerability correlator
	vulnCorrelator := vulnerability.NewVulnerabilityCorrelator(logger)

	// Initialize CT log client
	ctLogClient := certlogs.NewCTLogClient(logger)

	// Initialize technology fingerprinter
	techFingerprinter := techstack.NewTechFingerprinter(logger)

	// Initialize passive DNS client with API keys from credentials manager
	passiveDNSAPIKeys := make(map[string]string)
	
	// Try to get credentials from the credentials manager
	if credManager, err := credentials.NewManager(logger); err == nil {
		// Get all API keys from credentials manager
		apiKeys := credManager.GetAPIKeys()
		
		// Map the keys to the format expected by passive DNS client
		for k, v := range apiKeys {
			passiveDNSAPIKeys[k] = v
		}
		
		logger.Debug("Loaded API keys from credentials manager", 
			"keys_loaded", len(passiveDNSAPIKeys))
	} else {
		logger.Debug("Could not load credentials from manager, using empty API keys", 
			"error", err)
	}
	
	passiveDNSClient := passivedns.NewPassiveDNSClient(logger, passiveDNSAPIKeys)

	// Initialize IPv6 discoverer
	ipv6Discoverer := ipv6.NewIPv6Discoverer(logger)

	return &EnhancedDiscovery{
		config:            config,
		logger:            logger,
		searchEngine:      search.NewSearchEngineDiscovery(logger),
		dnsbruteforcer:    dns.NewDNSBruteforcer(logger),
		webSpider:         web.NewWebSpider(logger),
		whoisClient:       whois.NewWhoisClient(logger),
		asnClient:         asn.NewASNClient(logger),
		shodanClient:      shodanClient,
		censysClient:      censysClient,
		awsClient:         awsDiscovery,
		azureClient:       azureDiscovery,
		gcpClient:         gcpDiscovery,
		takeoverDetector:  takeoverDetector,
		portScanner:       portScanner,
		vulnCorrelator:    vulnCorrelator,
		ctLogClient:       ctLogClient,
		techFingerprinter: techFingerprinter,
		passiveDNSClient:  passiveDNSClient,
		ipv6Discoverer:    ipv6Discoverer,
		discoveredAssets:  make(map[string]bool),
		maxRecursion:      3,
		cache:             apiCache,
		rateLimiter:       rateLimiter,
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

	// FIXME: Recursive discovery is too broad for bug bounty
	// TODO: Only recurse on high-value assets (login, api, admin)
	if e.recursionDepth < e.maxRecursion {
		// TODO: Filter assets before recursing
		e.recursiveDiscovery(ctx, result)
	}

	// TODO: This is good for bug bounty! Move to vulnerability testing phase
	// Check for subdomain takeover vulnerabilities
	e.checkSubdomainTakeovers(ctx, result)

	// TODO: Port scanning is good but needs optimization
	// FIXME: Only scan common web/api ports for bug bounty
	// Perform port scanning on discovered assets
	e.portScanDiscovery(ctx, result)

	// Perform technology stack fingerprinting
	e.techStackFingerprinting(ctx, result)

	// Correlate vulnerabilities with discovered assets
	e.vulnerabilityCorrelation(ctx, result)

	e.logger.Info("Enhanced discovery completed",
		"target", target.Value,
		"assets_found", len(result.Assets),
		"relationships", len(result.Relationships))

	return result, nil
}

// discoverDomain performs comprehensive domain discovery
func (e *EnhancedDiscovery) discoverDomain(ctx context.Context, domain string, result *DiscoveryResult) {
	var wg sync.WaitGroup

	// FIXME: DNS brute-forcing is too slow for bug bounty
	// TODO: Only run if --deep flag is set
	if e.config.EnableDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// TODO: Add timeout context - max 10 seconds
			e.dnsBruteforce(ctx, domain, result)
		}()
	}

	// FIXME: Skip search engine discovery for bug bounty - not needed
	// TODO: Only enable if user has API keys configured
	if e.config.EnableSearch {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// FIXME: This takes too long and rarely finds vulns
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

	// Cloud provider discovery
	wg.Add(3)
	go func() {
		defer wg.Done()
		e.awsDiscovery(ctx, domain, result)
	}()
	go func() {
		defer wg.Done()
		e.azureDiscovery(ctx, domain, result)
	}()
	go func() {
		defer wg.Done()
		e.gcpDiscovery(ctx, domain, result)
	}()

	// Certificate Transparency log discovery
	if e.config.EnableCertLog {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.certLogDiscovery(ctx, domain, result)
		}()
	}

	// Passive DNS discovery
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.passiveDNSDiscovery(ctx, domain, result)
	}()

	// IPv6 discovery
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.ipv6Discovery(ctx, domain, result)
	}()

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
				Type:         AssetTypeSubdomain,
				Value:        sub.Subdomain,
				Domain:       domain,
				IP:           strings.Join(sub.IPs, ","), // Store multiple IPs as comma-separated
				Source:       "dns_bruteforce",
				Confidence:   0.9,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
				Metadata:     make(map[string]string),
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
				Type:         assetType,
				Value:        d,
				Domain:       domain,
				Source:       "search_engine",
				Confidence:   0.7,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
				Metadata:     map[string]string{"discovery_method": "google_dork"},
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
				Type:         AssetTypeURL,
				Value:        crawl.URL,
				Title:        crawl.Title,
				Technology:   crawl.Technologies,
				Source:       "web_crawler",
				Confidence:   0.95,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
				Metadata: map[string]string{
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
					Type:         AssetTypeSubdomain,
					Value:        subdomain,
					Source:       "web_crawler",
					Confidence:   0.8,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata:     map[string]string{"found_on": crawl.URL},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(subdomain)
			}
		}

		// Add APIs
		for _, api := range crawl.APIs {
			if !e.isAlreadyDiscovered(api) {
				asset := &Asset{
					Type:         AssetTypeAPI,
					Value:        api,
					Source:       "web_crawler",
					Confidence:   0.85,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata:     map[string]string{"found_on": crawl.URL},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(api)
			}
		}

		// Add emails
		for _, email := range crawl.Emails {
			if !e.isAlreadyDiscovered(email) {
				asset := &Asset{
					Type:         AssetTypeEmail,
					Value:        email,
					Source:       "web_crawler",
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata:     map[string]string{"found_on": crawl.URL},
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
				Type:         AssetTypeDomain,
				Value:        related,
				Source:       "whois",
				Confidence:   0.75,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
				Metadata: map[string]string{
					"registrant_org": whoisResult.RegistrantOrg,
					"registrar":      whoisResult.Registrar,
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
				Type:         AssetTypeEmail,
				Value:        email,
				Source:       "whois",
				Confidence:   0.9,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
				Metadata: map[string]string{
					"domain":         domain,
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
				Type:         AssetTypeIP,
				Value:        host.IP,
				Domain:       domain,
				IP:           host.IP,
				Source:       "shodan",
				Confidence:   0.95,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
				Metadata: map[string]string{
					"asn":     host.ASN,
					"isp":     host.ISP,
					"org":     host.Org,
					"country": host.Country,
					"city":    host.City,
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
					Type:         assetType,
					Value:        hostname,
					Domain:       domain,
					IP:           host.IP,
					Source:       "shodan",
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
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
				Type:         AssetTypeIP,
				Value:        hit.IP,
				Domain:       domain,
				IP:           hit.IP,
				Source:       "censys",
				Confidence:   0.95,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
				Metadata: map[string]string{
					"asn":     fmt.Sprintf("%d", hit.AutonomousSystem.ASN),
					"as_name": hit.AutonomousSystem.Name,
					"country": hit.Location.Country,
					"city":    hit.Location.City,
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

// awsDiscovery discovers AWS assets for a domain
func (e *EnhancedDiscovery) awsDiscovery(ctx context.Context, domain string, result *DiscoveryResult) {
	// Rate limit AWS API calls
	if err := e.rateLimiter.Wait(ctx, "aws"); err != nil {
		e.logger.Error("AWS rate limit error", "error", err)
		return
	}

	// Discover S3 buckets
	buckets, err := e.awsClient.DiscoverS3Buckets(ctx, domain)
	if err != nil {
		e.logger.Error("AWS S3 discovery failed", "domain", domain, "error", err)
	} else {
		for _, bucket := range buckets {
			if !e.isAlreadyDiscovered(bucket.Name) {
				asset := &Asset{
					Type:         AssetTypeCloudStorage,
					Value:        bucket.Name,
					Domain:       domain,
					Source:       "aws_s3",
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"provider":    "aws",
						"service":     "s3",
						"url":         bucket.URL,
						"region":      bucket.Region,
						"public":      fmt.Sprintf("%v", bucket.IsPublic),
						"has_listing": fmt.Sprintf("%v", bucket.HasListing),
					},
				}

				if bucket.IsPublic {
					asset.Tags = append(asset.Tags, "public", "exposed")
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(bucket.Name)
			}
		}
	}

	// Discover CloudFront distributions
	distributions, err := e.awsClient.DiscoverCloudFront(ctx, domain)
	if err != nil {
		e.logger.Error("AWS CloudFront discovery failed", "domain", domain, "error", err)
	} else {
		for _, dist := range distributions {
			if !e.isAlreadyDiscovered(dist.Domain) {
				asset := &Asset{
					Type:         AssetTypeCDN,
					Value:        dist.Domain,
					Domain:       domain,
					Source:       "aws_cloudfront",
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"provider": "aws",
						"service":  "cloudfront",
						"active":   fmt.Sprintf("%v", dist.IsActive),
					},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(dist.Domain)
			}
		}
	}

	// Discover Elastic Beanstalk apps
	ebApps, err := e.awsClient.DiscoverElasticBeanstalk(ctx, domain)
	if err != nil {
		e.logger.Error("AWS Elastic Beanstalk discovery failed", "domain", domain, "error", err)
	} else {
		for _, app := range ebApps {
			if !e.isAlreadyDiscovered(app.URL) {
				asset := &Asset{
					Type:         AssetTypeWebApp,
					Value:        app.URL,
					Domain:       domain,
					Source:       "aws_elastic_beanstalk",
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"provider": "aws",
						"service":  "elastic_beanstalk",
						"app_name": app.Name,
						"region":   app.Region,
					},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(app.URL)
			}
		}
	}

	// Discover Lambda functions
	lambdas, err := e.awsClient.DiscoverLambdaFunctions(ctx, domain)
	if err != nil {
		e.logger.Error("AWS Lambda discovery failed", "domain", domain, "error", err)
	} else {
		for _, lambda := range lambdas {
			if !e.isAlreadyDiscovered(lambda.URL) {
				asset := &Asset{
					Type:         AssetTypeAPI,
					Value:        lambda.URL,
					Domain:       domain,
					Source:       "aws_lambda",
					Confidence:   0.8,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"provider":      "aws",
						"service":       "lambda",
						"function_name": lambda.Name,
						"region":        lambda.Region,
					},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(lambda.URL)
			}
		}
	}
}

// azureDiscovery discovers Azure assets for a domain
func (e *EnhancedDiscovery) azureDiscovery(ctx context.Context, domain string, result *DiscoveryResult) {
	// Rate limit Azure API calls
	if err := e.rateLimiter.Wait(ctx, "azure"); err != nil {
		e.logger.Error("Azure rate limit error", "error", err)
		return
	}

	// Discover Blob containers
	containers, err := e.azureClient.DiscoverBlobContainers(ctx, domain)
	if err != nil {
		e.logger.Error("Azure Blob discovery failed", "domain", domain, "error", err)
	} else {
		for _, container := range containers {
			containerID := fmt.Sprintf("%s/%s", container.AccountName, container.ContainerName)
			if !e.isAlreadyDiscovered(containerID) {
				asset := &Asset{
					Type:         AssetTypeCloudStorage,
					Value:        containerID,
					Domain:       domain,
					Source:       "azure_blob",
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"provider":    "azure",
						"service":     "blob_storage",
						"account":     container.AccountName,
						"container":   container.ContainerName,
						"url":         container.URL,
						"public":      fmt.Sprintf("%v", container.IsPublic),
						"has_listing": fmt.Sprintf("%v", container.HasListing),
					},
				}

				if container.IsPublic {
					asset.Tags = append(asset.Tags, "public", "exposed")
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(containerID)
			}
		}
	}

	// Discover Azure Apps
	apps, err := e.azureClient.DiscoverAzureApps(ctx, domain)
	if err != nil {
		e.logger.Error("Azure App discovery failed", "domain", domain, "error", err)
	} else {
		for _, app := range apps {
			if !e.isAlreadyDiscovered(app.URL) {
				asset := &Asset{
					Type:         AssetTypeWebApp,
					Value:        app.URL,
					Domain:       domain,
					Source:       "azure_app_service",
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"provider": "azure",
						"service":  app.Type,
						"app_name": app.Name,
					},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(app.URL)
			}
		}
	}

	// Discover Container Registries
	registries, err := e.azureClient.DiscoverAzureContainerRegistry(ctx, domain)
	if err != nil {
		e.logger.Error("Azure Container Registry discovery failed", "domain", domain, "error", err)
	} else {
		for _, registry := range registries {
			if !e.isAlreadyDiscovered(registry.URL) {
				asset := &Asset{
					Type:         AssetTypeContainerRegistry,
					Value:        registry.URL,
					Domain:       domain,
					Source:       "azure_container_registry",
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"provider":      "azure",
						"service":       "container_registry",
						"registry_name": registry.Name,
						"public":        fmt.Sprintf("%v", registry.IsPublic),
					},
				}

				if registry.IsPublic {
					asset.Tags = append(asset.Tags, "public")
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(registry.URL)
			}
		}
	}

	// Discover Azure Functions
	functions, err := e.azureClient.DiscoverAzureFunctions(ctx, domain)
	if err != nil {
		e.logger.Error("Azure Functions discovery failed", "domain", domain, "error", err)
	} else {
		for _, function := range functions {
			if !e.isAlreadyDiscovered(function.URL) {
				asset := &Asset{
					Type:         AssetTypeAPI,
					Value:        function.URL,
					Domain:       domain,
					Source:       "azure_functions",
					Confidence:   0.8,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"provider":     "azure",
						"service":      "functions",
						"function_app": function.Name,
					},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(function.URL)
			}
		}
	}
}

// gcpDiscovery discovers GCP assets for a domain
func (e *EnhancedDiscovery) gcpDiscovery(ctx context.Context, domain string, result *DiscoveryResult) {
	// Rate limit GCP API calls
	if err := e.rateLimiter.Wait(ctx, "gcp"); err != nil {
		e.logger.Error("GCP rate limit error", "error", err)
		return
	}

	// Discover GCS buckets
	buckets, err := e.gcpClient.DiscoverGCSBuckets(ctx, domain)
	if err != nil {
		e.logger.Error("GCP GCS discovery failed", "domain", domain, "error", err)
	} else {
		for _, bucket := range buckets {
			if !e.isAlreadyDiscovered(bucket.Name) {
				asset := &Asset{
					Type:         AssetTypeCloudStorage,
					Value:        bucket.Name,
					Domain:       domain,
					Source:       "gcp_gcs",
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"provider":    "gcp",
						"service":     "cloud_storage",
						"url":         bucket.URL,
						"public":      fmt.Sprintf("%v", bucket.IsPublic),
						"has_listing": fmt.Sprintf("%v", bucket.HasListing),
					},
				}

				if bucket.IsPublic {
					asset.Tags = append(asset.Tags, "public", "exposed")
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(bucket.Name)
			}
		}
	}

	// Discover App Engine apps
	appEngines, err := e.gcpClient.DiscoverAppEngine(ctx, domain)
	if err != nil {
		e.logger.Error("GCP App Engine discovery failed", "domain", domain, "error", err)
	} else {
		for _, app := range appEngines {
			if !e.isAlreadyDiscovered(app.URL) {
				asset := &Asset{
					Type:         AssetTypeWebApp,
					Value:        app.URL,
					Domain:       domain,
					Source:       "gcp_app_engine",
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"provider":   "gcp",
						"service":    "app_engine",
						"project_id": app.ProjectID,
						"region":     app.Region,
					},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(app.URL)
			}
		}
	}

	// Discover Cloud Run services
	cloudRuns, err := e.gcpClient.DiscoverCloudRun(ctx, domain)
	if err != nil {
		e.logger.Error("GCP Cloud Run discovery failed", "domain", domain, "error", err)
	} else {
		for _, service := range cloudRuns {
			if !e.isAlreadyDiscovered(service.URL) {
				asset := &Asset{
					Type:         AssetTypeWebApp,
					Value:        service.URL,
					Domain:       domain,
					Source:       "gcp_cloud_run",
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"provider":     "gcp",
						"service":      "cloud_run",
						"service_name": service.Name,
						"region":       service.Region,
					},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(service.URL)
			}
		}
	}

	// Discover Cloud Functions
	cloudFunctions, err := e.gcpClient.DiscoverCloudFunctions(ctx, domain)
	if err != nil {
		e.logger.Error("GCP Cloud Functions discovery failed", "domain", domain, "error", err)
	} else {
		for _, function := range cloudFunctions {
			if !e.isAlreadyDiscovered(function.URL) {
				asset := &Asset{
					Type:         AssetTypeAPI,
					Value:        function.URL,
					Domain:       domain,
					Source:       "gcp_cloud_functions",
					Confidence:   0.8,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"provider":      "gcp",
						"service":       "cloud_functions",
						"function_name": function.Name,
						"project_id":    function.ProjectID,
						"region":        function.Region,
					},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(function.URL)
			}
		}
	}

	// Discover Firebase apps
	firebaseApps, err := e.gcpClient.DiscoverFirebaseApps(ctx, domain)
	if err != nil {
		e.logger.Error("GCP Firebase discovery failed", "domain", domain, "error", err)
	} else {
		for _, app := range firebaseApps {
			if !e.isAlreadyDiscovered(app.URL) {
				asset := &Asset{
					Type:         AssetTypeWebApp,
					Value:        app.URL,
					Domain:       domain,
					Source:       "gcp_firebase",
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"provider":      "gcp",
						"service":       "firebase",
						"project_id":    app.ProjectID,
						"firebase_type": app.Type,
					},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(app.URL)
			}
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
				Type:         AssetTypeOrganization,
				Value:        ipWhois.Organization,
				Source:       "whois",
				Confidence:   0.8,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
				Metadata: map[string]string{
					"ip":       ip,
					"asn":      ipWhois.ASN,
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
					Type:         AssetTypeDomain,
					Value:        name,
					IP:           ip,
					Source:       "reverse_dns",
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata:     map[string]string{"ip": ip},
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
						Type:         AssetTypeDomain,
						Value:        hostname,
						IP:           ip,
						Source:       "shodan",
						Confidence:   0.9,
						DiscoveredAt: time.Now(),
						LastSeen:     time.Now(),
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
			Type:         AssetTypeOrganization,
			Value:        asnInfo.Organization,
			Source:       "asn",
			Confidence:   0.85,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
			Metadata: map[string]string{
				"asn":     fmt.Sprintf("AS%d", asn),
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
				Type:         AssetTypeIPRange,
				Value:        prefix,
				Source:       "asn",
				Confidence:   0.95,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
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
					Type:         AssetTypeDomain,
					Value:        domain,
					Source:       "search_engine",
					Confidence:   0.6,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata:     map[string]string{"company": company},
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
						Type:         AssetTypeIP,
						Value:        host.IP,
						IP:           host.IP,
						Source:       "shodan",
						Confidence:   0.8,
						DiscoveredAt: time.Now(),
						LastSeen:     time.Now(),
						Metadata: map[string]string{
							"org":            host.Org,
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
			Type:         AssetTypeDomain,
			Value:        domain,
			Source:       "email",
			Confidence:   0.95,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
			Metadata:     map[string]string{"email": email},
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
		Type:         AssetTypeIPRange,
		Value:        ipRange,
		Source:       "input",
		Confidence:   1.0,
		DiscoveredAt: time.Now(),
		LastSeen:     time.Now(),
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

// checkSubdomainTakeovers checks discovered subdomains for takeover vulnerabilities
func (e *EnhancedDiscovery) checkSubdomainTakeovers(ctx context.Context, result *DiscoveryResult) {
	var subdomains []string

	// Collect all subdomains from results
	for _, asset := range result.Assets {
		if asset.Type == AssetTypeSubdomain || asset.Type == AssetTypeDomain {
			subdomains = append(subdomains, asset.Value)
		}
	}

	if len(subdomains) == 0 {
		return
	}

	e.logger.Infow("Checking subdomains for takeover vulnerabilities", "count", len(subdomains))

	// Check for takeovers
	takeovers, err := e.takeoverDetector.BulkCheck(ctx, subdomains)
	if err != nil {
		e.logger.Error("Subdomain takeover check failed", "error", err)
		return
	}

	// Add vulnerable subdomains as special assets
	for _, takeover := range takeovers {
		if takeover.Vulnerable {
			vulnAsset := &Asset{
				Type:         AssetTypeVulnerability,
				Value:        fmt.Sprintf("Subdomain Takeover: %s", takeover.Subdomain),
				Domain:       takeover.Subdomain,
				Source:       "takeover_detector",
				Confidence:   0.95,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
				Tags:         []string{"vulnerability", "takeover", takeover.Severity},
				Metadata: map[string]string{
					"subdomain":     takeover.Subdomain,
					"service":       takeover.Service,
					"cname":         takeover.CNAME,
					"severity":      takeover.Severity,
					"documentation": takeover.Documentation,
					"evidence":      strings.Join(takeover.Evidence, "; "),
				},
			}

			result.Assets = append(result.Assets, vulnAsset)

			// Create relationship between subdomain and vulnerability
			rel := &Relationship{
				ID:     fmt.Sprintf("takeover-%s", takeover.Subdomain),
				Source: takeover.Subdomain,
				Target: vulnAsset.Value,
				Type:   RelationTypeVulnerability,
				Weight: 1.0,
				Metadata: map[string]string{
					"vulnerability_type": "subdomain_takeover",
					"service":            takeover.Service,
				},
				CreatedAt: time.Now(),
			}

			result.Relationships = append(result.Relationships, rel)
		}
	}

	if len(takeovers) > 0 {
		e.logger.Info("Subdomain takeover vulnerabilities found",
			"vulnerable", len(takeovers),
			"total_checked", len(subdomains))
	}
}

// portScanDiscovery performs port scanning on discovered IPs and domains
func (e *EnhancedDiscovery) portScanDiscovery(ctx context.Context, result *DiscoveryResult) {
	if !e.config.EnablePortScan || e.portScanner == nil {
		return
	}

	// Collect unique IPs and domains to scan
	var targets []string
	seen := make(map[string]bool)

	for _, asset := range result.Assets {
		var target string

		switch asset.Type {
		case AssetTypeIP:
			target = asset.Value
		case AssetTypeDomain, AssetTypeSubdomain:
			// Resolve domain to IP first
			ips, err := net.LookupHost(asset.Value)
			if err != nil || len(ips) == 0 {
				continue
			}
			target = ips[0]
			asset.IP = target // Update asset with resolved IP
		default:
			continue
		}

		if !seen[target] {
			seen[target] = true
			targets = append(targets, target)
		}
	}

	if len(targets) == 0 {
		return
	}

	e.logger.Infow("Starting port scan on discovered assets", "targets", len(targets))

	// Perform port scanning
	scanResults, err := e.portScanner.ScanHosts(ctx, targets)
	if err != nil {
		e.logger.Error("Port scanning failed", "error", err)
		return
	}

	// Process scan results
	for _, scanResult := range scanResults {
		for _, port := range scanResult.OpenPorts {
			// Create a Port/Service asset for each open port
			portAsset := &Asset{
				Type:         AssetTypePort,
				Value:        fmt.Sprintf("%s:%d", scanResult.Host, port.Port),
				IP:           scanResult.Host,
				Port:         port.Port,
				Protocol:     "tcp",
				Source:       "port_scan",
				Confidence:   0.95,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
				Metadata: map[string]string{
					"service": port.Service,
					"banner":  port.Banner,
				},
			}

			// Check if it's a web service
			if isWebPort(port.Port) {
				portAsset.Tags = append(portAsset.Tags, "web", "http")

				// Create URL asset for web services
				scheme := "http"
				if port.Port == 443 || port.Port == 8443 {
					scheme = "https"
				}

				urlAsset := &Asset{
					Type:         AssetTypeURL,
					Value:        fmt.Sprintf("%s://%s:%d", scheme, scanResult.Host, port.Port),
					IP:           scanResult.Host,
					Port:         port.Port,
					Source:       "port_scan",
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Tags:         []string{"web", "discovered"},
				}

				result.Assets = append(result.Assets, urlAsset)
			}

			// Check for high-value services
			if isHighValuePort(port.Port) {
				portAsset.Priority = int(PriorityHigh)
				portAsset.Tags = append(portAsset.Tags, "high-value")
			}

			result.Assets = append(result.Assets, portAsset)
		}
	}

	e.logger.Info("Port scan completed",
		"hosts_scanned", len(scanResults),
		"ports_discovered", countOpenPorts(scanResults))
}

// Helper function to check if port is a web service
func isWebPort(port int) bool {
	webPorts := map[int]bool{
		80: true, 443: true, 8080: true, 8443: true,
		8000: true, 8001: true, 8008: true, 8088: true,
		8888: true, 3000: true, 3001: true, 4000: true,
		4443: true, 5000: true, 5001: true, 7000: true,
		7001: true, 9000: true, 9001: true, 9090: true,
		9443: true, 10000: true, 10443: true,
	}
	return webPorts[port]
}

// Helper function to check if port is high-value
func isHighValuePort(port int) bool {
	highValuePorts := map[int]bool{
		22:    true, // SSH
		23:    true, // Telnet
		25:    true, // SMTP
		110:   true, // POP3
		143:   true, // IMAP
		389:   true, // LDAP
		445:   true, // SMB
		1433:  true, // MSSQL
		3306:  true, // MySQL
		3389:  true, // RDP
		5432:  true, // PostgreSQL
		5900:  true, // VNC
		27017: true, // MongoDB
	}
	return highValuePorts[port]
}

// Helper function to count open ports
func countOpenPorts(results []*portscan.HostScanResult) int {
	count := 0
	for _, result := range results {
		count += len(result.OpenPorts)
	}
	return count
}

// certLogDiscovery discovers subdomains and certificates from CT logs
func (e *EnhancedDiscovery) certLogDiscovery(ctx context.Context, domain string, result *DiscoveryResult) {
	if e.ctLogClient == nil {
		return
	}

	e.logger.Infow("Starting Certificate Transparency log discovery", "domain", domain)

	// Discover subdomains from CT logs
	subdomains, err := e.ctLogClient.DiscoverSubdomains(ctx, domain)
	if err != nil {
		e.logger.Error("CT log subdomain discovery failed", "domain", domain, "error", err)
	} else {
		for _, subdomain := range subdomains {
			if !e.isAlreadyDiscovered(subdomain) {
				asset := &Asset{
					Type:         AssetTypeSubdomain,
					Value:        subdomain,
					Domain:       domain,
					Source:       "ct_logs",
					Confidence:   0.95,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"discovery_method": "certificate_transparency",
					},
					Tags: []string{"ct-discovered"},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(subdomain)
			}
		}

		e.logger.Info("CT log subdomain discovery completed",
			"domain", domain,
			"subdomains_found", len(subdomains))
	}

	// Analyze certificate history
	certHistory, err := e.ctLogClient.AnalyzeCertificateHistory(ctx, domain)
	if err != nil {
		e.logger.Error("Certificate history analysis failed", "domain", domain, "error", err)
		return
	}

	// Create certificate assets
	certs, err := e.ctLogClient.GetCertificateTimeline(ctx, domain)
	if err != nil {
		e.logger.Error("Failed to get certificate timeline", "domain", domain, "error", err)
	} else {
		for _, cert := range certs {
			certAsset := &Asset{
				Type:         AssetTypeCertificate,
				Value:        fmt.Sprintf("%s [%s]", cert.SubjectCN, cert.SerialNumber),
				Domain:       domain,
				Source:       "ct_logs",
				Confidence:   1.0,
				DiscoveredAt: cert.LogEntry.DiscoveredAt,
				LastSeen:     time.Now(),
				Metadata: map[string]string{
					"subject_cn":    cert.SubjectCN,
					"issuer":        cert.Issuer,
					"serial_number": cert.SerialNumber,
					"not_before":    cert.NotBefore.Format(time.RFC3339),
					"not_after":     cert.NotAfter.Format(time.RFC3339),
					"log_server":    cert.LogEntry.LogServer,
				},
			}

			// Add SANs to metadata
			if len(cert.SANs) > 0 {
				for i, san := range cert.SANs {
					if i < 5 { // Limit to first 5 SANs
						certAsset.Metadata[fmt.Sprintf("san_%d", i+1)] = san
					}
				}
				certAsset.Metadata["total_sans"] = fmt.Sprintf("%d", len(cert.SANs))
			}

			// Tag expired or soon-to-expire certificates
			now := time.Now()
			if cert.NotAfter.Before(now) {
				certAsset.Tags = append(certAsset.Tags, "expired")
			} else if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
				certAsset.Tags = append(certAsset.Tags, "expiring-soon")
			}

			result.Assets = append(result.Assets, certAsset)
		}
	}

	// Add certificate history analysis as metadata
	if certHistory != nil {
		historyAsset := &Asset{
			Type:         AssetTypeMetadata,
			Value:        fmt.Sprintf("Certificate History: %s", domain),
			Domain:       domain,
			Source:       "ct_logs",
			Confidence:   1.0,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
			Metadata: map[string]string{
				"total_certificates": fmt.Sprintf("%d", certHistory.TotalCerts),
				"active_certs":       fmt.Sprintf("%d", certHistory.ActiveCerts),
				"expired_certs":      fmt.Sprintf("%d", certHistory.ExpiredCerts),
			},
		}

		// Add issuer statistics
		for issuer, count := range certHistory.UniqueIssuers {
			if count > 1 {
				historyAsset.Metadata[fmt.Sprintf("issuer_%s", strings.ReplaceAll(issuer, " ", "_"))] = fmt.Sprintf("%d", count)
			}
		}

		result.Assets = append(result.Assets, historyAsset)
	}

	// Find wildcard certificates
	wildcardCerts, err := e.ctLogClient.FindWildcardCerts(ctx, domain)
	if err != nil {
		e.logger.Error("Failed to find wildcard certificates", "domain", domain, "error", err)
	} else {
		for _, cert := range wildcardCerts {
			// Wildcard certificates might expose additional subdomains
			for _, san := range cert.SANs {
				if strings.HasPrefix(san, "*.") {
					baseDomain := strings.TrimPrefix(san, "*.")
					if !e.isAlreadyDiscovered(baseDomain) {
						wildcardAsset := &Asset{
							Type:         AssetTypeDomain,
							Value:        baseDomain,
							Domain:       domain,
							Source:       "ct_logs_wildcard",
							Confidence:   0.8,
							DiscoveredAt: time.Now(),
							LastSeen:     time.Now(),
							Metadata: map[string]string{
								"wildcard_cert": "true",
								"issuer":        cert.Issuer,
							},
							Tags: []string{"wildcard-domain"},
						}
						result.Assets = append(result.Assets, wildcardAsset)
						e.markAsDiscovered(baseDomain)
					}
				}
			}
		}
	}
}

// passiveDNSDiscovery discovers assets using passive DNS data
func (e *EnhancedDiscovery) passiveDNSDiscovery(ctx context.Context, domain string, result *DiscoveryResult) {
	if e.passiveDNSClient == nil {
		return
	}

	e.logger.Infow("Starting passive DNS discovery", "domain", domain)

	// Discover subdomains via passive DNS
	subdomains, err := e.passiveDNSClient.DiscoverSubdomains(ctx, domain)
	if err != nil {
		e.logger.Error("Passive DNS subdomain discovery failed", "domain", domain, "error", err)
	} else {
		for _, subdomain := range subdomains {
			if !e.isAlreadyDiscovered(subdomain) {
				asset := &Asset{
					Type:         AssetTypeSubdomain,
					Value:        subdomain,
					Domain:       domain,
					Source:       "passive_dns",
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"discovery_method": "passive_dns",
					},
					Tags: []string{"passive-dns"},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(subdomain)
			}
		}

		e.logger.Info("Passive DNS subdomain discovery completed",
			"domain", domain,
			"subdomains_found", len(subdomains))
	}

	// Discover IP history
	ipHistory, err := e.passiveDNSClient.DiscoverIPHistory(ctx, domain)
	if err != nil {
		e.logger.Error("Passive DNS IP history discovery failed", "domain", domain, "error", err)
	} else {
		for _, ip := range ipHistory {
			if !e.isAlreadyDiscovered(ip) {
				asset := &Asset{
					Type:         AssetTypeIP,
					Value:        ip,
					Domain:       domain,
					IP:           ip,
					Source:       "passive_dns_history",
					Confidence:   0.8,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"discovery_method":  "passive_dns_history",
						"associated_domain": domain,
					},
					Tags: []string{"passive-dns", "historical"},
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(ip)
			}
		}

		e.logger.Info("Passive DNS IP history discovery completed",
			"domain", domain,
			"ips_found", len(ipHistory))
	}

	// Get DNS timeline for analysis
	timeline, err := e.passiveDNSClient.GetDNSTimeline(ctx, domain)
	if err != nil {
		e.logger.Error("Failed to get DNS timeline", "domain", domain, "error", err)
	} else {
		// Create timeline analysis asset
		if len(timeline) > 0 {
			timelineAsset := &Asset{
				Type:         AssetTypeMetadata,
				Value:        fmt.Sprintf("DNS Timeline: %s", domain),
				Domain:       domain,
				Source:       "passive_dns_timeline",
				Confidence:   1.0,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
				Metadata: map[string]string{
					"total_records": fmt.Sprintf("%d", len(timeline)),
				},
			}

			// Add timeline statistics
			recordTypes := make(map[string]int)
			sources := make(map[string]int)

			for _, record := range timeline {
				recordTypes[record.Type]++
				sources[record.Source]++
			}

			// Add record type counts
			for recordType, count := range recordTypes {
				timelineAsset.Metadata[fmt.Sprintf("records_%s", strings.ToLower(recordType))] = fmt.Sprintf("%d", count)
			}

			// Add source counts
			for source, count := range sources {
				timelineAsset.Metadata[fmt.Sprintf("source_%s", strings.ToLower(source))] = fmt.Sprintf("%d", count)
			}

			// Add first and last seen
			if len(timeline) > 0 {
				timelineAsset.Metadata["earliest_record"] = timeline[len(timeline)-1].FirstSeen.Format(time.RFC3339)
				timelineAsset.Metadata["latest_record"] = timeline[0].LastSeen.Format(time.RFC3339)
			}

			result.Assets = append(result.Assets, timelineAsset)
		}
	}

	// Get detailed passive DNS data
	dnsResults, err := e.passiveDNSClient.QueryDomain(ctx, domain)
	if err != nil {
		e.logger.Error("Passive DNS query failed", "domain", domain, "error", err)
		return
	}

	// Process DNS records for additional assets
	for _, dnsResult := range dnsResults {
		for _, record := range dnsResult.Records {
			// Create DNS record assets for high-value records
			if record.Type == "A" || record.Type == "CNAME" || record.Type == "MX" {
				recordAsset := &Asset{
					Type:         AssetTypeMetadata,
					Value:        fmt.Sprintf("%s -> %s", record.Query, record.Answer),
					Domain:       domain,
					Source:       fmt.Sprintf("passive_dns_%s", strings.ToLower(record.Source)),
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     record.LastSeen,
					Metadata: map[string]string{
						"record_type":  record.Type,
						"query":        record.Query,
						"answer":       record.Answer,
						"ttl":          fmt.Sprintf("%d", record.TTL),
						"source":       record.Source,
						"first_seen":   record.FirstSeen.Format(time.RFC3339),
						"last_seen":    record.LastSeen.Format(time.RFC3339),
						"record_count": fmt.Sprintf("%d", record.Count),
					},
					Tags: []string{"dns-record", strings.ToLower(record.Type)},
				}

				// Tag records by age
				daysSinceLastSeen := int(time.Since(record.LastSeen).Hours() / 24)
				if daysSinceLastSeen <= 30 {
					recordAsset.Tags = append(recordAsset.Tags, "recent")
				} else if daysSinceLastSeen <= 365 {
					recordAsset.Tags = append(recordAsset.Tags, "historical")
				} else {
					recordAsset.Tags = append(recordAsset.Tags, "old")
				}

				result.Assets = append(result.Assets, recordAsset)
			}

			// Extract additional domains/IPs from records
			switch record.Type {
			case "MX":
				if !e.isAlreadyDiscovered(record.Answer) {
					mailAsset := &Asset{
						Type:         AssetTypeMailServer,
						Value:        record.Answer,
						Domain:       domain,
						Source:       "passive_dns_mx",
						Confidence:   0.9,
						DiscoveredAt: time.Now(),
						LastSeen:     record.LastSeen,
						Metadata: map[string]string{
							"mx_record": record.Query,
						},
						Tags: []string{"mail-server", "passive-dns"},
					}
					result.Assets = append(result.Assets, mailAsset)
					e.markAsDiscovered(record.Answer)
				}
			case "NS":
				if !e.isAlreadyDiscovered(record.Answer) {
					nsAsset := &Asset{
						Type:         AssetTypeDomain,
						Value:        record.Answer,
						Domain:       domain,
						Source:       "passive_dns_ns",
						Confidence:   0.8,
						DiscoveredAt: time.Now(),
						LastSeen:     record.LastSeen,
						Metadata: map[string]string{
							"nameserver_for": record.Query,
						},
						Tags: []string{"nameserver", "passive-dns"},
					}
					result.Assets = append(result.Assets, nsAsset)
					e.markAsDiscovered(record.Answer)
				}
			}
		}
	}

	e.logger.Info("Passive DNS discovery completed",
		"domain", domain,
		"sources_queried", len(dnsResults))
}

// ipv6Discovery discovers IPv6 addresses and networks
func (e *EnhancedDiscovery) ipv6Discovery(ctx context.Context, domain string, result *DiscoveryResult) {
	if e.ipv6Discoverer == nil {
		return
	}

	e.logger.Infow("Starting IPv6 discovery", "domain", domain)

	// Discover IPv6 addresses for the domain
	ipv6Addresses, err := e.ipv6Discoverer.DiscoverIPv6Addresses(ctx, domain)
	if err != nil {
		e.logger.Error("IPv6 address discovery failed", "domain", domain, "error", err)
	} else {
		for _, ipv6Addr := range ipv6Addresses {
			if !e.isAlreadyDiscovered(ipv6Addr.Address) {
				asset := &Asset{
					Type:         AssetTypeIP,
					Value:        ipv6Addr.Address,
					Domain:       domain,
					IP:           ipv6Addr.Address,
					Source:       fmt.Sprintf("ipv6_%s", ipv6Addr.Source),
					Confidence:   0.9,
					DiscoveredAt: ipv6Addr.Discovered,
					LastSeen:     time.Now(),
					Metadata: map[string]string{
						"ip_version": "6",
						"type":       ipv6Addr.Type,
						"network":    ipv6Addr.Network,
					},
					Tags: []string{"ipv6", strings.ToLower(ipv6Addr.Type)},
				}

				// Analyze the IPv6 address for additional information
				analysis := e.ipv6Discoverer.AnalyzeIPv6Address(ipv6Addr.Address)
				for key, value := range analysis {
					asset.Metadata[fmt.Sprintf("analysis_%s", key)] = value
				}

				// Add transition mechanism info if available
				if mechanism, exists := analysis["transition_mechanism"]; exists {
					asset.Tags = append(asset.Tags, mechanism)
					if embeddedIPv4, hasIPv4 := analysis["embedded_ipv4"]; hasIPv4 {
						asset.Metadata["embedded_ipv4"] = embeddedIPv4
					}
				}

				result.Assets = append(result.Assets, asset)
				e.markAsDiscovered(ipv6Addr.Address)
			}
		}

		e.logger.Info("IPv6 address discovery completed",
			"domain", domain,
			"addresses_found", len(ipv6Addresses))
	}

	// Discover IPv6 networks
	ipv6Networks, err := e.ipv6Discoverer.DiscoverIPv6Networks(ctx, domain)
	if err != nil {
		e.logger.Error("IPv6 network discovery failed", "domain", domain, "error", err)
	} else {
		for _, network := range ipv6Networks {
			networkAsset := &Asset{
				Type:         AssetTypeIPRange,
				Value:        network.Network,
				Domain:       domain,
				Source:       "ipv6_network",
				Confidence:   0.8,
				DiscoveredAt: network.Discovered,
				LastSeen:     time.Now(),
				Metadata: map[string]string{
					"ip_version":    "6",
					"prefix":        fmt.Sprintf("%d", network.Prefix),
					"address_count": fmt.Sprintf("%d", len(network.Addresses)),
					"description":   network.Description,
				},
				Tags: []string{"ipv6", "network"},
			}

			result.Assets = append(result.Assets, networkAsset)
		}
	}

	// For discovered IPv4 addresses, try to find corresponding IPv6 addresses
	for _, asset := range result.Assets {
		if asset.Type == AssetTypeIP && asset.IP != "" && strings.Contains(asset.IP, ".") {
			// This is an IPv4 address, try to find IPv6 transition addresses
			ipv6Transitions, err := e.ipv6Discoverer.DiscoverIPv6FromIPv4(ctx, asset.IP, domain)
			if err != nil {
				continue
			}

			for _, ipv6Trans := range ipv6Transitions {
				if !e.isAlreadyDiscovered(ipv6Trans.Address) {
					transitionAsset := &Asset{
						Type:         AssetTypeIP,
						Value:        ipv6Trans.Address,
						Domain:       domain,
						IP:           ipv6Trans.Address,
						Source:       "ipv6_transition",
						Confidence:   0.7,
						DiscoveredAt: ipv6Trans.Discovered,
						LastSeen:     time.Now(),
						Metadata: map[string]string{
							"ip_version":      "6",
							"type":            ipv6Trans.Type,
							"source_ipv4":     asset.IP,
							"transition_type": ipv6Trans.Type,
						},
						Tags: []string{"ipv6", "transition", ipv6Trans.Type},
					}

					result.Assets = append(result.Assets, transitionAsset)
					e.markAsDiscovered(ipv6Trans.Address)

					// Create relationship between IPv4 and IPv6 transition address
					rel := &Relationship{
						ID:     fmt.Sprintf("ipv6-transition-%s-%s", asset.ID, ipv6Trans.Address),
						Source: asset.ID,
						Target: transitionAsset.ID,
						Type:   RelationTypeNetwork,
						Weight: 0.8,
						Metadata: map[string]string{
							"relationship": "ipv6_transition",
							"type":         ipv6Trans.Type,
						},
						CreatedAt: time.Now(),
					}
					result.Relationships = append(result.Relationships, rel)
				}
			}
		}
	}

	// Perform reverse lookups on discovered IPv6 addresses
	for _, asset := range result.Assets {
		if asset.Type == AssetTypeIP && strings.Contains(asset.IP, ":") {
			// This is an IPv6 address, try reverse lookup
			names, err := e.ipv6Discoverer.ReverseLookupIPv6(ctx, asset.IP)
			if err == nil && len(names) > 0 {
				for i, name := range names {
					if i < 3 && !e.isAlreadyDiscovered(name) { // Limit to 3 names
						reverseAsset := &Asset{
							Type:         AssetTypeDomain,
							Value:        name,
							IP:           asset.IP,
							Source:       "ipv6_reverse",
							Confidence:   0.8,
							DiscoveredAt: time.Now(),
							LastSeen:     time.Now(),
							Metadata: map[string]string{
								"reverse_ip": asset.IP,
							},
							Tags: []string{"reverse-dns", "ipv6"},
						}

						result.Assets = append(result.Assets, reverseAsset)
						e.markAsDiscovered(name)

						// Create relationship
						rel := &Relationship{
							ID:     fmt.Sprintf("ipv6-reverse-%s-%s", asset.ID, name),
							Source: asset.ID,
							Target: reverseAsset.ID,
							Type:   RelationTypeNetwork,
							Weight: 0.9,
							Metadata: map[string]string{
								"relationship": "reverse_dns",
							},
							CreatedAt: time.Now(),
						}
						result.Relationships = append(result.Relationships, rel)
					}
				}
			}
		}
	}

	e.logger.Infow("IPv6 discovery completed", "domain", domain)
}

// techStackFingerprinting performs technology stack fingerprinting on discovered assets
func (e *EnhancedDiscovery) techStackFingerprinting(ctx context.Context, result *DiscoveryResult) {
	if !e.config.EnableTechStack || e.techFingerprinter == nil {
		return
	}

	e.logger.Info("Starting technology stack fingerprinting")

	// Collect URLs to fingerprint
	var urls []string
	urlAssetMap := make(map[string]*Asset)

	for _, asset := range result.Assets {
		switch asset.Type {
		case AssetTypeURL:
			urls = append(urls, asset.Value)
			urlAssetMap[asset.Value] = asset
		case AssetTypeDomain, AssetTypeSubdomain:
			// Try both HTTP and HTTPS
			httpURL := fmt.Sprintf("http://%s", asset.Value)
			httpsURL := fmt.Sprintf("https://%s", asset.Value)

			urls = append(urls, httpURL, httpsURL)
			urlAssetMap[httpURL] = asset
			urlAssetMap[httpsURL] = asset
		case AssetTypePort:
			// Check if it's a web port
			if asset.Port == 80 || asset.Port == 443 || asset.Port == 8080 || asset.Port == 8443 {
				scheme := "http"
				if asset.Port == 443 || asset.Port == 8443 {
					scheme = "https"
				}
				url := fmt.Sprintf("%s://%s:%d", scheme, asset.IP, asset.Port)
				urls = append(urls, url)
				urlAssetMap[url] = asset
			}
		}
	}

	// Fingerprint each URL
	techMap := make(map[string]map[string]*techstack.Technology) // URL -> Tech Name -> Tech
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrent fingerprinting
	sem := make(chan struct{}, 5)

	for _, url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			technologies, err := e.techFingerprinter.FingerprintURL(ctx, u)
			if err != nil {
				e.logger.Debug("Failed to fingerprint URL", "url", u, "error", err)
				return
			}

			mu.Lock()
			if techMap[u] == nil {
				techMap[u] = make(map[string]*techstack.Technology)
			}
			for i := range technologies {
				tech := &technologies[i]
				techMap[u][tech.Name] = tech
			}
			mu.Unlock()
		}(url)
	}

	wg.Wait()

	// Create technology assets
	processedTech := make(map[string]bool)

	for url, technologies := range techMap {
		parentAsset := urlAssetMap[url]

		for _, tech := range technologies {
			// Create unique key for deduplication
			techKey := fmt.Sprintf("%s-%s-%s", tech.Name, tech.Version, parentAsset.Value)

			if processedTech[techKey] {
				continue
			}
			processedTech[techKey] = true

			techAsset := &Asset{
				Type:         AssetTypeTechnology,
				Value:        tech.Name,
				Domain:       parentAsset.Domain,
				Source:       "tech_fingerprint",
				Confidence:   tech.Confidence,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
				Technology:   []string{tech.Name},
				Metadata: map[string]string{
					"category":    tech.Category,
					"version":     tech.Version,
					"website":     tech.Website,
					"detected_on": url,
				},
				Tags: []string{"technology", strings.ToLower(tech.Category)},
			}

			// Add evidence
			for i, evidence := range tech.Evidence {
				if i < 3 { // Limit evidence entries
					techAsset.Metadata[fmt.Sprintf("evidence_%d", i+1)] = evidence
				}
			}

			// Add description if available
			if tech.Description != "" {
				techAsset.Metadata["description"] = tech.Description
			}

			// Mark as high-value for certain categories
			if tech.Category == "CMS" || tech.Category == "Web Framework" || tech.Category == "Database" {
				techAsset.Priority = int(PriorityHigh)
				techAsset.Tags = append(techAsset.Tags, "high-value")
			}

			result.Assets = append(result.Assets, techAsset)

			// Create relationship between technology and parent asset
			rel := &Relationship{
				ID:     fmt.Sprintf("tech-%s-%s", parentAsset.ID, tech.Name),
				Source: parentAsset.ID,
				Target: techAsset.ID,
				Type:   RelationTypeTechnology,
				Weight: tech.Confidence,
				Metadata: map[string]string{
					"technology": tech.Name,
					"category":   tech.Category,
				},
				CreatedAt: time.Now(),
			}
			result.Relationships = append(result.Relationships, rel)

			// Process implied technologies
			for _, impliedTech := range tech.Implies {
				impliedAsset := &Asset{
					Type:         AssetTypeTechnology,
					Value:        impliedTech,
					Domain:       parentAsset.Domain,
					Source:       "tech_implied",
					Confidence:   0.7,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
					Technology:   []string{impliedTech},
					Metadata: map[string]string{
						"implied_by": tech.Name,
					},
					Tags: []string{"technology", "implied"},
				}

				result.Assets = append(result.Assets, impliedAsset)
			}
		}
	}

	// Update original assets with discovered technologies
	for _, asset := range result.Assets {
		if urlTechs, exists := techMap[asset.Value]; exists {
			var techNames []string
			for name := range urlTechs {
				techNames = append(techNames, name)
			}
			asset.Technology = append(asset.Technology, techNames...)
		}
	}

	e.logger.Info("Technology stack fingerprinting completed",
		"urls_scanned", len(urls),
		"technologies_found", len(processedTech))
}

// vulnerabilityCorrelation correlates discovered assets with known vulnerabilities
func (e *EnhancedDiscovery) vulnerabilityCorrelation(ctx context.Context, result *DiscoveryResult) {
	if e.vulnCorrelator == nil {
		return
	}

	e.logger.Infow("Starting vulnerability correlation", "assets", len(result.Assets))

	// Convert assets to interface slice for correlator
	var assetInterfaces []interface{}
	for _, asset := range result.Assets {
		assetInterfaces = append(assetInterfaces, asset)
	}

	// Perform correlation
	findings, err := e.vulnCorrelator.BulkCorrelate(ctx, assetInterfaces)
	if err != nil {
		e.logger.Error("Vulnerability correlation failed", "error", err)
		return
	}

	// Create vulnerability assets for each finding
	for _, finding := range findings {
		vulnAsset := &Asset{
			Type:         AssetTypeVulnerability,
			Value:        fmt.Sprintf("%s - %s", finding.AssetValue, finding.Vulnerability.Name),
			Source:       "vulnerability_correlation",
			Confidence:   finding.Confidence,
			Priority:     severityToPriority(finding.Vulnerability.Severity),
			DiscoveredAt: finding.DiscoveredAt,
			LastSeen:     finding.DiscoveredAt,
			Metadata: map[string]string{
				"vulnerability_id":   finding.Vulnerability.ID,
				"vulnerability_name": finding.Vulnerability.Name,
				"severity":           finding.Vulnerability.Severity,
				"cvss":               fmt.Sprintf("%.1f", finding.Vulnerability.CVSS),
				"category":           finding.Vulnerability.Category,
				"affected_asset":     finding.AssetValue,
			},
			Tags: []string{"vulnerability", strings.ToLower(finding.Vulnerability.Severity)},
		}

		// Add evidence
		for i, evidence := range finding.Evidence {
			vulnAsset.Metadata[fmt.Sprintf("evidence_%d", i+1)] = evidence
		}

		// Add references
		if len(finding.Vulnerability.References) > 0 {
			vulnAsset.Metadata["reference"] = finding.Vulnerability.References[0]
		}

		result.Assets = append(result.Assets, vulnAsset)

		// Create relationship between vulnerable asset and vulnerability
		rel := &Relationship{
			ID:     fmt.Sprintf("vuln-%s-%s", finding.AssetID, finding.Vulnerability.ID),
			Source: finding.AssetID,
			Target: vulnAsset.ID,
			Type:   RelationTypeVulnerability,
			Weight: finding.Confidence,
			Metadata: map[string]string{
				"vulnerability": finding.Vulnerability.ID,
				"severity":      finding.Vulnerability.Severity,
			},
			CreatedAt: time.Now(),
		}
		result.Relationships = append(result.Relationships, rel)
	}

	e.logger.Info("Vulnerability correlation completed",
		"findings", len(findings),
		"critical", countBySeverity(findings, "CRITICAL"),
		"high", countBySeverity(findings, "HIGH"),
		"medium", countBySeverity(findings, "MEDIUM"))
}

// Helper function to convert severity to priority
func severityToPriority(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return int(PriorityCritical)
	case "HIGH":
		return int(PriorityHigh)
	case "MEDIUM":
		return int(PriorityMedium)
	default:
		return int(PriorityLow)
	}
}

// Helper function to count findings by severity
func countBySeverity(findings []*vulnerability.VulnerabilityFinding, severity string) int {
	count := 0
	for _, f := range findings {
		if strings.EqualFold(f.Vulnerability.Severity, severity) {
			count++
		}
	}
	return count
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
