package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/intel/certs"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/intel/cloudflare"
)

// DomainDiscovery discovers assets related to domains
type DomainDiscovery struct {
	config *DiscoveryConfig
	logger *logger.Logger
	client *http.Client
}

// NewDomainDiscovery creates a new domain discovery module
func NewDomainDiscovery(config *DiscoveryConfig, logger *logger.Logger) *DomainDiscovery {
	return &DomainDiscovery{
		config: config,
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}
}

func (d *DomainDiscovery) Name() string  { return "domain_discovery" }
func (d *DomainDiscovery) Priority() int { return 90 }

func (d *DomainDiscovery) CanHandle(target *Target) bool {
	return target.Type == TargetTypeDomain || target.Type == TargetTypeEmail || target.Type == TargetTypeURL
}

func (d *DomainDiscovery) Discover(ctx context.Context, target *Target, session *DiscoverySession) (*DiscoveryResult, error) {
	result := &DiscoveryResult{
		Assets:        []*Asset{},
		Relationships: []*Relationship{},
		Source:        d.Name(),
	}

	// Get the domain to work with
	domain := d.extractDomain(target)
	if domain == "" {
		return result, nil
	}

	d.logger.Debug("Starting domain discovery", "domain", domain)

	// DNS enumeration
	if d.config.EnableDNS {
		dnsAssets := d.dnsEnumeration(domain)
		result.Assets = append(result.Assets, dnsAssets...)
	}

	// Certificate transparency
	if d.config.EnableCertLog {
		certAssets := d.certificateTransparency(domain)
		result.Assets = append(result.Assets, certAssets...)
	}

	// Use organization context if available
	if session.OrgContext != nil {
		// TODO: Implement organization-aware discovery methods
		// d.prioritizeOrgDomains(session.OrgContext.KnownDomains)
		// d.searchEmployeeEmails(domain, session.OrgContext.EmailPatterns)
		// d.checkSubsidiaryDomains(domain, session.OrgContext.Subsidiaries)

		// For now, just log that org context is available
		d.logger.Info("Organization context available for domain discovery",
			"known_domains", len(session.OrgContext.KnownDomains),
			"subsidiaries", len(session.OrgContext.Subsidiaries))
	}

	// Web crawling
	if d.config.EnableWebCrawl {
		webAssets := d.webCrawling(domain)
		result.Assets = append(result.Assets, webAssets...)
	}

	// Cloudflare bypass detection
	if cfAssets := d.checkCloudflareBypass(ctx, domain); len(cfAssets) > 0 {
		result.Assets = append(result.Assets, cfAssets...)
	}

	d.logger.Debug("Domain discovery completed", "domain", domain, "assets_found", len(result.Assets))
	return result, nil
}

func (d *DomainDiscovery) extractDomain(target *Target) string {
	switch target.Type {
	case TargetTypeDomain:
		return target.Value
	case TargetTypeEmail:
		if domain, exists := target.Metadata["domain"]; exists {
			return domain
		}
	case TargetTypeURL:
		if host, exists := target.Metadata["host"]; exists {
			// Remove port if present
			if strings.Contains(host, ":") {
				return strings.Split(host, ":")[0]
			}
			return host
		}
	}
	return ""
}

func (d *DomainDiscovery) dnsEnumeration(domain string) []*Asset {
	var assets []*Asset

	// Common subdomains to check
	subdomains := []string{
		"www", "mail", "ftp", "ssh", "vpn", "remote", "admin", "api", "app",
		"blog", "shop", "store", "portal", "dev", "test", "staging", "prod",
		"m", "mobile", "cdn", "static", "assets", "img", "images", "media",
		"docs", "help", "support", "status", "monitor", "dashboard",
	}

	for _, subdomain := range subdomains {
		fullDomain := subdomain + "." + domain

		// Check if subdomain resolves
		if ips, err := net.LookupIP(fullDomain); err == nil && len(ips) > 0 {
			asset := &Asset{
				Type:         AssetTypeSubdomain,
				Value:        fullDomain,
				Domain:       domain,
				IP:           ips[0].String(),
				Metadata:     map[string]string{"subdomain": subdomain},
				Source:       d.Name(),
				Confidence:   0.9,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
			}
			assets = append(assets, asset)
		}
	}

	// DNS record enumeration
	records := d.enumerateDNSRecords(domain)
	assets = append(assets, records...)

	return assets
}

func (d *DomainDiscovery) enumerateDNSRecords(domain string) []*Asset {
	var assets []*Asset

	// A records
	if ips, err := net.LookupIP(domain); err == nil {
		for _, ip := range ips {
			asset := &Asset{
				Type:         AssetTypeIP,
				Value:        ip.String(),
				Domain:       domain,
				IP:           ip.String(),
				Metadata:     map[string]string{"record_type": "A"},
				Source:       d.Name(),
				Confidence:   0.95,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
			}
			assets = append(assets, asset)
		}
	}

	// MX records
	if mxRecords, err := net.LookupMX(domain); err == nil {
		for _, mx := range mxRecords {
			asset := &Asset{
				Type:         AssetTypeSubdomain,
				Value:        strings.TrimSuffix(mx.Host, "."),
				Domain:       domain,
				Metadata:     map[string]string{"record_type": "MX", "priority": strconv.Itoa(int(mx.Pref))},
				Source:       d.Name(),
				Confidence:   0.9,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
			}
			assets = append(assets, asset)
		}
	}

	// NS records
	if nsRecords, err := net.LookupNS(domain); err == nil {
		for _, ns := range nsRecords {
			asset := &Asset{
				Type:         AssetTypeSubdomain,
				Value:        strings.TrimSuffix(ns.Host, "."),
				Domain:       domain,
				Metadata:     map[string]string{"record_type": "NS"},
				Source:       d.Name(),
				Confidence:   0.8,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
			}
			assets = append(assets, asset)
		}
	}

	return assets
}

func (d *DomainDiscovery) certificateTransparency(domain string) []*Asset {
	var assets []*Asset

	// Use the intel/certs package for enhanced certificate transparency
	certIntel := certs.NewCertIntel(d.logger)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stream certificates for the domain
	certChan := certIntel.StreamCertificates(ctx, domain)

	seen := make(map[string]bool)

	for cert := range certChan {
		// Extract intelligence from certificate
		intel := certIntel.ExtractIntel(cert)

		// Add all discovered domains as assets
		allDomains := append(intel.SubjectAltNames, cert.CommonName)

		// Add internal domains with higher priority
		for _, internalDomain := range intel.InternalDomains {
			if !seen[internalDomain] && d.isValidSubdomain(internalDomain, domain) {
				asset := &Asset{
					Type:   AssetTypeSubdomain,
					Value:  internalDomain,
					Domain: domain,
					Metadata: map[string]string{
						"source":     "certificate_transparency",
						"internal":   "true",
						"issuer":     cert.IssuerName,
						"not_before": cert.NotBefore.Format(time.RFC3339),
						"not_after":  cert.NotAfter.Format(time.RFC3339),
					},
					Source:       d.Name(),
					Confidence:   0.95, // Higher confidence for internal domains
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
				}
				assets = append(assets, asset)
				seen[internalDomain] = true
			}
		}

		// Process all domains from certificate
		for _, name := range allDomains {
			name = strings.TrimSpace(name)
			if name == "" || seen[name] {
				continue
			}

			// Skip wildcard entries
			if strings.HasPrefix(name, "*.") {
				name = name[2:] // Remove *.
			}

			// Validate domain
			if d.isValidSubdomain(name, domain) {
				asset := &Asset{
					Type:   AssetTypeSubdomain,
					Value:  name,
					Domain: domain,
					Metadata: map[string]string{
						"source":     "certificate_transparency",
						"issuer":     cert.IssuerName,
						"not_before": cert.NotBefore.Format(time.RFC3339),
						"not_after":  cert.NotAfter.Format(time.RFC3339),
					},
					Source:       d.Name(),
					Confidence:   0.85,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
				}

				// Add organization info if available
				if cert.Organization != "" {
					asset.Metadata["organization"] = cert.Organization
				}

				assets = append(assets, asset)
				seen[name] = true
			}
		}

		// Extract patterns for future discovery
		if len(intel.WildcardPatterns) > 0 {
			// Store patterns as metadata for the domain asset
			for _, pattern := range intel.WildcardPatterns {
				if pattern.Confidence > 0.7 {
					// This could be used to generate additional discovery targets
					d.logger.Debug("Found wildcard pattern",
						"pattern", pattern.Pattern,
						"confidence", pattern.Confidence,
						"type", pattern.Type)
				}
			}
		}
	}

	return assets
}

func (d *DomainDiscovery) isValidSubdomain(subdomain, baseDomain string) bool {
	if subdomain == baseDomain {
		return false
	}

	return strings.HasSuffix(subdomain, "."+baseDomain) || subdomain == baseDomain
}

func (d *DomainDiscovery) webCrawling(domain string) []*Asset {
	var assets []*Asset

	// Try to fetch the main domain
	urls := []string{
		"https://" + domain,
		"http://" + domain,
		"https://www." + domain,
		"http://www." + domain,
	}

	for _, url := range urls {
		if crawlAssets := d.crawlURL(url, domain); len(crawlAssets) > 0 {
			assets = append(assets, crawlAssets...)
			break // Only crawl the first working URL
		}
	}

	return assets
}

func (d *DomainDiscovery) crawlURL(url, baseDomain string) []*Asset {
	var assets []*Asset

	resp, err := d.client.Get(url)
	if err != nil {
		return assets
	}
	defer resp.Body.Close()

	// Create URL asset
	asset := &Asset{
		Type:         AssetTypeURL,
		Value:        url,
		Domain:       baseDomain,
		Title:        d.extractTitle(resp),
		Technology:   d.detectTechnology(resp),
		Metadata:     map[string]string{"status_code": strconv.Itoa(resp.StatusCode)},
		Source:       d.Name(),
		Confidence:   0.95,
		DiscoveredAt: time.Now(),
		LastSeen:     time.Now(),
	}

	// Extract additional metadata
	if server := resp.Header.Get("Server"); server != "" {
		asset.Metadata["server"] = server
	}
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		asset.Metadata["powered_by"] = powered
	}

	assets = append(assets, asset)

	// TODO: Parse HTML for additional links and assets

	return assets
}

func (d *DomainDiscovery) extractTitle(resp *http.Response) string {
	// Simple title extraction (would need proper HTML parsing in production)
	return ""
}

func (d *DomainDiscovery) detectTechnology(resp *http.Response) []string {
	var technologies []string

	// Detect from headers
	if server := resp.Header.Get("Server"); server != "" {
		if strings.Contains(server, "nginx") {
			technologies = append(technologies, "nginx")
		}
		if strings.Contains(server, "Apache") {
			technologies = append(technologies, "Apache")
		}
		if strings.Contains(server, "IIS") {
			technologies = append(technologies, "IIS")
		}
	}

	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		if strings.Contains(powered, "PHP") {
			technologies = append(technologies, "PHP")
		}
		if strings.Contains(powered, "ASP.NET") {
			technologies = append(technologies, "ASP.NET")
		}
	}

	return technologies
}

// NetworkDiscovery discovers network-related assets
type NetworkDiscovery struct {
	config *DiscoveryConfig
	logger *logger.Logger
}

func NewNetworkDiscovery(config *DiscoveryConfig, logger *logger.Logger) *NetworkDiscovery {
	return &NetworkDiscovery{
		config: config,
		logger: logger,
	}
}

func (n *NetworkDiscovery) Name() string  { return "network_discovery" }
func (n *NetworkDiscovery) Priority() int { return 80 }

func (n *NetworkDiscovery) CanHandle(target *Target) bool {
	return target.Type == TargetTypeIP || target.Type == TargetTypeIPRange
}

func (n *NetworkDiscovery) Discover(ctx context.Context, target *Target, session *DiscoverySession) (*DiscoveryResult, error) {
	result := &DiscoveryResult{
		Assets:        []*Asset{},
		Relationships: []*Relationship{},
		Source:        n.Name(),
	}

	if target.Type == TargetTypeIP {
		assets := n.discoverSingleIP(target.Value)
		result.Assets = append(result.Assets, assets...)
	} else if target.Type == TargetTypeIPRange {
		assets := n.discoverIPRange(target.Value)
		result.Assets = append(result.Assets, assets...)
	}

	return result, nil
}

func (n *NetworkDiscovery) discoverSingleIP(ip string) []*Asset {
	var assets []*Asset

	// Create IP asset
	asset := &Asset{
		Type:         AssetTypeIP,
		Value:        ip,
		IP:           ip,
		Metadata:     make(map[string]string),
		Source:       n.Name(),
		Confidence:   0.95,
		DiscoveredAt: time.Now(),
		LastSeen:     time.Now(),
	}

	// Reverse DNS lookup
	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		asset.Domain = strings.TrimSuffix(names[0], ".")
		asset.Metadata["reverse_dns"] = asset.Domain
	}

	assets = append(assets, asset)

	// Port scanning
	if n.config.EnablePortScan {
		portAssets := n.scanPorts(ip)
		assets = append(assets, portAssets...)
	}

	return assets
}

func (n *NetworkDiscovery) discoverIPRange(ipRange string) []*Asset {
	var assets []*Asset

	_, network, err := net.ParseCIDR(ipRange)
	if err != nil {
		return assets
	}

	// Scan a subset of IPs in the range (don't scan entire /16 networks)
	maxIPs := 256
	count := 0

	for ip := network.IP.Mask(network.Mask); network.Contains(ip); n.incrementIP(ip) {
		if count >= maxIPs {
			break
		}

		// Skip network and broadcast addresses
		if ip.Equal(network.IP) || ip.Equal(n.getBroadcastIP(network)) {
			continue
		}

		// Quick ping check
		if n.isHostAlive(ip.String()) {
			ipAssets := n.discoverSingleIP(ip.String())
			assets = append(assets, ipAssets...)
		}

		count++
	}

	return assets
}

func (n *NetworkDiscovery) incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (n *NetworkDiscovery) getBroadcastIP(network *net.IPNet) net.IP {
	ip := make(net.IP, len(network.IP))
	for i := 0; i < len(network.IP); i++ {
		ip[i] = network.IP[i] | ^network.Mask[i]
	}
	return ip
}

func (n *NetworkDiscovery) isHostAlive(ip string) bool {
	// Simple TCP connection attempt (would use ICMP in production)
	conn, err := net.DialTimeout("tcp", ip+":80", 1*time.Second)
	if err == nil {
		conn.Close()
		return true
	}

	conn, err = net.DialTimeout("tcp", ip+":443", 1*time.Second)
	if err == nil {
		conn.Close()
		return true
	}

	return false
}

func (n *NetworkDiscovery) scanPorts(ip string) []*Asset {
	var assets []*Asset

	// Common ports to scan
	ports := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306}

	for _, port := range ports {
		if n.isPortOpen(ip, port) {
			asset := &Asset{
				Type:         AssetTypePort,
				Value:        fmt.Sprintf("%s:%d", ip, port),
				IP:           ip,
				Port:         port,
				Metadata:     map[string]string{"port": strconv.Itoa(port)},
				Source:       n.Name(),
				Confidence:   0.9,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
			}

			// Detect service
			if service := n.detectService(port); service != "" {
				asset.Metadata["service"] = service
				asset.Type = AssetTypeService
			}

			assets = append(assets, asset)
		}
	}

	return assets
}

func (n *NetworkDiscovery) isPortOpen(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (n *NetworkDiscovery) detectService(port int) string {
	services := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		993:  "IMAPS",
		995:  "POP3S",
		3389: "RDP",
		5432: "PostgreSQL",
		3306: "MySQL",
	}

	return services[port]
}

// TechnologyDiscovery discovers technology stack information
type TechnologyDiscovery struct {
	config *DiscoveryConfig
	logger *logger.Logger
	client *http.Client
}

func NewTechnologyDiscovery(config *DiscoveryConfig, logger *logger.Logger) *TechnologyDiscovery {
	return &TechnologyDiscovery{
		config: config,
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}
}

func (t *TechnologyDiscovery) Name() string  { return "technology_discovery" }
func (t *TechnologyDiscovery) Priority() int { return 70 }

func (t *TechnologyDiscovery) CanHandle(target *Target) bool {
	return target.Type == TargetTypeDomain || target.Type == TargetTypeURL
}

func (t *TechnologyDiscovery) Discover(ctx context.Context, target *Target, session *DiscoverySession) (*DiscoveryResult, error) {
	result := &DiscoveryResult{
		Assets:        []*Asset{},
		Relationships: []*Relationship{},
		Source:        t.Name(),
	}

	var url string
	switch target.Type {
	case TargetTypeDomain:
		url = "https://" + target.Value
	case TargetTypeURL:
		url = target.Value
	default:
		return result, nil
	}

	technologies := t.detectTechnologies(url)

	if len(technologies) > 0 {
		asset := &Asset{
			Type:         AssetTypeURL,
			Value:        url,
			Technology:   technologies,
			Metadata:     make(map[string]string),
			Source:       t.Name(),
			Confidence:   0.8,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
		}
		result.Assets = append(result.Assets, asset)
	}

	return result, nil
}

func (t *TechnologyDiscovery) detectTechnologies(url string) []string {
	var technologies []string

	resp, err := t.client.Get(url)
	if err != nil {
		return technologies
	}
	defer resp.Body.Close()

	// Detect from response headers
	headerTech := t.detectFromHeaders(resp.Header)
	technologies = append(technologies, headerTech...)

	// TODO: Detect from response body, JavaScript files, etc.

	return technologies
}

func (t *TechnologyDiscovery) detectFromHeaders(headers http.Header) []string {
	var technologies []string

	patterns := map[string]*regexp.Regexp{
		"nginx":      regexp.MustCompile(`nginx`),
		"Apache":     regexp.MustCompile(`Apache`),
		"PHP":        regexp.MustCompile(`PHP`),
		"ASP.NET":    regexp.MustCompile(`ASP\.NET`),
		"Express":    regexp.MustCompile(`Express`),
		"Cloudflare": regexp.MustCompile(`cloudflare`),
	}

	for tech, pattern := range patterns {
		for _, values := range headers {
			for _, value := range values {
				if pattern.MatchString(value) {
					technologies = append(technologies, tech)
					break
				}
			}
		}
	}

	return technologies
}

// checkCloudflareBypass checks if domain is behind Cloudflare and finds origin IPs
func (d *DomainDiscovery) checkCloudflareBypass(ctx context.Context, domain string) []*Asset {
	var assets []*Asset

	// Create Cloudflare intelligence client
	cfIntel := cloudflare.NewCloudFlareIntel(d.logger)

	// Check if domain is behind Cloudflare
	isCloudflare, err := cfIntel.DetectCloudFlare(ctx, domain)
	if err != nil {
		d.logger.Debug("Failed to detect Cloudflare", "domain", domain, "error", err)
		return assets
	}

	if !isCloudflare {
		return assets
	}

	d.logger.Info("Domain is behind Cloudflare, attempting to find origin IPs", "domain", domain)

	// Try to find origin IPs
	candidates, err := cfIntel.FindOriginIP(ctx, domain)
	if err != nil {
		d.logger.Error("Failed to find origin IPs", "domain", domain, "error", err)
		return assets
	}

	// Convert candidates to assets
	for _, candidate := range candidates {
		asset := &Asset{
			Type:       AssetTypeIP,
			Value:      candidate.IP,
			Domain:     domain,
			Title:      fmt.Sprintf("Potential origin IP for %s", domain),
			Technology: []string{"Cloudflare Bypass"},
			Metadata: map[string]string{
				"discovery_type": candidate.DiscoveryType,
				"confidence":     fmt.Sprintf("%.2f", candidate.Confidence),
				"evidence":       strings.Join(candidate.Evidence, "; "),
				"cloudflare":     "origin",
			},
			Source:       d.Name(),
			Confidence:   candidate.Confidence,
			DiscoveredAt: candidate.Timestamp,
			LastSeen:     time.Now(),
			Tags:         []string{"cloudflare-bypass", "origin-ip"},
		}

		// Higher priority for high-confidence origin IPs
		if candidate.Confidence > 0.8 {
			asset.Priority = 90
		} else if candidate.Confidence > 0.6 {
			asset.Priority = 70
		} else {
			asset.Priority = 50
		}

		assets = append(assets, asset)
	}

	if len(assets) > 0 {
		d.logger.Info("Found potential origin IPs",
			"domain", domain,
			"count", len(assets),
			"high_confidence", countHighConfidence(assets),
		)
	}

	return assets
}

func countHighConfidence(assets []*Asset) int {
	count := 0
	for _, asset := range assets {
		if asset.Confidence > 0.8 {
			count++
		}
	}
	return count
}

// CompanyDiscovery discovers assets related to company names
type CompanyDiscovery struct {
	config     *DiscoveryConfig
	logger     *logger.Logger
	client     *http.Client
	correlator *correlation.OrganizationCorrelator
}

func NewCompanyDiscovery(config *DiscoveryConfig, logger *logger.Logger) *CompanyDiscovery {
	// Create organization correlator
	correlatorConfig := correlation.CorrelatorConfig{
		EnableWhois:     true,
		EnableCerts:     true,
		EnableASN:       true,
		EnableTrademark: true,
		EnableLinkedIn:  true,
		EnableGitHub:    true,
		EnableCloud:     true,
		CacheTTL:        24 * time.Hour,
		MaxWorkers:      5,
	}

	correlator := correlation.NewOrganizationCorrelator(correlatorConfig, logger)

	// Set up default clients
	correlator.SetClients(
		correlation.NewDefaultWhoisClient(logger),
		correlation.NewDefaultCertificateClient(logger),
		correlation.NewDefaultASNClient(logger),
		correlation.NewDefaultTrademarkClient(logger),
		correlation.NewDefaultLinkedInClient(logger),
		correlation.NewDefaultGitHubClient(logger),
		correlation.NewDefaultCloudClient(logger),
	)

	return &CompanyDiscovery{
		config:     config,
		logger:     logger,
		client:     &http.Client{Timeout: 10 * time.Second},
		correlator: correlator,
	}
}

func (c *CompanyDiscovery) Name() string  { return "company_discovery" }
func (c *CompanyDiscovery) Priority() int { return 60 }

func (c *CompanyDiscovery) CanHandle(target *Target) bool {
	return target.Type == TargetTypeCompany
}

func (c *CompanyDiscovery) Discover(ctx context.Context, target *Target, session *DiscoverySession) (*DiscoveryResult, error) {
	result := &DiscoveryResult{
		Assets:        []*Asset{},
		Relationships: []*Relationship{},
		Source:        c.Name(),
	}

	// Use the organization correlator for comprehensive discovery
	org, err := c.correlator.FindOrganizationAssets(ctx, target.Value)
	if err != nil {
		c.logger.Error("Organization correlation failed", "company", target.Value, "error", err)
		// Fall back to basic discovery
		return c.basicDiscovery(target, result)
	}

	// Convert organization data to assets
	c.logger.Info("Organization correlation completed",
		"company", org.Name,
		"domains", len(org.Domains),
		"ips", len(org.IPRanges),
		"asns", len(org.ASNs),
		"employees", len(org.Employees),
		"confidence", org.Confidence,
	)

	// Add domains as assets
	for _, domain := range org.Domains {
		asset := &Asset{
			Type:         AssetTypeDomain,
			Value:        domain,
			Domain:       domain,
			Title:        fmt.Sprintf("Domain for %s", org.Name),
			Metadata:     map[string]string{"company": org.Name, "source": "correlation"},
			Source:       c.Name(),
			Confidence:   org.Confidence,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
		}
		result.Assets = append(result.Assets, asset)
	}

	// Add IP ranges as assets
	for _, ipRange := range org.IPRanges {
		asset := &Asset{
			Type:         AssetTypeIPRange,
			Value:        ipRange,
			Title:        fmt.Sprintf("IP Range for %s", org.Name),
			Metadata:     map[string]string{"company": org.Name, "source": "correlation"},
			Source:       c.Name(),
			Confidence:   org.Confidence,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
		}
		result.Assets = append(result.Assets, asset)
	}

	// Add ASNs as assets
	for _, asn := range org.ASNs {
		asset := &Asset{
			Type:         AssetTypeASN,
			Value:        asn,
			Title:        fmt.Sprintf("ASN for %s", org.Name),
			Metadata:     map[string]string{"company": org.Name, "source": "correlation"},
			Source:       c.Name(),
			Confidence:   org.Confidence,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
		}
		result.Assets = append(result.Assets, asset)
	}

	// Add GitHub organizations as assets
	for _, ghOrg := range org.GitHubOrgs {
		asset := &Asset{
			Type:         AssetTypeRepository,
			Value:        "github.com/" + ghOrg,
			Title:        fmt.Sprintf("GitHub org for %s", org.Name),
			Metadata:     map[string]string{"company": org.Name, "platform": "github"},
			Source:       c.Name(),
			Confidence:   org.Confidence * 0.9, // Slightly lower confidence for GitHub
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
		}
		result.Assets = append(result.Assets, asset)
	}

	// Add cloud accounts as metadata
	if len(org.CloudAccounts) > 0 {
		for _, account := range org.CloudAccounts {
			asset := &Asset{
				Type:  AssetTypeCloudAccount,
				Value: fmt.Sprintf("%s:%s", account.Provider, account.AccountID),
				Title: fmt.Sprintf("%s account for %s", account.Provider, org.Name),
				Metadata: map[string]string{
					"company":  org.Name,
					"provider": account.Provider,
					"account":  account.AccountID,
				},
				Source:       c.Name(),
				Confidence:   org.Confidence * 0.8,
				DiscoveredAt: time.Now(),
				LastSeen:     time.Now(),
			}
			result.Assets = append(result.Assets, asset)
		}
	}

	// Store organization metadata in session
	if session.DiscoveryTarget != nil && session.DiscoveryTarget.Metadata == nil {
		session.DiscoveryTarget.Metadata = make(map[string]interface{})
	}
	if session.DiscoveryTarget != nil {
		session.DiscoveryTarget.Metadata["organization"] = org
	}

	return result, nil
}

func (c *CompanyDiscovery) basicDiscovery(target *Target, result *DiscoveryResult) (*DiscoveryResult, error) {
	// Fall back to basic domain generation
	domains := c.findCompanyDomains(target.Value)

	for _, domain := range domains {
		asset := &Asset{
			Type:         AssetTypeDomain,
			Value:        domain,
			Domain:       domain,
			Metadata:     map[string]string{"company": target.Value},
			Source:       c.Name(),
			Confidence:   0.5, // Lower confidence for basic discovery
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
		}
		result.Assets = append(result.Assets, asset)
	}

	return result, nil
}

func (c *CompanyDiscovery) findCompanyDomains(companyName string) []string {
	var domains []string

	// Basic heuristics to generate potential domains
	normalizedName := strings.ToLower(strings.ReplaceAll(companyName, " ", ""))

	// Remove common suffixes
	suffixes := []string{"inc", "corp", "corporation", "company", "co", "ltd", "llc"}
	for _, suffix := range suffixes {
		if strings.HasSuffix(normalizedName, suffix) {
			normalizedName = strings.TrimSuffix(normalizedName, suffix)
			break
		}
	}

	// Generate potential domains
	candidates := []string{
		normalizedName + ".com",
		normalizedName + ".net",
		normalizedName + ".org",
		normalizedName + ".io",
	}

	// Check which candidates resolve
	for _, candidate := range candidates {
		if _, err := net.LookupIP(candidate); err == nil {
			domains = append(domains, candidate)
		}
	}

	return domains
}
