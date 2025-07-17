package discovery

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DomainDiscovery discovers assets related to domains
type DomainDiscovery struct {
	config *DiscoveryConfig
	logger Logger
	client *http.Client
}

// NewDomainDiscovery creates a new domain discovery module
func NewDomainDiscovery(config *DiscoveryConfig, logger Logger) *DomainDiscovery {
	return &DomainDiscovery{
		config: config,
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (d *DomainDiscovery) Name() string { return "domain_discovery" }
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

	// Web crawling
	if d.config.EnableWebCrawl {
		webAssets := d.webCrawling(domain)
		result.Assets = append(result.Assets, webAssets...)
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

	// Query Certificate Transparency logs
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	
	resp, err := d.client.Get(url)
	if err != nil {
		d.logger.Debug("Certificate transparency query failed", "domain", domain, "error", err)
		return assets
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return assets
	}

	var certEntries []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&certEntries); err != nil {
		return assets
	}

	seen := make(map[string]bool)
	
	for _, entry := range certEntries {
		// Parse SANs from name_value
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
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
					Type:         AssetTypeSubdomain,
					Value:        name,
					Domain:       domain,
					Metadata:     map[string]string{"source": "certificate_transparency"},
					Source:       d.Name(),
					Confidence:   0.85,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
				}
				assets = append(assets, asset)
				seen[name] = true
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
	logger Logger
}

func NewNetworkDiscovery(config *DiscoveryConfig, logger Logger) *NetworkDiscovery {
	return &NetworkDiscovery{
		config: config,
		logger: logger,
	}
}

func (n *NetworkDiscovery) Name() string { return "network_discovery" }
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
	logger Logger
	client *http.Client
}

func NewTechnologyDiscovery(config *DiscoveryConfig, logger Logger) *TechnologyDiscovery {
	return &TechnologyDiscovery{
		config: config,
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (t *TechnologyDiscovery) Name() string { return "technology_discovery" }
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
		"nginx":     regexp.MustCompile(`nginx`),
		"Apache":    regexp.MustCompile(`Apache`),
		"PHP":       regexp.MustCompile(`PHP`),
		"ASP.NET":   regexp.MustCompile(`ASP\.NET`),
		"Express":   regexp.MustCompile(`Express`),
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

// CompanyDiscovery discovers assets related to company names
type CompanyDiscovery struct {
	config *DiscoveryConfig
	logger Logger
	client *http.Client
}

func NewCompanyDiscovery(config *DiscoveryConfig, logger Logger) *CompanyDiscovery {
	return &CompanyDiscovery{
		config: config,
		logger: logger,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *CompanyDiscovery) Name() string { return "company_discovery" }
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

	// Try to find domains associated with the company
	domains := c.findCompanyDomains(target.Value)
	
	for _, domain := range domains {
		asset := &Asset{
			Type:         AssetTypeDomain,
			Value:        domain,
			Domain:       domain,
			Metadata:     map[string]string{"company": target.Value},
			Source:       c.Name(),
			Confidence:   0.7,
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