package external

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

// ShodanClient interacts with Shodan API
type ShodanClient struct {
	apiKey string
	client *http.Client
	logger *logger.Logger
}

// NewShodanClient creates a new Shodan client
func NewShodanClient(apiKey string, logger *logger.Logger) *ShodanClient {
	return &ShodanClient{
		apiKey: apiKey,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// ShodanHost represents a host from Shodan
type ShodanHost struct {
	IP         string   `json:"ip_str"`
	Port       int      `json:"port"`
	Hostnames  []string `json:"hostnames"`
	Domains    []string `json:"domains"`
	OS         string   `json:"os"`
	Transport  string   `json:"transport"`
	Product    string   `json:"product"`
	Version    string   `json:"version"`
	Data       string   `json:"data"`
	ASN        string   `json:"asn"`
	ISP        string   `json:"isp"`
	Org        string   `json:"org"`
	Country    string   `json:"country_name"`
	City       string   `json:"city"`
	Vulns      []string `json:"vulns"`
	LastUpdate string   `json:"timestamp"`
}

// ShodanSearchResult represents search results
type ShodanSearchResult struct {
	Total   int          `json:"total"`
	Matches []ShodanHost `json:"matches"`
}

// SearchDomain searches for hosts related to a domain
func (s *ShodanClient) SearchDomain(ctx context.Context, domain string) ([]ShodanHost, error) {
	if s.apiKey == "" {
		return nil, fmt.Errorf("Shodan API key not configured")
	}

	queries := []string{
		fmt.Sprintf("hostname:%s", domain),
		fmt.Sprintf("ssl.cert.subject.cn:%s", domain),
		fmt.Sprintf("ssl:%s", domain),
		fmt.Sprintf("org:\"%s\"", domain),
	}

	var allHosts []ShodanHost
	seen := make(map[string]bool)

	for _, query := range queries {
		hosts, err := s.search(ctx, query)
		if err != nil {
			s.logger.Debug("Shodan query failed", "query", query, "error", err)
			continue
		}

		for _, host := range hosts {
			key := fmt.Sprintf("%s:%d", host.IP, host.Port)
			if !seen[key] {
				seen[key] = true
				allHosts = append(allHosts, host)
			}
		}
	}

	s.logger.Infow("Shodan search completed", "domain", domain, "hosts_found", len(allHosts))
	return allHosts, nil
}

// SearchIP searches for information about an IP
func (s *ShodanClient) SearchIP(ctx context.Context, ip string) (*ShodanHost, error) {
	if s.apiKey == "" {
		return nil, fmt.Errorf("Shodan API key not configured")
	}

	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, s.apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Shodan API error: %d", resp.StatusCode)
	}

	var hostInfo struct {
		IP        string   `json:"ip_str"`
		Hostnames []string `json:"hostnames"`
		Domains   []string `json:"domains"`
		OS        string   `json:"os"`
		ASN       string   `json:"asn"`
		ISP       string   `json:"isp"`
		Org       string   `json:"org"`
		Country   string   `json:"country_name"`
		City      string   `json:"city"`
		Ports     []int    `json:"ports"`
		Vulns     []string `json:"vulns"`
		Data      []struct {
			Port      int    `json:"port"`
			Transport string `json:"transport"`
			Product   string `json:"product"`
			Version   string `json:"version"`
			Data      string `json:"data"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&hostInfo); err != nil {
		return nil, err
	}

	// Convert to ShodanHost
	host := &ShodanHost{
		IP:        hostInfo.IP,
		Hostnames: hostInfo.Hostnames,
		Domains:   hostInfo.Domains,
		OS:        hostInfo.OS,
		ASN:       hostInfo.ASN,
		ISP:       hostInfo.ISP,
		Org:       hostInfo.Org,
		Country:   hostInfo.Country,
		City:      hostInfo.City,
		Vulns:     hostInfo.Vulns,
	}

	return host, nil
}

// SearchOrg searches for hosts belonging to an organization
func (s *ShodanClient) SearchOrg(ctx context.Context, org string) ([]ShodanHost, error) {
	return s.search(ctx, fmt.Sprintf("org:\"%s\"", org))
}

// SearchASN searches for hosts in an ASN
func (s *ShodanClient) SearchASN(ctx context.Context, asn string) ([]ShodanHost, error) {
	return s.search(ctx, fmt.Sprintf("asn:%s", asn))
}

// SearchNetblock searches for hosts in a network range
func (s *ShodanClient) SearchNetblock(ctx context.Context, netblock string) ([]ShodanHost, error) {
	return s.search(ctx, fmt.Sprintf("net:%s", netblock))
}

// GetExploits searches for exploits related to a query
func (s *ShodanClient) GetExploits(ctx context.Context, query string) ([]Exploit, error) {
	if s.apiKey == "" {
		return nil, fmt.Errorf("Shodan API key not configured")
	}

	url := fmt.Sprintf("https://exploits.shodan.io/api/search?query=%s&key=%s", query, s.apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	var result struct {
		Matches []Exploit `json:"matches"`
		Total   int       `json:"total"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Matches, nil
}

// Exploit represents an exploit from Shodan
type Exploit struct {
	ID          string   `json:"_id"`
	Author      string   `json:"author"`
	Code        string   `json:"code"`
	Date        string   `json:"date"`
	Description string   `json:"description"`
	Platform    string   `json:"platform"`
	Port        int      `json:"port"`
	Source      string   `json:"source"`
	Type        string   `json:"type"`
	CVE         []string `json:"cve"`
}

// search performs a generic Shodan search
func (s *ShodanClient) search(ctx context.Context, query string) ([]ShodanHost, error) {
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s&facets=port,country", s.apiKey, query)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Shodan API error: %d", resp.StatusCode)
	}

	var result ShodanSearchResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Matches, nil
}

// GetAPIInfo returns information about the API key
func (s *ShodanClient) GetAPIInfo(ctx context.Context) (map[string]interface{}, error) {
	if s.apiKey == "" {
		return nil, fmt.Errorf("Shodan API key not configured")
	}

	url := fmt.Sprintf("https://api.shodan.io/api-info?key=%s", s.apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	var info map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	return info, nil
}

// SearchFacets searches with facet analysis
func (s *ShodanClient) SearchFacets(ctx context.Context, query string, facets []string) (map[string][]FacetResult, error) {
	if s.apiKey == "" {
		return nil, fmt.Errorf("Shodan API key not configured")
	}

	facetStr := ""
	for _, f := range facets {
		if facetStr != "" {
			facetStr += ","
		}
		facetStr += f
	}

	url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s&facets=%s", s.apiKey, query, facetStr)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	var result struct {
		Facets map[string][]FacetResult `json:"facets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Facets, nil
}

// FacetResult represents a facet analysis result
type FacetResult struct {
	Count int    `json:"count"`
	Value string `json:"value"`
}

// GetDNSResolve performs DNS lookups using Shodan
func (s *ShodanClient) GetDNSResolve(ctx context.Context, hostnames []string) (map[string]string, error) {
	if s.apiKey == "" {
		return nil, fmt.Errorf("Shodan API key not configured")
	}

	hostnameList := ""
	for i, h := range hostnames {
		if i > 0 {
			hostnameList += ","
		}
		hostnameList += h
	}

	url := fmt.Sprintf("https://api.shodan.io/dns/resolve?hostnames=%s&key=%s", hostnameList, s.apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// GetDNSReverse performs reverse DNS lookups
func (s *ShodanClient) GetDNSReverse(ctx context.Context, ips []string) (map[string][]string, error) {
	if s.apiKey == "" {
		return nil, fmt.Errorf("Shodan API key not configured")
	}

	ipList := ""
	for i, ip := range ips {
		if i > 0 {
			ipList += ","
		}
		ipList += ip
	}

	url := fmt.Sprintf("https://api.shodan.io/dns/reverse?ips=%s&key=%s", ipList, s.apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	var result map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}
