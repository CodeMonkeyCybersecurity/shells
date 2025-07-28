package external

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// CensysClient interacts with Censys API
type CensysClient struct {
	apiID     string
	apiSecret string
	client    *http.Client
	logger    *logger.Logger
}

// NewCensysClient creates a new Censys client
func NewCensysClient(apiID, apiSecret string, logger *logger.Logger) *CensysClient {
	return &CensysClient{
		apiID:     apiID,
		apiSecret: apiSecret,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// CensysHost represents a host from Censys
type CensysHost struct {
	IP               string                 `json:"ip"`
	LastUpdated      string                 `json:"last_updated_at"`
	Services         []CensysService        `json:"services"`
	Location         CensysLocation         `json:"location"`
	AutonomousSystem CensysAS               `json:"autonomous_system"`
	OperatingSystem  map[string]interface{} `json:"operating_system"`
	DNS              CensysDNS              `json:"dns"`
}

// CensysService represents a service on a host
type CensysService struct {
	Port            int                    `json:"port"`
	ServiceName     string                 `json:"service_name"`
	TransportProto  string                 `json:"transport_protocol"`
	ExtendedService string                 `json:"extended_service_name"`
	Certificate     map[string]interface{} `json:"tls"`
	HTTP            map[string]interface{} `json:"http"`
	Banner          string                 `json:"banner"`
}

// CensysLocation represents location data
type CensysLocation struct {
	Continent   string  `json:"continent"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Province    string  `json:"province"`
	Timezone    string  `json:"timezone"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

// CensysAS represents autonomous system info
type CensysAS struct {
	ASN         int    `json:"asn"`
	Description string `json:"description"`
	Name        string `json:"name"`
	CountryCode string `json:"country_code"`
}

// CensysDNS represents DNS information
type CensysDNS struct {
	ReverseNames []string `json:"reverse_dns_names"`
}

// CensysSearchResult represents search results
type CensysSearchResult struct {
	Status string       `json:"status"`
	Result CensysResult `json:"result"`
}

// CensysResult contains the actual results
type CensysResult struct {
	Query    string      `json:"query"`
	Total    int         `json:"total"`
	Duration int         `json:"duration"`
	Hits     []CensysHit `json:"hits"`
}

// CensysHit represents a search hit
type CensysHit struct {
	IP               string          `json:"ip"`
	Services         []CensysService `json:"services"`
	Location         CensysLocation  `json:"location"`
	LastUpdated      string          `json:"last_updated_at"`
	AutonomousSystem CensysAS        `json:"autonomous_system"`
}

// SearchHosts searches for hosts using Censys
func (c *CensysClient) SearchHosts(ctx context.Context, query string, limit int) ([]CensysHit, error) {
	if c.apiID == "" || c.apiSecret == "" {
		return nil, fmt.Errorf("Censys API credentials not configured")
	}

	searchReq := map[string]interface{}{
		"query":         query,
		"per_page":      limit,
		"virtual_hosts": "INCLUDE",
	}

	body, err := json.Marshal(searchReq)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://search.censys.io/api/v2/hosts/search", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.apiID, c.apiSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Censys API error: %d", resp.StatusCode)
	}

	var result CensysSearchResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Result.Hits, nil
}

// SearchCertificates searches for certificates
func (c *CensysClient) SearchCertificates(ctx context.Context, query string, limit int) ([]CensysCertificate, error) {
	if c.apiID == "" || c.apiSecret == "" {
		return nil, fmt.Errorf("Censys API credentials not configured")
	}

	searchReq := map[string]interface{}{
		"query":    query,
		"per_page": limit,
	}

	body, err := json.Marshal(searchReq)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://search.censys.io/api/v1/search/certificates", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.apiID, c.apiSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Status  string `json:"status"`
		Results []struct {
			ParsedFingerprint256 string                 `json:"parsed.fingerprint_sha256"`
			ParsedNames          []string               `json:"parsed.names"`
			ParsedSubject        map[string]interface{} `json:"parsed.subject"`
			ParsedIssuer         map[string]interface{} `json:"parsed.issuer"`
			ParsedValidityStart  string                 `json:"parsed.validity.start"`
			ParsedValidityEnd    string                 `json:"parsed.validity.end"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var certificates []CensysCertificate
	for _, cert := range result.Results {
		certificates = append(certificates, CensysCertificate{
			Fingerprint: cert.ParsedFingerprint256,
			Names:       cert.ParsedNames,
			Subject:     cert.ParsedSubject,
			Issuer:      cert.ParsedIssuer,
			ValidFrom:   cert.ParsedValidityStart,
			ValidTo:     cert.ParsedValidityEnd,
		})
	}

	return certificates, nil
}

// CensysCertificate represents a certificate
type CensysCertificate struct {
	Fingerprint string                 `json:"fingerprint"`
	Names       []string               `json:"names"`
	Subject     map[string]interface{} `json:"subject"`
	Issuer      map[string]interface{} `json:"issuer"`
	ValidFrom   string                 `json:"valid_from"`
	ValidTo     string                 `json:"valid_to"`
}

// GetHost gets detailed information about a host
func (c *CensysClient) GetHost(ctx context.Context, ip string) (*CensysHost, error) {
	if c.apiID == "" || c.apiSecret == "" {
		return nil, fmt.Errorf("Censys API credentials not configured")
	}

	url := fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.apiID, c.apiSecret)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Censys API error: %d", resp.StatusCode)
	}

	var result struct {
		Result CensysHost `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result.Result, nil
}

// SearchDomain searches for hosts related to a domain
func (c *CensysClient) SearchDomain(ctx context.Context, domain string) ([]CensysHit, error) {
	queries := []string{
		fmt.Sprintf("services.tls.certificates.leaf_data.names: %s", domain),
		fmt.Sprintf("services.http.response.html_title: %s", domain),
		fmt.Sprintf("dns.reverse_dns.names: %s", domain),
		fmt.Sprintf("services.http.response.headers.server: %s", domain),
	}

	var allHits []CensysHit
	seen := make(map[string]bool)

	for _, query := range queries {
		hits, err := c.SearchHosts(ctx, query, 100)
		if err != nil {
			c.logger.Debug("Censys query failed", "query", query, "error", err)
			continue
		}

		for _, hit := range hits {
			if !seen[hit.IP] {
				seen[hit.IP] = true
				allHits = append(allHits, hit)
			}
		}
	}

	c.logger.Infow("Censys domain search completed", "domain", domain, "hosts_found", len(allHits))
	return allHits, nil
}

// SearchOrg searches for hosts belonging to an organization
func (c *CensysClient) SearchOrg(ctx context.Context, org string) ([]CensysHit, error) {
	query := fmt.Sprintf("autonomous_system.name: \"%s\"", org)
	return c.SearchHosts(ctx, query, 100)
}

// SearchASN searches for hosts in an ASN
func (c *CensysClient) SearchASN(ctx context.Context, asn int) ([]CensysHit, error) {
	query := fmt.Sprintf("autonomous_system.asn: %d", asn)
	return c.SearchHosts(ctx, query, 100)
}

// SearchNetblock searches for hosts in a network range
func (c *CensysClient) SearchNetblock(ctx context.Context, netblock string) ([]CensysHit, error) {
	query := fmt.Sprintf("ip: %s", netblock)
	return c.SearchHosts(ctx, query, 100)
}

// SearchServices searches for specific services
func (c *CensysClient) SearchServices(ctx context.Context, service string, port int) ([]CensysHit, error) {
	query := fmt.Sprintf("services.service_name: %s AND services.port: %d", service, port)
	return c.SearchHosts(ctx, query, 100)
}

// GetCertificateHosts gets hosts using a specific certificate
func (c *CensysClient) GetCertificateHosts(ctx context.Context, fingerprint string) ([]string, error) {
	query := fmt.Sprintf("services.tls.certificates.leaf_data.fingerprint: %s", fingerprint)
	hits, err := c.SearchHosts(ctx, query, 100)
	if err != nil {
		return nil, err
	}

	var hosts []string
	for _, hit := range hits {
		hosts = append(hosts, hit.IP)
	}

	return hosts, nil
}

// SearchBanners searches for specific banner text
func (c *CensysClient) SearchBanners(ctx context.Context, banner string) ([]CensysHit, error) {
	query := fmt.Sprintf("services.banner: \"%s\"", banner)
	return c.SearchHosts(ctx, query, 100)
}

// SearchHTMLTitle searches for specific HTML titles
func (c *CensysClient) SearchHTMLTitle(ctx context.Context, title string) ([]CensysHit, error) {
	query := fmt.Sprintf("services.http.response.html_title: \"%s\"", title)
	return c.SearchHosts(ctx, query, 100)
}

// SearchHTTPHeaders searches for specific HTTP headers
func (c *CensysClient) SearchHTTPHeaders(ctx context.Context, header, value string) ([]CensysHit, error) {
	query := fmt.Sprintf("services.http.response.headers.%s: \"%s\"", header, value)
	return c.SearchHosts(ctx, query, 100)
}

// GetAccountStatus gets API account status
func (c *CensysClient) GetAccountStatus(ctx context.Context) (map[string]interface{}, error) {
	if c.apiID == "" || c.apiSecret == "" {
		return nil, fmt.Errorf("Censys API credentials not configured")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://search.censys.io/api/v1/account", nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.apiID, c.apiSecret)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}
