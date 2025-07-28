package passivedns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// PassiveDNSClient queries passive DNS databases
type PassiveDNSClient struct {
	client  *http.Client
	logger  *logger.Logger
	sources []PassiveDNSSource
	apiKeys map[string]string
	mu      sync.RWMutex
}

// PassiveDNSSource represents a passive DNS data source
type PassiveDNSSource struct {
	Name        string
	URL         string
	APIKeyParam string
	RateLimit   int
	Active      bool
}

// DNSRecord represents a passive DNS record
type DNSRecord struct {
	Query     string    `json:"query"`
	Answer    string    `json:"answer"`
	Type      string    `json:"type"`
	TTL       int       `json:"ttl"`
	Source    string    `json:"source"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
}

// DNSQueryResult represents the result of a passive DNS query
type DNSQueryResult struct {
	Domain  string      `json:"domain"`
	Records []DNSRecord `json:"records"`
	Source  string      `json:"source"`
	Total   int         `json:"total"`
}

// NewPassiveDNSClient creates a new passive DNS client
func NewPassiveDNSClient(logger *logger.Logger, apiKeys map[string]string) *PassiveDNSClient {
	client := &PassiveDNSClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger:  logger,
		apiKeys: apiKeys,
		sources: getDefaultSources(),
	}

	return client
}

// getDefaultSources returns default passive DNS sources
func getDefaultSources() []PassiveDNSSource {
	return []PassiveDNSSource{
		{
			Name:        "VirusTotal",
			URL:         "https://www.virustotal.com/vtapi/v2/domain/report",
			APIKeyParam: "apikey",
			RateLimit:   4, // requests per minute
			Active:      true,
		},
		{
			Name:        "SecurityTrails",
			URL:         "https://api.securitytrails.com/v1/domain/%s/subdomains",
			APIKeyParam: "APIKEY",
			RateLimit:   50,
			Active:      true,
		},
		{
			Name:        "PassiveTotal",
			URL:         "https://api.passivetotal.org/v2/dns/passive",
			APIKeyParam: "",
			RateLimit:   60,
			Active:      true,
		},
		{
			Name:        "CIRCL",
			URL:         "https://www.circl.lu/pdns/query/%s",
			APIKeyParam: "",
			RateLimit:   100,
			Active:      true,
		},
		{
			Name:        "Spyse",
			URL:         "https://api.spyse.com/v4/data/domain/%s/dns-records",
			APIKeyParam: "Authorization",
			RateLimit:   100,
			Active:      true,
		},
	}
}

// QueryDomain queries passive DNS for a domain
func (p *PassiveDNSClient) QueryDomain(ctx context.Context, domain string) ([]*DNSQueryResult, error) {
	var results []*DNSQueryResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Query each active source
	for _, source := range p.sources {
		if !source.Active {
			continue
		}

		// Check if we have required API key for sources that need them
		if p.requiresCredentials(source) && !p.hasValidCredentials(source) {
			p.logger.Debug("Skipping source due to missing credentials", "source", source.Name)
			continue
		}

		wg.Add(1)
		go func(src PassiveDNSSource) {
			defer wg.Done()

			result, err := p.querySingleSource(ctx, src, domain)
			if err != nil {
				// Log at debug level for expected API failures (missing credentials, access denied)
				// TODO: For bug bounty mode, reduce noise from expected failures
				if p.isExpectedFailure(err) {
					// FIXME: Don't log at all - these are expected without API keys
					// Silently skip
				} else {
					// FIXME: Change to Debug - only log real errors in bug bounty mode
					p.logger.Debug("Failed to query passive DNS source",
						"source", src.Name,
						"domain", domain,
						"error", err)
				}
				return
			}

			if result != nil {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(source)
	}

	wg.Wait()

	p.logger.Info("Passive DNS query completed",
		"domain", domain,
		"sources_queried", len(p.sources),
		"results_found", len(results))

	return results, nil
}

// querySingleSource queries a single passive DNS source
func (p *PassiveDNSClient) querySingleSource(ctx context.Context, source PassiveDNSSource, domain string) (*DNSQueryResult, error) {
	switch source.Name {
	case "VirusTotal":
		return p.queryVirusTotal(ctx, domain)
	case "SecurityTrails":
		return p.querySecurityTrails(ctx, domain)
	case "PassiveTotal":
		return p.queryPassiveTotal(ctx, domain)
	case "CIRCL":
		return p.queryCIRCL(ctx, domain)
	case "Spyse":
		return p.querySpyse(ctx, domain)
	default:
		return nil, fmt.Errorf("unknown source: %s", source.Name)
	}
}

// queryVirusTotal queries VirusTotal for passive DNS data
func (p *PassiveDNSClient) queryVirusTotal(ctx context.Context, domain string) (*DNSQueryResult, error) {
	apiKey := p.apiKeys["VirusTotal"]
	if apiKey == "" {
		return nil, fmt.Errorf("VirusTotal API key not provided")
	}

	params := url.Values{}
	params.Set("domain", domain)
	params.Set("apikey", apiKey)

	reqURL := "https://www.virustotal.com/vtapi/v2/domain/report?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("VirusTotal returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var vtResponse struct {
		ResponseCode int      `json:"response_code"`
		Subdomains   []string `json:"subdomains"`
		Resolutions  []struct {
			IPAddress string `json:"ip_address"`
			LastSeen  string `json:"last_resolved"`
		} `json:"resolutions"`
		DetectedURLs []struct {
			URL      string `json:"url"`
			Detected bool   `json:"detected"`
		} `json:"detected_urls"`
	}

	if err := json.Unmarshal(body, &vtResponse); err != nil {
		return nil, err
	}

	result := &DNSQueryResult{
		Domain: domain,
		Source: "VirusTotal",
		Total:  len(vtResponse.Subdomains) + len(vtResponse.Resolutions),
	}

	// Add subdomain records
	for _, subdomain := range vtResponse.Subdomains {
		record := DNSRecord{
			Query:  subdomain,
			Answer: domain,
			Type:   "CNAME",
			Source: "VirusTotal",
		}
		result.Records = append(result.Records, record)
	}

	// Add resolution records
	for _, resolution := range vtResponse.Resolutions {
		lastSeen, _ := time.Parse("2006-01-02 15:04:05", resolution.LastSeen)
		record := DNSRecord{
			Query:    domain,
			Answer:   resolution.IPAddress,
			Type:     "A",
			Source:   "VirusTotal",
			LastSeen: lastSeen,
		}
		result.Records = append(result.Records, record)
	}

	return result, nil
}

// querySecurityTrails queries SecurityTrails for passive DNS data
func (p *PassiveDNSClient) querySecurityTrails(ctx context.Context, domain string) (*DNSQueryResult, error) {
	apiKey := p.apiKeys["SecurityTrails"]
	if apiKey == "" {
		return nil, fmt.Errorf("SecurityTrails API key not provided")
	}

	reqURL := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("APIKEY", apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("SecurityTrails returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var stResponse struct {
		Subdomains []string `json:"subdomains"`
		Meta       struct {
			LimitReached bool `json:"limit_reached"`
		} `json:"meta"`
	}

	if err := json.Unmarshal(body, &stResponse); err != nil {
		return nil, err
	}

	result := &DNSQueryResult{
		Domain: domain,
		Source: "SecurityTrails",
		Total:  len(stResponse.Subdomains),
	}

	// Add subdomain records
	for _, subdomain := range stResponse.Subdomains {
		fullDomain := fmt.Sprintf("%s.%s", subdomain, domain)
		record := DNSRecord{
			Query:  fullDomain,
			Answer: domain,
			Type:   "subdomain",
			Source: "SecurityTrails",
		}
		result.Records = append(result.Records, record)
	}

	return result, nil
}

// queryPassiveTotal queries PassiveTotal for passive DNS data
func (p *PassiveDNSClient) queryPassiveTotal(ctx context.Context, domain string) (*DNSQueryResult, error) {
	// PassiveTotal requires username:API key authentication
	apiKey := p.apiKeys["PassiveTotal"]
	username := p.apiKeys["PassiveTotalUsername"]

	if apiKey == "" || username == "" {
		return nil, fmt.Errorf("PassiveTotal credentials not provided")
	}

	params := url.Values{}
	params.Set("query", domain)

	reqURL := "https://api.passivetotal.org/v2/dns/passive?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(username, apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("PassiveTotal returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ptResponse struct {
		Results []struct {
			Resolve   string `json:"resolve"`
			Source    string `json:"source"`
			Value     string `json:"value"`
			FirstSeen string `json:"firstSeen"`
			LastSeen  string `json:"lastSeen"`
			Collected string `json:"collected"`
		} `json:"results"`
		TotalRecords int    `json:"totalRecords"`
		QueryValue   string `json:"queryValue"`
	}

	if err := json.Unmarshal(body, &ptResponse); err != nil {
		return nil, err
	}

	result := &DNSQueryResult{
		Domain: domain,
		Source: "PassiveTotal",
		Total:  ptResponse.TotalRecords,
	}

	// Add DNS records
	for _, record := range ptResponse.Results {
		firstSeen, _ := time.Parse("2006-01-02 15:04:05", record.FirstSeen)
		lastSeen, _ := time.Parse("2006-01-02 15:04:05", record.LastSeen)

		dnsRecord := DNSRecord{
			Query:     record.Resolve,
			Answer:    record.Value,
			Type:      "A", // PassiveTotal mainly provides A records
			Source:    "PassiveTotal",
			FirstSeen: firstSeen,
			LastSeen:  lastSeen,
		}
		result.Records = append(result.Records, dnsRecord)
	}

	return result, nil
}

// queryCIRCL queries CIRCL passive DNS for data
func (p *PassiveDNSClient) queryCIRCL(ctx context.Context, domain string) (*DNSQueryResult, error) {
	reqURL := fmt.Sprintf("https://www.circl.lu/pdns/query/%s", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
			return nil, fmt.Errorf("CIRCL API access denied or rate limited: status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("CIRCL returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// CIRCL returns JSONL format (one JSON object per line)
	lines := strings.Split(string(body), "\n")

	result := &DNSQueryResult{
		Domain: domain,
		Source: "CIRCL",
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var circlRecord struct {
			Query     string `json:"rrname"`
			Answer    string `json:"rdata"`
			Type      string `json:"rrtype"`
			TTL       int    `json:"ttl"`
			FirstSeen int64  `json:"time_first"`
			LastSeen  int64  `json:"time_last"`
			Count     int    `json:"count"`
		}

		if err := json.Unmarshal([]byte(line), &circlRecord); err != nil {
			continue
		}

		record := DNSRecord{
			Query:     circlRecord.Query,
			Answer:    circlRecord.Answer,
			Type:      circlRecord.Type,
			TTL:       circlRecord.TTL,
			Source:    "CIRCL",
			FirstSeen: time.Unix(circlRecord.FirstSeen, 0),
			LastSeen:  time.Unix(circlRecord.LastSeen, 0),
			Count:     circlRecord.Count,
		}
		result.Records = append(result.Records, record)
	}

	result.Total = len(result.Records)
	return result, nil
}

// querySpyse queries Spyse for passive DNS data
func (p *PassiveDNSClient) querySpyse(ctx context.Context, domain string) (*DNSQueryResult, error) {
	apiKey := p.apiKeys["Spyse"]
	if apiKey == "" {
		return nil, fmt.Errorf("Spyse API key not provided")
	}

	reqURL := fmt.Sprintf("https://api.spyse.com/v4/data/domain/%s/dns-records", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Spyse returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var spyseResponse struct {
		Data struct {
			Items []struct {
				Name  string `json:"name"`
				Type  string `json:"type"`
				Value string `json:"value"`
				TTL   int    `json:"ttl"`
			} `json:"items"`
		} `json:"data"`
		Total int `json:"total"`
	}

	if err := json.Unmarshal(body, &spyseResponse); err != nil {
		return nil, err
	}

	result := &DNSQueryResult{
		Domain: domain,
		Source: "Spyse",
		Total:  spyseResponse.Total,
	}

	// Add DNS records
	for _, item := range spyseResponse.Data.Items {
		record := DNSRecord{
			Query:  item.Name,
			Answer: item.Value,
			Type:   item.Type,
			TTL:    item.TTL,
			Source: "Spyse",
		}
		result.Records = append(result.Records, record)
	}

	return result, nil
}

// DiscoverSubdomains discovers subdomains using passive DNS
func (p *PassiveDNSClient) DiscoverSubdomains(ctx context.Context, domain string) ([]string, error) {
	results, err := p.QueryDomain(ctx, domain)
	if err != nil {
		return nil, err
	}

	subdomainMap := make(map[string]bool)

	for _, result := range results {
		for _, record := range result.Records {
			// Extract subdomains from various record types
			switch record.Type {
			case "CNAME", "subdomain":
				if strings.HasSuffix(record.Query, "."+domain) {
					subdomainMap[record.Query] = true
				}
			case "A", "AAAA":
				if strings.HasSuffix(record.Query, "."+domain) && record.Query != domain {
					subdomainMap[record.Query] = true
				}
			}
		}
	}

	// Convert to slice
	var subdomains []string
	for subdomain := range subdomainMap {
		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}

// DiscoverIPHistory discovers IP address history for a domain
func (p *PassiveDNSClient) DiscoverIPHistory(ctx context.Context, domain string) ([]string, error) {
	results, err := p.QueryDomain(ctx, domain)
	if err != nil {
		return nil, err
	}

	ipMap := make(map[string]bool)

	for _, result := range results {
		for _, record := range result.Records {
			if record.Type == "A" && record.Query == domain {
				ipMap[record.Answer] = true
			}
		}
	}

	// Convert to slice
	var ips []string
	for ip := range ipMap {
		ips = append(ips, ip)
	}

	return ips, nil
}

// GetDNSTimeline gets DNS resolution timeline for a domain
func (p *PassiveDNSClient) GetDNSTimeline(ctx context.Context, domain string) ([]*DNSRecord, error) {
	results, err := p.QueryDomain(ctx, domain)
	if err != nil {
		return nil, err
	}

	var timeline []*DNSRecord

	for _, result := range results {
		for i := range result.Records {
			record := &result.Records[i]
			if record.Query == domain {
				timeline = append(timeline, record)
			}
		}
	}

	// Sort by last seen (newest first)
	for i := 0; i < len(timeline)-1; i++ {
		for j := 0; j < len(timeline)-i-1; j++ {
			if timeline[j].LastSeen.Before(timeline[j+1].LastSeen) {
				timeline[j], timeline[j+1] = timeline[j+1], timeline[j]
			}
		}
	}

	return timeline, nil
}

// requiresCredentials checks if a source requires API credentials
func (p *PassiveDNSClient) requiresCredentials(source PassiveDNSSource) bool {
	switch source.Name {
	case "PassiveTotal":
		return true // Requires username and API key
	case "CIRCL":
		return false // Public API, but may require authorization for some queries
	case "VirusTotal", "SecurityTrails", "Spyse":
		return true // Require API keys
	default:
		return source.APIKeyParam != ""
	}
}

// hasValidCredentials checks if we have valid credentials for a source
func (p *PassiveDNSClient) hasValidCredentials(source PassiveDNSSource) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	switch source.Name {
	case "PassiveTotal":
		// PassiveTotal requires both username and API key
		return p.apiKeys["PassiveTotal"] != "" && p.apiKeys["PassiveTotalUsername"] != ""
	case "CIRCL":
		// CIRCL is public but may have rate limits/auth requirements
		return true // Always try CIRCL, handle auth errors gracefully
	case "VirusTotal", "SecurityTrails", "Spyse":
		return p.apiKeys[source.Name] != ""
	default:
		if source.APIKeyParam != "" {
			return p.apiKeys[source.Name] != ""
		}
		return true
	}
}

// isExpectedFailure checks if an error is an expected API failure (credentials, rate limits, etc.)
// TODO: In bug bounty mode, treat ALL passive DNS failures as expected to reduce noise
func (p *PassiveDNSClient) isExpectedFailure(err error) bool {
	errStr := strings.ToLower(err.Error())

	// Common patterns for expected failures
	expectedPatterns := []string{
		"credentials not provided",
		"api key not provided",
		"status 401", // Unauthorized
		"status 403", // Forbidden
		"status 429", // Rate limited
		"authentication failed",
		"access denied",
		"unauthorized",
		"forbidden",
	}

	for _, pattern := range expectedPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}
