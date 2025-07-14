package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type DNSHistoryClient struct {
	securityTrails *SecurityTrailsClient
	dnsDB          *DNSDBClient
	viewDNS        *ViewDNSClient
	httpClient     *http.Client
}

type SecurityTrailsClient struct {
	APIKey     string
	HTTPClient *http.Client
}

type DNSDBClient struct {
	APIKey     string
	HTTPClient *http.Client
}

type ViewDNSClient struct {
	APIKey     string
	HTTPClient *http.Client
}

func NewDNSHistoryClient(securityTrailsKey, dnsDBKey, viewDNSKey string) *DNSHistoryClient {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &DNSHistoryClient{
		securityTrails: &SecurityTrailsClient{
			APIKey:     securityTrailsKey,
			HTTPClient: client,
		},
		dnsDB: &DNSDBClient{
			APIKey:     dnsDBKey,
			HTTPClient: client,
		},
		viewDNS: &ViewDNSClient{
			APIKey:     viewDNSKey,
			HTTPClient: client,
		},
		httpClient: client,
	}
}

func (d *DNSHistoryClient) GetCompleteHistory(ctx context.Context, domain string) (*DNSHistory, error) {
	history := &DNSHistory{
		Domain:        domain,
		Subdomains:    make(map[string][]HistoricalRecord),
		IPHistory:     make(map[string][]IPRecord),
		NSHistory:     []NameserverRecord{},
		MXHistory:     []MXRecord{},
		LastUpdated:   time.Now(),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := make(chan error, 3)

	// SecurityTrails historical data
	wg.Add(1)
	go func() {
		defer wg.Done()
		if d.securityTrails.APIKey != "" {
			if st, err := d.securityTrails.GetHistory(ctx, domain); err == nil {
				mu.Lock()
				history.Merge(st)
				mu.Unlock()
			} else {
				errors <- fmt.Errorf("SecurityTrails error: %v", err)
			}
		}
	}()

	// DNSDB passive DNS
	wg.Add(1)
	go func() {
		defer wg.Done()
		if d.dnsDB.APIKey != "" {
			if dnsdb, err := d.dnsDB.QueryDomain(ctx, domain); err == nil {
				mu.Lock()
				history.Merge(dnsdb)
				mu.Unlock()
			} else {
				errors <- fmt.Errorf("DNSDB error: %v", err)
			}
		}
	}()

	// ViewDNS free option
	wg.Add(1)
	go func() {
		defer wg.Done()
		if viewdns, err := d.viewDNS.GetIPHistory(ctx, domain); err == nil {
			mu.Lock()
			history.Merge(viewdns)
			mu.Unlock()
		} else {
			errors <- fmt.Errorf("ViewDNS error: %v", err)
		}
	}()

	wg.Wait()
	close(errors)

	// Find interesting patterns
	history.Findings = d.analyzeHistory(history)

	return history, nil
}

func (d *DNSHistoryClient) analyzeHistory(history *DNSHistory) []Finding {
	findings := []Finding{}

	// Look for subdomain takeover opportunities
	for subdomain, records := range history.Subdomains {
		if len(records) == 0 {
			continue
		}

		lastRecord := records[len(records)-1]

		// Was pointing to cloud service, now NXDOMAIN?
		if d.wasCloudService(lastRecord.Value) && !d.currentlyExists(subdomain) {
			findings = append(findings, Finding{
				Type:     "POTENTIAL_SUBDOMAIN_TAKEOVER",
				Severity: "HIGH",
				Domain:   subdomain,
				Details:  fmt.Sprintf("Was pointing to %s, now NXDOMAIN", lastRecord.Value),
			})
		}

		// Check for interesting patterns
		if d.isInterestingSubdomain(subdomain) {
			findings = append(findings, Finding{
				Type:     "INTERESTING_SUBDOMAIN",
				Severity: "MEDIUM",
				Domain:   subdomain,
				Details:  "Potentially interesting subdomain pattern",
			})
		}
	}

	// Find old IP addresses that might still have services
	for domain, ipRecords := range history.IPHistory {
		for _, record := range ipRecords {
			if d.stillHasWebService(record.IP) {
				findings = append(findings, Finding{
					Type:     "OLD_IP_STILL_ACTIVE",
					Severity: "MEDIUM",
					Domain:   domain,
					IP:       record.IP,
					Details:  fmt.Sprintf("Old IP %s still serves content", record.IP),
				})
			}
		}
	}

	// Look for nameserver changes indicating hosting changes
	if len(history.NSHistory) > 1 {
		findings = append(findings, Finding{
			Type:     "NAMESERVER_CHANGES",
			Severity: "LOW",
			Domain:   history.Domain,
			Details:  "Multiple nameserver changes detected",
		})
	}

	return findings
}

func (d *DNSHistoryClient) wasCloudService(value string) bool {
	cloudPatterns := []string{
		"amazonaws.com",
		"cloudfront.net",
		"azurewebsites.net",
		"herokuapp.com",
		"github.io",
		"netlify.com",
		"vercel.app",
		"surge.sh",
		"s3.amazonaws.com",
		"cloudflare.com",
	}

	for _, pattern := range cloudPatterns {
		if strings.Contains(strings.ToLower(value), pattern) {
			return true
		}
	}
	return false
}

func (d *DNSHistoryClient) currentlyExists(domain string) bool {
	// Simple DNS lookup to check if domain exists
	// In a real implementation, this would use proper DNS resolution
	return false // Placeholder
}

func (d *DNSHistoryClient) stillHasWebService(ip string) bool {
	// Check if IP still serves web content
	// In a real implementation, this would make HTTP requests
	return false // Placeholder
}

func (d *DNSHistoryClient) isInterestingSubdomain(subdomain string) bool {
	interestingPatterns := []string{
		"admin", "api", "dev", "test", "staging", "internal",
		"mail", "ftp", "ssh", "vpn", "db", "database",
		"backup", "old", "new", "legacy", "beta",
	}

	subLower := strings.ToLower(subdomain)
	for _, pattern := range interestingPatterns {
		if strings.Contains(subLower, pattern) {
			return true
		}
	}
	return false
}

// SecurityTrails API implementation
func (st *SecurityTrailsClient) GetHistory(ctx context.Context, domain string) (*DNSHistory, error) {
	url := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/a", domain)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("APIKEY", st.APIKey)
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := st.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SecurityTrails API returned status %d", resp.StatusCode)
	}
	
	var response SecurityTrailsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	
	return st.convertToHistory(domain, response), nil
}

func (st *SecurityTrailsClient) convertToHistory(domain string, response SecurityTrailsResponse) *DNSHistory {
	history := &DNSHistory{
		Domain:     domain,
		Subdomains: make(map[string][]HistoricalRecord),
		IPHistory:  make(map[string][]IPRecord),
	}
	
	for _, record := range response.Records {
		for _, value := range record.Values {
			histRecord := HistoricalRecord{
				Type:      record.Type,
				Value:     value,
				FirstSeen: record.First,
				LastSeen:  record.Last,
				Source:    "SecurityTrails",
			}
			
			history.Subdomains[domain] = append(history.Subdomains[domain], histRecord)
			
			// If it's an A record, also add to IP history
			if record.Type == "A" {
				ipRecord := IPRecord{
					IP:        value,
					FirstSeen: record.First,
					LastSeen:  record.Last,
					Source:    "SecurityTrails",
				}
				history.IPHistory[domain] = append(history.IPHistory[domain], ipRecord)
			}
		}
	}
	
	return history
}

// DNSDB API implementation
func (dnsdb *DNSDBClient) QueryDomain(ctx context.Context, domain string) (*DNSHistory, error) {
	url := fmt.Sprintf("https://api.dnsdb.info/lookup/rrset/name/%s", domain)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("X-API-Key", dnsdb.APIKey)
	req.Header.Set("Accept", "application/json")
	
	resp, err := dnsdb.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DNSDB API returned status %d", resp.StatusCode)
	}
	
	var response DNSDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	
	return dnsdb.convertToHistory(domain, response), nil
}

func (dnsdb *DNSDBClient) convertToHistory(domain string, response DNSDBResponse) *DNSHistory {
	history := &DNSHistory{
		Domain:     domain,
		Subdomains: make(map[string][]HistoricalRecord),
		IPHistory:  make(map[string][]IPRecord),
	}
	
	for _, record := range response.Data {
		histRecord := HistoricalRecord{
			Type:      record.RRType,
			Value:     record.RData,
			FirstSeen: record.TimeFirst,
			LastSeen:  record.TimeLast,
			Source:    "DNSDB",
		}
		
		history.Subdomains[record.RRName] = append(history.Subdomains[record.RRName], histRecord)
		
		if record.RRType == "A" {
			ipRecord := IPRecord{
				IP:        record.RData,
				FirstSeen: record.TimeFirst,
				LastSeen:  record.TimeLast,
				Source:    "DNSDB",
			}
			history.IPHistory[record.RRName] = append(history.IPHistory[record.RRName], ipRecord)
		}
	}
	
	return history
}

// ViewDNS API implementation
func (vdns *ViewDNSClient) GetIPHistory(ctx context.Context, domain string) (*DNSHistory, error) {
	url := fmt.Sprintf("https://api.viewdns.info/iphistory/?domain=%s&apikey=%s&output=json", domain, vdns.APIKey)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	resp, err := vdns.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ViewDNS API returned status %d", resp.StatusCode)
	}
	
	var response ViewDNSResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	
	return vdns.convertToHistory(domain, response), nil
}

func (vdns *ViewDNSClient) convertToHistory(domain string, response ViewDNSResponse) *DNSHistory {
	history := &DNSHistory{
		Domain:     domain,
		Subdomains: make(map[string][]HistoricalRecord),
		IPHistory:  make(map[string][]IPRecord),
	}
	
	for _, record := range response.Response.Records {
		// Parse date
		date, err := time.Parse("2006-01-02", record.Date)
		if err != nil {
			continue
		}
		
		histRecord := HistoricalRecord{
			Type:      "A",
			Value:     record.IP,
			FirstSeen: date,
			LastSeen:  date,
			Source:    "ViewDNS",
		}
		
		history.Subdomains[domain] = append(history.Subdomains[domain], histRecord)
		
		ipRecord := IPRecord{
			IP:        record.IP,
			FirstSeen: date,
			LastSeen:  date,
			Source:    "ViewDNS",
		}
		history.IPHistory[domain] = append(history.IPHistory[domain], ipRecord)
	}
	
	return history
}

// Merge function to combine multiple history sources
func (h *DNSHistory) Merge(other *DNSHistory) {
	if other == nil {
		return
	}
	
	// Merge subdomains
	for domain, records := range other.Subdomains {
		h.Subdomains[domain] = append(h.Subdomains[domain], records...)
	}
	
	// Merge IP history
	for domain, records := range other.IPHistory {
		h.IPHistory[domain] = append(h.IPHistory[domain], records...)
	}
	
	// Merge NS history
	h.NSHistory = append(h.NSHistory, other.NSHistory...)
	
	// Merge MX history
	h.MXHistory = append(h.MXHistory, other.MXHistory...)
	
	// Merge findings
	h.Findings = append(h.Findings, other.Findings...)
}

// Utility function to check for subdomain takeover patterns
func (d *DNSHistoryClient) CheckSubdomainTakeover(subdomain string) *Finding {
	// Check for common takeover patterns
	takeoverPatterns := map[string]string{
		"amazonaws.com":     "AWS S3",
		"cloudfront.net":    "AWS CloudFront",
		"herokuapp.com":     "Heroku",
		"github.io":         "GitHub Pages",
		"netlify.com":       "Netlify",
		"vercel.app":        "Vercel",
		"surge.sh":          "Surge",
		"fastly.com":        "Fastly",
		"cloudflare.com":    "Cloudflare",
		"azurewebsites.net": "Azure",
	}
	
	// This would be implemented with actual DNS resolution
	// Check if subdomain matches any takeover patterns
	for pattern, service := range takeoverPatterns {
		if strings.Contains(strings.ToLower(subdomain), pattern) {
			return &Finding{
				Type:     "POTENTIAL_SUBDOMAIN_TAKEOVER",
				Severity: "HIGH",
				Domain:   subdomain,
				Details:  fmt.Sprintf("Subdomain may be vulnerable to takeover via %s", service),
			}
		}
	}
	
	return nil
}

// Pattern detection for DNS enumeration
func (d *DNSHistoryClient) DetectPatterns(subdomains []string) *PatternAnalysis {
	analysis := &PatternAnalysis{
		CustomPatterns: []string{},
	}
	
	devPattern := regexp.MustCompile(`(?i)(dev|develop|development)`)
	regionalPattern := regexp.MustCompile(`(?i)(us|eu|asia|west|east|north|south)`)
	apiPattern := regexp.MustCompile(`(?i)(api|rest|graphql|v1|v2|v3)`)
	stagingPattern := regexp.MustCompile(`(?i)(staging|stage|test|qa|uat)`)
	
	for _, subdomain := range subdomains {
		if devPattern.MatchString(subdomain) {
			analysis.HasDevPattern = true
		}
		if regionalPattern.MatchString(subdomain) {
			analysis.HasRegionalPattern = true
		}
		if apiPattern.MatchString(subdomain) {
			analysis.HasAPIPattern = true
		}
		if stagingPattern.MatchString(subdomain) {
			analysis.HasStagingPattern = true
		}
	}
	
	return analysis
}