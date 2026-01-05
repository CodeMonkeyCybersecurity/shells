// pkg/intel/cloudflare/client.go
package cloudflare

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// OriginCandidate represents a potential origin server
type OriginCandidate struct {
	IP            string
	Confidence    float64
	DiscoveryType string
	Evidence      []string
	Timestamp     time.Time
}

// CloudFlareIntel provides CloudFlare bypass intelligence
type CloudFlareIntel struct {
	logger        *logger.Logger
	httpClient    *http.Client
	dnsResolver   *net.Resolver
	workers       int
	mu            sync.Mutex
	knownCFRanges []string
}

// NewCloudFlareIntel creates a new CloudFlare intelligence client
func NewCloudFlareIntel(log *logger.Logger) *CloudFlareIntel {
	return &CloudFlareIntel{
		logger: log,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		dnsResolver: &net.Resolver{},
		workers:     10,
		knownCFRanges: []string{
			"173.245.48.0/20",
			"103.21.244.0/22",
			"103.22.200.0/22",
			"103.31.4.0/22",
			"141.101.64.0/18",
			"108.162.192.0/18",
			"190.93.240.0/20",
			"188.114.96.0/20",
			"197.234.240.0/22",
			"198.41.128.0/17",
			"162.158.0.0/15",
			"104.16.0.0/13",
			"104.24.0.0/14",
			"172.64.0.0/13",
			"131.0.72.0/22",
		},
	}
}

// DetectCloudFlare checks if a domain is using CloudFlare
func (c *CloudFlareIntel) DetectCloudFlare(ctx context.Context, domain string) (bool, error) {
	// Check DNS
	ips, err := c.dnsResolver.LookupHost(ctx, domain)
	if err != nil {
		return false, fmt.Errorf("DNS lookup failed: %w", err)
	}

	for _, ip := range ips {
		if c.isCloudFlareIP(ip) {
			return true, nil
		}
	}

	// Check HTTP headers
	resp, err := c.httpClient.Get(fmt.Sprintf("https://%s", domain))
	if err != nil {
		// Try HTTP if HTTPS fails
		resp, err = c.httpClient.Get(fmt.Sprintf("http://%s", domain))
		if err != nil {
			return false, fmt.Errorf("HTTP request failed: %w", err)
		}
	}
	defer httpclient.CloseBody(resp)

	// Check for CloudFlare headers
	cfHeaders := []string{
		"CF-Ray",
		"CF-Cache-Status",
		"CF-Request-ID",
		"cf-apo-via",
	}

	for _, header := range cfHeaders {
		if resp.Header.Get(header) != "" {
			return true, nil
		}
	}

	// Check Server header
	if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "cloudflare") {
		return true, nil
	}

	return false, nil
}

// FindOriginIP discovers potential origin IPs behind CloudFlare
func (c *CloudFlareIntel) FindOriginIP(ctx context.Context, domain string) ([]OriginCandidate, error) {
	var candidates []OriginCandidate
	var wg sync.WaitGroup

	// Channel for collecting candidates
	candidateChan := make(chan OriginCandidate, 100)
	done := make(chan bool)

	// Collector goroutine
	go func() {
		for candidate := range candidateChan {
			c.mu.Lock()
			candidates = append(candidates, candidate)
			c.mu.Unlock()
		}
		done <- true
	}()

	// 1. Historical DNS records
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.findHistoricalDNS(ctx, domain, candidateChan)
	}()

	// 2. SSL Certificate SANs
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.findFromSSLCerts(ctx, domain, candidateChan)
	}()

	// 3. SPF/MX records
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.findFromEmailRecords(ctx, domain, candidateChan)
	}()

	// 4. Favicon hash matching
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.findFromFaviconHash(ctx, domain, candidateChan)
	}()

	// 5. Response timing analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.findFromTimingAnalysis(ctx, domain, candidateChan)
	}()

	// 6. HTTP headers leakage
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.findFromHeaderLeaks(ctx, domain, candidateChan)
	}()

	// Wait for all discovery methods to complete
	wg.Wait()
	close(candidateChan)
	<-done

	// Score and deduplicate candidates
	return c.processCanditates(candidates), nil
}

// findHistoricalDNS searches for pre-CloudFlare DNS records
func (c *CloudFlareIntel) findHistoricalDNS(ctx context.Context, domain string, results chan<- OriginCandidate) {
	c.logger.Infow("Searching historical DNS records", "domain", domain)

	// In production, integrate with SecurityTrails, DNS Dumpster APIs
	// This is a placeholder for the actual implementation

	// Example: Check common subdomains that might reveal origin
	subdomains := []string{
		"origin",
		"direct",
		"admin",
		"cpanel",
		"webmail",
		"mail",
		"ftp",
		"dev",
		"staging",
	}

	for _, subdomain := range subdomains {
		target := fmt.Sprintf("%s.%s", subdomain, domain)
		ips, err := c.dnsResolver.LookupHost(ctx, target)
		if err != nil {
			continue
		}

		for _, ip := range ips {
			if !c.isCloudFlareIP(ip) {
				results <- OriginCandidate{
					IP:            ip,
					Confidence:    0.6,
					DiscoveryType: "historical_dns",
					Evidence:      []string{fmt.Sprintf("Found on subdomain: %s", target)},
					Timestamp:     time.Now(),
				}
			}
		}
	}
}

// findFromSSLCerts searches for origin IPs in SSL certificate SANs
func (c *CloudFlareIntel) findFromSSLCerts(ctx context.Context, domain string, results chan<- OriginCandidate) {
	c.logger.Infow("Analyzing SSL certificates", "domain", domain)

	// In production, integrate with crt.sh, Censys APIs
	// This searches for certificates that might be shared between CloudFlare and origin
}

// findFromEmailRecords checks SPF and MX records for origin IPs
func (c *CloudFlareIntel) findFromEmailRecords(ctx context.Context, domain string, results chan<- OriginCandidate) {
	c.logger.Infow("Checking email records", "domain", domain)

	// Check MX records
	mxRecords, err := c.dnsResolver.LookupMX(ctx, domain)
	if err == nil {
		for _, mx := range mxRecords {
			ips, err := c.dnsResolver.LookupHost(ctx, mx.Host)
			if err != nil {
				continue
			}

			for _, ip := range ips {
				if !c.isCloudFlareIP(ip) {
					results <- OriginCandidate{
						IP:            ip,
						Confidence:    0.7,
						DiscoveryType: "mx_record",
						Evidence:      []string{fmt.Sprintf("MX record: %s", mx.Host)},
						Timestamp:     time.Now(),
					}
				}
			}
		}
	}

	// Check SPF records
	txtRecords, err := c.dnsResolver.LookupTXT(ctx, domain)
	if err == nil {
		for _, txt := range txtRecords {
			if strings.HasPrefix(txt, "v=spf1") {
				// Parse SPF record for IP addresses
				c.parseSPFRecord(txt, results)
			}
		}
	}
}

// findFromFaviconHash compares favicon hashes between CloudFlare and potential origins
func (c *CloudFlareIntel) findFromFaviconHash(ctx context.Context, domain string, results chan<- OriginCandidate) {
	c.logger.Infow("Comparing favicon hashes", "domain", domain)

	// Get favicon from CloudFlare
	cfFavicon, err := c.fetchFavicon(fmt.Sprintf("https://%s/favicon.ico", domain))
	if err != nil {
		return
	}

	cfHash := c.calculateFaviconHash(cfFavicon)

	// In production, search Shodan/Censys for matching favicon hashes
	// This finds servers with the same favicon that might be the origin
	_ = cfHash // TODO: Implement favicon hash search
}

// findFromTimingAnalysis uses response timing to identify geographic location
func (c *CloudFlareIntel) findFromTimingAnalysis(ctx context.Context, domain string, results chan<- OriginCandidate) {
	c.logger.Infow("Performing timing analysis", "domain", domain)

	// Measure response times from different geographic locations
	// Compare with CloudFlare edge locations to identify anomalies
}

// findFromHeaderLeaks checks for origin server information in HTTP headers
func (c *CloudFlareIntel) findFromHeaderLeaks(ctx context.Context, domain string, results chan<- OriginCandidate) {
	c.logger.Infow("Checking for header leaks", "domain", domain)

	resp, err := c.httpClient.Get(fmt.Sprintf("https://%s", domain))
	if err != nil {
		return
	}
	defer httpclient.CloseBody(resp)

	// Check for headers that might reveal origin
	suspiciousHeaders := []string{
		"X-Powered-By",
		"X-AspNet-Version",
		"X-Real-IP",
		"X-Originating-IP",
		"X-Forwarded-Server",
		"X-Backend-Server",
	}

	for _, header := range suspiciousHeaders {
		value := resp.Header.Get(header)
		if value != "" {
			// Check if it's an IP address
			if net.ParseIP(value) != nil && !c.isCloudFlareIP(value) {
				results <- OriginCandidate{
					IP:            value,
					Confidence:    0.8,
					DiscoveryType: "header_leak",
					Evidence:      []string{fmt.Sprintf("Found in header: %s: %s", header, value)},
					Timestamp:     time.Now(),
				}
			}
		}
	}
}

// Helper methods

// isCloudFlareIP checks if an IP belongs to CloudFlare ranges
func (c *CloudFlareIntel) isCloudFlareIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, cidr := range c.knownCFRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// fetchFavicon downloads favicon from a URL
func (c *CloudFlareIntel) fetchFavicon(url string) ([]byte, error) {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	favicon := make([]byte, 0)
	buffer := make([]byte, 1024)

	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			favicon = append(favicon, buffer[:n]...)
		}
		if err != nil {
			break
		}
	}

	return favicon, nil
}

// calculateFaviconHash generates MD5 hash of favicon
func (c *CloudFlareIntel) calculateFaviconHash(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// parseSPFRecord extracts IPs from SPF record
func (c *CloudFlareIntel) parseSPFRecord(spf string, results chan<- OriginCandidate) {
	parts := strings.Split(spf, " ")
	for _, part := range parts {
		if strings.HasPrefix(part, "ip4:") || strings.HasPrefix(part, "ip6:") {
			ip := strings.TrimPrefix(strings.TrimPrefix(part, "ip4:"), "ip6:")
			if !c.isCloudFlareIP(ip) {
				results <- OriginCandidate{
					IP:            ip,
					Confidence:    0.7,
					DiscoveryType: "spf_record",
					Evidence:      []string{fmt.Sprintf("Found in SPF: %s", part)},
					Timestamp:     time.Now(),
				}
			}
		}
	}
}

// processCanditates deduplicates and scores candidates
func (c *CloudFlareIntel) processCanditates(candidates []OriginCandidate) []OriginCandidate {
	// Deduplicate by IP
	uniqueMap := make(map[string]OriginCandidate)

	for _, candidate := range candidates {
		if existing, exists := uniqueMap[candidate.IP]; exists {
			// Merge evidence and update confidence
			candidate.Evidence = append(existing.Evidence, candidate.Evidence...)
			candidate.Confidence = (existing.Confidence + candidate.Confidence) / 2

			// Boost confidence if found by multiple methods
			if existing.DiscoveryType != candidate.DiscoveryType {
				candidate.Confidence *= 1.2
				if candidate.Confidence > 1.0 {
					candidate.Confidence = 1.0
				}
			}
		}
		uniqueMap[candidate.IP] = candidate
	}

	// Convert back to slice
	result := make([]OriginCandidate, 0, len(uniqueMap))
	for _, candidate := range uniqueMap {
		result = append(result, candidate)
	}

	return result
}

// ScoreOriginCandidate calculates confidence score for a candidate
func (c *CloudFlareIntel) ScoreOriginCandidate(candidate OriginCandidate) float64 {
	score := candidate.Confidence

	// Boost score based on evidence count
	evidenceBoost := float64(len(candidate.Evidence)) * 0.1
	score += evidenceBoost

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}
