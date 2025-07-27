package certlogs

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

// CTLogClient queries Certificate Transparency logs
type CTLogClient struct {
	client     *http.Client
	logger     *logger.Logger
	logServers []CTLogServer
	mu         sync.RWMutex
}

// CTLogServer represents a CT log server
type CTLogServer struct {
	Name        string
	URL         string
	Description string
	Active      bool
}

// Certificate represents a certificate from CT logs
type Certificate struct {
	Domain       string
	SubjectCN    string
	SANs         []string // Subject Alternative Names
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	SerialNumber string
	LogEntry     CTLogEntry
}

// CTLogEntry represents an entry from a CT log
type CTLogEntry struct {
	LeafInput    string    `json:"leaf_input"`
	ExtraData    string    `json:"extra_data"`
	EntryType    int       `json:"entry_type"`
	Timestamp    int64     `json:"timestamp"`
	LogServer    string    `json:"log_server"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// NewCTLogClient creates a new Certificate Transparency log client
func NewCTLogClient(logger *logger.Logger) *CTLogClient {
	client := &CTLogClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger:     logger,
		logServers: getDefaultCTLogServers(),
	}

	return client
}

// getDefaultCTLogServers returns popular CT log servers
func getDefaultCTLogServers() []CTLogServer {
	return []CTLogServer{
		{
			Name:        "Google Argon",
			URL:         "https://ct.googleapis.com/logs/argon2023",
			Description: "Google CT log server",
			Active:      true,
		},
		{
			Name:        "Google Xenon",
			URL:         "https://ct.googleapis.com/logs/xenon2023",
			Description: "Google CT log server",
			Active:      true,
		},
		{
			Name:        "Cloudflare Nimbus",
			URL:         "https://ct.cloudflare.com/logs/nimbus2023",
			Description: "Cloudflare CT log server",
			Active:      true,
		},
		{
			Name:        "DigiCert Yeti",
			URL:         "https://yeti2023.ct.digicert.com/log",
			Description: "DigiCert CT log server",
			Active:      true,
		},
		{
			Name:        "Sectigo Sabre",
			URL:         "https://sabre.ct.comodo.com",
			Description: "Sectigo CT log server",
			Active:      true,
		},
	}
}

// SearchDomain searches for certificates for a domain in CT logs
func (c *CTLogClient) SearchDomain(ctx context.Context, domain string) ([]Certificate, error) {
	var allCerts []Certificate
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Use crt.sh as primary source (aggregates multiple CT logs)
	crtshCerts, err := c.searchCrtSh(ctx, domain)
	if err != nil {
		c.logger.Error("Failed to search crt.sh", "error", err)
	} else {
		allCerts = append(allCerts, crtshCerts...)
	}

	// Also search individual CT logs for more recent entries
	for _, server := range c.logServers {
		if !server.Active {
			continue
		}

		wg.Add(1)
		go func(srv CTLogServer) {
			defer wg.Done()

			certs, err := c.searchCTLog(ctx, srv, domain)
			if err != nil {
				c.logger.Error("Failed to search CT log",
					"server", srv.Name,
					"error", err)
				return
			}

			mu.Lock()
			allCerts = append(allCerts, certs...)
			mu.Unlock()
		}(server)
	}

	wg.Wait()

	// Deduplicate certificates by serial number
	uniqueCerts := c.deduplicateCerts(allCerts)

	c.logger.Info("CT log search completed",
		"domain", domain,
		"total_certs", len(allCerts),
		"unique_certs", len(uniqueCerts))

	return uniqueCerts, nil
}

// searchCrtSh searches crt.sh for certificates
func (c *CTLogClient) searchCrtSh(ctx context.Context, domain string) ([]Certificate, error) {
	// crt.sh provides a simple JSON API
	apiURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse crt.sh response
	var crtshEntries []struct {
		IssuerCaID     int    `json:"issuer_ca_id"`
		IssuerName     string `json:"issuer_name"`
		CommonName     string `json:"common_name"`
		NameValue      string `json:"name_value"`
		ID             int64  `json:"id"`
		EntryTimestamp string `json:"entry_timestamp"`
		NotBefore      string `json:"not_before"`
		NotAfter       string `json:"not_after"`
		SerialNumber   string `json:"serial_number"`
	}

	if err := json.Unmarshal(body, &crtshEntries); err != nil {
		return nil, fmt.Errorf("failed to parse crt.sh response: %w", err)
	}

	var certificates []Certificate
	for _, entry := range crtshEntries {
		// Parse timestamps
		notBefore, _ := time.Parse("2006-01-02T15:04:05", entry.NotBefore)
		notAfter, _ := time.Parse("2006-01-02T15:04:05", entry.NotAfter)
		entryTime, _ := time.Parse("2006-01-02T15:04:05", entry.EntryTimestamp)

		// Extract SANs from name_value (contains all names separated by newlines)
		sans := strings.Split(entry.NameValue, "\n")

		cert := Certificate{
			Domain:       domain,
			SubjectCN:    entry.CommonName,
			SANs:         sans,
			Issuer:       entry.IssuerName,
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			SerialNumber: entry.SerialNumber,
			LogEntry: CTLogEntry{
				LogServer:    "crt.sh",
				Timestamp:    entryTime.Unix(),
				DiscoveredAt: time.Now(),
			},
		}

		certificates = append(certificates, cert)
	}

	return certificates, nil
}

// searchCTLog searches an individual CT log server
func (c *CTLogClient) searchCTLog(ctx context.Context, server CTLogServer, domain string) ([]Certificate, error) {
	// Most CT logs don't provide direct search APIs
	// This is a placeholder for future implementation with specific CT log APIs
	// For now, we rely on crt.sh which aggregates multiple logs

	// Some CT logs like Google's provide get-entries endpoint
	// but require iterating through all entries which is impractical

	return []Certificate{}, nil
}

// deduplicateCerts removes duplicate certificates based on serial number
func (c *CTLogClient) deduplicateCerts(certs []Certificate) []Certificate {
	seen := make(map[string]bool)
	unique := []Certificate{}

	for _, cert := range certs {
		key := cert.SerialNumber + cert.Issuer
		if !seen[key] {
			seen[key] = true
			unique = append(unique, cert)
		}
	}

	return unique
}

// DiscoverSubdomains discovers subdomains from CT logs
func (c *CTLogClient) DiscoverSubdomains(ctx context.Context, domain string) ([]string, error) {
	certificates, err := c.SearchDomain(ctx, domain)
	if err != nil {
		return nil, err
	}

	// Extract unique subdomains
	subdomainMap := make(map[string]bool)

	// Look for wildcard pattern
	wildcardPattern := fmt.Sprintf(".%s", domain)

	for _, cert := range certificates {
		// Check Subject CN
		if strings.HasSuffix(cert.SubjectCN, wildcardPattern) || cert.SubjectCN == domain {
			subdomain := strings.TrimPrefix(cert.SubjectCN, "*.")
			if isValidSubdomain(subdomain, domain) {
				subdomainMap[subdomain] = true
			}
		}

		// Check SANs
		for _, san := range cert.SANs {
			san = strings.TrimSpace(san)
			san = strings.TrimPrefix(san, "*.")

			if strings.HasSuffix(san, wildcardPattern) || san == domain {
				if isValidSubdomain(san, domain) {
					subdomainMap[san] = true
				}
			}
		}
	}

	// Convert map to slice
	var subdomains []string
	for subdomain := range subdomainMap {
		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}

// isValidSubdomain checks if a domain is a valid subdomain
func isValidSubdomain(subdomain, parentDomain string) bool {
	// Ensure it's actually a subdomain
	if !strings.HasSuffix(subdomain, parentDomain) {
		return false
	}

	// Ensure it's not just the parent domain
	if subdomain == parentDomain {
		return true
	}

	// Check if there's at least one subdomain level
	prefix := strings.TrimSuffix(subdomain, "."+parentDomain)
	return len(prefix) > 0 && !strings.Contains(prefix, " ")
}

// GetCertificateTimeline returns certificates ordered by issuance date
func (c *CTLogClient) GetCertificateTimeline(ctx context.Context, domain string) ([]Certificate, error) {
	certs, err := c.SearchDomain(ctx, domain)
	if err != nil {
		return nil, err
	}

	// Sort by NotBefore date (newest first)
	sortCertsByDate(certs)

	return certs, nil
}

// sortCertsByDate sorts certificates by NotBefore date (newest first)
func sortCertsByDate(certs []Certificate) {
	// Simple bubble sort for clarity
	n := len(certs)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if certs[j].NotBefore.Before(certs[j+1].NotBefore) {
				certs[j], certs[j+1] = certs[j+1], certs[j]
			}
		}
	}
}

// FindWildcardCerts finds wildcard certificates for a domain
func (c *CTLogClient) FindWildcardCerts(ctx context.Context, domain string) ([]Certificate, error) {
	allCerts, err := c.SearchDomain(ctx, domain)
	if err != nil {
		return nil, err
	}

	var wildcardCerts []Certificate
	for _, cert := range allCerts {
		// Check if Subject CN is wildcard
		if strings.HasPrefix(cert.SubjectCN, "*.") {
			wildcardCerts = append(wildcardCerts, cert)
			continue
		}

		// Check SANs for wildcards
		for _, san := range cert.SANs {
			if strings.HasPrefix(san, "*.") {
				wildcardCerts = append(wildcardCerts, cert)
				break
			}
		}
	}

	return wildcardCerts, nil
}

// AnalyzeCertificateHistory analyzes the certificate issuance history
func (c *CTLogClient) AnalyzeCertificateHistory(ctx context.Context, domain string) (*CertHistoryAnalysis, error) {
	certs, err := c.GetCertificateTimeline(ctx, domain)
	if err != nil {
		return nil, err
	}

	analysis := &CertHistoryAnalysis{
		Domain:        domain,
		TotalCerts:    len(certs),
		UniqueIssuers: make(map[string]int),
		CertFrequency: make(map[string]int),
		AnalyzedAt:    time.Now(),
	}

	if len(certs) == 0 {
		return analysis, nil
	}

	// Analyze certificates
	now := time.Now()
	var activeCerts []Certificate
	var expiredCerts []Certificate

	for _, cert := range certs {
		// Count issuers
		analysis.UniqueIssuers[cert.Issuer]++

		// Check if active
		if cert.NotBefore.Before(now) && cert.NotAfter.After(now) {
			activeCerts = append(activeCerts, cert)
		} else if cert.NotAfter.Before(now) {
			expiredCerts = append(expiredCerts, cert)
		}

		// Certificate issuance frequency by year
		year := cert.NotBefore.Format("2006")
		analysis.CertFrequency[year]++
	}

	analysis.ActiveCerts = len(activeCerts)
	analysis.ExpiredCerts = len(expiredCerts)

	// Find most recent cert
	if len(certs) > 0 {
		analysis.MostRecentCert = &certs[0]
		analysis.OldestCert = &certs[len(certs)-1]
	}

	return analysis, nil
}

// CertHistoryAnalysis contains certificate history analysis results
type CertHistoryAnalysis struct {
	Domain         string
	TotalCerts     int
	ActiveCerts    int
	ExpiredCerts   int
	UniqueIssuers  map[string]int
	CertFrequency  map[string]int // Year -> Count
	MostRecentCert *Certificate
	OldestCert     *Certificate
	AnalyzedAt     time.Time
}
