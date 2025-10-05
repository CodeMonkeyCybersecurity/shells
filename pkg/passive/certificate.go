// pkg/passive/certificate.go
package passive

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// CertIntel provides certificate transparency intelligence
type CertIntel struct {
	logger      *logger.Logger
	httpClient  *http.Client
	ctLogAPIs   []CTLogAPI
	tlsConfig   *tls.Config
	patternDB   *PatternDatabase
	emailParser *EmailParser
}

// CTLogAPI represents a Certificate Transparency log API
type CTLogAPI interface {
	Name() string
	SearchDomain(domain string) ([]CertificateRecord, error)
	StreamNewCertificates(domain string) <-chan CertificateRecord
}

// CertificateRecord represents a certificate from CT logs
type CertificateRecord struct {
	Domain         string
	SANs           []string
	CommonName     string
	Organizations  []string
	EmailAddresses []string
	NotBefore      time.Time
	NotAfter       time.Time
	SerialNumber   string
	Issuer         string
	Fingerprint    string
	LogURL         string
	EntryTimestamp time.Time
}

// NewCertIntel creates a new certificate intelligence module
func NewCertIntel(logger *logger.Logger) *CertIntel {
	return &CertIntel{
		logger:     logger,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		ctLogAPIs: []CTLogAPI{
			NewCrtShAPI(),
			NewFacebookCTAPI(),
			NewGoogleCTAPI(),
			NewCensysCertAPI(),
		},
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true, // For scanning purposes
		},
		patternDB:   NewPatternDatabase(),
		emailParser: NewEmailParser(),
	}
}

// StreamCertificates monitors CT logs for new certificates in real-time
func (c *CertIntel) StreamCertificates(domain string) <-chan Certificate {
	outChan := make(chan Certificate, 100)

	go func() {
		defer close(outChan)

		// Start streaming from each CT log API
		var wg sync.WaitGroup
		for _, api := range c.ctLogAPIs {
			wg.Add(1)
			go func(ctAPI CTLogAPI) {
				defer wg.Done()

				stream := ctAPI.StreamNewCertificates(domain)
				for cert := range stream {
					// Convert to our Certificate type
					converted := c.convertToCertificate(cert)
					outChan <- converted
				}
			}(api)
		}

		wg.Wait()
	}()

	return outChan
}

// ExtractIntel extracts intelligence from a certificate
func (c *CertIntel) ExtractIntel(cert Certificate) CertificateIntel {
	intel := CertificateIntel{
		Domain:        cert.Subject.CommonName,
		SANs:          cert.DNSNames,
		Organizations: cert.Subject.Organization,
		Emails:        []string{},
		IssuedDate:    cert.NotBefore,
		ExpiryDate:    cert.NotAfter,
		Issuer:        cert.Issuer.CommonName,
		SerialNumber:  cert.SerialNumber.String(),
		Fingerprint:   c.calculateFingerprint(cert),
	}

	// Extract wildcard patterns
	intel.WildcardPatterns = c.extractWildcardPatterns(cert.DNSNames)

	// Identify internal naming patterns
	intel.InternalNames = c.identifyInternalNames(cert.DNSNames)

	// Extract emails from certificate
	intel.Emails = c.extractEmails(cert)

	// Add additional metadata
	c.enrichIntelligence(&intel, cert)

	return intel
}

// IdentifyNamingPatterns analyzes certificates to find naming conventions
func (c *CertIntel) IdentifyNamingPatterns(certs []Certificate) []Pattern {
	var allDomains []string

	// Collect all domain names
	for _, cert := range certs {
		allDomains = append(allDomains, cert.DNSNames...)
	}

	// Deduplicate
	domainSet := make(map[string]bool)
	var uniqueDomains []string
	for _, domain := range allDomains {
		if !domainSet[domain] {
			domainSet[domain] = true
			uniqueDomains = append(uniqueDomains, domain)
		}
	}

	// Analyze patterns
	patterns := c.patternDB.AnalyzePatterns(uniqueDomains)

	// Generate predictions based on patterns
	for i := range patterns {
		patterns[i].Predictions = c.generatePredictions(patterns[i])
	}

	c.logger.Info("Identified naming patterns",
		"count", len(patterns),
		"domains_analyzed", len(uniqueDomains))

	return patterns
}

// DiscoverAllCertificates finds all certificates for a domain across CT logs
func (c *CertIntel) DiscoverAllCertificates(ctx context.Context, domain string) ([]CertificateRecord, error) {
	var allCerts []CertificateRecord
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Query each CT log API
	for _, api := range c.ctLogAPIs {
		wg.Add(1)
		go func(ctAPI CTLogAPI) {
			defer wg.Done()

			certs, err := ctAPI.SearchDomain(domain)
			if err != nil {
				c.logger.Error("CT log search failed",
					"api", ctAPI.Name(),
					"domain", domain,
					"error", err)
				return
			}

			mu.Lock()
			allCerts = append(allCerts, certs...)
			mu.Unlock()

			c.logger.Info("CT log search completed",
				"api", ctAPI.Name(),
				"domain", domain,
				"certificates", len(certs))
		}(api)
	}

	wg.Wait()

	// Deduplicate by fingerprint
	allCerts = c.deduplicateCertificates(allCerts)

	// Sort by timestamp
	c.sortCertificatesByTime(allCerts)

	return allCerts, nil
}

// CorrelateWithEmailDomains finds certificates using email domain patterns
func (c *CertIntel) CorrelateWithEmailDomains(emails []string) []string {
	var correlatedDomains []string
	domainSet := make(map[string]bool)

	// Extract domains from emails
	emailDomains := c.emailParser.ExtractDomainsFromEmails(emails)

	// Search for certificates with these domains
	for _, domain := range emailDomains {
		certs, err := c.DiscoverAllCertificates(context.Background(), domain)
		if err != nil {
			continue
		}

		// Extract all unique domains from certificates
		for _, cert := range certs {
			for _, san := range cert.SANs {
				if !domainSet[san] {
					domainSet[san] = true
					correlatedDomains = append(correlatedDomains, san)
				}
			}
		}
	}

	// Look for email patterns in certificate metadata
	patterns := c.emailParser.IdentifyEmailPatterns(emails)
	predictedDomains := c.predictDomainsFromEmailPatterns(patterns)

	for _, predicted := range predictedDomains {
		if !domainSet[predicted] {
			domainSet[predicted] = true
			correlatedDomains = append(correlatedDomains, predicted)
		}
	}

	return correlatedDomains
}

// extractWildcardPatterns identifies wildcard certificate patterns
func (c *CertIntel) extractWildcardPatterns(domains []string) []string {
	var patterns []string
	patternSet := make(map[string]bool)

	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			pattern := strings.TrimPrefix(domain, "*.")
			if !patternSet[pattern] {
				patternSet[pattern] = true
				patterns = append(patterns, pattern)
			}
		}
	}

	return patterns
}

// identifyInternalNames finds potentially internal domain names
func (c *CertIntel) identifyInternalNames(domains []string) []string {
	var internal []string

	// Patterns that suggest internal use
	internalPatterns := []string{
		"internal", "intranet", "corp", "private", "local",
		"staging", "dev", "test", "qa", "uat", "sandbox",
		"vpn", "admin", "console", "dashboard", "portal",
		"10.", "172.", "192.168.", // RFC1918 IPs
	}

	// TLDs that suggest internal use
	internalTLDs := []string{
		".local", ".internal", ".corp", ".lan", ".home",
		".test", ".example", ".invalid", ".localhost",
	}

	for _, domain := range domains {
		domainLower := strings.ToLower(domain)

		// Check patterns
		for _, pattern := range internalPatterns {
			if strings.Contains(domainLower, pattern) {
				internal = append(internal, domain)
				break
			}
		}

		// Check TLDs
		for _, tld := range internalTLDs {
			if strings.HasSuffix(domainLower, tld) {
				internal = append(internal, domain)
				break
			}
		}

		// Check for numeric subdomains (often internal)
		if matched, _ := regexp.MatchString(`^[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}\.`, domainLower); matched {
			internal = append(internal, domain)
		}
	}

	return c.deduplicateStrings(internal)
}

// generatePredictions generates predicted domain names from patterns
func (c *CertIntel) generatePredictions(pattern Pattern) []string {
	var predictions []string

	switch pattern.Type {
	case "sequential":
		predictions = c.generateSequentialPredictions(pattern)
	case "prefix":
		predictions = c.generatePrefixPredictions(pattern)
	case "suffix":
		predictions = c.generateSuffixPredictions(pattern)
	case "template":
		predictions = c.generateTemplatePredictions(pattern)
	}

	// Test if predictions resolve
	var validPredictions []string
	for _, pred := range predictions {
		if c.domainExists(pred) {
			validPredictions = append(validPredictions, pred)
		}
	}

	return validPredictions
}

// CrtShAPI implements the CTLogAPI interface for crt.sh
type CrtShAPI struct {
	baseURL    string
	httpClient *http.Client
}

func NewCrtShAPI() *CrtShAPI {
	return &CrtShAPI{
		baseURL:    "https://crt.sh",
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *CrtShAPI) Name() string {
	return "crt.sh"
}

func (c *CrtShAPI) SearchDomain(domain string) ([]CertificateRecord, error) {
	url := fmt.Sprintf("%s/?q=%%25.%s&output=json", c.baseURL, domain)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	var crtShResults []struct {
		IssuerCAID     int    `json:"issuer_ca_id"`
		IssuerName     string `json:"issuer_name"`
		CommonName     string `json:"common_name"`
		NameValue      string `json:"name_value"`
		ID             int64  `json:"id"`
		EntryTimestamp string `json:"entry_timestamp"`
		NotBefore      string `json:"not_before"`
		NotAfter       string `json:"not_after"`
		SerialNumber   string `json:"serial_number"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&crtShResults); err != nil {
		return nil, err
	}

	var records []CertificateRecord
	for _, result := range crtShResults {
		// Parse timestamps
		entryTime, _ := time.Parse("2006-01-02T15:04:05.999", result.EntryTimestamp)
		notBefore, _ := time.Parse("2006-01-02T15:04:05", result.NotBefore)
		notAfter, _ := time.Parse("2006-01-02T15:04:05", result.NotAfter)

		// Parse SANs
		sans := strings.Split(result.NameValue, "\n")

		record := CertificateRecord{
			Domain:         result.CommonName,
			SANs:           sans,
			CommonName:     result.CommonName,
			NotBefore:      notBefore,
			NotAfter:       notAfter,
			SerialNumber:   result.SerialNumber,
			Issuer:         result.IssuerName,
			LogURL:         fmt.Sprintf("%s/?id=%d", c.baseURL, result.ID),
			EntryTimestamp: entryTime,
		}

		records = append(records, record)
	}

	return records, nil
}

func (c *CrtShAPI) StreamNewCertificates(domain string) <-chan CertificateRecord {
	ch := make(chan CertificateRecord)

	go func() {
		defer close(ch)

		// Poll for new certificates every minute
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		lastCheck := time.Now()

		for range ticker.C {
			certs, err := c.SearchDomain(domain)
			if err != nil {
				continue
			}

			// Only send new certificates
			for _, cert := range certs {
				if cert.EntryTimestamp.After(lastCheck) {
					ch <- cert
				}
			}

			lastCheck = time.Now()
		}
	}()

	return ch
}

// Helper structures

// PatternDatabase analyzes and stores naming patterns
type PatternDatabase struct {
	patterns map[string][]Pattern
	mu       sync.RWMutex
}

func NewPatternDatabase() *PatternDatabase {
	return &PatternDatabase{
		patterns: make(map[string][]Pattern),
	}
}

func (p *PatternDatabase) AnalyzePatterns(domains []string) []Pattern {
	var patterns []Pattern

	// Sequential numbering pattern (e.g., app1, app2, app3)
	seqPattern := regexp.MustCompile(`([a-zA-Z]+)(\d+)`)
	sequences := make(map[string][]int)

	for _, domain := range domains {
		parts := strings.Split(domain, ".")
		for _, part := range parts {
			if matches := seqPattern.FindStringSubmatch(part); len(matches) == 3 {
				prefix := matches[1]
				var num int
				fmt.Sscanf(matches[2], "%d", &num)
				sequences[prefix] = append(sequences[prefix], num)
			}
		}
	}

	// Identify sequential patterns
	for prefix, numbers := range sequences {
		if len(numbers) >= 3 {
			patterns = append(patterns, Pattern{
				Type:       "sequential",
				Template:   fmt.Sprintf("%s{N}", prefix),
				Examples:   p.generateExamples(prefix, numbers),
				Confidence: float64(len(numbers)) / 10.0,
			})
		}
	}

	// Environment-based patterns (dev, test, prod)
	envPattern := regexp.MustCompile(`(dev|test|qa|uat|stage|staging|prod|production)`)
	envDomains := make(map[string][]string)

	for _, domain := range domains {
		if matches := envPattern.FindStringSubmatch(domain); len(matches) > 0 {
			env := matches[1]
			envDomains[env] = append(envDomains[env], domain)
		}
	}

	// Region-based patterns
	regionPattern := regexp.MustCompile(`(us|eu|asia|uk|au|ca|jp|kr|cn)-?(east|west|north|south|central)?-?(\d+)?`)
	regionDomains := make(map[string][]string)

	for _, domain := range domains {
		if matches := regionPattern.FindStringSubmatch(domain); len(matches) > 0 {
			region := matches[0]
			regionDomains[region] = append(regionDomains[region], domain)
		}
	}

	return patterns
}

// EmailParser extracts and analyzes email patterns
type EmailParser struct {
	domainExtractor *regexp.Regexp
	patterns        map[string]EmailPattern
}

type EmailPattern struct {
	Format   string
	Examples []string
	Domain   string
}

func NewEmailParser() *EmailParser {
	return &EmailParser{
		domainExtractor: regexp.MustCompile(`@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$`),
		patterns:        make(map[string]EmailPattern),
	}
}

func (e *EmailParser) ExtractDomainsFromEmails(emails []string) []string {
	domainSet := make(map[string]bool)
	var domains []string

	for _, email := range emails {
		if matches := e.domainExtractor.FindStringSubmatch(email); len(matches) > 1 {
			domain := matches[1]
			if !domainSet[domain] {
				domainSet[domain] = true
				domains = append(domains, domain)
			}
		}
	}

	return domains
}

func (e *EmailParser) IdentifyEmailPatterns(emails []string) []EmailPattern {
	// Group emails by domain
	domainEmails := make(map[string][]string)

	for _, email := range emails {
		if matches := e.domainExtractor.FindStringSubmatch(email); len(matches) > 1 {
			domain := matches[1]
			domainEmails[domain] = append(domainEmails[domain], email)
		}
	}

	var patterns []EmailPattern

	// Analyze patterns per domain
	for domain, domainEmailList := range domainEmails {
		if len(domainEmailList) >= 3 {
			// Extract local parts
			var localParts []string
			for _, email := range domainEmailList {
				parts := strings.Split(email, "@")
				if len(parts) == 2 {
					localParts = append(localParts, parts[0])
				}
			}

			// Detect common patterns
			pattern := e.detectEmailFormat(localParts)
			if pattern != "" {
				patterns = append(patterns, EmailPattern{
					Format:   pattern,
					Examples: domainEmailList[:min(3, len(domainEmailList))],
					Domain:   domain,
				})
			}
		}
	}

	return patterns
}

func (e *EmailParser) detectEmailFormat(localParts []string) string {
	// Check for firstname.lastname pattern
	dotCount := 0
	for _, part := range localParts {
		if strings.Contains(part, ".") {
			dotCount++
		}
	}
	if float64(dotCount)/float64(len(localParts)) > 0.7 {
		return "firstname.lastname"
	}

	// Check for first initial + lastname pattern
	singleInitial := 0
	for _, part := range localParts {
		if matched, _ := regexp.MatchString(`^[a-z][a-z]{2,}$`, part); matched {
			singleInitial++
		}
	}
	if float64(singleInitial)/float64(len(localParts)) > 0.7 {
		return "flastname"
	}

	return ""
}

// Utility functions

func (c *CertIntel) deduplicateStrings(strs []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, str := range strs {
		if !seen[str] {
			seen[str] = true
			result = append(result, str)
		}
	}

	return result
}

func (c *CertIntel) domainExists(domain string) bool {
	_, err := net.LookupIP(domain)
	return err == nil
}

func (c *CertIntel) deduplicateCertificates(certs []CertificateRecord) []CertificateRecord {
	seen := make(map[string]bool)
	var unique []CertificateRecord

	for _, cert := range certs {
		key := fmt.Sprintf("%s-%s-%s", cert.SerialNumber, cert.Issuer, cert.CommonName)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, cert)
		}
	}

	return unique
}

func (c *CertIntel) sortCertificatesByTime(certs []CertificateRecord) {
	// Simple bubble sort for now
	for i := 0; i < len(certs); i++ {
		for j := i + 1; j < len(certs); j++ {
			if certs[i].EntryTimestamp.Before(certs[j].EntryTimestamp) {
				certs[i], certs[j] = certs[j], certs[i]
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
