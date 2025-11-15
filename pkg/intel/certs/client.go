// pkg/intel/certs/client.go
package certs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

// Certificate represents an SSL certificate with metadata
type Certificate struct {
	ID               string
	IssuerCAID       int
	IssuerName       string
	CommonName       string
	NameValue        string // All names including SANs
	NotBefore        time.Time
	NotAfter         time.Time
	SerialNumber     string
	SubjectAltNames  []string
	Organization     string
	OrganizationUnit string
	Country          string
	State            string
	Locality         string
	Fingerprint      string
}

// CertificateIntel provides intelligence from certificate analysis
type CertificateIntel struct {
	SubjectAltNames    []string
	WildcardPatterns   []Pattern
	InternalDomains    []string
	AssociatedOrgs     []string
	CertificatePinning bool
	IssuerInfo         IssuerInfo
}

// Pattern represents a naming pattern discovered from certificates
type Pattern struct {
	Pattern    string
	Examples   []string
	Confidence float64
	Type       string // "subdomain", "service", "environment", etc.
}

// IssuerInfo contains certificate issuer information
type IssuerInfo struct {
	Name    string
	Trusted bool
	Type    string // "public", "private", "self-signed"
}

// CertIntel provides certificate transparency intelligence
type CertIntel struct {
	logger      *logger.Logger
	httpClient  *http.Client
	workers     int
	mu          sync.Mutex
	rateLimiter *time.Ticker
	ctLogAPIs   []CTLogAPI
}

// CTLogAPI represents a Certificate Transparency log API
type CTLogAPI struct {
	Name    string
	BaseURL string
	APIKey  string // Optional
}

// NewCertIntel creates a new certificate intelligence client
func NewCertIntel(log *logger.Logger) *CertIntel {
	return &CertIntel{
		logger: log,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		workers:     5,
		rateLimiter: time.NewTicker(100 * time.Millisecond), // 10 requests per second
		ctLogAPIs: []CTLogAPI{
			{
				Name:    "crt.sh",
				BaseURL: "https://crt.sh",
			},
			{
				Name:    "Google Argon",
				BaseURL: "https://ct.googleapis.com/logs/argon2021",
			},
			// Additional CT logs can be added here
		},
	}
}

// StreamCertificates monitors all certificates for a domain
func (c *CertIntel) StreamCertificates(ctx context.Context, domain string) <-chan Certificate {
	certChan := make(chan Certificate, 100)

	go func() {
		defer close(certChan)

		// Query each CT log
		var wg sync.WaitGroup
		for _, ctLog := range c.ctLogAPIs {
			wg.Add(1)
			go func(log CTLogAPI) {
				defer wg.Done()
				c.queryCTLog(ctx, log, domain, certChan)
			}(ctLog)
		}

		wg.Wait()
	}()

	return certChan
}

// ExtractIntel extracts intelligence from a certificate
func (c *CertIntel) ExtractIntel(cert Certificate) CertificateIntel {
	intel := CertificateIntel{
		SubjectAltNames: cert.SubjectAltNames,
		AssociatedOrgs:  []string{},
	}

	// Extract all unique domain names
	domains := c.extractAllDomains(cert)

	// Find wildcard patterns
	intel.WildcardPatterns = c.findWildcardPatterns(domains)

	// Identify internal domains
	intel.InternalDomains = c.identifyInternalDomains(domains)

	// Extract organization info
	if cert.Organization != "" {
		intel.AssociatedOrgs = append(intel.AssociatedOrgs, cert.Organization)
	}

	// Analyze issuer
	intel.IssuerInfo = c.analyzeIssuer(cert)

	// Check for certificate pinning indicators
	intel.CertificatePinning = c.detectCertificatePinning(cert)

	return intel
}

// IdentifyNamingPatterns identifies naming patterns from multiple certificates
func (c *CertIntel) IdentifyNamingPatterns(certs []Certificate) []Pattern {
	// Collect all domain names
	allDomains := make(map[string]int)
	for _, cert := range certs {
		domains := c.extractAllDomains(cert)
		for _, domain := range domains {
			allDomains[domain]++
		}
	}

	// Analyze patterns
	patterns := []Pattern{}

	// 1. Subdomain patterns
	subdomainPatterns := c.analyzeSubdomainPatterns(allDomains)
	patterns = append(patterns, subdomainPatterns...)

	// 2. Service naming patterns
	servicePatterns := c.analyzeServicePatterns(allDomains)
	patterns = append(patterns, servicePatterns...)

	// 3. Environment patterns
	envPatterns := c.analyzeEnvironmentPatterns(allDomains)
	patterns = append(patterns, envPatterns...)

	// 4. Geographic patterns
	geoPatterns := c.analyzeGeographicPatterns(allDomains)
	patterns = append(patterns, geoPatterns...)

	// Sort by confidence
	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].Confidence > patterns[j].Confidence
	})

	return patterns
}

// queryCTLog queries a specific CT log for certificates
func (c *CertIntel) queryCTLog(ctx context.Context, ctLog CTLogAPI, domain string, results chan<- Certificate) {
	switch ctLog.Name {
	case "crt.sh":
		c.queryCrtSh(ctx, domain, results)
	case "Google Argon":
		c.queryGoogleCT(ctx, ctLog, domain, results)
	default:
		c.logger.Warn("Unknown CT log", "name", ctLog.Name)
	}
}

// queryCrtSh queries crt.sh for certificates
func (c *CertIntel) queryCrtSh(ctx context.Context, domain string, results chan<- Certificate) {
	// Query crt.sh API
	apiURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		c.logger.Error("Failed to create request", "error", err)
		return
	}

	<-c.rateLimiter.C // Rate limiting

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("Failed to query crt.sh", "error", err)
		return
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == 502 || resp.StatusCode == 429 || resp.StatusCode == 503 {
			c.logger.Debug("crt.sh temporarily unavailable", "status", resp.StatusCode)
		} else {
			c.logger.Warn("crt.sh returned non-200 status", "status", resp.StatusCode)
		}
		return
	}

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Error("Failed to read response", "error", err)
		return
	}

	var crtShResults []crtShResult
	if err := json.Unmarshal(body, &crtShResults); err != nil {
		c.logger.Error("Failed to parse crt.sh response", "error", err)
		return
	}

	// Convert to certificates
	seen := make(map[string]bool)
	for _, result := range crtShResults {
		// Deduplicate by ID
		idStr := result.ID.String()
		if seen[idStr] {
			continue
		}
		seen[idStr] = true

		cert := c.convertCrtShResult(result)
		select {
		case results <- cert:
		case <-ctx.Done():
			return
		}
	}

	c.logger.Infow("Retrieved certificates from crt.sh", "count", len(crtShResults), "domain", domain)
}

// crtShResult represents a result from crt.sh API
type crtShResult struct {
	ID           json.Number `json:"id"`
	IssuerCAID   int         `json:"issuer_ca_id"`
	IssuerName   string      `json:"issuer_name"`
	CommonName   string      `json:"common_name"`
	NameValue    string      `json:"name_value"`
	NotBefore    string      `json:"not_before"`
	NotAfter     string      `json:"not_after"`
	SerialNumber string      `json:"serial_number"`
}

// convertCrtShResult converts crt.sh result to Certificate
func (c *CertIntel) convertCrtShResult(result crtShResult) Certificate {
	cert := Certificate{
		ID:           result.ID.String(),
		IssuerCAID:   result.IssuerCAID,
		IssuerName:   result.IssuerName,
		CommonName:   result.CommonName,
		NameValue:    result.NameValue,
		SerialNumber: result.SerialNumber,
	}

	// Parse timestamps
	if notBefore, err := time.Parse("2006-01-02T15:04:05", result.NotBefore); err == nil {
		cert.NotBefore = notBefore
	}
	if notAfter, err := time.Parse("2006-01-02T15:04:05", result.NotAfter); err == nil {
		cert.NotAfter = notAfter
	}

	// Extract SANs from name_value
	cert.SubjectAltNames = c.extractSANs(result.NameValue)

	return cert
}

// extractSANs extracts Subject Alternative Names from name_value field
func (c *CertIntel) extractSANs(nameValue string) []string {
	// Split by newline and clean up
	names := strings.Split(nameValue, "\n")
	uniqueNames := make(map[string]bool)

	for _, name := range names {
		name = strings.TrimSpace(name)
		name = strings.TrimPrefix(name, "*.")
		if name != "" && !strings.HasPrefix(name, "=") {
			uniqueNames[name] = true
		}
	}

	// Convert to slice
	result := make([]string, 0, len(uniqueNames))
	for name := range uniqueNames {
		result = append(result, name)
	}

	sort.Strings(result)
	return result
}

// extractAllDomains extracts all domain names from a certificate
func (c *CertIntel) extractAllDomains(cert Certificate) []string {
	domains := make(map[string]bool)

	// Add common name
	if cert.CommonName != "" {
		domains[cert.CommonName] = true
	}

	// Add all SANs
	for _, san := range cert.SubjectAltNames {
		domains[san] = true
	}

	// Convert to slice
	result := make([]string, 0, len(domains))
	for domain := range domains {
		result = append(result, domain)
	}

	return result
}

// findWildcardPatterns identifies wildcard certificate patterns
func (c *CertIntel) findWildcardPatterns(domains []string) []Pattern {
	patterns := []Pattern{}

	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			pattern := Pattern{
				Pattern:    domain,
				Examples:   []string{domain},
				Confidence: 0.9,
				Type:       "wildcard",
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

// identifyInternalDomains identifies potential internal domains
func (c *CertIntel) identifyInternalDomains(domains []string) []string {
	internal := []string{}

	internalKeywords := []string{
		"internal", "intranet", "corp", "private",
		"lan", "local", "dmz", "inside",
		"dev", "staging", "test", "qa",
		"uat", "preprod", "sandbox",
	}

	for _, domain := range domains {
		domainLower := strings.ToLower(domain)
		for _, keyword := range internalKeywords {
			if strings.Contains(domainLower, keyword) {
				internal = append(internal, domain)
				break
			}
		}
	}

	return internal
}

// analyzeSubdomainPatterns finds patterns in subdomain naming
func (c *CertIntel) analyzeSubdomainPatterns(domains map[string]int) []Pattern {
	patterns := []Pattern{}

	// Common subdomain prefixes
	prefixPatterns := map[string]string{
		`^api[0-9]*\.`:    "API versioning",
		`^[a-z]{2,3}-`:    "Geographic prefix",
		`^(dev|test|qa)-`: "Environment prefix",
		`^[0-9]{1,3}-`:    "Numeric prefix",
		`^(v|ver)[0-9]+`:  "Version prefix",
	}

	for pattern, description := range prefixPatterns {
		re := regexp.MustCompile(pattern)
		examples := []string{}

		for domain := range domains {
			if re.MatchString(domain) {
				examples = append(examples, domain)
				if len(examples) >= 5 {
					break
				}
			}
		}

		if len(examples) > 0 {
			patterns = append(patterns, Pattern{
				Pattern:    pattern,
				Examples:   examples,
				Confidence: float64(len(examples)) / 10.0,
				Type:       description,
			})
		}
	}

	return patterns
}

// analyzeServicePatterns identifies service naming patterns
func (c *CertIntel) analyzeServicePatterns(domains map[string]int) []Pattern {
	patterns := []Pattern{}

	serviceKeywords := []string{
		"api", "app", "admin", "portal", "dashboard",
		"mail", "smtp", "imap", "pop", "webmail",
		"ftp", "sftp", "ssh", "vpn", "remote",
		"db", "database", "mysql", "postgres", "mongo",
		"cache", "redis", "memcache", "elastic",
		"cdn", "static", "assets", "media", "img",
		"auth", "oauth", "sso", "login", "signin",
		"pay", "payment", "checkout", "billing",
		"search", "elasticsearch", "solr",
		"git", "gitlab", "github", "bitbucket",
		"jenkins", "ci", "cd", "build", "deploy",
		"monitor", "metrics", "grafana", "prometheus",
		"log", "logging", "logstash", "kibana",
	}

	serviceCount := make(map[string][]string)

	for domain := range domains {
		domainLower := strings.ToLower(domain)
		for _, service := range serviceKeywords {
			if strings.Contains(domainLower, service) {
				serviceCount[service] = append(serviceCount[service], domain)
			}
		}
	}

	// Create patterns for services with multiple instances
	for service, examples := range serviceCount {
		if len(examples) >= 2 {
			patterns = append(patterns, Pattern{
				Pattern:    service,
				Examples:   examples[:min(5, len(examples))],
				Confidence: float64(len(examples)) / 5.0,
				Type:       "service",
			})
		}
	}

	return patterns
}

// analyzeEnvironmentPatterns identifies environment naming patterns
func (c *CertIntel) analyzeEnvironmentPatterns(domains map[string]int) []Pattern {
	patterns := []Pattern{}

	envKeywords := map[string][]string{
		"development": {"dev", "develop", "development"},
		"testing":     {"test", "testing", "qa", "quality"},
		"staging":     {"stage", "staging", "preprod", "pre-prod"},
		"production":  {"prod", "production", "live"},
		"demo":        {"demo", "trial", "sandbox"},
		"backup":      {"backup", "bak", "dr", "failover"},
	}

	for envType, keywords := range envKeywords {
		examples := []string{}

		for domain := range domains {
			domainLower := strings.ToLower(domain)
			for _, keyword := range keywords {
				if strings.Contains(domainLower, keyword) {
					examples = append(examples, domain)
					break
				}
			}
			if len(examples) >= 5 {
				break
			}
		}

		if len(examples) > 0 {
			patterns = append(patterns, Pattern{
				Pattern:    envType,
				Examples:   examples,
				Confidence: float64(len(examples)) / 3.0,
				Type:       "environment",
			})
		}
	}

	return patterns
}

// analyzeGeographicPatterns identifies geographic naming patterns
func (c *CertIntel) analyzeGeographicPatterns(domains map[string]int) []Pattern {
	patterns := []Pattern{}

	// Common geographic identifiers
	geoPatterns := map[string]*regexp.Regexp{
		"us-region":    regexp.MustCompile(`(us-east|us-west|us-central|useast|uswest)`),
		"eu-region":    regexp.MustCompile(`(eu-west|eu-central|eu-north|euwest)`),
		"asia-region":  regexp.MustCompile(`(asia|apac|ap-southeast|ap-south)`),
		"country-code": regexp.MustCompile(`\b[a-z]{2}[0-9]?\.(.*\.)?[a-z]+$`),
		"city-name":    regexp.MustCompile(`(london|paris|tokyo|sydney|nyc|singapore)`),
	}

	for geoType, re := range geoPatterns {
		examples := []string{}

		for domain := range domains {
			if re.MatchString(strings.ToLower(domain)) {
				examples = append(examples, domain)
				if len(examples) >= 5 {
					break
				}
			}
		}

		if len(examples) > 0 {
			patterns = append(patterns, Pattern{
				Pattern:    geoType,
				Examples:   examples,
				Confidence: float64(len(examples)) / 3.0,
				Type:       "geographic",
			})
		}
	}

	return patterns
}

// analyzeIssuer analyzes certificate issuer information
func (c *CertIntel) analyzeIssuer(cert Certificate) IssuerInfo {
	info := IssuerInfo{
		Name: cert.IssuerName,
	}

	// Determine if it's a trusted public CA
	trustedCAs := []string{
		"Let's Encrypt", "DigiCert", "Sectigo", "GlobalSign",
		"GoDaddy", "Comodo", "Symantec", "Thawte", "GeoTrust",
		"RapidSSL", "Entrust", "Amazon", "Google Trust Services",
	}

	issuerLower := strings.ToLower(cert.IssuerName)
	for _, ca := range trustedCAs {
		if strings.Contains(issuerLower, strings.ToLower(ca)) {
			info.Trusted = true
			info.Type = "public"
			return info
		}
	}

	// Check for self-signed
	if cert.IssuerName == cert.CommonName {
		info.Type = "self-signed"
		info.Trusted = false
		return info
	}

	// Otherwise, it's likely a private CA
	info.Type = "private"
	info.Trusted = false

	return info
}

// detectCertificatePinning checks for certificate pinning indicators
func (c *CertIntel) detectCertificatePinning(cert Certificate) bool {
	// Look for indicators that suggest certificate pinning might be in use

	// 1. Short validity period (less than 90 days)
	validity := cert.NotAfter.Sub(cert.NotBefore)
	if validity < 90*24*time.Hour {
		return true
	}

	// 2. Private CA with specific patterns
	issuerInfo := c.analyzeIssuer(cert)
	if issuerInfo.Type == "private" {
		// Check for patterns suggesting pinning
		pinningKeywords := []string{"pin", "fixed", "static", "hardcoded"}
		issuerLower := strings.ToLower(cert.IssuerName)
		for _, keyword := range pinningKeywords {
			if strings.Contains(issuerLower, keyword) {
				return true
			}
		}
	}

	return false
}

// queryGoogleCT queries Google Certificate Transparency logs
func (c *CertIntel) queryGoogleCT(ctx context.Context, ctLog CTLogAPI, domain string, results chan<- Certificate) {
	// Google CT API implementation
	// This is a placeholder - in production, implement actual Google CT API queries
	c.logger.Debug("Google CT query not fully implemented", "domain", domain)
}

// Helper functions

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
