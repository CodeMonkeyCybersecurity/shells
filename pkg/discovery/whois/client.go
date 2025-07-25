package whois

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

// WhoisClient performs WHOIS lookups
type WhoisClient struct {
	logger  *logger.Logger
	timeout time.Duration
	cache   map[string]*WhoisResult
}

// NewWhoisClient creates a new WHOIS client
func NewWhoisClient(logger *logger.Logger) *WhoisClient {
	return &WhoisClient{
		logger:  logger,
		timeout: 30 * time.Second,
		cache:   make(map[string]*WhoisResult),
	}
}

// WhoisResult contains parsed WHOIS data
type WhoisResult struct {
	Domain           string
	Registrar        string
	RegistrantOrg    string
	RegistrantEmail  string
	AdminEmail       string
	TechEmail        string
	NameServers      []string
	CreatedDate      string
	ExpiresDate      string
	UpdatedDate      string
	Status           []string
	RelatedDomains   []string
	RelatedEmails    []string
	RegistrantASN    string
	RegistrantCountry string
}

// LookupDomain performs WHOIS lookup for a domain
func (w *WhoisClient) LookupDomain(ctx context.Context, domain string) (*WhoisResult, error) {
	// Check cache
	if cached, exists := w.cache[domain]; exists {
		return cached, nil
	}

	// Perform WHOIS query
	rawWhois, err := whois.Whois(domain)
	if err != nil {
		return nil, fmt.Errorf("whois lookup failed: %w", err)
	}

	// Parse WHOIS data
	result, err := w.parseWhois(domain, rawWhois)
	if err != nil {
		// If parsing fails, try to extract basic info manually
		result = w.parseWhoisManual(domain, rawWhois)
	}

	// Find related domains
	result.RelatedDomains = w.findRelatedDomains(result, rawWhois)

	// Cache result
	w.cache[domain] = result

	w.logger.Info("WHOIS lookup completed", 
		"domain", domain,
		"registrar", result.Registrar,
		"org", result.RegistrantOrg,
		"related_domains", len(result.RelatedDomains))

	return result, nil
}

// LookupIP performs WHOIS lookup for an IP
func (w *WhoisClient) LookupIP(ctx context.Context, ip string) (*IPWhoisResult, error) {
	rawWhois, err := whois.Whois(ip)
	if err != nil {
		return nil, fmt.Errorf("whois lookup failed: %w", err)
	}

	result := w.parseIPWhois(ip, rawWhois)
	
	w.logger.Info("IP WHOIS lookup completed",
		"ip", ip,
		"org", result.Organization,
		"asn", result.ASN,
		"netblock", result.NetBlock)

	return result, nil
}

// IPWhoisResult contains IP WHOIS data
type IPWhoisResult struct {
	IP           string
	Organization string
	ASN          string
	NetBlock     string
	NetName      string
	Country      string
	AdminEmail   string
	TechEmail    string
	AbuseEmail   string
}

// parseWhois parses WHOIS data using whois-parser
func (w *WhoisClient) parseWhois(domain, raw string) (*WhoisResult, error) {
	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		return nil, err
	}

	result := &WhoisResult{
		Domain:          domain,
		Registrar:       parsed.Registrar.Name,
		RegistrantOrg:   parsed.Registrant.Organization,
		RegistrantEmail: parsed.Registrant.Email,
		AdminEmail:      parsed.Administrative.Email,
		TechEmail:       parsed.Technical.Email,
		CreatedDate:     parsed.Domain.CreatedDate,
		ExpiresDate:     parsed.Domain.ExpirationDate,
		UpdatedDate:     parsed.Domain.UpdatedDate,
		Status:          parsed.Domain.Status,
		NameServers:     parsed.Domain.NameServers,
		RelatedEmails:   []string{},
	}

	// Collect all emails
	emails := make(map[string]bool)
	if result.RegistrantEmail != "" {
		emails[result.RegistrantEmail] = true
	}
	if result.AdminEmail != "" {
		emails[result.AdminEmail] = true
	}
	if result.TechEmail != "" {
		emails[result.TechEmail] = true
	}

	for email := range emails {
		result.RelatedEmails = append(result.RelatedEmails, email)
	}

	return result, nil
}

// parseWhoisManual manually extracts info from raw WHOIS
func (w *WhoisClient) parseWhoisManual(domain, raw string) *WhoisResult {
	result := &WhoisResult{
		Domain:        domain,
		RelatedEmails: []string{},
		NameServers:   []string{},
		Status:        []string{},
	}

	lines := strings.Split(raw, "\n")
	emailMap := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		// Extract registrar
		if strings.Contains(lower, "registrar:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.Registrar = strings.TrimSpace(parts[1])
			}
		}

		// Extract organization
		if strings.Contains(lower, "organization:") || strings.Contains(lower, "org:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.RegistrantOrg = strings.TrimSpace(parts[1])
			}
		}

		// Extract emails
		emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
		emails := emailPattern.FindAllString(line, -1)
		for _, email := range emails {
			emailMap[strings.ToLower(email)] = true
		}

		// Extract name servers
		if strings.Contains(lower, "name server:") || strings.Contains(lower, "nserver:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ns := strings.TrimSpace(parts[1])
				if ns != "" {
					result.NameServers = append(result.NameServers, ns)
				}
			}
		}

		// Extract dates
		if strings.Contains(lower, "creation date:") || strings.Contains(lower, "created:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.CreatedDate = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(lower, "expir") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.ExpiresDate = strings.TrimSpace(parts[1])
			}
		}

		// Extract status
		if strings.Contains(lower, "status:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				status := strings.TrimSpace(parts[1])
				if status != "" {
					result.Status = append(result.Status, status)
				}
			}
		}
	}

	// Convert email map to slice
	for email := range emailMap {
		result.RelatedEmails = append(result.RelatedEmails, email)
	}

	return result
}

// findRelatedDomains finds domains related through WHOIS data
func (w *WhoisClient) findRelatedDomains(result *WhoisResult, rawWhois string) []string {
	relatedMap := make(map[string]bool)

	// Search by registrant email
	if result.RegistrantEmail != "" {
		domains := w.searchDomainsByEmail(result.RegistrantEmail)
		for _, d := range domains {
			if d != result.Domain {
				relatedMap[d] = true
			}
		}
	}

	// Search by organization
	if result.RegistrantOrg != "" {
		domains := w.searchDomainsByOrg(result.RegistrantOrg)
		for _, d := range domains {
			if d != result.Domain {
				relatedMap[d] = true
			}
		}
	}

	// Extract domains from raw WHOIS
	domainPattern := regexp.MustCompile(`\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
	matches := domainPattern.FindAllString(rawWhois, -1)
	
	for _, match := range matches {
		// Filter out common non-domain matches
		if !strings.Contains(match, "whois.") && 
		   !strings.Contains(match, "nic.") &&
		   !strings.Contains(match, "registry.") &&
		   !strings.HasSuffix(match, ".arpa") &&
		   match != result.Domain {
			relatedMap[match] = true
		}
	}

	// Convert to slice
	var related []string
	for domain := range relatedMap {
		related = append(related, domain)
	}

	return related
}

// searchDomainsByEmail searches for domains by email using ViewDNS.info
func (w *WhoisClient) searchDomainsByEmail(email string) []string {
	// ViewDNS.info provides free reverse WHOIS lookups
	// Note: This has rate limits - consider caching results
	url := fmt.Sprintf("https://viewdns.info/reversewhois/?q=%s", strings.ReplaceAll(email, "@", "%40"))
	
	resp, err := http.Get(url)
	if err != nil {
		w.logger.Debug("Reverse WHOIS by email failed", "email", email, "error", err)
		return []string{}
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	domains := w.extractDomainsFromHTML(string(body))
	
	w.logger.Debug("Reverse WHOIS by email completed", "email", email, "found", len(domains))
	return domains
}

// searchDomainsByOrg searches for domains by organization
func (w *WhoisClient) searchDomainsByOrg(org string) []string {
	// For organization search, we'll use a combination of techniques
	var domains []string
	
	// Try ViewDNS reverse WHOIS
	url := fmt.Sprintf("https://viewdns.info/reversewhois/?q=%s", url.QueryEscape(org))
	
	resp, err := http.Get(url)
	if err != nil {
		w.logger.Debug("Reverse WHOIS by org failed", "org", org, "error", err)
		return domains
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	domains = w.extractDomainsFromHTML(string(body))
	
	w.logger.Debug("Reverse WHOIS by org completed", "org", org, "found", len(domains))
	return domains
}

// extractDomainsFromHTML extracts domains from ViewDNS HTML response
func (w *WhoisClient) extractDomainsFromHTML(html string) []string {
	var domains []string
	seen := make(map[string]bool)
	
	// Look for domain patterns in the HTML
	// ViewDNS returns results in a table format
	domainPattern := regexp.MustCompile(`<td>([a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.[a-zA-Z]{2,})</td>`)
	matches := domainPattern.FindAllStringSubmatch(html, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			domain := strings.ToLower(match[1])
			if !seen[domain] && w.isValidDomain(domain) {
				seen[domain] = true
				domains = append(domains, domain)
			}
		}
	}
	
	return domains
}

// isValidDomain checks if a string is a valid domain
func (w *WhoisClient) isValidDomain(domain string) bool {
	// Basic validation
	if len(domain) < 4 || len(domain) > 253 {
		return false
	}
	
	// Must have at least one dot
	if !strings.Contains(domain, ".") {
		return false
	}
	
	// Check TLD is reasonable length
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	
	tld := parts[len(parts)-1]
	if len(tld) < 2 || len(tld) > 63 {
		return false
	}
	
	return true
}

// parseIPWhois parses IP WHOIS data
func (w *WhoisClient) parseIPWhois(ip, raw string) *IPWhoisResult {
	result := &IPWhoisResult{
		IP: ip,
	}

	lines := strings.Split(raw, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		// Extract organization
		if strings.Contains(lower, "organization:") || strings.Contains(lower, "orgname:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.Organization = strings.TrimSpace(parts[1])
			}
		}

		// Extract ASN
		if strings.Contains(lower, "originas:") || strings.Contains(lower, "origin as:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				asn := strings.TrimSpace(parts[1])
				if strings.HasPrefix(asn, "AS") {
					result.ASN = asn
				} else {
					result.ASN = "AS" + asn
				}
			}
		}

		// Extract netblock/CIDR
		if strings.Contains(lower, "cidr:") || strings.Contains(lower, "netrange:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.NetBlock = strings.TrimSpace(parts[1])
			}
		}

		// Extract netname
		if strings.Contains(lower, "netname:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.NetName = strings.TrimSpace(parts[1])
			}
		}

		// Extract country
		if strings.Contains(lower, "country:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.Country = strings.TrimSpace(parts[1])
			}
		}

		// Extract emails
		if strings.Contains(lower, "abuse") && strings.Contains(line, "@") {
			emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
			emails := emailPattern.FindAllString(line, -1)
			if len(emails) > 0 {
				result.AbuseEmail = emails[0]
			}
		}

		if strings.Contains(lower, "admin") && strings.Contains(line, "@") {
			emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
			emails := emailPattern.FindAllString(line, -1)
			if len(emails) > 0 {
				result.AdminEmail = emails[0]
			}
		}

		if strings.Contains(lower, "tech") && strings.Contains(line, "@") {
			emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
			emails := emailPattern.FindAllString(line, -1)
			if len(emails) > 0 {
				result.TechEmail = emails[0]
			}
		}
	}

	// Try to extract CIDR from IP range if not found
	if result.NetBlock == "" {
		result.NetBlock = w.extractCIDRFromRange(raw)
	}

	return result
}

// extractCIDRFromRange extracts CIDR from IP range in WHOIS
func (w *WhoisClient) extractCIDRFromRange(raw string) string {
	// Look for patterns like "192.168.0.0 - 192.168.255.255"
	rangePattern := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*-\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	matches := rangePattern.FindStringSubmatch(raw)
	
	if len(matches) == 3 {
		startIP := net.ParseIP(matches[1])
		endIP := net.ParseIP(matches[2])
		
		if startIP != nil && endIP != nil {
			// Calculate CIDR (simplified - assumes contiguous block)
			return w.calculateCIDR(startIP, endIP)
		}
	}

	return ""
}

// calculateCIDR calculates CIDR from IP range
func (w *WhoisClient) calculateCIDR(start, end net.IP) string {
	// This is a simplified implementation
	// In production, use a proper IP range to CIDR converter
	
	// For now, just return the start IP with /24
	if start.To4() != nil {
		return start.String() + "/24"
	}
	
	return ""
}

// GetRegistrantInfo gets detailed registrant information
func (w *WhoisClient) GetRegistrantInfo(domain string) (*RegistrantInfo, error) {
	result, err := w.LookupDomain(context.Background(), domain)
	if err != nil {
		return nil, err
	}

	return &RegistrantInfo{
		Organization: result.RegistrantOrg,
		Email:        result.RegistrantEmail,
		Domains:      result.RelatedDomains,
	}, nil
}

// RegistrantInfo contains registrant details
type RegistrantInfo struct {
	Organization string
	Email        string
	Domains      []string
}

// FindExpiredDomains finds recently expired domains from an organization
func (w *WhoisClient) FindExpiredDomains(org string) []string {
	// Check ExpiredDomains.net for domains matching the organization
	// Note: This is a simplified implementation
	var domains []string
	
	// Search for the organization name in expired domains
	searchURL := fmt.Sprintf("https://www.expireddomains.net/domain-name-search/?q=%s", url.QueryEscape(org))
	
	resp, err := http.Get(searchURL)
	if err != nil {
		w.logger.Debug("Expired domains search failed", "org", org, "error", err)
		return domains
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	
	// Extract domain names from the response
	domainPattern := regexp.MustCompile(`<td class="field_domain">.*?<a[^>]+>([^<]+)</a>`)
	matches := domainPattern.FindAllStringSubmatch(string(body), -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			domain := strings.TrimSpace(match[1])
			if w.isValidDomain(domain) {
				domains = append(domains, domain)
			}
		}
	}
	
	w.logger.Debug("Expired domains search completed", "org", org, "found", len(domains))
	return domains
}

// GetHistoricalWhois gets historical WHOIS records from DomainTools-style services
func (w *WhoisClient) GetHistoricalWhois(domain string) ([]WhoisResult, error) {
	// Note: Most historical WHOIS services require paid access
	// This is a simplified implementation that shows the concept
	
	// For now, just return current WHOIS as a single-item history
	current, err := w.LookupDomain(context.Background(), domain)
	if err != nil {
		return nil, err
	}
	
	return []WhoisResult{*current}, nil
}

// BulkWhoisLookup performs WHOIS lookups for multiple domains
func (w *WhoisClient) BulkWhoisLookup(ctx context.Context, domains []string) map[string]*WhoisResult {
	results := make(map[string]*WhoisResult)
	
	// Rate limit to avoid being blocked
	for _, domain := range domains {
		select {
		case <-ctx.Done():
			return results
		default:
			if result, err := w.LookupDomain(ctx, domain); err == nil {
				results[domain] = result
			}
			// Rate limit
			time.Sleep(2 * time.Second)
		}
	}
	
	return results
}