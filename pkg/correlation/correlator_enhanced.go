// pkg/correlation/correlator_enhanced.go
package correlation

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// EnhancedOrganizationCorrelator wraps the existing correlator with enhanced functionality
type EnhancedOrganizationCorrelator struct {
	*OrganizationCorrelator
	logger *logger.Logger
	cache  *EnhancedCache
}

// NewEnhancedOrganizationCorrelator creates a new enhanced correlator
func NewEnhancedOrganizationCorrelator(config CorrelatorConfig, logger *logger.Logger) *EnhancedOrganizationCorrelator {
	base := NewOrganizationCorrelator(config, logger)
	return &EnhancedOrganizationCorrelator{
		OrganizationCorrelator: base,
		logger:                 logger,
		cache:                  NewEnhancedCache(config.CacheTTL),
	}
}

// ResolveIdentifier resolves any identifier to an organization
func (ec *EnhancedOrganizationCorrelator) ResolveIdentifier(ctx context.Context, identifier string) (*Organization, error) {
	resolver := NewIdentifierResolver(ec.logger)
	info, err := resolver.ParseIdentifier(identifier)
	if err != nil {
		return nil, fmt.Errorf("failed to parse identifier: %w", err)
	}
	
	// Handle each type
	switch info.Type {
	case TypeEmail:
		return ec.DiscoverFromEmail(ctx, info.Value)
	case TypeDomain:
		return ec.DiscoverFromDomain(ctx, info.Domain)
	case TypeIP:
		return ec.DiscoverFromIP(ctx, info.Value)
	case TypeIPRange:
		return ec.DiscoverFromIPRange(ctx, info.Value)
	case "asn":
		return ec.DiscoverFromASN(ctx, info.Value)
	case TypeCompanyName:
		return ec.DiscoverFromCompanyName(ctx, info.Company)
	case "linkedin":
		return ec.DiscoverFromLinkedIn(ctx, info.Value)
	case "github":
		return ec.DiscoverFromGitHub(ctx, info.Value)
	default:
		return nil, fmt.Errorf("unsupported identifier type: %s", info.Type)
	}
}

// DiscoverFromEmail discovers organization from email with enhanced logic
func (ec *EnhancedOrganizationCorrelator) DiscoverFromEmail(ctx context.Context, email string) (*Organization, error) {
	// Check enhanced cache first
	if cached := ec.cache.GetByEmail(email); cached != nil {
		return cached, nil
	}
	
	// Extract domain
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid email format")
	}
	
	domain := parts[1]
	
	// Use domain discovery
	org, err := ec.DiscoverFromDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	
	// Add email pattern metadata
	if org.Metadata == nil {
		org.Metadata = make(map[string]interface{})
	}
	emailPatterns, _ := org.Metadata["email_patterns"].([]string)
	pattern := fmt.Sprintf("*@%s", domain)
	if !containsString(emailPatterns, pattern) {
		emailPatterns = append(emailPatterns, pattern)
		org.Metadata["email_patterns"] = emailPatterns
	}
	
	// Search for employees if LinkedIn is enabled
	if ec.config.EnableLinkedIn && ec.linkedinClient != nil {
		if employees, err := ec.linkedinClient.SearchEmployees(org.Name); err == nil {
			// Merge employees
			existingEmails := make(map[string]bool)
			for _, emp := range org.Employees {
				existingEmails[emp.Email] = true
			}
			
			for _, emp := range employees {
				if !existingEmails[emp.Email] {
					org.Employees = append(org.Employees, emp)
				}
			}
		}
	}
	
	// Cache and return
	ec.cache.Store(org)
	return org, nil
}

// DiscoverFromDomain discovers organization from domain
func (ec *EnhancedOrganizationCorrelator) DiscoverFromDomain(ctx context.Context, domain string) (*Organization, error) {
	// Use the base correlator's methods
	org := &Organization{
		Domains:      []string{domain},
		LastUpdated:  time.Now(),
		Metadata:     make(map[string]interface{}),
	}
	
	ec.correlateDomain(ctx, domain, org)
	ec.secondPassCorrelation(ctx, org)
	org.Confidence = ec.calculateConfidence(org)
	
	// Cache and return
	ec.cache.Store(org)
	return org, nil
}

// DiscoverFromIP discovers organization from IP
func (ec *EnhancedOrganizationCorrelator) DiscoverFromIP(ctx context.Context, ip string) (*Organization, error) {
	org := &Organization{
		LastUpdated: time.Now(),
		Metadata:    make(map[string]interface{}),
	}
	
	ec.correlateIP(ctx, ip, org)
	ec.secondPassCorrelation(ctx, org)
	org.Confidence = ec.calculateConfidence(org)
	
	// Cache and return
	ec.cache.Store(org)
	return org, nil
}

// DiscoverFromCompanyName discovers organization from company name
func (ec *EnhancedOrganizationCorrelator) DiscoverFromCompanyName(ctx context.Context, companyName string) (*Organization, error) {
	org := &Organization{
		Name:        companyName,
		LastUpdated: time.Now(),
		Metadata:    make(map[string]interface{}),
	}
	
	ec.correlateCompanyName(ctx, companyName, org)
	ec.secondPassCorrelation(ctx, org)
	org.Confidence = ec.calculateConfidence(org)
	
	// Cache and return
	ec.cache.Store(org)
	return org, nil
}

// DiscoverFromIPRange discovers organization from IP range
func (ec *EnhancedOrganizationCorrelator) DiscoverFromIPRange(ctx context.Context, ipRange string) (*Organization, error) {
	ec.logger.Infow("Discovering organization from IP range", "ip_range", ipRange)
	
	// Parse CIDR
	_, ipnet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return nil, fmt.Errorf("invalid IP range: %w", err)
	}
	
	org := &Organization{
		Name:        fmt.Sprintf("Organization for %s", ipRange),
		IPRanges:    []string{ipRange},
		LastUpdated: time.Now(),
		Metadata:    make(map[string]interface{}),
	}
	
	// Try to get ASN info for the range
	if ec.asnClient != nil && ec.config.EnableASN {
		// Get first IP in range
		firstIP := ipnet.IP.String()
		if whoisInfo, err := ec.whoisClient.LookupIP(firstIP); err == nil {
			if whoisInfo.Organization != "" {
				org.Name = whoisInfo.Organization
			}
		}
	}
	
	// Try reverse DNS for some IPs
	ips, _ := expandIPRange(ipRange)
	for i, ip := range ips {
		if i > 10 { // Limit to first 10 IPs
			break
		}
		if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
			for _, name := range names {
				name = strings.TrimSuffix(name, ".")
				if isDomainValid(name) && !containsString(org.Domains, name) {
					org.Domains = append(org.Domains, name)
				}
			}
		}
	}
	
	return org, nil
}

// DiscoverFromASN discovers organization from ASN
func (ec *EnhancedOrganizationCorrelator) DiscoverFromASN(ctx context.Context, asn string) (*Organization, error) {
	ec.logger.Infow("Discovering organization from ASN", "asn", asn)
	
	org := &Organization{
		Name:        fmt.Sprintf("Organization for %s", asn),
		ASNs:        []string{asn},
		LastUpdated: time.Now(),
		Metadata:    make(map[string]interface{}),
	}
	
	// Get ASN details
	if ec.asnClient != nil && ec.config.EnableASN {
		if asnInfo, err := ec.asnClient.LookupASN(asn); err == nil {
			if asnInfo.Organization != "" {
				org.Name = asnInfo.Organization
			}
			org.IPRanges = append(org.IPRanges, asnInfo.IPRanges...)
		}
	}
	
	return org, nil
}

// DiscoverFromLinkedIn discovers organization from LinkedIn URL
func (ec *EnhancedOrganizationCorrelator) DiscoverFromLinkedIn(ctx context.Context, linkedinURL string) (*Organization, error) {
	ec.logger.Infow("Discovering organization from LinkedIn", "url", linkedinURL)
	
	companyName := extractLinkedInCompany(linkedinURL)
	if companyName == "" {
		return nil, fmt.Errorf("could not extract company from LinkedIn URL")
	}
	
	// Use company name discovery
	return ec.DiscoverFromCompanyName(ctx, companyName)
}

// DiscoverFromGitHub discovers organization from GitHub URL
func (ec *EnhancedOrganizationCorrelator) DiscoverFromGitHub(ctx context.Context, githubURL string) (*Organization, error) {
	ec.logger.Infow("Discovering organization from GitHub", "url", githubURL)
	
	orgName := extractGitHubOrg(githubURL)
	if orgName == "" {
		return nil, fmt.Errorf("could not extract organization from GitHub URL")
	}
	
	org := &Organization{
		Name:        orgName,
		GitHubOrgs:  []string{orgName},
		LastUpdated: time.Now(),
		Metadata:    make(map[string]interface{}),
	}
	
	// Get GitHub organization details
	if ec.githubClient != nil && ec.config.EnableGitHub {
		if githubOrg, err := ec.githubClient.GetOrgDetails(orgName); err == nil {
			if githubOrg.Name != "" {
				org.Name = githubOrg.Name
			}
			
			// Add repositories as metadata
			org.Metadata["github_repos"] = githubOrg.Repositories
			if githubOrg.Location != "" {
				org.Metadata["github_location"] = githubOrg.Location
			}
		}
	}
	
	return org, nil
}

// EnhancedCache provides caching with multiple lookup methods
type EnhancedCache struct {
	cache    sync.Map
	domainIndex sync.Map
	emailIndex  sync.Map
	ipIndex     sync.Map
	ttl         time.Duration
}

// NewEnhancedCache creates a new enhanced cache
func NewEnhancedCache(ttl time.Duration) *EnhancedCache {
	cache := &EnhancedCache{
		ttl: ttl,
	}
	
	// Start cleanup routine
	go cache.cleanup()
	
	return cache
}

// Store stores an organization in the cache
func (c *EnhancedCache) Store(org *Organization) {
	key := generateOrgID(org.Name)
	
	// Store with timestamp
	c.cache.Store(key, &cacheEntry{
		org:       org,
		timestamp: time.Now(),
	})
	
	// Update indices
	for _, domain := range org.Domains {
		c.domainIndex.Store(domain, key)
	}
	
	// Store email patterns
	if patterns, ok := org.Metadata["email_patterns"].([]string); ok {
		for _, pattern := range patterns {
			if domain := extractDomainFromPattern(pattern); domain != "" {
				c.emailIndex.Store(domain, key)
			}
		}
	}
	
	// Store IP ranges
	for _, ipRange := range org.IPRanges {
		c.ipIndex.Store(ipRange, key)
	}
}

// GetByEmail retrieves an organization by email
func (c *EnhancedCache) GetByEmail(email string) *Organization {
	domain := extractDomainFromEmail(email)
	if domain == "" {
		return nil
	}
	
	if keyInterface, ok := c.emailIndex.Load(domain); ok {
		if key, ok := keyInterface.(string); ok {
			return c.getByKey(key)
		}
	}
	
	return nil
}

// getByKey retrieves an organization by its cache key
func (c *EnhancedCache) getByKey(key string) *Organization {
	if entryInterface, ok := c.cache.Load(key); ok {
		if entry, ok := entryInterface.(*cacheEntry); ok {
			if time.Since(entry.timestamp) < c.ttl {
				return entry.org
			}
		}
	}
	return nil
}

// cleanup removes expired entries
func (c *EnhancedCache) cleanup() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()
	
	for range ticker.C {
		var expiredKeys []string
		
		// Find expired entries
		c.cache.Range(func(key, value interface{}) bool {
			if entry, ok := value.(*cacheEntry); ok {
				if time.Since(entry.timestamp) > c.ttl {
					expiredKeys = append(expiredKeys, key.(string))
				}
			}
			return true
		})
		
		// Remove expired entries and their indices
		for _, key := range expiredKeys {
			if entryInterface, ok := c.cache.Load(key); ok {
				if entry, ok := entryInterface.(*cacheEntry); ok {
					// Clean indices
					for _, domain := range entry.org.Domains {
						c.domainIndex.Delete(domain)
					}
					if patterns, ok := entry.org.Metadata["email_patterns"].([]string); ok {
						for _, pattern := range patterns {
							if domain := extractDomainFromPattern(pattern); domain != "" {
								c.emailIndex.Delete(domain)
							}
						}
					}
					for _, ipRange := range entry.org.IPRanges {
						c.ipIndex.Delete(ipRange)
					}
				}
			}
			c.cache.Delete(key)
		}
	}
}

type cacheEntry struct {
	org       *Organization
	timestamp time.Time
}