// correlation/cache.go
package correlation

import (
	"sync"
	"time"
	
	pkgcorrelation "github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
)

// OrganizationCache caches organization profiles
type OrganizationCache struct {
	mu            sync.RWMutex
	profiles      map[string]*pkgcorrelation.OrganizationProfile
	domainIndex   map[string]string // domain -> profile ID
	ipIndex       map[string]string // IP -> profile ID
	emailIndex    map[string]string // email domain -> profile ID
	nameIndex     map[string]string // company name -> profile ID
	ttl           time.Duration
}

// NewOrganizationCache creates a new cache
func NewOrganizationCache(ttl time.Duration) *OrganizationCache {
	cache := &OrganizationCache{
		profiles:    make(map[string]*pkgcorrelation.OrganizationProfile),
		domainIndex: make(map[string]string),
		ipIndex:     make(map[string]string),
		emailIndex:  make(map[string]string),
		nameIndex:   make(map[string]string),
		ttl:         ttl,
	}
	
	// Start cleanup goroutine
	go cache.cleanup()
	
	return cache
}

// Store stores an organization profile in cache
func (oc *OrganizationCache) Store(profile *pkgcorrelation.OrganizationProfile) {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	
	// Store profile
	oc.profiles[profile.ID] = profile
	
	// Update indices
	for _, domain := range profile.Domains {
		oc.domainIndex[domain] = profile.ID
	}
	
	for _, ipRange := range profile.IPRanges {
		// For simplicity, just store the range as-is
		// In production, you might want to parse and store individual IPs
		oc.ipIndex[ipRange] = profile.ID
	}
	
	for _, pattern := range profile.EmailPatterns {
		// Extract domain from pattern
		if domain := extractDomainFromPattern(pattern); domain != "" {
			oc.emailIndex[domain] = profile.ID
		}
	}
	
	if profile.Name != "" {
		oc.nameIndex[normalizeCompanyName(profile.Name)] = profile.ID
	}
}

// GetByDomain retrieves profile by domain
func (oc *OrganizationCache) GetByDomain(domain string) *pkgcorrelation.OrganizationProfile {
	oc.mu.RLock()
	defer oc.mu.RUnlock()
	
	if profileID, exists := oc.domainIndex[domain]; exists {
		if profile, exists := oc.profiles[profileID]; exists {
			if time.Since(profile.LastUpdated) < oc.ttl {
				return profile
			}
		}
	}
	return nil
}

// GetByIP retrieves profile by IP
func (oc *OrganizationCache) GetByIP(ip string) *pkgcorrelation.OrganizationProfile {
	oc.mu.RLock()
	defer oc.mu.RUnlock()
	
	// First check exact match
	if profileID, exists := oc.ipIndex[ip]; exists {
		if profile, exists := oc.profiles[profileID]; exists {
			if time.Since(profile.LastUpdated) < oc.ttl {
				return profile
			}
		}
	}
	
	// Then check if IP is in any range
	for ipRange, profileID := range oc.ipIndex {
		if ipInRange(ip, ipRange) {
			if profile, exists := oc.profiles[profileID]; exists {
				if time.Since(profile.LastUpdated) < oc.ttl {
					return profile
				}
			}
		}
	}
	
	return nil
}

// GetByEmail retrieves profile by email
func (oc *OrganizationCache) GetByEmail(email string) *pkgcorrelation.OrganizationProfile {
	oc.mu.RLock()
	defer oc.mu.RUnlock()
	
	domain := extractDomainFromEmail(email)
	if domain == "" {
		return nil
	}
	
	if profileID, exists := oc.emailIndex[domain]; exists {
		if profile, exists := oc.profiles[profileID]; exists {
			if time.Since(profile.LastUpdated) < oc.ttl {
				return profile
			}
		}
	}
	return nil
}

// GetByName retrieves profile by company name
func (oc *OrganizationCache) GetByName(name string) *pkgcorrelation.OrganizationProfile {
	oc.mu.RLock()
	defer oc.mu.RUnlock()
	
	normalized := normalizeCompanyName(name)
	if profileID, exists := oc.nameIndex[normalized]; exists {
		if profile, exists := oc.profiles[profileID]; exists {
			if time.Since(profile.LastUpdated) < oc.ttl {
				return profile
			}
		}
	}
	return nil
}

// cleanup removes expired entries
func (oc *OrganizationCache) cleanup() {
	ticker := time.NewTicker(oc.ttl / 2)
	defer ticker.Stop()
	
	for range ticker.C {
		oc.mu.Lock()
		
		// Find expired profiles
		expired := []string{}
		for id, profile := range oc.profiles {
			if time.Since(profile.LastUpdated) > oc.ttl {
				expired = append(expired, id)
			}
		}
		
		// Remove expired profiles and their indices
		for _, id := range expired {
			profile := oc.profiles[id]
			delete(oc.profiles, id)
			
			// Clean up indices
			for _, domain := range profile.Domains {
				delete(oc.domainIndex, domain)
			}
			for _, ipRange := range profile.IPRanges {
				delete(oc.ipIndex, ipRange)
			}
			for _, pattern := range profile.EmailPatterns {
				if domain := extractDomainFromPattern(pattern); domain != "" {
					delete(oc.emailIndex, domain)
				}
			}
			if profile.Name != "" {
				delete(oc.nameIndex, normalizeCompanyName(profile.Name))
			}
		}
		
		oc.mu.Unlock()
	}
}