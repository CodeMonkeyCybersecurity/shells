package dns

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

type DNSEnumerator struct {
	resolvers    []string
	wordlists    map[string][]string
	permutations bool
	timeout      time.Duration
	workers      int
}

type EnumerationConfig struct {
	Resolvers    []string
	Permutations bool
	Timeout      time.Duration
	Workers      int
	Wordlists    map[string][]string
}

func NewDNSEnumerator(config EnumerationConfig) *DNSEnumerator {
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	if config.Workers == 0 {
		config.Workers = 100
	}
	if config.Resolvers == nil {
		config.Resolvers = []string{"8.8.8.8", "1.1.1.1", "8.8.4.4", "1.0.0.1"}
	}
	if config.Wordlists == nil {
		config.Wordlists = getDefaultWordlists()
	}

	return &DNSEnumerator{
		resolvers:    config.Resolvers,
		wordlists:    config.Wordlists,
		permutations: config.Permutations,
		timeout:      config.Timeout,
		workers:      config.Workers,
	}
}

func (d *DNSEnumerator) DeepEnumeration(ctx context.Context, domain string) (*EnumerationResult, error) {
	result := &EnumerationResult{
		Subdomains: []Subdomain{},
		Patterns:   []Pattern{},
		Statistics: Statistics{
			Sources: make(map[string]int),
		},
	}

	// 1. Passive sources first
	passive, err := d.passiveEnumeration(ctx, domain)
	if err == nil {
		result.Subdomains = append(result.Subdomains, passive...)
		result.Statistics.Sources["passive"] = len(passive)
	}

	// 2. Certificate transparency
	ctSubs, err := d.certificateTransparency(ctx, domain)
	if err == nil {
		result.Subdomains = append(result.Subdomains, ctSubs...)
		result.Statistics.Sources["certificate_transparency"] = len(ctSubs)
	}

	// 3. DNS brute force with smart wordlists
	bruteforce, err := d.smartBruteforce(ctx, domain, result.Subdomains)
	if err == nil {
		result.Subdomains = append(result.Subdomains, bruteforce...)
		result.Statistics.Sources["bruteforce"] = len(bruteforce)
	}

	// 4. Permutation scanning
	if d.permutations {
		perms, err := d.generatePermutations(ctx, domain, result.Subdomains)
		if err == nil {
			result.Subdomains = append(result.Subdomains, perms...)
			result.Statistics.Sources["permutations"] = len(perms)
		}
	}

	// 5. Zone transfer attempts
	if zoneTransfer, err := d.attemptZoneTransfer(ctx, domain); err == nil && zoneTransfer != nil {
		result.Subdomains = append(result.Subdomains, zoneTransfer...)
		result.Statistics.Sources["zone_transfer"] = len(zoneTransfer)
	}

	// 6. Virtual host scanning on discovered IPs
	if vhosts, err := d.virtualHostScanning(ctx, result.Subdomains); err == nil {
		result.Subdomains = append(result.Subdomains, vhosts...)
		result.Statistics.Sources["virtual_hosts"] = len(vhosts)
	}

	// Deduplicate and analyze patterns
	result.Subdomains = d.deduplicateSubdomains(result.Subdomains)
	result.Patterns = d.analyzePatterns(result.Subdomains)
	result.Statistics.TotalSubdomains = len(result.Subdomains)
	result.Statistics.ActiveSubdomains = d.countActiveSubdomains(result.Subdomains)
	result.Statistics.UniqueIPs = d.countUniqueIPs(result.Subdomains)

	return result, nil
}

func (d *DNSEnumerator) passiveEnumeration(ctx context.Context, domain string) ([]Subdomain, error) {
	subdomains := []Subdomain{}

	// Sources for passive enumeration
	sources := map[string]func(context.Context, string) ([]Subdomain, error){
		"crt.sh":         d.queryRapidDNS,
		"threatminer":    d.queryThreatMiner,
		"virustotal":     d.queryVirusTotal,
		"securitytrails": d.querySecurityTrails,
		"shodan":         d.queryShoDan,
		"censys":         d.queryCensys,
		"dnsrepo":        d.queryDNSRepo,
		"hackertarget":   d.queryHackerTarget,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make(chan []Subdomain, len(sources))

	for source, queryFunc := range sources {
		wg.Add(1)
		go func(src string, fn func(context.Context, string) ([]Subdomain, error)) {
			defer wg.Done()
			if subs, err := fn(ctx, domain); err == nil {
				for i := range subs {
					subs[i].Source = src
				}
				results <- subs
			}
		}(source, queryFunc)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		mu.Lock()
		subdomains = append(subdomains, result...)
		mu.Unlock()
	}

	return subdomains, nil
}

func (d *DNSEnumerator) certificateTransparency(ctx context.Context, domain string) ([]Subdomain, error) {
	subdomains := []Subdomain{}

	// Query crt.sh
	if subs, err := d.queryCrtSh(ctx, domain); err == nil {
		subdomains = append(subdomains, subs...)
	}

	// Query Facebook CT
	if subs, err := d.queryFacebookCT(ctx, domain); err == nil {
		subdomains = append(subdomains, subs...)
	}

	// Query Google CT
	if subs, err := d.queryGoogleCT(ctx, domain); err == nil {
		subdomains = append(subdomains, subs...)
	}

	return subdomains, nil
}

func (d *DNSEnumerator) smartBruteforce(ctx context.Context, domain string, known []Subdomain) ([]Subdomain, error) {
	// Analyze patterns in known subdomains
	patterns := d.detectPatterns(known)

	// Select appropriate wordlists
	wordlists := []string{}

	if patterns.HasDevPattern {
		wordlists = append(wordlists, d.wordlists["development"]...)
	}
	if patterns.HasRegionalPattern {
		wordlists = append(wordlists, d.wordlists["regions"]...)
	}
	if patterns.HasAPIPattern {
		wordlists = append(wordlists, d.wordlists["api"]...)
	}
	if patterns.HasStagingPattern {
		wordlists = append(wordlists, d.wordlists["staging"]...)
	}

	// Add base wordlist
	wordlists = append(wordlists, d.wordlists["common"]...)

	// Add custom generated words based on patterns
	customWords := d.generateCustomWordlist(patterns)
	wordlists = append(wordlists, customWords...)

	return d.bruteforce(ctx, domain, wordlists)
}

func (d *DNSEnumerator) bruteforce(ctx context.Context, domain string, wordlist []string) ([]Subdomain, error) {
	subdomains := []Subdomain{}

	// Create worker pool
	work := make(chan string, len(wordlist))
	results := make(chan Subdomain, len(wordlist))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < d.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range work {
				subdomain := fmt.Sprintf("%s.%s", word, domain)
				if ips, err := d.resolve(ctx, subdomain); err == nil && len(ips) > 0 {
					results <- Subdomain{
						Name:      subdomain,
						IPs:       ips,
						Status:    "active",
						Source:    "bruteforce",
						FirstSeen: time.Now(),
					}
				}
			}
		}()
	}

	// Send work
	go func() {
		for _, word := range wordlist {
			select {
			case work <- word:
			case <-ctx.Done():
				break
			}
		}
		close(work)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		subdomains = append(subdomains, result)
	}

	return subdomains, nil
}

func (d *DNSEnumerator) generatePermutations(ctx context.Context, domain string, known []Subdomain) ([]Subdomain, error) {

	// Extract base words from known subdomains
	baseWords := []string{}
	for _, sub := range known {
		parts := strings.Split(sub.Name, ".")
		if len(parts) > 0 {
			baseWords = append(baseWords, parts[0])
		}
	}

	// Generate permutations
	permutations := []string{}

	// Common prefixes and suffixes
	prefixes := []string{"www", "mail", "ftp", "admin", "api", "dev", "test", "staging"}
	suffixes := []string{"01", "02", "03", "new", "old", "bak", "backup"}

	for _, base := range baseWords {
		// Add prefixes
		for _, prefix := range prefixes {
			permutations = append(permutations, prefix+"-"+base)
			permutations = append(permutations, prefix+base)
		}

		// Add suffixes
		for _, suffix := range suffixes {
			permutations = append(permutations, base+"-"+suffix)
			permutations = append(permutations, base+suffix)
		}
	}

	// Test permutations
	return d.bruteforce(ctx, domain, permutations)
}

func (d *DNSEnumerator) attemptZoneTransfer(ctx context.Context, domain string) ([]Subdomain, error) {
	subdomains := []Subdomain{}

	// Get nameservers
	nameservers, err := net.LookupNS(domain)
	if err != nil {
		return subdomains, err
	}

	// Try zone transfer on each nameserver
	for _, ns := range nameservers {
		if zoneData, err := d.tryZoneTransfer(ctx, domain, ns.Host); err == nil {
			subdomains = append(subdomains, zoneData...)
		}
	}

	return subdomains, nil
}

func (d *DNSEnumerator) tryZoneTransfer(ctx context.Context, domain, nameserver string) ([]Subdomain, error) {
	// Implementation would use DNS AXFR request
	// This is a placeholder
	return []Subdomain{}, nil
}

func (d *DNSEnumerator) virtualHostScanning(ctx context.Context, subdomains []Subdomain) ([]Subdomain, error) {
	vhosts := []Subdomain{}

	// Group subdomains by IP
	ipGroups := make(map[string][]Subdomain)
	for _, sub := range subdomains {
		for _, ip := range sub.IPs {
			ipGroups[ip] = append(ipGroups[ip], sub)
		}
	}

	// For each IP with multiple subdomains, scan for virtual hosts
	for ip, subs := range ipGroups {
		if len(subs) > 1 {
			// Try common virtual host patterns
			patterns := d.generateVHostPatterns(subs)
			for _, pattern := range patterns {
				if d.testVirtualHost(ctx, ip, pattern) {
					vhosts = append(vhosts, Subdomain{
						Name:      pattern,
						IPs:       []string{ip},
						Status:    "active",
						Source:    "virtual_host",
						FirstSeen: time.Now(),
					})
				}
			}
		}
	}

	return vhosts, nil
}

func (d *DNSEnumerator) generateVHostPatterns(subdomains []Subdomain) []string {
	patterns := []string{}

	// Extract base domain
	if len(subdomains) == 0 {
		return patterns
	}

	baseDomain := d.extractBaseDomain(subdomains[0].Name)

	// Generate patterns based on existing subdomains
	for _, sub := range subdomains {
		parts := strings.Split(sub.Name, ".")
		if len(parts) > 0 {
			base := parts[0]

			// Generate variations
			variations := []string{
				base + "-backup",
				base + "-old",
				base + "-new",
				base + "-test",
				base + "-dev",
				base + "2",
				base + "01",
				"old-" + base,
				"new-" + base,
				"backup-" + base,
			}

			for _, variation := range variations {
				patterns = append(patterns, variation+"."+baseDomain)
			}
		}
	}

	return patterns
}

func (d *DNSEnumerator) testVirtualHost(ctx context.Context, ip, hostname string) bool {
	// Implementation would test HTTP virtual hosting
	// This is a placeholder
	return false
}

func (d *DNSEnumerator) resolve(ctx context.Context, domain string) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Use custom resolver if configured
			if len(d.resolvers) > 0 {
				resolver := d.resolvers[0] // Simple round-robin could be improved
				return net.Dial(network, resolver+":53")
			}
			return net.Dial(network, address)
		},
	}

	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}

	return ips, nil
}

func (d *DNSEnumerator) detectPatterns(subdomains []Subdomain) *PatternAnalysis {
	analysis := &PatternAnalysis{
		CustomPatterns: []string{},
	}

	devPattern := regexp.MustCompile(`(?i)(dev|develop|development)`)
	regionalPattern := regexp.MustCompile(`(?i)(us|eu|asia|west|east|north|south|\d{2})`)
	apiPattern := regexp.MustCompile(`(?i)(api|rest|graphql|v\d+)`)
	stagingPattern := regexp.MustCompile(`(?i)(staging|stage|test|qa|uat|beta)`)

	for _, subdomain := range subdomains {
		if devPattern.MatchString(subdomain.Name) {
			analysis.HasDevPattern = true
		}
		if regionalPattern.MatchString(subdomain.Name) {
			analysis.HasRegionalPattern = true
		}
		if apiPattern.MatchString(subdomain.Name) {
			analysis.HasAPIPattern = true
		}
		if stagingPattern.MatchString(subdomain.Name) {
			analysis.HasStagingPattern = true
		}
	}

	return analysis
}

func (d *DNSEnumerator) generateCustomWordlist(patterns *PatternAnalysis) []string {
	custom := []string{}

	if patterns.HasDevPattern {
		custom = append(custom, "dev01", "dev02", "dev03", "developer", "development")
	}
	if patterns.HasRegionalPattern {
		custom = append(custom, "us-east", "us-west", "eu-central", "asia-pacific")
	}
	if patterns.HasAPIPattern {
		custom = append(custom, "api-v1", "api-v2", "api-v3", "rest-api", "graphql")
	}
	if patterns.HasStagingPattern {
		custom = append(custom, "staging01", "staging02", "pre-prod", "uat")
	}

	return custom
}

func (d *DNSEnumerator) analyzePatterns(subdomains []Subdomain) []Pattern {
	patterns := []Pattern{}

	// Group by pattern
	patternGroups := make(map[string][]string)

	for _, sub := range subdomains {
		parts := strings.Split(sub.Name, ".")
		if len(parts) > 0 {
			// Extract pattern from subdomain
			pattern := d.extractPattern(parts[0])
			patternGroups[pattern] = append(patternGroups[pattern], sub.Name)
		}
	}

	// Convert to Pattern objects
	for pattern, examples := range patternGroups {
		if len(examples) > 1 { // Only include patterns with multiple examples
			patterns = append(patterns, Pattern{
				Type:       "subdomain",
				Pattern:    pattern,
				Examples:   examples,
				Confidence: float64(len(examples)) / float64(len(subdomains)),
			})
		}
	}

	return patterns
}

func (d *DNSEnumerator) extractPattern(subdomain string) string {
	// Simple pattern extraction - could be more sophisticated
	numberPattern := regexp.MustCompile(`\d+`)
	return numberPattern.ReplaceAllString(subdomain, "N")
}

func (d *DNSEnumerator) extractBaseDomain(fullDomain string) string {
	parts := strings.Split(fullDomain, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return fullDomain
}

func (d *DNSEnumerator) deduplicateSubdomains(subdomains []Subdomain) []Subdomain {
	seen := make(map[string]bool)
	result := []Subdomain{}

	for _, sub := range subdomains {
		if !seen[sub.Name] {
			seen[sub.Name] = true
			result = append(result, sub)
		}
	}

	return result
}

func (d *DNSEnumerator) countActiveSubdomains(subdomains []Subdomain) int {
	count := 0
	for _, sub := range subdomains {
		if sub.Status == "active" {
			count++
		}
	}
	return count
}

func (d *DNSEnumerator) countUniqueIPs(subdomains []Subdomain) int {
	ips := make(map[string]bool)
	for _, sub := range subdomains {
		for _, ip := range sub.IPs {
			ips[ip] = true
		}
	}
	return len(ips)
}

// Placeholder implementations for passive enumeration sources
func (d *DNSEnumerator) queryRapidDNS(ctx context.Context, domain string) ([]Subdomain, error) {
	return []Subdomain{}, nil
}

func (d *DNSEnumerator) queryThreatMiner(ctx context.Context, domain string) ([]Subdomain, error) {
	return []Subdomain{}, nil
}

func (d *DNSEnumerator) queryVirusTotal(ctx context.Context, domain string) ([]Subdomain, error) {
	return []Subdomain{}, nil
}

func (d *DNSEnumerator) querySecurityTrails(ctx context.Context, domain string) ([]Subdomain, error) {
	return []Subdomain{}, nil
}

func (d *DNSEnumerator) queryShoDan(ctx context.Context, domain string) ([]Subdomain, error) {
	return []Subdomain{}, nil
}

func (d *DNSEnumerator) queryCensys(ctx context.Context, domain string) ([]Subdomain, error) {
	return []Subdomain{}, nil
}

func (d *DNSEnumerator) queryDNSRepo(ctx context.Context, domain string) ([]Subdomain, error) {
	return []Subdomain{}, nil
}

func (d *DNSEnumerator) queryHackerTarget(ctx context.Context, domain string) ([]Subdomain, error) {
	return []Subdomain{}, nil
}

func (d *DNSEnumerator) queryCrtSh(ctx context.Context, domain string) ([]Subdomain, error) {
	return []Subdomain{}, nil
}

func (d *DNSEnumerator) queryFacebookCT(ctx context.Context, domain string) ([]Subdomain, error) {
	return []Subdomain{}, nil
}

func (d *DNSEnumerator) queryGoogleCT(ctx context.Context, domain string) ([]Subdomain, error) {
	return []Subdomain{}, nil
}

func getDefaultWordlists() map[string][]string {
	return map[string][]string{
		"common": {
			"www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
			"blog", "shop", "store", "portal", "client", "customer", "support",
			"help", "docs", "documentation", "wiki", "forum", "community",
			"news", "media", "images", "static", "assets", "cdn", "cache",
			"secure", "ssl", "vpn", "remote", "access", "login", "auth",
			"dashboard", "panel", "control", "manage", "manager", "console",
		},
		"development": {
			"dev", "develop", "development", "dev01", "dev02", "dev03",
			"developer", "devops", "build", "ci", "cd", "jenkins", "gitlab",
			"github", "git", "svn", "repo", "repository", "code", "source",
		},
		"regions": {
			"us", "eu", "asia", "west", "east", "north", "south", "central",
			"us-east", "us-west", "eu-central", "asia-pacific", "ap",
			"na", "sa", "af", "oc", "an", "global", "worldwide", "international",
		},
		"api": {
			"api", "rest", "graphql", "v1", "v2", "v3", "v4", "v5",
			"api-v1", "api-v2", "rest-api", "api-gateway", "gateway",
			"service", "microservice", "webhook", "callback", "endpoint",
		},
		"staging": {
			"staging", "stage", "test", "testing", "qa", "uat", "beta",
			"pre-prod", "preprod", "preview", "demo", "sandbox", "experimental",
		},
	}
}
