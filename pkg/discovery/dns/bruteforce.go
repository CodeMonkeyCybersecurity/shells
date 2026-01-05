package dns

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/miekg/dns"
)

// DNSBruteforcer performs DNS subdomain brute-forcing
type DNSBruteforcer struct {
	resolvers   []string
	wordlist    []string
	concurrency int
	timeout     time.Duration
	logger      *logger.Logger
	client      *dns.Client
}

// NewDNSBruteforcer creates a new DNS brute-forcer
func NewDNSBruteforcer(logger *logger.Logger) *DNSBruteforcer {
	return &DNSBruteforcer{
		resolvers: []string{
			"8.8.8.8:53",
			"8.8.4.4:53",
			"1.1.1.1:53",
			"1.0.0.1:53",
			"9.9.9.9:53",
			"149.112.112.112:53",
			"208.67.222.222:53",
			"208.67.220.220:53",
		},
		concurrency: 50,
		timeout:     2 * time.Second,
		logger:      logger,
		client: &dns.Client{
			Timeout: 2 * time.Second,
		},
		wordlist: getDefaultWordlist(),
	}
}

// BruteforceResult represents a discovered subdomain
type BruteforceResult struct {
	Subdomain string
	IPs       []string
	CNAME     string
	Wildcard  bool
}

// Bruteforce performs subdomain brute-forcing
func (b *DNSBruteforcer) Bruteforce(ctx context.Context, domain string) ([]BruteforceResult, error) {
	// First check for wildcards
	wildcardIPs := b.checkWildcard(domain)
	hasWildcard := len(wildcardIPs) > 0

	if hasWildcard {
		b.logger.Infow("Wildcard DNS detected", "domain", domain, "ips", wildcardIPs)
	}

	results := make([]BruteforceResult, 0)
	resultsChan := make(chan BruteforceResult, 100)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, b.concurrency)

	// Worker function
	worker := func(subdomain string) {
		defer wg.Done()
		defer func() { <-semaphore }()

		select {
		case <-ctx.Done():
			return
		default:
		}

		fullDomain := subdomain + "." + domain
		ips, cname := b.resolve(fullDomain)

		if len(ips) > 0 {
			// Check if it's a wildcard response
			isWildcard := false
			if hasWildcard && b.isWildcardResponse(ips, wildcardIPs) {
				isWildcard = true
			}

			result := BruteforceResult{
				Subdomain: fullDomain,
				IPs:       ips,
				CNAME:     cname,
				Wildcard:  isWildcard,
			}

			select {
			case resultsChan <- result:
			case <-ctx.Done():
				return
			}
		}
	}

	// Start workers
	for _, word := range b.wordlist {
		wg.Add(1)
		semaphore <- struct{}{}
		go worker(word)
	}

	// Also try permutations
	permutations := b.generatePermutations(domain)
	for _, perm := range permutations {
		wg.Add(1)
		semaphore <- struct{}{}
		go worker(perm)
	}

	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		if !result.Wildcard {
			results = append(results, result)
		}
	}

	b.logger.Info("DNS brute-force completed",
		"domain", domain,
		"tested", len(b.wordlist)+len(permutations),
		"found", len(results))

	return results, nil
}

// resolve performs DNS resolution
func (b *DNSBruteforcer) resolve(domain string) ([]string, string) {
	var ips []string
	var cname string

	// Try A records
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	for _, resolver := range b.resolvers {
		r, _, err := b.client.Exchange(m, resolver)
		if err != nil {
			continue
		}

		for _, ans := range r.Answer {
			switch v := ans.(type) {
			case *dns.A:
				ips = append(ips, v.A.String())
			case *dns.CNAME:
				cname = v.Target
			}
		}

		if len(ips) > 0 || cname != "" {
			break
		}
	}

	// Try AAAA records
	m.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
	for _, resolver := range b.resolvers {
		r, _, err := b.client.Exchange(m, resolver)
		if err != nil {
			continue
		}

		for _, ans := range r.Answer {
			if v, ok := ans.(*dns.AAAA); ok {
				ips = append(ips, v.AAAA.String())
			}
		}

		if len(ips) > 0 {
			break
		}
	}

	return ips, cname
}

// checkWildcard checks if domain has wildcard DNS
func (b *DNSBruteforcer) checkWildcard(domain string) []string {
	randomSubdomain := fmt.Sprintf("wildcard-test-%d.%s", time.Now().UnixNano(), domain)
	ips, _ := b.resolve(randomSubdomain)
	return ips
}

// isWildcardResponse checks if IPs match wildcard
func (b *DNSBruteforcer) isWildcardResponse(ips, wildcardIPs []string) bool {
	ipMap := make(map[string]bool)
	for _, ip := range wildcardIPs {
		ipMap[ip] = true
	}

	for _, ip := range ips {
		if ipMap[ip] {
			return true
		}
	}

	return false
}

// generatePermutations generates subdomain permutations
func (b *DNSBruteforcer) generatePermutations(domain string) []string {
	var permutations []string

	// Extract base name
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return permutations
	}

	baseName := parts[0]

	// Common patterns
	patterns := []string{
		"%s-dev", "%s-staging", "%s-prod", "%s-test",
		"%s-api", "%s-admin", "%s-portal", "%s-app",
		"dev-%s", "staging-%s", "prod-%s", "test-%s",
		"api-%s", "admin-%s", "portal-%s", "app-%s",
		"%s1", "%s2", "%s3", "%s01", "%s02", "%s03",
		"new-%s", "old-%s", "legacy-%s", "beta-%s",
		"%s-backup", "%s-temp", "%s-cdn", "%s-assets",
		"%s-us", "%s-eu", "%s-asia", "%s-uk",
		"%s-east", "%s-west", "%s-north", "%s-south",
	}

	for _, pattern := range patterns {
		permutations = append(permutations, fmt.Sprintf(pattern, baseName))
	}

	// Year-based patterns
	currentYear := time.Now().Year()
	for year := currentYear - 3; year <= currentYear+1; year++ {
		permutations = append(permutations, fmt.Sprintf("%s%d", baseName, year))
		permutations = append(permutations, fmt.Sprintf("%s-%d", baseName, year))
	}

	return permutations
}

// SetWordlist sets a custom wordlist
func (b *DNSBruteforcer) SetWordlist(wordlist []string) {
	b.wordlist = wordlist
}

// LoadWordlistFromFile loads wordlist from file
func (b *DNSBruteforcer) LoadWordlistFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	b.wordlist = words
	return nil
}

// getDefaultWordlist returns a comprehensive default wordlist
func getDefaultWordlist() []string {
	return []string{
		// Common subdomains
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig",
		"m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin", "portal", "kb", "mobile", "mx", "wiki", "api",
		"media", "www1", "stage", "stats", "staging", "secure", "vpn", "mx1", "cdn", "cdn1", "cdn2", "alpha", "beta",
		"preview", "demo", "internal", "private", "public", "static", "assets", "img", "images", "css", "js",

		// Services
		"mail1", "mail2", "mail3", "smtp1", "smtp2", "mx2", "mx3", "email", "exchange", "outlook", "owa",
		"imap1", "imap2", "pop1", "pop2", "relay", "mailgate", "mailserver", "webmail1", "webmail2",

		// Development/Testing
		"dev1", "dev2", "dev3", "test1", "test2", "test3", "qa", "qa1", "qa2", "uat", "sandbox", "stg", "staging1", "staging2",
		"dev-api", "test-api", "stage-api", "qa-api", "dev-www", "test-www", "stage-www",

		// Admin/Management
		"admin1", "admin2", "administrator", "panel", "control", "cp", "phpmyadmin", "pma", "cms", "manager",
		"management", "console", "backend", "backoffice", "sysadmin", "webadmin", "adminpanel", "controlpanel",

		// Applications
		"app", "app1", "app2", "app3", "application", "apps", "web", "web1", "web2", "web3", "webapp", "webapps",
		"api1", "api2", "api3", "api-v1", "api-v2", "rest", "restapi", "graphql", "grpc", "rpc", "soap", "services",

		// Infrastructure
		"ns3", "ns4", "dns", "dns1", "dns2", "router", "gateway", "firewall", "switch", "proxy", "reverse-proxy",
		"loadbalancer", "lb", "lb1", "lb2", "cluster", "node", "node1", "node2", "server", "server1", "server2",

		// Storage/CDN
		"storage", "files", "data", "backup", "archive", "mirror", "download", "downloads", "dl", "ftp1", "ftp2",
		"sftp", "tftp", "nfs", "share", "shares", "content", "cache", "static1", "static2", "assets1", "assets2",

		// Database
		"db", "db1", "db2", "database", "mysql", "postgres", "postgresql", "mongo", "mongodb", "redis", "elastic",
		"elasticsearch", "cassandra", "oracle", "mssql", "sqlserver", "mariadb", "influxdb", "clickhouse",

		// Monitoring/Analytics
		"monitor", "monitoring", "status", "health", "metrics", "analytics", "stats1", "stats2", "grafana", "kibana",
		"nagios", "zabbix", "prometheus", "logs", "logging", "logstash", "syslog", "graylog", "splunk",

		// Security
		"security", "auth", "authentication", "oauth", "oauth2", "sso", "saml", "ldap", "ad", "radius", "cert",
		"pki", "ca", "acme", "letsencrypt", "ssl", "tls", "waf", "ids", "ips", "siem", "soc",

		// Communication
		"chat", "im", "messaging", "slack", "teams", "discord", "irc", "xmpp", "jabber", "sip", "voip", "pbx",
		"conference", "meeting", "zoom", "webrtc", "turn", "stun", "signal", "matrix", "rocketchat",

		// Geographic
		"us", "eu", "asia", "uk", "de", "fr", "jp", "au", "ca", "in", "cn", "br", "ru", "nl", "es", "it",
		"us-east", "us-west", "eu-west", "eu-central", "asia-pacific", "north", "south", "east", "west",

		// Cloud providers
		"aws", "azure", "gcp", "digitalocean", "linode", "vultr", "ovh", "alibaba", "oracle-cloud",
		"s3", "ec2", "rds", "lambda", "cloudfront", "route53", "elb", "ecs", "eks", "fargate",

		// Environments
		"production", "prod1", "prod2", "development", "integration", "acceptance", "performance", "perf",
		"stress", "load", "preprod", "preproduction", "postprod", "disaster", "dr", "failover", "standby",

		// Projects/Teams
		"project", "team", "dept", "division", "branch", "office", "site", "location", "region", "zone",
		"customer", "client", "partner", "vendor", "supplier", "contractor", "consultant", "agency",

		// Special
		"old", "new", "legacy", "v1", "v2", "v3", "2018", "2019", "2020", "2021", "2022", "2023", "2024",
		"temp", "tmp", "bak", "backup1", "backup2", "archive1", "archive2", "mirror1", "mirror2",
		"hidden", "secret", "private1", "private2", "internal1", "internal2", "restricted", "confidential",

		// Miscellaneous
		"info", "support", "help", "docs", "documentation", "kb", "knowledgebase", "faq", "forum", "forums",
		"community", "social", "mobile1", "mobile2", "tablet", "android", "ios", "windows", "linux", "mac",
		"desktop", "laptop", "workstation", "kiosk", "pos", "atm", "iot", "embedded", "firmware", "hardware",
	}
}
