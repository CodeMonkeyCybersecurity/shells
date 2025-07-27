package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/certlogs"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/ipv6"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/passivedns"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/techstack"
)

func TestIntegratedDiscovery(t *testing.T) {
	// Create test logger
	log, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "json",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Test context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Test domain
	testDomain := "example.com"

	t.Run("SSL Certificate Transparency", func(t *testing.T) {
		ctClient := certlogs.NewCTLogClient(log)
		
		// Test certificate discovery
		certs, err := ctClient.SearchDomain(ctx, testDomain)
		if err != nil {
			t.Errorf("Failed to search CT logs: %v", err)
		}
		
		t.Logf("Found %d certificates for %s", len(certs), testDomain)
		
		// Test subdomain discovery
		subdomains, err := ctClient.DiscoverSubdomains(ctx, testDomain)
		if err != nil {
			t.Errorf("Failed to discover subdomains: %v", err)
		}
		
		t.Logf("Found %d subdomains from CT logs", len(subdomains))
		
		// Test certificate timeline
		timeline, err := ctClient.GetCertificateTimeline(ctx, testDomain)
		if err != nil {
			t.Errorf("Failed to get certificate timeline: %v", err)
		}
		
		t.Logf("Certificate timeline has %d entries", len(timeline))
		
		// Test wildcard certificates
		wildcards, err := ctClient.FindWildcardCerts(ctx, testDomain)
		if err != nil {
			t.Errorf("Failed to find wildcard certificates: %v", err)
		}
		
		t.Logf("Found %d wildcard certificates", len(wildcards))
		
		// Test certificate history analysis
		analysis, err := ctClient.AnalyzeCertificateHistory(ctx, testDomain)
		if err != nil {
			t.Errorf("Failed to analyze certificate history: %v", err)
		}
		
		if analysis != nil {
			t.Logf("Certificate Analysis:")
			t.Logf("  Total Certificates: %d", analysis.TotalCerts)
			t.Logf("  Active Certificates: %d", analysis.ActiveCerts)
			t.Logf("  Expired Certificates: %d", analysis.ExpiredCerts)
			t.Logf("  Unique Issuers: %d", len(analysis.UniqueIssuers))
		}
	})

	t.Run("Technology Stack Fingerprinting", func(t *testing.T) {
		techFp := techstack.NewTechFingerprinter(log)
		
		// Test URL fingerprinting
		testURL := "https://" + testDomain
		technologies, err := techFp.FingerprintURL(ctx, testURL)
		if err != nil {
			t.Logf("Failed to fingerprint URL %s: %v (this may be expected)", testURL, err)
		} else {
			t.Logf("Found %d technologies at %s", len(technologies), testURL)
			
			for _, tech := range technologies {
				t.Logf("  - %s (%s) v%s - Confidence: %.2f", 
					tech.Name, tech.Category, tech.Version, tech.Confidence)
				for _, evidence := range tech.Evidence {
					t.Logf("    Evidence: %s", evidence)
				}
			}
		}
		
		// Test getting available categories
		categories := techFp.GetCategories()
		t.Logf("Available technology categories: %d", len(categories))
		for _, cat := range categories {
			t.Logf("  - %s", cat)
		}
	})

	t.Run("Passive DNS Integration", func(t *testing.T) {
		// Create passive DNS client (without API keys for testing)
		pdnsClient := passivedns.NewPassiveDNSClient(log, map[string]string{})
		
		// Test domain query (will likely fail without API keys)
		results, err := pdnsClient.QueryDomain(ctx, testDomain)
		if err != nil {
			t.Logf("Failed to query passive DNS: %v (expected without API keys)", err)
		} else {
			t.Logf("Passive DNS query returned %d results", len(results))
			
			for _, result := range results {
				t.Logf("  Source: %s, Records: %d", result.Source, len(result.Records))
			}
		}
		
		// Test subdomain discovery
		subdomains, err := pdnsClient.DiscoverSubdomains(ctx, testDomain)
		if err != nil {
			t.Logf("Failed to discover subdomains: %v", err)
		} else {
			t.Logf("Found %d subdomains from passive DNS", len(subdomains))
		}
		
		// Test IP history discovery
		ipHistory, err := pdnsClient.DiscoverIPHistory(ctx, testDomain)
		if err != nil {
			t.Logf("Failed to discover IP history: %v", err)
		} else {
			t.Logf("Found %d historical IP addresses", len(ipHistory))
		}
		
		// Test DNS timeline
		timeline, err := pdnsClient.GetDNSTimeline(ctx, testDomain)
		if err != nil {
			t.Logf("Failed to get DNS timeline: %v", err)
		} else {
			t.Logf("DNS timeline has %d entries", len(timeline))
		}
	})

	t.Run("IPv6 Address Discovery", func(t *testing.T) {
		ipv6Disc := ipv6.NewIPv6Discoverer(log)
		
		// Test IPv6 address discovery
		addresses, err := ipv6Disc.DiscoverIPv6Addresses(ctx, testDomain)
		if err != nil {
			t.Errorf("Failed to discover IPv6 addresses: %v", err)
		}
		
		t.Logf("Found %d IPv6 addresses for %s", len(addresses), testDomain)
		for _, addr := range addresses {
			t.Logf("  - %s (Type: %s, Source: %s)", addr.Address, addr.Type, addr.Source)
		}
		
		// Test IPv6 network discovery
		networks, err := ipv6Disc.DiscoverIPv6Networks(ctx, testDomain)
		if err != nil {
			t.Errorf("Failed to discover IPv6 networks: %v", err)
		}
		
		t.Logf("Found %d IPv6 networks", len(networks))
		for _, network := range networks {
			t.Logf("  - %s (Prefix: /%d, Addresses: %d)", 
				network.Network, network.Prefix, len(network.Addresses))
		}
		
		// Test IPv4 to IPv6 transition discovery
		testIPv4 := "93.184.216.34" // example.com's IPv4
		transitionAddrs, err := ipv6Disc.DiscoverIPv6FromIPv4(ctx, testIPv4, testDomain)
		if err != nil {
			t.Errorf("Failed to discover transition addresses: %v", err)
		}
		
		t.Logf("Found %d IPv6 transition addresses from IPv4 %s", len(transitionAddrs), testIPv4)
		for _, addr := range transitionAddrs {
			t.Logf("  - %s (Type: %s)", addr.Address, addr.Type)
		}
		
		// Test IPv6 address analysis
		if len(addresses) > 0 {
			analysis := ipv6Disc.AnalyzeIPv6Address(addresses[0].Address)
			t.Logf("IPv6 Address Analysis for %s:", addresses[0].Address)
			for k, v := range analysis {
				t.Logf("  %s: %s", k, v)
			}
		}
		
		// Test reverse lookup
		if len(addresses) > 0 {
			names, err := ipv6Disc.ReverseLookupIPv6(ctx, addresses[0].Address)
			if err != nil {
				t.Logf("Failed to reverse lookup IPv6: %v", err)
			} else {
				t.Logf("Reverse lookup returned %d names", len(names))
				for _, name := range names {
					t.Logf("  - %s", name)
				}
			}
		}
	})
}

func TestDiscoveryFeatures(t *testing.T) {
	// Create test logger
	log, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "json",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	ctx := context.Background()

	t.Run("CT Log Features", func(t *testing.T) {
		ctClient := certlogs.NewCTLogClient(log)
		
		// Test with a known domain that should have certificates
		testDomain := "google.com"
		
		certs, err := ctClient.SearchDomain(ctx, testDomain)
		if err != nil {
			t.Logf("CT log search error: %v", err)
		}
		
		if len(certs) > 0 {
			t.Logf("Successfully found %d certificates for %s", len(certs), testDomain)
			
			// Check certificate properties
			cert := certs[0]
			if cert.SubjectCN == "" {
				t.Error("Certificate SubjectCN should not be empty")
			}
			if cert.Issuer == "" {
				t.Error("Certificate Issuer should not be empty")
			}
			if len(cert.SANs) == 0 {
				t.Error("Certificate should have SANs")
			}
		}
	})

	t.Run("Tech Fingerprint Features", func(t *testing.T) {
		techFp := techstack.NewTechFingerprinter(log)
		
		// Test categories
		categories := techFp.GetCategories()
		if len(categories) == 0 {
			t.Error("Should have technology categories")
		}
		
		expectedCategories := []string{
			"Web Server",
			"Programming Language",
			"Web Framework",
			"CMS",
			"JavaScript Library",
			"JavaScript Framework",
			"Database",
			"Analytics",
			"CDN",
			"Security",
		}
		
		categoryMap := make(map[string]bool)
		for _, cat := range categories {
			categoryMap[cat] = true
		}
		
		for _, expected := range expectedCategories {
			if !categoryMap[expected] {
				t.Errorf("Missing expected category: %s", expected)
			}
		}
	})

	t.Run("IPv6 Features", func(t *testing.T) {
		ipv6Disc := ipv6.NewIPv6Discoverer(log)
		
		// Test IPv6 address analysis
		testAddresses := []string{
			"2001:4860:4860::8888", // Google DNS
			"::1",                   // Loopback
			"fe80::1",              // Link-local
			"2002:5dba:d820::1",    // 6to4
			"::ffff:192.0.2.1",     // IPv4-mapped
		}
		
		for _, addr := range testAddresses {
			analysis := ipv6Disc.AnalyzeIPv6Address(addr)
			
			if analysis["address"] == "" {
				t.Errorf("Analysis should include address for %s", addr)
			}
			if analysis["type"] == "" {
				t.Errorf("Analysis should include type for %s", addr)
			}
			
			t.Logf("IPv6 %s analysis: type=%s", addr, analysis["type"])
		}
		
		// Test 6to4 IPv4 extraction
		sixto4Addr := "2002:5dba:d820::1"
		analysis := ipv6Disc.AnalyzeIPv6Address(sixto4Addr)
		if analysis["embedded_ipv4"] != "93.186.216.32" {
			t.Errorf("Failed to extract correct IPv4 from 6to4 address")
		}
	})
}

func TestEdgeCases(t *testing.T) {
	// Create test logger
	log, err := logger.New(config.LoggerConfig{
		Level:  "debug",
		Format: "json",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	ctx := context.Background()

	t.Run("Empty Domain Handling", func(t *testing.T) {
		ctClient := certlogs.NewCTLogClient(log)
		
		_, err := ctClient.SearchDomain(ctx, "")
		if err == nil {
			t.Error("Expected error for empty domain")
		}
	})

	t.Run("Invalid IPv6 Handling", func(t *testing.T) {
		ipv6Disc := ipv6.NewIPv6Discoverer(log)
		
		analysis := ipv6Disc.AnalyzeIPv6Address("not-an-ip")
		if analysis["error"] == "" {
			t.Error("Expected error for invalid IPv6 address")
		}
	})

	t.Run("Tech Fingerprint Empty Response", func(t *testing.T) {
		techFp := techstack.NewTechFingerprinter(log)
		
		// Test with invalid URL
		_, err := techFp.FingerprintURL(ctx, "http://")
		if err == nil {
			t.Error("Expected error for invalid URL")
		}
	})
}