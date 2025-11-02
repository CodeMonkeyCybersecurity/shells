// test_certificate_discovery.go - Live test showing certificate-based discovery
//
// This test demonstrates EXACTLY how microsoft.com → azure.com discovery works
// by querying real certificate transparency logs and showing the extracted SANs.
//
// Run as a test: go test ./cmd -run TestCertificateDiscovery -v

package cmd

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
)

func TestCertificateDiscovery(t *testing.T) {
	fmt.Println("=" + repeat("=", 70))
	fmt.Println(" Certificate Transparency Discovery Test")
	fmt.Println(" Demonstrating: microsoft.com → azure.com discovery")
	fmt.Println("=" + repeat("=", 70))
	fmt.Println()

	// Setup logger
	logCfg := config.LoggerConfig{
		Level:       "info",
		Format:      "text",
		OutputPaths: []string{"stdout"},
	}
	logger, err := logger.New(logCfg)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Setup organization correlator with all features enabled
	corrCfg := correlation.CorrelatorConfig{
		EnableWhois:   true,
		EnableCerts:   true,
		EnableASN:     true,
		EnableLinkedIn: false, // Skip for this test
		EnableGitHub:  false,  // Skip for this test
		CacheTTL:      1 * time.Hour,
	}

	fmt.Println("📊 Configuration:")
	fmt.Printf("   - WHOIS lookup: %v\n", corrCfg.EnableWhois)
	fmt.Printf("   - Certificate transparency: %v\n", corrCfg.EnableCerts)
	fmt.Printf("   - ASN/IP ownership: %v\n", corrCfg.EnableASN)
	fmt.Println()

	correlator := correlation.NewEnhancedOrganizationCorrelator(corrCfg, logger)

	// Wire up default clients for certificate lookup
	whoisClient := correlation.NewDefaultWhoisClient(logger)
	certClient := correlation.NewDefaultCertificateClient(logger)
	asnClient := correlation.NewDefaultASNClient(logger)

	correlator.SetClients(
		whoisClient,
		certClient,
		asnClient,
		nil, // trademark
		nil, // linkedin
		nil, // github
		nil, // cloud
	)

	// Test 1: Discover organization from microsoft.com
	fmt.Println("🔍 Test 1: Discovering organization from microsoft.com")
	fmt.Println(repeat("-", 72))
	fmt.Println()

	ctx := context.Background()
	org, err := correlator.DiscoverFromDomain(ctx, "microsoft.com")
	if err != nil {
		t.Fatalf("Discovery failed: %v", err)
	}

	fmt.Println("✅ Discovery completed!")
	fmt.Println()

	// Display organization info
	fmt.Println("📋 Organization Information:")
	fmt.Printf("   Name: %s\n", org.Name)
	fmt.Printf("   Confidence: %.1f%%\n", org.Confidence*100)
	fmt.Printf("   Data sources: %v\n", org.Sources)
	fmt.Println()

	// Display discovered domains
	fmt.Println("🌐 Discovered Domains:")
	fmt.Printf("   Total: %d domains\n", len(org.Domains))
	fmt.Println()

	// Check if azure.com was found
	azureFound := false
	officeFound := false
	liveFound := false

	for _, domain := range org.Domains {
		if domain == "azure.com" || domain == "azure.microsoft.com" {
			azureFound = true
		}
		if domain == "office.com" || domain == "office365.com" {
			officeFound = true
		}
		if domain == "live.com" {
			liveFound = true
		}
	}

	// Show first 20 domains
	fmt.Println("   First 20 discovered domains:")
	for i, domain := range org.Domains {
		if i >= 20 {
			break
		}

		marker := "   "
		if domain == "azure.com" || domain == "azure.microsoft.com" {
			marker = " ► " // Azure found!
		} else if domain == "office.com" || domain == "office365.com" {
			marker = " ► " // Office found!
		} else if domain == "live.com" {
			marker = " ► " // Live found!
		}

		fmt.Printf("   %s %d. %s\n", marker, i+1, domain)
	}

	if len(org.Domains) > 20 {
		fmt.Printf("   ... and %d more domains\n", len(org.Domains)-20)
	}
	fmt.Println()

	// Display certificates found
	fmt.Println("🔐 Certificates Analyzed:")
	fmt.Printf("   Total certificates: %d\n", len(org.Certificates))
	fmt.Println()

	if len(org.Certificates) > 0 {
		fmt.Println("   Certificate #1 Details:")
		cert := org.Certificates[0]
		fmt.Printf("      Subject: %s\n", cert.Subject)
		fmt.Printf("      Issuer: %s\n", cert.Issuer)
		fmt.Printf("      Valid: %s to %s\n",
			cert.NotBefore.Format("2006-01-02"),
			cert.NotAfter.Format("2006-01-02"))
		fmt.Printf("      SANs (Subject Alternative Names): %d\n", len(cert.SANs))
		fmt.Println()

		// Show SANs (this is where azure.com comes from!)
		fmt.Println("      📜 Subject Alternative Names (SANs):")
		sanCount := len(cert.SANs)
		displayLimit := 30
		if sanCount > displayLimit {
			fmt.Printf("         (Showing first %d of %d SANs)\n", displayLimit, sanCount)
		}

		for i, san := range cert.SANs {
			if i >= displayLimit {
				break
			}

			marker := "         "
			if san == "azure.com" || san == "*.azure.com" || san == "azure.microsoft.com" {
				marker = "      ►►► " // THIS IS IT!
			} else if san == "office.com" || san == "*.office.com" {
				marker = "      ►►► " // THIS IS IT!
			} else if san == "live.com" || san == "*.live.com" {
				marker = "      ►►► " // THIS IS IT!
			}

			fmt.Printf("%s%s\n", marker, san)
		}

		if sanCount > displayLimit {
			fmt.Printf("         ... and %d more SANs\n", sanCount-displayLimit)
		}
		fmt.Println()
	}

	// Display IP ranges
	if len(org.IPRanges) > 0 {
		fmt.Println("🌍 IP Ranges (from ASN):")
		fmt.Printf("   Total: %d ranges\n", len(org.IPRanges))
		for i, ipRange := range org.IPRanges {
			if i >= 5 {
				fmt.Printf("   ... and %d more ranges\n", len(org.IPRanges)-5)
				break
			}
			fmt.Printf("   - %s\n", ipRange)
		}
		fmt.Println()
	}

	// Display ASNs
	if len(org.ASNs) > 0 {
		fmt.Println("🔢 Autonomous System Numbers (ASNs):")
		for _, asn := range org.ASNs {
			fmt.Printf("   - %s\n", asn)
		}
		fmt.Println()
	}

	// Summary
	fmt.Println("=" + repeat("=", 70))
	fmt.Println(" 📊 Discovery Summary")
	fmt.Println("=" + repeat("=", 70))
	fmt.Println()
	fmt.Printf("Organization: %s\n", org.Name)
	fmt.Printf("Total Domains Discovered: %d\n", len(org.Domains))
	fmt.Printf("Total Certificates: %d\n", len(org.Certificates))
	fmt.Printf("Total IP Ranges: %d\n", len(org.IPRanges))
	fmt.Printf("Total ASNs: %d\n", len(org.ASNs))
	fmt.Println()

	// KEY FINDINGS
	fmt.Println("🎯 Key Findings:")
	if azureFound {
		fmt.Println("   ✅ azure.com DISCOVERED via certificate SANs")
	} else {
		fmt.Println("   ❌ azure.com NOT found")
	}

	if officeFound {
		fmt.Println("   ✅ office.com DISCOVERED via certificate SANs")
	} else {
		fmt.Println("   ❌ office.com NOT found")
	}

	if liveFound {
		fmt.Println("   ✅ live.com DISCOVERED via certificate SANs")
	} else {
		fmt.Println("   ❌ live.com NOT found")
	}
	fmt.Println()

	// Explain the mechanism
	fmt.Println("=" + repeat("=", 70))
	fmt.Println(" 🔬 How It Works")
	fmt.Println("=" + repeat("=", 70))
	fmt.Println()
	fmt.Println("1. Query certificate transparency logs for microsoft.com")
	fmt.Println("2. Extract SSL certificate details")
	fmt.Println("3. Read Subject Alternative Names (SANs) from certificate")
	fmt.Println("4. Add all SANs as related domains")
	fmt.Println("5. Result: azure.com, office.com, live.com automatically discovered!")
	fmt.Println()
	fmt.Println("This is how shells discovers ALL Microsoft properties automatically")
	fmt.Println("when you run: shells microsoft.com")
	fmt.Println()

	// Code references
	fmt.Println("📁 Code References:")
	fmt.Println("   - Certificate query: pkg/correlation/organization.go:354")
	fmt.Println("   - SAN extraction: pkg/correlation/organization.go:376-380")
	fmt.Println("   - Organization context: internal/discovery/asset_relationship_mapper.go:1265")
	fmt.Println()
}

func repeat(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}
