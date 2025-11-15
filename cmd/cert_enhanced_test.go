// test_cert_enhanced.go - Test enhanced certificate client with direct TLS
package cmd

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/correlation"
)

func TestCertEnhanced(t *testing.T) {
	fmt.Println("=" + strings.Repeat("=", 78))
	fmt.Println(" Enhanced Certificate Discovery Test")
	fmt.Println(" Using Direct TLS Connection + Certificate Transparency")
	fmt.Println("=" + strings.Repeat("=", 78))
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

	// Test with multiple domains
	testDomains := []string{
		"anthropic.com",  // AI company
		"github.com",     // Should have many SANs
		"cloudflare.com", // CDN with many properties
	}

	for _, domain := range testDomains {
		fmt.Printf("Testing: %s\n", domain)
		fmt.Println(strings.Repeat("-", 78))

		// Create enhanced certificate client
		certClient := correlation.NewEnhancedCertificateClient(logger)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Get certificates
		certs, err := certClient.GetCertificates(ctx, domain)
		if err != nil {
			fmt.Printf("  Error: %v\n", err)
			fmt.Println()
			continue
		}

		if len(certs) == 0 {
			fmt.Println("  No certificates found")
			fmt.Println()
			continue
		}

		fmt.Printf("  Certificates found: %d\n", len(certs))
		fmt.Println()

		// Display first certificate
		cert := certs[0]
		fmt.Println("  Certificate Details:")
		fmt.Printf("    Subject:     %s\n", cert.Subject)
		fmt.Printf("    Issuer:      %s\n", cert.Issuer)
		fmt.Printf("    Valid From:  %s\n", cert.NotBefore.Format("2006-01-02"))
		fmt.Printf("    Valid Until: %s\n", cert.NotAfter.Format("2006-01-02"))
		fmt.Printf("    Total SANs:  %d\n", len(cert.SANs))
		fmt.Println()

		if len(cert.SANs) > 0 {
			fmt.Println("  Subject Alternative Names (SANs):")
			for i, san := range cert.SANs {
				if i >= 20 {
					fmt.Printf("    ... and %d more\n", len(cert.SANs)-20)
					break
				}
				fmt.Printf("    - %s\n", san)
			}
			fmt.Println()
		}

		fmt.Println("  Discovery Results:")
		// Extract unique domains from SANs (filter wildcards and IPs)
		domains := make(map[string]bool)
		for _, san := range cert.SANs {
			if strings.HasPrefix(san, "*.") {
				// Extract base domain from wildcard
				baseDomain := strings.TrimPrefix(san, "*.")
				domains[baseDomain] = true
			} else if !strings.Contains(san, ":") { // Skip IPs
				domains[san] = true
			}
		}

		fmt.Printf("    Unique domains discovered: %d\n", len(domains))
		count := 0
		for domain := range domains {
			if count >= 10 {
				fmt.Printf("    ... and %d more\n", len(domains)-10)
				break
			}
			fmt.Printf("      → %s\n", domain)
			count++
		}
		fmt.Println()
		fmt.Println()
	}

	fmt.Println("=" + strings.Repeat("=", 78))
	fmt.Println(" Summary")
	fmt.Println("=" + strings.Repeat("=", 78))
	fmt.Println()
	fmt.Println("This demonstrates the enhanced certificate client with multiple fallback sources:")
	fmt.Println("  1. Direct TLS connection (fast, reliable)")
	fmt.Println("  2. Certificate Transparency logs (comprehensive, but may be slow)")
	fmt.Println("  3. Future: PostgreSQL connection to crt.sh")
	fmt.Println("  4. Future: Censys API (requires API key)")
	fmt.Println()
	fmt.Println("The same mechanism discovers azure.com from microsoft.com when queried.")
}
