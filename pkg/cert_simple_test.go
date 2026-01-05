// test_cert_simple.go - Test certificate discovery with smaller domain
package pkg

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
)

func TestCertSimple(t *testing.T) {
	fmt.Println("Testing Certificate SAN Extraction")
	fmt.Println("===================================")
	fmt.Println()

	// Setup logger
	logCfg := config.LoggerConfig{
		Level:       "warn", // Only show warnings/errors
		Format:      "text",
		OutputPaths: []string{"stdout"},
	}
	logger, err := logger.New(logCfg)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Setup correlator
	corrCfg := correlation.CorrelatorConfig{
		EnableWhois: true,
		EnableCerts: true,
		EnableASN:   false,
		CacheTTL:    1 * time.Hour,
	}

	correlator := correlation.NewEnhancedOrganizationCorrelator(corrCfg, logger)

	// Wire up clients
	whoisClient := correlation.NewDefaultWhoisClient(logger)
	certClient := correlation.NewDefaultCertificateClient(logger)

	correlator.SetClients(
		whoisClient,
		certClient,
		nil, nil, nil, nil, nil,
	)

	// Test with anthropic.com (smaller, less queried than microsoft.com)
	testDomain := "anthropic.com"
	fmt.Printf("Testing domain: %s\n", testDomain)
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Println("Querying certificate transparency logs...")
	org, err := correlator.DiscoverFromDomain(ctx, testDomain)
	if err != nil {
		t.Fatalf("Discovery failed: %v", err)
	}

	fmt.Println()
	fmt.Println("Results:")
	fmt.Println("--------")
	fmt.Printf("Organization: %s\n", org.Name)
	fmt.Printf("Certificates found: %d\n", len(org.Certificates))
	fmt.Printf("Domains discovered: %d\n", len(org.Domains))
	fmt.Println()

	if len(org.Certificates) > 0 {
		fmt.Println("Certificate #1 SANs (Subject Alternative Names):")
		cert := org.Certificates[0]
		fmt.Printf("  Subject: %s\n", cert.Subject)
		fmt.Printf("  Issuer: %s\n", cert.Issuer)
		fmt.Printf("  Total SANs: %d\n", len(cert.SANs))
		fmt.Println()

		if len(cert.SANs) > 0 {
			fmt.Println("  SANs extracted:")
			for i, san := range cert.SANs {
				if i >= 20 {
					fmt.Printf("  ... and %d more\n", len(cert.SANs)-20)
					break
				}
				fmt.Printf("    - %s\n", san)
			}
		}
		fmt.Println()
	}

	fmt.Println("Discovered domains (from all sources):")
	for i, domain := range org.Domains {
		if i >= 20 {
			fmt.Printf("  ... and %d more\n", len(org.Domains)-20)
			break
		}
		fmt.Printf("  - %s\n", domain)
	}
	fmt.Println()

	fmt.Println("This demonstrates how related domains are discovered through certificate SANs.")
	fmt.Println("When scanning microsoft.com, the same mechanism would find azure.com, office.com, etc.")
}
