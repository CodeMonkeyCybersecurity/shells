package discovery

import "time"

// BugBountyDiscoveryConfig returns an optimized config for bug bounty hunting
// This config prioritizes speed and high-value findings over comprehensive coverage
func BugBountyDiscoveryConfig() *DiscoveryConfig {
	return &DiscoveryConfig{
		// Minimal depth - focus on direct targets
		MaxDepth:  1,
		MaxAssets: 50, // Quality over quantity

		// Time-boxed discovery - never wait more than 30 seconds
		Timeout: 30 * time.Second,

		// Disable slow/low-value discovery methods
		EnableDNS:     false, // DNS enumeration is slow and low-value for direct targets
		EnableCertLog: false, // Certificate transparency logs can take 5-10 seconds
		EnableSearch:  false, // Search engine discovery not needed for direct targets

		// Enable fast, high-value discovery
		EnablePortScan:  true, // Quick port scan to find services
		EnableWebCrawl:  true, // Crawl to find endpoints
		EnableTechStack: true, // Identify technologies for targeted testing

		// Performance settings
		MaxWorkers: 10,        // Parallel workers for speed
		RateLimit:  50,        // Higher rate limit for faster scanning
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", // Blend in

		// Behavior settings
		Recursive:     false, // No recursive discovery - stay focused
		HighValueOnly: true,  // Only return high-value assets

		// Port scan settings (quick scan of common web/api ports)
		PortScanPorts:   "80,443,8080,8443,3000,5000,8000,8888", // Common web ports only
		PortScanTimeout: 5 * time.Second,                        // Fast timeout

		// Crawl settings (shallow crawl for endpoints)
		CrawlDepth:   2,              // Shallow crawl
		CrawlTimeout: 10 * time.Second, // Quick crawl
		CrawlMaxURLs: 50,             // Limit URLs crawled
	}
}

// QuickDiscoveryConfig returns an even faster config for quick scans
func QuickDiscoveryConfig() *DiscoveryConfig {
	config := BugBountyDiscoveryConfig()

	// Even more aggressive timeouts
	config.Timeout = 15 * time.Second
	config.MaxAssets = 20
	config.MaxWorkers = 5

	// Minimal crawling
	config.EnableWebCrawl = false
	config.EnablePortScan = true // Only port scan, no crawl

	return config
}

// DeepDiscoveryConfig returns config for comprehensive discovery
// Use this only when you have time and need complete asset coverage
func DeepDiscoveryConfig() *DiscoveryConfig {
	return &DiscoveryConfig{
		MaxDepth:  3,
		MaxAssets: 1000,
		Timeout:   5 * time.Minute,

		// Enable everything for deep discovery
		EnableDNS:       true,
		EnableCertLog:   true,
		EnableSearch:    true,
		EnablePortScan:  true,
		EnableWebCrawl:  true,
		EnableTechStack: true,

		MaxWorkers: 20,
		RateLimit:  100,
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",

		Recursive:     true,
		HighValueOnly: false, // Include all assets

		PortScanPorts:   "1-10000",          // Full port range
		PortScanTimeout: 30 * time.Second,
		CrawlDepth:      5,
		CrawlTimeout:    2 * time.Minute,
		CrawlMaxURLs:    500,
	}
}
