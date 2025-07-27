package ipv6

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// IPv6Discoverer discovers IPv6 addresses for domains and networks
type IPv6Discoverer struct {
	logger *logger.Logger
}

// IPv6Address represents a discovered IPv6 address
type IPv6Address struct {
	Address    string
	Domain     string
	Type       string // AAAA, PTR, etc.
	Source     string
	Prefix     string
	Network    string
	Discovered time.Time
}

// IPv6Network represents an IPv6 network/prefix
type IPv6Network struct {
	Network     string
	Prefix      int
	Addresses   []IPv6Address
	Source      string
	Description string
	Discovered  time.Time
}

// NewIPv6Discoverer creates a new IPv6 discoverer
func NewIPv6Discoverer(logger *logger.Logger) *IPv6Discoverer {
	return &IPv6Discoverer{
		logger: logger,
	}
}

// DiscoverIPv6Addresses discovers IPv6 addresses for a domain
func (d *IPv6Discoverer) DiscoverIPv6Addresses(ctx context.Context, domain string) ([]IPv6Address, error) {
	var addresses []IPv6Address
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Direct AAAA lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ipv6s, err := d.lookupAAAA(ctx, domain); err == nil {
			mu.Lock()
			addresses = append(addresses, ipv6s...)
			mu.Unlock()
		}
	}()

	// Try common IPv6 subdomains
	commonSubdomains := []string{
		"ipv6." + domain,
		"v6." + domain,
		"www.ipv6." + domain,
		"mail.ipv6." + domain,
		"ftp.ipv6." + domain,
		"ns1.ipv6." + domain,
		"ns2.ipv6." + domain,
	}

	for _, subdomain := range commonSubdomains {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			if ipv6s, err := d.lookupAAAA(ctx, sub); err == nil {
				mu.Lock()
				addresses = append(addresses, ipv6s...)
				mu.Unlock()
			}
		}(subdomain)
	}

	wg.Wait()

	d.logger.Info("IPv6 address discovery completed",
		"domain", domain,
		"addresses_found", len(addresses))

	return addresses, nil
}

// lookupAAAA performs AAAA DNS lookup
func (d *IPv6Discoverer) lookupAAAA(ctx context.Context, domain string) ([]IPv6Address, error) {
	var addresses []IPv6Address

	// Use a resolver for context support
	resolver := &net.Resolver{}

	// Perform AAAA lookup
	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return addresses, err
	}

	for _, ip := range ips {
		if ip.IP.To16() != nil && ip.IP.To4() == nil { // IPv6 address
			addr := IPv6Address{
				Address:    ip.IP.String(),
				Domain:     domain,
				Type:       "AAAA",
				Source:     "dns_lookup",
				Network:    d.getIPv6Network(ip.IP.String()),
				Discovered: time.Now(),
			}
			addresses = append(addresses, addr)
		}
	}

	return addresses, nil
}

// getIPv6Network determines the IPv6 network prefix
func (d *IPv6Discoverer) getIPv6Network(ipv6 string) string {
	ip := net.ParseIP(ipv6)
	if ip == nil {
		return ""
	}

	// Get /64 network (common for IPv6)
	ipv6Net := &net.IPNet{
		IP:   ip.Mask(net.CIDRMask(64, 128)),
		Mask: net.CIDRMask(64, 128),
	}

	return ipv6Net.String()
}

// DiscoverIPv6Networks discovers IPv6 networks for an organization
func (d *IPv6Discoverer) DiscoverIPv6Networks(ctx context.Context, domain string) ([]IPv6Network, error) {
	var networks []IPv6Network

	// First, discover IPv6 addresses
	addresses, err := d.DiscoverIPv6Addresses(ctx, domain)
	if err != nil {
		return networks, err
	}

	// Group addresses by network
	networkMap := make(map[string][]IPv6Address)
	for _, addr := range addresses {
		if addr.Network != "" {
			networkMap[addr.Network] = append(networkMap[addr.Network], addr)
		}
	}

	// Create network objects
	for networkStr, addrs := range networkMap {
		network := IPv6Network{
			Network:     networkStr,
			Prefix:      64, // Default /64
			Addresses:   addrs,
			Source:      "address_aggregation",
			Description: fmt.Sprintf("IPv6 network derived from domain %s", domain),
			Discovered:  time.Now(),
		}
		networks = append(networks, network)
	}

	return networks, nil
}

// ScanIPv6Network scans an IPv6 network for active addresses
func (d *IPv6Discoverer) ScanIPv6Network(ctx context.Context, network string) ([]IPv6Address, error) {
	var addresses []IPv6Address

	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		return addresses, err
	}

	d.logger.Info("Starting IPv6 network scan", "network", network)

	// For IPv6, we can't scan entire networks like we do with IPv4
	// Instead, we try common address patterns
	commonPatterns := d.generateCommonIPv6Patterns(ipNet)

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100) // Limit concurrency

	for _, addr := range commonPatterns {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			if d.isIPv6AddressActive(ctx, ip) {
				mu.Lock()
				addresses = append(addresses, IPv6Address{
					Address:    ip,
					Type:       "scan",
					Source:     "network_scan",
					Network:    network,
					Discovered: time.Now(),
				})
				mu.Unlock()
			}
		}(addr)
	}

	wg.Wait()

	d.logger.Info("IPv6 network scan completed",
		"network", network,
		"addresses_tested", len(commonPatterns),
		"active_addresses", len(addresses))

	return addresses, nil
}

// generateCommonIPv6Patterns generates common IPv6 address patterns in a network
func (d *IPv6Discoverer) generateCommonIPv6Patterns(ipNet *net.IPNet) []string {
	var patterns []string

	// Get network prefix
	ip := ipNet.IP
	prefixLen, _ := ipNet.Mask.Size()

	// For /64 networks, try common patterns
	if prefixLen == 64 {
		// Get the first 64 bits (network part)
		networkPart := ip[:8] // First 8 bytes = 64 bits

		// Common patterns for the host part (last 64 bits)
		hostPatterns := []string{
			"::1",                   // Router
			"::2",                   // Common server
			"::10",                  // Common server
			"::100",                 // Common server
			"::1:1",                 // Pattern
			"::ffff:ffff:ffff:ffff", // All ones
			"::" + strings.ToLower(ip.String()[len(ip.String())-4:]), // Based on last part of network
		}

		// Convert network part to string
		networkStr := fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			networkPart[0], networkPart[1], networkPart[2], networkPart[3],
			networkPart[4], networkPart[5], networkPart[6], networkPart[7])

		for _, hostPattern := range hostPatterns {
			fullAddr := networkStr + hostPattern
			if parsedIP := net.ParseIP(fullAddr); parsedIP != nil {
				patterns = append(patterns, parsedIP.String())
			}
		}

		// Also try SLAAC-style addresses (based on MAC addresses)
		slaacPatterns := d.generateSLAACPatterns(networkStr)
		patterns = append(patterns, slaacPatterns...)
	}

	// For other prefix lengths, try simpler patterns
	if prefixLen < 64 {
		// Just try the network address and ::1
		patterns = append(patterns, ip.String())

		// Try ::1 in the network
		ip1 := make(net.IP, len(ip))
		copy(ip1, ip)
		ip1[len(ip1)-1] = 1
		patterns = append(patterns, ip1.String())
	}

	return patterns
}

// generateSLAACPatterns generates SLAAC (Stateless Address Autoconfiguration) patterns
func (d *IPv6Discoverer) generateSLAACPatterns(networkPrefix string) []string {
	var patterns []string

	// Common MAC address patterns that would be used in SLAAC
	commonMACs := []string{
		"00:00:5e:00:53:00", // VRRP
		"00:00:0c:07:ac:00", // Cisco
		"00:50:56:00:00:00", // VMware
		"52:54:00:00:00:00", // QEMU/KVM
		"02:00:4c:4f:4f:50", // Loop
	}

	for _, mac := range commonMACs {
		// Convert MAC to IPv6 Interface ID (EUI-64)
		interfaceID := d.macToEUI64(mac)
		if interfaceID != "" {
			fullAddr := networkPrefix + "::" + interfaceID
			if parsedIP := net.ParseIP(fullAddr); parsedIP != nil {
				patterns = append(patterns, parsedIP.String())
			}
		}
	}

	return patterns
}

// macToEUI64 converts a MAC address to EUI-64 format for IPv6
func (d *IPv6Discoverer) macToEUI64(mac string) string {
	// Remove colons and convert to lowercase
	cleanMAC := strings.ReplaceAll(strings.ToLower(mac), ":", "")

	if len(cleanMAC) != 12 {
		return ""
	}

	// Split into two halves and insert FFFE
	firstHalf := cleanMAC[:6]
	secondHalf := cleanMAC[6:]

	// Flip the universal/local bit (7th bit of first byte)
	firstByteStr := cleanMAC[:2]
	var firstByteInt int
	if n, err := fmt.Sscanf(firstByteStr, "%02x", &firstByteInt); err == nil && n == 1 {
		firstByteInt ^= 0x02 // Flip bit 1 (7th bit)
		eui64 := fmt.Sprintf("%02x%s:fffe:%s", firstByteInt, firstHalf[2:], secondHalf)
		return eui64
	}

	return ""
}

// isIPv6AddressActive checks if an IPv6 address is active
func (d *IPv6Discoverer) isIPv6AddressActive(ctx context.Context, ipv6 string) bool {
	// Try ICMP ping
	if d.pingIPv6(ctx, ipv6) {
		return true
	}

	// Try connecting to common ports
	commonPorts := []int{80, 443, 22, 25, 53}
	for _, port := range commonPorts {
		if d.testIPv6Port(ctx, ipv6, port) {
			return true
		}
	}

	return false
}

// pingIPv6 attempts to ping an IPv6 address
func (d *IPv6Discoverer) pingIPv6(ctx context.Context, ipv6 string) bool {
	// Create ICMP connection
	conn, err := net.Dial("ip6:ipv6-icmp", ipv6)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Set deadline
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)

	// Send ICMP Echo Request
	// Simplified - in production you'd craft proper ICMP packets
	_, err = conn.Write([]byte("ping"))
	return err == nil
}

// testIPv6Port tests if a port is open on an IPv6 address
func (d *IPv6Discoverer) testIPv6Port(ctx context.Context, ipv6 string, port int) bool {
	target := fmt.Sprintf("[%s]:%d", ipv6, port)

	dialer := net.Dialer{
		Timeout: 3 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// DiscoverIPv6FromIPv4 discovers potential IPv6 addresses based on IPv4 addresses
func (d *IPv6Discoverer) DiscoverIPv6FromIPv4(ctx context.Context, ipv4 string, domain string) ([]IPv6Address, error) {
	var addresses []IPv6Address

	ip := net.ParseIP(ipv4)
	if ip == nil || ip.To4() == nil {
		return addresses, fmt.Errorf("invalid IPv4 address: %s", ipv4)
	}

	// Common IPv6 transition mechanisms

	// 1. 6to4 (2002::/16)
	sixto4 := d.generateSixToFour(ip)
	if sixto4 != "" {
		addresses = append(addresses, IPv6Address{
			Address:    sixto4,
			Domain:     domain,
			Type:       "6to4",
			Source:     "ipv4_transition",
			Discovered: time.Now(),
		})
	}

	// 2. Teredo (2001::/32)
	teredo := d.generateTeredo(ip)
	if teredo != "" {
		addresses = append(addresses, IPv6Address{
			Address:    teredo,
			Domain:     domain,
			Type:       "teredo",
			Source:     "ipv4_transition",
			Discovered: time.Now(),
		})
	}

	// 3. IPv4-mapped IPv6 (::ffff:0:0/96)
	mapped := fmt.Sprintf("::ffff:%s", ip.String())
	addresses = append(addresses, IPv6Address{
		Address:    mapped,
		Domain:     domain,
		Type:       "ipv4_mapped",
		Source:     "ipv4_transition",
		Discovered: time.Now(),
	})

	// 4. IPv4-compatible IPv6 (deprecated but still found)
	compatible := fmt.Sprintf("::%s", ip.String())
	addresses = append(addresses, IPv6Address{
		Address:    compatible,
		Domain:     domain,
		Type:       "ipv4_compatible",
		Source:     "ipv4_transition",
		Discovered: time.Now(),
	})

	return addresses, nil
}

// generateSixToFour generates 6to4 IPv6 address from IPv4
func (d *IPv6Discoverer) generateSixToFour(ipv4 net.IP) string {
	if ipv4.To4() == nil {
		return ""
	}

	// 6to4 format: 2002:WWXX:YYZZ::/48 where WW.XX.YY.ZZ is the IPv4 address
	octets := ipv4.To4()
	return fmt.Sprintf("2002:%02x%02x:%02x%02x::1",
		octets[0], octets[1], octets[2], octets[3])
}

// generateTeredo generates Teredo IPv6 address from IPv4
func (d *IPv6Discoverer) generateTeredo(ipv4 net.IP) string {
	if ipv4.To4() == nil {
		return ""
	}

	// Teredo format: 2001::/32 with embedded IPv4
	// Simplified version - real Teredo is more complex
	octets := ipv4.To4()
	return fmt.Sprintf("2001::ffff:%02x%02x:%02x%02x",
		octets[0], octets[1], octets[2], octets[3])
}

// AnalyzeIPv6Address analyzes an IPv6 address for information
func (d *IPv6Discoverer) AnalyzeIPv6Address(ipv6 string) map[string]string {
	analysis := make(map[string]string)

	ip := net.ParseIP(ipv6)
	if ip == nil {
		analysis["error"] = "Invalid IPv6 address"
		return analysis
	}

	analysis["address"] = ip.String()
	analysis["compressed"] = ip.String()

	// Determine address type
	if ip.IsLoopback() {
		analysis["type"] = "loopback"
	} else if ip.IsLinkLocalUnicast() {
		analysis["type"] = "link_local"
	} else if ip.IsLinkLocalMulticast() {
		analysis["type"] = "link_local_multicast"
	} else if ip.IsMulticast() {
		analysis["type"] = "multicast"
	} else if ip.IsUnspecified() {
		analysis["type"] = "unspecified"
	} else {
		analysis["type"] = "global_unicast"
	}

	// Check for special prefixes
	if strings.HasPrefix(ipv6, "2002:") {
		analysis["transition_mechanism"] = "6to4"
		// Extract embedded IPv4
		if embeddedIPv4 := d.extract6to4IPv4(ipv6); embeddedIPv4 != "" {
			analysis["embedded_ipv4"] = embeddedIPv4
		}
	} else if strings.HasPrefix(ipv6, "2001:0:") || strings.HasPrefix(ipv6, "2001::") {
		analysis["transition_mechanism"] = "teredo"
	} else if strings.HasPrefix(ipv6, "::ffff:") {
		analysis["transition_mechanism"] = "ipv4_mapped"
		analysis["embedded_ipv4"] = strings.TrimPrefix(ipv6, "::ffff:")
	}

	// Geographic/provider hints (simplified)
	if strings.HasPrefix(ipv6, "2001:4860:") {
		analysis["provider_hint"] = "Google"
	} else if strings.HasPrefix(ipv6, "2001:4998:") {
		analysis["provider_hint"] = "Yahoo"
	} else if strings.HasPrefix(ipv6, "2a03:2880:") {
		analysis["provider_hint"] = "Facebook"
	}

	return analysis
}

// extract6to4IPv4 extracts IPv4 address from 6to4 IPv6 address
func (d *IPv6Discoverer) extract6to4IPv4(ipv6 string) string {
	// 6to4 format: 2002:WWXX:YYZZ::/48
	re := regexp.MustCompile(`^2002:([0-9a-f]{2})([0-9a-f]{2}):([0-9a-f]{2})([0-9a-f]{2})`)
	matches := re.FindStringSubmatch(strings.ToLower(ipv6))

	if len(matches) == 5 {
		var octets [4]int
		for i := 1; i <= 4; i++ {
			if n, err := fmt.Sscanf(matches[i], "%x", &octets[i-1]); err != nil || n != 1 {
				return ""
			}
		}
		return fmt.Sprintf("%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3])
	}

	return ""
}

// ReverseLookupIPv6 performs reverse DNS lookup for IPv6 addresses
func (d *IPv6Discoverer) ReverseLookupIPv6(ctx context.Context, ipv6 string) ([]string, error) {
	names, err := net.LookupAddr(ipv6)
	if err != nil {
		return nil, err
	}

	// Clean up names (remove trailing dots)
	var cleanNames []string
	for _, name := range names {
		cleanNames = append(cleanNames, strings.TrimSuffix(name, "."))
	}

	return cleanNames, nil
}
