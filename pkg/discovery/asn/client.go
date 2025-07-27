package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// ASNClient performs ASN lookups and expansion
type ASNClient struct {
	client *http.Client
	logger *logger.Logger
	cache  map[string]*ASNInfo
}

// NewASNClient creates a new ASN client
func NewASNClient(logger *logger.Logger) *ASNClient {
	return &ASNClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
		cache:  make(map[string]*ASNInfo),
	}
}

// ASNInfo contains ASN information
type ASNInfo struct {
	ASN           int
	Name          string
	Organization  string
	Country       string
	Registry      string
	DateAllocated string
	Prefixes      []string
	IPv4Count     int
	IPv6Count     int
}

// IPInfo contains IP to ASN mapping
type IPInfo struct {
	IP       string
	ASN      int
	ASName   string
	Prefix   string
	Country  string
	Registry string
}

// LookupIP finds ASN information for an IP
func (a *ASNClient) LookupIP(ctx context.Context, ip string) (*IPInfo, error) {
	// Use Team Cymru IP to ASN mapping service
	result := a.queryTeamCymru(ip)
	if result != nil {
		return result, nil
	}

	// Fallback to RIPEstat
	result, err := a.queryRIPEstat(ctx, ip)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// LookupASN gets detailed information about an ASN
func (a *ASNClient) LookupASN(ctx context.Context, asn int) (*ASNInfo, error) {
	asnStr := fmt.Sprintf("AS%d", asn)

	// Check cache
	if cached, exists := a.cache[asnStr]; exists {
		return cached, nil
	}

	// Query RIPEstat for ASN info
	info, err := a.queryASNInfo(ctx, asn)
	if err != nil {
		return nil, err
	}

	// Get prefixes
	prefixes, err := a.queryASNPrefixes(ctx, asn)
	if err == nil {
		info.Prefixes = prefixes
		info.IPv4Count = a.countIPv4Addresses(prefixes)
		info.IPv6Count = a.countIPv6Addresses(prefixes)
	}

	// Cache result
	a.cache[asnStr] = info

	a.logger.Info("ASN lookup completed",
		"asn", asn,
		"name", info.Name,
		"prefixes", len(info.Prefixes),
		"ipv4_count", info.IPv4Count)

	return info, nil
}

// GetASNPrefixes gets all IP prefixes for an ASN
func (a *ASNClient) GetASNPrefixes(ctx context.Context, asn int) ([]string, error) {
	return a.queryASNPrefixes(ctx, asn)
}

// ExpandASN expands an ASN to all its IP ranges
func (a *ASNClient) ExpandASN(ctx context.Context, asn int) ([]IPRange, error) {
	prefixes, err := a.GetASNPrefixes(ctx, asn)
	if err != nil {
		return nil, err
	}

	var ranges []IPRange
	for _, prefix := range prefixes {
		_, ipnet, err := net.ParseCIDR(prefix)
		if err != nil {
			continue
		}

		ranges = append(ranges, IPRange{
			CIDR:     prefix,
			StartIP:  ipnet.IP.String(),
			EndIP:    a.getLastIP(ipnet).String(),
			TotalIPs: a.countIPs(ipnet),
			IsIPv6:   ipnet.IP.To4() == nil,
		})
	}

	return ranges, nil
}

// IPRange represents an IP range
type IPRange struct {
	CIDR     string
	StartIP  string
	EndIP    string
	TotalIPs uint64
	IsIPv6   bool
}

// FindRelatedASNs finds ASNs related to an organization
func (a *ASNClient) FindRelatedASNs(ctx context.Context, org string) ([]int, error) {
	// Search for ASNs by organization name
	asns, err := a.searchASNsByOrg(ctx, org)
	if err != nil {
		return nil, err
	}

	return asns, nil
}

// queryTeamCymru queries Team Cymru DNS service
func (a *ASNClient) queryTeamCymru(ip string) *IPInfo {
	// Reverse IP for DNS query
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return nil
	}

	reversed := fmt.Sprintf("%s.%s.%s.%s.origin.asn.cymru.com",
		parts[3], parts[2], parts[1], parts[0])

	// Perform DNS TXT lookup
	records, err := net.LookupTXT(reversed)
	if err != nil || len(records) == 0 {
		return nil
	}

	// Parse response: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
	fields := strings.Split(records[0], "|")
	if len(fields) < 3 {
		return nil
	}

	asnStr := strings.TrimSpace(fields[0])
	asn, _ := strconv.Atoi(asnStr)

	return &IPInfo{
		IP:      ip,
		ASN:     asn,
		Prefix:  strings.TrimSpace(fields[1]),
		Country: strings.TrimSpace(fields[2]),
	}
}

// queryRIPEstat queries RIPEstat API
func (a *ASNClient) queryRIPEstat(ctx context.Context, ip string) (*IPInfo, error) {
	url := fmt.Sprintf("https://stat.ripe.net/data/prefix-overview/data.json?resource=%s", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			ASNs []struct {
				ASN    int    `json:"asn"`
				Holder string `json:"holder"`
			} `json:"asns"`
			Prefix string `json:"prefix"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Data.ASNs) == 0 {
		return nil, fmt.Errorf("no ASN found for IP %s", ip)
	}

	return &IPInfo{
		IP:     ip,
		ASN:    result.Data.ASNs[0].ASN,
		ASName: result.Data.ASNs[0].Holder,
		Prefix: result.Data.Prefix,
	}, nil
}

// queryASNInfo queries ASN information
func (a *ASNClient) queryASNInfo(ctx context.Context, asn int) (*ASNInfo, error) {
	url := fmt.Sprintf("https://stat.ripe.net/data/as-overview/data.json?resource=AS%d", asn)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			Holder      string `json:"holder"`
			Country     string `json:"country"`
			Announced   bool   `json:"announced"`
			Description string `json:"description"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &ASNInfo{
		ASN:          asn,
		Name:         result.Data.Holder,
		Organization: result.Data.Description,
		Country:      result.Data.Country,
	}, nil
}

// queryASNPrefixes queries prefixes announced by an ASN
func (a *ASNClient) queryASNPrefixes(ctx context.Context, asn int) ([]string, error) {
	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d", asn)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var prefixes []string
	for _, p := range result.Data.Prefixes {
		prefixes = append(prefixes, p.Prefix)
	}

	return prefixes, nil
}

// searchASNsByOrg searches for ASNs by organization name
func (a *ASNClient) searchASNsByOrg(ctx context.Context, org string) ([]int, error) {
	// Use BGPView API for searching
	url := fmt.Sprintf("https://api.bgpview.io/search?query_term=%s", org)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			ASNs []struct {
				ASN         int    `json:"asn"`
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"asns"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var asns []int
	for _, a := range result.Data.ASNs {
		asns = append(asns, a.ASN)
	}

	return asns, nil
}

// GetPeerASNs gets ASNs that peer with the given ASN
func (a *ASNClient) GetPeerASNs(ctx context.Context, asn int) ([]int, error) {
	url := fmt.Sprintf("https://api.bgpview.io/asn/%d/peers", asn)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			IPv4Peers []struct {
				ASN int `json:"asn"`
			} `json:"ipv4_peers"`
			IPv6Peers []struct {
				ASN int `json:"asn"`
			} `json:"ipv6_peers"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	peerMap := make(map[int]bool)
	for _, peer := range result.Data.IPv4Peers {
		peerMap[peer.ASN] = true
	}
	for _, peer := range result.Data.IPv6Peers {
		peerMap[peer.ASN] = true
	}

	var peers []int
	for asn := range peerMap {
		peers = append(peers, asn)
	}

	return peers, nil
}

// Helper functions

func (a *ASNClient) getLastIP(ipnet *net.IPNet) net.IP {
	// Get the last IP in the range
	ip := make(net.IP, len(ipnet.IP))
	copy(ip, ipnet.IP)

	for i := range ip {
		ip[i] |= ^ipnet.Mask[i]
	}

	return ip
}

func (a *ASNClient) countIPs(ipnet *net.IPNet) uint64 {
	ones, bits := ipnet.Mask.Size()
	if bits-ones > 63 {
		// Too large to count precisely
		return 0
	}
	return 1 << uint(bits-ones)
}

func (a *ASNClient) countIPv4Addresses(prefixes []string) int {
	total := 0
	for _, prefix := range prefixes {
		_, ipnet, err := net.ParseCIDR(prefix)
		if err != nil {
			continue
		}
		if ipnet.IP.To4() != nil {
			total += int(a.countIPs(ipnet))
		}
	}
	return total
}

func (a *ASNClient) countIPv6Addresses(prefixes []string) int {
	// For IPv6, just count the number of prefixes
	count := 0
	for _, prefix := range prefixes {
		_, ipnet, err := net.ParseCIDR(prefix)
		if err != nil {
			continue
		}
		if ipnet.IP.To4() == nil {
			count++
		}
	}
	return count
}

// GetASNHistory gets historical data for an ASN
func (a *ASNClient) GetASNHistory(ctx context.Context, asn int) ([]ASNEvent, error) {
	// This would query services that track ASN history
	// Placeholder implementation
	return []ASNEvent{}, nil
}

// ASNEvent represents a historical ASN event
type ASNEvent struct {
	Date        time.Time
	EventType   string
	Description string
	Prefixes    []string
}

// GetBGPRoutes gets current BGP routes for an ASN
func (a *ASNClient) GetBGPRoutes(ctx context.Context, asn int) ([]BGPRoute, error) {
	url := fmt.Sprintf("https://api.bgpview.io/asn/%d/prefixes", asn)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			IPv4Prefixes []struct {
				Prefix      string `json:"prefix"`
				Name        string `json:"name"`
				Description string `json:"description"`
				CountryCode string `json:"country_code"`
			} `json:"ipv4_prefixes"`
			IPv6Prefixes []struct {
				Prefix      string `json:"prefix"`
				Name        string `json:"name"`
				Description string `json:"description"`
				CountryCode string `json:"country_code"`
			} `json:"ipv6_prefixes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var routes []BGPRoute

	for _, p := range result.Data.IPv4Prefixes {
		routes = append(routes, BGPRoute{
			Prefix:      p.Prefix,
			Name:        p.Name,
			Description: p.Description,
			Country:     p.CountryCode,
			IsIPv6:      false,
		})
	}

	for _, p := range result.Data.IPv6Prefixes {
		routes = append(routes, BGPRoute{
			Prefix:      p.Prefix,
			Name:        p.Name,
			Description: p.Description,
			Country:     p.CountryCode,
			IsIPv6:      true,
		})
	}

	return routes, nil
}

// BGPRoute represents a BGP route
type BGPRoute struct {
	Prefix      string
	Name        string
	Description string
	Country     string
	IsIPv6      bool
}
