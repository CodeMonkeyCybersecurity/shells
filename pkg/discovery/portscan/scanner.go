package portscan

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

// PortScanner performs TCP port scanning
type PortScanner struct {
	timeout     time.Duration
	concurrency int
	logger      *logger.Logger
	commonPorts []int
	webPorts    []int
}

// ScanResult represents a port scan result
type ScanResult struct {
	Host    string
	Port    int
	Open    bool
	Service string
	Banner  string
}

// HostScanResult represents scan results for a host
type HostScanResult struct {
	Host      string
	OpenPorts []ScanResult
	ScanTime  time.Duration
}

// NewPortScanner creates a new port scanner
func NewPortScanner(logger *logger.Logger) *PortScanner {
	return &PortScanner{
		timeout:     3 * time.Second,
		concurrency: 100,
		logger:      logger,
		commonPorts: getCommonPorts(),
		webPorts:    getWebPorts(),
	}
}

// ScanHost scans common ports on a single host
func (p *PortScanner) ScanHost(ctx context.Context, host string) (*HostScanResult, error) {
	start := time.Now()
	result := &HostScanResult{
		Host:      host,
		OpenPorts: []ScanResult{},
	}

	// Resolve hostname if needed
	ips, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve host %s: %w", host, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for %s", host)
	}

	// Use first IP
	targetIP := ips[0]

	// Channel for results
	resultChan := make(chan ScanResult, len(p.commonPorts))

	// Semaphore for concurrency control
	sem := make(chan struct{}, p.concurrency)
	var wg sync.WaitGroup

	// Scan each port
	for _, port := range p.commonPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			if p.isPortOpen(ctx, targetIP, port) {
				scanResult := ScanResult{
					Host:    host,
					Port:    port,
					Open:    true,
					Service: p.guessService(port),
				}

				// Try to grab banner for some services
				if p.shouldGrabBanner(port) {
					scanResult.Banner = p.grabBanner(targetIP, port)
				}

				resultChan <- scanResult
			}
		}(port)
	}

	// Wait for all scans to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for res := range resultChan {
		result.OpenPorts = append(result.OpenPorts, res)
	}

	result.ScanTime = time.Since(start)

	p.logger.Info("Port scan completed",
		"host", host,
		"open_ports", len(result.OpenPorts),
		"scan_time", result.ScanTime)

	return result, nil
}

// ScanHosts scans multiple hosts
func (p *PortScanner) ScanHosts(ctx context.Context, hosts []string) ([]*HostScanResult, error) {
	var results []*HostScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrent host scans
	hostSem := make(chan struct{}, 5)

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case hostSem <- struct{}{}:
				defer func() { <-hostSem }()
			}

			result, err := p.ScanHost(ctx, h)
			if err != nil {
				p.logger.Error("Failed to scan host", "host", h, "error", err)
				return
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(host)
	}

	wg.Wait()
	return results, nil
}

// QuickScan performs a quick scan of web ports only
func (p *PortScanner) QuickScan(ctx context.Context, host string) (*HostScanResult, error) {
	// Temporarily use web ports only
	oldPorts := p.commonPorts
	p.commonPorts = p.webPorts
	defer func() { p.commonPorts = oldPorts }()

	return p.ScanHost(ctx, host)
}

// isPortOpen checks if a port is open
func (p *PortScanner) isPortOpen(ctx context.Context, host string, port int) bool {
	// Use net.JoinHostPort for proper IPv6 support
	target := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := net.Dialer{
		Timeout: p.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// grabBanner attempts to grab a service banner
func (p *PortScanner) grabBanner(host string, port int) string {
	// Use net.JoinHostPort for proper IPv6 support
	target := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", target, p.timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Try to read banner
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		// Some services require sending data first
		if p.requiresHandshake(port) {
			// Send a basic request
			conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
			n, err = conn.Read(buffer)
			if err != nil {
				return ""
			}
		} else {
			return ""
		}
	}

	banner := string(buffer[:n])
	// Clean up banner
	if len(banner) > 100 {
		banner = banner[:100] + "..."
	}

	return banner
}

// shouldGrabBanner determines if we should try to grab a banner
func (p *PortScanner) shouldGrabBanner(port int) bool {
	bannerPorts := map[int]bool{
		21:   true, // FTP
		22:   true, // SSH
		23:   true, // Telnet
		25:   true, // SMTP
		80:   true, // HTTP
		110:  true, // POP3
		143:  true, // IMAP
		443:  true, // HTTPS
		3306: true, // MySQL
		5432: true, // PostgreSQL
		6379: true, // Redis
		8080: true, // HTTP Alt
		8443: true, // HTTPS Alt
	}

	return bannerPorts[port]
}

// requiresHandshake checks if a service requires sending data first
func (p *PortScanner) requiresHandshake(port int) bool {
	handshakePorts := map[int]bool{
		80:   true,
		443:  true,
		8080: true,
		8443: true,
	}

	return handshakePorts[port]
}

// guessService attempts to guess the service based on port number
func (p *PortScanner) guessService(port int) string {
	services := map[int]string{
		20:    "ftp-data",
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		111:   "rpcbind",
		135:   "msrpc",
		139:   "netbios-ssn",
		143:   "imap",
		443:   "https",
		445:   "microsoft-ds",
		993:   "imaps",
		995:   "pop3s",
		1723:  "pptp",
		3306:  "mysql",
		3389:  "ms-wbt-server",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http-proxy",
		8443:  "https-alt",
		27017: "mongodb",
	}

	if service, ok := services[port]; ok {
		return service
	}

	return fmt.Sprintf("unknown-%d", port)
}

// getCommonPorts returns a list of commonly used ports
func getCommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
		993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
		// Additional common ports
		8, 9, 13, 17, 19, 37, 42, 49, 67, 68, 69, 79, 88, 113, 119,
		123, 137, 138, 161, 162, 177, 179, 194, 264, 318, 381, 383,
		389, 427, 464, 465, 497, 500, 512, 513, 514, 515, 520, 521,
		540, 548, 554, 587, 593, 623, 625, 631, 636, 646, 691, 873,
		902, 989, 990, 992, 1025, 1026, 1027, 1028, 1029, 1080, 1110,
		1194, 1214, 1220, 1234, 1241, 1311, 1337, 1352, 1433, 1434,
		1521, 1720, 1812, 1813, 1900, 2000, 2049, 2082, 2083, 2086,
		2087, 2095, 2096, 2121, 2181, 2222, 2375, 2376, 2483, 2484,
		3000, 3001, 3128, 3260, 3268, 3269, 3283, 3333, 3456, 3690,
		3703, 3784, 3785, 4000, 4001, 4022, 4321, 4333, 4343, 4443,
		4444, 4445, 4567, 4662, 4711, 4712, 4899, 4900, 5000, 5001,
		5002, 5003, 5004, 5005, 5050, 5060, 5061, 5190, 5222, 5223,
		5269, 5280, 5357, 5400, 5500, 5555, 5556, 5631, 5632, 5666,
		5672, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811,
		5984, 5985, 5986, 6000, 6001, 6002, 6003, 6004, 6005, 6346,
		6347, 6646, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667,
		6668, 6669, 6679, 6697, 6699, 6779, 6788, 6789, 6881, 6888,
		6889, 6969, 7000, 7001, 7002, 7070, 7071, 7218, 7474, 7548,
		7625, 7777, 7778, 7779, 8000, 8001, 8008, 8009, 8010, 8020,
		8021, 8022, 8025, 8026, 8028, 8029, 8030, 8031, 8081, 8082,
		8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8099, 8123,
		8181, 8200, 8222, 8333, 8383, 8384, 8400, 8402, 8500, 8600,
		8649, 8651, 8652, 8654, 8701, 8800, 8873, 8880, 8888, 8899,
		8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9043,
		9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102,
		9103, 9110, 9111, 9200, 9207, 9220, 9290, 9300, 9415, 9418,
		9443, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595,
		9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943,
		9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004,
		10009, 10010, 10012, 10024, 10025, 10082, 10162, 10180, 10215,
		10243, 10566, 10616, 10617, 10621, 10623, 10626, 10628, 10629,
		10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456,
		13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002,
		15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018,
		16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988,
		19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005,
		20031, 20221, 20222, 20828, 21571, 22222, 22939, 23023, 23502,
		24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355,
		27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768,
		32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777,
		32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354,
		33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511,
		42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153,
		49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163,
		49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002,
		50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493,
		52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555,
		55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532,
		61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389,
	}
}

// getWebPorts returns common web service ports
func getWebPorts() []int {
	return []int{
		80, 443, 8080, 8443, 8000, 8001, 8008, 8088, 8888,
		3000, 3001, 4000, 4443, 5000, 5001, 7000, 7001,
		9000, 9001, 9090, 9443, 10000, 10443,
	}
}

// ScanIPRange scans a range of IPs
func (p *PortScanner) ScanIPRange(ctx context.Context, startIP, endIP string) ([]*HostScanResult, error) {
	start := net.ParseIP(startIP)
	end := net.ParseIP(endIP)

	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid IP range")
	}

	var ips []string
	for ip := start; !ip.Equal(end); incrementIP(ip) {
		ips = append(ips, ip.String())
	}
	ips = append(ips, end.String())

	return p.ScanHosts(ctx, ips)
}

// incrementIP increments an IP address
func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}
