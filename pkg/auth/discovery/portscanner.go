// pkg/auth/discovery/portscanner.go
package discovery

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

type PortScanner struct {
	logger     *logger.Logger
	timeout    time.Duration
	maxWorkers int
}

type PortDefinition struct {
	Port     int
	Protocol string
	SSL      bool
}

type PortScanResult struct {
	Host     string
	Port     int
	Protocol string
	SSL      bool
	Open     bool
	Banner   string
	Error    error
}

func NewPortScanner(logger *logger.Logger) *PortScanner {
	return &PortScanner{
		logger:     logger,
		timeout:    3 * time.Second,
		maxWorkers: 50,
	}
}

func (p *PortScanner) ScanPorts(ctx context.Context, target *TargetInfo, ports []PortDefinition) []PortScanResult {
	var results []PortScanResult
	var mu sync.Mutex

	// Create work channel
	work := make(chan PortDefinition, len(ports))
	for _, port := range ports {
		work <- port
	}
	close(work)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < p.maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for port := range work {
				select {
				case <-ctx.Done():
					return
				default:
					result := p.scanSinglePort(target.Host, port)
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	// Filter only open ports
	var openPorts []PortScanResult
	for _, result := range results {
		if result.Open {
			openPorts = append(openPorts, result)
			p.logger.Debugw("Found open auth port",
				"host", result.Host,
				"port", result.Port,
				"protocol", result.Protocol)
		}
	}

	return openPorts
}

func (p *PortScanner) scanSinglePort(host string, port PortDefinition) PortScanResult {
	result := PortScanResult{
		Host:     host,
		Port:     port.Port,
		Protocol: port.Protocol,
		SSL:      port.SSL,
	}

	// Use net.JoinHostPort for proper IPv6 support
	address := net.JoinHostPort(host, strconv.Itoa(port.Port))
	conn, err := net.DialTimeout("tcp", address, p.timeout)
	if err != nil {
		result.Error = err
		return result
	}
	defer conn.Close()

	result.Open = true

	// Try to grab banner
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1024)
	n, _ := conn.Read(buffer)
	if n > 0 {
		result.Banner = string(buffer[:n])
	}

	return result
}
