// pkg/scanners/interfaces.go
package scanner

import (
	"context"
	"net/http"
)

// PortScanner interface for port scanning
type PortScanner interface {
	ScanPorts(ctx context.Context, host string) []Service
	ScanAllPorts(ctx context.Context, host string) []Service
}

// WebScanner interface for web scanning
type WebScanner interface {
	TestEndpoint(ctx context.Context, url string) (*http.Response, error)
	ScanEndpoints(ctx context.Context, baseURL string) []Endpoint
}

// VulnerabilityScanner interface for vulnerability scanning
type VulnerabilityScanner interface {
	TestSQLInjection(ctx context.Context, url string, params []string) *Vulnerability
	TestXSS(ctx context.Context, url string, params []string) *Vulnerability
	TestSSRF(ctx context.Context, url string, params []string) *Vulnerability
}

// ExploitEngine interface for exploitation
type ExploitEngine interface {
	ExploitVulnerability(ctx context.Context, vuln Vulnerability) (*ExploitResult, error)
	GeneratePayload(vulnType string) string
}

// FuzzingEngine interface for fuzzing
type FuzzingEngine interface {
	FuzzEndpoint(ctx context.Context, url string, params []string) []Vulnerability
	GenerateFuzzPayloads(paramType string) []string
}

// AuthenticationTester interface for auth testing
type AuthenticationTester interface {
	TestAuthBypass(ctx context.Context, url string) *Vulnerability
	TestWeakCredentials(ctx context.Context, url string) []Credential
}

// ExploitResult represents the result of an exploitation attempt
type ExploitResult struct {
	Success bool
	Output  string
	Impact  string
}

// Credential represents discovered credentials
type Credential struct {
	Username string
	Password string
	Valid    bool
}
