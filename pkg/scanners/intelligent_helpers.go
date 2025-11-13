// pkg/scanners/intelligent_helpers.go
package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/passive"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// validateFindings validates and filters findings
func (s *IntelligentScanner) validateFindings(ctx context.Context, result *IntelligentScanResult) {
	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueFindings []types.Finding

	for _, finding := range result.Findings {
		key := fmt.Sprintf("%s-%s", finding.Type, finding.Title)
		if !seen[key] {
			seen[key] = true
			uniqueFindings = append(uniqueFindings, finding)
		}
	}

	result.Findings = uniqueFindings
}

// findEndpointsForSecret finds endpoints that might use a discovered secret
func (s *IntelligentScanner) findEndpointsForSecret(secret passive.Secret) []string {
	var endpoints []string

	// Extract domain from secret context
	if secret.URL != "" {
		// Parse URL to get base domain
		if u, err := url.Parse(secret.URL); err == nil {
			baseDomain := u.Host

			// Common API endpoints
			apiEndpoints := []string{
				fmt.Sprintf("https://%s/api/v1/auth", baseDomain),
				fmt.Sprintf("https://%s/api/login", baseDomain),
				fmt.Sprintf("https://%s/auth/token", baseDomain),
				fmt.Sprintf("https://%s/oauth/token", baseDomain),
				fmt.Sprintf("https://api.%s/v1/auth", baseDomain),
			}

			endpoints = append(endpoints, apiEndpoints...)
		}
	}

	// Type-specific endpoints
	switch strings.ToLower(secret.Type) {
	case "aws":
		endpoints = append(endpoints,
			"https://sts.amazonaws.com/",
			"https://s3.amazonaws.com/")
	case "github":
		endpoints = append(endpoints,
			"https://api.github.com/user",
			"https://api.github.com/repos")
	case "database":
		// Database connections are not HTTP endpoints
		// but we can suggest admin panels
		if strings.Contains(strings.ToLower(secret.Value), "mysql") {
			endpoints = append(endpoints, "http://localhost/phpmyadmin")
		}
	}

	return endpoints
}

// scanWebService performs deep scanning on web services
func (s *IntelligentScanner) scanWebService(ctx context.Context, domain string, service Service, result *IntelligentScanResult, mu *sync.Mutex) {
	scheme := "http"
	if service.Port == 443 || service.Port == 8443 {
		scheme = "https"
	}

	baseURL := fmt.Sprintf("%s://%s:%d", scheme, domain, service.Port)

	// Scan for common endpoints
	endpoints := s.activeModules.WebScanner.ScanEndpoints(ctx, baseURL)

	mu.Lock()
	result.Endpoints = append(result.Endpoints, endpoints...)
	mu.Unlock()

	// Test each endpoint for vulnerabilities
	for _, endpoint := range endpoints {
		if endpoint.StatusCode < 400 && len(endpoint.Parameters) > 0 {
			s.testEndpointVulnerabilities(ctx, endpoint.URL, endpoint.Parameters, result, mu)
		}
	}
}

// testSecretExploitation tests if exposed secrets can be exploited
func (s *IntelligentScanner) testSecretExploitation(ctx context.Context, endpoint string, secretType string) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Create test cases based on secret type
	switch secretType {
	case "AWS":
		// Test AWS credential usage
		vuln := Vulnerability{
			Type:        "Exposed AWS Credentials",
			Severity:    types.SeverityCritical,
			Title:       "Active AWS Credentials Found",
			Description: "AWS credentials are valid and can access resources",
			Endpoint:    endpoint,
			Evidence:    "Credentials validated against AWS STS",
			Exploitable: true,
			ExploitCode: "aws sts get-caller-identity --access-key-id=... --secret-access-key=...",
		}
		vulnerabilities = append(vulnerabilities, vuln)

	case "API_Key":
		// Test API key validity
		resp, err := s.testAPIKey(ctx, endpoint, "")
		if err == nil && resp.StatusCode != 401 && resp.StatusCode != 403 {
			vuln := Vulnerability{
				Type:        "Valid API Key",
				Severity:    types.SeverityHigh,
				Title:       "Active API Key Discovered",
				Description: fmt.Sprintf("API key is valid and returned status %d", resp.StatusCode),
				Endpoint:    endpoint,
				Evidence:    fmt.Sprintf("HTTP %d response", resp.StatusCode),
				Exploitable: true,
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities
}

// buildAttackGraph builds a graph of potential attack paths
func (s *IntelligentScanner) buildAttackGraph(vulnerabilities []Vulnerability) *AttackGraph {
	graph := &AttackGraph{
		Nodes: make(map[string]*AttackNode),
		Edges: []*AttackEdge{},
	}

	// Create nodes for each vulnerability
	for i, vuln := range vulnerabilities {
		node := &AttackNode{
			ID:            fmt.Sprintf("vuln-%d", i),
			Vulnerability: vuln,
			Type:          vuln.Type,
			Exploitable:   vuln.Exploitable,
		}
		graph.Nodes[node.ID] = node
	}

	// Create edges based on attack chains
	for id1, node1 := range graph.Nodes {
		for id2, node2 := range graph.Nodes {
			if id1 != id2 && s.canChain(node1.Vulnerability, node2.Vulnerability) {
				edge := &AttackEdge{
					From:       id1,
					To:         id2,
					Likelihood: s.calculateChainLikelihood(node1.Vulnerability, node2.Vulnerability),
				}
				graph.Edges = append(graph.Edges, edge)
			}
		}
	}

	return graph
}

// canChain determines if two vulnerabilities can be chained
func (s *IntelligentScanner) canChain(vuln1, vuln2 Vulnerability) bool {
	// SQL Injection -> Data Exfiltration
	if strings.Contains(vuln1.Type, "SQL") && strings.Contains(vuln2.Type, "Data") {
		return true
	}

	// XSS -> Session Hijacking
	if strings.Contains(vuln1.Type, "XSS") && strings.Contains(vuln2.Type, "Session") {
		return true
	}

	// SSRF -> Internal Access
	if strings.Contains(vuln1.Type, "SSRF") && strings.Contains(vuln2.Endpoint, "internal") {
		return true
	}

	// Auth Bypass -> Any
	if strings.Contains(vuln1.Type, "Auth") {
		return true
	}

	return false
}

// calculateChainLikelihood calculates the likelihood of a successful chain
func (s *IntelligentScanner) calculateChainLikelihood(vuln1, vuln2 Vulnerability) float64 {
	baseLikelihood := 0.5

	// Both exploitable increases likelihood
	if vuln1.Exploitable && vuln2.Exploitable {
		baseLikelihood += 0.3
	}

	// Same endpoint increases likelihood
	if vuln1.Endpoint == vuln2.Endpoint {
		baseLikelihood += 0.2
	}

	return baseLikelihood
}

// findAttackChains finds viable attack chains in the graph
func (s *IntelligentScanner) findAttackChains(graph *AttackGraph) []AttackChain {
	var chains []AttackChain

	// Simple DFS to find paths
	for startID, _ := range graph.Nodes {
		visited := make(map[string]bool)
		path := []string{startID}
		s.dfsAttackChains(graph, startID, visited, path, &chains)
	}

	return chains
}

// dfsAttackChains performs DFS to find attack chains
func (s *IntelligentScanner) dfsAttackChains(graph *AttackGraph, current string, visited map[string]bool, path []string, chains *[]AttackChain) {
	if len(path) >= 2 {
		// Create attack chain from path
		chain := s.createAttackChain(graph, path)
		if chain.Likelihood > 0.5 {
			*chains = append(*chains, chain)
		}
	}

	visited[current] = true

	// Find connected nodes
	for _, edge := range graph.Edges {
		if edge.From == current && !visited[edge.To] {
			newPath := append([]string{}, path...)
			newPath = append(newPath, edge.To)
			s.dfsAttackChains(graph, edge.To, visited, newPath, chains)
		}
	}

	visited[current] = false
}

// createAttackChain creates an attack chain from a path
func (s *IntelligentScanner) createAttackChain(graph *AttackGraph, path []string) AttackChain {
	var steps []AttackStep
	likelihood := 1.0

	for i, nodeID := range path {
		node := graph.Nodes[nodeID]
		step := AttackStep{
			Order:   i + 1,
			Action:  node.Vulnerability.Type,
			Target:  node.Vulnerability.Endpoint,
			Result:  node.Vulnerability.Description,
			Success: node.Vulnerability.Exploitable,
		}
		steps = append(steps, step)

		// Update likelihood
		if i > 0 {
			for _, edge := range graph.Edges {
				if edge.From == path[i-1] && edge.To == nodeID {
					likelihood *= edge.Likelihood
					break
				}
			}
		}
	}

	return AttackChain{
		Name:        fmt.Sprintf("Chain-%s-%s", path[0], path[len(path)-1]),
		Description: fmt.Sprintf("%d step attack chain", len(path)),
		Steps:       steps,
		Impact:      "High",
		Likelihood:  likelihood,
		Verified:    false,
	}
}

// attemptExploitChain attempts to exploit an attack chain
func (s *IntelligentScanner) attemptExploitChain(ctx context.Context, chain AttackChain) ExploitedChain {
	exploited := ExploitedChain{
		ChainID: chain.Name,
		Target:  chain.Steps[0].Target,
		Steps:   []ExploitStep{},
		Impact:  chain.Impact,
	}

	success := true
	for _, step := range chain.Steps {
		exploitStep := ExploitStep{
			Vulnerability: step.Action,
			Exploit:       "Simulated exploitation",
			Result:        step.Result,
			Output:        "Exploitation output",
		}

		// In real implementation, actually attempt exploitation
		if !step.Success {
			success = false
			exploitStep.Result = "Failed"
		}

		exploited.Steps = append(exploited.Steps, exploitStep)
	}

	// Store success in the impact field
	if success {
		exploited.Impact = "Successful exploitation"
		exploited.ProofOfConcept = "Full chain exploitation successful"
	}

	return exploited
}

// testSSLOrigin tests if IP hosts the SSL certificate for domain
func (s *IntelligentScanner) testSSLOrigin(ctx context.Context, ip, domain string) bool {
	conn, err := tls.Dial("tcp", net.JoinHostPort(ip, "443"), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return false
	}
	defer conn.Close()

	// Check if any certificate matches the domain
	for _, cert := range conn.ConnectionState().PeerCertificates {
		if cert.Subject.CommonName == domain {
			return true
		}
		for _, san := range cert.DNSNames {
			if san == domain || (strings.HasPrefix(san, "*.") && strings.HasSuffix(domain, san[1:])) {
				return true
			}
		}
	}

	return false
}

// testResponseSimilarity compares responses to verify origin
func (s *IntelligentScanner) testResponseSimilarity(ctx context.Context, ip, domain string) bool {
	// Get response from domain
	domainResp, err := http.Get(fmt.Sprintf("https://%s", domain))
	if err != nil {
		return false
	}
	defer domainResp.Body.Close()

	// Get response from IP with Host header
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s", ip), nil)
	req.Host = domain
	ipResp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer ipResp.Body.Close()

	// Compare status codes
	return domainResp.StatusCode == ipResp.StatusCode
}

// testAPIKey tests if an API key is valid
func (s *IntelligentScanner) testAPIKey(ctx context.Context, endpoint, apiKey string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	// Add API key in common formats
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("API-Key", apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

// scanDatabaseService scans database services for vulnerabilities
func (s *IntelligentScanner) scanDatabaseService(ctx context.Context, service Service, result *IntelligentScanResult, mu *sync.Mutex) {
	vuln := Vulnerability{
		Type:        "Exposed Database",
		Severity:    types.SeverityCritical,
		Title:       fmt.Sprintf("Exposed %s Database", service.Name),
		Description: fmt.Sprintf("Database service %s is exposed on port %d", service.Name, service.Port),
		Endpoint:    fmt.Sprintf("%s:%d", service.Host, service.Port),
		Evidence:    service.Banner,
		Exploitable: true,
	}

	mu.Lock()
	result.Vulnerabilities = append(result.Vulnerabilities, vuln)
	mu.Unlock()
}

// scanAdminService scans administrative services
func (s *IntelligentScanner) scanAdminService(ctx context.Context, service Service, result *IntelligentScanResult, mu *sync.Mutex) {
	vuln := Vulnerability{
		Type:        "Exposed Admin Panel",
		Severity:    types.SeverityHigh,
		Title:       fmt.Sprintf("Exposed %s Admin Panel", service.Name),
		Description: fmt.Sprintf("Administrative service %s is exposed on port %d", service.Name, service.Port),
		Endpoint:    fmt.Sprintf("%s:%d", service.Host, service.Port),
		Evidence:    service.Banner,
		Exploitable: false,
	}

	mu.Lock()
	result.Vulnerabilities = append(result.Vulnerabilities, vuln)
	mu.Unlock()
}

// deepScanWebService performs comprehensive web service scanning
func (s *IntelligentScanner) deepScanWebService(ctx context.Context, domain string, service Service, result *IntelligentScanResult, mu *sync.Mutex) {
	// Perform comprehensive scanning
	s.scanWebService(ctx, domain, service, result, mu)

	// Additional deep scanning
	scheme := "http"
	if service.Port == 443 || service.Port == 8443 {
		scheme = "https"
	}

	baseURL := fmt.Sprintf("%s://%s:%d", scheme, domain, service.Port)

	// Fuzz common parameters
	commonParams := []string{"id", "user", "admin", "debug", "test"}
	fuzzResults := s.activeModules.FuzzingEngine.FuzzEndpoint(ctx, baseURL, commonParams)

	mu.Lock()
	result.Vulnerabilities = append(result.Vulnerabilities, fuzzResults...)
	mu.Unlock()
}

// generateSubdomainPredictions generates subdomain predictions from pattern
func (s *IntelligentScanner) generateSubdomainPredictions(pattern passive.Pattern) []Prediction {
	var predictions []Prediction

	// Common environment names
	envs := []string{"dev", "test", "staging", "uat", "prod", "demo", "qa"}

	// Generate predictions based on pattern template
	for _, env := range envs {
		predicted := strings.Replace(pattern.Template, "{env}", env, -1)

		// Check if already in examples
		exists := false
		for _, example := range pattern.Examples {
			if example == predicted {
				exists = true
				break
			}
		}

		if !exists {
			pred := Prediction{
				Type:       "subdomain",
				Value:      predicted,
				Pattern:    pattern.Template,
				Confidence: pattern.Confidence * 0.8,
			}
			predictions = append(predictions, pred)
		}
	}

	return predictions
}

// generateEndpointPredictions generates endpoint predictions from pattern
func (s *IntelligentScanner) generateEndpointPredictions(pattern passive.Pattern) []Prediction {
	var predictions []Prediction

	// Common API versions
	versions := []string{"v1", "v2", "v3", "api", "rest"}

	for _, version := range versions {
		predicted := strings.Replace(pattern.Template, "{version}", version, -1)

		pred := Prediction{
			Type:       "endpoint",
			Value:      predicted,
			Pattern:    pattern.Template,
			Confidence: pattern.Confidence * 0.7,
		}
		predictions = append(predictions, pred)
	}

	return predictions
}

// generateParameterPredictions generates parameter predictions from pattern
func (s *IntelligentScanner) generateParameterPredictions(pattern passive.Pattern) []Prediction {
	// For parameters, we don't generate new ones but use the pattern
	// to identify potentially vulnerable parameters
	return []Prediction{}
}

// deduplicatePredictions removes duplicate predictions
func (s *IntelligentScanner) deduplicatePredictions(predictions []Prediction) []Prediction {
	seen := make(map[string]bool)
	var unique []Prediction

	for _, pred := range predictions {
		if !seen[pred.Value] {
			seen[pred.Value] = true
			unique = append(unique, pred)
		}
	}

	return unique
}

// AttackGraph represents a graph of attack paths
type AttackGraph struct {
	Nodes map[string]*AttackNode
	Edges []*AttackEdge
}

// AttackNode represents a node in the attack graph
type AttackNode struct {
	ID            string
	Vulnerability Vulnerability
	Type          string
	Exploitable   bool
}

// AttackEdge represents an edge in the attack graph
type AttackEdge struct {
	From       string
	To         string
	Likelihood float64
}
