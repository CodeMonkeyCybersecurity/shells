// pkg/scanner/intelligent.go
package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/passive"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// IntelligentScanner uses passive intelligence to guide active scanning
type IntelligentScanner struct {
	logger         *logger.Logger
	passiveModules passive.PassiveModules
	activeModules  ActiveModules
	correlator     *correlation.Engine
	config         *IntelligentScanConfig
}

// IntelligentScanConfig contains configuration for intelligent scanning
type IntelligentScanConfig struct {
	// Scan targeting
	PrioritizeBypassedOrigins bool
	ScanDeletedEndpoints      bool
	TestPredictedEndpoints    bool
	VerifySecurityChanges     bool

	// Performance
	MaxConcurrency   int
	TimeoutPerTarget time.Duration
	RetryFailedScans bool

	// Intelligence thresholds
	MinConfidenceForScan   float64
	MinSeverityForPriority types.Severity

	// Scan depth
	DeepScanHighValue bool
	ChainExploits     bool
}

// ActiveModules contains all active scanning modules
type ActiveModules struct {
	PortScanner   PortScanner
	WebScanner    WebScanner
	VulnScanner   VulnerabilityScanner
	ExploitEngine ExploitEngine
	FuzzingEngine FuzzingEngine
	AuthTester    AuthenticationTester
}

// IntelligentScanResult contains results from intelligent scanning
type IntelligentScanResult struct {
	Target    string
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration

	// Discovered assets
	Assets    []Asset
	Services  []Service
	Endpoints []Endpoint

	// Findings
	Findings        []types.Finding
	Vulnerabilities []Vulnerability
	AttackChains    []AttackChain

	// Intelligence-driven results
	BypassedOrigins      []BypassedOrigin
	ResurrectedEndpoints []ResurrectedEndpoint
	ExploitedChains      []ExploitedChain

	// Metrics
	IntelligenceHits int
	FalsePositives   int
	TruePositives    int
}

// Asset represents a discovered asset
type Asset struct {
	Type       string // domain, subdomain, ip, service
	Value      string
	Confidence float64
	Source     string
	Metadata   map[string]interface{}
}

// Service represents a discovered service
type Service struct {
	Host        string
	Port        int
	Protocol    string
	Name        string
	Version     string
	Banner      string
	Fingerprint map[string]string
}

// Endpoint represents a web endpoint
type Endpoint struct {
	URL         string
	Method      string
	Parameters  []string
	StatusCode  int
	Title       string
	Technology  []string
	Interesting bool
}

// Vulnerability represents a confirmed vulnerability
type Vulnerability struct {
	Type        string
	Severity    types.Severity
	Title       string
	Description string
	Endpoint    string
	Evidence    string
	Exploitable bool
	ExploitCode string
}

// AttackChain represents a multi-step attack path
type AttackChain struct {
	Name        string
	Description string
	Steps       []AttackStep
	Impact      string
	Likelihood  float64
	Verified    bool
}

// AttackStep represents a single step in an attack chain
type AttackStep struct {
	Order   int
	Action  string
	Target  string
	Result  string
	Success bool
}

// BypassedOrigin represents a successfully bypassed protection
type BypassedOrigin struct {
	Protection string // CloudFlare, Akamai, etc
	OriginIP   string
	Method     string
	Evidence   []string
	Verified   bool
}

// ResurrectedEndpoint represents a deleted endpoint that still exists
type ResurrectedEndpoint struct {
	URL             string
	OriginalStatus  int
	CurrentStatus   int
	Parameters      []string
	StillFunctional bool
	LastSeen        time.Time
}

// ExploitedChain represents a successfully exploited attack chain
type ExploitedChain struct {
	ChainID        string
	Target         string
	Steps          []ExploitStep
	Impact         string
	ProofOfConcept string
}

// ExploitStep represents a step in an exploitation chain
type ExploitStep struct {
	Vulnerability string
	Exploit       string
	Result        string
	Output        string
}

// NewIntelligentScanner creates a new intelligent scanner
func NewIntelligentScanner(logger *logger.Logger, passiveModules passive.PassiveModules, activeModules ActiveModules) *IntelligentScanner {
	return &IntelligentScanner{
		logger:         logger,
		passiveModules: passiveModules,
		activeModules:  activeModules,
		config: &IntelligentScanConfig{
			PrioritizeBypassedOrigins: true,
			ScanDeletedEndpoints:      true,
			TestPredictedEndpoints:    true,
			VerifySecurityChanges:     true,
			MaxConcurrency:            10,
			TimeoutPerTarget:          30 * time.Minute,
			MinConfidenceForScan:      0.7,
			MinSeverityForPriority:    types.SeverityMedium,
			DeepScanHighValue:         true,
			ChainExploits:             true,
		},
	}
}

// ScanWithIntelligence performs intelligent scanning based on passive intel
func (s *IntelligentScanner) ScanWithIntelligence(ctx context.Context, target string) (*IntelligentScanResult, error) {
	s.logger.Info("Starting intelligent scan", "target", target)

	result := &IntelligentScanResult{
		Target:    target,
		StartTime: time.Now(),
		Assets:    []Asset{},
		Findings:  []types.Finding{},
	}

	// Phase 1: Gather passive intelligence
	intel, err := s.gatherPassiveIntelligence(ctx, target)
	if err != nil {
		s.logger.Error("Passive intelligence gathering failed", "error", err)
		// Continue with limited intelligence
	}

	// Phase 2: Correlate and prioritize targets
	scanTargets := s.generateScanTargets(intel)
	s.logger.Info("Generated scan targets", "count", len(scanTargets))

	// Phase 3: Execute intelligent active scanning
	s.executeIntelligentScans(ctx, scanTargets, result)

	// Phase 4: Exploit discovered vulnerabilities
	if s.config.ChainExploits {
		s.exploitVulnerabilities(ctx, result)
	}

	// Phase 5: Verify and validate findings
	s.validateFindings(ctx, result)

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Calculate metrics
	s.calculateMetrics(result)

	s.logger.Info("Intelligent scan completed",
		"duration", result.Duration,
		"findings", len(result.Findings),
		"intelligence_hits", result.IntelligenceHits)

	return result, nil
}

// ScanWithContext allows passing pre-gathered intelligence
func (s *IntelligentScanner) ScanWithContext(ctx context.Context, target string, intel *passive.PassiveIntel) (*IntelligentScanResult, error) {
	s.logger.Info("Starting contextual intelligent scan", "target", target)

	result := &IntelligentScanResult{
		Target:    target,
		StartTime: time.Now(),
	}

	// Use provided intelligence
	scanTargets := s.generateScanTargets(intel)

	// Execute scans
	s.executeIntelligentScans(ctx, scanTargets, result)

	// Exploit if configured
	if s.config.ChainExploits {
		s.exploitVulnerabilities(ctx, result)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	return result, nil
}

// gatherPassiveIntelligence collects all passive intelligence
func (s *IntelligentScanner) gatherPassiveIntelligence(ctx context.Context, target string) (*passive.PassiveIntel, error) {
	intel := &passive.PassiveIntel{
		Target:                target,
		Timestamp:             time.Now(),
		CloudFlareOrigins:     []passive.OriginCandidate{},
		ArchivedEndpoints:     []passive.ArchivedEndpoint{},
		CertificateSubdomains: []string{},
		TechStack:             make(map[string]passive.TechInfo),
		SecurityTimeline:      []passive.SecurityEvent{},
		DiscoveredSecrets:     []passive.Secret{},
		NamingPatterns:        []passive.Pattern{},
	}

	// Gather from each module in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Certificate intelligence
	wg.Add(1)
	go func() {
		defer wg.Done()

		certs, err := s.passiveModules.Certificate.DiscoverAllCertificates(ctx, target)
		if err != nil {
			s.logger.Error("Certificate discovery failed", "error", err)
			return
		}

		mu.Lock()
		for _, cert := range certs {
			intel.CertificateSubdomains = append(intel.CertificateSubdomains, cert.SANs...)
		}

		// Extract naming patterns
		patterns := s.passiveModules.Certificate.IdentifyNamingPatterns(convertCertificates(certs))
		intel.NamingPatterns = append(intel.NamingPatterns, patterns...)
		mu.Unlock()
	}()

	// Archive intelligence
	wg.Add(1)
	go func() {
		defer wg.Done()

		archiveFindings, err := s.passiveModules.Archive.ExtractIntelligence(target)
		if err != nil {
			s.logger.Error("Archive intelligence failed", "error", err)
			return
		}

		mu.Lock()
		intel.ArchivedEndpoints = archiveFindings.DeletedEndpoints
		intel.DiscoveredSecrets = append(intel.DiscoveredSecrets, archiveFindings.ExposedSecrets...)

		// Add to security timeline
		for _, change := range archiveFindings.TechStackChanges {
			event := passive.SecurityEvent{
				Type:        "tech_change",
				Description: fmt.Sprintf("Technology changed from %s to %s", change.OldTech, change.NewTech),
				Timestamp:   change.Timestamp,
				Severity:    "INFO",
				Source:      passive.SourceWebArchive,
			}
			intel.SecurityTimeline = append(intel.SecurityTimeline, event)
		}
		mu.Unlock()
	}()

	// CloudFlare bypass intelligence
	wg.Add(1)
	go func() {
		defer wg.Done()

		isCloudFlare, _ := s.passiveModules.CloudFlare.DetectCloudFlare(target)
		if isCloudFlare {
			origins, err := s.passiveModules.CloudFlare.FindOriginIP(target)
			if err != nil {
				s.logger.Error("CloudFlare bypass failed", "error", err)
				return
			}

			mu.Lock()
			intel.CloudFlareOrigins = origins
			mu.Unlock()
		}
	}()

	// Email security intelligence
	wg.Add(1)
	go func() {
		defer wg.Done()

		emailFindings, err := s.passiveModules.EmailSec.AnalyzeDomain(ctx, target)
		if err != nil {
			s.logger.Error("Email security analysis failed", "error", err)
			return
		}

		mu.Lock()
		// Add security events from email findings
		for _, issue := range emailFindings.Issues {
			event := passive.SecurityEvent{
				Type:        "email_security",
				Description: issue.Description,
				Timestamp:   time.Now(),
				Severity:    string(issue.Severity),
				Source:      passive.SourceDNS,
				Evidence:    issue.Evidence,
			}
			intel.SecurityTimeline = append(intel.SecurityTimeline, event)
		}
		mu.Unlock()
	}()

	// Code repository intelligence
	wg.Add(1)
	go func() {
		defer wg.Done()

		codeResults, err := s.passiveModules.CodeRepo.SearchAllPlatforms(ctx, target)
		if err != nil {
			s.logger.Error("Code repository search failed", "error", err)
			return
		}

		mu.Lock()
		for _, result := range codeResults {
			// Extract secrets from code
			if result.Type == "secret" {
				secret := passive.Secret{
					Type:     result.SecretType,
					Value:    result.SecretValue,
					Source:   result.Platform,
					URL:      result.URL,
					Severity: string(result.Severity),
				}
				intel.DiscoveredSecrets = append(intel.DiscoveredSecrets, secret)
			}
		}
		mu.Unlock()
	}()

	wg.Wait()

	return intel, nil
}

// generateScanTargets creates prioritized scan targets from intelligence
func (s *IntelligentScanner) generateScanTargets(intel *passive.PassiveIntel) []ScanTarget {
	var targets []ScanTarget

	// CloudFlare bypassed origins (highest priority)
	if s.config.PrioritizeBypassedOrigins {
		for _, origin := range intel.CloudFlareOrigins {
			if origin.Confidence >= s.config.MinConfidenceForScan {
				target := ScanTarget{
					Type:       "origin_ip",
					Value:      origin.IP,
					Priority:   10,
					Confidence: origin.Confidence,
					Context: map[string]interface{}{
						"domain":    origin.Domain,
						"method":    origin.Method,
						"evidence":  origin.Evidence,
						"validated": origin.Validated,
					},
				}
				targets = append(targets, target)
			}
		}
	}

	// Deleted endpoints that might still exist
	if s.config.ScanDeletedEndpoints {
		for _, endpoint := range intel.ArchivedEndpoints {
			target := ScanTarget{
				Type:       "endpoint",
				Value:      endpoint.URL,
				Priority:   8,
				Confidence: 0.6,
				Context: map[string]interface{}{
					"parameters":   endpoint.Parameters,
					"last_seen":    endpoint.LastSeen,
					"technologies": endpoint.Technologies,
					"still_exists": endpoint.StillExists,
				},
			}

			// Higher priority if it had interesting parameters
			if len(endpoint.Parameters) > 3 || containsSensitiveParam(endpoint.Parameters) {
				target.Priority = 9
			}

			targets = append(targets, target)
		}
	}

	// Certificate subdomains
	for _, subdomain := range intel.CertificateSubdomains {
		target := ScanTarget{
			Type:       "subdomain",
			Value:      subdomain,
			Priority:   6,
			Confidence: 0.9,
			Context: map[string]interface{}{
				"source": "certificate",
			},
		}

		// Higher priority for interesting subdomains
		if isInterestingSubdomain(subdomain) {
			target.Priority = 7
		}

		targets = append(targets, target)
	}

	// Predicted endpoints from patterns
	if s.config.TestPredictedEndpoints {
		predictions := s.generatePredictions(intel.NamingPatterns)
		for _, pred := range predictions {
			target := ScanTarget{
				Type:       "predicted",
				Value:      pred.Value,
				Priority:   5,
				Confidence: pred.Confidence,
				Context: map[string]interface{}{
					"pattern": pred.Pattern,
					"type":    pred.Type,
				},
			}
			targets = append(targets, target)
		}
	}

	// Exposed secrets and their associated endpoints
	for _, secret := range intel.DiscoveredSecrets {
		// Convert string severity to types.Severity for comparison
		secretSeverity := types.SeverityMedium
		switch strings.ToLower(secret.Severity) {
		case "critical":
			secretSeverity = types.SeverityCritical
		case "high":
			secretSeverity = types.SeverityHigh
		case "low":
			secretSeverity = types.SeverityLow
		}

		if secretSeverity >= s.config.MinSeverityForPriority {
			// Try to find associated endpoints
			endpoints := s.findEndpointsForSecret(secret)
			for _, endpoint := range endpoints {
				target := ScanTarget{
					Type:       "secret_endpoint",
					Value:      endpoint,
					Priority:   9,
					Confidence: 0.8,
					Context: map[string]interface{}{
						"secret_type": secret.Type,
						"severity":    secret.Severity,
					},
				}
				targets = append(targets, target)
			}
		}
	}

	// Sort by priority
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Priority > targets[j].Priority
	})

	return targets
}

// executeIntelligentScans performs targeted scanning based on intelligence
func (s *IntelligentScanner) executeIntelligentScans(ctx context.Context, targets []ScanTarget, result *IntelligentScanResult) {
	// Create worker pool
	sem := make(chan struct{}, s.config.MaxConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, target := range targets {
		wg.Add(1)
		go func(t ScanTarget) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			// Create target-specific context with timeout
			scanCtx, cancel := context.WithTimeout(ctx, s.config.TimeoutPerTarget)
			defer cancel()

			// Execute appropriate scan based on target type
			switch t.Type {
			case "origin_ip":
				s.scanOriginIP(scanCtx, t, result, &mu)

			case "endpoint":
				s.scanEndpoint(scanCtx, t, result, &mu)

			case "subdomain":
				s.scanSubdomain(scanCtx, t, result, &mu)

			case "predicted":
				s.scanPredicted(scanCtx, t, result, &mu)

			case "secret_endpoint":
				s.scanSecretEndpoint(scanCtx, t, result, &mu)
			}
		}(target)
	}

	wg.Wait()
}

// scanOriginIP scans a potential origin IP behind CDN
func (s *IntelligentScanner) scanOriginIP(ctx context.Context, target ScanTarget, result *IntelligentScanResult, mu *sync.Mutex) {
	ip := target.Value
	domain := target.Context["domain"].(string)

	s.logger.Info("Scanning potential origin IP", "ip", ip, "domain", domain)

	// Verify it's actually the origin
	verified := s.verifyOrigin(ctx, ip, domain)

	if verified {
		mu.Lock()
		result.BypassedOrigins = append(result.BypassedOrigins, BypassedOrigin{
			Protection: "CloudFlare",
			OriginIP:   ip,
			Method:     target.Context["method"].(string),
			Evidence:   target.Context["evidence"].([]string),
			Verified:   true,
		})
		result.IntelligenceHits++
		mu.Unlock()

		// Deep scan the origin
		if s.config.DeepScanHighValue {
			s.deepScanTarget(ctx, ip, domain, result, mu)
		}
	}
}

// scanEndpoint scans a potentially deleted endpoint
func (s *IntelligentScanner) scanEndpoint(ctx context.Context, target ScanTarget, result *IntelligentScanResult, mu *sync.Mutex) {
	endpoint := target.Value
	params := target.Context["parameters"].([]string)

	s.logger.Debug("Scanning potentially deleted endpoint", "url", endpoint)

	// Test if endpoint still exists
	exists, status := s.testEndpointExists(ctx, endpoint)

	if exists {
		mu.Lock()
		result.ResurrectedEndpoints = append(result.ResurrectedEndpoints, ResurrectedEndpoint{
			URL:             endpoint,
			OriginalStatus:  200, // From archive
			CurrentStatus:   status,
			Parameters:      params,
			StillFunctional: status < 400,
			LastSeen:        target.Context["last_seen"].(time.Time),
		})

		if status < 400 {
			result.IntelligenceHits++

			// Test for vulnerabilities with known parameters
			if len(params) > 0 {
				s.testEndpointVulnerabilities(ctx, endpoint, params, result, mu)
			}
		}
		mu.Unlock()
	}
}

// scanSubdomain performs reconnaissance on discovered subdomain
func (s *IntelligentScanner) scanSubdomain(ctx context.Context, target ScanTarget, result *IntelligentScanResult, mu *sync.Mutex) {
	subdomain := target.Value

	// Resolve subdomain
	ips, err := net.LookupHost(subdomain)
	if err != nil {
		return
	}

	mu.Lock()
	for _, ip := range ips {
		asset := Asset{
			Type:       "subdomain",
			Value:      subdomain,
			Confidence: target.Confidence,
			Source:     "certificate",
			Metadata: map[string]interface{}{
				"ip": ip,
			},
		}
		result.Assets = append(result.Assets, asset)
	}
	mu.Unlock()

	// Port scan if interesting
	if isInterestingSubdomain(subdomain) {
		for _, ip := range ips {
			services := s.activeModules.PortScanner.ScanPorts(ctx, ip)

			mu.Lock()
			result.Services = append(result.Services, services...)
			mu.Unlock()

			// Web scan if HTTP/HTTPS found
			for _, service := range services {
				if service.Port == 80 || service.Port == 443 || service.Port == 8080 || service.Port == 8443 {
					s.scanWebService(ctx, subdomain, service, result, mu)
				}
			}
		}
	}
}

// scanPredicted tests predicted endpoints/subdomains
func (s *IntelligentScanner) scanPredicted(ctx context.Context, target ScanTarget, result *IntelligentScanResult, mu *sync.Mutex) {
	predicted := target.Value

	// Test if prediction exists
	if target.Context["type"] == "endpoint" {
		exists, status := s.testEndpointExists(ctx, predicted)
		if exists && status < 400 {
			mu.Lock()
			result.IntelligenceHits++

			endpoint := Endpoint{
				URL:        predicted,
				Method:     "GET",
				StatusCode: status,
			}
			result.Endpoints = append(result.Endpoints, endpoint)
			mu.Unlock()

			// Test for vulnerabilities
			s.testEndpointVulnerabilities(ctx, predicted, []string{}, result, mu)
		}
	} else if target.Context["type"] == "subdomain" {
		// Test subdomain
		ips, err := net.LookupHost(predicted)
		if err == nil && len(ips) > 0 {
			mu.Lock()
			result.IntelligenceHits++

			asset := Asset{
				Type:       "predicted_subdomain",
				Value:      predicted,
				Confidence: target.Confidence,
				Source:     "pattern",
				Metadata: map[string]interface{}{
					"pattern": target.Context["pattern"],
					"ips":     ips,
				},
			}
			result.Assets = append(result.Assets, asset)
			mu.Unlock()
		}
	}
}

// scanSecretEndpoint scans endpoints associated with exposed secrets
func (s *IntelligentScanner) scanSecretEndpoint(ctx context.Context, target ScanTarget, result *IntelligentScanResult, mu *sync.Mutex) {
	endpoint := target.Value
	secretType := target.Context["secret_type"].(string)

	// Test endpoint with exposed secret context
	vulnerabilities := s.testSecretExploitation(ctx, endpoint, secretType)

	mu.Lock()
	for _, vuln := range vulnerabilities {
		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		if vuln.Exploitable {
			result.IntelligenceHits++
		}
	}
	mu.Unlock()
}

// exploitVulnerabilities attempts to exploit discovered vulnerabilities
func (s *IntelligentScanner) exploitVulnerabilities(ctx context.Context, result *IntelligentScanResult) {
	// Build attack graph from vulnerabilities
	attackGraph := s.buildAttackGraph(result.Vulnerabilities)

	// Find viable attack chains
	chains := s.findAttackChains(attackGraph)

	// Attempt to exploit chains
	for _, chain := range chains {
		if chain.Likelihood > 0.7 {
			exploited := s.attemptExploitChain(ctx, chain)
			if exploited.Impact == "Successful exploitation" {
				result.ExploitedChains = append(result.ExploitedChains, exploited)
				result.IntelligenceHits++
			}
		}
	}
}

// Helper methods

// verifyOrigin verifies if an IP is the actual origin for a domain
func (s *IntelligentScanner) verifyOrigin(ctx context.Context, ip, domain string) bool {
	// Method 1: Direct HTTP request with Host header
	if s.testHTTPOrigin(ctx, ip, domain) {
		return true
	}

	// Method 2: SSL certificate verification
	if s.testSSLOrigin(ctx, ip, domain) {
		return true
	}

	// Method 3: Response similarity
	if s.testResponseSimilarity(ctx, ip, domain) {
		return true
	}

	return false
}

// testHTTPOrigin tests origin via HTTP Host header
func (s *IntelligentScanner) testHTTPOrigin(ctx context.Context, ip, domain string) bool {
	// Create custom HTTP client that connects to IP
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Always connect to the target IP regardless of hostname
				_, port, _ := net.SplitHostPort(addr)
				if port == "" {
					port = "80"
				}
				return net.Dial(network, net.JoinHostPort(ip, port))
			},
		},
		Timeout: 10 * time.Second,
	}

	// Make request with proper Host header
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://%s/", domain), nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check if we got a valid response
	return resp.StatusCode < 400
}

// testEndpointExists checks if an endpoint still exists
func (s *IntelligentScanner) testEndpointExists(ctx context.Context, endpoint string) (bool, int) {
	resp, err := s.activeModules.WebScanner.TestEndpoint(ctx, endpoint)
	if err != nil {
		return false, 0
	}

	return true, resp.StatusCode
}

// testEndpointVulnerabilities tests an endpoint for common vulnerabilities
func (s *IntelligentScanner) testEndpointVulnerabilities(ctx context.Context, endpoint string, params []string, result *IntelligentScanResult, mu *sync.Mutex) {
	// Test for SQL injection
	if sqlVuln := s.activeModules.VulnScanner.TestSQLInjection(ctx, endpoint, params); sqlVuln != nil {
		mu.Lock()
		result.Vulnerabilities = append(result.Vulnerabilities, *sqlVuln)
		mu.Unlock()
	}

	// Test for XSS
	if xssVuln := s.activeModules.VulnScanner.TestXSS(ctx, endpoint, params); xssVuln != nil {
		mu.Lock()
		result.Vulnerabilities = append(result.Vulnerabilities, *xssVuln)
		mu.Unlock()
	}

	// Test for SSRF
	if ssrfVuln := s.activeModules.VulnScanner.TestSSRF(ctx, endpoint, params); ssrfVuln != nil {
		mu.Lock()
		result.Vulnerabilities = append(result.Vulnerabilities, *ssrfVuln)
		mu.Unlock()
	}

	// Test for authentication bypass
	if authVuln := s.activeModules.AuthTester.TestAuthBypass(ctx, endpoint); authVuln != nil {
		mu.Lock()
		result.Vulnerabilities = append(result.Vulnerabilities, *authVuln)
		mu.Unlock()
	}
}

// deepScanTarget performs comprehensive scanning on high-value targets
func (s *IntelligentScanner) deepScanTarget(ctx context.Context, ip, domain string, result *IntelligentScanResult, mu *sync.Mutex) {
	// Full port scan
	services := s.activeModules.PortScanner.ScanAllPorts(ctx, ip)

	mu.Lock()
	result.Services = append(result.Services, services...)
	mu.Unlock()

	// Service enumeration and exploitation
	for _, service := range services {
		// Web services
		if isWebService(service) {
			s.deepScanWebService(ctx, domain, service, result, mu)
		}

		// Database services
		if isDatabaseService(service) {
			s.scanDatabaseService(ctx, service, result, mu)
		}

		// Admin panels
		if isAdminService(service) {
			s.scanAdminService(ctx, service, result, mu)
		}
	}
}

// generatePredictions creates predictions from patterns
func (s *IntelligentScanner) generatePredictions(patterns []passive.Pattern) []Prediction {
	var predictions []Prediction

	for _, pattern := range patterns {
		// Generate predictions based on pattern type
		switch pattern.Type {
		case "subdomain":
			preds := s.generateSubdomainPredictions(pattern)
			predictions = append(predictions, preds...)

		case "endpoint":
			preds := s.generateEndpointPredictions(pattern)
			predictions = append(predictions, preds...)

		case "parameter":
			preds := s.generateParameterPredictions(pattern)
			predictions = append(predictions, preds...)
		}
	}

	// Deduplicate and sort by confidence
	predictions = s.deduplicatePredictions(predictions)
	sort.Slice(predictions, func(i, j int) bool {
		return predictions[i].Confidence > predictions[j].Confidence
	})

	return predictions
}

// calculateMetrics calculates scan metrics
func (s *IntelligentScanner) calculateMetrics(result *IntelligentScanResult) {
	// Count true positives based on intelligence hits
	result.TruePositives = result.IntelligenceHits

	// Estimate false positives (simplified)
	totalTests := len(result.Assets) + len(result.Endpoints)
	result.FalsePositives = totalTests - result.IntelligenceHits
	if result.FalsePositives < 0 {
		result.FalsePositives = 0
	}
}

// Helper types

// ScanTarget represents a prioritized scan target
type ScanTarget struct {
	Type       string                 // origin_ip, endpoint, subdomain, predicted
	Value      string                 // IP, URL, or domain
	Priority   int                    // 1-10, higher is more important
	Confidence float64                // 0-1, confidence in the target
	Context    map[string]interface{} // Additional context for scanning
}

// Prediction represents a predicted asset
type Prediction struct {
	Type       string // endpoint, subdomain, parameter
	Value      string
	Pattern    string
	Confidence float64
}

// Helper functions

func containsSensitiveParam(params []string) bool {
	sensitive := []string{"admin", "api", "key", "token", "secret", "password", "auth", "session", "debug", "test"}
	for _, param := range params {
		paramLower := strings.ToLower(param)
		for _, s := range sensitive {
			if strings.Contains(paramLower, s) {
				return true
			}
		}
	}
	return false
}

func isInterestingSubdomain(subdomain string) bool {
	interesting := []string{"admin", "api", "dev", "test", "staging", "uat", "internal", "private", "secret", "backup", "old", "legacy", "beta", "alpha", "preview"}
	subLower := strings.ToLower(subdomain)
	for _, i := range interesting {
		if strings.Contains(subLower, i) {
			return true
		}
	}
	return false
}

func isWebService(service Service) bool {
	webPorts := []int{80, 443, 8080, 8443, 8000, 8001, 8888, 9000, 3000, 5000}
	for _, port := range webPorts {
		if service.Port == port {
			return true
		}
	}
	return strings.Contains(strings.ToLower(service.Name), "http")
}

func isDatabaseService(service Service) bool {
	dbPorts := []int{3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984}
	for _, port := range dbPorts {
		if service.Port == port {
			return true
		}
	}
	dbNames := []string{"mysql", "postgres", "mssql", "oracle", "mongodb", "redis", "elastic", "couchdb"}
	serviceLower := strings.ToLower(service.Name)
	for _, db := range dbNames {
		if strings.Contains(serviceLower, db) {
			return true
		}
	}
	return false
}

func isAdminService(service Service) bool {
	adminPorts := []int{2222, 10000, 8834, 9090, 10050}
	for _, port := range adminPorts {
		if service.Port == port {
			return true
		}
	}
	adminNames := []string{"admin", "cpanel", "webmin", "plesk", "manager"}
	serviceLower := strings.ToLower(service.Name)
	for _, admin := range adminNames {
		if strings.Contains(serviceLower, admin) {
			return true
		}
	}
	return false
}

func convertCertificates(records []passive.CertificateRecord) []passive.Certificate {
	var certs []passive.Certificate
	for _, record := range records {
		cert := passive.Certificate{
			DNSNames: record.SANs,
			Subject: passive.Name{
				CommonName:   record.CommonName,
				Organization: record.Organizations,
			},
			NotBefore: record.NotBefore,
			NotAfter:  record.NotAfter,
		}
		certs = append(certs, cert)
	}
	return certs
}
