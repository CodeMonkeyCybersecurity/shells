package httpx

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourusername/shells/internal/core"
	"github.com/yourusername/shells/pkg/types"
)

type httpxScanner struct {
	cfg    HTTPXConfig
	logger interface {
		Info(msg string, keysAndValues ...interface{})
		Error(msg string, keysAndValues ...interface{})
		Debug(msg string, keysAndValues ...interface{})
	}
}

type HTTPXConfig struct {
	BinaryPath      string
	Timeout         time.Duration
	Threads         int
	RateLimit       int
	Retries         int
	FollowRedirects bool
	ProbeAllIPs     bool
}

type HTTPXOutput struct {
	Timestamp      string   `json:"timestamp"`
	Host           string   `json:"host"`
	URL            string   `json:"url"`
	Port           string   `json:"port"`
	StatusCode     int      `json:"status_code"`
	ContentLength  int      `json:"content_length"`
	ContentType    string   `json:"content_type"`
	Title          string   `json:"title"`
	WebServer      string   `json:"webserver"`
	ResponseTime   string   `json:"response_time"`
	Technologies   []string `json:"technologies,omitempty"`
	Hashes         struct {
		BodyMD5    string `json:"body_md5,omitempty"`
		BodySHA256 string `json:"body_sha256,omitempty"`
		HeaderMD5  string `json:"header_md5,omitempty"`
	} `json:"hashes,omitempty"`
	CDN         bool     `json:"cdn"`
	CDNName     string   `json:"cdn_name,omitempty"`
	Scheme      string   `json:"scheme"`
	Method      string   `json:"method"`
	TLS         *TLSInfo `json:"tls,omitempty"`
	Extracts    []string `json:"extracts,omitempty"`
	ChainStatus []int    `json:"chain_status_codes,omitempty"`
	Words       int      `json:"words,omitempty"`
	Lines       int      `json:"lines,omitempty"`
	ASN         string   `json:"asn,omitempty"`
	Failed      bool     `json:"failed"`
	VHost       bool     `json:"vhost"`
	WebSocket   bool     `json:"websocket"`
	Pipeline    bool     `json:"pipeline"`
	HTTP2       bool     `json:"http2"`
	IPAddress   []string `json:"a,omitempty"`
	CNAMEs      []string `json:"cname,omitempty"`
}

type TLSInfo struct {
	SNI            string   `json:"sni,omitempty"`
	CN             []string `json:"cn,omitempty"`
	SAN            []string `json:"san,omitempty"`
	Issuer         []string `json:"issuer,omitempty"`
	FingerprintSHA256 string `json:"fingerprint_sha256,omitempty"`
	Serial         string   `json:"serial,omitempty"`
}

func NewScanner(cfg HTTPXConfig, logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}) core.Scanner {
	if cfg.BinaryPath == "" {
		cfg.BinaryPath = "httpx"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Threads == 0 {
		cfg.Threads = 50
	}
	if cfg.RateLimit == 0 {
		cfg.RateLimit = 150
	}
	if cfg.Retries == 0 {
		cfg.Retries = 2
	}
	
	return &httpxScanner{
		cfg:    cfg,
		logger: logger,
	}
}

func (s *httpxScanner) Name() string {
	return "httpx"
}

func (s *httpxScanner) Type() types.ScanType {
	return types.ScanType("http_probe")
}

func (s *httpxScanner) Validate(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	
	if _, err := exec.LookPath(s.cfg.BinaryPath); err != nil {
		return fmt.Errorf("httpx binary not found: %w", err)
	}
	
	return nil
}

func (s *httpxScanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("httpx_%d.json", time.Now().Unix()))
	defer os.Remove(tempFile)
	
	args := s.buildHTTPXArgs(target, tempFile, options)
	
	s.logger.Info("Running httpx scan", "target", target, "args", args)
	
	cmd := exec.CommandContext(ctx, s.cfg.BinaryPath, args...)
	
	// Capture stderr for debugging
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}
	
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start httpx: %w", err)
	}
	
	// Log stderr output
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			s.logger.Debug("httpx stderr", "output", scanner.Text())
		}
	}()
	
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("httpx scan failed: %w", err)
	}
	
	return s.parseHTTPXOutput(tempFile, target)
}

func (s *httpxScanner) buildHTTPXArgs(target, outputFile string, options map[string]string) []string {
	args := []string{
		"-json",
		"-o", outputFile,
		"-threads", fmt.Sprintf("%d", s.cfg.Threads),
		"-rate-limit", fmt.Sprintf("%d", s.cfg.RateLimit),
		"-retries", fmt.Sprintf("%d", s.cfg.Retries),
		"-timeout", fmt.Sprintf("%d", int(s.cfg.Timeout.Seconds())),
		"-silent",
		"-stats",
		"-tech-detect",
		"-title",
		"-status-code",
		"-content-length",
		"-response-time",
		"-web-server",
		"-method",
		"-websocket",
		"-pipeline",
		"-http2",
		"-vhost",
		"-cdn",
		"-tls-grab",
		"-tls-probe",
		"-asn",
		"-hash", "md5,sha256",
		"-extract-regex", `(?i)(client_id|client[-_]?secret|api[-_]?key|access[-_]?token|oauth|jwt|bearer|authorization)[\s]*[:=][\s]*['"]?([a-zA-Z0-9\-_.~+\/]+)['"]?`,
		"-favicon",
		"-jarm",
		"-screenshot",
		"-include-response",
		"-include-chain",
	}
	
	// Add target
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		args = append(args, "-u", target)
	} else {
		args = append(args, "-u", target)
	}
	
	// OAuth2/API specific options
	if scanType := options["scan_type"]; scanType == "oauth2" || scanType == "api" {
		args = append(args, 
			"-path", "/.well-known/openid-configuration",
			"-path", "/oauth/authorize",
			"-path", "/oauth/token",
			"-path", "/.well-known/oauth-authorization-server",
			"-path", "/api/swagger.json",
			"-path", "/api/v1/swagger.json",
			"-path", "/swagger/v1/swagger.json",
			"-path", "/graphql",
			"-path", "/graphiql",
			"-path", "/altair",
			"-path", "/playground",
		)
	}
	
	// Follow redirects
	if s.cfg.FollowRedirects || options["follow_redirects"] == "true" {
		args = append(args, "-follow-redirects", "-follow-host-redirects")
		args = append(args, "-max-redirects", "10")
	}
	
	// Probe all IPs
	if s.cfg.ProbeAllIPs || options["probe_all_ips"] == "true" {
		args = append(args, "-probe-all-ips")
	}
	
	// Custom ports
	if ports := options["ports"]; ports != "" {
		args = append(args, "-ports", ports)
	}
	
	// Custom headers for authentication
	if authHeader := options["auth_header"]; authHeader != "" {
		args = append(args, "-H", authHeader)
	}
	
	// Proxy support
	if proxy := options["proxy"]; proxy != "" {
		args = append(args, "-http-proxy", proxy)
	}
	
	// Match specific responses
	if match := options["match_status"]; match != "" {
		args = append(args, "-mc", match)
	}
	
	if match := options["match_length"]; match != "" {
		args = append(args, "-ml", match)
	}
	
	if match := options["match_word"]; match != "" {
		args = append(args, "-mw", match)
	}
	
	// Filter responses
	if filter := options["filter_status"]; filter != "" {
		args = append(args, "-fc", filter)
	}
	
	if filter := options["filter_length"]; filter != "" {
		args = append(args, "-fl", filter)
	}
	
	return args
}

func (s *httpxScanner) parseHTTPXOutput(outputFile, target string) ([]types.Finding, error) {
	file, err := os.Open(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open httpx output: %w", err)
	}
	defer file.Close()
	
	findings := []types.Finding{}
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		var output HTTPXOutput
		if err := json.Unmarshal(scanner.Bytes(), &output); err != nil {
			s.logger.Error("Failed to parse httpx output line", "error", err)
			continue
		}
		
		// Convert httpx output to findings
		findings = append(findings, s.analyzeHTTPXOutput(output, target)...)
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading httpx output: %w", err)
	}
	
	return findings, nil
}

func (s *httpxScanner) analyzeHTTPXOutput(output HTTPXOutput, target string) []types.Finding {
	findings := []types.Finding{}
	
	// Check for interesting status codes
	if finding := s.checkStatusCode(output); finding != nil {
		findings = append(findings, *finding)
	}
	
	// Check for sensitive information in extracts
	if finding := s.checkSensitiveData(output); finding != nil {
		findings = append(findings, *finding)
	}
	
	// Check for technology-specific issues
	findings = append(findings, s.checkTechnologies(output)...)
	
	// Check for OAuth2/API endpoints
	if finding := s.checkOAuth2Endpoints(output); finding != nil {
		findings = append(findings, *finding)
	}
	
	// Check for security headers
	if finding := s.checkSecurityHeaders(output); finding != nil {
		findings = append(findings, *finding)
	}
	
	// Check for TLS issues
	if output.TLS != nil {
		findings = append(findings, s.checkTLSIssues(output)...)
	}
	
	// Check for potential subdomain takeover
	if finding := s.checkSubdomainTakeover(output); finding != nil {
		findings = append(findings, *finding)
	}
	
	// Always create an info finding for discovered service
	serviceFinding := types.Finding{
		Tool:     "httpx",
		Type:     "service_discovery",
		Severity: types.SeverityInfo,
		Title:    fmt.Sprintf("HTTP Service Discovered: %s", output.URL),
		Description: fmt.Sprintf("Active HTTP service found at %s\nTitle: %s\nServer: %s\nStatus: %d",
			output.URL, output.Title, output.WebServer, output.StatusCode),
		Metadata: map[string]interface{}{
			"url":           output.URL,
			"status_code":   output.StatusCode,
			"title":         output.Title,
			"server":        output.WebServer,
			"technologies":  output.Technologies,
			"response_time": output.ResponseTime,
			"content_type":  output.ContentType,
			"http2":         output.HTTP2,
			"websocket":     output.WebSocket,
		},
	}
	findings = append(findings, serviceFinding)
	
	return findings
}

func (s *httpxScanner) checkStatusCode(output HTTPXOutput) *types.Finding {
	interestingCodes := map[int]struct {
		severity types.Severity
		title    string
		desc     string
	}{
		401: {types.SeverityInfo, "Authentication Required", "Protected endpoint requiring authentication"},
		403: {types.SeverityInfo, "Forbidden Access", "Access forbidden but resource exists"},
		500: {types.SeverityMedium, "Internal Server Error", "Server error that might reveal information"},
		502: {types.SeverityLow, "Bad Gateway", "Backend server communication issue"},
		503: {types.SeverityLow, "Service Unavailable", "Service temporarily unavailable"},
	}
	
	if info, ok := interestingCodes[output.StatusCode]; ok {
		return &types.Finding{
			Tool:     "httpx",
			Type:     "interesting_response",
			Severity: info.severity,
			Title:    fmt.Sprintf("%s at %s", info.title, output.URL),
			Description: fmt.Sprintf("%s (Status Code: %d)", info.desc, output.StatusCode),
			Metadata: map[string]interface{}{
				"url":         output.URL,
				"status_code": output.StatusCode,
			},
		}
	}
	
	return nil
}

func (s *httpxScanner) checkSensitiveData(output HTTPXOutput) *types.Finding {
	if len(output.Extracts) == 0 {
		return nil
	}
	
	sensitivePatterns := []struct {
		pattern  string
		severity types.Severity
		title    string
	}{
		{"client_secret", types.SeverityCritical, "Client Secret Exposed"},
		{"api_key", types.SeverityHigh, "API Key Exposed"},
		{"access_token", types.SeverityHigh, "Access Token Exposed"},
		{"jwt", types.SeverityHigh, "JWT Token Exposed"},
		{"bearer", types.SeverityHigh, "Bearer Token Exposed"},
		{"private_key", types.SeverityCritical, "Private Key Exposed"},
	}
	
	for _, extract := range output.Extracts {
		extractLower := strings.ToLower(extract)
		for _, pattern := range sensitivePatterns {
			if strings.Contains(extractLower, pattern.pattern) {
				return &types.Finding{
					Tool:     "httpx",
					Type:     "sensitive_data_exposure",
					Severity: pattern.severity,
					Title:    fmt.Sprintf("%s at %s", pattern.title, output.URL),
					Description: fmt.Sprintf("Potentially sensitive data found in HTTP response: %s", 
						s.sanitizeExtract(extract)),
					Evidence: fmt.Sprintf("Extract: %s", s.sanitizeExtract(extract)),
					Solution: "Remove sensitive data from HTTP responses. Use secure storage and transmission methods.",
					Metadata: map[string]interface{}{
						"url":      output.URL,
						"pattern":  pattern.pattern,
						"extract":  s.sanitizeExtract(extract),
					},
				}
			}
		}
	}
	
	return nil
}

func (s *httpxScanner) checkTechnologies(output HTTPXOutput) []types.Finding {
	findings := []types.Finding{}
	
	vulnerableTech := map[string]struct {
		severity types.Severity
		desc     string
	}{
		"WordPress": {types.SeverityInfo, "WordPress CMS detected - check for outdated plugins and themes"},
		"Joomla":    {types.SeverityInfo, "Joomla CMS detected - check for security updates"},
		"Drupal":    {types.SeverityInfo, "Drupal CMS detected - check for security advisories"},
		"phpMyAdmin": {types.SeverityMedium, "phpMyAdmin detected - should not be publicly accessible"},
		"Apache Tomcat": {types.SeverityInfo, "Apache Tomcat detected - check for default credentials and CVEs"},
		"Jenkins":   {types.SeverityMedium, "Jenkins detected - should be properly secured"},
		"Grafana":   {types.SeverityMedium, "Grafana detected - check for default credentials"},
		"Kibana":    {types.SeverityMedium, "Kibana detected - should not be publicly accessible"},
	}
	
	for _, tech := range output.Technologies {
		if info, ok := vulnerableTech[tech]; ok {
			findings = append(findings, types.Finding{
				Tool:     "httpx",
				Type:     "technology_detection",
				Severity: info.severity,
				Title:    fmt.Sprintf("%s Detected at %s", tech, output.URL),
				Description: info.desc,
				Metadata: map[string]interface{}{
					"url":        output.URL,
					"technology": tech,
				},
			})
		}
	}
	
	return findings
}

func (s *httpxScanner) checkOAuth2Endpoints(output HTTPXOutput) *types.Finding {
	oauth2Paths := []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
		"/oauth/authorize",
		"/oauth/token",
		"/oauth2/authorize",
		"/oauth2/token",
		"/connect/authorize",
		"/connect/token",
	}
	
	for _, path := range oauth2Paths {
		if strings.Contains(output.URL, path) && output.StatusCode == 200 {
			return &types.Finding{
				Tool:     "httpx",
				Type:     "oauth2_endpoint_discovered",
				Severity: types.SeverityInfo,
				Title:    fmt.Sprintf("OAuth2/OIDC Endpoint Found: %s", output.URL),
				Description: fmt.Sprintf("OAuth2/OpenID Connect endpoint discovered. This should be tested for security misconfigurations."),
				Metadata: map[string]interface{}{
					"url":         output.URL,
					"endpoint":    path,
					"status_code": output.StatusCode,
				},
			}
		}
	}
	
	// Check for GraphQL endpoints
	graphqlPaths := []string{"/graphql", "/graphiql", "/playground", "/altair"}
	for _, path := range graphqlPaths {
		if strings.Contains(output.URL, path) && output.StatusCode == 200 {
			return &types.Finding{
				Tool:     "httpx",
				Type:     "graphql_endpoint_discovered",
				Severity: types.SeverityMedium,
				Title:    fmt.Sprintf("GraphQL Endpoint Found: %s", output.URL),
				Description: "GraphQL endpoint discovered. Check for introspection, batching attacks, and query depth limits.",
				Metadata: map[string]interface{}{
					"url":         output.URL,
					"endpoint":    path,
					"status_code": output.StatusCode,
				},
			}
		}
	}
	
	return nil
}

func (s *httpxScanner) checkSecurityHeaders(output HTTPXOutput) *types.Finding {
	// This is a simplified check - in reality, we'd need to parse response headers
	if output.StatusCode == 200 && !strings.Contains(strings.ToLower(output.WebServer), "secure") {
		return &types.Finding{
			Tool:     "httpx",
			Type:     "security_headers",
			Severity: types.SeverityLow,
			Title:    "Security Headers Check Required",
			Description: fmt.Sprintf("HTTP service at %s should be checked for security headers (CSP, HSTS, X-Frame-Options, etc.)", output.URL),
			Solution: "Implement security headers according to OWASP recommendations",
			Metadata: map[string]interface{}{
				"url":    output.URL,
				"server": output.WebServer,
			},
		}
	}
	
	return nil
}

func (s *httpxScanner) checkTLSIssues(output HTTPXOutput) []types.Finding {
	findings := []types.Finding{}
	
	if output.TLS == nil {
		return findings
	}
	
	// Check for wildcard certificates
	for _, san := range output.TLS.SAN {
		if strings.HasPrefix(san, "*.") {
			findings = append(findings, types.Finding{
				Tool:     "httpx",
				Type:     "tls_wildcard_certificate",
				Severity: types.SeverityInfo,
				Title:    "Wildcard Certificate in Use",
				Description: fmt.Sprintf("Site %s uses wildcard certificate for %s", output.URL, san),
				Metadata: map[string]interface{}{
					"url":      output.URL,
					"wildcard": san,
				},
			})
		}
	}
	
	return findings
}

func (s *httpxScanner) checkSubdomainTakeover(output HTTPXOutput) *types.Finding {
	// Check for CNAME pointing to common vulnerable services
	vulnerableServices := []string{
		"amazonaws.com",
		"azurewebsites.net",
		"cloudapp.net",
		"herokuapp.com",
		"github.io",
		"gitlab.io",
		"surge.sh",
		"bitbucket.io",
	}
	
	for _, cname := range output.CNAMEs {
		for _, service := range vulnerableServices {
			if strings.Contains(cname, service) && output.StatusCode == 404 {
				return &types.Finding{
					Tool:     "httpx",
					Type:     "potential_subdomain_takeover",
					Severity: types.SeverityHigh,
					Title:    "Potential Subdomain Takeover",
					Description: fmt.Sprintf("Domain %s has CNAME to %s with 404 response - potential subdomain takeover",
						output.Host, cname),
					Evidence: fmt.Sprintf("CNAME: %s, Status: %d", cname, output.StatusCode),
					Solution: "Remove dangling DNS records or claim the service",
					Metadata: map[string]interface{}{
						"host":        output.Host,
						"cname":       cname,
						"service":     service,
						"status_code": output.StatusCode,
					},
				}
			}
		}
	}
	
	return nil
}

func (s *httpxScanner) sanitizeExtract(extract string) string {
	// Sanitize sensitive data by showing only partial information
	if len(extract) > 20 {
		return extract[:10] + "..." + extract[len(extract)-5:]
	}
	return extract[:len(extract)/2] + "..."
}