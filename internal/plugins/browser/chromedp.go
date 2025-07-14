package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/yourusername/shells/internal/core"
	"github.com/yourusername/shells/pkg/types"
)

type chromedpAnalyzer struct {
	logger interface {
		Info(msg string, keysAndValues ...interface{})
		Error(msg string, keysAndValues ...interface{})
		Debug(msg string, keysAndValues ...interface{})
	}
	config BrowserConfig
}

type BrowserConfig struct {
	Headless        bool
	Timeout         time.Duration
	UserAgent       string
	ViewportWidth   int64
	ViewportHeight  int64
	DisableImages   bool
	DisableCSS      bool
	WaitForLoad     time.Duration
}

type JSAnalysisResult struct {
	APIEndpoints     []APIEndpoint     `json:"api_endpoints"`
	Secrets          []Secret          `json:"secrets"`
	DOMSources       []DOMSource       `json:"dom_sources"`
	EventListeners   []EventListener   `json:"event_listeners"`
	GlobalVariables  []GlobalVar       `json:"global_variables"`
	StorageData      []StorageItem     `json:"storage_data"`
	NetworkRequests  []NetworkReq      `json:"network_requests"`
	JSFiles          []string          `json:"js_files"`
	Vulnerabilities  []JSVulnerability `json:"vulnerabilities"`
}

type APIEndpoint struct {
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Source     string            `json:"source"`
	LineNumber int               `json:"line_number"`
}

type Secret struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	Context    string `json:"context"`
	Source     string `json:"source"`
	LineNumber int    `json:"line_number"`
	Confidence string `json:"confidence"`
}

type DOMSource struct {
	Element    string `json:"element"`
	Property   string `json:"property"`
	Value      string `json:"value"`
	Dangerous  bool   `json:"dangerous"`
}

type EventListener struct {
	Event    string `json:"event"`
	Element  string `json:"element"`
	Handler  string `json:"handler"`
	Source   string `json:"source"`
}

type GlobalVar struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Value       interface{} `json:"value"`
	Sensitive   bool        `json:"sensitive"`
}

type StorageItem struct {
	Type  string `json:"type"` // localStorage, sessionStorage, cookie
	Key   string `json:"key"`
	Value string `json:"value"`
}

type NetworkReq struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Status  int               `json:"status"`
}

type JSVulnerability struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Severity    string `json:"severity"`
	Line        int    `json:"line"`
	Source      string `json:"source"`
}

func NewChromedpAnalyzer(config BrowserConfig, logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}) core.Scanner {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.ViewportWidth == 0 {
		config.ViewportWidth = 1920
	}
	if config.ViewportHeight == 0 {
		config.ViewportHeight = 1080
	}
	if config.WaitForLoad == 0 {
		config.WaitForLoad = 5 * time.Second
	}
	
	return &chromedpAnalyzer{
		logger: logger,
		config: config,
	}
}

func (a *chromedpAnalyzer) Name() string {
	return "browser"
}

func (a *chromedpAnalyzer) Type() types.ScanType {
	return types.ScanType("browser_analysis")
}

func (a *chromedpAnalyzer) Validate(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return fmt.Errorf("target must be a valid HTTP/HTTPS URL")
	}
	
	return nil
}

func (a *chromedpAnalyzer) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	a.logger.Info("Starting browser-based JavaScript analysis", "target", target)
	
	// Setup Chrome options
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", a.config.Headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.WindowSize(int(a.config.ViewportWidth), int(a.config.ViewportHeight)),
	)
	
	if a.config.UserAgent != "" {
		opts = append(opts, chromedp.UserAgent(a.config.UserAgent))
	}
	
	if a.config.DisableImages {
		opts = append(opts, chromedp.Flag("disable-images", true))
	}
	
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()
	
	// Create browser context with timeout
	browserCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	
	timeoutCtx, cancel := context.WithTimeout(browserCtx, a.config.Timeout)
	defer cancel()
	
	// Track network requests
	var networkRequests []NetworkReq
	chromedp.ListenTarget(timeoutCtx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *network.EventResponseReceived:
			req := NetworkReq{
				URL:    ev.Response.URL,
				Status: int(ev.Response.Status),
			}
			networkRequests = append(networkRequests, req)
		}
	})
	
	// Inject our analysis scripts
	analysisResult := &JSAnalysisResult{}
	
	err := chromedp.Run(timeoutCtx,
		network.Enable(),
		chromedp.Navigate(target),
		chromedp.Sleep(a.config.WaitForLoad),
		
		// Inject comprehensive analysis script
		chromedp.ActionFunc(func(ctx context.Context) error {
			return a.injectAnalysisScript(ctx, analysisResult)
		}),
		
		// Wait a bit more for async operations
		chromedp.Sleep(2*time.Second),
		
		// Extract results
		chromedp.ActionFunc(func(ctx context.Context) error {
			return a.extractResults(ctx, analysisResult)
		}),
	)
	
	if err != nil {
		return nil, fmt.Errorf("browser analysis failed: %w", err)
	}
	
	analysisResult.NetworkRequests = networkRequests
	
	// Convert analysis results to findings
	findings := a.convertToFindings(analysisResult, target)
	
	a.logger.Info("Browser analysis completed", 
		"target", target,
		"findings", len(findings),
		"api_endpoints", len(analysisResult.APIEndpoints),
		"secrets", len(analysisResult.Secrets),
		"vulnerabilities", len(analysisResult.Vulnerabilities),
	)
	
	return findings, nil
}

func (a *chromedpAnalyzer) injectAnalysisScript(ctx context.Context, result *JSAnalysisResult) error {
	// Comprehensive JavaScript analysis script
	script := `
	(function() {
		window.webScanResults = {
			apiEndpoints: [],
			secrets: [],
			domSources: [],
			eventListeners: [],
			globalVariables: [],
			storageData: [],
			vulnerabilities: []
		};
		
		// 1. API Endpoint Discovery
		function findAPIEndpoints() {
			const endpoints = [];
			
			// Hook fetch
			const originalFetch = window.fetch;
			window.fetch = function(...args) {
				const [url, options = {}] = args;
				endpoints.push({
					url: url.toString(),
					method: options.method || 'GET',
					headers: options.headers || {},
					body: options.body || '',
					source: 'fetch_hook'
				});
				return originalFetch.apply(this, args);
			};
			
			// Hook XMLHttpRequest
			const originalXHR = window.XMLHttpRequest;
			window.XMLHttpRequest = function() {
				const xhr = new originalXHR();
				const originalOpen = xhr.open;
				const originalSend = xhr.send;
				
				xhr.open = function(method, url, ...args) {
					endpoints.push({
						url: url.toString(),
						method: method,
						source: 'xhr_hook'
					});
					return originalOpen.apply(this, [method, url, ...args]);
				};
				
				return xhr;
			};
			
			// Search in existing scripts for API patterns
			const scripts = document.getElementsByTagName('script');
			for (let script of scripts) {
				if (script.src) continue;
				
				const content = script.textContent || script.innerHTML;
				const apiPatterns = [
					/fetch\s*\(\s*['"`]([^'"`]+)['"`]/g,
					/\.get\s*\(\s*['"`]([^'"`]+)['"`]/g,
					/\.post\s*\(\s*['"`]([^'"`]+)['"`]/g,
					/ajax\s*\(\s*{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]/g,
					/['"`](\/api\/[^'"`]+)['"`]/g,
					/['"`](\/graphql[^'"`]*)['"`]/g,
					/['"`](\/rest\/[^'"`]+)['"`]/g
				];
				
				apiPatterns.forEach(pattern => {
					let match;
					while ((match = pattern.exec(content)) !== null) {
						endpoints.push({
							url: match[1],
							method: 'unknown',
							source: 'static_analysis'
						});
					}
				});
			}
			
			return endpoints;
		}
		
		// 2. Secret Detection
		function findSecrets() {
			const secrets = [];
			const secretPatterns = [
				{type: 'aws_access_key', pattern: /AKIA[0-9A-Z]{16}/g, confidence: 'high'},
				{type: 'aws_secret_key', pattern: /[A-Za-z0-9/+=]{40}/g, confidence: 'medium'},
				{type: 'google_api_key', pattern: /AIza[0-9A-Za-z\-_]{35}/g, confidence: 'high'},
				{type: 'github_token', pattern: /[gG][hH][pP]_[0-9a-zA-Z]{36}/g, confidence: 'high'},
				{type: 'jwt_token', pattern: /eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+/g, confidence: 'high'},
				{type: 'slack_token', pattern: /xox[baprs]-[0-9a-zA-Z]{10,48}/g, confidence: 'high'},
				{type: 'stripe_key', pattern: /(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}/g, confidence: 'high'},
				{type: 'client_secret', pattern: /client_secret['"\s]*[:=]['"\s]*['"']([^'"]{20,})['"']/g, confidence: 'high'},
				{type: 'api_key', pattern: /api[_-]?key['"\s]*[:=]['"\s]*['"']([^'"]{16,})['"']/g, confidence: 'medium'},
				{type: 'password', pattern: /password['"\s]*[:=]['"\s]*['"']([^'"]{8,})['"']/g, confidence: 'medium'}
			];
			
			// Search in all scripts
			const scripts = document.getElementsByTagName('script');
			for (let script of scripts) {
				const content = script.textContent || script.innerHTML;
				
				secretPatterns.forEach(({type, pattern, confidence}) => {
					let match;
					while ((match = pattern.exec(content)) !== null) {
						secrets.push({
							type: type,
							value: match[1] || match[0],
							context: content.substring(Math.max(0, match.index - 50), match.index + 50),
							source: script.src || 'inline_script',
							confidence: confidence
						});
					}
				});
			}
			
			// Search in global variables
			for (let key in window) {
				try {
					const value = window[key];
					if (typeof value === 'string' && value.length > 10) {
						secretPatterns.forEach(({type, pattern, confidence}) => {
							if (pattern.test(value)) {
								secrets.push({
									type: type,
									value: value,
									context: 'window.' + key,
									source: 'global_variable',
									confidence: confidence
								});
							}
						});
					}
				} catch(e) {}
			}
			
			return secrets;
		}
		
		// 3. DOM Sources Analysis
		function analyzeDOMSources() {
			const sources = [];
			const dangerousSources = [
				'location.href', 'location.search', 'location.hash',
				'document.referrer', 'document.URL', 'document.documentURI',
				'document.baseURI', 'window.name'
			];
			
			// Check if dangerous sources are used in scripts
			const scripts = document.getElementsByTagName('script');
			for (let script of scripts) {
				const content = script.textContent || script.innerHTML;
				
				dangerousSources.forEach(source => {
					if (content.includes(source)) {
						sources.push({
							element: 'script',
							property: source,
							value: content.substring(content.indexOf(source), content.indexOf(source) + 100),
							dangerous: true
						});
					}
				});
			}
			
			return sources;
		}
		
		// 4. Event Listener Analysis
		function analyzeEventListeners() {
			const listeners = [];
			
			// Override addEventListener to track listeners
			const originalAddEventListener = EventTarget.prototype.addEventListener;
			EventTarget.prototype.addEventListener = function(type, listener, options) {
				listeners.push({
					event: type,
					element: this.tagName || this.constructor.name,
					handler: listener.toString().substring(0, 200),
					source: 'addEventListener_hook'
				});
				return originalAddEventListener.call(this, type, listener, options);
			};
			
			return listeners;
		}
		
		// 5. Global Variables Analysis
		function analyzeGlobalVariables() {
			const variables = [];
			const sensitiveNames = [
				'token', 'jwt', 'auth', 'session', 'cookie', 'password',
				'secret', 'key', 'api', 'oauth', 'user', 'admin'
			];
			
			for (let key in window) {
				try {
					if (typeof window[key] !== 'function' && key !== 'webScanResults') {
						const value = window[key];
						const sensitive = sensitiveNames.some(name => 
							key.toLowerCase().includes(name) || 
							(typeof value === 'string' && value.toLowerCase().includes(name))
						);
						
						variables.push({
							name: key,
							type: typeof value,
							value: typeof value === 'object' ? JSON.stringify(value).substring(0, 200) : String(value).substring(0, 200),
							sensitive: sensitive
						});
					}
				} catch(e) {}
			}
			
			return variables;
		}
		
		// 6. Storage Analysis
		function analyzeStorage() {
			const storage = [];
			
			// localStorage
			for (let i = 0; i < localStorage.length; i++) {
				const key = localStorage.key(i);
				const value = localStorage.getItem(key);
				storage.push({
					type: 'localStorage',
					key: key,
					value: value
				});
			}
			
			// sessionStorage
			for (let i = 0; i < sessionStorage.length; i++) {
				const key = sessionStorage.key(i);
				const value = sessionStorage.getItem(key);
				storage.push({
					type: 'sessionStorage',
					key: key,
					value: value
				});
			}
			
			// cookies
			document.cookie.split(';').forEach(cookie => {
				const [key, value] = cookie.trim().split('=');
				if (key && value) {
					storage.push({
						type: 'cookie',
						key: key,
						value: value
					});
				}
			});
			
			return storage;
		}
		
		// 7. Vulnerability Detection
		function detectVulnerabilities() {
			const vulnerabilities = [];
			
			// Check for dangerous sinks
			const dangerousSinks = [
				'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
				'eval', 'setTimeout', 'setInterval', 'Function'
			];
			
			const scripts = document.getElementsByTagName('script');
			for (let script of scripts) {
				const content = script.textContent || script.innerHTML;
				
				dangerousSinks.forEach(sink => {
					const regex = new RegExp(sink.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
					let match;
					while ((match = regex.exec(content)) !== null) {
						vulnerabilities.push({
							type: 'potential_xss_sink',
							description: 'Potentially dangerous sink: ' + sink,
							evidence: content.substring(Math.max(0, match.index - 50), match.index + 50),
							severity: sink === 'eval' || sink === 'Function' ? 'critical' : 'high',
							line: content.substring(0, match.index).split('\n').length,
							source: script.src || 'inline_script'
						});
					}
				});
			}
			
			return vulnerabilities;
		}
		
		// Execute all analysis functions
		try {
			window.webScanResults.apiEndpoints = findAPIEndpoints();
			window.webScanResults.secrets = findSecrets();
			window.webScanResults.domSources = analyzeDOMSources();
			window.webScanResults.eventListeners = analyzeEventListeners();
			window.webScanResults.globalVariables = analyzeGlobalVariables();
			window.webScanResults.storageData = analyzeStorage();
			window.webScanResults.vulnerabilities = detectVulnerabilities();
		} catch(e) {
			console.error('WebScan analysis error:', e);
		}
		
		return window.webScanResults;
	})();
	`
	
	_, err := runtime.Evaluate(script).Do(ctx)
	return err
}

func (a *chromedpAnalyzer) extractResults(ctx context.Context, result *JSAnalysisResult) error {
	var res runtime.RemoteObject
	
	err := chromedp.Evaluate(`window.webScanResults`, &res).Do(ctx)
	if err != nil {
		return err
	}
	
	if res.Value != nil {
		return json.Unmarshal(res.Value, result)
	}
	
	return nil
}

func (a *chromedpAnalyzer) convertToFindings(result *JSAnalysisResult, target string) []types.Finding {
	findings := []types.Finding{}
	
	// Convert secrets to findings
	for _, secret := range result.Secrets {
		severity := types.SeverityMedium
		if secret.Confidence == "high" {
			severity = types.SeverityHigh
		}
		if secret.Type == "aws_access_key" || secret.Type == "github_token" || secret.Type == "client_secret" {
			severity = types.SeverityCritical
		}
		
		finding := types.Finding{
			Tool:     "browser",
			Type:     "js_secret_exposure",
			Severity: severity,
			Title:    fmt.Sprintf("JavaScript Secret Exposed: %s", strings.Replace(secret.Type, "_", " ", -1)),
			Description: fmt.Sprintf("Found %s in JavaScript execution context. This credential could be extracted by attackers.",
				strings.Replace(secret.Type, "_", " ", -1)),
			Evidence: fmt.Sprintf("Source: %s\nContext: %s\nValue: %s", 
				secret.Source, secret.Context, a.sanitizeSecret(secret.Value)),
			Solution: "Remove hardcoded secrets from client-side code:\n" +
				"1. Move sensitive operations to server-side\n" +
				"2. Use environment variables on backend\n" +
				"3. Implement proper authentication flows\n" +
				"4. Rotate exposed credentials immediately",
			Metadata: map[string]interface{}{
				"secret_type": secret.Type,
				"source":      secret.Source,
				"confidence":  secret.Confidence,
			},
		}
		findings = append(findings, finding)
	}
	
	// Convert vulnerabilities to findings
	for _, vuln := range result.Vulnerabilities {
		severity := types.SeverityMedium
		switch vuln.Severity {
		case "critical":
			severity = types.SeverityCritical
		case "high":
			severity = types.SeverityHigh
		case "low":
			severity = types.SeverityLow
		}
		
		finding := types.Finding{
			Tool:     "browser",
			Type:     vuln.Type,
			Severity: severity,
			Title:    fmt.Sprintf("JavaScript Vulnerability: %s", vuln.Description),
			Description: "Potential security vulnerability detected in JavaScript code execution",
			Evidence: fmt.Sprintf("Line %d in %s: %s", vuln.Line, vuln.Source, vuln.Evidence),
			Solution: "Review and secure JavaScript code:\n" +
				"1. Sanitize user input before using in dangerous sinks\n" +
				"2. Use safe alternatives (textContent vs innerHTML)\n" +
				"3. Implement Content Security Policy\n" +
				"4. Validate and encode all user input",
			Metadata: map[string]interface{}{
				"line":   vuln.Line,
				"source": vuln.Source,
			},
		}
		findings = append(findings, finding)
	}
	
	// Convert API endpoints to findings
	if len(result.APIEndpoints) > 0 {
		var endpoints []string
		for _, ep := range result.APIEndpoints {
			endpoints = append(endpoints, fmt.Sprintf("%s %s", ep.Method, ep.URL))
		}
		
		finding := types.Finding{
			Tool:     "browser",
			Type:     "js_api_discovery",
			Severity: types.SeverityInfo,
			Title:    fmt.Sprintf("JavaScript API Endpoints Discovered (%d)", len(result.APIEndpoints)),
			Description: "API endpoints discovered through JavaScript execution and analysis",
			Evidence: strings.Join(endpoints, "\n"),
			Metadata: map[string]interface{}{
				"endpoint_count": len(result.APIEndpoints),
				"endpoints":      result.APIEndpoints,
			},
		}
		findings = append(findings, finding)
	}
	
	// Convert sensitive storage data to findings
	for _, storage := range result.StorageData {
		if a.isSensitiveStorage(storage.Key, storage.Value) {
			finding := types.Finding{
				Tool:     "browser",
				Type:     "sensitive_storage",
				Severity: types.SeverityMedium,
				Title:    fmt.Sprintf("Sensitive Data in %s", storage.Type),
				Description: fmt.Sprintf("Potentially sensitive data found in %s", storage.Type),
				Evidence: fmt.Sprintf("Key: %s\nValue: %s", storage.Key, a.sanitizeSecret(storage.Value)),
				Solution: "Secure client-side storage:\n" +
					"1. Use httpOnly cookies for sensitive data\n" +
					"2. Avoid storing secrets in localStorage/sessionStorage\n" +
					"3. Encrypt sensitive data before storage\n" +
					"4. Implement proper session management",
				Metadata: map[string]interface{}{
					"storage_type": storage.Type,
					"key":          storage.Key,
				},
			}
			findings = append(findings, finding)
		}
	}
	
	// Convert global variables to findings
	for _, gvar := range result.GlobalVariables {
		if gvar.Sensitive {
			finding := types.Finding{
				Tool:     "browser",
				Type:     "sensitive_global_variable",
				Severity: types.SeverityLow,
				Title:    fmt.Sprintf("Sensitive Global Variable: %s", gvar.Name),
				Description: "Potentially sensitive data exposed in global JavaScript variables",
				Evidence: fmt.Sprintf("Variable: %s\nType: %s\nValue: %s", 
					gvar.Name, gvar.Type, a.sanitizeSecret(fmt.Sprintf("%v", gvar.Value))),
				Solution: "Secure global variables:\n" +
					"1. Avoid exposing sensitive data globally\n" +
					"2. Use module patterns or closures\n" +
					"3. Implement proper access controls\n" +
					"4. Minimize global scope pollution",
				Metadata: map[string]interface{}{
					"variable_name": gvar.Name,
					"variable_type": gvar.Type,
				},
			}
			findings = append(findings, finding)
		}
	}
	
	return findings
}

func (a *chromedpAnalyzer) sanitizeSecret(secret string) string {
	if len(secret) > 20 {
		return secret[:10] + "..." + secret[len(secret)-5:]
	}
	return secret[:len(secret)/2] + "..."
}

func (a *chromedpAnalyzer) isSensitiveStorage(key, value string) bool {
	sensitivePatterns := []string{
		"token", "jwt", "auth", "session", "password", "secret", 
		"key", "credential", "oauth", "bearer", "api",
	}
	
	keyLower := strings.ToLower(key)
	valueLower := strings.ToLower(value)
	
	for _, pattern := range sensitivePatterns {
		if strings.Contains(keyLower, pattern) || strings.Contains(valueLower, pattern) {
			return true
		}
	}
	
	// Check for JWT pattern
	jwtPattern := regexp.MustCompile(`eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+`)
	if jwtPattern.MatchString(value) {
		return true
	}
	
	return false
}