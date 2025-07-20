// pkg/fuzzing/fuzzer.go
package fuzzing

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Fuzzer represents the main fuzzing engine
type Fuzzer struct {
	client      *http.Client
	config      FuzzerConfig
	logger      Logger
	wordlists   map[string][]string
	results     chan FuzzResult
	rateLimiter *RateLimiter
}

// FuzzerConfig holds fuzzer configuration
type FuzzerConfig struct {
	Threads           int
	Timeout           time.Duration
	FollowRedirects   bool
	UserAgent         string
	CustomHeaders     map[string]string
	Extensions        []string
	Methods           []string
	StatusCodeFilters []int
	SizeFilters       []int
	WordlistDir       string
	RateLimit         int
	SmartMode         bool
	RecursionDepth    int
}

// FuzzResult represents a fuzzing result
type FuzzResult struct {
	URL          string                 `json:"url"`
	Method       string                 `json:"method"`
	StatusCode   int                    `json:"status_code"`
	Size         int                    `json:"size"`
	Words        int                    `json:"words"`
	Lines        int                    `json:"lines"`
	RedirectURL  string                 `json:"redirect_url,omitempty"`
	Headers      map[string]string      `json:"headers,omitempty"`
	ResponseTime time.Duration          `json:"response_time"`
	Timestamp    time.Time              `json:"timestamp"`
	Type         string                 `json:"type"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
}

// Logger interface
type Logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
}

// NewFuzzer creates a new fuzzer instance
func NewFuzzer(config FuzzerConfig, logger Logger) *Fuzzer {
	if config.Threads == 0 {
		config.Threads = 10
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.UserAgent == "" {
		config.UserAgent = "shells-fuzzer/1.0"
	}

	client := &http.Client{
		Timeout: config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !config.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return &Fuzzer{
		client:      client,
		config:      config,
		logger:      logger,
		wordlists:   make(map[string][]string),
		results:     make(chan FuzzResult, 1000),
		rateLimiter: NewRateLimiter(config.RateLimit),
	}
}

// DirectoryFuzzing performs directory and file discovery
func (f *Fuzzer) DirectoryFuzzing(ctx context.Context, target string, wordlist string) ([]FuzzResult, error) {
	f.logger.Info("Starting directory fuzzing", "target", target, "wordlist", wordlist)

	// Load wordlist
	words, err := f.loadWordlist(wordlist)
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}

	// Parse target URL
	baseURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	// Create worker pool
	var wg sync.WaitGroup
	workChan := make(chan string, len(words))
	results := []FuzzResult{}
	resultsMutex := &sync.Mutex{}

	// Start workers
	for i := 0; i < f.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range workChan {
				select {
				case <-ctx.Done():
					return
				default:
					if result := f.fuzzDirectory(ctx, baseURL, word); result != nil {
						resultsMutex.Lock()
						results = append(results, *result)
						resultsMutex.Unlock()
					}
				}
			}
		}()
	}

	// Send work
	for _, word := range words {
		workChan <- word
	}
	close(workChan)

	wg.Wait()

	// If smart mode is enabled, perform recursive fuzzing
	if f.config.SmartMode && f.config.RecursionDepth > 0 {
		recursiveResults := f.recursiveFuzz(ctx, baseURL, results, 1)
		results = append(results, recursiveResults...)
	}

	return results, nil
}

// ParameterFuzzing discovers hidden parameters
func (f *Fuzzer) ParameterFuzzing(ctx context.Context, target string, wordlist string) ([]FuzzResult, error) {
	f.logger.Info("Starting parameter fuzzing", "target", target)

	// Load parameter wordlist
	params, err := f.loadWordlist(wordlist)
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}

	// Parse target URL
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	// Get baseline response
	baseline, err := f.getBaseline(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get baseline: %w", err)
	}

	// Test each parameter
	results := []FuzzResult{}
	var wg sync.WaitGroup
	resultsChan := make(chan FuzzResult, f.config.Threads)

	// Parameter testing methods
	methods := []string{"GET", "POST", "PUT", "PATCH"}
	if len(f.config.Methods) > 0 {
		methods = f.config.Methods
	}

	// Start workers
	paramChan := make(chan paramTest, len(params)*len(methods))
	
	for i := 0; i < f.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for test := range paramChan {
				if result := f.testParameter(ctx, test, baseline); result != nil {
					resultsChan <- *result
				}
			}
		}()
	}

	// Generate parameter tests
	for _, param := range params {
		for _, method := range methods {
			paramChan <- paramTest{
				URL:    targetURL,
				Param:  param,
				Method: method,
			}
		}
	}
	close(paramChan)

	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		results = append(results, result)
	}

	// Advanced parameter discovery techniques
	if f.config.SmartMode {
		// Test parameter pollution
		pollutionResults := f.testParameterPollution(ctx, targetURL, results)
		results = append(results, pollutionResults...)

		// Test array parameters
		arrayResults := f.testArrayParameters(ctx, targetURL, params)
		results = append(results, arrayResults...)

		// Test JSON parameters
		jsonResults := f.testJSONParameters(ctx, targetURL, params)
		results = append(results, jsonResults...)
	}

	return results, nil
}

// VHostFuzzing discovers virtual hosts
func (f *Fuzzer) VHostFuzzing(ctx context.Context, target string, wordlist string) ([]FuzzResult, error) {
	f.logger.Info("Starting vhost fuzzing", "target", target)

	// Load vhost wordlist
	vhosts, err := f.loadWordlist(wordlist)
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}

	// Parse target
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	// Extract base domain
	baseDomain := targetURL.Hostname()
	
	// Get baseline (non-existent vhost)
	baseline, err := f.getVHostBaseline(ctx, targetURL, "definitely-not-a-real-subdomain")
	if err != nil {
		return nil, fmt.Errorf("failed to get baseline: %w", err)
	}

	// Test vhosts
	results := []FuzzResult{}
	var wg sync.WaitGroup
	vhostChan := make(chan string, len(vhosts))
	resultsChan := make(chan FuzzResult, f.config.Threads)

	// Start workers
	for i := 0; i < f.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for vhost := range vhostChan {
				if result := f.testVHost(ctx, targetURL, vhost, baseDomain, baseline); result != nil {
					resultsChan <- *result
				}
			}
		}()
	}

	// Send work
	for _, vhost := range vhosts {
		vhostChan <- vhost
	}
	close(vhostChan)

	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		results = append(results, result)
	}

	return results, nil
}

// SubdomainFuzzing performs subdomain enumeration via fuzzing
func (f *Fuzzer) SubdomainFuzzing(ctx context.Context, domain string, wordlist string) ([]FuzzResult, error) {
	f.logger.Info("Starting subdomain fuzzing", "domain", domain)

	// Load subdomain wordlist
	subdomains, err := f.loadWordlist(wordlist)
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}

	// Prepare for DNS resolution and HTTP testing
	results := []FuzzResult{}
	var wg sync.WaitGroup
	subChan := make(chan string, len(subdomains))
	resultsChan := make(chan FuzzResult, f.config.Threads)

	// Start workers
	for i := 0; i < f.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range subChan {
				subdomain := fmt.Sprintf("%s.%s", sub, domain)
				
				// First try DNS resolution
				if f.resolveDomain(subdomain) {
					// If it resolves, try HTTP/HTTPS
					for _, proto := range []string{"https", "http"} {
						target := fmt.Sprintf("%s://%s", proto, subdomain)
						if result := f.testSubdomain(ctx, target, subdomain); result != nil {
							resultsChan <- *result
						}
					}
				}
			}
		}()
	}

	// Send work
	for _, sub := range subdomains {
		subChan <- sub
	}
	close(subChan)

	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		results = append(results, result)
	}

	// Smart subdomain generation
	if f.config.SmartMode {
		// Generate permutations
		permutations := f.generateSubdomainPermutations(domain, results)
		for _, perm := range permutations {
			if f.resolveDomain(perm) {
				for _, proto := range []string{"https", "http"} {
					target := fmt.Sprintf("%s://%s", proto, perm)
					if result := f.testSubdomain(ctx, target, perm); result != nil {
						results = append(results, *result)
					}
				}
			}
		}
	}

	return results, nil
}

// Helper methods

func (f *Fuzzer) fuzzDirectory(ctx context.Context, baseURL *url.URL, path string) *FuzzResult {
	// Rate limiting
	f.rateLimiter.Wait()

	// Build URL
	testURL := *baseURL
	testURL.Path = filepath.Join(baseURL.Path, path)

	// Test with extensions
	urls := []string{testURL.String()}
	for _, ext := range f.config.Extensions {
		extURL := testURL
		extURL.Path = testURL.Path + ext
		urls = append(urls, extURL.String())
	}

	// Test each URL
	for _, u := range urls {
		start := time.Now()
		
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			continue
		}

		// Set headers
		req.Header.Set("User-Agent", f.config.UserAgent)
		for k, v := range f.config.CustomHeaders {
			req.Header.Set(k, v)
		}

		resp, err := f.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check status code filters
		if !f.isValidStatusCode(resp.StatusCode) {
			continue
		}

		// Read response for size calculation
		body := make([]byte, 0, 1024)
		scanner := bufio.NewScanner(resp.Body)
		wordCount := 0
		lineCount := 0

		for scanner.Scan() {
			line := scanner.Text()
			body = append(body, []byte(line+"\n")...)
			lineCount++
			wordCount += len(strings.Fields(line))
		}

		size := len(body)

		// Check size filters
		if !f.isValidSize(size) {
			continue
		}

		result := &FuzzResult{
			URL:          u,
			Method:       "GET",
			StatusCode:   resp.StatusCode,
			Size:         size,
			Words:        wordCount,
			Lines:        lineCount,
			ResponseTime: time.Since(start),
			Timestamp:    time.Now(),
			Type:         "directory",
		}

		// Add redirect URL if applicable
		if location := resp.Header.Get("Location"); location != "" {
			result.RedirectURL = location
		}

		f.logger.Debug("Found", "url", u, "status", resp.StatusCode, "size", size)
		
		return result
	}

	return nil
}

func (f *Fuzzer) testParameter(ctx context.Context, test paramTest, baseline *baselineResponse) *FuzzResult {
	f.rateLimiter.Wait()

	var req *http.Request
	var err error

	// Build request based on method
	switch test.Method {
	case "GET":
		// Add parameter to query string
		u := *test.URL
		q := u.Query()
		q.Set(test.Param, "shells-test-value")
		u.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, "GET", u.String(), nil)

	case "POST", "PUT", "PATCH":
		// Add parameter to body
		data := url.Values{}
		data.Set(test.Param, "shells-test-value")
		req, err = http.NewRequestWithContext(ctx, test.Method, test.URL.String(), strings.NewReader(data.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	if err != nil {
		return nil
	}

	// Set headers
	req.Header.Set("User-Agent", f.config.UserAgent)
	for k, v := range f.config.CustomHeaders {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := f.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Read response
	body := make([]byte, 0, 1024)
	scanner := bufio.NewScanner(resp.Body)
	wordCount := 0
	lineCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		body = append(body, []byte(line+"\n")...)
		lineCount++
		wordCount += len(strings.Fields(line))
	}

	// Compare with baseline
	if f.isDifferentFromBaseline(resp, body, baseline) {
		return &FuzzResult{
			URL:          test.URL.String(),
			Method:       test.Method,
			StatusCode:   resp.StatusCode,
			Size:         len(body),
			Words:        wordCount,
			Lines:        lineCount,
			ResponseTime: time.Since(start),
			Timestamp:    time.Now(),
			Type:         "parameter",
			Parameters: map[string]interface{}{
				"name":   test.Param,
				"method": test.Method,
			},
		}
	}

	return nil
}

func (f *Fuzzer) loadWordlist(path string) ([]string, error) {
	// Check cache
	if words, ok := f.wordlists[path]; ok {
		return words, nil
	}

	// Check if it's a built-in wordlist
	if !filepath.IsAbs(path) && f.config.WordlistDir != "" {
		path = filepath.Join(f.config.WordlistDir, path)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Cache wordlist
	f.wordlists[path] = words

	return words, nil
}

func (f *Fuzzer) isValidStatusCode(code int) bool {
	if len(f.config.StatusCodeFilters) == 0 {
		// Default: accept 200, 301, 302, 401, 403
		validCodes := []int{200, 301, 302, 401, 403}
		for _, valid := range validCodes {
			if code == valid {
				return true
			}
		}
		return false
	}

	for _, filter := range f.config.StatusCodeFilters {
		if code == filter {
			return true
		}
	}
	return false
}

func (f *Fuzzer) isValidSize(size int) bool {
	if len(f.config.SizeFilters) == 0 {
		return true
	}

	for _, filter := range f.config.SizeFilters {
		if size != filter {
			return true
		}
	}
	return false
}

// RateLimiter implementation
type RateLimiter struct {
	rate   int
	ticker *time.Ticker
	mu     sync.Mutex
}

func NewRateLimiter(rate int) *RateLimiter {
	if rate <= 0 {
		rate = 1000 // Default: 1000 req/s
	}
	
	interval := time.Second / time.Duration(rate)
	return &RateLimiter{
		rate:   rate,
		ticker: time.NewTicker(interval),
	}
}

func (r *RateLimiter) Wait() {
	<-r.ticker.C
}

// Additional types
type paramTest struct {
	URL    *url.URL
	Param  string
	Method string
}

type baselineResponse struct {
	StatusCode int
	Size       int
	Words      int
	Lines      int
	Headers    map[string]string
}

func (f *Fuzzer) getBaseline(ctx context.Context, target *url.URL) (*baselineResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", f.config.UserAgent)
	
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response
	body := make([]byte, 0, 1024)
	scanner := bufio.NewScanner(resp.Body)
	wordCount := 0
	lineCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		body = append(body, []byte(line+"\n")...)
		lineCount++
		wordCount += len(strings.Fields(line))
	}

	return &baselineResponse{
		StatusCode: resp.StatusCode,
		Size:       len(body),
		Words:      wordCount,
		Lines:      lineCount,
	}, nil
}

func (f *Fuzzer) isDifferentFromBaseline(resp *http.Response, body []byte, baseline *baselineResponse) bool {
	// Check significant differences
	if resp.StatusCode != baseline.StatusCode {
		return true
	}

	sizeDiff := abs(len(body) - baseline.Size)
	if sizeDiff > 100 { // More than 100 bytes difference
		return true
	}

	return false
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// recursiveFuzz performs recursive fuzzing on discovered directories
func (f *Fuzzer) recursiveFuzz(ctx context.Context, baseURL *url.URL, found []FuzzResult, depth int) []FuzzResult {
	if depth > f.config.RecursionDepth {
		return []FuzzResult{}
	}

	results := []FuzzResult{}

	for _, result := range found {
		if result.Type == "directory" && result.StatusCode == 200 {
			// Parse the found URL
			foundURL, err := url.Parse(result.URL)
			if err != nil {
				continue
			}

			// Load a smaller wordlist for recursive fuzzing
			words := f.getRecursiveWordlist()
			
			for _, word := range words {
				newURL := *foundURL
				newURL.Path = strings.TrimSuffix(newURL.Path, "/") + "/" + word
				
				if newResult := f.fuzzDirectory(ctx, &newURL, ""); newResult != nil {
					results = append(results, *newResult)
				}
			}

			// Recurse deeper
			if len(results) > 0 {
				deeperResults := f.recursiveFuzz(ctx, baseURL, results, depth+1)
				results = append(results, deeperResults...)
			}
		}
	}

	return results
}

// testParameterPollution tests for HTTP Parameter Pollution vulnerabilities
func (f *Fuzzer) testParameterPollution(ctx context.Context, target *url.URL, knownParams []FuzzResult) []FuzzResult {
	results := []FuzzResult{}

	for _, param := range knownParams {
		if paramName, ok := param.Parameters["name"].(string); ok {
			// Test various pollution techniques
			pollutionTests := []struct {
				name   string
				values []string
			}{
				{"duplicate", []string{"value1", "value2"}},
				{"array", []string{"value[0]", "value[1]"}},
				{"encoded", []string{"value1", "value%32"}},
				{"null", []string{"value", "\x00"}},
			}

			for _, test := range pollutionTests {
				u := *target
				q := u.Query()
				
				// Add multiple values
				for _, v := range test.values {
					q.Add(paramName, v)
				}
				u.RawQuery = q.Encode()

				req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
				if err != nil {
					continue
				}

				start := time.Now()
				resp, err := f.client.Do(req)
				if err != nil {
					continue
				}
				resp.Body.Close()

				if resp.StatusCode == 200 {
					results = append(results, FuzzResult{
						URL:          u.String(),
						Method:       "GET",
						StatusCode:   resp.StatusCode,
						ResponseTime: time.Since(start),
						Timestamp:    time.Now(),
						Type:         "parameter_pollution",
						Parameters: map[string]interface{}{
							"parameter": paramName,
							"technique": test.name,
							"values":    test.values,
						},
					})
				}
			}
		}
	}

	return results
}

// testArrayParameters tests for array parameter handling
func (f *Fuzzer) testArrayParameters(ctx context.Context, target *url.URL, params []string) []FuzzResult {
	results := []FuzzResult{}

	arrayNotations := []string{
		"%s[]",
		"%s[0]",
		"%s.0",
		"%s*",
		"{%s}",
	}

	for _, param := range params {
		for _, notation := range arrayNotations {
			arrayParam := fmt.Sprintf(notation, param)
			
			u := *target
			q := u.Query()
			q.Set(arrayParam, "test")
			u.RawQuery = q.Encode()

			req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
			if err != nil {
				continue
			}

			resp, err := f.client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == 200 {
				results = append(results, FuzzResult{
					URL:        u.String(),
					Method:     "GET",
					StatusCode: resp.StatusCode,
					Type:       "array_parameter",
					Parameters: map[string]interface{}{
						"original": param,
						"array":    arrayParam,
					},
					Timestamp: time.Now(),
				})
			}
		}
	}

	return results
}

// testJSONParameters tests for JSON parameter acceptance
func (f *Fuzzer) testJSONParameters(ctx context.Context, target *url.URL, params []string) []FuzzResult {
	results := []FuzzResult{}

	// Build JSON payload
	payload := make(map[string]interface{})
	for _, param := range params {
		payload[param] = "test-value"
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return results
	}

	req, err := http.NewRequestWithContext(ctx, "POST", target.String(), strings.NewReader(string(jsonData)))
	if err != nil {
		return results
	}

	req.Header.Set("Content-Type", "application/json")
	
	resp, err := f.client.Do(req)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 400 {
		results = append(results, FuzzResult{
			URL:        target.String(),
			Method:     "POST",
			StatusCode: resp.StatusCode,
			Type:       "json_parameters",
			Parameters: map[string]interface{}{
				"accepts_json": true,
				"parameters":   params,
			},
			Timestamp: time.Now(),
		})
	}

	return results
}

// getRecursiveWordlist returns a smaller wordlist for recursive fuzzing
func (f *Fuzzer) getRecursiveWordlist() []string {
	return []string{
		"admin", "api", "backup", "config", "data", "db", "debug",
		"dev", "files", "images", "include", "js", "lib", "logs",
		"private", "public", "scripts", "src", "static", "temp",
		"test", "tmp", "upload", "uploads", "vendor", "www",
	}
}

// getVHostBaseline gets a baseline response for vhost fuzzing
func (f *Fuzzer) getVHostBaseline(ctx context.Context, target *url.URL, vhost string) (*baselineResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Host = vhost
	req.Header.Set("User-Agent", f.config.UserAgent)
	
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read limited response for baseline
	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	body = body[:n]

	// Convert http.Header to map[string]string
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return &baselineResponse{
		StatusCode: resp.StatusCode,
		Size:       n,
		Headers:    headers,
	}, nil
}

// testVHost tests a virtual host
func (f *Fuzzer) testVHost(ctx context.Context, target *url.URL, vhost, baseDomain string, baseline *baselineResponse) *FuzzResult {
	f.rateLimiter.Wait()

	// Build full vhost
	fullVHost := vhost
	if !strings.Contains(vhost, ".") {
		fullVHost = fmt.Sprintf("%s.%s", vhost, baseDomain)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", target.String(), nil)
	if err != nil {
		return nil
	}

	req.Host = fullVHost
	req.Header.Set("User-Agent", f.config.UserAgent)
	
	start := time.Now()
	resp, err := f.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check if different from baseline
	if resp.StatusCode != baseline.StatusCode {
		return &FuzzResult{
			URL:          target.String(),
			Method:       "GET",
			StatusCode:   resp.StatusCode,
			ResponseTime: time.Since(start),
			Timestamp:    time.Now(),
			Type:         "vhost",
			Parameters: map[string]interface{}{
				"vhost": fullVHost,
			},
		}
	}

	return nil
}

// resolveDomain checks if a domain resolves
func (f *Fuzzer) resolveDomain(domain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	r := &net.Resolver{}
	addrs, err := r.LookupHost(ctx, domain)
	
	return err == nil && len(addrs) > 0
}

// testSubdomain tests if a subdomain is alive and responding
func (f *Fuzzer) testSubdomain(ctx context.Context, target, subdomain string) *FuzzResult {
	f.rateLimiter.Wait()

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", f.config.UserAgent)
	
	start := time.Now()
	resp, err := f.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	return &FuzzResult{
		URL:          target,
		Method:       "GET",
		StatusCode:   resp.StatusCode,
		ResponseTime: time.Since(start),
		Timestamp:    time.Now(),
		Type:         "subdomain",
		Parameters: map[string]interface{}{
			"subdomain": subdomain,
		},
	}
}

// generateSubdomainPermutations creates smart subdomain variations
func (f *Fuzzer) generateSubdomainPermutations(domain string, found []FuzzResult) []string {
	permutations := []string{}
	
	// Extract found subdomain parts
	parts := make(map[string]bool)
	for _, result := range found {
		if sub, ok := result.Parameters["subdomain"].(string); ok {
			subParts := strings.Split(sub, ".")
			for _, part := range subParts {
				parts[part] = true
			}
		}
	}

	// Common patterns
	prefixes := []string{"dev", "staging", "test", "uat", "api", "admin", "portal"}
	suffixes := []string{"01", "02", "1", "2", "new", "old", "backup"}
	
	// Generate combinations
	for part := range parts {
		for _, prefix := range prefixes {
			permutations = append(permutations, fmt.Sprintf("%s-%s.%s", prefix, part, domain))
			permutations = append(permutations, fmt.Sprintf("%s.%s.%s", prefix, part, domain))
		}
		
		for _, suffix := range suffixes {
			permutations = append(permutations, fmt.Sprintf("%s-%s.%s", part, suffix, domain))
			permutations = append(permutations, fmt.Sprintf("%s%s.%s", part, suffix, domain))
		}
	}

	return uniqueStrings(permutations)
}

// Helper function for unique strings
func uniqueStrings(items []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	return result
}