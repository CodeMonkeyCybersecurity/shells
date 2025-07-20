// pkg/fuzzing/advanced.go
package fuzzing

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SmartFuzzer implements advanced fuzzing techniques
type SmartFuzzer struct {
	*Fuzzer
	patterns    *PatternAnalyzer
	heuristics  *HeuristicEngine
	mlPredictor *MLPredictor
}

// NewSmartFuzzer creates an advanced fuzzer with ML and heuristics
func NewSmartFuzzer(config FuzzerConfig, logger Logger) *SmartFuzzer {
	config.SmartMode = true

	return &SmartFuzzer{
		Fuzzer:      NewFuzzer(config, logger),
		patterns:    NewPatternAnalyzer(),
		heuristics:  NewHeuristicEngine(),
		mlPredictor: NewMLPredictor(),
	}
}

// IntelligentParameterDiscovery uses multiple techniques to find parameters
func (s *SmartFuzzer) IntelligentParameterDiscovery(ctx context.Context, target string) ([]FuzzResult, error) {
	s.logger.Info("Starting intelligent parameter discovery", "target", target)

	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	results := []FuzzResult{}

	// 1. Analyze JavaScript for parameter hints
	jsParams := s.extractParametersFromJS(ctx, targetURL)
	results = append(results, s.testExtractedParameters(ctx, targetURL, jsParams)...)

	// 2. Use ML to predict likely parameters based on application type
	predictedParams := s.mlPredictor.PredictParameters(targetURL)
	results = append(results, s.testPredictedParameters(ctx, targetURL, predictedParams)...)

	// 3. Test common parameter patterns
	patternParams := s.patterns.GenerateParameterPatterns(targetURL)
	results = append(results, s.testPatternParameters(ctx, targetURL, patternParams)...)

	// 4. HPP (HTTP Parameter Pollution) testing
	hppResults := s.testParameterPollution(ctx, targetURL, results)
	results = append(results, hppResults...)

	// 5. Parameter type confusion
	typeResults := s.testParameterTypeConfusion(ctx, targetURL, results)
	results = append(results, typeResults...)

	return results, nil
}

// ContentDiscoveryWithContext performs context-aware content discovery
func (s *SmartFuzzer) ContentDiscoveryWithContext(ctx context.Context, target string) ([]FuzzResult, error) {
	s.logger.Info("Starting context-aware content discovery", "target", target)

	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	// Identify application framework
	framework := s.identifyFramework(ctx, targetURL)
	s.logger.Info("Identified framework", "framework", framework)

	// Load framework-specific wordlists
	wordlists := s.getFrameworkWordlists(framework)

	results := []FuzzResult{}

	// Fuzz with each wordlist
	for _, wordlist := range wordlists {
		wlResults, err := s.DirectoryFuzzing(ctx, target, wordlist)
		if err != nil {
			s.logger.Error("Wordlist fuzzing failed", "wordlist", wordlist, "error", err)
			continue
		}
		results = append(results, wlResults...)
	}

	// Apply heuristics to generate new paths
	heuristicPaths := s.heuristics.GeneratePaths(results, framework)
	for _, path := range heuristicPaths {
		if result := s.fuzzDirectory(ctx, targetURL, path); result != nil {
			results = append(results, *result)
		}
	}

	return results, nil
}

// extractParametersFromJS analyzes JavaScript files for parameters
func (s *SmartFuzzer) extractParametersFromJS(ctx context.Context, target *url.URL) []string {
	params := []string{}

	// Common JS file locations
	jsFiles := []string{
		"/js/app.js",
		"/js/main.js",
		"/static/js/bundle.js",
		"/assets/js/app.js",
		"/dist/bundle.js",
	}

	// Regex patterns for parameter extraction
	patterns := []string{
		`['"]([\w]+)['"]\s*:\s*`,  // Object keys
		`\.get\(['"]([\w]+)['"]`,  // jQuery get
		`\$\{([\w]+)\}`,           // Template literals
		`params\.['"]([\w]+)['"]`, // params.something
		`data\.['"]([\w]+)['"]`,   // data.something
	}

	for _, jsPath := range jsFiles {
		jsURL := *target
		jsURL.Path = jsPath

		req, err := http.NewRequestWithContext(ctx, "GET", jsURL.String(), nil)
		if err != nil {
			continue
		}

		resp, err := s.client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		defer resp.Body.Close()

		// Analyze JS content
		// This is simplified - real implementation would use proper JS parsing
		params = append(params, s.patterns.ExtractFromContent(resp.Body, patterns)...)
	}

	return unique(params)
}

// testParameterPollution tests for HTTP Parameter Pollution vulnerabilities
func (s *SmartFuzzer) testParameterPollution(ctx context.Context, target *url.URL, knownParams []FuzzResult) []FuzzResult {
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
				resp, err := s.client.Do(req)
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
func (s *SmartFuzzer) testArrayParameters(ctx context.Context, target *url.URL, params []string) []FuzzResult {
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

			resp, err := s.client.Do(req)
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
func (s *SmartFuzzer) testJSONParameters(ctx context.Context, target *url.URL, params []string) []FuzzResult {
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

	resp, err := s.client.Do(req)
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

// recursiveFuzz performs recursive fuzzing on discovered directories
func (s *SmartFuzzer) recursiveFuzz(ctx context.Context, baseURL *url.URL, found []FuzzResult, depth int) []FuzzResult {
	if depth > s.config.RecursionDepth {
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
			words := s.getRecursiveWordlist()

			for _, word := range words {
				newURL := *foundURL
				newURL.Path = strings.TrimSuffix(newURL.Path, "/") + "/" + word

				if newResult := s.fuzzDirectory(ctx, &newURL, ""); newResult != nil {
					results = append(results, *newResult)
				}
			}

			// Recurse deeper
			if len(results) > 0 {
				deeperResults := s.recursiveFuzz(ctx, baseURL, results, depth+1)
				results = append(results, deeperResults...)
			}
		}
	}

	return results
}

// getVHostBaseline gets a baseline response for vhost fuzzing
func (s *SmartFuzzer) getVHostBaseline(ctx context.Context, target *url.URL, vhost string) (*baselineResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Host = vhost
	req.Header.Set("User-Agent", s.config.UserAgent)

	resp, err := s.client.Do(req)
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
func (s *SmartFuzzer) testVHost(ctx context.Context, target *url.URL, vhost, baseDomain string, baseline *baselineResponse) *FuzzResult {
	s.rateLimiter.Wait()

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
	req.Header.Set("User-Agent", s.config.UserAgent)

	start := time.Now()
	resp, err := s.client.Do(req)
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
func (s *SmartFuzzer) resolveDomain(domain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	r := &net.Resolver{}
	addrs, err := r.LookupHost(ctx, domain)

	return err == nil && len(addrs) > 0
}

// testSubdomain tests if a subdomain is alive and responding
func (s *SmartFuzzer) testSubdomain(ctx context.Context, target, subdomain string) *FuzzResult {
	s.rateLimiter.Wait()

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.config.UserAgent)

	start := time.Now()
	resp, err := s.client.Do(req)
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
func (s *SmartFuzzer) generateSubdomainPermutations(domain string, found []FuzzResult) []string {
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

	return unique(permutations)
}

// identifyFramework attempts to identify the web framework
func (s *SmartFuzzer) identifyFramework(ctx context.Context, target *url.URL) string {
	req, err := http.NewRequestWithContext(ctx, "GET", target.String(), nil)
	if err != nil {
		return "unknown"
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()

	// Check headers
	headers := map[string]string{
		"X-Powered-By":     resp.Header.Get("X-Powered-By"),
		"Server":           resp.Header.Get("Server"),
		"X-AspNet-Version": resp.Header.Get("X-AspNet-Version"),
	}

	// Framework detection logic
	if strings.Contains(headers["X-Powered-By"], "Express") {
		return "express"
	}
	if strings.Contains(headers["X-Powered-By"], "PHP") {
		return "php"
	}
	if headers["X-AspNet-Version"] != "" {
		return "aspnet"
	}
	if strings.Contains(headers["Server"], "nginx") {
		return "nginx"
	}
	if strings.Contains(headers["Server"], "Apache") {
		return "apache"
	}

	return "generic"
}

// getFrameworkWordlists returns framework-specific wordlists
func (s *SmartFuzzer) getFrameworkWordlists(framework string) []string {
	baseWordlists := []string{"common.txt", "directories.txt"}

	frameworkWordlists := map[string][]string{
		"php":     {"php.txt", "phpmyadmin.txt"},
		"aspnet":  {"aspnet.txt", "iis.txt"},
		"express": {"nodejs.txt", "npm.txt"},
		"nginx":   {"nginx.txt"},
		"apache":  {"apache.txt"},
	}

	if specific, ok := frameworkWordlists[framework]; ok {
		return append(baseWordlists, specific...)
	}

	return baseWordlists
}

// getRecursiveWordlist returns a smaller wordlist for recursive fuzzing
func (s *SmartFuzzer) getRecursiveWordlist() []string {
	return []string{
		"admin", "api", "backup", "config", "data", "db", "debug",
		"dev", "files", "images", "include", "js", "lib", "logs",
		"private", "public", "scripts", "src", "static", "temp",
		"test", "tmp", "upload", "uploads", "vendor", "www",
	}
}

// testParameterTypeConfusion tests parameter type confusion vulnerabilities
func (s *SmartFuzzer) testParameterTypeConfusion(ctx context.Context, target *url.URL, knownParams []FuzzResult) []FuzzResult {
	results := []FuzzResult{}

	typeTests := []struct {
		name  string
		value string
	}{
		{"integer", "1"},
		{"negative", "-1"},
		{"float", "1.5"},
		{"boolean_true", "true"},
		{"boolean_false", "false"},
		{"null", "null"},
		{"empty", ""},
		{"large_number", "999999999999"},
		{"hex", "0xff"},
		{"scientific", "1e10"},
	}

	for _, param := range knownParams {
		if paramName, ok := param.Parameters["name"].(string); ok {
			for _, test := range typeTests {
				u := *target
				q := u.Query()
				q.Set(paramName, test.value)
				u.RawQuery = q.Encode()

				req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
				if err != nil {
					continue
				}

				resp, err := s.client.Do(req)
				if err != nil {
					continue
				}
				resp.Body.Close()

				// Look for errors or different behavior
				if resp.StatusCode >= 400 && resp.StatusCode < 600 {
					results = append(results, FuzzResult{
						URL:        u.String(),
						Method:     "GET",
						StatusCode: resp.StatusCode,
						Type:       "type_confusion",
						Parameters: map[string]interface{}{
							"parameter": paramName,
							"type":      test.name,
							"value":     test.value,
						},
						Timestamp: time.Now(),
					})
				}
			}
		}
	}

	return results
}

// Helper functions

// testExtractedParameters tests parameters extracted from JavaScript
func (s *SmartFuzzer) testExtractedParameters(ctx context.Context, target *url.URL, params []string) []FuzzResult {
	results := []FuzzResult{}

	for _, param := range params {
		u := *target
		q := u.Query()
		q.Set(param, "extracted-test")
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", s.config.UserAgent)

		start := time.Now()
		resp, err := s.client.Do(req)
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
				Type:         "extracted_parameter",
				Parameters: map[string]interface{}{
					"name":   param,
					"source": "javascript",
				},
			})
		}
	}

	return results
}

// testPredictedParameters tests ML-predicted parameters
func (s *SmartFuzzer) testPredictedParameters(ctx context.Context, target *url.URL, params []string) []FuzzResult {
	results := []FuzzResult{}

	for _, param := range params {
		u := *target
		q := u.Query()
		q.Set(param, "predicted-test")
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", s.config.UserAgent)

		start := time.Now()
		resp, err := s.client.Do(req)
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
				Type:         "predicted_parameter",
				Parameters: map[string]interface{}{
					"name":   param,
					"source": "ml_prediction",
				},
			})
		}
	}

	return results
}

// testPatternParameters tests pattern-generated parameters
func (s *SmartFuzzer) testPatternParameters(ctx context.Context, target *url.URL, params []string) []FuzzResult {
	results := []FuzzResult{}

	for _, param := range params {
		u := *target
		q := u.Query()
		q.Set(param, "pattern-test")
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", s.config.UserAgent)

		start := time.Now()
		resp, err := s.client.Do(req)
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
				Type:         "pattern_parameter",
				Parameters: map[string]interface{}{
					"name":   param,
					"source": "pattern_analysis",
				},
			})
		}
	}

	return results
}

func unique(items []string) []string {
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
