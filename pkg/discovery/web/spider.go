package web

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/PuerkitoBio/goquery"
)

// WebSpider crawls websites and discovers assets
type WebSpider struct {
	client      *http.Client
	logger      *logger.Logger
	maxDepth    int
	concurrency int
	visited     map[string]bool
	visitedLock sync.RWMutex
	scope       []string
}

// NewWebSpider creates a new web spider
func NewWebSpider(logger *logger.Logger) *WebSpider {
	return &WebSpider{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
			},
		},
		logger:      logger,
		maxDepth:    3,
		concurrency: 10,
		visited:     make(map[string]bool),
		scope:       []string{},
	}
}

// CrawlResult represents a discovered asset from crawling
type CrawlResult struct {
	URL          string
	Title        string
	StatusCode   int
	Headers      http.Header
	Links        []string
	Forms        []FormInfo
	Scripts      []string
	APIs         []string
	Emails       []string
	Comments     []string
	Subdomains   []string
	Technologies []string
}

// FormInfo represents an HTML form
type FormInfo struct {
	Action string
	Method string
	Inputs []InputInfo
}

// InputInfo represents a form input
type InputInfo struct {
	Name  string
	Type  string
	Value string
}

// Crawl starts crawling from a URL
func (s *WebSpider) Crawl(ctx context.Context, startURL string) ([]CrawlResult, error) {
	// Parse start URL to determine scope
	u, err := url.Parse(startURL)
	if err != nil {
		return nil, err
	}

	s.scope = []string{u.Host}

	// Add variations to scope
	if strings.HasPrefix(u.Host, "www.") {
		s.scope = append(s.scope, strings.TrimPrefix(u.Host, "www."))
	} else {
		s.scope = append(s.scope, "www."+u.Host)
	}

	results := make([]CrawlResult, 0)
	resultsChan := make(chan CrawlResult, 100)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.concurrency)

	// Start crawling
	wg.Add(1)
	go s.crawlURL(ctx, startURL, 0, &wg, semaphore, resultsChan)

	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		results = append(results, result)
	}

	s.logger.Info("Web crawling completed",
		"start_url", startURL,
		"pages_crawled", len(results),
		"unique_urls", len(s.visited))

	return results, nil
}

// crawlURL crawls a single URL
func (s *WebSpider) crawlURL(ctx context.Context, urlStr string, depth int, wg *sync.WaitGroup, sem chan struct{}, results chan<- CrawlResult) {
	defer wg.Done()

	// Check depth
	if depth > s.maxDepth {
		return
	}

	// Check if already visited
	s.visitedLock.Lock()
	if s.visited[urlStr] {
		s.visitedLock.Unlock()
		return
	}
	s.visited[urlStr] = true
	s.visitedLock.Unlock()

	// Acquire semaphore
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return
	}

	// Fetch the page
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer httpclient.CloseBody(resp)

	// Read body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		return
	}

	// Parse the page
	result := s.parsePage(urlStr, resp, body)

	select {
	case results <- result:
	case <-ctx.Done():
		return
	}

	// Crawl discovered links
	for _, link := range result.Links {
		if s.isInScope(link) {
			wg.Add(1)
			go s.crawlURL(ctx, link, depth+1, wg, sem, results)
		}
	}
}

// parsePage parses HTML and extracts information
func (s *WebSpider) parsePage(urlStr string, resp *http.Response, body []byte) CrawlResult {
	result := CrawlResult{
		URL:          urlStr,
		StatusCode:   resp.StatusCode,
		Headers:      resp.Header,
		Links:        []string{},
		Forms:        []FormInfo{},
		Scripts:      []string{},
		APIs:         []string{},
		Emails:       []string{},
		Comments:     []string{},
		Subdomains:   []string{},
		Technologies: []string{},
	}

	// Parse HTML
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		return result
	}

	// Extract title
	result.Title = doc.Find("title").Text()

	// Extract links
	doc.Find("a[href]").Each(func(i int, sel *goquery.Selection) {
		if href, exists := sel.Attr("href"); exists {
			if absURL := s.resolveURL(urlStr, href); absURL != "" {
				result.Links = append(result.Links, absURL)
			}
		}
	})

	// Extract forms
	doc.Find("form").Each(func(i int, sel *goquery.Selection) {
		form := FormInfo{
			Inputs: []InputInfo{},
		}

		if action, exists := sel.Attr("action"); exists {
			form.Action = s.resolveURL(urlStr, action)
		}

		if method, exists := sel.Attr("method"); exists {
			form.Method = strings.ToUpper(method)
		} else {
			form.Method = "GET"
		}

		sel.Find("input").Each(func(j int, input *goquery.Selection) {
			inputInfo := InputInfo{}
			if name, exists := input.Attr("name"); exists {
				inputInfo.Name = name
			}
			if inputType, exists := input.Attr("type"); exists {
				inputInfo.Type = inputType
			}
			if value, exists := input.Attr("value"); exists {
				inputInfo.Value = value
			}
			form.Inputs = append(form.Inputs, inputInfo)
		})

		result.Forms = append(result.Forms, form)
	})

	// Extract scripts
	doc.Find("script[src]").Each(func(i int, sel *goquery.Selection) {
		if src, exists := sel.Attr("src"); exists {
			if absURL := s.resolveURL(urlStr, src); absURL != "" {
				result.Scripts = append(result.Scripts, absURL)
			}
		}
	})

	// Extract from JavaScript
	s.extractFromJS(string(body), &result)

	// Extract emails
	result.Emails = s.extractEmails(string(body))

	// Extract HTML comments
	result.Comments = s.extractComments(string(body))

	// Extract subdomains
	result.Subdomains = s.extractSubdomains(string(body), urlStr)

	// Detect technologies
	result.Technologies = s.detectTechnologies(resp.Header, string(body))

	return result
}

// extractFromJS extracts information from JavaScript
func (s *WebSpider) extractFromJS(body string, result *CrawlResult) {
	// API endpoint patterns
	apiPatterns := []string{
		`["']/(api|v\d+)/[^"']*["']`,
		`["'](https?://[^"']*/(api|v\d+)/[^"']*)["']`,
		`fetch\s*\(\s*["']([^"']+)["']`,
		`axios\.\w+\s*\(\s*["']([^"']+)["']`,
		`\$\.ajax\s*\(\s*{[^}]*url\s*:\s*["']([^"']+)["']`,
		`XMLHttpRequest.*open\s*\([^,]+,\s*["']([^"']+)["']`,
	}

	for _, pattern := range apiPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 0 {
				api := match[len(match)-1]
				if s.isValidAPI(api) {
					result.APIs = append(result.APIs, api)
				}
			}
		}
	}

	// Extract hardcoded URLs
	urlPattern := regexp.MustCompile(`["'](https?://[^"']+)["']`)
	urls := urlPattern.FindAllStringSubmatch(body, -1)
	for _, match := range urls {
		if len(match) > 1 {
			result.Links = append(result.Links, match[1])
		}
	}
}

// extractEmails extracts email addresses
func (s *WebSpider) extractEmails(body string) []string {
	emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	emails := emailPattern.FindAllString(body, -1)

	uniqueEmails := make(map[string]bool)
	for _, email := range emails {
		uniqueEmails[strings.ToLower(email)] = true
	}

	result := make([]string, 0, len(uniqueEmails))
	for email := range uniqueEmails {
		result = append(result, email)
	}

	return result
}

// extractComments extracts HTML comments
func (s *WebSpider) extractComments(body string) []string {
	commentPattern := regexp.MustCompile(`<!--\s*([^-]+)\s*-->`)
	matches := commentPattern.FindAllStringSubmatch(body, -1)

	var comments []string
	for _, match := range matches {
		if len(match) > 1 {
			comment := strings.TrimSpace(match[1])
			if comment != "" && !strings.Contains(comment, "[if") {
				comments = append(comments, comment)
			}
		}
	}

	return comments
}

// extractSubdomains extracts subdomains from content
func (s *WebSpider) extractSubdomains(body string, baseURL string) []string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return []string{}
	}

	baseDomain := s.getBaseDomain(u.Host)
	subdomainPattern := regexp.MustCompile(`\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+` + regexp.QuoteMeta(baseDomain) + `\b`)

	matches := subdomainPattern.FindAllString(body, -1)

	uniqueSubs := make(map[string]bool)
	for _, match := range matches {
		if match != baseDomain && match != "www."+baseDomain {
			uniqueSubs[match] = true
		}
	}

	result := make([]string, 0, len(uniqueSubs))
	for sub := range uniqueSubs {
		result = append(result, sub)
	}

	return result
}

// detectTechnologies detects technologies from headers and content
func (s *WebSpider) detectTechnologies(headers http.Header, body string) []string {
	var technologies []string

	// Check headers
	if server := headers.Get("Server"); server != "" {
		technologies = append(technologies, s.parseServerHeader(server)...)
	}

	if powered := headers.Get("X-Powered-By"); powered != "" {
		technologies = append(technologies, powered)
	}

	// Check for frameworks in HTML
	frameworks := map[string][]string{
		"WordPress":     {`<meta name="generator" content="WordPress`, `/wp-content/`, `/wp-includes/`},
		"Drupal":        {`<meta name="Generator" content="Drupal`, `/sites/default/`, `drupal.js`},
		"Joomla":        {`<meta name="generator" content="Joomla`, `/components/com_`, `/templates/`},
		"Angular":       {`ng-app=`, `angular.js`, `angular.min.js`},
		"React":         {`react.js`, `react.min.js`, `_react`, `React.createElement`},
		"Vue.js":        {`vue.js`, `vue.min.js`, `new Vue({`},
		"jQuery":        {`jquery.js`, `jquery.min.js`, `jQuery(`, `$(document).ready`},
		"Bootstrap":     {`bootstrap.css`, `bootstrap.min.css`, `bootstrap.js`},
		"Laravel":       {`laravel_session`, `csrf-token`},
		"Django":        {`django`, `csrfmiddlewaretoken`},
		"Ruby on Rails": {`<meta name="csrf-param"`, `X-CSRF-Token`},
		"ASP.NET":       {`ASP.NET`, `__VIEWSTATE`, `.aspx`},
		"Spring":        {`spring`, `JSESSIONID`},
	}

	for tech, patterns := range frameworks {
		for _, pattern := range patterns {
			if strings.Contains(body, pattern) {
				technologies = append(technologies, tech)
				break
			}
		}
	}

	// Remove duplicates
	uniqueTech := make(map[string]bool)
	for _, tech := range technologies {
		uniqueTech[tech] = true
	}

	result := make([]string, 0, len(uniqueTech))
	for tech := range uniqueTech {
		result = append(result, tech)
	}

	return result
}

// Helper methods

func (s *WebSpider) resolveURL(base, href string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}

	hrefURL, err := url.Parse(href)
	if err != nil {
		return ""
	}

	return baseURL.ResolveReference(hrefURL).String()
}

func (s *WebSpider) isInScope(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	for _, scopeHost := range s.scope {
		if u.Host == scopeHost || strings.HasSuffix(u.Host, "."+scopeHost) {
			return true
		}
	}

	return false
}

func (s *WebSpider) isValidAPI(api string) bool {
	// Basic validation for API endpoints
	if strings.HasPrefix(api, "/") || strings.HasPrefix(api, "http") {
		return true
	}
	return false
}

func (s *WebSpider) getBaseDomain(host string) string {
	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Remove subdomains (simplified)
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}

	return host
}

func (s *WebSpider) parseServerHeader(server string) []string {
	var technologies []string

	// Common server technologies
	servers := map[string][]string{
		"nginx":     {"nginx"},
		"Apache":    {"Apache"},
		"IIS":       {"Microsoft-IIS", "IIS"},
		"Tomcat":    {"Tomcat"},
		"Jetty":     {"Jetty"},
		"WebLogic":  {"WebLogic"},
		"WebSphere": {"WebSphere"},
		"JBoss":     {"JBoss"},
		"GlassFish": {"GlassFish"},
		"Kestrel":   {"Kestrel"},
		"Gunicorn":  {"gunicorn"},
		"uWSGI":     {"uWSGI"},
		"Caddy":     {"Caddy"},
		"LiteSpeed": {"LiteSpeed"},
		"OpenResty": {"openresty"},
		"Tengine":   {"Tengine"},
		"Cowboy":    {"Cowboy"},
		"Puma":      {"Puma"},
		"Thin":      {"Thin"},
		"Unicorn":   {"Unicorn"},
		"Passenger": {"Phusion Passenger", "Passenger"},
		"Express":   {"Express"},
		"Werkzeug":  {"Werkzeug"},
	}

	lowerServer := strings.ToLower(server)
	for tech, patterns := range servers {
		for _, pattern := range patterns {
			if strings.Contains(lowerServer, strings.ToLower(pattern)) {
				technologies = append(technologies, tech)
				break
			}
		}
	}

	return technologies
}

// SetMaxDepth sets the maximum crawl depth
func (s *WebSpider) SetMaxDepth(depth int) {
	s.maxDepth = depth
}

// SetConcurrency sets the concurrency level
func (s *WebSpider) SetConcurrency(concurrency int) {
	s.concurrency = concurrency
}

// AddToScope adds a domain to the crawl scope
func (s *WebSpider) AddToScope(domain string) {
	s.scope = append(s.scope, domain)
}
