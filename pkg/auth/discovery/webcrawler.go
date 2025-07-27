// pkg/auth/discovery/webcrawler.go
package discovery

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/PuerkitoBio/goquery"
)

// WebCrawler intelligently crawls websites looking for authentication endpoints
type WebCrawler struct {
	logger          *logger.Logger
	httpClient      *http.Client
	visited         map[string]bool
	visitedMutex    sync.RWMutex
	maxDepth        int
	maxPages        int
	authPatterns    []string
	excludePatterns []string
}

// CrawlResult represents a discovered page with authentication potential
type CrawlResult struct {
	URL            string
	Title          string
	Forms          []FormInfo
	Links          []string
	Scripts        []string
	MetaTags       map[string]string
	Headers        http.Header
	StatusCode     int
	AuthIndicators []string
	Confidence     float64
}

// FormInfo contains detailed information about HTML forms
type FormInfo struct {
	Action           string
	Method           string
	Fields           []FormField
	HasPasswordField bool
	HasEmailField    bool
	HasUsernameField bool
	IsLoginForm      bool
	Confidence       float64
}

// FormField represents a form input field
type FormField struct {
	Name        string
	Type        string
	ID          string
	Placeholder string
	Label       string
	Required    bool
}

func NewWebCrawler(logger *logger.Logger) *WebCrawler {
	return &WebCrawler{
		logger:   logger,
		visited:  make(map[string]bool),
		maxDepth: 3,
		maxPages: 100,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// We want to know about redirects for auth detection
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		// These patterns indicate authentication-related pages
		authPatterns: []string{
			"login", "signin", "sign-in", "auth", "authenticate",
			"logon", "account", "user", "member", "portal",
			"sso", "saml", "oauth", "oidc", "cas",
			"password", "credential", "identity", "secure",
			"admin", "dashboard", "console", "panel",
		},
		// Exclude these to avoid wasting time
		excludePatterns: []string{
			"logout", "signout", "exit", "forgot", "reset",
			"register", "signup", "join", "create",
			".pdf", ".jpg", ".png", ".gif", ".css", ".js",
			"terms", "privacy", "about", "contact", "blog",
		},
	}
}

// FindAuthPages discovers pages likely to contain authentication
func (w *WebCrawler) FindAuthPages(ctx context.Context, baseURL string) []CrawlResult {
	w.logger.Info("Starting web crawl for auth endpoints",
		"baseURL", baseURL,
		"maxDepth", w.maxDepth,
		"maxPages", w.maxPages)

	var authPages []CrawlResult
	var mu sync.Mutex

	// Parse base URL to ensure we stay on the same domain
	baseParsed, err := url.Parse(baseURL)
	if err != nil {
		w.logger.Error("Failed to parse base URL", "error", err)
		return authPages
	}

	// Start crawling from the base URL
	w.crawlPage(ctx, baseURL, baseParsed, 0, &authPages, &mu)

	// Also check common auth paths directly
	commonPaths := w.generateCommonAuthPaths(baseURL)
	for _, path := range commonPaths {
		if w.shouldVisit(path) {
			if result := w.analyzePage(ctx, path); result != nil && result.Confidence > 0.5 {
				mu.Lock()
				authPages = append(authPages, *result)
				mu.Unlock()
			}
		}
	}

	w.logger.Info("Web crawl completed",
		"totalPages", len(w.visited),
		"authPages", len(authPages))

	return authPages
}

// generateCommonAuthPaths generates common authentication paths to check
func (w *WebCrawler) generateCommonAuthPaths(baseURL string) []string {
	commonPaths := []string{
		"/login", "/signin", "/sign-in", "/auth", "/authenticate",
		"/admin", "/admin/login", "/wp-login.php", "/wp-admin",
		"/user/login", "/users/sign_in", "/account/login",
		"/oauth/authorize", "/oauth2/authorize", "/connect/authorize",
		"/saml/login", "/saml/sso", "/sso", "/sso/login",
		"/.well-known/openid-configuration", "/openid/login",
		"/api/auth", "/api/login", "/api/v1/auth",
		"/auth/login", "/auth/signin", "/authentication",
		"/portal", "/portal/login", "/customer/login",
		"/secure", "/secure/login", "/security/login",
	}

	var fullPaths []string
	for _, path := range commonPaths {
		fullPaths = append(fullPaths, baseURL+path)
	}

	return fullPaths
}

// crawlPage recursively crawls pages looking for auth endpoints
func (w *WebCrawler) crawlPage(ctx context.Context, pageURL string, baseDomain *url.URL, depth int, results *[]CrawlResult, mu *sync.Mutex) {
	// Check termination conditions
	if depth > w.maxDepth || len(w.visited) >= w.maxPages {
		return
	}

	// Check if we should visit this URL
	if !w.shouldVisit(pageURL) {
		return
	}

	// Mark as visited
	w.visitedMutex.Lock()
	w.visited[pageURL] = true
	w.visitedMutex.Unlock()

	// Analyze the page
	result := w.analyzePage(ctx, pageURL)
	if result == nil {
		return
	}

	// If this looks like an auth page, add it to results
	if result.Confidence > 0.5 {
		mu.Lock()
		*results = append(*results, *result)
		mu.Unlock()

		w.logger.Debug("Found potential auth page",
			"url", pageURL,
			"confidence", result.Confidence,
			"indicators", result.AuthIndicators)
	}

	// Crawl links from this page
	var wg sync.WaitGroup
	for _, link := range result.Links {
		// Ensure we stay on the same domain
		linkParsed, err := url.Parse(link)
		if err != nil || linkParsed.Host != baseDomain.Host {
			continue
		}

		wg.Add(1)
		go func(nextURL string) {
			defer wg.Done()
			w.crawlPage(ctx, nextURL, baseDomain, depth+1, results, mu)
		}(link)
	}
	wg.Wait()
}

// analyzePage analyzes a single page for authentication indicators
func (w *WebCrawler) analyzePage(ctx context.Context, pageURL string) *CrawlResult {
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return nil
	}
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Don't analyze non-HTML content
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "html") {
		return nil
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil
	}

	result := &CrawlResult{
		URL:            pageURL,
		StatusCode:     resp.StatusCode,
		Headers:        resp.Header,
		MetaTags:       make(map[string]string),
		AuthIndicators: []string{},
	}

	// Extract title
	result.Title = doc.Find("title").First().Text()

	// Extract meta tags
	doc.Find("meta").Each(func(i int, s *goquery.Selection) {
		if name, exists := s.Attr("name"); exists {
			if content, exists := s.Attr("content"); exists {
				result.MetaTags[name] = content
			}
		}
	})

	// Analyze forms
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		if form := w.analyzeForm(s, pageURL); form != nil {
			result.Forms = append(result.Forms, *form)
			if form.IsLoginForm {
				result.AuthIndicators = append(result.AuthIndicators, "login_form")
			}
		}
	})

	// Extract links for further crawling
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			if parsedPage, err := url.Parse(pageURL); err == nil {
				if absURL := w.resolveURL(parsedPage, href); absURL != "" {
					result.Links = append(result.Links, absURL)
				}
			}
		}
	})

	// Extract script sources
	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists {
			result.Scripts = append(result.Scripts, src)
		}
	})

	// Check for auth-related content
	bodyText := strings.ToLower(doc.Text())
	for _, pattern := range w.authPatterns {
		if strings.Contains(bodyText, pattern) {
			result.AuthIndicators = append(result.AuthIndicators, "keyword:"+pattern)
		}
	}

	// Check URL for auth patterns
	lowerURL := strings.ToLower(pageURL)
	for _, pattern := range w.authPatterns {
		if strings.Contains(lowerURL, pattern) {
			result.AuthIndicators = append(result.AuthIndicators, "url:"+pattern)
		}
	}

	// Calculate confidence score
	result.Confidence = w.calculateAuthConfidence(result)

	return result
}

// analyzeForm examines a form for authentication characteristics
func (w *WebCrawler) analyzeForm(form *goquery.Selection, pageURL string) *FormInfo {
	info := &FormInfo{
		Fields: []FormField{},
	}

	// Get form attributes
	info.Action, _ = form.Attr("action")
	info.Method, _ = form.Attr("method")
	if info.Method == "" {
		info.Method = "GET"
	}

	// Resolve action URL
	if info.Action != "" {
		if parsedPage, err := url.Parse(pageURL); err == nil {
			info.Action = w.resolveURL(parsedPage, info.Action)
		}
	} else {
		info.Action = pageURL
	}

	// Analyze form fields
	form.Find("input, select, textarea").Each(func(i int, s *goquery.Selection) {
		field := FormField{}
		field.Name, _ = s.Attr("name")
		field.Type, _ = s.Attr("type")
		field.ID, _ = s.Attr("id")
		field.Placeholder, _ = s.Attr("placeholder")
		_, field.Required = s.Attr("required")

		// Try to find associated label
		if field.ID != "" {
			label := form.Find(fmt.Sprintf("label[for='%s']", field.ID))
			field.Label = strings.TrimSpace(label.Text())
		}

		// Detect field purpose
		lowerName := strings.ToLower(field.Name)
		lowerPlaceholder := strings.ToLower(field.Placeholder)
		lowerLabel := strings.ToLower(field.Label)

		// Check for password fields
		if field.Type == "password" ||
			strings.Contains(lowerName, "pass") ||
			strings.Contains(lowerPlaceholder, "pass") {
			info.HasPasswordField = true
		}

		// Check for username fields
		if strings.Contains(lowerName, "user") ||
			strings.Contains(lowerName, "login") ||
			strings.Contains(lowerPlaceholder, "username") ||
			strings.Contains(lowerLabel, "username") {
			info.HasUsernameField = true
		}

		// Check for email fields
		if field.Type == "email" ||
			strings.Contains(lowerName, "email") ||
			strings.Contains(lowerPlaceholder, "email") {
			info.HasEmailField = true
		}

		info.Fields = append(info.Fields, field)
	})

	// Determine if this is likely a login form
	info.IsLoginForm = (info.HasPasswordField && (info.HasUsernameField || info.HasEmailField)) ||
		(len(info.Fields) >= 2 && info.HasPasswordField)

	// Calculate form confidence
	if info.IsLoginForm {
		info.Confidence = 0.9
	} else if info.HasPasswordField {
		info.Confidence = 0.6
	} else if len(info.Fields) > 0 {
		info.Confidence = 0.3
	}

	return info
}

// Additional helper methods...
func (w *WebCrawler) shouldVisit(urlStr string) bool {
	w.visitedMutex.RLock()
	defer w.visitedMutex.RUnlock()

	// Already visited?
	if w.visited[urlStr] {
		return false
	}

	// Check exclude patterns
	lowerURL := strings.ToLower(urlStr)
	for _, pattern := range w.excludePatterns {
		if strings.Contains(lowerURL, pattern) {
			return false
		}
	}

	return true
}

// CrawlForAuth performs authentication-focused crawling
func (w *WebCrawler) CrawlForAuth(ctx context.Context, url string, maxDepth int) ([]WebPage, error) {
	w.maxDepth = maxDepth
	var allPages []WebPage

	// Reset visited state for this crawl
	w.visitedMutex.Lock()
	w.visited = make(map[string]bool)
	w.visitedMutex.Unlock()

	// Find auth pages using existing discovery logic
	authPages := w.FindAuthPages(ctx, url)

	// Convert CrawlResult to WebPage
	for _, page := range authPages {
		// Fetch the actual content for each auth page
		content, err := w.fetchPageContent(ctx, page.URL)
		if err != nil {
			w.logger.Debug("Failed to fetch page content", "url", page.URL, "error", err)
			continue
		}

		webPage := WebPage{
			URL:     page.URL,
			Content: content,
		}
		allPages = append(allPages, webPage)
	}

	// Also fetch the main page content
	if mainContent, err := w.fetchPageContent(ctx, url); err == nil {
		mainPage := WebPage{
			URL:     url,
			Content: mainContent,
		}
		allPages = append(allPages, mainPage)
	}

	return allPages, nil
}

// fetchPageContent fetches the HTML content of a page
func (w *WebCrawler) fetchPageContent(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Only process HTML content
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "html") {
		return "", fmt.Errorf("not HTML content")
	}

	// Read the body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(bodyBytes), nil
}

func (w *WebCrawler) calculateAuthConfidence(result *CrawlResult) float64 {
	confidence := 0.0

	// Forms are strong indicators
	for _, form := range result.Forms {
		if form.IsLoginForm {
			confidence += 0.5
		}
	}

	// Auth keywords in various places
	indicatorWeight := 0.1
	confidence += float64(len(result.AuthIndicators)) * indicatorWeight

	// Specific patterns boost confidence
	urlLower := strings.ToLower(result.URL)
	if strings.Contains(urlLower, "/login") || strings.Contains(urlLower, "/signin") {
		confidence += 0.3
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// resolveURL resolves a relative URL to absolute
func (w *WebCrawler) resolveURL(baseURL *url.URL, relativeURL string) string {
	relURL, err := url.Parse(relativeURL)
	if err != nil {
		return ""
	}
	return baseURL.ResolveReference(relURL).String()
}
