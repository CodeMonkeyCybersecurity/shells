package search

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// SearchEngine interface for different search providers
type SearchEngine interface {
	Search(ctx context.Context, query string) ([]SearchResult, error)
	Name() string
}

// SearchResult represents a search result
type SearchResult struct {
	Title       string
	URL         string
	Description string
	Domain      string
}

// MultiSearchEngine combines multiple search engines
type MultiSearchEngine struct {
	engines []SearchEngine
	logger  *logger.Logger
}

// NewMultiSearchEngine creates a new multi-engine searcher
func NewMultiSearchEngine(logger *logger.Logger) *MultiSearchEngine {
	return &MultiSearchEngine{
		engines: []SearchEngine{
			NewCommonCrawlEngine(logger), // Free and unrestricted
			NewDuckDuckGoEngine(logger),   // Has API
			NewBingEngine(logger),         // Requires API key
			// Google disabled due to ToS restrictions
		},
		logger: logger,
	}
}

// SearchAll searches across all engines
func (m *MultiSearchEngine) SearchAll(ctx context.Context, query string) []SearchResult {
	var allResults []SearchResult
	seen := make(map[string]bool)

	for _, engine := range m.engines {
		results, err := engine.Search(ctx, query)
		if err != nil {
			m.logger.Debug("Search engine failed", "engine", engine.Name(), "error", err)
			continue
		}

		for _, result := range results {
			if !seen[result.URL] {
				seen[result.URL] = true
				allResults = append(allResults, result)
			}
		}
	}

	return allResults
}

// GoogleDorkEngine implements Google dorking
type GoogleDorkEngine struct {
	client *http.Client
	logger *logger.Logger
}

// NewGoogleDorkEngine creates a new Google dork engine
func NewGoogleDorkEngine(logger *logger.Logger) *GoogleDorkEngine {
	return &GoogleDorkEngine{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

func (g *GoogleDorkEngine) Name() string {
	return "google_dork"
}

func (g *GoogleDorkEngine) Search(ctx context.Context, query string) ([]SearchResult, error) {
	// Note: Google actively blocks automated searches. This is for educational purposes.
	// In production, use Google Custom Search API with proper API key.
	g.logger.Debug("Google search disabled to comply with ToS", "query", query)
	return []SearchResult{}, nil
}

// BingEngine implements Bing search
type BingEngine struct {
	client *http.Client
	logger *logger.Logger
	apiKey string
}

// NewBingEngine creates a new Bing search engine
func NewBingEngine(logger *logger.Logger) *BingEngine {
	return &BingEngine{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
		apiKey: "", // Would be set from config
	}
}

func (b *BingEngine) Name() string {
	return "bing"
}

func (b *BingEngine) Search(ctx context.Context, query string) ([]SearchResult, error) {
	if b.apiKey == "" {
		// Fallback to web scraping
		return b.searchWithoutAPI(ctx, query)
	}
	
	// Use Bing Search API
	searchURL := fmt.Sprintf("https://api.bing.microsoft.com/v7.0/search?q=%s&count=50", url.QueryEscape(query))
	
	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Ocp-Apim-Subscription-Key", b.apiKey)
	
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var bingResp struct {
		WebPages struct {
			Value []struct {
				Name        string `json:"name"`
				URL         string `json:"url"`
				DisplayUrl  string `json:"displayUrl"`
				Snippet     string `json:"snippet"`
			} `json:"value"`
		} `json:"webPages"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&bingResp); err != nil {
		return nil, err
	}
	
	var results []SearchResult
	for _, page := range bingResp.WebPages.Value {
		result := SearchResult{
			Title:       page.Name,
			URL:         page.URL,
			Description: page.Snippet,
			Domain:      extractDomain(page.URL),
		}
		results = append(results, result)
	}
	
	return results, nil
}

func (b *BingEngine) searchWithoutAPI(ctx context.Context, query string) ([]SearchResult, error) {
	// Note: Web scraping search engines may violate ToS
	// This implementation is for educational purposes only
	b.logger.Debug("Bing search requires API key", "query", query)
	return []SearchResult{}, nil
}

// DuckDuckGoEngine implements DuckDuckGo search
type DuckDuckGoEngine struct {
	client *http.Client
	logger *logger.Logger
}

// NewDuckDuckGoEngine creates a new DuckDuckGo search engine
func NewDuckDuckGoEngine(logger *logger.Logger) *DuckDuckGoEngine {
	return &DuckDuckGoEngine{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

func (d *DuckDuckGoEngine) Name() string {
	return "duckduckgo"
}

func (d *DuckDuckGoEngine) Search(ctx context.Context, query string) ([]SearchResult, error) {
	// Use DuckDuckGo's instant answer API
	apiURL := fmt.Sprintf("https://api.duckduckgo.com/?q=%s&format=json&no_html=1", url.QueryEscape(query))
	
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var ddgResp struct {
		RelatedTopics []struct {
			FirstURL string `json:"FirstURL"`
			Text     string `json:"Text"`
		} `json:"RelatedTopics"`
		Results []struct {
			FirstURL string `json:"FirstURL"`
			Text     string `json:"Text"`
		} `json:"Results"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&ddgResp); err != nil {
		return nil, err
	}
	
	var results []SearchResult
	
	// Process direct results
	for _, r := range ddgResp.Results {
		if r.FirstURL != "" {
			results = append(results, SearchResult{
				Title:       extractTitle(r.Text),
				URL:         r.FirstURL,
				Description: r.Text,
				Domain:      extractDomain(r.FirstURL),
			})
		}
	}
	
	return results, nil
}

// DorkGenerator generates search dorks for a target
type DorkGenerator struct {
	logger *logger.Logger
}

// NewDorkGenerator creates a new dork generator
func NewDorkGenerator(logger *logger.Logger) *DorkGenerator {
	return &DorkGenerator{logger: logger}
}

// GenerateDorks generates various search dorks for a domain
func (d *DorkGenerator) GenerateDorks(domain string) []string {
	dorks := []string{
		// Basic site search
		fmt.Sprintf("site:%s", domain),
		fmt.Sprintf("site:*.%s", domain),
		
		// Find subdomains
		fmt.Sprintf("site:%s -www", domain),
		fmt.Sprintf("site:*.%s -www -mail", domain),
		
		// Find specific file types
		fmt.Sprintf("site:%s filetype:pdf", domain),
		fmt.Sprintf("site:%s filetype:doc OR filetype:docx", domain),
		fmt.Sprintf("site:%s filetype:xls OR filetype:xlsx", domain),
		fmt.Sprintf("site:%s filetype:sql OR filetype:db", domain),
		fmt.Sprintf("site:%s filetype:conf OR filetype:config", domain),
		fmt.Sprintf("site:%s filetype:log", domain),
		fmt.Sprintf("site:%s filetype:bak OR filetype:backup", domain),
		
		// Find login pages
		fmt.Sprintf("site:%s inurl:login", domain),
		fmt.Sprintf("site:%s inurl:admin", domain),
		fmt.Sprintf("site:%s inurl:portal", domain),
		fmt.Sprintf("site:%s inurl:dashboard", domain),
		fmt.Sprintf("site:%s intitle:login", domain),
		
		// Find sensitive information
		fmt.Sprintf("site:%s intitle:\"index of\"", domain),
		fmt.Sprintf("site:%s \"parent directory\"", domain),
		fmt.Sprintf("site:%s intext:\"api_key\"", domain),
		fmt.Sprintf("site:%s intext:\"api key\"", domain),
		fmt.Sprintf("site:%s intext:password filetype:log", domain),
		fmt.Sprintf("site:%s intext:username filetype:log", domain),
		
		// Find error messages
		fmt.Sprintf("site:%s \"Fatal error\"", domain),
		fmt.Sprintf("site:%s \"Warning: mysql_connect()\"", domain),
		fmt.Sprintf("site:%s \"Notice: Undefined variable\"", domain),
		
		// Find development/staging sites
		fmt.Sprintf("site:%s inurl:dev", domain),
		fmt.Sprintf("site:%s inurl:staging", domain),
		fmt.Sprintf("site:%s inurl:test", domain),
		fmt.Sprintf("site:%s inurl:uat", domain),
		fmt.Sprintf("site:%s inurl:demo", domain),
		
		// Find API endpoints
		fmt.Sprintf("site:%s inurl:api", domain),
		fmt.Sprintf("site:%s inurl:v1 OR inurl:v2", domain),
		fmt.Sprintf("site:%s filetype:wadl", domain),
		fmt.Sprintf("site:%s filetype:wsdl", domain),
		fmt.Sprintf("site:%s inurl:swagger", domain),
		
		// Find cloud storage
		fmt.Sprintf("site:s3.amazonaws.com \"%s\"", domain),
		fmt.Sprintf("site:blob.core.windows.net \"%s\"", domain),
		fmt.Sprintf("site:googleapis.com \"%s\"", domain),
		fmt.Sprintf("site:drive.google.com \"%s\"", domain),
	}
	
	// Add dorks for company name if available
	companyName := extractCompanyName(domain)
	if companyName != "" {
		dorks = append(dorks, d.generateCompanyDorks(companyName)...)
	}
	
	return dorks
}

// generateCompanyDorks generates dorks for a company name
func (d *DorkGenerator) generateCompanyDorks(company string) []string {
	return []string{
		// LinkedIn
		fmt.Sprintf("site:linkedin.com \"%s\"", company),
		fmt.Sprintf("site:linkedin.com/company \"%s\"", company),
		
		// GitHub
		fmt.Sprintf("site:github.com \"%s\"", company),
		
		// Social media
		fmt.Sprintf("site:twitter.com \"%s\"", company),
		fmt.Sprintf("site:facebook.com \"%s\"", company),
		
		// Job postings (reveals tech stack)
		fmt.Sprintf("site:indeed.com \"%s\" developer", company),
		fmt.Sprintf("site:glassdoor.com \"%s\"", company),
		
		// News and press
		fmt.Sprintf("\"%s\" \"security breach\"", company),
		fmt.Sprintf("\"%s\" \"data leak\"", company),
		fmt.Sprintf("\"%s\" acquisition", company),
		fmt.Sprintf("\"%s\" merger", company),
		
		// Patents and trademarks
		fmt.Sprintf("site:patents.google.com \"%s\"", company),
		
		// SEC filings
		fmt.Sprintf("site:sec.gov \"%s\"", company),
		
		// Pastebin and similar
		fmt.Sprintf("site:pastebin.com \"%s\"", company),
		fmt.Sprintf("site:paste2.org \"%s\"", company),
	}
}

// Helper functions
func extractDomain(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func extractTitle(text string) string {
	// Extract first sentence or up to 100 chars
	if len(text) > 100 {
		return text[:100] + "..."
	}
	return text
}

func extractCompanyName(domain string) string {
	// Simple extraction - remove TLD and common prefixes
	parts := strings.Split(domain, ".")
	if len(parts) > 0 {
		name := parts[0]
		name = strings.TrimPrefix(name, "www")
		name = strings.TrimPrefix(name, "mail")
		return name
	}
	return ""
}

// CommonCrawlEngine uses Common Crawl index for discovery
type CommonCrawlEngine struct {
	client *http.Client
	logger *logger.Logger
}

// NewCommonCrawlEngine creates a new Common Crawl search engine
func NewCommonCrawlEngine(logger *logger.Logger) *CommonCrawlEngine {
	return &CommonCrawlEngine{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

func (c *CommonCrawlEngine) Name() string {
	return "commoncrawl"
}

func (c *CommonCrawlEngine) Search(ctx context.Context, domain string) ([]SearchResult, error) {
	// Use Common Crawl index API
	indexURL := "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*." + domain + "&output=json"
	
	req, err := http.NewRequestWithContext(ctx, "GET", indexURL, nil)
	if err != nil {
		return nil, err
	}
	
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("common crawl returned status %d", resp.StatusCode)
	}
	
	var results []SearchResult
	seen := make(map[string]bool)
	
	// Read line by line (NDJSON format)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		var record struct {
			URL      string `json:"url"`
			MIME     string `json:"mime"`
			Status   string `json:"status"`
			Digest   string `json:"digest"`
			Length   string `json:"length"`
			Offset   string `json:"offset"`
			Filename string `json:"filename"`
		}
		
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		
		if record.URL != "" && !seen[record.URL] {
			seen[record.URL] = true
			u, _ := url.Parse(record.URL)
			if u != nil {
				results = append(results, SearchResult{
					Title:       u.Host,
					URL:         record.URL,
					Description: fmt.Sprintf("Found in Common Crawl: %s", record.MIME),
					Domain:      u.Host,
				})
			}
		}
	}
	
	return results, nil
}

// SearchEngineDiscovery performs search engine discovery
type SearchEngineDiscovery struct {
	searcher *MultiSearchEngine
	dorker   *DorkGenerator
	logger   *logger.Logger
}

// NewSearchEngineDiscovery creates a new search engine discovery module
func NewSearchEngineDiscovery(logger *logger.Logger) *SearchEngineDiscovery {
	return &SearchEngineDiscovery{
		searcher: NewMultiSearchEngine(logger),
		dorker:   NewDorkGenerator(logger),
		logger:   logger,
	}
}

// DiscoverAssets discovers assets using search engines
func (s *SearchEngineDiscovery) DiscoverAssets(ctx context.Context, domain string) ([]string, error) {
	var discoveredDomains []string
	seen := make(map[string]bool)
	
	// Generate dorks
	dorks := s.dorker.GenerateDorks(domain)
	
	// Search with each dork
	for _, dork := range dorks {
		results := s.searcher.SearchAll(ctx, dork)
		
		for _, result := range results {
			if result.Domain != "" && !seen[result.Domain] {
				seen[result.Domain] = true
				discoveredDomains = append(discoveredDomains, result.Domain)
			}
			
			// Extract subdomains from URLs
			subdomains := extractSubdomains(result.URL, domain)
			for _, sub := range subdomains {
				if !seen[sub] {
					seen[sub] = true
					discoveredDomains = append(discoveredDomains, sub)
				}
			}
		}
		
		// Rate limit between searches
		time.Sleep(2 * time.Second)
	}
	
	s.logger.Info("Search engine discovery completed",
		"domain", domain,
		"dorks_used", len(dorks),
		"domains_found", len(discoveredDomains))
	
	return discoveredDomains, nil
}

// extractSubdomains extracts subdomains from a URL
func extractSubdomains(urlStr, baseDomain string) []string {
	var subdomains []string
	
	u, err := url.Parse(urlStr)
	if err != nil {
		return subdomains
	}
	
	hostname := u.Hostname()
	if strings.HasSuffix(hostname, baseDomain) && hostname != baseDomain {
		subdomains = append(subdomains, hostname)
	}
	
	// Also check URL path for subdomain references
	subPattern := regexp.MustCompile(`\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+` + regexp.QuoteMeta(baseDomain) + `\b`)
	matches := subPattern.FindAllString(u.String(), -1)
	
	for _, match := range matches {
		if match != baseDomain {
			subdomains = append(subdomains, match)
		}
	}
	
	return subdomains
}