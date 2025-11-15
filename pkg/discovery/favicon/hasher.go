package favicon

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"

	"github.com/twmb/murmur3"
)

// FaviconHasher handles favicon downloading and hash calculation
type FaviconHasher struct {
	client    *http.Client
	userAgent string
	timeout   time.Duration
	maxSize   int64
}

// NewHasher creates a new favicon hasher
func NewHasher(timeout time.Duration, userAgent string) *FaviconHasher {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For bug bounty testing
			},
		},
	}

	if userAgent == "" {
		userAgent = "Mozilla/5.0 (compatible; FaviconScanner/1.0)"
	}

	return &FaviconHasher{
		client:    client,
		userAgent: userAgent,
		timeout:   timeout,
		maxSize:   1024 * 1024, // 1MB max favicon size
	}
}

// HashResult contains all hash variants of a favicon
type HashResult struct {
	URL         string `json:"url"`
	MD5         string `json:"md5"`
	SHA256      string `json:"sha256"`
	MMH3        string `json:"mmh3"`        // Shodan format
	MMH3Signed  string `json:"mmh3_signed"` // Alternative format
	Base64      string `json:"base64,omitempty"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
	StatusCode  int    `json:"status_code"`
}

// DownloadAndHash downloads a favicon and calculates all hash variants
func (h *FaviconHasher) DownloadAndHash(faviconURL string) (*HashResult, error) {
	// Validate URL
	parsedURL, err := url.Parse(faviconURL)
	if err != nil {
		return nil, fmt.Errorf("invalid favicon URL: %w", err)
	}

	// Ensure HTTPS for secure connections
	if parsedURL.Scheme == "http" {
		parsedURL.Scheme = "https"
	}

	// Create request
	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("User-Agent", h.userAgent)
	req.Header.Set("Accept", "image/*,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	// Download favicon
	resp, err := h.client.Do(req)
	if err != nil {
		// Try HTTP if HTTPS fails
		if parsedURL.Scheme == "https" {
			parsedURL.Scheme = "http"
			req.URL = parsedURL
			resp, err = h.client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("failed to download favicon: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to download favicon: %v", err)
		}
	}
	defer httpclient.CloseBody(resp)

	// Check response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Limit read size
	limitedReader := io.LimitReader(resp.Body, h.maxSize)

	// Read favicon data
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read favicon data: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("empty favicon")
	}

	// Calculate hashes
	result := &HashResult{
		URL:         faviconURL,
		Size:        int64(len(data)),
		ContentType: resp.Header.Get("Content-Type"),
		StatusCode:  resp.StatusCode,
	}

	result.MD5 = h.calculateMD5(data)
	result.SHA256 = h.calculateSHA256(data)
	result.MMH3 = h.calculateMMH3(data)
	result.MMH3Signed = h.calculateMMH3Signed(data)
	result.Base64 = base64.StdEncoding.EncodeToString(data)

	return result, nil
}

// DiscoverFaviconURLs attempts to discover favicon URLs for a host
func (h *FaviconHasher) DiscoverFaviconURLs(host string) []string {
	var urls []string

	// Ensure host has protocol
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}

	parsedURL, err := url.Parse(host)
	if err != nil {
		return urls
	}

	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// Common favicon locations
	commonPaths := []string{
		"/favicon.ico",
		"/favicon.png",
		"/favicon.gif",
		"/favicon.jpg",
		"/apple-touch-icon.png",
		"/apple-touch-icon-precomposed.png",
		"/assets/favicon.ico",
		"/static/favicon.ico",
		"/img/favicon.ico",
		"/images/favicon.ico",
		"/public/favicon.ico",
		"/resources/favicon.ico",
	}

	// Add common paths
	for _, path := range commonPaths {
		urls = append(urls, baseURL+path)
	}

	// Try to discover from HTML
	if htmlFavicons := h.discoverFromHTML(baseURL); len(htmlFavicons) > 0 {
		urls = append(urls, htmlFavicons...)
	}

	return urls
}

// discoverFromHTML attempts to discover favicon URLs from HTML meta tags
func (h *FaviconHasher) discoverFromHTML(baseURL string) []string {
	var favicons []string

	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return favicons
	}

	req.Header.Set("User-Agent", h.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := h.client.Do(req)
	if err != nil {
		return favicons
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return favicons
	}

	// Read first 64KB of HTML (should contain head section)
	limitedReader := io.LimitReader(resp.Body, 65536)
	htmlData, err := io.ReadAll(limitedReader)
	if err != nil {
		return favicons
	}

	html := string(htmlData)

	// Look for favicon link tags
	faviconPatterns := []string{
		`<link[^>]*rel=["\'](?:icon|shortcut icon|apple-touch-icon)["\'][^>]*href=["\']([^"\']+)["\']`,
		`<link[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\'](?:icon|shortcut icon|apple-touch-icon)["\']`,
	}

	for _, pattern := range faviconPatterns {
		matches := extractURLsFromHTML(html, pattern)
		for _, match := range matches {
			faviconURL := h.resolveURL(baseURL, match)
			if faviconURL != "" {
				favicons = append(favicons, faviconURL)
			}
		}
	}

	return favicons
}

// resolveURL resolves a relative URL against a base URL
func (h *FaviconHasher) resolveURL(baseURL, relativeURL string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	rel, err := url.Parse(relativeURL)
	if err != nil {
		return ""
	}

	resolved := base.ResolveReference(rel)
	return resolved.String()
}

// Hash calculation methods

func (h *FaviconHasher) calculateMD5(data []byte) string {
	hash := md5.Sum(data)
	return fmt.Sprintf("%x", hash)
}

func (h *FaviconHasher) calculateSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// calculateMMH3 calculates MurmurHash3 in Shodan format
func (h *FaviconHasher) calculateMMH3(data []byte) string {
	// Shodan uses base64 encoded data for hashing
	b64Data := base64.StdEncoding.EncodeToString(data)
	hash := murmur3.Sum32([]byte(b64Data))
	return fmt.Sprintf("%d", int32(hash))
}

// calculateMMH3Signed calculates MurmurHash3 with signed interpretation
func (h *FaviconHasher) calculateMMH3Signed(data []byte) string {
	hash := murmur3.Sum32(data)
	return fmt.Sprintf("%d", int32(hash))
}

// ScanHost scans a single host for favicons and returns hash results
func (h *FaviconHasher) ScanHost(host string) ([]*HashResult, error) {
	var results []*HashResult

	// Discover favicon URLs
	faviconURLs := h.DiscoverFaviconURLs(host)

	// Hash each discovered favicon
	for _, faviconURL := range faviconURLs {
		result, err := h.DownloadAndHash(faviconURL)
		if err != nil {
			// Skip failed downloads but log them
			continue
		}
		results = append(results, result)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no favicons found for host: %s", host)
	}

	return results, nil
}

// ScanHosts scans multiple hosts for favicons
func (h *FaviconHasher) ScanHosts(hosts []string) (map[string][]*HashResult, error) {
	results := make(map[string][]*HashResult)

	for _, host := range hosts {
		hostResults, err := h.ScanHost(host)
		if err != nil {
			// Continue with other hosts even if one fails
			continue
		}
		results[host] = hostResults
	}

	return results, nil
}

// ValidateFavicon checks if downloaded data is a valid favicon
func (h *FaviconHasher) ValidateFavicon(data []byte, contentType string) bool {
	if len(data) == 0 {
		return false
	}

	// Check magic bytes for common image formats
	if len(data) >= 4 {
		// ICO format
		if data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x01 && data[3] == 0x00 {
			return true
		}
		// PNG format
		if data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 {
			return true
		}
	}

	if len(data) >= 3 {
		// GIF format
		if data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46 {
			return true
		}
	}

	if len(data) >= 2 {
		// JPEG format
		if data[0] == 0xFF && data[1] == 0xD8 {
			return true
		}
	}

	// Check content type if magic bytes don't match
	if contentType != "" {
		validTypes := []string{
			"image/x-icon", "image/vnd.microsoft.icon", "image/ico",
			"image/png", "image/gif", "image/jpeg", "image/jpg",
			"image/svg+xml", "image/webp",
		}

		for _, validType := range validTypes {
			if strings.Contains(contentType, validType) {
				return true
			}
		}
	}

	return false
}

// Helper function to extract URLs from HTML using regex-like patterns
func extractURLsFromHTML(html, pattern string) []string {
	var urls []string

	// Simple pattern matching for link tags
	// This is a basic implementation - in production, use a proper HTML parser

	// Look for href attributes in link tags
	linkStart := 0
	for {
		linkIndex := strings.Index(html[linkStart:], "<link")
		if linkIndex == -1 {
			break
		}
		linkIndex += linkStart

		// Find end of link tag
		linkEnd := strings.Index(html[linkIndex:], ">")
		if linkEnd == -1 {
			break
		}
		linkEnd += linkIndex

		linkTag := html[linkIndex : linkEnd+1]

		// Check if this is a favicon link
		if strings.Contains(linkTag, "rel=\"icon\"") ||
			strings.Contains(linkTag, "rel='icon'") ||
			strings.Contains(linkTag, "rel=\"shortcut icon\"") ||
			strings.Contains(linkTag, "rel='shortcut icon'") ||
			strings.Contains(linkTag, "rel=\"apple-touch-icon\"") ||
			strings.Contains(linkTag, "rel='apple-touch-icon'") {

			// Extract href value
			href := extractHrefValue(linkTag)
			if href != "" {
				urls = append(urls, href)
			}
		}

		linkStart = linkEnd + 1
	}

	return urls
}

func extractHrefValue(linkTag string) string {
	// Look for href="..." or href='...'
	hrefIndex := strings.Index(linkTag, "href=")
	if hrefIndex == -1 {
		return ""
	}

	start := hrefIndex + 5
	if start >= len(linkTag) {
		return ""
	}

	quote := linkTag[start]
	if quote != '"' && quote != '\'' {
		return ""
	}

	start++
	end := strings.Index(linkTag[start:], string(quote))
	if end == -1 {
		return ""
	}

	return linkTag[start : start+end]
}
