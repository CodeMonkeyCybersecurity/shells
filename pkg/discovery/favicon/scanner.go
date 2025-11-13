package favicon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// Scanner provides favicon scanning and technology identification
type Scanner struct {
	hasher   *FaviconHasher
	matcher  *TechnologyMatcher
	database *Database
	config   Config
}

// Config represents favicon scanner configuration
type Config struct {
	Timeout        time.Duration `yaml:"timeout"`
	UserAgent      string        `yaml:"user_agent"`
	CacheDir       string        `yaml:"cache_dir"`
	ShodanAPIKey   string        `yaml:"shodan_api_key"`
	MaxConcurrency int           `yaml:"max_concurrency"`
	EnableShodan   bool          `yaml:"enable_shodan"`
	EnableCache    bool          `yaml:"enable_cache"`
	CustomDatabase string        `yaml:"custom_database"`
}

// FaviconResult represents the complete result of a favicon scan
type FaviconResult struct {
	Host         string            `json:"host"`
	Favicons     []*HashResult     `json:"favicons"`
	Technologies []TechnologyMatch `json:"technologies"`
	ShodanHosts  []ShodanHost      `json:"shodan_hosts,omitempty"`
	Related      []string          `json:"related,omitempty"`
	Confidence   float64           `json:"confidence"`
	ScanTime     time.Time         `json:"scan_time"`
	Duration     time.Duration     `json:"duration"`
	Error        string            `json:"error,omitempty"`
}

// TechnologyMatch represents a matched technology
type TechnologyMatch struct {
	Technology string  `json:"technology"`
	Version    string  `json:"version,omitempty"`
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
	Hash       string  `json:"hash"`
	HashType   string  `json:"hash_type"`
	Source     string  `json:"source"` // "database", "shodan", "custom"
}

// ShodanHost represents a host found via Shodan favicon search
type ShodanHost struct {
	IP       string   `json:"ip"`
	Hostname string   `json:"hostname,omitempty"`
	Port     int      `json:"port"`
	Product  string   `json:"product,omitempty"`
	Version  string   `json:"version,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Country  string   `json:"country,omitempty"`
	City     string   `json:"city,omitempty"`
	ISP      string   `json:"isp,omitempty"`
}

// NewScanner creates a new favicon scanner
func NewScanner(config Config) (*Scanner, error) {
	// Set defaults
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.MaxConcurrency == 0 {
		config.MaxConcurrency = 10
	}
	if config.UserAgent == "" {
		config.UserAgent = "Mozilla/5.0 (compatible; FaviconScanner/1.0; Bug Bounty Research)"
	}

	// Initialize components
	hasher := NewHasher(config.Timeout, config.UserAgent)
	matcher := NewTechnologyMatcher()
	database := NewDatabase()

	// Load custom database if specified
	if config.CustomDatabase != "" {
		if err := database.LoadFromFile(config.CustomDatabase); err != nil {
			return nil, fmt.Errorf("failed to load custom database: %v", err)
		}
	}

	// Setup cache directory
	if config.EnableCache && config.CacheDir != "" {
		if err := os.MkdirAll(config.CacheDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create cache directory: %v", err)
		}
	}

	scanner := &Scanner{
		hasher:   hasher,
		matcher:  matcher,
		database: database,
		config:   config,
	}

	return scanner, nil
}

// ScanHost scans a single host for favicon and technology identification
func (s *Scanner) ScanHost(ctx context.Context, host string) (*FaviconResult, error) {
	start := time.Now()

	result := &FaviconResult{
		Host:         host,
		Favicons:     []*HashResult{},
		Technologies: []TechnologyMatch{},
		ShodanHosts:  []ShodanHost{},
		Related:      []string{},
		ScanTime:     start,
	}

	// Check cache first
	if s.config.EnableCache {
		if cached := s.loadFromCache(host); cached != nil {
			return cached, nil
		}
	}

	// Download and hash favicons
	favicons, err := s.hasher.ScanHost(host)
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, nil // Return partial result rather than error
	}

	result.Favicons = favicons

	// Identify technologies for each favicon
	for _, favicon := range favicons {
		technologies := s.identifyTechnologies(favicon)
		result.Technologies = append(result.Technologies, technologies...)
	}

	// Search Shodan if enabled and API key provided
	if s.config.EnableShodan && s.config.ShodanAPIKey != "" {
		for _, favicon := range favicons {
			shodanHosts := s.searchShodan(ctx, favicon.MMH3)
			result.ShodanHosts = append(result.ShodanHosts, shodanHosts...)
		}
	}

	// Calculate confidence score
	result.Confidence = s.calculateConfidence(result.Technologies, result.ShodanHosts)

	// Find related hosts (hosts with same favicon)
	result.Related = s.findRelatedHosts(result.Favicons)

	result.Duration = time.Since(start)

	// Cache result
	if s.config.EnableCache {
		s.saveToCache(host, result)
	}

	return result, nil
}

// ScanHosts scans multiple hosts concurrently
func (s *Scanner) ScanHosts(ctx context.Context, hosts []string) ([]*FaviconResult, error) {
	results := make([]*FaviconResult, len(hosts))

	// Use semaphore to limit concurrency
	sem := make(chan struct{}, s.config.MaxConcurrency)
	var wg sync.WaitGroup

	for i, host := range hosts {
		wg.Add(1)
		go func(index int, hostname string) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			// Create host-specific context with timeout
			hostCtx, cancel := context.WithTimeout(ctx, s.config.Timeout*2)
			defer cancel()

			result, err := s.ScanHost(hostCtx, hostname)
			if err != nil {
				result = &FaviconResult{
					Host:     hostname,
					Error:    err.Error(),
					ScanTime: time.Now(),
				}
			}
			results[index] = result
		}(i, host)
	}

	wg.Wait()
	return results, nil
}

// identifyTechnologies identifies technologies based on favicon hashes
func (s *Scanner) identifyTechnologies(favicon *HashResult) []TechnologyMatch {
	var matches []TechnologyMatch

	// Check against database using different hash types
	hashChecks := []struct {
		hash     string
		hashType string
	}{
		{favicon.MMH3, "mmh3"},
		{favicon.MD5, "md5"},
		{favicon.SHA256, "sha256"},
	}

	for _, check := range hashChecks {
		if check.hash == "" {
			continue
		}

		technologies := s.database.LookupByHash(check.hash, check.hashType)
		for _, tech := range technologies {
			match := TechnologyMatch{
				Technology: tech.Name,
				Version:    tech.Version,
				Category:   tech.Category,
				Confidence: tech.Confidence,
				Hash:       check.hash,
				HashType:   check.hashType,
				Source:     "database",
			}
			matches = append(matches, match)
		}
	}

	// Use technology matcher for additional analysis
	additionalMatches := s.matcher.AnalyzeFavicon(favicon)
	matches = append(matches, additionalMatches...)

	return matches
}

// searchShodan searches Shodan for hosts with matching favicon hash
func (s *Scanner) searchShodan(ctx context.Context, hash string) []ShodanHost {
	if hash == "" {
		return []ShodanHost{}
	}

	// TODO: Implement Shodan API integration
	// For now, return empty results
	// In a real implementation, this would:
	// 1. Query Shodan API with http.favicon.hash:hash
	// 2. Parse results and return ShodanHost structs
	return []ShodanHost{}
}

// calculateConfidence calculates overall confidence score
func (s *Scanner) calculateConfidence(technologies []TechnologyMatch, shodanHosts []ShodanHost) float64 {
	if len(technologies) == 0 {
		return 0.0
	}

	var totalConfidence float64
	var count int

	// Average technology match confidence
	for _, tech := range technologies {
		totalConfidence += tech.Confidence
		count++
	}

	confidence := totalConfidence / float64(count)

	// Boost confidence if we have Shodan matches
	if len(shodanHosts) > 0 {
		confidence = confidence * 1.2
		if confidence > 1.0 {
			confidence = 1.0
		}
	}

	return confidence
}

// findRelatedHosts finds other hosts with the same favicon hashes
func (s *Scanner) findRelatedHosts(favicons []*HashResult) []string {
	var related []string

	// In a real implementation, this would:
	// 1. Query a database of previously scanned hosts
	// 2. Find hosts with matching favicon hashes
	// 3. Return list of related hostnames

	return related
}

// AddCustomHash adds a custom hash to technology mapping
func (s *Scanner) AddCustomHash(hash, technology, category string, confidence float64) error {
	entry := TechnologyEntry{
		Hash:       hash,
		HashType:   "custom",
		Name:       technology,
		Category:   category,
		Confidence: confidence,
		Source:     "custom",
	}

	return s.database.AddEntry(entry)
}

// GetStatistics returns scanner statistics
func (s *Scanner) GetStatistics() ScannerStatistics {
	return ScannerStatistics{
		TotalScans:        s.database.GetTotalScans(),
		TechnologiesFound: s.database.GetTotalTechnologies(),
		UniqueHashes:      s.database.GetUniqueHashes(),
		DatabaseEntries:   s.database.GetEntryCount(),
		CacheHits:         s.getCacheHits(),
		AverageConfidence: s.getAverageConfidence(),
	}
}

// ScannerStatistics provides scanner performance metrics
type ScannerStatistics struct {
	TotalScans        int     `json:"total_scans"`
	TechnologiesFound int     `json:"technologies_found"`
	UniqueHashes      int     `json:"unique_hashes"`
	DatabaseEntries   int     `json:"database_entries"`
	CacheHits         int     `json:"cache_hits"`
	AverageConfidence float64 `json:"average_confidence"`
}

// ConvertToFinding converts FaviconResult to standard Finding type
func (s *Scanner) ConvertToFinding(result *FaviconResult) []types.Finding {
	var findings []types.Finding

	if result.Error != "" {
		return findings // No findings if scan failed
	}

	for _, tech := range result.Technologies {
		finding := types.Finding{
			ID:          fmt.Sprintf("favicon-%s-%s", result.Host, tech.Hash[:8]),
			Type:        "technology-discovery",
			Severity:    types.SeverityInfo,
			Title:       fmt.Sprintf("%s Technology Detected via Favicon", tech.Technology),
			Description: fmt.Sprintf("Detected %s technology on %s via favicon hash analysis", tech.Technology, result.Host),
			Metadata: map[string]interface{}{
				"target":     result.Host,
				"impact":     fmt.Sprintf("Technology fingerprinting reveals %s usage", tech.Technology),
				"technology": tech.Technology,
				"category":   tech.Category,
				"confidence": tech.Confidence,
				"hash":       tech.Hash,
				"hash_type":  tech.HashType,
				"source":     tech.Source,
				"scan_time":  result.ScanTime,
				"duration":   result.Duration.String(),
				"tags": []string{
					"favicon",
					"technology-discovery",
					"fingerprinting",
					tech.Category,
					tech.Source,
				},
			},
		}

		if tech.Version != "" {
			finding.Description += fmt.Sprintf(" (version: %s)", tech.Version)
			finding.Metadata["version"] = tech.Version
		}

		findings = append(findings, finding)
	}

	return findings
}

// Cache management methods

func (s *Scanner) loadFromCache(host string) *FaviconResult {
	if !s.config.EnableCache {
		return nil
	}

	cacheFile := filepath.Join(s.config.CacheDir, fmt.Sprintf("%s.json", sanitizeFilename(host)))

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil
	}

	var result FaviconResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}

	// Check if cache is still valid (24 hours)
	if time.Since(result.ScanTime) > 24*time.Hour {
		return nil
	}

	return &result
}

func (s *Scanner) saveToCache(host string, result *FaviconResult) {
	if !s.config.EnableCache {
		return
	}

	cacheFile := filepath.Join(s.config.CacheDir, fmt.Sprintf("%s.json", sanitizeFilename(host)))

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return
	}

	os.WriteFile(cacheFile, data, 0644)
}

func (s *Scanner) getCacheHits() int {
	// TODO: Implement cache hit tracking
	return 0
}

func (s *Scanner) getAverageConfidence() float64 {
	// TODO: Implement confidence tracking
	return 0.0
}

// Helper functions

func sanitizeFilename(name string) string {
	// Replace invalid filename characters
	replacer := strings.NewReplacer(
		":", "_",
		"/", "_",
		"\\", "_",
		"?", "_",
		"*", "_",
		"|", "_",
		"<", "_",
		">", "_",
		"\"", "_",
	)
	return replacer.Replace(name)
}

// ExportResults exports scan results in various formats
func (s *Scanner) ExportResults(results []*FaviconResult, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(results, "", "  ")
	case "csv":
		return s.exportCSV(results)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

func (s *Scanner) exportCSV(results []*FaviconResult) ([]byte, error) {
	var lines []string

	// Header
	lines = append(lines, "Host,Technology,Category,Confidence,Hash,HashType,Source,ScanTime")

	// Data rows
	for _, result := range results {
		for _, tech := range result.Technologies {
			line := fmt.Sprintf("%s,%s,%s,%.2f,%s,%s,%s,%s",
				result.Host, tech.Technology, tech.Category, tech.Confidence,
				tech.Hash, tech.HashType, tech.Source, result.ScanTime.Format(time.RFC3339))
			lines = append(lines, line)
		}
	}

	return []byte(strings.Join(lines, "\n")), nil
}
