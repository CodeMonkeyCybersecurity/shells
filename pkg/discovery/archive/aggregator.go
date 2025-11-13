package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type ArchiveAggregator struct {
	wayback      *WaybackScanner
	archiveToday *ArchiveTodayClient
	commonCrawl  *CommonCrawlClient
	httpClient   *http.Client
}

type ArchiveTodayClient struct {
	httpClient *http.Client
	userAgent  string
}

type CommonCrawlClient struct {
	httpClient *http.Client
	userAgent  string
}

func NewArchiveAggregator() *ArchiveAggregator {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &ArchiveAggregator{
		wayback:      NewWaybackScanner(),
		archiveToday: NewArchiveTodayClient(client),
		commonCrawl:  NewCommonCrawlClient(client),
		httpClient:   client,
	}
}

func NewArchiveTodayClient(client *http.Client) *ArchiveTodayClient {
	return &ArchiveTodayClient{
		httpClient: client,
		userAgent:  "Mozilla/5.0 (compatible; SecurityTool/1.0)",
	}
}

func NewCommonCrawlClient(client *http.Client) *CommonCrawlClient {
	return &CommonCrawlClient{
		httpClient: client,
		userAgent:  "Mozilla/5.0 (compatible; SecurityTool/1.0)",
	}
}

func (a *ArchiveAggregator) DeepArchiveSearch(ctx context.Context, domain string) (*DeepArchiveReport, error) {
	report := &DeepArchiveReport{
		Domain:   domain,
		Sources:  make(map[string]Statistics),
		Findings: []ArchiveFinding{},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Search all archives concurrently
	wg.Add(3)

	// Wayback Machine
	go func() {
		defer wg.Done()
		if waybackResults, err := a.wayback.ScanDomain(ctx, domain); err == nil {
			mu.Lock()
			report.Sources["wayback"] = Statistics{
				TotalURLs:      len(waybackResults.URLs),
				SecretsFound:   len(waybackResults.Secrets),
				EndpointsFound: len(waybackResults.Endpoints),
				FilesFound:     len(waybackResults.SensitiveFiles),
			}
			report.TotalSnapshots += len(waybackResults.URLs)

			// Convert to findings
			for _, secret := range waybackResults.Secrets {
				report.Findings = append(report.Findings, ArchiveFinding{
					Type:      "SECRET",
					Name:      secret.Type,
					Value:     secret.Value,
					URL:       secret.URL,
					Timestamp: secret.Timestamp,
					Severity:  secret.Severity,
					Context:   secret.Context,
				})
			}

			for _, endpoint := range waybackResults.Endpoints {
				report.Findings = append(report.Findings, ArchiveFinding{
					Type:      "ENDPOINT",
					Name:      "api_endpoint",
					Value:     endpoint.Path,
					URL:       "",
					Timestamp: endpoint.FirstSeen,
					Severity:  "MEDIUM",
				})
			}

			for _, panel := range waybackResults.AdminPanels {
				report.Findings = append(report.Findings, ArchiveFinding{
					Type:      "ADMIN_PANEL",
					Name:      "admin_panel",
					Value:     panel.URL,
					URL:       panel.URL,
					Timestamp: panel.Timestamp,
					Severity:  "HIGH",
				})
			}

			for _, file := range waybackResults.SensitiveFiles {
				report.Findings = append(report.Findings, ArchiveFinding{
					Type:      "SENSITIVE_FILE",
					Name:      file.Type,
					Value:     file.URL,
					URL:       file.URL,
					Timestamp: file.Timestamp,
					Severity:  "HIGH",
				})
			}
			mu.Unlock()
		}
	}()

	// Archive.today
	go func() {
		defer wg.Done()
		if archiveTodayResults, err := a.archiveToday.Search(ctx, domain); err == nil {
			mu.Lock()
			report.Sources["archive_today"] = Statistics{
				TotalURLs: len(archiveTodayResults),
			}
			report.TotalSnapshots += len(archiveTodayResults)

			// Convert to findings
			for _, result := range archiveTodayResults {
				timestamp, _ := time.Parse(time.RFC3339, result.Timestamp)
				report.Findings = append(report.Findings, ArchiveFinding{
					Type:      "ARCHIVED_URL",
					Name:      "archive_today",
					Value:     result.URL,
					URL:       result.URL,
					Timestamp: timestamp,
					Severity:  "LOW",
				})
			}
			mu.Unlock()
		}
	}()

	// Common Crawl
	go func() {
		defer wg.Done()
		if commonCrawlResults, err := a.commonCrawl.QueryIndex(ctx, domain); err == nil {
			mu.Lock()
			report.Sources["common_crawl"] = Statistics{
				TotalURLs: len(commonCrawlResults),
			}
			report.TotalSnapshots += len(commonCrawlResults)

			// Convert to findings
			for _, result := range commonCrawlResults {
				timestamp, _ := time.Parse(time.RFC3339, result.Timestamp)
				report.Findings = append(report.Findings, ArchiveFinding{
					Type:      "ARCHIVED_URL",
					Name:      "common_crawl",
					Value:     result.URL,
					URL:       result.URL,
					Timestamp: timestamp,
					Severity:  "LOW",
				})
			}
			mu.Unlock()
		}
	}()

	wg.Wait()

	// Advanced analysis
	report.Findings = append(report.Findings, a.findDeletedAdminPanels(report.Findings)...)
	report.Findings = append(report.Findings, a.findOldAPIEndpoints(report.Findings)...)
	report.Findings = append(report.Findings, a.findStagingEnvironments(report.Findings)...)
	report.Findings = append(report.Findings, a.findBackupFiles(report.Findings)...)

	// Generate analysis
	report.Analysis = a.generateAnalysis(report.Findings)

	return report, nil
}

func (at *ArchiveTodayClient) Search(ctx context.Context, domain string) ([]ArchiveTodayResult, error) {
	// Archive.today API endpoint
	apiURL := fmt.Sprintf("http://archive.today/api/search?q=%s", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", at.userAgent)

	resp, err := at.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("archive.today API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response ArchiveTodayResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	// Convert to our format
	results := make([]ArchiveTodayResult, 0, len(response.Results))
	for _, result := range response.Results {
		timestamp, err := time.Parse("2006-01-02T15:04:05Z", result.Timestamp)
		if err != nil {
			continue
		}

		results = append(results, ArchiveTodayResult{
			URL:       result.URL,
			Timestamp: timestamp.Format(time.RFC3339),
			Title:     result.Title,
			Size:      result.Size,
		})
	}

	return results, nil
}

func (cc *CommonCrawlClient) QueryIndex(ctx context.Context, domain string) ([]CommonCrawlURL, error) {
	// Common Crawl Index API
	apiURL := fmt.Sprintf("https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=%s/*&output=json", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", cc.userAgent)

	resp, err := cc.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("common crawl API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse JSONL format
	lines := strings.Split(string(body), "\n")
	results := make([]CommonCrawlURL, 0, len(lines))

	for _, line := range lines {
		if line == "" {
			continue
		}

		var record CommonCrawlURL
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}

		// Parse timestamp - Common Crawl uses different format
		timestamp, err := time.Parse("20060102150405", record.Timestamp)
		if err != nil {
			continue
		}

		results = append(results, CommonCrawlURL{
			URL:       record.URL,
			Timestamp: timestamp.Format(time.RFC3339),
			Status:    record.Status,
			MimeType:  record.MimeType,
			Size:      record.Size,
		})
	}

	return results, nil
}

func (a *ArchiveAggregator) findDeletedAdminPanels(findings []ArchiveFinding) []ArchiveFinding {
	deletedPanels := []ArchiveFinding{}

	for _, finding := range findings {
		if finding.Type == "ADMIN_PANEL" {
			// Check if admin panel still exists
			if !a.urlStillExists(finding.URL) {
				deletedPanels = append(deletedPanels, ArchiveFinding{
					Type:      "DELETED_ADMIN_PANEL",
					Name:      "deleted_admin_panel",
					Value:     finding.URL,
					URL:       finding.URL,
					Timestamp: finding.Timestamp,
					Severity:  "MEDIUM",
					Context:   "Admin panel found in archive but no longer accessible",
				})
			}
		}
	}

	return deletedPanels
}

func (a *ArchiveAggregator) findOldAPIEndpoints(findings []ArchiveFinding) []ArchiveFinding {
	oldEndpoints := []ArchiveFinding{}

	endpointCount := make(map[string]int)
	for _, finding := range findings {
		if finding.Type == "ENDPOINT" {
			endpointCount[finding.Value]++
		}
	}

	for endpoint, count := range endpointCount {
		if count > 5 { // Endpoint appeared multiple times
			// Check if endpoint still exists
			if !a.endpointStillExists(endpoint) {
				oldEndpoints = append(oldEndpoints, ArchiveFinding{
					Type:     "OLD_API_ENDPOINT",
					Name:     "old_api_endpoint",
					Value:    endpoint,
					Severity: "MEDIUM",
					Context:  fmt.Sprintf("API endpoint appeared %d times in archive but no longer exists", count),
				})
			}
		}
	}

	return oldEndpoints
}

func (a *ArchiveAggregator) findStagingEnvironments(findings []ArchiveFinding) []ArchiveFinding {
	stagingEnvs := []ArchiveFinding{}

	stagingPatterns := []string{
		"staging", "stage", "test", "dev", "beta", "pre-prod", "preprod",
		"qa", "uat", "demo", "sandbox", "experimental",
	}

	for _, finding := range findings {
		if finding.Type == "ARCHIVED_URL" {
			urlLower := strings.ToLower(finding.URL)
			for _, pattern := range stagingPatterns {
				if strings.Contains(urlLower, pattern) {
					stagingEnvs = append(stagingEnvs, ArchiveFinding{
						Type:      "STAGING_ENVIRONMENT",
						Name:      "staging_environment",
						Value:     finding.URL,
						URL:       finding.URL,
						Timestamp: finding.Timestamp,
						Severity:  "HIGH",
						Context:   fmt.Sprintf("Potential staging environment: %s", pattern),
					})
					break
				}
			}
		}
	}

	return stagingEnvs
}

func (a *ArchiveAggregator) findBackupFiles(findings []ArchiveFinding) []ArchiveFinding {
	backupFiles := []ArchiveFinding{}

	backupPatterns := []string{
		".bak", ".backup", ".old", ".orig", ".tmp", ".temp",
		"backup", "dump", "export", "archive", "copy",
	}

	for _, finding := range findings {
		if finding.Type == "ARCHIVED_URL" {
			urlLower := strings.ToLower(finding.URL)
			for _, pattern := range backupPatterns {
				if strings.Contains(urlLower, pattern) {
					backupFiles = append(backupFiles, ArchiveFinding{
						Type:      "BACKUP_FILE",
						Name:      "backup_file",
						Value:     finding.URL,
						URL:       finding.URL,
						Timestamp: finding.Timestamp,
						Severity:  "HIGH",
						Context:   fmt.Sprintf("Potential backup file: %s", pattern),
					})
					break
				}
			}
		}
	}

	return backupFiles
}

func (a *ArchiveAggregator) generateAnalysis(findings []ArchiveFinding) ArchiveAnalysis {
	analysis := ArchiveAnalysis{
		TechnologyStack:    []string{},
		FrameworksDetected: []string{},
		DatabasesDetected:  []string{},
		PathPatterns:       []PathPattern{},
		ParameterPatterns:  []ParameterPattern{},
	}

	// Technology detection
	techKeywords := map[string][]string{
		"php":       {"php", ".php", "phpinfo", "phpmyadmin"},
		"asp":       {"asp", ".asp", ".aspx", "aspnet"},
		"jsp":       {"jsp", ".jsp", "java", "tomcat"},
		"python":    {"python", ".py", "django", "flask"},
		"ruby":      {"ruby", ".rb", "rails", "gem"},
		"node":      {"node", ".js", "npm", "express"},
		"wordpress": {"wp-", "wordpress", "wp-content", "wp-admin"},
		"drupal":    {"drupal", "sites/default", "modules"},
		"joomla":    {"joomla", "administrator", "components"},
	}

	for tech, keywords := range techKeywords {
		for _, finding := range findings {
			for _, keyword := range keywords {
				if strings.Contains(strings.ToLower(finding.URL), keyword) {
					analysis.TechnologyStack = append(analysis.TechnologyStack, tech)
					goto nextTech
				}
			}
		}
	nextTech:
	}

	// Framework detection
	frameworkKeywords := map[string][]string{
		"laravel":     {"laravel", "artisan", "vendor"},
		"symfony":     {"symfony", "app/config"},
		"codeigniter": {"codeigniter", "system", "application"},
		"zend":        {"zend", "library/zend"},
		"cakephp":     {"cakephp", "app/config", "cake"},
		"django":      {"django", "admin", "static"},
		"flask":       {"flask", "app.py"},
		"rails":       {"rails", "app/controllers", "config/routes"},
		"spring":      {"spring", "WEB-INF", "servlet"},
		"struts":      {"struts", "action", "struts.xml"},
	}

	for framework, keywords := range frameworkKeywords {
		for _, finding := range findings {
			for _, keyword := range keywords {
				if strings.Contains(strings.ToLower(finding.URL), keyword) {
					analysis.FrameworksDetected = append(analysis.FrameworksDetected, framework)
					goto nextFramework
				}
			}
		}
	nextFramework:
	}

	// Database detection
	dbKeywords := map[string][]string{
		"mysql":         {"mysql", "phpmyadmin", "mysqldump"},
		"postgresql":    {"postgresql", "postgres", "pgadmin"},
		"mongodb":       {"mongodb", "mongo", "mongodump"},
		"redis":         {"redis", "redis-cli"},
		"elasticsearch": {"elasticsearch", "elastic", "_search"},
		"oracle":        {"oracle", "ora_", "sqlplus"},
		"mssql":         {"mssql", "sqlserver", "master.dbo"},
	}

	for db, keywords := range dbKeywords {
		for _, finding := range findings {
			for _, keyword := range keywords {
				if strings.Contains(strings.ToLower(finding.URL), keyword) {
					analysis.DatabasesDetected = append(analysis.DatabasesDetected, db)
					goto nextDB
				}
			}
		}
	nextDB:
	}

	// Path pattern analysis
	pathCounts := make(map[string]int)
	for _, finding := range findings {
		if finding.Type == "ARCHIVED_URL" {
			// Extract path pattern
			parts := strings.Split(finding.URL, "/")
			if len(parts) > 3 {
				pattern := "/" + strings.Join(parts[3:], "/")
				// Normalize numbers
				pattern = strings.ReplaceAll(pattern, "[0-9]+", "N")
				pathCounts[pattern]++
			}
		}
	}

	for pattern, count := range pathCounts {
		if count > 3 {
			analysis.PathPatterns = append(analysis.PathPatterns, PathPattern{
				Pattern:   pattern,
				Examples:  []string{}, // Would need to collect examples
				Frequency: count,
			})
		}
	}

	// Deduplicate slices
	analysis.TechnologyStack = a.deduplicate(analysis.TechnologyStack)
	analysis.FrameworksDetected = a.deduplicate(analysis.FrameworksDetected)
	analysis.DatabasesDetected = a.deduplicate(analysis.DatabasesDetected)

	return analysis
}

func (a *ArchiveAggregator) deduplicate(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

func (a *ArchiveAggregator) urlStillExists(urlStr string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "HEAD", urlStr, nil)
	if err != nil {
		return false
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer httpclient.CloseBody(resp)

	return resp.StatusCode < 400
}

func (a *ArchiveAggregator) endpointStillExists(endpoint string) bool {
	// This would need domain context - simplified for now
	return false
}

func (a *ArchiveAggregator) MergeResults(wayback *ArchiveReport, archiveToday []ArchiveTodayResult, commonCrawl []CommonCrawlURL) []ArchivedURL {
	allURLs := []ArchivedURL{}

	// Add Wayback URLs
	allURLs = append(allURLs, wayback.URLs...)

	// Add Archive.today URLs
	for _, result := range archiveToday {
		timestamp, _ := time.Parse(time.RFC3339, result.Timestamp)
		allURLs = append(allURLs, ArchivedURL{
			URL:       result.URL,
			Timestamp: timestamp,
			Source:    "archive_today",
		})
	}

	// Add Common Crawl URLs
	for _, result := range commonCrawl {
		timestamp, _ := time.Parse(time.RFC3339, result.Timestamp)
		allURLs = append(allURLs, ArchivedURL{
			URL:       result.URL,
			Timestamp: timestamp,
			MimeType:  result.MimeType,
			Source:    "common_crawl",
		})
	}

	// Deduplicate by URL
	seen := make(map[string]bool)
	deduplicated := []ArchivedURL{}

	for _, url := range allURLs {
		if !seen[url.URL] {
			seen[url.URL] = true
			deduplicated = append(deduplicated, url)
		}
	}

	return deduplicated
}

// Helper function to extract path from URL
func extractPath(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return u.Path
}
