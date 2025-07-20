// pkg/intel/archive/wayback.go
package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// WaybackMachine implements the ArchiveSource interface for archive.org
type WaybackMachine struct {
	httpClient *http.Client
	logger     *logger.Logger
	baseURL    string
}

// WaybackResponse represents the CDX API response
type WaybackResponse [][]string

// NewWaybackMachine creates a new Wayback Machine client
func NewWaybackMachine(client *http.Client, log *logger.Logger) *WaybackMachine {
	return &WaybackMachine{
		httpClient: client,
		logger:     log,
		baseURL:    "https://web.archive.org",
	}
}

// Name returns the name of this archive source
func (w *WaybackMachine) Name() string {
	return "wayback_machine"
}

// GetSnapshots retrieves all snapshots for a domain from Wayback Machine
func (w *WaybackMachine) GetSnapshots(ctx context.Context, domain string) ([]Snapshot, error) {
	// Use CDX API to get all captures
	cdxURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=timestamp,original,statuscode,mimetype",
		url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", cdxURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CDX data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CDX API returned status %d", resp.StatusCode)
	}

	// Parse CDX response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var cdxData WaybackResponse
	if err := json.Unmarshal(body, &cdxData); err != nil {
		return nil, fmt.Errorf("failed to parse CDX response: %w", err)
	}

	// Convert to snapshots
	snapshots := []Snapshot{}

	// Skip header row if present
	startIdx := 0
	if len(cdxData) > 0 && len(cdxData[0]) > 0 && cdxData[0][0] == "timestamp" {
		startIdx = 1
	}

	for i := startIdx; i < len(cdxData); i++ {
		row := cdxData[i]
		if len(row) < 4 {
			continue
		}

		// Parse timestamp (YYYYMMDDhhmmss format)
		timestamp, err := time.Parse("20060102150405", row[0])
		if err != nil {
			w.logger.Debug("Failed to parse timestamp", "timestamp", row[0], "error", err)
			continue
		}

		// Parse status code
		statusCode := 0
		if row[2] != "-" {
			fmt.Sscanf(row[2], "%d", &statusCode)
		}

		snapshot := Snapshot{
			URL:       row[1],
			Timestamp: timestamp,
			Status:    statusCode,
			MimeType:  row[3],
			Source:    w.Name(),
		}

		snapshots = append(snapshots, snapshot)
	}

	w.logger.Info("Retrieved snapshots from Wayback Machine", "count", len(snapshots), "domain", domain)
	return snapshots, nil
}

// GetContent retrieves the content of a specific snapshot
func (w *WaybackMachine) GetContent(ctx context.Context, originalURL string, timestamp time.Time) (string, error) {
	// Format timestamp for Wayback Machine
	timestampStr := timestamp.Format("20060102150405")

	// Construct Wayback Machine URL
	waybackURL := fmt.Sprintf("%s/web/%s/%s", w.baseURL, timestampStr, originalURL)

	req, err := http.NewRequestWithContext(ctx, "GET", waybackURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Add header to get raw content without Wayback toolbar
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch content: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Wayback Machine returned status %d", resp.StatusCode)
	}

	// Read content
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read content: %w", err)
	}

	// Remove Wayback Machine toolbar/banner from content
	content := w.cleanWaybackContent(string(body))

	return content, nil
}

// cleanWaybackContent removes Wayback Machine additions from archived content
func (w *WaybackMachine) cleanWaybackContent(content string) string {
	// Remove common Wayback Machine injected content
	// This is a simplified version - in production, use proper HTML parsing

	// Remove Wayback toolbar
	startMarker := "<!-- BEGIN WAYBACK TOOLBAR INSERT -->"
	endMarker := "<!-- END WAYBACK TOOLBAR INSERT -->"

	startIdx := 0
	for {
		start := indexOf(content[startIdx:], startMarker)
		if start == -1 {
			break
		}
		start += startIdx

		end := indexOf(content[start:], endMarker)
		if end == -1 {
			break
		}
		end += start + len(endMarker)

		// Remove this section
		content = content[:start] + content[end:]
		startIdx = start
	}

	// Remove Wayback Machine URL rewriting
	content = w.revertURLRewriting(content)

	return content
}

// revertURLRewriting converts Wayback URLs back to original URLs
func (w *WaybackMachine) revertURLRewriting(content string) string {
	// Pattern: /web/YYYYMMDDhhmmss/originalURL
	// This is simplified - in production, use proper regex

	// For now, return content as-is
	// A full implementation would parse and revert all rewritten URLs
	return content
}

// indexOf finds the index of substr in s, returns -1 if not found
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Additional archive source implementations

// ArchiveToday implements the ArchiveSource interface for archive.today
type ArchiveToday struct {
	httpClient *http.Client
	logger     *logger.Logger
	baseURL    string
}

// NewArchiveToday creates a new Archive.today client
func NewArchiveToday(client *http.Client, log *logger.Logger) *ArchiveToday {
	return &ArchiveToday{
		httpClient: client,
		logger:     log,
		baseURL:    "https://archive.today",
	}
}

// Name returns the name of this archive source
func (a *ArchiveToday) Name() string {
	return "archive_today"
}

// GetSnapshots retrieves all snapshots for a domain from Archive.today
func (a *ArchiveToday) GetSnapshots(ctx context.Context, domain string) ([]Snapshot, error) {
	// Archive.today doesn't have a public API like Wayback Machine
	// In a production implementation, you would:
	// 1. Scrape the search results page
	// 2. Parse the HTML to extract snapshot URLs and timestamps
	// 3. Convert to Snapshot objects

	a.logger.Debug("Archive.today snapshot retrieval not fully implemented", "domain", domain)

	// For now, return empty slice
	// A full implementation would scrape archive.today search results
	return []Snapshot{}, nil
}

// GetContent retrieves the content of a specific snapshot from Archive.today
func (a *ArchiveToday) GetContent(ctx context.Context, originalURL string, timestamp time.Time) (string, error) {
	// Archive.today uses different URL structure
	// Would need to implement proper content fetching

	return "", fmt.Errorf("Archive.today content retrieval not implemented")
}
