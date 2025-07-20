// pkg/passive/helpers.go
package passive

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Helper methods for certificate intelligence

func (c *CertIntel) convertToCertificate(cert CertificateRecord) Certificate {
	return Certificate{
		DNSNames:  cert.SANs,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}
}

func (c *CertIntel) calculateFingerprint(cert Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", hash)
}

func (c *CertIntel) extractEmails(cert Certificate) []string {
	var emails []string
	// Extract emails from certificate extensions
	// This is a simplified implementation
	return emails
}

func (c *CertIntel) enrichIntelligence(intel *CertificateIntel, cert Certificate) {
	// Add additional metadata and analysis
	// This is a placeholder for enrichment logic
}

func (c *CertIntel) generateExamples(prefix string, numbers []int) []string {
	var examples []string
	sort.Ints(numbers)
	for i, num := range numbers {
		if i >= 3 { // Limit to 3 examples
			break
		}
		examples = append(examples, fmt.Sprintf("%s%d", prefix, num))
	}
	return examples
}

func (p *PatternDatabase) generateExamples(prefix string, numbers []int) []string {
	var examples []string
	sort.Ints(numbers)
	for i, num := range numbers {
		if i >= 3 { // Limit to 3 examples
			break
		}
		examples = append(examples, fmt.Sprintf("%s%d", prefix, num))
	}
	return examples
}

func (c *CertIntel) generateSequentialPredictions(pattern Pattern) []string {
	var predictions []string
	// Extract pattern and generate sequential predictions
	// This is a simplified implementation
	return predictions
}

func (c *CertIntel) generatePrefixPredictions(pattern Pattern) []string {
	var predictions []string
	// Generate predictions based on prefix patterns
	return predictions
}

func (c *CertIntel) generateSuffixPredictions(pattern Pattern) []string {
	var predictions []string
	// Generate predictions based on suffix patterns
	return predictions
}

func (c *CertIntel) generateTemplatePredictions(pattern Pattern) []string {
	var predictions []string
	// Generate predictions based on template patterns
	return predictions
}

func (c *CertIntel) predictDomainsFromEmailPatterns(patterns []EmailPattern) []string {
	var domains []string
	for _, pattern := range patterns {
		// Predict domains based on email patterns
		domains = append(domains, pattern.Domain)
	}
	return domains
}

// Helper methods for archive intelligence

func (a *ArchiveIntel) collectAllSnapshots(domain string) []Snapshot {
	var allSnapshots []Snapshot
	
	for _, source := range a.sources {
		snapshots, err := source.GetSnapshots(domain)
		if err != nil {
			a.logger.Error("Failed to get snapshots", "source", source.Name(), "error", err)
			continue
		}
		allSnapshots = append(allSnapshots, snapshots...)
	}
	
	return allSnapshots
}

func (a *ArchiveIntel) getSnapshotContent(snapshot Snapshot) (string, error) {
	// Find the appropriate source and get content
	for _, source := range a.sources {
		content, err := source.GetSnapshotContent(snapshot.URL, snapshot.Timestamp)
		if err == nil {
			return content, nil
		}
	}
	return "", fmt.Errorf("failed to get content for snapshot")
}

func (a *ArchiveIntel) addOrUpdateEndpoint(findings *ArchiveFindings, endpoint ArchivedEndpoint, timestamp time.Time) {
	// Check if endpoint already exists
	for i, existing := range findings.DeletedEndpoints {
		if existing.URL == endpoint.URL {
			// Update existing endpoint
			findings.DeletedEndpoints[i].LastSeen = timestamp
			if timestamp.Before(existing.FirstSeen) {
				findings.DeletedEndpoints[i].FirstSeen = timestamp
			}
			return
		}
	}
	
	// Add new endpoint
	endpoint.FirstSeen = timestamp
	endpoint.LastSeen = timestamp
	findings.DeletedEndpoints = append(findings.DeletedEndpoints, endpoint)
}

func (a *ArchiveIntel) extractAPIDocs(content, baseURL string) []APIDoc {
	var docs []APIDoc
	
	// Look for common API documentation patterns
	patterns := []string{
		`api.*docs?`,
		`swagger`,
		`openapi`,
		`postman`,
		`documentation`,
	}
	
	for _, pattern := range patterns {
		regex := regexp.MustCompile(`(?i)` + pattern)
		if regex.MatchString(content) {
			docs = append(docs, APIDoc{
				URL:         baseURL,
				Title:       "API Documentation",
				Timestamp:   time.Now(),
				Description: "Found API documentation reference",
			})
			break
		}
	}
	
	return docs
}

func (a *ArchiveIntel) identifyPatterns(findings *ArchiveFindings) {
	// Analyze collected data to identify patterns and predict new endpoints
	// This is a placeholder for pattern identification logic
}

func (a *ArchiveIntel) sortSnapshotsByTime(snapshots []Snapshot) {
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Timestamp.Before(snapshots[j].Timestamp)
	})
}

func (a *ArchiveIntel) extractSecurityHeaders(content string) map[string]string {
	headers := make(map[string]string)
	
	// Extract security headers from content
	// This is a simplified implementation
	headerPatterns := map[string]*regexp.Regexp{
		"Content-Security-Policy": regexp.MustCompile(`(?i)content-security-policy:\s*([^\r\n]+)`),
		"Strict-Transport-Security": regexp.MustCompile(`(?i)strict-transport-security:\s*([^\r\n]+)`),
		"X-Frame-Options": regexp.MustCompile(`(?i)x-frame-options:\s*([^\r\n]+)`),
		"X-Content-Type-Options": regexp.MustCompile(`(?i)x-content-type-options:\s*([^\r\n]+)`),
	}
	
	for header, regex := range headerPatterns {
		if matches := regex.FindStringSubmatch(content); len(matches) > 1 {
			headers[header] = strings.TrimSpace(matches[1])
		}
	}
	
	return headers
}

func (a *ArchiveIntel) detectTechnology(content string) string {
	// Simple technology detection
	techPatterns := map[string]*regexp.Regexp{
		"WordPress": regexp.MustCompile(`(?i)wp-content|wordpress`),
		"React": regexp.MustCompile(`(?i)react|reactjs`),
		"Angular": regexp.MustCompile(`(?i)angular|angularjs`),
		"Vue": regexp.MustCompile(`(?i)vue\.js|vuejs`),
		"jQuery": regexp.MustCompile(`(?i)jquery`),
		"Bootstrap": regexp.MustCompile(`(?i)bootstrap`),
	}
	
	for tech, regex := range techPatterns {
		if regex.MatchString(content) {
			return tech
		}
	}
	
	return "Unknown"
}

// Helper methods for code repository intelligence

func (c *CodeIntel) getRepositoryFiles(repo Repository) ([]RepositoryFile, error) {
	// Placeholder implementation for getting repository files
	return []RepositoryFile{}, nil
}

func (c *CodeIntel) isBinaryFile(path string) bool {
	// Simple check for binary file extensions
	binaryExtensions := []string{
		".exe", ".dll", ".so", ".dylib", ".jar", ".war", ".ear",
		".zip", ".tar", ".gz", ".rar", ".7z",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",
	}
	
	pathLower := strings.ToLower(path)
	for _, ext := range binaryExtensions {
		if strings.HasSuffix(pathLower, ext) {
			return true
		}
	}
	
	return false
}