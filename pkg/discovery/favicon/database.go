package favicon

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// Database manages favicon hash to technology mappings
type Database struct {
	entries map[string][]TechnologyEntry
	mutex   sync.RWMutex
	stats   DatabaseStats
}

// TechnologyEntry represents a technology identified by favicon hash
type TechnologyEntry struct {
	Hash        string   `json:"hash"`
	HashType    string   `json:"hash_type"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Version     string   `json:"version,omitempty"`
	Confidence  float64  `json:"confidence"`
	Source      string   `json:"source"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	References  []string `json:"references,omitempty"`
}

// DatabaseStats provides database statistics
type DatabaseStats struct {
	TotalEntries     int `json:"total_entries"`
	TotalScans       int `json:"total_scans"`
	TotalTechnologies int `json:"total_technologies"`
	UniqueHashes     int `json:"unique_hashes"`
}

// NewDatabase creates a new favicon database with default entries
func NewDatabase() *Database {
	db := &Database{
		entries: make(map[string][]TechnologyEntry),
		stats:   DatabaseStats{},
	}

	// Load default database
	db.loadDefaultEntries()

	return db
}

// LoadFromFile loads database entries from a JSON file
func (db *Database) LoadFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read database file: %w", err)
	}

	var entries []TechnologyEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to parse database file: %w", err)
	}

	db.mutex.Lock()
	defer db.mutex.Unlock()

	for _, entry := range entries {
		db.addEntryUnsafe(entry)
	}

	return nil
}

// SaveToFile saves database entries to a JSON file
func (db *Database) SaveToFile(filename string) error {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	var allEntries []TechnologyEntry
	for _, entries := range db.entries {
		allEntries = append(allEntries, entries...)
	}

	data, err := json.MarshalIndent(allEntries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal database: %w", err)
	}

	return os.WriteFile(filename, data, 0644)
}

// AddEntry adds a new technology entry to the database
func (db *Database) AddEntry(entry TechnologyEntry) error {
	if entry.Hash == "" || entry.Name == "" {
		return fmt.Errorf("hash and name are required")
	}

	db.mutex.Lock()
	defer db.mutex.Unlock()

	return db.addEntryUnsafe(entry)
}

// addEntryUnsafe adds an entry without locking (internal use)
func (db *Database) addEntryUnsafe(entry TechnologyEntry) error {
	key := strings.ToLower(entry.Hash)
	
	// Check for duplicates
	for _, existing := range db.entries[key] {
		if existing.Name == entry.Name && existing.HashType == entry.HashType {
			// Update existing entry
			existing.Confidence = entry.Confidence
			existing.Version = entry.Version
			existing.Description = entry.Description
			return nil
		}
	}

	// Add new entry
	db.entries[key] = append(db.entries[key], entry)
	db.stats.TotalEntries++

	return nil
}

// LookupByHash finds technologies by favicon hash
func (db *Database) LookupByHash(hash, hashType string) []TechnologyEntry {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	key := strings.ToLower(hash)
	entries, exists := db.entries[key]
	if !exists {
		return []TechnologyEntry{}
	}

	var matches []TechnologyEntry
	for _, entry := range entries {
		if hashType == "" || entry.HashType == hashType {
			matches = append(matches, entry)
		}
	}

	// Sort by confidence (highest first)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Confidence > matches[j].Confidence
	})

	return matches
}

// SearchByTechnology finds entries by technology name
func (db *Database) SearchByTechnology(technology string) []TechnologyEntry {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	var matches []TechnologyEntry
	searchTerm := strings.ToLower(technology)

	for _, entries := range db.entries {
		for _, entry := range entries {
			if strings.Contains(strings.ToLower(entry.Name), searchTerm) {
				matches = append(matches, entry)
			}
		}
	}

	return matches
}

// GetAllTechnologies returns a list of all technologies in the database
func (db *Database) GetAllTechnologies() []string {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	techSet := make(map[string]bool)
	for _, entries := range db.entries {
		for _, entry := range entries {
			techSet[entry.Name] = true
		}
	}

	var technologies []string
	for tech := range techSet {
		technologies = append(technologies, tech)
	}

	sort.Strings(technologies)
	return technologies
}

// GetStatistics returns database statistics
func (db *Database) GetStatistics() DatabaseStats {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	stats := db.stats
	stats.UniqueHashes = len(db.entries)
	
	techSet := make(map[string]bool)
	for _, entries := range db.entries {
		for _, entry := range entries {
			techSet[entry.Name] = true
		}
	}
	stats.TotalTechnologies = len(techSet)

	return stats
}

// Database access methods for scanner
func (db *Database) GetTotalScans() int {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	return db.stats.TotalScans
}

func (db *Database) GetTotalTechnologies() int {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	
	techSet := make(map[string]bool)
	for _, entries := range db.entries {
		for _, entry := range entries {
			techSet[entry.Name] = true
		}
	}
	return len(techSet)
}

func (db *Database) GetUniqueHashes() int {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	return len(db.entries)
}

func (db *Database) GetEntryCount() int {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	return db.stats.TotalEntries
}

// loadDefaultEntries loads the default favicon hash database
func (db *Database) loadDefaultEntries() {
	defaultEntries := []TechnologyEntry{
		// Web Servers
		{
			Hash: "2128322903", HashType: "mmh3", Name: "Fortinet", Category: "security",
			Confidence: 0.95, Source: "default", Description: "Fortinet security appliance",
		},
		{
			Hash: "743365239", HashType: "mmh3", Name: "Palo Alto Networks", Category: "security",
			Confidence: 0.95, Source: "default", Description: "Palo Alto Networks firewall",
		},
		{
			Hash: "-766957629", HashType: "mmh3", Name: "Jenkins", Category: "ci-cd",
			Confidence: 0.90, Source: "default", Description: "Jenkins automation server",
		},
		{
			Hash: "81586312", HashType: "mmh3", Name: "GitLab", Category: "development",
			Confidence: 0.90, Source: "default", Description: "GitLab version control",
		},
		{
			Hash: "-1255347784", HashType: "mmh3", Name: "Grafana", Category: "monitoring",
			Confidence: 0.85, Source: "default", Description: "Grafana monitoring dashboard",
		},

		// Content Management Systems
		{
			Hash: "708578229", HashType: "mmh3", Name: "WordPress", Category: "cms",
			Confidence: 0.80, Source: "default", Description: "WordPress content management system",
		},
		{
			Hash: "1713906415", HashType: "mmh3", Name: "Drupal", Category: "cms",
			Confidence: 0.80, Source: "default", Description: "Drupal content management system",
		},
		{
			Hash: "-235893474", HashType: "mmh3", Name: "Joomla", Category: "cms",
			Confidence: 0.80, Source: "default", Description: "Joomla content management system",
		},

		// Web Frameworks
		{
			Hash: "1588244429", HashType: "mmh3", Name: "Django", Category: "framework",
			Confidence: 0.75, Source: "default", Description: "Django web framework",
		},
		{
			Hash: "-1420295627", HashType: "mmh3", Name: "Laravel", Category: "framework",
			Confidence: 0.75, Source: "default", Description: "Laravel PHP framework",
		},
		{
			Hash: "372759689", HashType: "mmh3", Name: "React", Category: "frontend",
			Confidence: 0.70, Source: "default", Description: "React frontend framework",
		},

		// E-commerce Platforms
		{
			Hash: "1842519814", HashType: "mmh3", Name: "Shopify", Category: "ecommerce",
			Confidence: 0.85, Source: "default", Description: "Shopify e-commerce platform",
		},
		{
			Hash: "-1248316168", HashType: "mmh3", Name: "Magento", Category: "ecommerce",
			Confidence: 0.85, Source: "default", Description: "Magento e-commerce platform",
		},
		{
			Hash: "1335283723", HashType: "mmh3", Name: "WooCommerce", Category: "ecommerce",
			Confidence: 0.80, Source: "default", Description: "WooCommerce for WordPress",
		},

		// Development Tools
		{
			Hash: "-1365892801", HashType: "mmh3", Name: "GitHub", Category: "development",
			Confidence: 0.90, Source: "default", Description: "GitHub version control",
		},
		{
			Hash: "1889419479", HashType: "mmh3", Name: "Bitbucket", Category: "development",
			Confidence: 0.90, Source: "default", Description: "Bitbucket version control",
		},
		{
			Hash: "-1336066072", HashType: "mmh3", Name: "JIRA", Category: "project-management",
			Confidence: 0.85, Source: "default", Description: "Atlassian JIRA",
		},
		{
			Hash: "398081544", HashType: "mmh3", Name: "Confluence", Category: "collaboration",
			Confidence: 0.85, Source: "default", Description: "Atlassian Confluence",
		},

		// Monitoring and Analytics
		{
			Hash: "-235893474", HashType: "mmh3", Name: "Kibana", Category: "monitoring",
			Confidence: 0.80, Source: "default", Description: "Elastic Kibana",
		},
		{
			Hash: "1953045938", HashType: "mmh3", Name: "Prometheus", Category: "monitoring",
			Confidence: 0.80, Source: "default", Description: "Prometheus monitoring",
		},
		{
			Hash: "-1205822479", HashType: "mmh3", Name: "Splunk", Category: "monitoring",
			Confidence: 0.85, Source: "default", Description: "Splunk analytics platform",
		},

		// Network Equipment
		{
			Hash: "1942532307", HashType: "mmh3", Name: "pfSense", Category: "network",
			Confidence: 0.90, Source: "default", Description: "pfSense firewall",
		},
		{
			Hash: "-1448444208", HashType: "mmh3", Name: "Ubiquiti", Category: "network",
			Confidence: 0.85, Source: "default", Description: "Ubiquiti network equipment",
		},
		{
			Hash: "1378306495", HashType: "mmh3", Name: "MikroTik", Category: "network",
			Confidence: 0.85, Source: "default", Description: "MikroTik router",
		},

		// Cloud Platforms
		{
			Hash: "1120562854", HashType: "mmh3", Name: "AWS", Category: "cloud",
			Confidence: 0.80, Source: "default", Description: "Amazon Web Services",
		},
		{
			Hash: "-1439374736", HashType: "mmh3", Name: "Azure", Category: "cloud",
			Confidence: 0.80, Source: "default", Description: "Microsoft Azure",
		},
		{
			Hash: "1653422767", HashType: "mmh3", Name: "Google Cloud", Category: "cloud",
			Confidence: 0.80, Source: "default", Description: "Google Cloud Platform",
		},

		// Databases
		{
			Hash: "-1636564815", HashType: "mmh3", Name: "phpMyAdmin", Category: "database",
			Confidence: 0.85, Source: "default", Description: "phpMyAdmin MySQL interface",
		},
		{
			Hash: "1364128287", HashType: "mmh3", Name: "MongoDB", Category: "database",
			Confidence: 0.80, Source: "default", Description: "MongoDB database",
		},
		{
			Hash: "-877424385", HashType: "mmh3", Name: "Adminer", Category: "database",
			Confidence: 0.80, Source: "default", Description: "Adminer database tool",
		},

		// Web Servers
		{
			Hash: "2130473948", HashType: "mmh3", Name: "Apache", Category: "web-server",
			Confidence: 0.70, Source: "default", Description: "Apache HTTP Server",
		},
		{
			Hash: "-1282058891", HashType: "mmh3", Name: "Nginx", Category: "web-server",
			Confidence: 0.70, Source: "default", Description: "Nginx web server",
		},
		{
			Hash: "1196411029", HashType: "mmh3", Name: "IIS", Category: "web-server",
			Confidence: 0.75, Source: "default", Description: "Microsoft IIS",
		},

		// Security Tools
		{
			Hash: "-1256734829", HashType: "mmh3", Name: "Nessus", Category: "security",
			Confidence: 0.90, Source: "default", Description: "Tenable Nessus scanner",
		},
		{
			Hash: "1893092004", HashType: "mmh3", Name: "OpenVAS", Category: "security",
			Confidence: 0.85, Source: "default", Description: "OpenVAS vulnerability scanner",
		},
		{
			Hash: "-573069290", HashType: "mmh3", Name: "Burp Suite", Category: "security",
			Confidence: 0.90, Source: "default", Description: "PortSwigger Burp Suite",
		},

		// Communication Tools
		{
			Hash: "737387491", HashType: "mmh3", Name: "Slack", Category: "communication",
			Confidence: 0.80, Source: "default", Description: "Slack team communication",
		},
		{
			Hash: "-1367798989", HashType: "mmh3", Name: "Discord", Category: "communication",
			Confidence: 0.80, Source: "default", Description: "Discord chat platform",
		},
		{
			Hash: "1947286925", HashType: "mmh3", Name: "Zoom", Category: "communication",
			Confidence: 0.80, Source: "default", Description: "Zoom video conferencing",
		},
	}

	// Add all default entries
	for _, entry := range defaultEntries {
		db.addEntryUnsafe(entry)
	}
}

// UpdateEntry updates an existing entry or adds it if it doesn't exist
func (db *Database) UpdateEntry(hash string, updates TechnologyEntry) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	key := strings.ToLower(hash)
	entries, exists := db.entries[key]
	if !exists {
		return db.addEntryUnsafe(updates)
	}

	// Find and update existing entry
	for i, entry := range entries {
		if entry.Name == updates.Name && entry.HashType == updates.HashType {
			entries[i] = updates
			return nil
		}
	}

	// Add as new entry if not found
	return db.addEntryUnsafe(updates)
}

// DeleteEntry removes an entry from the database
func (db *Database) DeleteEntry(hash, technology, hashType string) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	key := strings.ToLower(hash)
	entries, exists := db.entries[key]
	if !exists {
		return fmt.Errorf("hash not found: %s", hash)
	}

	// Find and remove entry
	for i, entry := range entries {
		if entry.Name == technology && entry.HashType == hashType {
			db.entries[key] = append(entries[:i], entries[i+1:]...)
			db.stats.TotalEntries--
			
			// Remove key if no entries left
			if len(db.entries[key]) == 0 {
				delete(db.entries, key)
			}
			return nil
		}
	}

	return fmt.Errorf("entry not found: %s/%s/%s", hash, technology, hashType)
}

// ExportDatabase exports the database in various formats
func (db *Database) ExportDatabase(format string) ([]byte, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	var allEntries []TechnologyEntry
	for _, entries := range db.entries {
		allEntries = append(allEntries, entries...)
	}

	switch format {
	case "json":
		return json.MarshalIndent(allEntries, "", "  ")
	case "csv":
		return db.exportCSV(allEntries)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

func (db *Database) exportCSV(entries []TechnologyEntry) ([]byte, error) {
	var lines []string
	
	// Header
	lines = append(lines, "Hash,HashType,Name,Category,Version,Confidence,Source,Description")
	
	// Data rows
	for _, entry := range entries {
		line := fmt.Sprintf("%s,%s,%s,%s,%s,%.2f,%s,%s",
			entry.Hash, entry.HashType, entry.Name, entry.Category,
			entry.Version, entry.Confidence, entry.Source, entry.Description)
		lines = append(lines, line)
	}
	
	return []byte(strings.Join(lines, "\n")), nil
}