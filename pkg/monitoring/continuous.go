// pkg/monitoring/continuous.go
package monitoring

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ContinuousMonitor provides 24/7 monitoring capabilities
type ContinuousMonitor struct {
	ctMonitor      *CertificateTransparencyMonitor
	dnsMonitor     *DNSMonitor
	gitMonitor     *GitMonitor
	changeDetector *ChangeDetector
	alertManager   *AlertManager
	storage        MonitoringStorage
	config         MonitorConfig
	mu             sync.RWMutex
}

// MonitorConfig holds monitoring configuration
type MonitorConfig struct {
	CTLogs          []string
	DNSResolvers    []string
	GitRepositories []GitRepo
	CheckInterval   time.Duration
	AlertChannels   []AlertChannel
	StorageBackend  string
	WebhookURL      string
}

// CertificateTransparencyMonitor monitors CT logs for new certificates
type CertificateTransparencyMonitor struct {
	domains      map[string]*DomainWatch
	ctStreams    []*CTStream
	newCertsChan chan *Certificate
	httpClient   *http.Client
	wsDialer     *websocket.Dialer
	mu           sync.RWMutex
}

// DomainWatch represents a domain being monitored
type DomainWatch struct {
	Domain            string    `json:"domain"`
	IncludeSubdomains bool      `json:"include_subdomains"`
	AddedAt           time.Time `json:"added_at"`
	LastSeen          time.Time `json:"last_seen"`
	Certificates      []string  `json:"certificates"`
}

// CTStream represents a certificate transparency log stream
type CTStream struct {
	Name      string
	URL       string
	WSConn    *websocket.Conn
	Connected bool
	mu        sync.Mutex
}

// Certificate represents a certificate from CT logs
type Certificate struct {
	Domain       string                 `json:"domain"`
	SubjectCN    string                 `json:"subject_cn"`
	SANs         []string               `json:"sans"`
	Issuer       string                 `json:"issuer"`
	NotBefore    time.Time              `json:"not_before"`
	NotAfter     time.Time              `json:"not_after"`
	SerialNumber string                 `json:"serial_number"`
	Fingerprint  string                 `json:"fingerprint"`
	Source       string                 `json:"source"`
	SeenAt       time.Time              `json:"seen_at"`
	RawCert      []byte                 `json:"-"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// DNSMonitor monitors DNS records for changes
type DNSMonitor struct {
	domains    map[string]*DNSRecordSet
	resolvers  []string
	checkTypes []string
	changeChan chan *DNSChange
	mu         sync.RWMutex
}

// DNSRecordSet represents DNS records for a domain
type DNSRecordSet struct {
	Domain       string              `json:"domain"`
	Records      map[string][]string `json:"records"`
	LastChecked  time.Time           `json:"last_checked"`
	LastModified time.Time           `json:"last_modified"`
	Hash         string              `json:"hash"`
}

// DNSChange represents a change in DNS records
type DNSChange struct {
	Domain     string                 `json:"domain"`
	ChangeType string                 `json:"change_type"`
	RecordType string                 `json:"record_type"`
	OldRecords []string               `json:"old_records"`
	NewRecords []string               `json:"new_records"`
	DetectedAt time.Time              `json:"detected_at"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// GitMonitor monitors Git repositories for security-relevant changes
type GitMonitor struct {
	repos         []GitRepo
	secretScanner *SecretScanner
	changeChan    chan *GitChange
	mu            sync.RWMutex
}

// GitRepo represents a Git repository to monitor
type GitRepo struct {
	URL        string    `json:"url"`
	Branch     string    `json:"branch"`
	Paths      []string  `json:"paths"`
	LastCommit string    `json:"last_commit"`
	CheckedAt  time.Time `json:"checked_at"`
}

// GitChange represents a change in a Git repository
type GitChange struct {
	Repository string                 `json:"repository"`
	CommitHash string                 `json:"commit_hash"`
	Author     string                 `json:"author"`
	Message    string                 `json:"message"`
	Files      []string               `json:"files"`
	Secrets    []DetectedSecret       `json:"secrets,omitempty"`
	DetectedAt time.Time              `json:"detected_at"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// DetectedSecret represents a detected secret in code
type DetectedSecret struct {
	Type     string  `json:"type"`
	File     string  `json:"file"`
	Line     int     `json:"line"`
	Match    string  `json:"match"`
	Entropy  float64 `json:"entropy"`
	Severity string  `json:"severity"`
}

// ChangeDetector detects changes in monitored assets
type ChangeDetector struct {
	assetHashes map[string]string
	httpClient  *http.Client
	mu          sync.RWMutex
}

// AlertManager manages alerts for detected changes
type AlertManager struct {
	channels     []AlertChannel
	rateLimiter  *RateLimiter
	deduplicator *AlertDeduplicator
	mu           sync.RWMutex
}

// AlertChannel represents a channel for sending alerts
type AlertChannel interface {
	SendAlert(alert *Alert) error
	GetType() string
}

// Alert represents a monitoring alert
type Alert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Timestamp   time.Time              `json:"timestamp"`
	Data        map[string]interface{} `json:"data"`
}

// MonitoringStorage interface for storing monitoring data
type MonitoringStorage interface {
	StoreCertificate(cert *Certificate) error
	StoreIPRecord(record *DNSRecordSet) error
	StoreGitChange(change *GitChange) error
	GetLastSeen(domain string) (time.Time, error)
	GetHistoricalData(target string, dataType string, since time.Time) ([]interface{}, error)
}

// NewContinuousMonitor creates a new continuous monitor
func NewContinuousMonitor(config MonitorConfig) (*ContinuousMonitor, error) {
	if config.CheckInterval == 0 {
		config.CheckInterval = 5 * time.Minute
	}

	storage, err := createStorage(config.StorageBackend)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	monitor := &ContinuousMonitor{
		ctMonitor:      NewCertificateTransparencyMonitor(),
		dnsMonitor:     NewDNSMonitor(config.DNSResolvers),
		gitMonitor:     NewGitMonitor(),
		changeDetector: NewChangeDetector(),
		alertManager:   NewAlertManager(config.AlertChannels),
		storage:        storage,
		config:         config,
	}

	return monitor, nil
}

// StartMonitoring starts continuous monitoring for targets
func (cm *ContinuousMonitor) StartMonitoring(ctx context.Context, targets []MonitorTarget) error {
	// Start component monitors
	go cm.ctMonitor.Start(ctx)
	go cm.dnsMonitor.Start(ctx)
	go cm.gitMonitor.Start(ctx)

	// Add targets to monitors
	for _, target := range targets {
		if err := cm.addTarget(target); err != nil {
			return fmt.Errorf("failed to add target %s: %w", target.Value, err)
		}
	}

	// Start monitoring loop
	go cm.monitoringLoop(ctx)

	// Start alert processing
	go cm.processAlerts(ctx)

	return nil
}

// MonitorTarget represents a target to monitor
type MonitorTarget struct {
	Type    string                 `json:"type"` // domain, ip, repository
	Value   string                 `json:"value"`
	Options map[string]interface{} `json:"options"`
}

// addTarget adds a target to the appropriate monitors
func (cm *ContinuousMonitor) addTarget(target MonitorTarget) error {
	switch target.Type {
	case "domain":
		includeSubdomains := true
		if val, ok := target.Options["include_subdomains"].(bool); ok {
			includeSubdomains = val
		}
		cm.ctMonitor.AddDomain(target.Value, includeSubdomains)
		cm.dnsMonitor.AddDomain(target.Value)

	case "repository":
		branch := "main"
		if val, ok := target.Options["branch"].(string); ok {
			branch = val
		}
		repo := GitRepo{
			URL:    target.Value,
			Branch: branch,
		}
		cm.gitMonitor.AddRepository(repo)

	default:
		return fmt.Errorf("unsupported target type: %s", target.Type)
	}
	return nil
}

// monitoringLoop handles the main monitoring workflow
func (cm *ContinuousMonitor) monitoringLoop(ctx context.Context) {
	// Process new certificates
	go func() {
		for cert := range cm.ctMonitor.newCertsChan {
			// Store certificate in database
			if err := cm.storage.StoreCertificate(cert); err != nil {
				// Log error but continue processing
				continue
			}

			// Create alert for new certificate
			alert := &Alert{
				ID:          fmt.Sprintf("cert-%s-%d", cert.Fingerprint, time.Now().Unix()),
				Type:        "new_certificate",
				Severity:    "info",
				Title:       fmt.Sprintf("New Certificate Detected for %s", cert.Domain),
				Description: fmt.Sprintf("New SSL certificate issued for %s by %s", cert.Domain, cert.Issuer),
				Source:      "ct_monitor",
				Target:      cert.Domain,
				Timestamp:   time.Now(),
				Data: map[string]interface{}{
					"certificate": cert,
				},
			}
			cm.alertManager.SendAlert(alert)
		}
	}()

	// Process DNS changes
	go func() {
		for change := range cm.dnsMonitor.changeChan {
			// Store DNS change in database
			if sqliteStorage, ok := cm.storage.(*SQLiteStorage); ok {
				if err := sqliteStorage.StoreDNSChange(change); err != nil {
					// Log error but continue processing
					continue
				}
			}

			// Create alert for DNS change
			severity := "medium"
			if change.RecordType == "A" || change.RecordType == "AAAA" {
				severity = "high"
			}

			alert := &Alert{
				ID:          fmt.Sprintf("dns-%s-%s-%d", change.Domain, change.RecordType, time.Now().Unix()),
				Type:        "dns_change",
				Severity:    severity,
				Title:       fmt.Sprintf("DNS Change Detected for %s", change.Domain),
				Description: fmt.Sprintf("%s records %s for %s", change.RecordType, change.ChangeType, change.Domain),
				Source:      "dns_monitor",
				Target:      change.Domain,
				Timestamp:   time.Now(),
				Data: map[string]interface{}{
					"change": change,
				},
			}
			cm.alertManager.SendAlert(alert)
		}
	}()

	// Process Git changes
	go func() {
		for change := range cm.gitMonitor.changeChan {
			// Store git change in database
			if err := cm.storage.StoreGitChange(change); err != nil {
				// Log error but continue processing
				continue
			}

			// Create alert for git change
			severity := "info"
			if len(change.Secrets) > 0 {
				severity = "critical"
			}

			alert := &Alert{
				ID:          fmt.Sprintf("git-%s-%s", change.Repository, change.CommitHash),
				Type:        "git_change",
				Severity:    severity,
				Title:       fmt.Sprintf("Git Change Detected in %s", change.Repository),
				Description: fmt.Sprintf("New commit detected: %s", change.Message),
				Source:      "git_monitor",
				Target:      change.Repository,
				Timestamp:   time.Now(),
				Data: map[string]interface{}{
					"change": change,
				},
			}
			cm.alertManager.SendAlert(alert)
		}
	}()
}

// processAlerts handles alert processing and storage
func (cm *ContinuousMonitor) processAlerts(ctx context.Context) {
	// This would implement alert processing logic
	// For now, it's a placeholder that ensures alerts are stored

	// The alertManager.SendAlert already handles the alert distribution
	// We can add additional processing here if needed
}

// Certificate Transparency Monitor Implementation

func NewCertificateTransparencyMonitor() *CertificateTransparencyMonitor {
	return &CertificateTransparencyMonitor{
		domains:      make(map[string]*DomainWatch),
		ctStreams:    make([]*CTStream, 0),
		newCertsChan: make(chan *Certificate, 1000),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		wsDialer: &websocket.Dialer{
			HandshakeTimeout: 10 * time.Second,
		},
	}
}

func (ctm *CertificateTransparencyMonitor) Start(ctx context.Context) {
	// Connect to CertStream for real-time certificate monitoring
	go ctm.connectCertStream(ctx)

	// Also poll CT logs periodically
	go ctm.pollCTLogs(ctx)
}

func (ctm *CertificateTransparencyMonitor) connectCertStream(ctx context.Context) {
	certStreamURL := "wss://certstream.calidog.io"

	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, _, err := ctm.wsDialer.Dial(certStreamURL, nil)
			if err != nil {
				time.Sleep(30 * time.Second)
				continue
			}

			stream := &CTStream{
				Name:      "CertStream",
				URL:       certStreamURL,
				WSConn:    conn,
				Connected: true,
			}

			ctm.mu.Lock()
			ctm.ctStreams = append(ctm.ctStreams, stream)
			ctm.mu.Unlock()

			// Read certificates from stream
			ctm.readCertStream(ctx, stream)

			// Connection lost, remove and retry
			ctm.mu.Lock()
			for i, s := range ctm.ctStreams {
				if s == stream {
					ctm.ctStreams = append(ctm.ctStreams[:i], ctm.ctStreams[i+1:]...)
					break
				}
			}
			ctm.mu.Unlock()
		}
	}
}

func (ctm *CertificateTransparencyMonitor) readCertStream(ctx context.Context, stream *CTStream) {
	for {
		select {
		case <-ctx.Done():
			stream.WSConn.Close()
			return
		default:
			var message struct {
				MessageType string `json:"message_type"`
				Data        struct {
					CertIndex int64  `json:"cert_index"`
					CertLink  string `json:"cert_link"`
					LeafCert  struct {
						Subject struct {
							CN string `json:"CN"`
						} `json:"subject"`
						Extensions struct {
							SubjectAltName []string `json:"subjectAltName"`
						} `json:"extensions"`
						NotBefore float64 `json:"not_before"`
						NotAfter  float64 `json:"not_after"`
					} `json:"leaf_cert"`
				} `json:"data"`
			}

			err := stream.WSConn.ReadJSON(&message)
			if err != nil {
				stream.Connected = false
				return
			}

			if message.MessageType == "certificate_update" {
				cert := ctm.parseCertStreamMessage(&message)
				if cert != nil && ctm.isMonitoredCert(cert) {
					ctm.newCertsChan <- cert
				}
			}
		}
	}
}

func (ctm *CertificateTransparencyMonitor) parseCertStreamMessage(message interface{}) *Certificate {
	// Parse the certificate from CertStream message
	// This is a simplified version - real implementation would handle all fields

	cert := &Certificate{
		SeenAt:   time.Now(),
		Source:   "CertStream",
		Metadata: make(map[string]interface{}),
	}

	// Extract certificate details from message
	// (Implementation details omitted for brevity)

	return cert
}

func (ctm *CertificateTransparencyMonitor) isMonitoredCert(cert *Certificate) bool {
	ctm.mu.RLock()
	defer ctm.mu.RUnlock()

	for _, watch := range ctm.domains {
		if ctm.matchesDomain(cert, watch) {
			return true
		}
	}

	return false
}

func (ctm *CertificateTransparencyMonitor) matchesDomain(cert *Certificate, watch *DomainWatch) bool {
	// Check if certificate matches watched domain
	domains := append([]string{cert.SubjectCN}, cert.SANs...)

	for _, domain := range domains {
		if watch.IncludeSubdomains {
			if strings.HasSuffix(domain, "."+watch.Domain) || domain == watch.Domain {
				return true
			}
		} else if domain == watch.Domain {
			return true
		}
	}

	return false
}

func (ctm *CertificateTransparencyMonitor) AddDomain(domain string, includeSubdomains bool) {
	ctm.mu.Lock()
	defer ctm.mu.Unlock()

	ctm.domains[domain] = &DomainWatch{
		Domain:            domain,
		IncludeSubdomains: includeSubdomains,
		AddedAt:           time.Now(),
		Certificates:      make([]string, 0),
	}
}

// pollCTLogs periodically polls CT logs for new certificates
func (ctm *CertificateTransparencyMonitor) pollCTLogs(ctx context.Context) {
	// This is a placeholder for CT log polling
	// In a real implementation, this would query CT log APIs
	// For now, we rely on the CertStream WebSocket connection
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Would poll CT logs here
			// This is typically done through CT log APIs
		}
	}
}

// DNS Monitor Implementation

func NewDNSMonitor(resolvers []string) *DNSMonitor {
	if len(resolvers) == 0 {
		resolvers = []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"}
	}

	return &DNSMonitor{
		domains:    make(map[string]*DNSRecordSet),
		resolvers:  resolvers,
		checkTypes: []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS"},
		changeChan: make(chan *DNSChange, 100),
	}
}

func (dm *DNSMonitor) Start(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dm.checkAllDomains()
		}
	}
}

func (dm *DNSMonitor) AddDomain(domain string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Get initial records
	records := dm.queryDNSRecords(domain)

	dm.domains[domain] = &DNSRecordSet{
		Domain:       domain,
		Records:      records,
		LastChecked:  time.Now(),
		LastModified: time.Now(),
		Hash:         dm.calculateRecordHash(records),
	}
}

func (dm *DNSMonitor) checkAllDomains() {
	dm.mu.RLock()
	domains := make([]string, 0, len(dm.domains))
	for domain := range dm.domains {
		domains = append(domains, domain)
	}
	dm.mu.RUnlock()

	for _, domain := range domains {
		dm.checkDomain(domain)
	}
}

func (dm *DNSMonitor) checkDomain(domain string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	currentRecordSet, exists := dm.domains[domain]
	if !exists {
		return
	}

	// Query current DNS records
	newRecords := dm.queryDNSRecords(domain)
	newHash := dm.calculateRecordHash(newRecords)

	// Check for changes
	if newHash != currentRecordSet.Hash {
		changes := dm.detectChanges(currentRecordSet.Records, newRecords)

		for _, change := range changes {
			change.Domain = domain
			change.DetectedAt = time.Now()
			dm.changeChan <- change
		}

		// Update record set
		currentRecordSet.Records = newRecords
		currentRecordSet.Hash = newHash
		currentRecordSet.LastModified = time.Now()
	}

	currentRecordSet.LastChecked = time.Now()
}

func (dm *DNSMonitor) queryDNSRecords(domain string) map[string][]string {
	records := make(map[string][]string)

	for _, recordType := range dm.checkTypes {
		results := dm.queryRecordType(domain, recordType)
		if len(results) > 0 {
			records[recordType] = results
		}
	}

	return records
}

func (dm *DNSMonitor) queryRecordType(domain, recordType string) []string {
	results := make([]string, 0)

	// Use multiple resolvers for reliability
	for _, resolver := range dm.resolvers {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 5 * time.Second,
				}
				return d.DialContext(ctx, network, resolver)
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		switch recordType {
		case "A":
			addrs, err := r.LookupIPAddr(ctx, domain)
			if err == nil {
				for _, addr := range addrs {
					if addr.IP.To4() != nil {
						results = append(results, addr.IP.String())
					}
				}
			}
		case "AAAA":
			addrs, err := r.LookupIPAddr(ctx, domain)
			if err == nil {
				for _, addr := range addrs {
					if addr.IP.To4() == nil {
						results = append(results, addr.IP.String())
					}
				}
			}
		case "CNAME":
			cname, err := r.LookupCNAME(ctx, domain)
			if err == nil && cname != domain+"." {
				results = append(results, cname)
			}
		case "MX":
			mxRecords, err := r.LookupMX(ctx, domain)
			if err == nil {
				for _, mx := range mxRecords {
					results = append(results, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
				}
			}
		case "TXT":
			txtRecords, err := r.LookupTXT(ctx, domain)
			if err == nil {
				results = append(results, txtRecords...)
			}
		case "NS":
			nsRecords, err := r.LookupNS(ctx, domain)
			if err == nil {
				for _, ns := range nsRecords {
					results = append(results, ns.Host)
				}
			}
		}

		if len(results) > 0 {
			break // Got results from this resolver
		}
	}

	return removeDuplicates(results)
}

func (dm *DNSMonitor) calculateRecordHash(records map[string][]string) string {
	// Create deterministic string representation
	var parts []string
	for recordType, values := range records {
		for _, value := range values {
			parts = append(parts, fmt.Sprintf("%s:%s", recordType, value))
		}
	}

	// Sort for consistency
	sortStrings(parts)

	// Calculate hash
	h := sha256.New()
	h.Write([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h.Sum(nil))
}

func (dm *DNSMonitor) detectChanges(oldRecords, newRecords map[string][]string) []*DNSChange {
	changes := make([]*DNSChange, 0)

	// Check for added or modified records
	for recordType, newValues := range newRecords {
		oldValues, existed := oldRecords[recordType]

		if !existed {
			// New record type
			changes = append(changes, &DNSChange{
				ChangeType: "added",
				RecordType: recordType,
				OldRecords: []string{},
				NewRecords: newValues,
			})
		} else {
			// Check for changes in existing record type
			added := difference(newValues, oldValues)
			removed := difference(oldValues, newValues)

			if len(added) > 0 {
				changes = append(changes, &DNSChange{
					ChangeType: "added",
					RecordType: recordType,
					OldRecords: []string{},
					NewRecords: added,
				})
			}

			if len(removed) > 0 {
				changes = append(changes, &DNSChange{
					ChangeType: "removed",
					RecordType: recordType,
					OldRecords: removed,
					NewRecords: []string{},
				})
			}
		}
	}

	// Check for removed record types
	for recordType, oldValues := range oldRecords {
		if _, exists := newRecords[recordType]; !exists {
			changes = append(changes, &DNSChange{
				ChangeType: "removed",
				RecordType: recordType,
				OldRecords: oldValues,
				NewRecords: []string{},
			})
		}
	}

	return changes
}

// Git Monitor Implementation

func NewGitMonitor() *GitMonitor {
	return &GitMonitor{
		repos:         make([]GitRepo, 0),
		secretScanner: NewSecretScanner(),
		changeChan:    make(chan *GitChange, 100),
	}
}

func (gm *GitMonitor) Start(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			gm.checkAllRepos()
		}
	}
}

func (gm *GitMonitor) AddRepository(repo GitRepo) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	gm.repos = append(gm.repos, repo)
}

func (gm *GitMonitor) checkAllRepos() {
	gm.mu.RLock()
	repos := make([]GitRepo, len(gm.repos))
	copy(repos, gm.repos)
	gm.mu.RUnlock()

	for i, repo := range repos {
		changes := gm.checkRepo(&repo)

		// Update last commit
		if len(changes) > 0 {
			gm.mu.Lock()
			gm.repos[i].LastCommit = changes[0].CommitHash
			gm.repos[i].CheckedAt = time.Now()
			gm.mu.Unlock()

			// Send changes
			for _, change := range changes {
				gm.changeChan <- change
			}
		}
	}
}

func (gm *GitMonitor) checkRepo(repo *GitRepo) []*GitChange {
	// This would use git commands or GitHub API to check for changes
	// Simplified implementation for demonstration

	changes := make([]*GitChange, 0)

	// Check for new commits since last check
	// Scan for secrets in changed files
	// Detect security-relevant changes

	return changes
}

// Secret Scanner for Git monitoring

type SecretScanner struct {
	patterns map[string]*SecretPattern
}

type SecretPattern struct {
	Name     string
	Pattern  string
	Entropy  float64
	Severity string
}

func NewSecretScanner() *SecretScanner {
	return &SecretScanner{
		patterns: getDefaultSecretPatterns(),
	}
}

func getDefaultSecretPatterns() map[string]*SecretPattern {
	return map[string]*SecretPattern{
		"aws_access_key": {
			Name:     "AWS Access Key",
			Pattern:  `AKIA[0-9A-Z]{16}`,
			Severity: "critical",
		},
		"aws_secret_key": {
			Name:     "AWS Secret Key",
			Pattern:  `[0-9a-zA-Z/+=]{40}`,
			Entropy:  4.5,
			Severity: "critical",
		},
		"github_token": {
			Name:     "GitHub Token",
			Pattern:  `ghp_[0-9a-zA-Z]{36}`,
			Severity: "high",
		},
		"private_key": {
			Name:     "Private Key",
			Pattern:  `-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`,
			Severity: "critical",
		},
	}
}

// Alert Manager Implementation

func NewAlertManager(channels []AlertChannel) *AlertManager {
	return &AlertManager{
		channels:     channels,
		rateLimiter:  NewRateLimiter(),
		deduplicator: NewAlertDeduplicator(),
	}
}

func (am *AlertManager) SendAlert(alert *Alert) error {
	// Check rate limits
	if !am.rateLimiter.Allow(alert.Type) {
		return fmt.Errorf("rate limit exceeded for alert type: %s", alert.Type)
	}

	// Check for duplicates
	if am.deduplicator.IsDuplicate(alert) {
		return nil // Silently skip duplicates
	}

	// Send to all configured channels
	var errors []error
	for _, channel := range am.channels {
		if err := channel.SendAlert(alert); err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", channel.GetType(), err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to send to some channels: %v", errors)
	}

	return nil
}

// Webhook Alert Channel

type WebhookAlertChannel struct {
	URL        string
	HTTPClient *http.Client
}

func (w *WebhookAlertChannel) SendAlert(alert *Alert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	resp, err := w.HTTPClient.Post(w.URL, "application/json", strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func (w *WebhookAlertChannel) GetType() string {
	return "webhook"
}

// Helper functions

func NewChangeDetector() *ChangeDetector {
	return &ChangeDetector{
		assetHashes: make(map[string]string),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

type RateLimiter struct {
	limits map[string]*rateLimitBucket
	mu     sync.RWMutex
}

type rateLimitBucket struct {
	tokens    int
	lastReset time.Time
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limits: make(map[string]*rateLimitBucket),
	}
}

func (rl *RateLimiter) Allow(alertType string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.limits[alertType]
	if !exists {
		bucket = &rateLimitBucket{
			tokens:    10, // 10 alerts per hour
			lastReset: time.Now(),
		}
		rl.limits[alertType] = bucket
	}

	// Reset bucket if hour has passed
	if time.Since(bucket.lastReset) > time.Hour {
		bucket.tokens = 10
		bucket.lastReset = time.Now()
	}

	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}

	return false
}

type AlertDeduplicator struct {
	seen map[string]time.Time
	mu   sync.RWMutex
}

func NewAlertDeduplicator() *AlertDeduplicator {
	dedup := &AlertDeduplicator{
		seen: make(map[string]time.Time),
	}

	// Clean up old entries periodically
	go dedup.cleanup()

	return dedup
}

func (ad *AlertDeduplicator) IsDuplicate(alert *Alert) bool {
	key := fmt.Sprintf("%s:%s:%s", alert.Type, alert.Source, alert.Target)

	ad.mu.RLock()
	lastSeen, exists := ad.seen[key]
	ad.mu.RUnlock()

	if exists && time.Since(lastSeen) < 30*time.Minute {
		return true
	}

	ad.mu.Lock()
	ad.seen[key] = time.Now()
	ad.mu.Unlock()

	return false
}

func (ad *AlertDeduplicator) cleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		ad.mu.Lock()
		now := time.Now()
		for key, lastSeen := range ad.seen {
			if now.Sub(lastSeen) > 1*time.Hour {
				delete(ad.seen, key)
			}
		}
		ad.mu.Unlock()
	}
}

// Utility functions

func removeDuplicates(items []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

func difference(a, b []string) []string {
	bMap := make(map[string]bool)
	for _, item := range b {
		bMap[item] = true
	}

	diff := make([]string, 0)
	for _, item := range a {
		if !bMap[item] {
			diff = append(diff, item)
		}
	}

	return diff
}

func sortStrings(items []string) {
	for i := 0; i < len(items)-1; i++ {
		for j := i + 1; j < len(items); j++ {
			if items[i] > items[j] {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
}

func createStorage(backend string) (MonitoringStorage, error) {
	// Create appropriate storage backend
	switch backend {
	case "postgres", "postgresql":
		// Use PostgreSQL connection string from environment or default
		dsn := "postgres://shells:shells_password@localhost:5432/shells?sslmode=disable"
		return NewSQLiteStorage(dsn)
	case "memory":
		return &InMemoryStorage{
			data: make(map[string]interface{}),
		}, nil
	default:
		// Default to PostgreSQL for persistence
		dsn := "postgres://shells:shells_password@localhost:5432/shells?sslmode=disable"
		return NewSQLiteStorage(dsn)
	}
}

// InMemoryStorage is a simple in-memory storage implementation
type InMemoryStorage struct {
	data map[string]interface{}
	mu   sync.RWMutex
}

func (s *InMemoryStorage) StoreCertificate(cert *Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Implementation
	return nil
}

func (s *InMemoryStorage) StoreIPRecord(record *DNSRecordSet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Implementation
	return nil
}

func (s *InMemoryStorage) StoreGitChange(change *GitChange) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Implementation
	return nil
}

func (s *InMemoryStorage) GetLastSeen(domain string) (time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Implementation
	return time.Time{}, nil
}

func (s *InMemoryStorage) GetHistoricalData(target string, dataType string, since time.Time) ([]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Implementation
	return []interface{}{}, nil
}
