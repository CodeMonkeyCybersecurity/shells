// pkg/passive/types.go
package passive

import (
	"crypto/x509"
	"math/big"
	"time"
)

// Name represents a distinguished name for certificates
type Name struct {
	Country            []string
	Organization       []string
	OrganizationalUnit []string
	Locality           []string
	Province           []string
	StreetAddress      []string
	PostalCode         []string
	SerialNumber       string
	CommonName         string
}

// Certificate represents an X.509 certificate for passive scanning
type Certificate struct {
	Raw                   []byte
	DNSNames              []string
	Subject               Name
	Issuer                Name
	SerialNumber          *big.Int
	NotBefore             time.Time
	NotAfter              time.Time
	KeyUsage              x509.KeyUsage
	ExtKeyUsage           []x509.ExtKeyUsage
	UnknownExtKeyUsage    []string
	BasicConstraintsValid bool
	IsCA                  bool
	MaxPathLen            int
	MaxPathLenZero        bool
}

// CertificateIntel represents intelligence extracted from certificates
type CertificateIntel struct {
	Domain            string    `json:"domain"`
	SANs              []string  `json:"sans"`
	Organizations     []string  `json:"organizations"`
	Emails            []string  `json:"emails"`
	IssuedDate        time.Time `json:"issued_date"`
	ExpiryDate        time.Time `json:"expiry_date"`
	Issuer            string    `json:"issuer"`
	SerialNumber      string    `json:"serial_number"`
	Fingerprint       string    `json:"fingerprint"`
	WildcardPatterns  []string  `json:"wildcard_patterns"`
	InternalNames     []string  `json:"internal_names"`
}

// Pattern represents a naming pattern found in certificates
type Pattern struct {
	Type        string    `json:"type"`
	Template    string    `json:"template"`
	Examples    []string  `json:"examples"`
	Confidence  float64   `json:"confidence"`
	Predictions []string  `json:"predictions"`
}

// ArchiveFindings represents intelligence extracted from web archives
type ArchiveFindings struct {
	Domain           string                     `json:"domain"`
	DeletedEndpoints []ArchivedEndpoint         `json:"deleted_endpoints"`
	OldParameters    []string                   `json:"old_parameters"`
	DevURLs          []string                   `json:"dev_urls"`
	APIDocumentation []APIDoc                   `json:"api_documentation"`
	ExposedSecrets   []Secret                   `json:"exposed_secrets"`
	TechStackChanges []TechChange               `json:"tech_stack_changes"`
	SecurityHeaders  map[string][]HeaderChange `json:"security_headers"`
}

// ArchivedEndpoint represents an endpoint found in archives
type ArchivedEndpoint struct {
	URL        string    `json:"url"`
	Method     string    `json:"method"`
	Parameters []string  `json:"parameters"`
	LastSeen   time.Time `json:"last_seen"`
	FirstSeen  time.Time `json:"first_seen"`
	Status     string    `json:"status"` // active, deleted, moved
}

// Secret represents exposed credentials found in archives
type Secret struct {
	Type      string    `json:"type"`
	Value     string    `json:"value"` // redacted
	URL       string    `json:"url"`
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
	Context   string    `json:"context"`
}

// APIDoc represents API documentation found in archives
type APIDoc struct {
	URL         string    `json:"url"`
	Title       string    `json:"title"`
	Version     string    `json:"version"`
	Endpoints   []string  `json:"endpoints"`
	Timestamp   time.Time `json:"timestamp"`
	Description string    `json:"description"`
}

// TechChange represents a technology stack change over time
type TechChange struct {
	Timestamp  time.Time `json:"timestamp"`
	OldTech    string    `json:"old_tech"`
	NewTech    string    `json:"new_tech"`
	ChangeType string    `json:"change_type"`
	Endpoints  []string  `json:"endpoints"`
}

// HeaderChange represents a security header change over time
type HeaderChange struct {
	Timestamp time.Time `json:"timestamp"`
	OldValue  string    `json:"old_value"`
	NewValue  string    `json:"new_value"`
	Removed   bool      `json:"removed"`
}

// SecurityDegradation represents a security posture degradation
type SecurityDegradation struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    string    `json:"severity"`
	URLs        []string  `json:"urls"`
}

// JavaScriptFindings represents findings from JavaScript analysis
type JavaScriptFindings struct {
	Parameters   []string `json:"parameters"`
	APIEndpoints []string `json:"api_endpoints"`
	Secrets      []Secret `json:"secrets"`
}

// JavaScriptAnalyzer analyzes JavaScript for intelligence
type JavaScriptAnalyzer struct {
	regexPatterns map[string]string
}

// DiffEngine compares content between different time periods
type DiffEngine struct {
	maxDiffSize int
}

// NewJavaScriptAnalyzer creates a new JavaScript analyzer
func NewJavaScriptAnalyzer() *JavaScriptAnalyzer {
	return &JavaScriptAnalyzer{
		regexPatterns: make(map[string]string),
	}
}

// AnalyzeJavaScript analyzes JavaScript content for intelligence
func (js *JavaScriptAnalyzer) AnalyzeJavaScript(content, sourceURL string) JavaScriptFindings {
	return JavaScriptFindings{
		Parameters:   []string{},
		APIEndpoints: []string{},
		Secrets:      []Secret{},
	}
}

// NewDiffEngine creates a new diff engine
func NewDiffEngine() *DiffEngine {
	return &DiffEngine{
		maxDiffSize: 1024 * 1024, // 1MB
	}
}

// Archive source implementations

// ArchiveToday implements the ArchiveSource interface
type ArchiveToday struct {
	baseURL string
	client  interface{}
}

func NewArchiveToday() *ArchiveToday {
	return &ArchiveToday{
		baseURL: "https://archive.today",
	}
}

func (a *ArchiveToday) Name() string {
	return "archive_today"
}

func (a *ArchiveToday) GetSnapshots(domain string) ([]Snapshot, error) {
	return []Snapshot{}, nil
}

func (a *ArchiveToday) GetSnapshotContent(url string, timestamp time.Time) (string, error) {
	return "", nil
}

// CommonCrawl implements the ArchiveSource interface
type CommonCrawl struct {
	baseURL string
	client  interface{}
}

func NewCommonCrawl() *CommonCrawl {
	return &CommonCrawl{
		baseURL: "https://commoncrawl.org",
	}
}

func (c *CommonCrawl) Name() string {
	return "common_crawl"
}

func (c *CommonCrawl) GetSnapshots(domain string) ([]Snapshot, error) {
	return []Snapshot{}, nil
}

func (c *CommonCrawl) GetSnapshotContent(url string, timestamp time.Time) (string, error) {
	return "", nil
}

// CT Log API implementations

// FacebookCTAPI implements the CTLogAPI interface
type FacebookCTAPI struct {
	baseURL string
	client  interface{}
}

func NewFacebookCTAPI() *FacebookCTAPI {
	return &FacebookCTAPI{
		baseURL: "https://ct.facebook.com",
	}
}

func (f *FacebookCTAPI) Name() string {
	return "facebook_ct"
}

func (f *FacebookCTAPI) SearchDomain(domain string) ([]CertificateRecord, error) {
	return []CertificateRecord{}, nil
}

func (f *FacebookCTAPI) StreamNewCertificates(domain string) <-chan CertificateRecord {
	ch := make(chan CertificateRecord)
	close(ch)
	return ch
}

// GoogleCTAPI implements the CTLogAPI interface
type GoogleCTAPI struct {
	baseURL string
	client  interface{}
}

func NewGoogleCTAPI() *GoogleCTAPI {
	return &GoogleCTAPI{
		baseURL: "https://ct.googleapis.com",
	}
}

func (g *GoogleCTAPI) Name() string {
	return "google_ct"
}

func (g *GoogleCTAPI) SearchDomain(domain string) ([]CertificateRecord, error) {
	return []CertificateRecord{}, nil
}

func (g *GoogleCTAPI) StreamNewCertificates(domain string) <-chan CertificateRecord {
	ch := make(chan CertificateRecord)
	close(ch)
	return ch
}

// CensysCertAPI implements the CTLogAPI interface
type CensysCertAPI struct {
	baseURL string
	client  interface{}
}

func NewCensysCertAPI() *CensysCertAPI {
	return &CensysCertAPI{
		baseURL: "https://search.censys.io",
	}
}

func (c *CensysCertAPI) Name() string {
	return "censys_cert"
}

func (c *CensysCertAPI) SearchDomain(domain string) ([]CertificateRecord, error) {
	return []CertificateRecord{}, nil
}

func (c *CensysCertAPI) StreamNewCertificates(domain string) <-chan CertificateRecord {
	ch := make(chan CertificateRecord)
	close(ch)
	return ch
}