package discovery

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// TargetType represents the type of input target
type TargetType string

const (
	TargetTypeCompany     TargetType = "company"
	TargetTypeEmail       TargetType = "email"
	TargetTypeDomain      TargetType = "domain"
	TargetTypeIP          TargetType = "ip"
	TargetTypeIPRange     TargetType = "ip_range"
	TargetTypeNetwork     TargetType = "network"
	TargetTypeURL         TargetType = "url"
	TargetTypeASN         TargetType = "asn"
	TargetTypeCertificate TargetType = "certificate"
	TargetTypeUnknown     TargetType = "unknown"
)

// Target represents a parsed input target
type Target struct {
	Raw        string            `json:"raw"`
	Type       TargetType        `json:"type"`
	Value      string            `json:"value"`
	Metadata   map[string]string `json:"metadata"`
	Confidence float64           `json:"confidence"`
	CreatedAt  time.Time         `json:"created_at"`
}

// Asset represents a discovered asset
type Asset struct {
	ID           string            `json:"id"`
	Type         AssetType         `json:"type"`
	Value        string            `json:"value"`
	Domain       string            `json:"domain,omitempty"`
	IP           string            `json:"ip,omitempty"`
	Port         int               `json:"port,omitempty"`
	Protocol     string            `json:"protocol,omitempty"`
	Title        string            `json:"title,omitempty"`
	Technology   []string          `json:"technology,omitempty"`
	Metadata     map[string]string `json:"metadata"`
	Source       string            `json:"source"`
	Confidence   float64           `json:"confidence"`
	Priority     int               `json:"priority"`
	DiscoveredAt time.Time         `json:"discovered_at"`
	LastSeen     time.Time         `json:"last_seen"`
	Tags         []string          `json:"tags,omitempty"`
}

// AssetType represents the type of discovered asset
type AssetType string

const (
	AssetTypeDomain            AssetType = "domain"
	AssetTypeSubdomain         AssetType = "subdomain"
	AssetTypeURL               AssetType = "url"
	AssetTypeIP                AssetType = "ip"
	AssetTypeIPRange           AssetType = "ip_range"
	AssetTypeASN               AssetType = "asn"
	AssetTypePort              AssetType = "port"
	AssetTypeService           AssetType = "service"
	AssetTypeEndpoint          AssetType = "endpoint"
	AssetTypeAPI               AssetType = "api"
	AssetTypeLogin             AssetType = "login"
	AssetTypeAdmin             AssetType = "admin"
	AssetTypePayment           AssetType = "payment"
	AssetTypeRepository        AssetType = "repository"
	AssetTypeCloudAccount      AssetType = "cloud_account"
	AssetTypeFile              AssetType = "file"
	AssetTypeDirectory         AssetType = "directory"
	AssetTypeCertificate       AssetType = "certificate"
	AssetTypeEmail             AssetType = "email"
	AssetTypeAuthentication    AssetType = "authentication"
	AssetTypeAuth              AssetType = "auth"
	AssetTypeMailServer        AssetType = "mail_server"
	AssetTypeAdminPanel        AssetType = "admin_panel"
	AssetTypeOrganization      AssetType = "organization"
	AssetTypeCloudStorage      AssetType = "cloud_storage"
	AssetTypeCDN               AssetType = "cdn"
	AssetTypeWebApp            AssetType = "web_app"
	AssetTypeContainerRegistry AssetType = "container_registry"
	AssetTypeVulnerability     AssetType = "vulnerability"
)

// Relationship represents a relationship between assets
type Relationship struct {
	ID        string            `json:"id"`
	Source    string            `json:"source"` // Source asset ID
	Target    string            `json:"target"` // Target asset ID
	Type      RelationType      `json:"type"`
	Weight    float64           `json:"weight"`
	Metadata  map[string]string `json:"metadata"`
	CreatedAt time.Time         `json:"created_at"`
}

// RelationType represents the type of relationship between assets
type RelationType string

const (
	RelationTypeSubdomain     RelationType = "subdomain"
	RelationTypeRedirect      RelationType = "redirect"
	RelationTypeCNAME         RelationType = "cname"
	RelationTypeLink          RelationType = "link"
	RelationTypeCertificate   RelationType = "certificate"
	RelationTypeService       RelationType = "service"
	RelationTypeOwnership     RelationType = "ownership"
	RelationTypeHosting       RelationType = "hosting"
	RelationTypeTechnology    RelationType = "technology"
	RelationTypeNetwork       RelationType = "network"
	RelationTypeVulnerability RelationType = "vulnerability"
)

// DiscoverySession represents a discovery session
type DiscoverySession struct {
	ID              string                   `json:"id"`
	Target          Target                   `json:"target"`
	DiscoveryTarget *types.DiscoveryTarget   `json:"discovery_target,omitempty"`
	Assets          map[string]*Asset        `json:"assets"`
	Relationships   map[string]*Relationship `json:"relationships"`
	Status          SessionStatus            `json:"status"`
	StartedAt       time.Time                `json:"started_at"`
	CompletedAt     *time.Time               `json:"completed_at,omitempty"`
	Progress        float64                  `json:"progress"`
	TotalDiscovered int                      `json:"total_discovered"`
	HighValueAssets int                      `json:"high_value_assets"`
	Errors          []string                 `json:"errors,omitempty"`
	Config          *DiscoveryConfig         `json:"config"`
	// Add organization context
	Organization *correlation.Organization `json:"organization,omitempty"`
	OrgContext   *OrganizationContext      `json:"org_context,omitempty"`
	Metadata     map[string]interface{}    `json:"metadata,omitempty"`
}

// OrganizationContext provides context for discovery modules
type OrganizationContext struct {
	OrgID         string
	OrgName       string
	KnownDomains  []string
	KnownIPRanges []string
	EmailPatterns []string
	Subsidiaries  []string
	Technologies  []string
	IndustryType  string
}

// SessionStatus represents the status of a discovery session
type SessionStatus string

const (
	StatusPending   SessionStatus = "pending"
	StatusRunning   SessionStatus = "running"
	StatusCompleted SessionStatus = "completed"
	StatusFailed    SessionStatus = "failed"
	StatusPaused    SessionStatus = "paused"
)

// DiscoveryConfig represents configuration for asset discovery
type DiscoveryConfig struct {
	MaxDepth        int           `json:"max_depth"`
	MaxAssets       int           `json:"max_assets"`
	Timeout         time.Duration `json:"timeout"`
	EnableDNS       bool          `json:"enable_dns"`
	EnableCertLog   bool          `json:"enable_cert_log"`
	EnableSearch    bool          `json:"enable_search"`
	EnablePortScan  bool          `json:"enable_port_scan"`
	EnableWebCrawl  bool          `json:"enable_web_crawl"`
	EnableTechStack bool          `json:"enable_tech_stack"`
	MaxWorkers      int           `json:"max_workers"`
	RateLimit       int           `json:"rate_limit"`
	UserAgent       string        `json:"user_agent"`
	Recursive       bool          `json:"recursive"`
	HighValueOnly   bool          `json:"high_value_only"`
	ExcludeDomains  []string      `json:"exclude_domains"`
	IncludePatterns []string      `json:"include_patterns"`
	ExcludePatterns []string      `json:"exclude_patterns"`
}

// DefaultDiscoveryConfig returns default discovery configuration
func DefaultDiscoveryConfig() *DiscoveryConfig {
	// TODO: Add BugBountyConfig() for optimized settings
	// FIXME: These defaults are too slow for bug bounty hunting
	return &DiscoveryConfig{
		MaxDepth:        3,                // TODO: Reduce to 1 for bug bounty
		MaxAssets:       1000,             // TODO: Reduce to 100 for focused testing
		Timeout:         30 * time.Minute, // FIXME: Way too long - max 30 seconds
		EnableDNS:       true,             // TODO: Make optional - low value
		EnableCertLog:   true,             // FIXME: Disable by default - too slow
		EnableSearch:    true,             // FIXME: Disable - not needed for direct targets
		EnablePortScan:  true,             // Keep for finding services
		EnableWebCrawl:  true,             // Keep for finding endpoints
		EnableTechStack: true,             // Keep for targeting vulns
		MaxWorkers:      10,
		RateLimit:       10,
		UserAgent:       "shells-discovery/1.0",
		Recursive:       true,  // FIXME: Disable for bug bounty
		HighValueOnly:   false, // TODO: Enable for bug bounty mode
	}
}

// TODO: Add this function
// BugBountyDiscoveryConfig returns optimized config for bug bounty hunting
// func BugBountyDiscoveryConfig() *DiscoveryConfig {
// 	return &DiscoveryConfig{
// 		MaxDepth:        1,
// 		MaxAssets:       50,
// 		Timeout:         30 * time.Second,
// 		EnableDNS:       false,
// 		EnableCertLog:   false,
// 		EnableSearch:    false,
// 		EnablePortScan:  true,
// 		EnableWebCrawl:  true,
// 		EnableTechStack: true,
// 		MaxWorkers:      20,
// 		RateLimit:       50,
// 		UserAgent:       "Mozilla/5.0",
// 		Recursive:       false,
// 		HighValueOnly:   true,
// 	}
// }

// AssetPriority represents asset priority levels
type AssetPriority int

const (
	PriorityLow      AssetPriority = 1
	PriorityMedium   AssetPriority = 2
	PriorityHigh     AssetPriority = 3
	PriorityCritical AssetPriority = 4
)

// DiscoveryResult represents the result of a discovery operation
type DiscoveryResult struct {
	Assets        []*Asset        `json:"assets"`
	Relationships []*Relationship `json:"relationships"`
	Source        string          `json:"source"`
	Duration      time.Duration   `json:"duration"`
	Errors        []error         `json:"errors,omitempty"`
}

// ScanJob represents a scan job for discovered assets
type ScanJob struct {
	ID          string                 `json:"id"`
	AssetID     string                 `json:"asset_id"`
	ScanType    string                 `json:"scan_type"`
	Status      string                 `json:"status"`
	CreatedAt   time.Time              `json:"created_at"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Results     map[string]interface{} `json:"results,omitempty"`
	Errors      []string               `json:"errors,omitempty"`
}

// HighValueIndicators defines what makes an asset high-value
var HighValueIndicators = map[AssetType][]string{
	AssetTypeLogin: {
		"login", "signin", "auth", "authentication", "sso", "oauth", "saml",
		"admin", "administrator", "panel", "dashboard", "console",
	},
	AssetTypeAdmin: {
		"admin", "administrator", "management", "manager", "control",
		"panel", "dashboard", "console", "backend", "cp",
	},
	AssetTypePayment: {
		"payment", "pay", "checkout", "billing", "invoice", "cart",
		"shop", "store", "ecommerce", "purchase", "order",
	},
	AssetTypeAPI: {
		"api", "rest", "graphql", "endpoint", "service", "webhook",
		"v1", "v2", "v3", "swagger", "openapi",
	},
}

// TechnologyStack represents detected technology stack
type TechnologyStack struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	Category   string   `json:"category"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

// Certificate represents an SSL/TLS certificate
type Certificate struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	SANs       []string  `json:"sans,omitempty"`
	Algorithm  string    `json:"algorithm"`
	KeySize    int       `json:"key_size"`
	Serial     string    `json:"serial"`
	Thumbprint string    `json:"thumbprint"`
}
