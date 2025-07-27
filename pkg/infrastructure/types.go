package infrastructure

import (
	"net"
	"time"
)

// InfrastructureReport represents the complete infrastructure analysis
type InfrastructureReport struct {
	Target        string                `json:"target"`
	Assets        []InfrastructureAsset `json:"assets"`
	Organizations []OrganizationInfo    `json:"organizations"`
	Relationships []AssetRelationship   `json:"relationships"`
	SupplyChain   *SupplyChainInfo      `json:"supply_chain,omitempty"`
	ThreatIntel   *ThreatIntelligence   `json:"threat_intel,omitempty"`
	Statistics    InfrastructureStats   `json:"statistics"`
	DiscoveryTime time.Duration         `json:"discovery_time"`
	DiscoveredAt  time.Time             `json:"discovered_at"`
}

// InfrastructureAsset represents a discovered infrastructure component
type InfrastructureAsset struct {
	ID           string                 `json:"id"`
	Type         AssetType              `json:"type"`
	Value        string                 `json:"value"`
	Source       string                 `json:"source"`
	Confidence   float64                `json:"confidence"`
	Priority     int                    `json:"priority"`
	Tags         []string               `json:"tags"`
	Technologies []Technology           `json:"technologies"`
	Metadata     map[string]interface{} `json:"metadata"`
	CloudInfo    *CloudInfo             `json:"cloud_info,omitempty"`
	CDNInfo      *CDNInfo               `json:"cdn_info,omitempty"`
	SSLInfo      *SSLInfo               `json:"ssl_info,omitempty"`
	NetworkInfo  *NetworkInfo           `json:"network_info,omitempty"`
	Location     *GeographicLocation    `json:"location,omitempty"`
	DiscoveredAt time.Time              `json:"discovered_at"`
}

// AssetType represents different types of infrastructure assets
type AssetType string

const (
	AssetTypeDomain       AssetType = "domain"
	AssetTypeSubdomain    AssetType = "subdomain"
	AssetTypeIP           AssetType = "ip"
	AssetTypeURL          AssetType = "url"
	AssetTypeCloudStorage AssetType = "cloud_storage"
	AssetTypeCloudCompute AssetType = "cloud_compute"
	AssetTypeCloudAPI     AssetType = "cloud_api"
	AssetTypeCDN          AssetType = "cdn"
	AssetTypeDatabase     AssetType = "database"
	AssetTypeEmail        AssetType = "email"
	AssetTypeAPI          AssetType = "api"
	AssetTypeRepository   AssetType = "repository"
	AssetTypeCertificate  AssetType = "certificate"
	AssetTypePort         AssetType = "port"
	AssetTypeService      AssetType = "service"
)

// OrganizationInfo represents information about related organizations
type OrganizationInfo struct {
	Name           string            `json:"name"`
	Domain         string            `json:"domain"`
	ASN            int               `json:"asn"`
	IPRanges       []string          `json:"ip_ranges"`
	Subsidiaries   []string          `json:"subsidiaries"`
	RelatedDomains []string          `json:"related_domains"`
	Confidence     float64           `json:"confidence"`
	Source         string            `json:"source"`
	Metadata       map[string]string `json:"metadata"`
}

// AssetRelationship represents relationships between assets
type AssetRelationship struct {
	SourceAssetID string            `json:"source_asset_id"`
	TargetAssetID string            `json:"target_asset_id"`
	RelationType  RelationType      `json:"relation_type"`
	Confidence    float64           `json:"confidence"`
	Evidence      []string          `json:"evidence"`
	Metadata      map[string]string `json:"metadata"`
}

// RelationType represents different types of asset relationships
type RelationType string

const (
	RelationTypeHostedOn     RelationType = "hosted_on"
	RelationTypePointsTo     RelationType = "points_to"
	RelationTypeSameASN      RelationType = "same_asn"
	RelationTypeSharedSSL    RelationType = "shared_ssl"
	RelationTypeSameNetwork  RelationType = "same_network"
	RelationTypeCDNOrigin    RelationType = "cdn_origin"
	RelationTypeLoadBalancer RelationType = "load_balancer"
	RelationTypeRedirectsTo  RelationType = "redirects_to"
	RelationTypeSameTech     RelationType = "same_technology"
	RelationTypeAPIEndpoint  RelationType = "api_endpoint"
)

// Technology represents detected technologies
type Technology struct {
	Name       string            `json:"name"`
	Version    string            `json:"version,omitempty"`
	Category   string            `json:"category"`
	Confidence float64           `json:"confidence"`
	Source     string            `json:"source"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// CloudInfo represents cloud-specific information
type CloudInfo struct {
	Provider     CloudProvider     `json:"provider"`
	Service      string            `json:"service"`
	Region       string            `json:"region,omitempty"`
	Account      string            `json:"account,omitempty"`
	ResourceID   string            `json:"resource_id,omitempty"`
	PublicAccess bool              `json:"public_access"`
	Permissions  []CloudPermission `json:"permissions,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// CloudProvider represents different cloud providers
type CloudProvider string

const (
	CloudProviderAWS          CloudProvider = "aws"
	CloudProviderAzure        CloudProvider = "azure"
	CloudProviderGCP          CloudProvider = "gcp"
	CloudProviderCloudflare   CloudProvider = "cloudflare"
	CloudProviderDigitalOcean CloudProvider = "digitalocean"
	CloudProviderUnknown      CloudProvider = "unknown"
)

// CloudPermission represents cloud resource permissions
type CloudPermission struct {
	Principal  string   `json:"principal"`
	Actions    []string `json:"actions"`
	Resources  []string `json:"resources"`
	Effect     string   `json:"effect"`
	Conditions []string `json:"conditions,omitempty"`
}

// CDNInfo represents CDN-specific information
type CDNInfo struct {
	Provider     string   `json:"provider"`
	OriginServer string   `json:"origin_server,omitempty"`
	EdgeServers  []string `json:"edge_servers,omitempty"`
	CacheStatus  string   `json:"cache_status,omitempty"`
	Headers      []string `json:"headers,omitempty"`
	Bypassable   bool     `json:"bypassable"`
}

// SSLInfo represents SSL/TLS certificate information
type SSLInfo struct {
	Subject         string       `json:"subject"`
	Issuer          string       `json:"issuer"`
	SerialNumber    string       `json:"serial_number"`
	NotBefore       time.Time    `json:"not_before"`
	NotAfter        time.Time    `json:"not_after"`
	SANs            []string     `json:"sans"`
	Fingerprint     string       `json:"fingerprint"`
	Algorithm       string       `json:"algorithm"`
	KeySize         int          `json:"key_size"`
	Vulnerabilities []string     `json:"vulnerabilities,omitempty"`
	TrustChain      []string     `json:"trust_chain,omitempty"`
	CTLogs          []CTLogEntry `json:"ct_logs,omitempty"`
	Expired         bool         `json:"expired"`
	SelfSigned      bool         `json:"self_signed"`
	Wildcard        bool         `json:"wildcard"`
}

// CTLogEntry represents Certificate Transparency log entry
type CTLogEntry struct {
	LogID       string    `json:"log_id"`
	Index       int64     `json:"index"`
	Timestamp   time.Time `json:"timestamp"`
	EntryType   string    `json:"entry_type"`
	LeafCert    string    `json:"leaf_cert,omitempty"`
	PrecertHash string    `json:"precert_hash,omitempty"`
}

// NetworkInfo represents network-level information
type NetworkInfo struct {
	ASN          int           `json:"asn"`
	ASNName      string        `json:"asn_name"`
	IPRange      string        `json:"ip_range"`
	BGPPeers     []BGPPeer     `json:"bgp_peers,omitempty"`
	Geolocation  *Geolocation  `json:"geolocation,omitempty"`
	ISP          string        `json:"isp,omitempty"`
	Organization string        `json:"organization,omitempty"`
	OpenPorts    []PortInfo    `json:"open_ports,omitempty"`
	Services     []ServiceInfo `json:"services,omitempty"`
}

// BGPPeer represents BGP peering information
type BGPPeer struct {
	ASN      int    `json:"asn"`
	Name     string `json:"name"`
	PeerType string `json:"peer_type"`
	Country  string `json:"country,omitempty"`
	IPv4     bool   `json:"ipv4"`
	IPv6     bool   `json:"ipv6"`
}

// Geolocation represents geographic location data
type Geolocation struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
}

// GeographicLocation represents precise geographic location
type GeographicLocation struct {
	Latitude   float64 `json:"latitude"`
	Longitude  float64 `json:"longitude"`
	Country    string  `json:"country"`
	Region     string  `json:"region"`
	City       string  `json:"city"`
	PostalCode string  `json:"postal_code,omitempty"`
	Provider   string  `json:"provider"`
	Accuracy   int     `json:"accuracy"`
}

// PortInfo represents open port information
type PortInfo struct {
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	State    string   `json:"state"`
	Service  string   `json:"service,omitempty"`
	Version  string   `json:"version,omitempty"`
	Banner   string   `json:"banner,omitempty"`
	SSL      bool     `json:"ssl"`
	Headers  []string `json:"headers,omitempty"`
}

// ServiceInfo represents service-level information
type ServiceInfo struct {
	Name        string            `json:"name"`
	Version     string            `json:"version,omitempty"`
	Port        int               `json:"port"`
	Protocol    string            `json:"protocol"`
	State       string            `json:"state"`
	Product     string            `json:"product,omitempty"`
	ExtraInfo   string            `json:"extra_info,omitempty"`
	Confidence  int               `json:"confidence"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// SupplyChainInfo represents supply chain analysis
type SupplyChainInfo struct {
	JavaScript    []JSLibrary        `json:"javascript"`
	APIs          []ThirdPartyAPI    `json:"apis"`
	CDNs          []CDNService       `json:"cdns"`
	Analytics     []AnalyticsService `json:"analytics"`
	CloudServices []CloudService     `json:"cloud_services"`
	Dependencies  []Dependency       `json:"dependencies"`
	Risks         []SupplyChainRisk  `json:"risks"`
}

// JSLibrary represents JavaScript library information
type JSLibrary struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Source          string   `json:"source"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	License         string   `json:"license,omitempty"`
	Outdated        bool     `json:"outdated"`
}

// ThirdPartyAPI represents third-party API usage
type ThirdPartyAPI struct {
	Provider     string   `json:"provider"`
	Service      string   `json:"service"`
	Endpoints    []string `json:"endpoints"`
	APIKeys      []string `json:"api_keys,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
	DataSharing  bool     `json:"data_sharing"`
	SecurityRisk string   `json:"security_risk"`
}

// CDNService represents CDN service information
type CDNService struct {
	Provider string   `json:"provider"`
	Domains  []string `json:"domains"`
	Features []string `json:"features"`
	Config   string   `json:"config,omitempty"`
}

// AnalyticsService represents analytics service information
type AnalyticsService struct {
	Provider   string   `json:"provider"`
	TrackingID string   `json:"tracking_id,omitempty"`
	DataTypes  []string `json:"data_types"`
	Privacy    string   `json:"privacy_level"`
}

// CloudService represents cloud service dependencies
type CloudService struct {
	Provider string   `json:"provider"`
	Services []string `json:"services"`
	Regions  []string `json:"regions"`
	Public   bool     `json:"public_exposure"`
}

// Dependency represents software dependencies
type Dependency struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Type    string   `json:"type"`
	CVEs    []string `json:"cves,omitempty"`
	License string   `json:"license"`
	Direct  bool     `json:"direct"`
}

// SupplyChainRisk represents supply chain risks
type SupplyChainRisk struct {
	Component   string   `json:"component"`
	RiskType    string   `json:"risk_type"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Mitigation  []string `json:"mitigation,omitempty"`
	CVEs        []string `json:"cves,omitempty"`
}

// ThreatIntelligence represents threat intelligence data
type ThreatIntelligence struct {
	Reputation  ReputationInfo     `json:"reputation"`
	Malware     []MalwareInfo      `json:"malware,omitempty"`
	Blacklists  []BlacklistInfo    `json:"blacklists,omitempty"`
	Incidents   []SecurityIncident `json:"incidents,omitempty"`
	Attribution []Attribution      `json:"attribution,omitempty"`
	IOCs        []IOC              `json:"iocs,omitempty"`
	LastUpdated time.Time          `json:"last_updated"`
}

// ReputationInfo represents reputation scoring
type ReputationInfo struct {
	Score      float64           `json:"score"` // 0-100, higher is better
	Category   string            `json:"category"`
	Sources    []string          `json:"sources"`
	LastSeen   time.Time         `json:"last_seen"`
	Confidence float64           `json:"confidence"`
	Details    map[string]string `json:"details,omitempty"`
}

// MalwareInfo represents malware intelligence
type MalwareInfo struct {
	Family      string    `json:"family"`
	Hash        string    `json:"hash"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Source      string    `json:"source"`
	Confidence  float64   `json:"confidence"`
	Description string    `json:"description,omitempty"`
}

// BlacklistInfo represents blacklist information
type BlacklistInfo struct {
	Source     string    `json:"source"`
	Reason     string    `json:"reason"`
	Listed     bool      `json:"listed"`
	FirstSeen  time.Time `json:"first_seen,omitempty"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
	Confidence float64   `json:"confidence"`
}

// SecurityIncident represents security incidents
type SecurityIncident struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Date        time.Time `json:"date"`
	Severity    string    `json:"severity"`
	Source      string    `json:"source"`
	Verified    bool      `json:"verified"`
}

// Attribution represents threat attribution
type Attribution struct {
	Actor      string   `json:"actor"`
	Group      string   `json:"group,omitempty"`
	Country    string   `json:"country,omitempty"`
	Motivation string   `json:"motivation"`
	TTPs       []string `json:"ttps"` // Tactics, Techniques, Procedures
	Confidence float64  `json:"confidence"`
	Source     string   `json:"source"`
}

// IOC represents Indicators of Compromise
type IOC struct {
	Value      string    `json:"value"`
	Type       string    `json:"type"` // IP, domain, hash, etc.
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Confidence float64   `json:"confidence"`
	Source     string    `json:"source"`
	Tags       []string  `json:"tags,omitempty"`
}

// InfrastructureStats represents statistics about the infrastructure
type InfrastructureStats struct {
	TotalAssets      int            `json:"total_assets"`
	AssetsByType     map[string]int `json:"assets_by_type"`
	UniqueIPs        int            `json:"unique_ips"`
	UniqueDomains    int            `json:"unique_domains"`
	CloudAssets      int            `json:"cloud_assets"`
	CDNProtected     int            `json:"cdn_protected"`
	SSLCertificates  int            `json:"ssl_certificates"`
	OpenPorts        int            `json:"open_ports"`
	Technologies     int            `json:"technologies"`
	Organizations    int            `json:"organizations"`
	SupplyChainRisks int            `json:"supply_chain_risks"`
	HighRiskAssets   int            `json:"high_risk_assets"`
	ExposedServices  int            `json:"exposed_services"`
}

// DiscoveryConfig represents configuration for infrastructure discovery
type DiscoveryConfig struct {
	// General settings
	MaxDepth           int           `json:"max_depth"`
	MaxAssets          int           `json:"max_assets"`
	Timeout            time.Duration `json:"timeout"`
	Workers            int           `json:"workers"`
	RateLimitPerSecond int           `json:"rate_limit_per_second"`

	// Discovery modules
	EnableDNSEnumeration      bool `json:"enable_dns_enumeration"`
	EnableSubdomainBrute      bool `json:"enable_subdomain_brute"`
	EnablePortScanning        bool `json:"enable_port_scanning"`
	EnableSSLAnalysis         bool `json:"enable_ssl_analysis"`
	EnableCloudDiscovery      bool `json:"enable_cloud_discovery"`
	EnableCDNDetection        bool `json:"enable_cdn_detection"`
	EnableASNAnalysis         bool `json:"enable_asn_analysis"`
	EnableTechDetection       bool `json:"enable_tech_detection"`
	EnableSupplyChainAnalysis bool `json:"enable_supply_chain_analysis"`
	EnableThreatIntel         bool `json:"enable_threat_intel"`

	// API configurations
	ShodanAPIKey      string `json:"shodan_api_key,omitempty"`
	CensysAPIKey      string `json:"censys_api_key,omitempty"`
	CensysSecret      string `json:"censys_secret,omitempty"`
	VirusTotalAPIKey  string `json:"virustotal_api_key,omitempty"`
	SecurityTrailsKey string `json:"security_trails_key,omitempty"`
	BinaryEdgeKey     string `json:"binary_edge_key,omitempty"`
	PassiveTotalKey   string `json:"passive_total_key,omitempty"`

	// Cloud credentials
	AWSAccessKey   string `json:"aws_access_key,omitempty"`
	AWSSecretKey   string `json:"aws_secret_key,omitempty"`
	AzureClientID  string `json:"azure_client_id,omitempty"`
	AzureSecret    string `json:"azure_secret,omitempty"`
	GCPCredentials string `json:"gcp_credentials,omitempty"`

	// Custom wordlists and patterns
	SubdomainWordlist string   `json:"subdomain_wordlist,omitempty"`
	S3BucketPatterns  []string `json:"s3_bucket_patterns,omitempty"`
	CustomPorts       []int    `json:"custom_ports,omitempty"`
}

// Asset represents a discovered asset for scanning
type Asset struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	Value    string            `json:"value"`
	Source   string            `json:"source"`
	Priority int               `json:"priority"`
	Tags     []string          `json:"tags"`
	Metadata map[string]string `json:"metadata"`
}

// Priority levels for assets
const (
	PriorityLow      = 1
	PriorityMedium   = 2
	PriorityHigh     = 3
	PriorityCritical = 4
)

// Network represents an IP network range
type Network struct {
	CIDR    string     `json:"cidr"`
	Network *net.IPNet `json:"-"`
	ASN     int        `json:"asn"`
	ASNName string     `json:"asn_name"`
	Country string     `json:"country"`
}
