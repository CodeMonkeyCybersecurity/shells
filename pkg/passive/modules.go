// pkg/passive/modules.go
package passive

import (
	"context"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// PassiveModules contains all passive scanning modules
type PassiveModules struct {
	Certificate CertificateModule
	Archive     ArchiveModule
	CloudFlare  CloudFlareModule
	EmailSec    EmailSecurityModule
	CodeRepo    CodeRepositoryModule
}

// CertificateModule interface for certificate intelligence
type CertificateModule interface {
	DiscoverAllCertificates(ctx context.Context, domain string) ([]CertificateRecord, error)
	IdentifyNamingPatterns(certs []Certificate) []Pattern
}

// ArchiveModule interface for archive intelligence
type ArchiveModule interface {
	ExtractIntelligence(target string) (*ArchiveFindings, error)
}

// CloudFlareModule interface for CloudFlare bypass
type CloudFlareModule interface {
	DetectCloudFlare(domain string) (bool, error)
	FindOriginIP(domain string) ([]OriginCandidate, error)
}

// EmailSecurityModule interface for email security analysis
type EmailSecurityModule interface {
	AnalyzeDomain(ctx context.Context, domain string) (*EmailFindings, error)
}

// CodeRepositoryModule interface for code repository scanning
type CodeRepositoryModule interface {
	SearchAllPlatforms(ctx context.Context, target string) ([]CodeResult, error)
}

// PassiveIntel represents aggregated passive intelligence
type PassiveIntel struct {
	Target                string
	Timestamp             time.Time
	CloudFlareOrigins     []OriginCandidate
	ArchivedEndpoints     []ArchivedEndpoint
	CertificateSubdomains []string
	TechStack             map[string]TechInfo
	SecurityTimeline      []SecurityEvent
	DiscoveredSecrets     []Secret
	NamingPatterns        []Pattern
}

// TechStackChange represents a technology change over time
type TechStackChange struct {
	OldTech   string
	NewTech   string
	Timestamp time.Time
}

// EmailFindings from email security analysis
type EmailFindings struct {
	Issues []EmailIssue
}

// EmailIssue represents an email security issue
type EmailIssue struct {
	Type        string
	Severity    types.Severity
	Description string
	Evidence    []string
}

// CodeResult from code repository search
type CodeResult struct {
	Platform    string
	Type        string
	URL         string
	SecretType  string
	SecretValue string
	Severity    types.Severity
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	Type        string
	Description string
	Timestamp   time.Time
	Severity    string
	Source      string
	Evidence    []string
}

// TechInfo represents technology information
type TechInfo struct {
	Name     string
	Version  string
	LastSeen time.Time
}

// OriginCandidate represents a potential origin IP
type OriginCandidate struct {
	IP         string
	Domain     string
	Method     string
	Evidence   []string
	Confidence float64
	Validated  bool
}

// Source constants
const (
	SourceWebArchive  = "web_archive"
	SourceDNS         = "dns"
	SourceCertificate = "certificate"
	SourceCodeRepo    = "code_repository"
)
