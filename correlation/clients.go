// correlation/clients.go
package correlation

import (
	"context"
	"time"
	
	pkgcorrelation "github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
)

// WhoisClient interface for WHOIS lookups
type WhoisClient interface {
	Lookup(ctx context.Context, domain string) (*WhoisData, error)
}

// WhoisData represents WHOIS information
type WhoisData struct {
	Domain          string
	Organization    string
	RegistrantName  string
	RegistrantEmail string
	NameServers     []string
	CreatedDate     time.Time
	UpdatedDate     time.Time
	ExpiryDate      time.Time
}

// CertificateClient interface for certificate lookups
type CertificateClient interface {
	GetCertificates(ctx context.Context, domain string) ([]pkgcorrelation.CertificateInfo, error)
	SearchByOrganization(ctx context.Context, org string) ([]pkgcorrelation.CertificateInfo, error)
}

// ASNClient interface for ASN lookups
type ASNClient interface {
	LookupIP(ctx context.Context, ip string) (*ASNData, error)
	LookupDomain(ctx context.Context, domain string) (*ASNData, error)
	GetASNDetails(ctx context.Context, asn int) (*ASNData, error)
}

// ASNData represents ASN information
type ASNData struct {
	Number       int
	Organization string
	Description  string
	IPRanges     []string
	Country      string
}

// TrademarkClient interface for trademark searches
type TrademarkClient interface {
	Search(ctx context.Context, query string) (*TrademarkData, error)
}

// TrademarkData represents trademark information
type TrademarkData struct {
	Trademarks []Trademark
}

type Trademark struct {
	Name         string
	Owner        string
	OwnerAddress string
	Number       string
	Status       string
	FilingDate   time.Time
}

// LinkedInClient interface for LinkedIn searches
type LinkedInClient interface {
	SearchCompany(ctx context.Context, name string) (*LinkedInData, error)
	SearchEmployees(ctx context.Context, company, domain string) ([]pkgcorrelation.EmployeeInfo, error)
}

// LinkedInData represents LinkedIn company information
type LinkedInData struct {
	CompanyName   string
	CompanyURL    string
	Industry      string
	EmployeeCount int
	Employees     []LinkedInEmployee
	Technologies  []string
}

type LinkedInEmployee struct {
	Name       string
	Email      string
	Title      string
	Department string
	ProfileURL string
}

// GitHubClient interface for GitHub searches
type GitHubClient interface {
	SearchOrganization(ctx context.Context, name string) (*GitHubData, error)
	GetOrganizationMembers(ctx context.Context, org string) ([]GitHubMember, error)
}

// GitHubData represents GitHub organization information
type GitHubData struct {
	OrganizationName string
	OrganizationURL  string
	RepositoryCount  int
	Members          []GitHubMember
	Technologies     []string
	Domains          []string // Found in CNAME files, etc.
}

type GitHubMember struct {
	Username string
	Name     string
	Email    string
}

// CloudAssetClient interface for cloud asset discovery
type CloudAssetClient interface {
	DiscoverAWS(ctx context.Context, profile *pkgcorrelation.OrganizationProfile) ([]string, error)
	DiscoverAzure(ctx context.Context, profile *pkgcorrelation.OrganizationProfile) ([]string, error)
	DiscoverGCP(ctx context.Context, profile *pkgcorrelation.OrganizationProfile) ([]string, error)
}