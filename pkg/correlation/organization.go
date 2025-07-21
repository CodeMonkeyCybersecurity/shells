// pkg/correlation/organization.go
package correlation

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// Organization represents a correlated organization with all its assets
type Organization struct {
	Name          string                 `json:"name"`
	Aliases       []string               `json:"aliases"`
	Domains       []string               `json:"domains"`
	IPRanges      []string               `json:"ip_ranges"`
	ASNs          []string               `json:"asns"`
	Certificates  []Certificate          `json:"certificates"`
	Employees     []Employee             `json:"employees"`
	Technologies  []Technology           `json:"technologies"`
	Subsidiaries  []string               `json:"subsidiaries"`
	GitHubOrgs    []string               `json:"github_orgs"`
	CloudAccounts []CloudAccount         `json:"cloud_accounts"`
	Metadata      map[string]interface{} `json:"metadata"`
	Confidence    float64                `json:"confidence"`
	Sources       []string               `json:"sources"`
	LastUpdated   time.Time              `json:"last_updated"`
}

// Certificate represents SSL certificate information
type Certificate struct {
	Fingerprint string    `json:"fingerprint"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	SANs        []string  `json:"sans"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	IsWildcard  bool      `json:"is_wildcard"`
}

// Employee represents an employee of the organization
type Employee struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Title    string `json:"title"`
	LinkedIn string `json:"linkedin"`
	GitHub   string `json:"github"`
}

// Technology represents a technology used by the organization
type Technology struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Category   string   `json:"category"`
	Domains    []string `json:"domains"`
	Confidence float64  `json:"confidence"`
}

// CloudAccount represents a cloud provider account
type CloudAccount struct {
	Provider  string   `json:"provider"`
	AccountID string   `json:"account_id"`
	Regions   []string `json:"regions"`
	Services  []string `json:"services"`
}

// OrganizationCorrelator correlates various data sources to build organization profiles
type OrganizationCorrelator struct {
	whoisClient     WhoisClient
	certClient      CertificateClient
	asnClient       ASNClient
	trademarkClient TrademarkClient
	linkedinClient  LinkedInClient
	githubClient    GitHubClient
	cloudClient     CloudClient
	logger          *logger.Logger
	cache           sync.Map
	config          CorrelatorConfig
}

// CorrelatorConfig contains configuration for the correlator
type CorrelatorConfig struct {
	EnableWhois     bool
	EnableCerts     bool
	EnableASN       bool
	EnableTrademark bool
	EnableLinkedIn  bool
	EnableGitHub    bool
	EnableCloud     bool
	CacheTTL        time.Duration
	MaxWorkers      int
}

// Client interfaces
type WhoisClient interface {
	LookupDomain(domain string) (*WhoisInfo, error)
	LookupIP(ip string) (*WhoisInfo, error)
}

type CertificateClient interface {
	GetCertificates(domain string) ([]Certificate, error)
	GetCertificateByFingerprint(fingerprint string) (*Certificate, error)
}

type ASNClient interface {
	LookupASN(asn string) (*ASNInfo, error)
	GetASNsByOrg(org string) ([]string, error)
	LookupIP(ip string) (*ASNInfo, error)
}

type TrademarkClient interface {
	SearchTrademarks(company string) ([]TrademarkInfo, error)
}

type LinkedInClient interface {
	SearchEmployees(company string) ([]Employee, error)
	GetCompanyInfo(company string) (*LinkedInCompany, error)
}

type GitHubClient interface {
	SearchOrganizations(company string) ([]string, error)
	GetOrgDetails(org string) (*GitHubOrg, error)
}

type CloudClient interface {
	FindAWSAccounts(org string) ([]CloudAccount, error)
	FindGCPProjects(org string) ([]CloudAccount, error)
	FindAzureSubscriptions(org string) ([]CloudAccount, error)
}

// Data structures for client responses
type WhoisInfo struct {
	Registrant   string
	Organization string
	Email        string
	CreatedDate  time.Time
	UpdatedDate  time.Time
	ExpiryDate   time.Time
}

type ASNInfo struct {
	ASN          string
	Organization string
	Country      string
	IPRanges     []string
}

type TrademarkInfo struct {
	Name         string
	Owner        string
	Registration string
	FilingDate   time.Time
}

type LinkedInCompany struct {
	Name         string
	Industry     string
	Size         string
	Headquarters string
	Website      string
}

type GitHubOrg struct {
	Name         string
	DisplayName  string
	Email        string
	Blog         string
	Location     string
	Repositories int
}

// NewOrganizationCorrelator creates a new organization correlator
func NewOrganizationCorrelator(correlatorConfig CorrelatorConfig, log *logger.Logger) *OrganizationCorrelator {
	if log == nil {
		// Create a no-op logger if none provided
		cfg := config.LoggerConfig{Level: "error", Format: "json"}
		log, _ = logger.New(cfg)
	}

	return &OrganizationCorrelator{
		config: correlatorConfig,
		logger: log.WithComponent("org-correlator"),
	}
}

// SetClients sets the various clients (for dependency injection)
func (oc *OrganizationCorrelator) SetClients(
	whois WhoisClient,
	cert CertificateClient,
	asn ASNClient,
	trademark TrademarkClient,
	linkedin LinkedInClient,
	github GitHubClient,
	cloud CloudClient,
) {
	oc.whoisClient = whois
	oc.certClient = cert
	oc.asnClient = asn
	oc.trademarkClient = trademark
	oc.linkedinClient = linkedin
	oc.githubClient = github
	oc.cloudClient = cloud
}

// FindOrganizationAssets correlates data from seed information
func (oc *OrganizationCorrelator) FindOrganizationAssets(ctx context.Context, seedData interface{}) (*Organization, error) {
	org := &Organization{
		Domains:       []string{},
		IPRanges:      []string{},
		ASNs:          []string{},
		Certificates:  []Certificate{},
		Employees:     []Employee{},
		Technologies:  []Technology{},
		Subsidiaries:  []string{},
		GitHubOrgs:    []string{},
		CloudAccounts: []CloudAccount{},
		Metadata:      make(map[string]interface{}),
		Sources:       []string{},
		LastUpdated:   time.Now(),
	}

	// Determine seed type and start correlation
	switch seed := seedData.(type) {
	case *types.DiscoveryTarget:
		return oc.correlateFromDiscoveryTarget(ctx, seed, org)
	case string:
		return oc.correlateFromString(ctx, seed, org)
	default:
		return nil, fmt.Errorf("unsupported seed data type: %T", seedData)
	}
}

// correlateFromDiscoveryTarget correlates from a discovery target
func (oc *OrganizationCorrelator) correlateFromDiscoveryTarget(ctx context.Context, target *types.DiscoveryTarget, org *Organization) (*Organization, error) {
	var wg sync.WaitGroup
	errChan := make(chan error, 10)

	// Set organization name
	if target.CompanyName != "" {
		org.Name = target.CompanyName
	}

	// Correlate based on target type
	switch target.Type {
	case "email":
		if domain, ok := target.Metadata["domain"].(string); ok {
			wg.Add(1)
			go func() {
				defer wg.Done()
				oc.correlateDomain(ctx, domain, org)
			}()
		}

	case "domain", "url":
		wg.Add(1)
		go func() {
			defer wg.Done()
			oc.correlateDomain(ctx, target.PrimaryDomain, org)
		}()

	case "ip":
		wg.Add(1)
		go func() {
			defer wg.Done()
			oc.correlateIP(ctx, target.PrimaryIP, org)
		}()

	case "company_name":
		// Correlate from company name
		wg.Add(1)
		go func() {
			defer wg.Done()
			oc.correlateCompanyName(ctx, target.CompanyName, org)
		}()

	case "asn":
		wg.Add(1)
		go func() {
			defer wg.Done()
			oc.correlateASN(ctx, target.ASN, org)
		}()

	case "cert_hash":
		wg.Add(1)
		go func() {
			defer wg.Done()
			oc.correlateCertificate(ctx, target.Identifier, org)
		}()
	}

	// Wait for initial correlation
	wg.Wait()
	close(errChan)

	// Second pass: correlate from discovered assets
	oc.secondPassCorrelation(ctx, org)

	// Calculate confidence score
	org.Confidence = oc.calculateConfidence(org)

	return org, nil
}

// correlateFromString correlates from a simple string
func (oc *OrganizationCorrelator) correlateFromString(ctx context.Context, input string, org *Organization) (*Organization, error) {
	// Try to determine what the string is
	if strings.Contains(input, "@") {
		// Email
		parts := strings.Split(input, "@")
		if len(parts) == 2 {
			return oc.correlateFromDomain(ctx, parts[1], org)
		}
	} else if net.ParseIP(input) != nil {
		// IP address
		return oc.correlateFromIP(ctx, input, org)
	} else if strings.Contains(input, ".") {
		// Likely a domain
		return oc.correlateFromDomain(ctx, input, org)
	} else {
		// Assume company name
		org.Name = input
		oc.correlateCompanyName(ctx, input, org)
		oc.secondPassCorrelation(ctx, org)
		org.Confidence = oc.calculateConfidence(org)
		return org, nil
	}

	return org, nil
}

// correlateDomain correlates from a domain
func (oc *OrganizationCorrelator) correlateDomain(ctx context.Context, domain string, org *Organization) {
	org.Domains = appendUnique(org.Domains, domain)
	org.Sources = appendUnique(org.Sources, "domain")

	// WHOIS lookup
	if oc.config.EnableWhois && oc.whoisClient != nil {
		if whois, err := oc.whoisClient.LookupDomain(domain); err == nil && whois != nil {
			if whois.Organization != "" && org.Name == "" {
				org.Name = whois.Organization
			}
			if whois.Email != "" {
				org.Metadata["registrant_email"] = whois.Email
			}
		}
	}

	// Certificate lookup
	if oc.config.EnableCerts && oc.certClient != nil {
		if certs, err := oc.certClient.GetCertificates(domain); err == nil {
			org.Certificates = append(org.Certificates, certs...)

			// Extract organization from certificates
			for _, cert := range certs {
				if orgName := extractOrgFromCert(cert); orgName != "" && org.Name == "" {
					org.Name = orgName
				}

				// Add SANs as potential domains
				for _, san := range cert.SANs {
					if !strings.HasPrefix(san, "*.") {
						org.Domains = appendUnique(org.Domains, san)
					}
				}
			}
		}
	}
}

// correlateIP correlates from an IP address
func (oc *OrganizationCorrelator) correlateIP(ctx context.Context, ip string, org *Organization) {
	org.Sources = appendUnique(org.Sources, "ip")

	// WHOIS lookup
	if oc.config.EnableWhois && oc.whoisClient != nil {
		if whois, err := oc.whoisClient.LookupIP(ip); err == nil && whois != nil {
			if whois.Organization != "" && org.Name == "" {
				org.Name = whois.Organization
			}
		}
	}

	// Reverse DNS
	if names, err := net.LookupAddr(ip); err == nil {
		for _, name := range names {
			name = strings.TrimSuffix(name, ".")
			org.Domains = appendUnique(org.Domains, name)
		}
	}
}

// correlateCompanyName correlates from a company name
func (oc *OrganizationCorrelator) correlateCompanyName(ctx context.Context, company string, org *Organization) {
	org.Sources = appendUnique(org.Sources, "company_name")

	var wg sync.WaitGroup

	// Search for trademarks
	if oc.config.EnableTrademark && oc.trademarkClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if marks, err := oc.trademarkClient.SearchTrademarks(company); err == nil {
				for _, mark := range marks {
					org.Metadata[fmt.Sprintf("trademark_%s", mark.Registration)] = mark
				}
			}
		}()
	}

	// Search LinkedIn
	if oc.config.EnableLinkedIn && oc.linkedinClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Get company info
			if info, err := oc.linkedinClient.GetCompanyInfo(company); err == nil && info != nil {
				if info.Website != "" {
					org.Domains = appendUnique(org.Domains, cleanDomain(info.Website))
				}
				org.Metadata["linkedin_info"] = info
			}

			// Search employees
			if employees, err := oc.linkedinClient.SearchEmployees(company); err == nil {
				org.Employees = append(org.Employees, employees...)

				// Extract email domains
				for _, emp := range employees {
					if emp.Email != "" && strings.Contains(emp.Email, "@") {
						parts := strings.Split(emp.Email, "@")
						if len(parts) == 2 {
							org.Domains = appendUnique(org.Domains, parts[1])
						}
					}
				}
			}
		}()
	}

	// Search GitHub
	if oc.config.EnableGitHub && oc.githubClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if orgs, err := oc.githubClient.SearchOrganizations(company); err == nil {
				org.GitHubOrgs = append(org.GitHubOrgs, orgs...)

				// Get details for each org
				for _, ghOrg := range orgs {
					if details, err := oc.githubClient.GetOrgDetails(ghOrg); err == nil && details != nil {
						if details.Blog != "" {
							org.Domains = appendUnique(org.Domains, cleanDomain(details.Blog))
						}
						if details.Email != "" && strings.Contains(details.Email, "@") {
							parts := strings.Split(details.Email, "@")
							if len(parts) == 2 {
								org.Domains = appendUnique(org.Domains, parts[1])
							}
						}
					}
				}
			}
		}()
	}

	// Search for cloud accounts
	if oc.config.EnableCloud && oc.cloudClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// AWS
			if accounts, err := oc.cloudClient.FindAWSAccounts(company); err == nil {
				org.CloudAccounts = append(org.CloudAccounts, accounts...)
			}

			// GCP
			if accounts, err := oc.cloudClient.FindGCPProjects(company); err == nil {
				org.CloudAccounts = append(org.CloudAccounts, accounts...)
			}

			// Azure
			if accounts, err := oc.cloudClient.FindAzureSubscriptions(company); err == nil {
				org.CloudAccounts = append(org.CloudAccounts, accounts...)
			}
		}()
	}

	wg.Wait()
}

// correlateASN correlates from an ASN
func (oc *OrganizationCorrelator) correlateASN(ctx context.Context, asn string, org *Organization) {
	org.ASNs = appendUnique(org.ASNs, asn)
	org.Sources = appendUnique(org.Sources, "asn")

	if oc.config.EnableASN && oc.asnClient != nil {
		if info, err := oc.asnClient.LookupASN(asn); err == nil && info != nil {
			if info.Organization != "" && org.Name == "" {
				org.Name = info.Organization
			}
			org.IPRanges = append(org.IPRanges, info.IPRanges...)
		}
	}
}

// correlateCertificate correlates from a certificate
func (oc *OrganizationCorrelator) correlateCertificate(ctx context.Context, fingerprint string, org *Organization) {
	org.Sources = appendUnique(org.Sources, "certificate")

	if oc.config.EnableCerts && oc.certClient != nil {
		if cert, err := oc.certClient.GetCertificateByFingerprint(fingerprint); err == nil && cert != nil {
			org.Certificates = append(org.Certificates, *cert)

			// Extract organization
			if orgName := extractOrgFromCert(*cert); orgName != "" && org.Name == "" {
				org.Name = orgName
			}

			// Add SANs as domains
			for _, san := range cert.SANs {
				if !strings.HasPrefix(san, "*.") {
					org.Domains = appendUnique(org.Domains, san)
				}
			}
		}
	}
}

// correlateFromDomain is a helper that creates an org from a domain
func (oc *OrganizationCorrelator) correlateFromDomain(ctx context.Context, domain string, org *Organization) (*Organization, error) {
	oc.correlateDomain(ctx, domain, org)
	oc.secondPassCorrelation(ctx, org)
	org.Confidence = oc.calculateConfidence(org)
	return org, nil
}

// correlateFromIP is a helper that creates an org from an IP
func (oc *OrganizationCorrelator) correlateFromIP(ctx context.Context, ip string, org *Organization) (*Organization, error) {
	oc.correlateIP(ctx, ip, org)
	oc.secondPassCorrelation(ctx, org)
	org.Confidence = oc.calculateConfidence(org)
	return org, nil
}

// secondPassCorrelation performs additional correlation based on discovered data
func (oc *OrganizationCorrelator) secondPassCorrelation(ctx context.Context, org *Organization) {
	// If we found an organization name, search for more assets
	if org.Name != "" {
		oc.correlateCompanyName(ctx, org.Name, org)

		// Search for ASNs by organization
		if oc.config.EnableASN && oc.asnClient != nil {
			if asns, err := oc.asnClient.GetASNsByOrg(org.Name); err == nil {
				for _, asn := range asns {
					oc.correlateASN(ctx, asn, org)
				}
			}
		}
	}

	// Correlate from discovered domains
	discoveredDomains := make([]string, len(org.Domains))
	copy(discoveredDomains, org.Domains)

	for _, domain := range discoveredDomains {
		oc.correlateDomain(ctx, domain, org)
	}
}

// calculateConfidence calculates the confidence score for the organization correlation
func (oc *OrganizationCorrelator) calculateConfidence(org *Organization) float64 {
	score := 0.0
	factors := 0

	// Name found
	if org.Name != "" {
		score += 0.2
		factors++
	}

	// Multiple domains
	if len(org.Domains) > 1 {
		score += 0.15
		factors++
	}

	// Has certificates
	if len(org.Certificates) > 0 {
		score += 0.15
		factors++
	}

	// Has employees
	if len(org.Employees) > 0 {
		score += 0.1
		factors++
	}

	// Has ASNs
	if len(org.ASNs) > 0 {
		score += 0.1
		factors++
	}

	// Has cloud accounts
	if len(org.CloudAccounts) > 0 {
		score += 0.1
		factors++
	}

	// Has GitHub orgs
	if len(org.GitHubOrgs) > 0 {
		score += 0.1
		factors++
	}

	// Multiple sources
	if len(org.Sources) > 2 {
		score += 0.1
		factors++
	}

	if factors == 0 {
		return 0.0
	}

	return score
}

// Helper functions

func appendUnique(slice []string, item string) []string {
	for _, existing := range slice {
		if existing == item {
			return slice
		}
	}
	return append(slice, item)
}

func extractOrgFromCert(cert Certificate) string {
	// Extract O= from subject
	re := regexp.MustCompile(`O=([^,]+)`)
	matches := re.FindStringSubmatch(cert.Subject)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func cleanDomain(url string) string {
	// Remove protocol
	domain := strings.TrimPrefix(url, "https://")
	domain = strings.TrimPrefix(domain, "http://")

	// Remove path
	if idx := strings.Index(domain, "/"); idx > 0 {
		domain = domain[:idx]
	}

	// Remove port
	if idx := strings.Index(domain, ":"); idx > 0 {
		domain = domain[:idx]
	}

	return strings.ToLower(domain)
}
