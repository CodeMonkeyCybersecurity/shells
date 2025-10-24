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

// Client interfaces are defined in clients.go

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
	// Strip protocol if present (https://example.com → example.com)
	normalizedInput := input
	if strings.HasPrefix(input, "http://") {
		normalizedInput = strings.TrimPrefix(input, "http://")
	} else if strings.HasPrefix(input, "https://") {
		normalizedInput = strings.TrimPrefix(input, "https://")
	}
	// Strip trailing slash if present
	normalizedInput = strings.TrimSuffix(normalizedInput, "/")
	// Strip path if present (example.com/path → example.com)
	if idx := strings.Index(normalizedInput, "/"); idx != -1 {
		normalizedInput = normalizedInput[:idx]
	}

	// Try to determine what the string is
	if strings.Contains(normalizedInput, "@") {
		// Email
		parts := strings.Split(normalizedInput, "@")
		if len(parts) == 2 {
			return oc.correlateFromDomain(ctx, parts[1], org)
		}
	} else if net.ParseIP(normalizedInput) != nil {
		// IP address
		return oc.correlateFromIP(ctx, normalizedInput, org)
	} else if strings.Contains(normalizedInput, ".") {
		// Likely a domain
		return oc.correlateFromDomain(ctx, normalizedInput, org)
	} else {
		// Assume company name
		org.Name = normalizedInput
		oc.correlateCompanyName(ctx, normalizedInput, org)
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

	// TASK 16: Add progress indicator for WHOIS lookup
	if oc.config.EnableWhois && oc.whoisClient != nil {
		oc.logger.Infow("[1/3] Querying WHOIS for organization info...",
			"domain", domain,
			"component", "org_footprinting",
		)
		if whois, err := oc.whoisClient.Lookup(context.Background(), domain); err == nil && whois != nil {
			if whois.Organization != "" && org.Name == "" {
				org.Name = whois.Organization
				oc.logger.Infow("✓ Found organization from WHOIS",
					"organization", whois.Organization,
					"domain", domain,
				)
			}
			if whois.RegistrantEmail != "" {
				org.Metadata["registrant_email"] = whois.RegistrantEmail
			}
		}
	}

	// TASK 16: Add progress indicator for certificate lookup
	if oc.config.EnableCerts && oc.certClient != nil {
		oc.logger.Infow("[2/3] Searching certificate transparency logs...",
			"domain", domain,
			"component", "org_footprinting",
		)
		if certInfos, err := oc.certClient.GetCertificates(context.Background(), domain); err == nil {
			oc.logger.Infow("✓ Found certificates",
				"certificate_count", len(certInfos),
				"domain", domain,
			)
			// Convert CertificateInfo to Certificate
			for _, certInfo := range certInfos {
				cert := Certificate{
					Subject:     certInfo.Subject,
					Issuer:      certInfo.Issuer,
					NotBefore:   certInfo.NotBefore,
					NotAfter:    certInfo.NotAfter,
					SANs:        certInfo.SANs,
					Fingerprint: certInfo.Fingerprint,
				}
				org.Certificates = append(org.Certificates, cert)

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

	// TASK 16: Add progress indicator for ASN lookup
	if oc.config.EnableASN && oc.asnClient != nil {
		oc.logger.Infow("[1/2] Looking up ASN for IP address...",
			"ip", ip,
			"component", "org_footprinting",
		)
		if asnData, err := oc.asnClient.LookupIP(context.Background(), ip); err == nil && asnData != nil {
			if asnData.Organization != "" && org.Name == "" {
				org.Name = asnData.Organization
				oc.logger.Infow("✓ Found organization from ASN",
					"organization", asnData.Organization,
					"asn", fmt.Sprintf("AS%d", asnData.Number),
					"ip", ip,
				)
			}
			org.ASNs = appendUnique(org.ASNs, fmt.Sprintf("AS%d", asnData.Number))
		}
	}

	// TASK 16: Add progress indicator for reverse DNS
	oc.logger.Infow("[2/2] Performing reverse DNS lookup...",
		"ip", ip,
		"component", "org_footprinting",
	)
	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		oc.logger.Infow("✓ Found domains from reverse DNS",
			"domain_count", len(names),
			"ip", ip,
		)
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

	// TASK 16: Add progress indicator for company footprinting
	oc.logger.Infow(" Searching for company information...",
		"company", company,
		"component", "org_footprinting",
	)

	// Search for trademarks
	if oc.config.EnableTrademark && oc.trademarkClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			oc.logger.Infow("[1/3] Searching trademark databases...",
				"company", company,
				"component", "org_footprinting",
			)
			if trademarkData, err := oc.trademarkClient.Search(context.Background(), company); err == nil && trademarkData != nil {
				for _, mark := range trademarkData.Trademarks {
					org.Metadata[fmt.Sprintf("trademark_%s", mark.Number)] = mark
				}
			}
		}()
	}

	// Search LinkedIn
	if oc.config.EnableLinkedIn && oc.linkedinClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// TASK 16: Add progress indicator for LinkedIn search
			oc.logger.Infow("[2/3] Searching LinkedIn for company and employees...",
				"company", company,
				"component", "org_footprinting",
			)

			// Get company info
			if linkedinData, err := oc.linkedinClient.SearchCompany(context.Background(), company); err == nil && linkedinData != nil {
				org.Metadata["linkedin_info"] = linkedinData
				org.Metadata["linkedin_employee_count"] = linkedinData.EmployeeCount
			}

			// Search employees - need a domain for this
			// Try to get a domain from existing data
			domain := ""
			if len(org.Domains) > 0 {
				domain = org.Domains[0]
			}

			if domain != "" {
				if employees, err := oc.linkedinClient.SearchEmployees(context.Background(), company, domain); err == nil {
					// Convert EmployeeInfo to Employee
					for _, empInfo := range employees {
						emp := Employee{
							Email: empInfo.Email,
							Name:  empInfo.Name,
							Title: empInfo.Title,
						}
						org.Employees = append(org.Employees, emp)
					}

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
			}
		}()
	}

	// Search GitHub
	if oc.config.EnableGitHub && oc.githubClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if githubData, err := oc.githubClient.SearchOrganization(context.Background(), company); err == nil && githubData != nil {
				if githubData.OrganizationName != "" {
					org.GitHubOrgs = append(org.GitHubOrgs, githubData.OrganizationName)
				}

				// Add domains found in GitHub
				for _, domain := range githubData.Domains {
					org.Domains = appendUnique(org.Domains, domain)
				}

				// Store metadata
				org.Metadata["github_repo_count"] = githubData.RepositoryCount
				org.Metadata["github_technologies"] = githubData.Technologies
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
		// Parse ASN number
		asnNum := 0
		if strings.HasPrefix(asn, "AS") {
			fmt.Sscanf(asn[2:], "%d", &asnNum)
		} else {
			fmt.Sscanf(asn, "%d", &asnNum)
		}

		if asnNum > 0 {
			if info, err := oc.asnClient.GetASNDetails(context.Background(), asnNum); err == nil && info != nil {
				if info.Organization != "" && org.Name == "" {
					org.Name = info.Organization
				}
				org.IPRanges = append(org.IPRanges, info.IPRanges...)
			}
		}
	}
}

// correlateCertificate correlates from a certificate
func (oc *OrganizationCorrelator) correlateCertificate(ctx context.Context, fingerprint string, org *Organization) {
	org.Sources = appendUnique(org.Sources, "certificate")

	// TODO: Certificate by fingerprint lookup not available in current interface
	// Would need to implement this method in CertificateClient or find certificates
	// through domain lookups
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

		// TODO: ASN search by organization not available in current interface
		// Would need to implement this method in ASNClient
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
