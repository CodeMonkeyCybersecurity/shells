// pkg/correlation/organization_enhanced.go
package correlation

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// OrganizationProfile represents a complete organization profile (enhanced version)
type OrganizationProfile struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	LegalName     string                 `json:"legal_name,omitempty"`
	Aliases       []string               `json:"aliases,omitempty"`
	Domains       []string               `json:"domains"`
	IPRanges      []string               `json:"ip_ranges"`
	ASNumbers     []int                  `json:"as_numbers"`
	Subsidiaries  []string               `json:"subsidiaries"`
	EmailPatterns []string               `json:"email_patterns"`
	Technologies  []string               `json:"technologies"`
	CloudAccounts map[string][]string    `json:"cloud_accounts"` // provider -> account IDs
	Certificates  []CertificateInfo      `json:"certificates"`
	Employees     []EmployeeInfo         `json:"employees"`
	Metadata      map[string]interface{} `json:"metadata"`
	Confidence    float64                `json:"confidence"`
	LastUpdated   time.Time              `json:"last_updated"`
}

// CertificateInfo contains certificate details for correlation
type CertificateInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SANs         []string  `json:"sans"`
	Fingerprint  string    `json:"fingerprint"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Organization string    `json:"organization"`
}

// EmployeeInfo represents employee information for correlation
type EmployeeInfo struct {
	Email          string  `json:"email"`
	Name           string  `json:"name"`
	Title          string  `json:"title"`
	Department     string  `json:"department"`
	LinkedInURL    string  `json:"linkedin_url,omitempty"`
	GitHubUsername string  `json:"github_username,omitempty"`
	Confidence     float64 `json:"confidence"`
}

// Convert from existing Organization to OrganizationProfile
func (o *Organization) ToProfile() *OrganizationProfile {
	profile := &OrganizationProfile{
		ID:            generateOrgID(o.Name),
		Name:          o.Name,
		Aliases:       o.Aliases,
		Domains:       o.Domains,
		IPRanges:      o.IPRanges,
		Subsidiaries:  o.Subsidiaries,
		Metadata:      o.Metadata,
		Confidence:    o.Confidence,
		LastUpdated:   o.LastUpdated,
		CloudAccounts: make(map[string][]string),
		Technologies:  make([]string, 0),
		EmailPatterns: make([]string, 0),
	}

	// Convert ASNs from string to int
	profile.ASNumbers = make([]int, 0, len(o.ASNs))
	for _, asn := range o.ASNs {
		// Parse ASN string to int
		if num := extractASNNumber(asn); num > 0 {
			profile.ASNumbers = append(profile.ASNumbers, num)
		}
	}

	// Convert certificates
	profile.Certificates = make([]CertificateInfo, 0, len(o.Certificates))
	for _, cert := range o.Certificates {
		profile.Certificates = append(profile.Certificates, CertificateInfo{
			Subject:      cert.Subject,
			Issuer:       cert.Issuer,
			SANs:         cert.SANs,
			Fingerprint:  cert.Fingerprint,
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			Organization: extractOrgFromSubject(cert.Subject),
		})
	}

	// Convert employees
	profile.Employees = make([]EmployeeInfo, 0, len(o.Employees))
	for _, emp := range o.Employees {
		profile.Employees = append(profile.Employees, EmployeeInfo{
			Email:          emp.Email,
			Name:           emp.Name,
			Title:          emp.Title,
			LinkedInURL:    emp.LinkedIn,
			GitHubUsername: emp.GitHub,
			Confidence:     0.8,
		})
	}

	// Convert cloud accounts
	for _, ca := range o.CloudAccounts {
		if profile.CloudAccounts[ca.Provider] == nil {
			profile.CloudAccounts[ca.Provider] = make([]string, 0)
		}
		profile.CloudAccounts[ca.Provider] = append(profile.CloudAccounts[ca.Provider], ca.AccountID)
	}

	// Convert technologies
	for _, tech := range o.Technologies {
		profile.Technologies = append(profile.Technologies, tech.Name)
	}

	// Generate email patterns from domains
	for _, domain := range o.Domains {
		profile.EmailPatterns = append(profile.EmailPatterns, fmt.Sprintf("*@%s", domain))
	}

	return profile
}

// Convert from OrganizationProfile to existing Organization
func ProfileToOrganization(profile *OrganizationProfile) *Organization {
	org := &Organization{
		Name:          profile.Name,
		Aliases:       profile.Aliases,
		Domains:       profile.Domains,
		IPRanges:      profile.IPRanges,
		Subsidiaries:  profile.Subsidiaries,
		Metadata:      profile.Metadata,
		Confidence:    profile.Confidence,
		LastUpdated:   profile.LastUpdated,
		CloudAccounts: make([]CloudAccount, 0),
		Technologies:  make([]Technology, 0),
	}

	// Convert ASNs from int to string
	org.ASNs = make([]string, 0, len(profile.ASNumbers))
	for _, num := range profile.ASNumbers {
		org.ASNs = append(org.ASNs, fmt.Sprintf("AS%d", num))
	}

	// Convert certificates
	org.Certificates = make([]Certificate, 0, len(profile.Certificates))
	for _, cert := range profile.Certificates {
		org.Certificates = append(org.Certificates, Certificate{
			Subject:     cert.Subject,
			Issuer:      cert.Issuer,
			SANs:        cert.SANs,
			Fingerprint: cert.Fingerprint,
			NotBefore:   cert.NotBefore,
			NotAfter:    cert.NotAfter,
			IsWildcard:  isWildcardCert(cert.Subject),
		})
	}

	// Convert employees
	org.Employees = make([]Employee, 0, len(profile.Employees))
	for _, emp := range profile.Employees {
		org.Employees = append(org.Employees, Employee{
			Email:    emp.Email,
			Name:     emp.Name,
			Title:    emp.Title,
			LinkedIn: emp.LinkedInURL,
			GitHub:   emp.GitHubUsername,
		})
	}

	// Convert cloud accounts
	for provider, accounts := range profile.CloudAccounts {
		for _, accountID := range accounts {
			org.CloudAccounts = append(org.CloudAccounts, CloudAccount{
				Provider:  provider,
				AccountID: accountID,
			})
		}
	}

	// Convert technologies
	for _, tech := range profile.Technologies {
		org.Technologies = append(org.Technologies, Technology{
			Name:       tech,
			Confidence: 0.7,
		})
	}

	return org
}

// Enhanced methods for OrganizationCorrelator

// DiscoverFromIPRange discovers organization from IP range
func (oc *OrganizationCorrelator) DiscoverFromIPRange(ctx context.Context, ipRange string) (*Organization, error) {
	oc.logger.Infow("Discovering organization from IP range", "ip_range", ipRange)

	// Parse CIDR
	_, ipnet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return nil, fmt.Errorf("invalid IP range: %w", err)
	}

	org := &Organization{
		Name:        fmt.Sprintf("Organization for %s", ipRange),
		IPRanges:    []string{ipRange},
		LastUpdated: time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	// ASN lookup for the range
	if oc.asnClient != nil && oc.config.EnableASN {
		// Get first IP in range for ASN lookup
		firstIP := ipnet.IP.String()
		if asnData, err := oc.asnClient.LookupIP(context.Background(), firstIP); err == nil {
			if asnData.Number > 0 {
				org.ASNs = append(org.ASNs, fmt.Sprintf("AS%d", asnData.Number))
				if asnData.Organization != "" {
					org.Name = asnData.Organization
				}
			}
		}
	}

	// Try reverse DNS for some IPs in the range
	ips, _ := expandIPRange(ipRange)
	for i, ip := range ips {
		if i > 10 { // Limit to first 10 IPs
			break
		}
		if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
			for _, name := range names {
				name = strings.TrimSuffix(name, ".")
				if isDomainValid(name) && !containsString(org.Domains, name) {
					org.Domains = append(org.Domains, name)
				}
			}
		}
	}

	return org, nil
}

// DiscoverFromASN discovers organization from ASN
func (oc *OrganizationCorrelator) DiscoverFromASN(ctx context.Context, asn string) (*Organization, error) {
	oc.logger.Infow("Discovering organization from ASN", "asn", asn)

	// Extract ASN number
	asnNum := extractASNNumber(asn)
	if asnNum == 0 {
		return nil, fmt.Errorf("invalid ASN format")
	}

	org := &Organization{
		Name:        fmt.Sprintf("Organization for %s", asn),
		ASNs:        []string{asn},
		LastUpdated: time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	// Get ASN details
	if oc.asnClient != nil && oc.config.EnableASN {
		// Parse ASN number
		asnNum := 0
		if strings.HasPrefix(asn, "AS") {
			fmt.Sscanf(asn[2:], "%d", &asnNum)
		} else {
			fmt.Sscanf(asn, "%d", &asnNum)
		}

		if asnNum > 0 {
			if asnData, err := oc.asnClient.GetASNDetails(context.Background(), asnNum); err == nil {
				if asnData.Organization != "" {
					org.Name = asnData.Organization
				}
				org.IPRanges = append(org.IPRanges, asnData.IPRanges...)
			}
		}
	}

	return org, nil
}

// DiscoverFromLinkedIn discovers organization from LinkedIn URL
func (oc *OrganizationCorrelator) DiscoverFromLinkedIn(ctx context.Context, linkedinURL string) (*Organization, error) {
	oc.logger.Infow("Discovering organization from LinkedIn", "url", linkedinURL)

	companyName := extractLinkedInCompany(linkedinURL)
	if companyName == "" {
		return nil, fmt.Errorf("could not extract company from LinkedIn URL")
	}

	// Use company name correlation
	org := &Organization{
		Name:        companyName,
		LastUpdated: time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	oc.correlateCompanyName(ctx, companyName, org)
	oc.secondPassCorrelation(ctx, org)
	org.Confidence = oc.calculateConfidence(org)

	return org, nil
}

// DiscoverFromGitHub discovers organization from GitHub URL
func (oc *OrganizationCorrelator) DiscoverFromGitHub(ctx context.Context, githubURL string) (*Organization, error) {
	oc.logger.Infow("Discovering organization from GitHub", "url", githubURL)

	orgName := extractGitHubOrg(githubURL)
	if orgName == "" {
		return nil, fmt.Errorf("could not extract organization from GitHub URL")
	}

	org := &Organization{
		Name:        orgName,
		GitHubOrgs:  []string{orgName},
		LastUpdated: time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	// Get GitHub organization details
	if oc.githubClient != nil && oc.config.EnableGitHub {
		if githubData, err := oc.githubClient.SearchOrganization(context.Background(), orgName); err == nil && githubData != nil {
			if githubData.OrganizationName != "" {
				org.Name = githubData.OrganizationName
			}

			// Add domains found in GitHub
			for _, domain := range githubData.Domains {
				org.Domains = append(org.Domains, domain)
			}

			// Store GitHub metadata
			org.Metadata["github_repo_count"] = githubData.RepositoryCount
			org.Metadata["github_technologies"] = githubData.Technologies
		}
	}

	return org, nil
}

// Helper functions

func extractASNNumber(asn string) int {
	asn = strings.ToUpper(strings.TrimSpace(asn))
	if strings.HasPrefix(asn, "AS") {
		asn = strings.TrimPrefix(asn, "AS")
	}

	var num int
	fmt.Sscanf(asn, "%d", &num)
	return num
}

func extractOrgFromSubject(subject string) string {
	// Extract O= from certificate subject
	parts := strings.Split(subject, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "O=") {
			return strings.TrimPrefix(part, "O=")
		}
	}
	return ""
}

func isWildcardCert(subject string) bool {
	return strings.Contains(subject, "CN=*.") || strings.Contains(subject, "*.")
}
