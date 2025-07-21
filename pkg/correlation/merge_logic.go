// pkg/correlation/merge_logic.go
package correlation

import (
	"fmt"
	"strings"
)

// WhoisData represents WHOIS lookup results
type WhoisData struct {
	Organization    string
	RegistrantName  string
	RegistrantEmail string
	NameServers     []string
}

// ASNData represents ASN lookup results
type ASNData struct {
	Number       int
	IPRanges     []string
	Organization string
	Description  string
}

// LinkedInData represents LinkedIn company data
type LinkedInData struct {
	CompanyName   string
	CompanyURL    string
	EmployeeCount int
	Industry      string
	Employees     []LinkedInEmployee
	Technologies  []string
}

// LinkedInEmployee represents an employee found on LinkedIn
type LinkedInEmployee struct {
	Email      string
	Name       string
	Title      string
	Department string
	ProfileURL string
}

// GitHubData represents GitHub organization data
type GitHubData struct {
	OrganizationName string
	OrganizationURL  string
	RepositoryCount  int
	Members          []GitHubMember
	Technologies     []string
	Domains          []string
}

// GitHubMember represents a GitHub organization member
type GitHubMember struct {
	Email    string
	Name     string
	Username string
}

// mergeWhoisData merges WHOIS data into organization profile
func (oc *OrganizationCorrelator) mergeWhoisData(profile *OrganizationProfile, whois *WhoisData) {
	// Extract organization name
	if whois.Organization != "" && profile.Name == "" {
		profile.Name = whois.Organization
	}
	
	// Extract registrant information
	if whois.RegistrantName != "" && profile.LegalName == "" {
		profile.LegalName = whois.RegistrantName
	}
	
	// Extract email patterns
	if whois.RegistrantEmail != "" {
		if domain := extractDomainFromEmail(whois.RegistrantEmail); domain != "" {
			pattern := fmt.Sprintf("*@%s", domain)
			if !containsString(profile.EmailPatterns, pattern) {
				profile.EmailPatterns = append(profile.EmailPatterns, pattern)
			}
		}
	}
	
	// Store additional WHOIS organizations for subsidiary detection
	if orgs, ok := profile.Metadata["whois_organizations"].([]string); ok {
		if !containsString(orgs, whois.Organization) {
			orgs = append(orgs, whois.Organization)
			profile.Metadata["whois_organizations"] = orgs
		}
	} else {
		profile.Metadata["whois_organizations"] = []string{whois.Organization}
	}
	
	// Extract name servers (often reveal hosting providers or related infrastructure)
	if nameservers, ok := profile.Metadata["nameservers"].([]string); ok {
		nameservers = append(nameservers, whois.NameServers...)
		profile.Metadata["nameservers"] = deduplicateStrings(nameservers)
	} else {
		profile.Metadata["nameservers"] = whois.NameServers
	}
}

// mergeCertificateData merges certificate data into organization profile
func (oc *OrganizationCorrelator) mergeCertificateData(profile *OrganizationProfile, certs []CertificateInfo) {
	for _, cert := range certs {
		// Add certificate to profile
		profile.Certificates = append(profile.Certificates, cert)
		
		// Extract organization name
		if cert.Organization != "" && profile.Name == "" {
			profile.Name = cert.Organization
		}
		
		// Extract all domains from SANs
		for _, san := range cert.SANs {
			san = strings.TrimPrefix(san, "*.")
			if !containsString(profile.Domains, san) && isDomainValid(san) {
				profile.Domains = append(profile.Domains, san)
			}
		}
	}
}

// mergeASNData merges ASN data into organization profile
func (oc *OrganizationCorrelator) mergeASNData(profile *OrganizationProfile, asn *ASNData) {
	// Add AS numbers
	if !containsInt(profile.ASNumbers, asn.Number) {
		profile.ASNumbers = append(profile.ASNumbers, asn.Number)
	}
	
	// Add IP ranges
	for _, ipRange := range asn.IPRanges {
		if !containsString(profile.IPRanges, ipRange) {
			profile.IPRanges = append(profile.IPRanges, ipRange)
		}
	}
	
	// Update organization name if not set
	if asn.Organization != "" && profile.Name == "" {
		profile.Name = asn.Organization
	}
	
	// Store ASN description for additional context
	if profile.Metadata["asn_descriptions"] == nil {
		profile.Metadata["asn_descriptions"] = make(map[int]string)
	}
	profile.Metadata["asn_descriptions"].(map[int]string)[asn.Number] = asn.Description
}

// mergeLinkedInData merges LinkedIn data into organization profile
func (oc *OrganizationCorrelator) mergeLinkedInData(profile *OrganizationProfile, linkedin *LinkedInData) {
	// Update company name if more complete
	if linkedin.CompanyName != "" && len(linkedin.CompanyName) > len(profile.Name) {
		profile.Name = linkedin.CompanyName
	}
	
	// Add employees
	for _, emp := range linkedin.Employees {
		empInfo := EmployeeInfo{
			Email:       emp.Email,
			Name:        emp.Name,
			Title:       emp.Title,
			Department:  emp.Department,
			LinkedInURL: emp.ProfileURL,
			Confidence:  0.8,
		}
		profile.Employees = append(profile.Employees, empInfo)
		
		// Extract email domain
		if emp.Email != "" {
			if domain := extractDomainFromEmail(emp.Email); domain != "" {
				if !containsString(profile.Domains, domain) {
					profile.Domains = append(profile.Domains, domain)
				}
			}
		}
	}
	
	// Extract technologies from job postings
	if linkedin.Technologies != nil {
		profile.Technologies = append(profile.Technologies, linkedin.Technologies...)
		profile.Technologies = deduplicateStrings(profile.Technologies)
	}
	
	// Store LinkedIn metadata
	profile.Metadata["linkedin_url"] = linkedin.CompanyURL
	profile.Metadata["employee_count"] = linkedin.EmployeeCount
	profile.Metadata["industry"] = linkedin.Industry
}

// mergeGitHubData merges GitHub data into organization profile
func (oc *OrganizationCorrelator) mergeGitHubData(profile *OrganizationProfile, github *GitHubData) {
	// Update organization name if available
	if github.OrganizationName != "" && profile.Name == "" {
		profile.Name = github.OrganizationName
	}
	
	// Add GitHub employees
	for _, member := range github.Members {
		// Check if we already have this employee
		found := false
		for i, emp := range profile.Employees {
			if emp.Email == member.Email || emp.Name == member.Name {
				// Update with GitHub username
				profile.Employees[i].GitHubUsername = member.Username
				found = true
				break
			}
		}
		
		if !found {
			empInfo := EmployeeInfo{
				Email:          member.Email,
				Name:           member.Name,
				GitHubUsername: member.Username,
				Confidence:     0.7,
			}
			profile.Employees = append(profile.Employees, empInfo)
		}
	}
	
	// Extract technologies from repositories
	if github.Technologies != nil {
		profile.Technologies = append(profile.Technologies, github.Technologies...)
		profile.Technologies = deduplicateStrings(profile.Technologies)
	}
	
	// Extract domains from repository URLs or CNAME files
	for _, domain := range github.Domains {
		if !containsString(profile.Domains, domain) {
			profile.Domains = append(profile.Domains, domain)
		}
	}
	
	// Store GitHub metadata
	profile.Metadata["github_org"] = github.OrganizationURL
	profile.Metadata["github_repos"] = github.RepositoryCount
}

// mergeProfiles merges two organization profiles
func (oc *OrganizationCorrelator) mergeProfiles(target, source *OrganizationProfile) {
	// Merge basic fields
	if target.Name == "" && source.Name != "" {
		target.Name = source.Name
	}
	if target.LegalName == "" && source.LegalName != "" {
		target.LegalName = source.LegalName
	}
	
	// Merge arrays with deduplication
	target.Aliases = deduplicateStrings(append(target.Aliases, source.Aliases...))
	target.Domains = deduplicateStrings(append(target.Domains, source.Domains...))
	target.IPRanges = deduplicateStrings(append(target.IPRanges, source.IPRanges...))
	target.ASNumbers = deduplicateInts(append(target.ASNumbers, source.ASNumbers...))
	target.Subsidiaries = deduplicateStrings(append(target.Subsidiaries, source.Subsidiaries...))
	target.EmailPatterns = deduplicateStrings(append(target.EmailPatterns, source.EmailPatterns...))
	target.Technologies = deduplicateStrings(append(target.Technologies, source.Technologies...))
	
	// Merge certificates
	target.Certificates = append(target.Certificates, source.Certificates...)
	
	// Merge employees with deduplication
	employeeMap := make(map[string]EmployeeInfo)
	for _, emp := range target.Employees {
		key := emp.Email
		if key == "" {
			key = emp.Name
		}
		employeeMap[key] = emp
	}
	for _, emp := range source.Employees {
		key := emp.Email
		if key == "" {
			key = emp.Name
		}
		if existing, exists := employeeMap[key]; exists {
			// Merge employee data
			if existing.GitHubUsername == "" && emp.GitHubUsername != "" {
				existing.GitHubUsername = emp.GitHubUsername
			}
			if existing.LinkedInURL == "" && emp.LinkedInURL != "" {
				existing.LinkedInURL = emp.LinkedInURL
			}
			employeeMap[key] = existing
		} else {
			employeeMap[key] = emp
		}
	}
	target.Employees = make([]EmployeeInfo, 0, len(employeeMap))
	for _, emp := range employeeMap {
		target.Employees = append(target.Employees, emp)
	}
	
	// Merge cloud accounts
	if target.CloudAccounts == nil {
		target.CloudAccounts = make(map[string][]string)
	}
	for provider, accounts := range source.CloudAccounts {
		target.CloudAccounts[provider] = deduplicateStrings(
			append(target.CloudAccounts[provider], accounts...),
		)
	}
	
	// Merge metadata
	for k, v := range source.Metadata {
		if _, exists := target.Metadata[k]; !exists {
			target.Metadata[k] = v
		}
	}
	
	// Update confidence (take the higher value)
	if source.Confidence > target.Confidence {
		target.Confidence = source.Confidence
	}
}

// calculateConfidenceProfile calculates organization profile confidence score
func (oc *OrganizationCorrelator) calculateConfidenceProfile(profile *OrganizationProfile) float64 {
	score := 0.0
	factors := 0
	
	// Name discovery confidence
	if profile.Name != "" {
		score += 0.9
		factors++
	}
	
	// Domain count factor
	if len(profile.Domains) > 0 {
		domainScore := float64(len(profile.Domains)) / 10.0
		if domainScore > 1.0 {
			domainScore = 1.0
		}
		score += domainScore
		factors++
	}
	
	// ASN information
	if len(profile.ASNumbers) > 0 {
		score += 0.8
		factors++
	}
	
	// Certificate information
	if len(profile.Certificates) > 0 {
		certScore := float64(len(profile.Certificates)) / 5.0
		if certScore > 1.0 {
			certScore = 1.0
		}
		score += certScore
		factors++
	}
	
	// Employee information
	if len(profile.Employees) > 0 {
		empScore := float64(len(profile.Employees)) / 20.0
		if empScore > 1.0 {
			empScore = 1.0
		}
		score += empScore
		factors++
	}
	
	// Cloud accounts
	if len(profile.CloudAccounts) > 0 {
		score += 0.7
		factors++
	}
	
	if factors == 0 {
		return 0.0
	}
	
	return score / float64(factors)
}