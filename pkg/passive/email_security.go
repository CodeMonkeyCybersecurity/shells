// pkg/passive/email_security.go
package passive

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/miekg/dns"
)

// EmailSecurityIntel performs email security analysis on domains
type EmailSecurityIntel struct {
	logger    *logger.Logger
	resolver  *dns.Client
	dnsServer string
}

// EmailSecurityFindings contains all email security analysis results
type EmailSecurityFindings struct {
	Domain         string
	SPF            SPFRecord
	DKIM           []DKIMRecord
	DMARC          DMARCRecord
	MX             []MXRecord
	Issues         []SecurityIssue
	Opportunities  []SpoofingOpportunity
	RelatedDomains []string
	EmailProviders []EmailProvider
	Timestamp      time.Time
}

// SPFRecord represents SPF configuration analysis
type SPFRecord struct {
	Exists          bool
	Raw             string
	Version         string
	Mechanisms      []SPFMechanism
	Modifiers       map[string]string
	Includes        []string
	IPs             []string
	All             string // +all, -all, ~all, ?all
	IsTooPermissive bool
	Issues          []string
}

// SPFMechanism represents an SPF mechanism
type SPFMechanism struct {
	Type      string // a, mx, include, ip4, ip6, exists, ptr
	Qualifier string // +, -, ~, ?
	Value     string
}

// DKIMRecord represents DKIM configuration
type DKIMRecord struct {
	Selector    string
	Exists      bool
	Raw         string
	Version     string
	KeyType     string
	PublicKey   string
	KeyStrength int
	Flags       []string
	Issues      []string
}

// DMARCRecord represents DMARC configuration analysis
type DMARCRecord struct {
	Exists          bool
	Raw             string
	Version         string
	Policy          string // none, quarantine, reject
	SubdomainPolicy string
	Percentage      int
	RUA             []string // Aggregate report URIs
	RUF             []string // Forensic report URIs
	ADKIM           string   // DKIM alignment
	ASPF            string   // SPF alignment
	ReportFormat    string
	ReportInterval  int
	IsTooPermissive bool
	Issues          []string
}

// MXRecord represents mail exchanger information
type MXRecord struct {
	Priority   uint16
	Host       string
	IPs        []string
	Provider   string
	Reputation float64
}

// SecurityIssue represents an email security problem
type SecurityIssue struct {
	Type        string
	Title       string
	Description string
	Severity    types.Severity
	Evidence    []string
	Remediation string
}

// SpoofingOpportunity represents a potential spoofing vector
type SpoofingOpportunity struct {
	Type       string
	Method     string
	Target     string
	Likelihood float64
	Impact     string
	POC        string // Proof of concept
	Mitigation string
}

// EmailProvider represents an email service provider
type EmailProvider struct {
	Name       string
	Type       string // hosting, protection, relay
	Confidence float64
	Features   []string
}

// NewEmailSecurityIntel creates a new email security intelligence module
func NewEmailSecurityIntel(logger *logger.Logger) *EmailSecurityIntel {
	return &EmailSecurityIntel{
		logger:    logger,
		resolver:  new(dns.Client),
		dnsServer: "8.8.8.8:53", // Use Google DNS by default
	}
}

// AnalyzeDomain performs comprehensive email security analysis
func (e *EmailSecurityIntel) AnalyzeDomain(ctx context.Context, domain string) (*EmailSecurityFindings, error) {
	e.logger.Infow("Starting email security analysis", "domain", domain)

	findings := &EmailSecurityFindings{
		Domain:         domain,
		Issues:         []SecurityIssue{},
		Opportunities:  []SpoofingOpportunity{},
		RelatedDomains: []string{},
		EmailProviders: []EmailProvider{},
		Timestamp:      time.Now(),
	}

	// Analyze SPF
	spf, err := e.analyzeSPF(ctx, domain)
	if err != nil {
		e.logger.Error("SPF analysis failed", "error", err)
	}
	findings.SPF = spf

	// Analyze DKIM (check common selectors)
	dkimRecords := e.analyzeDKIM(ctx, domain)
	findings.DKIM = dkimRecords

	// Analyze DMARC
	dmarc, err := e.analyzeDMARC(ctx, domain)
	if err != nil {
		e.logger.Error("DMARC analysis failed", "error", err)
	}
	findings.DMARC = dmarc

	// Analyze MX records
	mxRecords, err := e.analyzeMX(ctx, domain)
	if err != nil {
		e.logger.Error("MX analysis failed", "error", err)
	}
	findings.MX = mxRecords

	// Identify email providers
	findings.EmailProviders = e.identifyProviders(findings)

	// Extract related domains
	findings.RelatedDomains = e.extractRelatedDomains(findings)

	// Identify security issues
	findings.Issues = e.identifySecurityIssues(findings)

	// Identify spoofing opportunities
	findings.Opportunities = e.identifySpoofingOpportunities(findings)

	e.logger.Info("Email security analysis completed",
		"domain", domain,
		"issues", len(findings.Issues),
		"opportunities", len(findings.Opportunities))

	return findings, nil
}

// analyzeSPF analyzes the SPF record for a domain
func (e *EmailSecurityIntel) analyzeSPF(ctx context.Context, domain string) (SPFRecord, error) {
	spf := SPFRecord{
		Mechanisms: []SPFMechanism{},
		Modifiers:  make(map[string]string),
		Includes:   []string{},
		IPs:        []string{},
		Issues:     []string{},
	}

	// Query TXT records
	txtRecords, err := e.queryTXT(domain)
	if err != nil {
		return spf, err
	}

	// Find SPF record
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			spf.Exists = true
			spf.Raw = txt
			spf.Version = "spf1"
			break
		}
	}

	if !spf.Exists {
		return spf, nil
	}

	// Parse SPF record
	e.parseSPF(&spf)

	// Analyze SPF security
	e.analyzeSPFSecurity(&spf)

	// Expand includes recursively
	e.expandSPFIncludes(ctx, &spf, domain)

	return spf, nil
}

// parseSPF parses SPF record mechanisms and modifiers
func (e *EmailSecurityIntel) parseSPF(spf *SPFRecord) {
	parts := strings.Fields(spf.Raw)

	for i := 1; i < len(parts); i++ { // Skip v=spf1
		part := parts[i]

		// Check for modifiers (redirect=, exp=)
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			spf.Modifiers[kv[0]] = kv[1]
			continue
		}

		// Extract qualifier
		qualifier := "+"
		if strings.HasPrefix(part, "+") || strings.HasPrefix(part, "-") ||
			strings.HasPrefix(part, "~") || strings.HasPrefix(part, "?") {
			qualifier = string(part[0])
			part = part[1:]
		}

		// Parse mechanism
		mechanism := SPFMechanism{Qualifier: qualifier}

		if strings.HasPrefix(part, "include:") {
			mechanism.Type = "include"
			mechanism.Value = strings.TrimPrefix(part, "include:")
			spf.Includes = append(spf.Includes, mechanism.Value)
		} else if strings.HasPrefix(part, "ip4:") {
			mechanism.Type = "ip4"
			mechanism.Value = strings.TrimPrefix(part, "ip4:")
			spf.IPs = append(spf.IPs, mechanism.Value)
		} else if strings.HasPrefix(part, "ip6:") {
			mechanism.Type = "ip6"
			mechanism.Value = strings.TrimPrefix(part, "ip6:")
			spf.IPs = append(spf.IPs, mechanism.Value)
		} else if strings.HasPrefix(part, "a") {
			mechanism.Type = "a"
			if strings.Contains(part, ":") {
				mechanism.Value = strings.TrimPrefix(part, "a:")
			}
		} else if strings.HasPrefix(part, "mx") {
			mechanism.Type = "mx"
			if strings.Contains(part, ":") {
				mechanism.Value = strings.TrimPrefix(part, "mx:")
			}
		} else if part == "all" {
			spf.All = qualifier + "all"
			mechanism.Type = "all"
		} else if strings.HasPrefix(part, "exists:") {
			mechanism.Type = "exists"
			mechanism.Value = strings.TrimPrefix(part, "exists:")
		} else if strings.HasPrefix(part, "ptr") {
			mechanism.Type = "ptr"
			if strings.Contains(part, ":") {
				mechanism.Value = strings.TrimPrefix(part, "ptr:")
			}
		}

		spf.Mechanisms = append(spf.Mechanisms, mechanism)
	}
}

// analyzeSPFSecurity checks for SPF security issues
func (e *EmailSecurityIntel) analyzeSPFSecurity(spf *SPFRecord) {
	// Check if too permissive
	if spf.All == "+all" || spf.All == "?all" {
		spf.IsTooPermissive = true
		spf.Issues = append(spf.Issues, "SPF record ends with permissive +all or ?all")
	}

	// Check for ptr mechanism (deprecated and slow)
	for _, mech := range spf.Mechanisms {
		if mech.Type == "ptr" {
			spf.Issues = append(spf.Issues, "Uses deprecated 'ptr' mechanism")
		}
	}

	// Check for too many DNS lookups
	dnsLookups := 0
	for _, mech := range spf.Mechanisms {
		if mech.Type == "include" || mech.Type == "a" || mech.Type == "mx" ||
			mech.Type == "exists" || mech.Type == "ptr" {
			dnsLookups++
		}
	}
	if dnsLookups > 10 {
		spf.Issues = append(spf.Issues, fmt.Sprintf("Too many DNS lookups (%d/10)", dnsLookups))
	}

	// Check for redirect without all
	if _, hasRedirect := spf.Modifiers["redirect"]; hasRedirect && spf.All != "" {
		spf.Issues = append(spf.Issues, "Has both 'redirect' and 'all' mechanism")
	}
}

// analyzeDKIM checks for DKIM records using common selectors
func (e *EmailSecurityIntel) analyzeDKIM(ctx context.Context, domain string) []DKIMRecord {
	var dkimRecords []DKIMRecord

	// Common DKIM selectors to check
	selectors := []string{
		"default", "dkim", "google", "k1", "k2", "selector1", "selector2",
		"mail", "smtp", "dkim1", "dkim2", "email", "mx", "domainkey",
		"postfix", "sendgrid", "mailgun", "mandrill", "sparkpost",
		"amazonses", "pm", "protonmail", "zoho", "yandex", "mail-dkim",
		"scph1220", "cm", "sm1", "sm2", // Common enterprise selectors
	}

	// Also check date-based selectors
	now := time.Now()
	for i := 0; i < 3; i++ {
		year := now.AddDate(-i, 0, 0).Format("2006")
		selectors = append(selectors, year, year+"01", year+"q1", year+"q2", year+"q3", year+"q4")
	}

	// Check each selector
	for _, selector := range selectors {
		dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)

		txtRecords, err := e.queryTXT(dkimDomain)
		if err != nil || len(txtRecords) == 0 {
			continue
		}

		// Parse DKIM record
		for _, txt := range txtRecords {
			if strings.Contains(txt, "p=") || strings.Contains(txt, "v=DKIM") {
				dkim := e.parseDKIMRecord(selector, txt)
				dkimRecords = append(dkimRecords, dkim)
				e.logger.Debug("Found DKIM record", "selector", selector, "domain", domain)
			}
		}
	}

	return dkimRecords
}

// parseDKIMRecord parses a DKIM TXT record
func (e *EmailSecurityIntel) parseDKIMRecord(selector, txt string) DKIMRecord {
	dkim := DKIMRecord{
		Selector: selector,
		Exists:   true,
		Raw:      txt,
		Issues:   []string{},
	}

	// Parse DKIM tags
	tags := e.parseTags(txt)

	// Extract version
	if v, ok := tags["v"]; ok {
		dkim.Version = v
	}

	// Extract key type
	if k, ok := tags["k"]; ok {
		dkim.KeyType = k
	} else {
		dkim.KeyType = "rsa" // Default
	}

	// Extract public key
	if p, ok := tags["p"]; ok {
		dkim.PublicKey = p

		// Estimate key strength for RSA
		if dkim.KeyType == "rsa" && p != "" {
			// Rough estimation based on base64 encoded key length
			keyBytes := len(p) * 3 / 4
			if keyBytes < 128 {
				dkim.KeyStrength = 512
			} else if keyBytes < 256 {
				dkim.KeyStrength = 1024
			} else if keyBytes < 384 {
				dkim.KeyStrength = 2048
			} else {
				dkim.KeyStrength = 4096
			}
		}
	}

	// Extract flags
	if t, ok := tags["t"]; ok {
		dkim.Flags = strings.Split(t, ":")
	}

	// Check for issues
	if dkim.PublicKey == "" {
		dkim.Issues = append(dkim.Issues, "Empty public key (selector might be revoked)")
	}

	if dkim.KeyStrength > 0 && dkim.KeyStrength < 2048 {
		dkim.Issues = append(dkim.Issues, fmt.Sprintf("Weak key strength: %d bits", dkim.KeyStrength))
	}

	return dkim
}

// analyzeDMARC analyzes the DMARC record
func (e *EmailSecurityIntel) analyzeDMARC(ctx context.Context, domain string) (DMARCRecord, error) {
	dmarc := DMARCRecord{
		Issues: []string{},
	}

	// Query _dmarc.domain
	dmarcDomain := fmt.Sprintf("_dmarc.%s", domain)
	txtRecords, err := e.queryTXT(dmarcDomain)
	if err != nil {
		return dmarc, err
	}

	// Find DMARC record
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			dmarc.Exists = true
			dmarc.Raw = txt
			dmarc.Version = "DMARC1"
			break
		}
	}

	if !dmarc.Exists {
		return dmarc, nil
	}

	// Parse DMARC record
	e.parseDMARC(&dmarc)

	// Analyze DMARC security
	e.analyzeDMARCSecurity(&dmarc)

	return dmarc, nil
}

// parseDMARC parses DMARC record tags
func (e *EmailSecurityIntel) parseDMARC(dmarc *DMARCRecord) {
	tags := e.parseTags(dmarc.Raw)

	// Extract policy
	if p, ok := tags["p"]; ok {
		dmarc.Policy = p
	}

	// Extract subdomain policy
	if sp, ok := tags["sp"]; ok {
		dmarc.SubdomainPolicy = sp
	} else {
		dmarc.SubdomainPolicy = dmarc.Policy // Default to main policy
	}

	// Extract percentage
	if pct, ok := tags["pct"]; ok {
		fmt.Sscanf(pct, "%d", &dmarc.Percentage)
	} else {
		dmarc.Percentage = 100 // Default
	}

	// Extract aggregate report URIs
	if rua, ok := tags["rua"]; ok {
		dmarc.RUA = strings.Split(rua, ",")
	}

	// Extract forensic report URIs
	if ruf, ok := tags["ruf"]; ok {
		dmarc.RUF = strings.Split(ruf, ",")
	}

	// Extract alignment modes
	if adkim, ok := tags["adkim"]; ok {
		dmarc.ADKIM = adkim
	} else {
		dmarc.ADKIM = "r" // Relaxed by default
	}

	if aspf, ok := tags["aspf"]; ok {
		dmarc.ASPF = aspf
	} else {
		dmarc.ASPF = "r" // Relaxed by default
	}

	// Extract report format
	if rf, ok := tags["rf"]; ok {
		dmarc.ReportFormat = rf
	} else {
		dmarc.ReportFormat = "afrf" // Default
	}

	// Extract report interval
	if ri, ok := tags["ri"]; ok {
		fmt.Sscanf(ri, "%d", &dmarc.ReportInterval)
	} else {
		dmarc.ReportInterval = 86400 // Default 24 hours
	}
}

// analyzeDMARCSecurity checks for DMARC security issues
func (e *EmailSecurityIntel) analyzeDMARCSecurity(dmarc *DMARCRecord) {
	// Check if policy is too permissive
	if dmarc.Policy == "none" {
		dmarc.IsTooPermissive = true
		dmarc.Issues = append(dmarc.Issues, "DMARC policy set to 'none' (monitoring only)")
	}

	// Check if percentage is less than 100
	if dmarc.Percentage < 100 {
		dmarc.Issues = append(dmarc.Issues,
			fmt.Sprintf("DMARC only applied to %d%% of messages", dmarc.Percentage))
	}

	// Check subdomain policy
	if dmarc.SubdomainPolicy == "none" && dmarc.Policy != "none" {
		dmarc.Issues = append(dmarc.Issues, "Subdomain policy is weaker than domain policy")
	}

	// Check if no reporting URIs
	if len(dmarc.RUA) == 0 && len(dmarc.RUF) == 0 {
		dmarc.Issues = append(dmarc.Issues, "No DMARC reports configured")
	}

	// Check alignment modes
	if dmarc.ADKIM == "r" || dmarc.ASPF == "r" {
		dmarc.Issues = append(dmarc.Issues, "Using relaxed alignment (less secure)")
	}
}

// analyzeMX analyzes MX records
func (e *EmailSecurityIntel) analyzeMX(ctx context.Context, domain string) ([]MXRecord, error) {
	var mxRecords []MXRecord

	// Query MX records
	mxs, err := net.LookupMX(domain)
	if err != nil {
		return mxRecords, err
	}

	for _, mx := range mxs {
		record := MXRecord{
			Priority: mx.Pref,
			Host:     strings.TrimSuffix(mx.Host, "."),
			IPs:      []string{},
		}

		// Resolve MX host to IPs
		ips, err := net.LookupHost(record.Host)
		if err == nil {
			record.IPs = ips
		}

		// Identify provider
		record.Provider = e.identifyMXProvider(record.Host)

		// Check reputation (simplified)
		record.Reputation = e.checkMXReputation(record.Host)

		mxRecords = append(mxRecords, record)
	}

	return mxRecords, nil
}

// identifyMXProvider identifies the email provider from MX hostname
func (e *EmailSecurityIntel) identifyMXProvider(mxHost string) string {
	providers := map[string]string{
		"google.com":        "Google Workspace",
		"googlemail.com":    "Google Workspace",
		"outlook.com":       "Microsoft 365",
		"office365.com":     "Microsoft 365",
		"mimecast":          "Mimecast",
		"proofpoint":        "Proofpoint",
		"barracuda":         "Barracuda",
		"messagelabs":       "Symantec MessageLabs",
		"pphosted.com":      "Proofpoint",
		"mailgun.org":       "Mailgun",
		"sendgrid.net":      "SendGrid",
		"amazonses.com":     "Amazon SES",
		"mandrillapp.com":   "Mandrill",
		"sparkpostmail.com": "SparkPost",
		"zoho.com":          "Zoho Mail",
		"yandex":            "Yandex Mail",
		"mail.ru":           "Mail.ru",
	}

	mxLower := strings.ToLower(mxHost)
	for pattern, provider := range providers {
		if strings.Contains(mxLower, pattern) {
			return provider
		}
	}

	return "Unknown"
}

// checkMXReputation checks the reputation of an MX host
func (e *EmailSecurityIntel) checkMXReputation(mxHost string) float64 {
	// Simplified reputation check
	// In production, this would query reputation databases

	trustedProviders := []string{
		"google", "microsoft", "mimecast", "proofpoint",
		"barracuda", "messagelabs", "pphosted",
	}

	mxLower := strings.ToLower(mxHost)
	for _, trusted := range trustedProviders {
		if strings.Contains(mxLower, trusted) {
			return 0.9 // High reputation
		}
	}

	// Check if it's the domain itself
	if strings.Contains(mxHost, ".") {
		return 0.5 // Medium reputation
	}

	return 0.3 // Low reputation
}

// identifyProviders identifies all email-related service providers
func (e *EmailSecurityIntel) identifyProviders(findings *EmailSecurityFindings) []EmailProvider {
	providers := make(map[string]EmailProvider)

	// From MX records
	for _, mx := range findings.MX {
		if mx.Provider != "Unknown" {
			if p, exists := providers[mx.Provider]; exists {
				p.Features = append(p.Features, "mail_hosting")
			} else {
				providers[mx.Provider] = EmailProvider{
					Name:       mx.Provider,
					Type:       "hosting",
					Confidence: 0.9,
					Features:   []string{"mail_hosting"},
				}
			}
		}
	}

	// From SPF includes
	for _, include := range findings.SPF.Includes {
		provider := e.identifyProviderFromDomain(include)
		if provider != "" {
			if p, exists := providers[provider]; exists {
				p.Features = append(p.Features, "spf_authorized")
			} else {
				providers[provider] = EmailProvider{
					Name:       provider,
					Type:       "relay",
					Confidence: 0.8,
					Features:   []string{"spf_authorized"},
				}
			}
		}
	}

	// Convert map to slice
	var result []EmailProvider
	for _, provider := range providers {
		result = append(result, provider)
	}

	return result
}

// identifyProviderFromDomain identifies provider from a domain
func (e *EmailSecurityIntel) identifyProviderFromDomain(domain string) string {
	providers := map[string]string{
		"_spf.google.com":            "Google Workspace",
		"spf.protection.outlook.com": "Microsoft 365",
		"sendgrid.net":               "SendGrid",
		"mailgun.org":                "Mailgun",
		"mandrillapp.com":            "Mandrill",
		"amazonses.com":              "Amazon SES",
		"sparkpostmail.com":          "SparkPost",
	}

	for pattern, provider := range providers {
		if strings.Contains(domain, pattern) {
			return provider
		}
	}

	return ""
}

// extractRelatedDomains finds related domains from email configuration
func (e *EmailSecurityIntel) extractRelatedDomains(findings *EmailSecurityFindings) []string {
	relatedMap := make(map[string]bool)

	// From SPF includes
	for _, include := range findings.SPF.Includes {
		// Skip known provider domains
		if e.identifyProviderFromDomain(include) == "" {
			// Extract base domain
			parts := strings.Split(include, ".")
			if len(parts) >= 2 {
				baseDomain := strings.Join(parts[len(parts)-2:], ".")
				if baseDomain != findings.Domain {
					relatedMap[baseDomain] = true
				}
			}
		}
	}

	// From DMARC report URIs
	for _, uri := range append(findings.DMARC.RUA, findings.DMARC.RUF...) {
		if strings.Contains(uri, "@") {
			parts := strings.Split(uri, "@")
			if len(parts) == 2 {
				domain := parts[1]
				if domain != findings.Domain {
					relatedMap[domain] = true
				}
			}
		}
	}

	// Convert to slice
	var related []string
	for domain := range relatedMap {
		related = append(related, domain)
	}

	return related
}

// identifySecurityIssues identifies email security issues
func (e *EmailSecurityIntel) identifySecurityIssues(findings *EmailSecurityFindings) []SecurityIssue {
	var issues []SecurityIssue

	// SPF issues
	if !findings.SPF.Exists {
		issues = append(issues, SecurityIssue{
			Type:        "missing_spf",
			Title:       "No SPF Record Found",
			Description: "Domain does not have an SPF record, allowing anyone to send emails on behalf of this domain",
			Severity:    types.SeverityHigh,
			Evidence:    []string{"No TXT record with v=spf1 found"},
			Remediation: "Add an SPF record to specify authorized mail servers",
		})
	} else if findings.SPF.IsTooPermissive {
		issues = append(issues, SecurityIssue{
			Type:        "permissive_spf",
			Title:       "SPF Record Too Permissive",
			Description: fmt.Sprintf("SPF record ends with '%s' which allows unauthorized servers", findings.SPF.All),
			Severity:    types.SeverityMedium,
			Evidence:    []string{findings.SPF.Raw},
			Remediation: "Change SPF record to end with '-all' to reject unauthorized senders",
		})
	}

	// DKIM issues
	if len(findings.DKIM) == 0 {
		issues = append(issues, SecurityIssue{
			Type:        "no_dkim",
			Title:       "No DKIM Records Found",
			Description: "No DKIM records found for common selectors, emails cannot be cryptographically verified",
			Severity:    types.SeverityMedium,
			Evidence:    []string{"Checked common DKIM selectors, none found"},
			Remediation: "Implement DKIM signing for outgoing emails",
		})
	}

	// DMARC issues
	if !findings.DMARC.Exists {
		issues = append(issues, SecurityIssue{
			Type:        "missing_dmarc",
			Title:       "No DMARC Record Found",
			Description: "Domain does not have a DMARC policy, making it vulnerable to email spoofing",
			Severity:    types.SeverityHigh,
			Evidence:    []string{fmt.Sprintf("No TXT record at _dmarc.%s", findings.Domain)},
			Remediation: "Add a DMARC record to prevent email spoofing",
		})
	} else if findings.DMARC.IsTooPermissive {
		issues = append(issues, SecurityIssue{
			Type:        "permissive_dmarc",
			Title:       "DMARC Policy Not Enforced",
			Description: "DMARC policy is set to 'none', only monitoring but not blocking spoofed emails",
			Severity:    types.SeverityMedium,
			Evidence:    []string{findings.DMARC.Raw},
			Remediation: "Change DMARC policy to 'quarantine' or 'reject'",
		})
	}

	// MX issues
	if len(findings.MX) == 0 {
		issues = append(issues, SecurityIssue{
			Type:        "no_mx",
			Title:       "No MX Records Found",
			Description: "Domain has no MX records, cannot receive emails",
			Severity:    types.SeverityInfo,
			Evidence:    []string{"No MX records in DNS"},
			Remediation: "Add MX records if email reception is needed",
		})
	}

	// Add SPF-specific issues
	for _, issue := range findings.SPF.Issues {
		issues = append(issues, SecurityIssue{
			Type:        "spf_issue",
			Title:       "SPF Configuration Issue",
			Description: issue,
			Severity:    types.SeverityLow,
			Evidence:    []string{findings.SPF.Raw},
			Remediation: "Review and fix SPF record configuration",
		})
	}

	// Add DMARC-specific issues
	for _, issue := range findings.DMARC.Issues {
		issues = append(issues, SecurityIssue{
			Type:        "dmarc_issue",
			Title:       "DMARC Configuration Issue",
			Description: issue,
			Severity:    types.SeverityLow,
			Evidence:    []string{findings.DMARC.Raw},
			Remediation: "Review and fix DMARC record configuration",
		})
	}

	return issues
}

// identifySpoofingOpportunities identifies potential email spoofing vectors
func (e *EmailSecurityIntel) identifySpoofingOpportunities(findings *EmailSecurityFindings) []SpoofingOpportunity {
	var opportunities []SpoofingOpportunity

	// Direct spoofing if no SPF
	if !findings.SPF.Exists {
		opportunities = append(opportunities, SpoofingOpportunity{
			Type:       "direct_spoof",
			Method:     "SMTP Direct",
			Target:     findings.Domain,
			Likelihood: 0.9,
			Impact:     "Complete email spoofing capability",
			POC:        fmt.Sprintf("swaks --to victim@target.com --from ceo@%s --server [any SMTP server]", findings.Domain),
			Mitigation: "Implement SPF record",
		})
	}

	// Subdomain spoofing if no DMARC or weak subdomain policy
	if !findings.DMARC.Exists || findings.DMARC.SubdomainPolicy == "none" {
		opportunities = append(opportunities, SpoofingOpportunity{
			Type:       "subdomain_spoof",
			Method:     "Subdomain Creation",
			Target:     fmt.Sprintf("*.%s", findings.Domain),
			Likelihood: 0.8,
			Impact:     "Can spoof from any subdomain",
			POC:        fmt.Sprintf("swaks --to victim@target.com --from admin@fake.%s", findings.Domain),
			Mitigation: "Implement DMARC with strict subdomain policy",
		})
	}

	// Display name spoofing if DMARC not reject
	if !findings.DMARC.Exists || findings.DMARC.Policy != "reject" {
		opportunities = append(opportunities, SpoofingOpportunity{
			Type:       "display_name_spoof",
			Method:     "Display Name",
			Target:     findings.Domain,
			Likelihood: 0.7,
			Impact:     "Can spoof display name while using different domain",
			POC:        fmt.Sprintf(`swaks --to victim@target.com --from attacker@evil.com --header "From: CEO <%s>" `, findings.Domain),
			Mitigation: "Implement DMARC with reject policy",
		})
	}

	// Homograph attack
	opportunities = append(opportunities, SpoofingOpportunity{
		Type:       "homograph",
		Method:     "IDN Homograph",
		Target:     findings.Domain,
		Likelihood: 0.6,
		Impact:     "Visual spoofing using similar-looking characters",
		POC:        e.generateHomographExample(findings.Domain),
		Mitigation: "User awareness training and email filtering",
	})

	// Cousin domain
	opportunities = append(opportunities, SpoofingOpportunity{
		Type:       "cousin_domain",
		Method:     "Similar Domain Registration",
		Target:     findings.Domain,
		Likelihood: 0.5,
		Impact:     "Confusion through similar domain names",
		POC:        e.generateCousinDomainExamples(findings.Domain),
		Mitigation: "Register similar domains defensively",
	})

	return opportunities
}

// generateHomographExample creates homograph attack examples
func (e *EmailSecurityIntel) generateHomographExample(domain string) string {
	// Common homograph substitutions
	substitutions := map[rune]string{
		'a': "а", // Cyrillic
		'e': "е", // Cyrillic
		'o': "о", // Cyrillic
		'i': "і", // Cyrillic
		'l': "ӏ", // Cyrillic
	}

	examples := []string{}
	for i, char := range domain {
		if sub, ok := substitutions[char]; ok {
			homograph := domain[:i] + sub + domain[i+1:]
			examples = append(examples, homograph)
			if len(examples) >= 3 {
				break
			}
		}
	}

	if len(examples) > 0 {
		return fmt.Sprintf("Examples: %s", strings.Join(examples, ", "))
	}

	return "Replace Latin characters with visually similar Unicode characters"
}

// generateCousinDomainExamples creates typosquatting examples
func (e *EmailSecurityIntel) generateCousinDomainExamples(domain string) string {
	examples := []string{}

	// Remove TLD
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}

	name := parts[0]
	tld := strings.Join(parts[1:], ".")

	// Common typos
	if len(name) > 3 {
		// Character swap
		if len(name) > 1 {
			swapped := name[:0] + string(name[1]) + string(name[0]) + name[2:]
			examples = append(examples, swapped+"."+tld)
		}

		// Missing character
		examples = append(examples, name[1:]+"."+tld)

		// Double character
		examples = append(examples, name[:1]+string(name[0])+name[1:]+"."+tld)
	}

	// Different TLDs
	altTLDs := []string{"com", "net", "org", "io", "co"}
	for _, altTLD := range altTLDs {
		if altTLD != tld {
			examples = append(examples, name+"."+altTLD)
			if len(examples) >= 3 {
				break
			}
		}
	}

	return strings.Join(examples[:min(3, len(examples))], ", ")
}

// Helper functions

// queryTXT performs DNS TXT record lookup
func (e *EmailSecurityIntel) queryTXT(domain string) ([]string, error) {
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return nil, err
	}

	// Concatenate multi-string TXT records
	var result []string
	for _, record := range txtRecords {
		result = append(result, record)
	}

	return result, nil
}

// parseTags parses tag=value pairs from SPF/DMARC records
func (e *EmailSecurityIntel) parseTags(record string) map[string]string {
	tags := make(map[string]string)

	// Remove record type prefix
	record = strings.TrimPrefix(record, "v=spf1 ")
	record = strings.TrimPrefix(record, "v=DMARC1;")
	record = strings.TrimPrefix(record, "v=DMARC1 ;")

	// Split by semicolon for DMARC or space for SPF
	var parts []string
	if strings.Contains(record, ";") {
		parts = strings.Split(record, ";")
	} else {
		parts = strings.Fields(record)
	}

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				tags[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	return tags
}

// expandSPFIncludes recursively expands SPF include mechanisms
func (e *EmailSecurityIntel) expandSPFIncludes(ctx context.Context, spf *SPFRecord, domain string) {
	// Limit recursion depth
	maxDepth := 3
	visited := make(map[string]bool)

	var expand func(include string, depth int)
	expand = func(include string, depth int) {
		if depth > maxDepth || visited[include] {
			return
		}
		visited[include] = true

		// Query the included domain
		includedSPF, err := e.analyzeSPF(ctx, include)
		if err != nil || !includedSPF.Exists {
			return
		}

		// Add IPs from included record
		spf.IPs = append(spf.IPs, includedSPF.IPs...)

		// Recursively expand its includes
		for _, nestedInclude := range includedSPF.Includes {
			expand(nestedInclude, depth+1)
		}
	}

	// Start expansion
	for _, include := range spf.Includes {
		expand(include, 1)
	}
}
