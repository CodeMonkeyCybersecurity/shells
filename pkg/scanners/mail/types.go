// pkg/scanners/mail/types.go
//
// Mail Server Security Scanner - Type Definitions
//
// Tests SMTP, POP3, and IMAP servers for common security vulnerabilities:
// - Open relay detection (CRITICAL)
// - SPF/DKIM/DMARC validation
// - User enumeration via VRFY/EXPN
// - STARTTLS support and configuration
// - Weak authentication methods
// - Information disclosure in banners

package mail

import "time"

// MailServiceType represents the type of mail service
type MailServiceType string

const (
	ServiceSMTP MailServiceType = "SMTP"
	ServicePOP3 MailServiceType = "POP3"
	ServiceIMAP MailServiceType = "IMAP"
)

// MailVulnerabilityType represents specific mail vulnerabilities
type MailVulnerabilityType string

const (
	VulnOpenRelay          MailVulnerabilityType = "open_relay"
	VulnUserEnumeration    MailVulnerabilityType = "user_enumeration"
	VulnNoSPF              MailVulnerabilityType = "missing_spf"
	VulnNoDKIM             MailVulnerabilityType = "missing_dkim"
	VulnNoDMARC            MailVulnerabilityType = "missing_dmarc"
	VulnNoSTARTTLS         MailVulnerabilityType = "missing_starttls"
	VulnWeakAuth           MailVulnerabilityType = "weak_authentication"
	VulnBannerDisclosure   MailVulnerabilityType = "banner_information_disclosure"
	VulnExpiredCertificate MailVulnerabilityType = "expired_certificate"
	VulnWeakCipher         MailVulnerabilityType = "weak_cipher"
)

// MailFinding represents a mail security finding
type MailFinding struct {
	Host              string                `json:"host"`
	Port              int                   `json:"port"`
	Service           MailServiceType       `json:"service"`
	VulnerabilityType MailVulnerabilityType `json:"vulnerability_type"`
	Severity          string                `json:"severity"`
	Title             string                `json:"title"`
	Description       string                `json:"description"`
	Evidence          string                `json:"evidence"`
	Remediation       string                `json:"remediation"`

	// Service information
	Version       string   `json:"version,omitempty"`
	Banner        string   `json:"banner,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
	TLSSupported  bool     `json:"tls_supported"`
	AuthMethods   []string `json:"auth_methods,omitempty"`

	// DNS security records
	SPFRecord   string `json:"spf_record,omitempty"`
	DKIMPresent bool   `json:"dkim_present"`
	DMARCRecord string `json:"dmarc_record,omitempty"`

	// Certificate information
	CertificateValid bool      `json:"certificate_valid"`
	CertificateExpiry time.Time `json:"certificate_expiry,omitempty"`

	DiscoveredAt time.Time `json:"discovered_at"`
}

// MailServerInfo contains information about a discovered mail server
type MailServerInfo struct {
	Host          string          `json:"host"`
	Port          int             `json:"port"`
	Service       MailServiceType `json:"service"`
	Banner        string          `json:"banner"`
	Version       string          `json:"version"`
	Capabilities  []string        `json:"capabilities"`
	TLSSupported  bool            `json:"tls_supported"`
	AuthMethods   []string        `json:"auth_methods"`
	Reachable     bool            `json:"reachable"`
	ResponseTime  time.Duration   `json:"response_time"`
}
