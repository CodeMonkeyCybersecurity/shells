// pkg/auth/discovery/types.go
package discovery

import "time"

// LDAPEndpoint represents a discovered LDAP endpoint
type LDAPEndpoint struct {
	Host                    string    `json:"host"`
	Port                    int       `json:"port"`
	SSL                     bool      `json:"ssl"`
	Type                    string    `json:"type"` // ActiveDirectory, OpenLDAP, etc.
	AnonymousBindAllowed    bool      `json:"anonymous_bind_allowed"`
	NamingContexts          []string  `json:"naming_contexts"`
	SupportedSASLMechanisms []string  `json:"supported_sasl_mechanisms"`
	VendorName              string    `json:"vendor_name,omitempty"`
	UserEnumerationPossible bool      `json:"user_enumeration_possible"`
	DiscoveredAt            time.Time `json:"discovered_at"`
}

// SMTPAuthMethod represents SMTP authentication methods
type SMTPAuthMethod struct {
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	TLS               bool     `json:"tls"`
	AuthMechanisms    []string `json:"auth_mechanisms"` // PLAIN, LOGIN, CRAM-MD5, etc.
	StartTLSAvailable bool     `json:"starttls_available"`
}

// FormLoginEndpoint represents a form-based login
type FormLoginEndpoint struct {
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	UsernameField    string            `json:"username_field"`
	PasswordField    string            `json:"password_field"`
	CSRFToken        bool              `json:"csrf_token"`
	AdditionalFields map[string]string `json:"additional_fields"`
	SubmitURL        string            `json:"submit_url"`
}

// OAuth2Endpoint represents an OAuth2 endpoint
type OAuth2Endpoint struct {
	AuthorizeURL string   `json:"authorize_url"`
	TokenURL     string   `json:"token_url"`
	UserInfoURL  string   `json:"userinfo_url,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	GrantTypes   []string `json:"grant_types,omitempty"`
	ClientID     string   `json:"client_id,omitempty"` // If discoverable
	PKCE         bool     `json:"pkce_supported"`
}

// KerberosEndpoint represents a Kerberos authentication endpoint
type KerberosEndpoint struct {
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Realm string `json:"realm"`
}

// RADIUSEndpoint represents a RADIUS authentication endpoint
type RADIUSEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// SMBEndpoint represents an SMB/CIFS endpoint
type SMBEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// RDPEndpoint represents an RDP endpoint
type RDPEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// SSHEndpoint represents an SSH endpoint
type SSHEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// IMAPAuthMethod represents IMAP authentication methods
type IMAPAuthMethod struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	TLS            bool     `json:"tls"`
	AuthMechanisms []string `json:"auth_mechanisms"`
}

// DatabaseAuth represents database authentication
type DatabaseAuth struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	DatabaseType string `json:"database_type"` // MySQL, PostgreSQL, etc.
	AuthMethod   string `json:"auth_method"`
}

// BasicAuthEndpoint represents HTTP Basic Auth
type BasicAuthEndpoint struct {
	URL   string `json:"url"`
	Realm string `json:"realm"`
}

// SAMLEndpoint represents a SAML endpoint
type SAMLEndpoint struct {
	MetadataURL string `json:"metadata_url"`
	SSOURL      string `json:"sso_url"`
	EntityID    string `json:"entity_id"`
}

// OIDCEndpoint represents an OpenID Connect endpoint
type OIDCEndpoint struct {
	ConfigURL string `json:"config_url"`
}

// WebAuthnEndpoint represents a WebAuthn/FIDO2 endpoint
type WebAuthnEndpoint struct {
	RegisterURL     string `json:"register_url"`
	LoginURL        string `json:"login_url"`
	AttestationType string `json:"attestation_type"`
}

// CASEndpoint represents a CAS endpoint
type CASEndpoint struct {
	URL string `json:"url"`
}

// JWTEndpoint represents a JWT-based auth endpoint
type JWTEndpoint struct {
	URL string `json:"url"`
}

// NTLMEndpoint represents an NTLM auth endpoint
type NTLMEndpoint struct {
	URL string `json:"url"`
}

// CookieAuth represents cookie-based authentication
type CookieAuth struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

// HeaderAuth represents header-based authentication
type HeaderAuth struct {
	HeaderName string `json:"header_name"`
	Pattern    string `json:"pattern"`
}

// CustomAuthMethod represents a non-standard auth method
type CustomAuthMethod struct {
	Type        string                 `json:"type"`
	Endpoint    string                 `json:"endpoint"`
	Confidence  float64                `json:"confidence"`
	Indicators  []string               `json:"indicators"`
	Description string                 `json:"description"`
	Headers     map[string]string      `json:"headers,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// APIKeyAuth represents API key authentication
type APIKeyAuth struct {
	Location string `json:"location"` // header, query, cookie
	Name     string `json:"name"`
	Pattern  string `json:"pattern,omitempty"`
}
