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
