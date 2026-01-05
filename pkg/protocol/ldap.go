// pkg/protocol/ldap.go
package protocol

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/go-ldap/ldap/v3"
)

// LDAPScanner performs LDAP security testing
type LDAPScanner struct {
	config Config
	logger Logger
}

// NewLDAPScanner creates a new LDAP scanner
func NewLDAPScanner(config Config, logger Logger) *LDAPScanner {
	return &LDAPScanner{
		config: config,
		logger: logger,
	}
}

// TestAnonymousBind tests for anonymous LDAP bind
func (l *LDAPScanner) TestAnonymousBind(ctx context.Context, target string) []types.Finding {
	findings := []types.Finding{}

	host, port, err := parseTarget(target)
	if err != nil {
		return findings
	}

	// Default LDAP ports
	if port == "443" {
		port = "389"
	}

	// Test anonymous bind
	conn, err := l.connectLDAP(ctx, host, port)
	if err != nil {
		return findings
	}
	defer conn.Close()

	// Try anonymous bind
	err = conn.Bind("", "")
	if err == nil {
		findings = append(findings, types.Finding{
			Tool:        "ldap-scanner",
			Type:        "LDAP_ANONYMOUS_BIND",
			Severity:    types.SeverityHigh,
			Title:       "LDAP server allows anonymous bind",
			Description: "The LDAP server accepts anonymous bind requests, potentially exposing sensitive directory information",
			Solution:    "Disable anonymous bind in LDAP server configuration",
			References: []string{
				"https://ldapwiki.com/wiki/Anonymous%20Bind",
				"https://www.rfc-editor.org/rfc/rfc4513.html#section-5.1.1",
			},
			Metadata: map[string]interface{}{
				"target":      fmt.Sprintf("%s:%s", host, port),
				"port":        port,
				"bind_method": "anonymous",
				"confidence":  "HIGH",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})

		// Test what information is accessible
		infoDisclosed := l.testAnonymousInfoDisclosure(conn)
		if len(infoDisclosed) > 0 {
			findings = append(findings, types.Finding{
				Tool:        "ldap-scanner",
				Type:        "LDAP_ANONYMOUS_INFO_DISCLOSURE",
				Severity:    types.SeverityHigh,
				Title:       "Anonymous LDAP access exposes sensitive information",
				Description: "Anonymous users can access sensitive directory information",
				Solution:    "Restrict anonymous access to only necessary information",
				Metadata: map[string]interface{}{
					"target":          fmt.Sprintf("%s:%s", host, port),
					"accessible_info": infoDisclosed,
					"confidence":      "HIGH",
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			})
		}
	}

	return findings
}

// TestNullBind tests for null bind vulnerability
func (l *LDAPScanner) TestNullBind(ctx context.Context, target string) []types.Finding {
	findings := []types.Finding{}

	host, port, err := parseTarget(target)
	if err != nil {
		return findings
	}

	if port == "443" {
		port = "389"
	}

	// Test null bind with various DNs
	testDNs := []string{
		"cn=admin",
		"cn=administrator",
		"cn=root",
		"cn=manager",
		"uid=admin",
		"uid=administrator",
	}

	vulnerableDNs := []string{}

	for _, dn := range testDNs {
		if l.testNullBind(ctx, host, port, dn) {
			vulnerableDNs = append(vulnerableDNs, dn)
		}
	}

	if len(vulnerableDNs) > 0 {
		findings = append(findings, types.Finding{
			Tool:        "ldap-scanner",
			Type:        "LDAP_NULL_BIND",
			Severity:    types.SeverityCritical,
			Title:       "LDAP null bind vulnerability detected",
			Description: "The LDAP server accepts bind requests with a DN but no password, granting unauthorized access",
			Solution:    "Configure LDAP server to reject bind requests with empty passwords",
			References: []string{
				"https://www.rfc-editor.org/rfc/rfc4513.html#section-5.1.2",
			},
			Metadata: map[string]interface{}{
				"target":         fmt.Sprintf("%s:%s", host, port),
				"vulnerable_dns": vulnerableDNs,
				"confidence":     "HIGH",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	return findings
}

// TestInformationDisclosure tests for information disclosure
func (l *LDAPScanner) TestInformationDisclosure(ctx context.Context, target string) []types.Finding {
	findings := []types.Finding{}

	host, port, err := parseTarget(target)
	if err != nil {
		return findings
	}

	if port == "443" {
		port = "389"
	}

	conn, err := l.connectLDAP(ctx, host, port)
	if err != nil {
		return findings
	}
	defer conn.Close()

	// Try to get root DSE
	rootDSE := l.getRootDSE(conn)
	if rootDSE != nil {
		sensitiveAttrs := []string{}

		// Check for sensitive attributes
		checkAttrs := []string{
			"namingContexts",
			"subschemaSubentry",
			"supportedControl",
			"supportedExtension",
			"supportedFeatures",
			"supportedLDAPVersion",
			"supportedSASLMechanisms",
		}

		for _, attr := range checkAttrs {
			if values := rootDSE.GetAttributeValues(attr); len(values) > 0 {
				sensitiveAttrs = append(sensitiveAttrs, attr)
			}
		}

		if len(sensitiveAttrs) > 0 {
			findings = append(findings, types.Finding{
				Tool:        "ldap-scanner",
				Type:        "LDAP_ROOTDSE_DISCLOSURE",
				Severity:    types.SeverityLow,
				Title:       "LDAP root DSE exposes server information",
				Description: "The LDAP server's root DSE exposes configuration information",
				Solution:    "Consider restricting access to root DSE information",
				Metadata: map[string]interface{}{
					"target":             fmt.Sprintf("%s:%s", host, port),
					"exposed_attributes": sensitiveAttrs,
					"confidence":         "HIGH",
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			})
		}
	}

	// Test for user enumeration
	if l.testUserEnumeration(conn) {
		findings = append(findings, types.Finding{
			Tool:        "ldap-scanner",
			Type:        "LDAP_USER_ENUMERATION",
			Severity:    types.SeverityMedium,
			Title:       "LDAP allows user enumeration",
			Description: "The LDAP server allows enumeration of valid usernames through different error responses",
			Solution:    "Configure LDAP to return consistent error messages",
			Metadata: map[string]interface{}{
				"target":     fmt.Sprintf("%s:%s", host, port),
				"confidence": "HIGH",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	return findings
}

// TestInjection tests for LDAP injection vulnerabilities
func (l *LDAPScanner) TestInjection(ctx context.Context, target string) []types.Finding {
	findings := []types.Finding{}

	// This would typically be tested in the context of a web application
	// Here we just provide information about LDAP injection risks

	findings = append(findings, types.Finding{
		Tool:        "ldap-scanner",
		Type:        "LDAP_INJECTION_INFO",
		Severity:    types.SeverityInfo,
		Title:       "LDAP injection testing requires application context",
		Description: "LDAP injection vulnerabilities exist in applications that construct LDAP queries from user input without proper sanitization",
		Solution:    "Always escape special LDAP characters in user input: ( ) * \\ NUL",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
		},
		Metadata: map[string]interface{}{
			"target": target,
			"common_payloads": []string{
				"*",
				"*)(&",
				"*)(uid=*))(|(uid=*",
				"admin)(&))",
				"admin)|(|",
			},
			"test_locations": []string{
				"Login forms",
				"User search functions",
				"Directory browsers",
				"Password reset forms",
			},
			"confidence": "HIGH",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	return findings
}

// Helper methods

func (l *LDAPScanner) connectLDAP(ctx context.Context, host, port string) (*ldap.Conn, error) {
	address := net.JoinHostPort(host, port)

	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s", address))
	if err != nil {
		// Try LDAPS
		conn, err = ldap.DialURL(fmt.Sprintf("ldaps://%s", address))
		if err != nil {
			return nil, err
		}
	}

	// Set timeout
	conn.SetTimeout(l.config.Timeout)

	return conn, nil
}

func (l *LDAPScanner) testNullBind(ctx context.Context, host, port, dn string) bool {
	conn, err := l.connectLDAP(ctx, host, port)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Try bind with DN but empty password
	err = conn.Bind(dn, "")
	return err == nil
}

func (l *LDAPScanner) testAnonymousInfoDisclosure(conn *ldap.Conn) []string {
	disclosed := []string{}

	// Common base DNs to try
	baseDNs := []string{
		"",
		"dc=example,dc=com",
		"dc=local",
		"cn=users",
		"ou=people",
		"ou=users",
		"ou=groups",
		"cn=admin",
	}

	for _, baseDN := range baseDNs {
		searchRequest := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			10, // Size limit
			5,  // Time limit
			false,
			"(objectClass=*)",
			[]string{},
			nil,
		)

		result, err := conn.Search(searchRequest)
		if err == nil && len(result.Entries) > 0 {
			disclosed = append(disclosed, fmt.Sprintf("Base DN '%s' with %d entries", baseDN, len(result.Entries)))

			// Check for sensitive object classes
			for _, entry := range result.Entries {
				for _, attr := range entry.Attributes {
					if attr.Name == "objectClass" {
						for _, value := range attr.Values {
							if isSensitiveObjectClass(value) {
								disclosed = append(disclosed, fmt.Sprintf("Sensitive object class: %s", value))
							}
						}
					}
				}
			}
		}
	}

	return disclosed
}

func (l *LDAPScanner) getRootDSE(conn *ldap.Conn) *ldap.Entry {
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil || len(result.Entries) == 0 {
		return nil
	}

	return result.Entries[0]
}

func (l *LDAPScanner) testUserEnumeration(conn *ldap.Conn) bool {
	// Test with valid and invalid usernames
	validUserFilter := "(uid=admin)"
	invalidUserFilter := "(uid=definitely-not-a-real-user-12345)"

	// Use the filters for testing (example usage)
	_ = validUserFilter
	_ = invalidUserFilter

	// Try to bind and check error messages
	validErr := conn.Bind("uid=admin,dc=example,dc=com", "wrongpassword")
	invalidErr := conn.Bind("uid=definitely-not-a-real-user-12345,dc=example,dc=com", "wrongpassword")

	// If error messages are different, enumeration is possible
	if validErr != nil && invalidErr != nil {
		return validErr.Error() != invalidErr.Error()
	}

	return false
}

func isSensitiveObjectClass(objectClass string) bool {
	sensitive := []string{
		"person",
		"organizationalPerson",
		"inetOrgPerson",
		"user",
		"computer",
		"group",
		"organizationalUnit",
		"domain",
		"posixAccount",
		"shadowAccount",
	}

	objectClass = strings.ToLower(objectClass)
	for _, s := range sensitive {
		if objectClass == strings.ToLower(s) {
			return true
		}
	}

	return false
}
