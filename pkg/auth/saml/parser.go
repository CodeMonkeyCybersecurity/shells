package saml

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/common"
)

// SAMLParser handles SAML response parsing and analysis
type SAMLParser struct {
	logger common.Logger
}

// NewSAMLParser creates a new SAML parser
func NewSAMLParser(logger common.Logger) *SAMLParser {
	return &SAMLParser{
		logger: logger,
	}
}

// SAMLResponse represents a SAML response
type SAMLResponse struct {
	XMLName      xml.Name          `xml:"Response"`
	ID           string            `xml:"ID,attr"`
	Version      string            `xml:"Version,attr"`
	IssueInstant string            `xml:"IssueInstant,attr"`
	Destination  string            `xml:"Destination,attr"`
	InResponseTo string            `xml:"InResponseTo,attr"`
	Issuer       string            `xml:"Issuer"`
	Status       SAMLStatus        `xml:"Status"`
	Assertion    SAMLAssertion     `xml:"Assertion"`
	Signature    *SAMLSignature    `xml:"Signature"`
	Subject      string            `xml:"-"`
	Attributes   map[string]string `xml:"-"`
}

// SAMLStatus represents SAML response status
type SAMLStatus struct {
	StatusCode SAMLStatusCode `xml:"StatusCode"`
}

// SAMLStatusCode represents SAML status code
type SAMLStatusCode struct {
	Value string `xml:"Value,attr"`
}

// SAMLAssertion represents a SAML assertion
type SAMLAssertion struct {
	XMLName            xml.Name               `xml:"Assertion"`
	ID                 string                 `xml:"ID,attr"`
	Version            string                 `xml:"Version,attr"`
	IssueInstant       string                 `xml:"IssueInstant,attr"`
	Issuer             string                 `xml:"Issuer"`
	Subject            SAMLSubject            `xml:"Subject"`
	Conditions         SAMLConditions         `xml:"Conditions"`
	AuthnStatement     SAMLAuthnStatement     `xml:"AuthnStatement"`
	AttributeStatement SAMLAttributeStatement `xml:"AttributeStatement"`
	Signature          *SAMLSignature         `xml:"Signature"`
}

// SAMLSubject represents SAML subject
type SAMLSubject struct {
	NameID              SAMLNameID              `xml:"NameID"`
	SubjectConfirmation SAMLSubjectConfirmation `xml:"SubjectConfirmation"`
}

// SAMLNameID represents SAML name identifier
type SAMLNameID struct {
	Format string `xml:"Format,attr"`
	Value  string `xml:",chardata"`
}

// SAMLSubjectConfirmation represents subject confirmation
type SAMLSubjectConfirmation struct {
	Method                  string                      `xml:"Method,attr"`
	SubjectConfirmationData SAMLSubjectConfirmationData `xml:"SubjectConfirmationData"`
}

// SAMLSubjectConfirmationData represents subject confirmation data
type SAMLSubjectConfirmationData struct {
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	Recipient    string `xml:"Recipient,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`
}

// SAMLConditions represents SAML conditions
type SAMLConditions struct {
	NotBefore            time.Time                 `xml:"NotBefore,attr"`
	NotOnOrAfter         time.Time                 `xml:"NotOnOrAfter,attr"`
	AudienceRestriction  SAMLAudienceRestriction   `xml:"AudienceRestriction"`
	AudienceRestrictions []SAMLAudienceRestriction `xml:"-"`
}

// SAMLAudienceRestriction represents audience restriction
type SAMLAudienceRestriction struct {
	Audience string `xml:"Audience"`
}

// SAMLAuthnStatement represents authentication statement
type SAMLAuthnStatement struct {
	AuthnInstant string           `xml:"AuthnInstant,attr"`
	AuthnContext SAMLAuthnContext `xml:"AuthnContext"`
}

// SAMLAuthnContext represents authentication context
type SAMLAuthnContext struct {
	AuthnContextClassRef string `xml:"AuthnContextClassRef"`
}

// SAMLAttributeStatement represents attribute statement
type SAMLAttributeStatement struct {
	Attributes []SAMLAttribute `xml:"Attribute"`
}

// SAMLAttribute represents a SAML attribute
type SAMLAttribute struct {
	Name       string               `xml:"Name,attr"`
	NameFormat string               `xml:"NameFormat,attr"`
	Values     []SAMLAttributeValue `xml:"AttributeValue"`
}

// SAMLAttributeValue represents attribute value
type SAMLAttributeValue struct {
	Value string `xml:",chardata"`
}

// SAMLSignature represents XML signature
type SAMLSignature struct {
	XMLName        xml.Name       `xml:"Signature"`
	SignedInfo     SAMLSignedInfo `xml:"SignedInfo"`
	SignatureValue string         `xml:"SignatureValue"`
	KeyInfo        SAMLKeyInfo    `xml:"KeyInfo"`
}

// SAMLSignedInfo represents signed info
type SAMLSignedInfo struct {
	CanonicalizationMethod SAMLCanonicalizationMethod `xml:"CanonicalizationMethod"`
	SignatureMethod        SAMLSignatureMethod        `xml:"SignatureMethod"`
	Reference              SAMLReference              `xml:"Reference"`
}

// SAMLCanonicalizationMethod represents canonicalization method
type SAMLCanonicalizationMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// SAMLSignatureMethod represents signature method
type SAMLSignatureMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// SAMLReference represents signature reference
type SAMLReference struct {
	URI          string           `xml:"URI,attr"`
	Transforms   SAMLTransforms   `xml:"Transforms"`
	DigestMethod SAMLDigestMethod `xml:"DigestMethod"`
	DigestValue  string           `xml:"DigestValue"`
}

// SAMLTransforms represents transforms
type SAMLTransforms struct {
	Transform []SAMLTransform `xml:"Transform"`
}

// SAMLTransform represents a transform
type SAMLTransform struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// SAMLDigestMethod represents digest method
type SAMLDigestMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// SAMLKeyInfo represents key info
type SAMLKeyInfo struct {
	X509Data SAMLX509Data `xml:"X509Data"`
}

// SAMLX509Data represents X509 data
type SAMLX509Data struct {
	X509Certificate string `xml:"X509Certificate"`
}

// SAMLEndpoint represents a SAML endpoint
type SAMLEndpoint struct {
	URL      string            `json:"url"`
	Method   string            `json:"method"`
	Binding  string            `json:"binding"`
	Metadata map[string]string `json:"metadata"`
}

// SAMLDiscoverer discovers SAML endpoints
type SAMLDiscoverer struct {
	httpClient *http.Client
	logger     common.Logger
}

// NewSAMLDiscoverer creates a new SAML discoverer
func NewSAMLDiscoverer(client *http.Client, logger common.Logger) *SAMLDiscoverer {
	return &SAMLDiscoverer{
		httpClient: client,
		logger:     logger,
	}
}

// DiscoverEndpoints discovers SAML endpoints
func (d *SAMLDiscoverer) DiscoverEndpoints(target string) ([]SAMLEndpoint, error) {
	endpoints := []SAMLEndpoint{}

	// Common SAML paths
	samlPaths := []string{
		"/saml/metadata",
		"/saml/SSO",
		"/saml/acs",
		"/saml2/metadata",
		"/saml2/SSO",
		"/saml2/acs",
		"/auth/saml/metadata",
		"/auth/saml/SSO",
		"/auth/saml/acs",
		"/sso/saml2/metadata",
		"/sso/saml2/SSO",
		"/sso/saml2/acs",
		"/.well-known/saml/metadata",
	}

	d.logger.Debug("Discovering SAML endpoints", "target", target, "paths", len(samlPaths))

	for _, path := range samlPaths {
		fullURL := strings.TrimSuffix(target, "/") + path

		resp, err := d.httpClient.Get(fullURL)
		if err != nil {
			continue
		}

		resp.Body.Close()

		if resp.StatusCode == 200 {
			endpoint := SAMLEndpoint{
				URL:      fullURL,
				Method:   "GET",
				Metadata: make(map[string]string),
			}

			// Determine binding and endpoint type
			if strings.Contains(path, "metadata") {
				endpoint.Binding = "metadata"
			} else if strings.Contains(path, "SSO") {
				endpoint.Binding = "SSO"
				endpoint.Method = "POST"
			} else if strings.Contains(path, "acs") {
				endpoint.Binding = "ACS"
				endpoint.Method = "POST"
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	d.logger.Info("SAML endpoint discovery completed", "found", len(endpoints))

	return endpoints, nil
}

// ParseSAMLResponse parses a SAML response
func (p *SAMLParser) ParseSAMLResponse(responseXML string) (*SAMLResponse, error) {
	var response SAMLResponse

	err := xml.Unmarshal([]byte(responseXML), &response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SAML response: %w", err)
	}

	// Extract additional information
	response.Subject = response.Assertion.Subject.NameID.Value
	response.Attributes = make(map[string]string)

	// Parse attributes
	for _, attr := range response.Assertion.AttributeStatement.Attributes {
		values := []string{}
		for _, value := range attr.Values {
			values = append(values, value.Value)
		}
		response.Attributes[attr.Name] = strings.Join(values, ",")
	}

	return &response, nil
}

// ValidateSAMLResponse validates a SAML response
func (p *SAMLParser) ValidateSAMLResponse(response *SAMLResponse) []string {
	issues := []string{}

	// Check required fields
	if response.ID == "" {
		issues = append(issues, "Missing response ID")
	}

	if response.Version != "2.0" {
		issues = append(issues, "Invalid SAML version")
	}

	if response.IssueInstant == "" {
		issues = append(issues, "Missing issue instant")
	}

	if response.Issuer == "" {
		issues = append(issues, "Missing issuer")
	}

	// Check status
	if response.Status.StatusCode.Value == "" {
		issues = append(issues, "Missing status code")
	}

	// Check assertion
	if response.Assertion.ID == "" {
		issues = append(issues, "Missing assertion ID")
	}

	if response.Assertion.Subject.NameID.Value == "" {
		issues = append(issues, "Missing subject name ID")
	}

	// Check conditions
	if response.Assertion.Conditions.NotBefore.IsZero() {
		issues = append(issues, "Missing NotBefore condition")
	}

	if response.Assertion.Conditions.NotOnOrAfter.IsZero() {
		issues = append(issues, "Missing NotOnOrAfter condition")
	}

	// Check signature
	if response.Signature == nil && response.Assertion.Signature == nil {
		issues = append(issues, "Missing signature")
	}

	return issues
}

// Finding represents a SAML security finding
type Finding struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	URL         string    `json:"url"`
	Method      string    `json:"method"`
	Risk        string    `json:"risk"`
	Confidence  string    `json:"confidence"`
	CreatedAt   time.Time `json:"created_at"`
}
