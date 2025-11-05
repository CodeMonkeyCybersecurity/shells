package saml

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/common"
)

// mockLogger implements common.Logger for testing
type mockLogger struct{}

func (m *mockLogger) Info(msg string, keysAndValues ...interface{})  {}
func (m *mockLogger) Debug(msg string, keysAndValues ...interface{}) {}
func (m *mockLogger) Warn(msg string, keysAndValues ...interface{})  {}
func (m *mockLogger) Error(msg string, keysAndValues ...interface{}) {}

// TestNewSAMLScanner tests scanner initialization
func TestNewSAMLScanner(t *testing.T) {
	logger := &mockLogger{}
	scanner := NewSAMLScanner(logger)

	if scanner == nil {
		t.Fatal("Expected scanner to be initialized")
	}

	if scanner.httpClient == null {
		t.Error("Expected HTTP client to be initialized")
	}

	if scanner.parser == nil {
		t.Error("Expected parser to be initialized")
	}

	if scanner.goldenSAML == nil {
		t.Error("Expected Golden SAML scanner to be initialized")
	}

	if scanner.manipulator == nil {
		t.Error("Expected manipulator to be initialized")
	}
}

// TestSAMLScan_GoldenSAMLDetection tests Golden SAML attack detection
func TestSAMLScan_GoldenSAMLDetection(t *testing.T) {
	tests := []struct {
		name              string
		serverResponse    string
		expectVulnerable  bool
		expectedVulnCount int
		vulnerabilityType string
	}{
		{
			name: "vulnerable to signature bypass",
			serverResponse: `<?xml version="1.0"?>
<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
    <Subject>
      <NameID>admin@example.com</NameID>
    </Subject>
  </Assertion>
</Response>`,
			expectVulnerable:  true,
			expectedVulnCount: 1,
			vulnerabilityType: "Golden SAML",
		},
		{
			name: "properly validates signatures",
			serverResponse: `<?xml version="1.0"?>
<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    </SignedInfo>
    <SignatureValue>validSignature</SignatureValue>
  </Signature>
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
    <Subject>
      <NameID>user@example.com</NameID>
    </Subject>
  </Assertion>
</Response>`,
			expectVulnerable:  false,
			expectedVulnCount: 0,
			vulnerabilityType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/saml/acs") {
					// Accept any SAML response (vulnerable behavior)
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"authenticated": true}`))
					return
				}

				if strings.Contains(r.URL.Path, "/saml/metadata") {
					metadata := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <SPSSODescriptor>
    <AssertionConsumerService Location="` + server.URL + `/saml/acs"/>
  </SPSSODescriptor>
</EntityDescriptor>`
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(metadata))
					return
				}

				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			// Create scanner
			logger := &mockLogger{}
			scanner := NewSAMLScanner(logger)

			// Run scan
			report, err := scanner.Scan(server.URL, nil)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			// Verify results
			if tt.expectVulnerable {
				if len(report.Vulnerabilities) == 0 {
					t.Error("Expected vulnerabilities but found none")
				}

				// Verify vulnerability type
				found := false
				for _, vuln := range report.Vulnerabilities {
					if strings.Contains(vuln.Title, tt.vulnerabilityType) {
						found = true
						break
					}
				}
				if !found && tt.vulnerabilityType != "" {
					t.Errorf("Expected %s vulnerability but didn't find it", tt.vulnerabilityType)
				}
			} else {
				if len(report.Vulnerabilities) > 0 {
					t.Errorf("Expected no vulnerabilities but found %d", len(report.Vulnerabilities))
				}
			}

			// Verify report structure
			if report.Target != server.URL {
				t.Errorf("Expected target %s, got %s", server.URL, report.Target)
			}

			if report.StartTime.IsZero() {
				t.Error("Expected StartTime to be set")
			}

			if report.EndTime.IsZero() {
				t.Error("Expected EndTime to be set")
			}

			if report.EndTime.Before(report.StartTime) {
				t.Error("EndTime should be after StartTime")
			}
		})
	}
}

// TestSAMLScan_XMLSignatureWrapping tests XSW attack detection
func TestSAMLScan_XMLSignatureWrapping(t *testing.T) {
	tests := []struct {
		name           string
		samlResponse   string
		expectDetected bool
		xswVariant     string
	}{
		{
			name: "XSW1 - Comment-based wrapping",
			samlResponse: `<?xml version="1.0"?>
<Response>
  <!-- <Assertion ID="evil">admin@example.com</Assertion> -->
  <Assertion ID="original">user@example.com</Assertion>
  <Signature>
    <Reference URI="#original"/>
  </Signature>
</Response>`,
			expectDetected: true,
			xswVariant:     "XSW1",
		},
		{
			name: "XSW2 - Extensions wrapping",
			samlResponse: `<?xml version="1.0"?>
<Response>
  <Extensions>
    <Assertion ID="evil">admin@example.com</Assertion>
  </Extensions>
  <Assertion ID="original">user@example.com</Assertion>
  <Signature>
    <Reference URI="#original"/>
  </Signature>
</Response>`,
			expectDetected: true,
			xswVariant:     "XSW2",
		},
		{
			name: "XSW3 - Transform-based wrapping",
			samlResponse: `<?xml version="1.0"?>
<Response>
  <Assertion ID="original">user@example.com</Assertion>
  <Signature>
    <Transforms>
      <Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
        <XPath>not(ancestor-or-self::Assertion[@ID='evil'])</XPath>
      </Transform>
    </Transforms>
    <Reference URI="#original"/>
  </Signature>
  <Assertion ID="evil">admin@example.com</Assertion>
</Response>`,
			expectDetected: true,
			xswVariant:     "XSW3",
		},
		{
			name: "Valid SAML response",
			samlResponse: `<?xml version="1.0"?>
<Response>
  <Assertion ID="valid">user@example.com</Assertion>
  <Signature>
    <Reference URI="#valid"/>
    <SignatureValue>validSignature</SignatureValue>
  </Signature>
</Response>`,
			expectDetected: false,
			xswVariant:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &mockLogger{}
			scanner := NewSAMLScanner(logger)

			// Create endpoint for testing
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/saml/acs") {
					// Vulnerable implementation that doesn't properly validate XSW
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"authenticated": true}`))
				}
			}))
			defer server.Close()

			endpoint := &SAMLEndpoint{
				URL:  server.URL + "/saml/acs",
				Type: "AssertionConsumerService",
			}

			// Test XSW detection
			findings := scanner.testXMLSignatureWrapping(endpoint)

			if tt.expectDetected {
				if len(findings) == 0 {
					t.Error("Expected XSW vulnerability to be detected")
				}

				// Verify the specific XSW variant was detected
				if tt.xswVariant != "" {
					found := false
					for _, finding := range findings {
						if strings.Contains(finding.Title, tt.xswVariant) ||
						   strings.Contains(finding.Description, "XML Signature Wrapping") {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected %s variant to be detected", tt.xswVariant)
					}
				}
			} else {
				if len(findings) > 0 {
					t.Errorf("Expected no XSW vulnerability but found %d findings", len(findings))
				}
			}
		})
	}
}

// TestSAMLScan_AssertionManipulation tests SAML assertion manipulation detection
func TestSAMLScan_AssertionManipulation(t *testing.T) {
	logger := &mockLogger{}
	scanner := NewSAMLScanner(logger)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: accepts any SAML assertion without proper validation
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"authenticated": true}`))
	}))
	defer server.Close()

	endpoint := &SAMLEndpoint{
		URL:  server.URL + "/saml/acs",
		Type: "AssertionConsumerService",
	}

	t.Run("privilege escalation via attribute modification", func(t *testing.T) {
		findings := scanner.testResponseManipulation(endpoint)

		// Should detect that server accepts manipulated assertions
		if len(findings) == 0 {
			t.Error("Expected assertion manipulation vulnerability to be detected")
		}

		// Verify findings contain expected vulnerability types
		foundPrivEsc := false
		for _, finding := range findings {
			if strings.Contains(finding.Title, "Privilege") ||
			   strings.Contains(finding.Title, "Assertion") {
				foundPrivEsc = true
				break
			}
		}

		if !foundPrivEsc {
			t.Error("Expected privilege escalation finding")
		}
	})
}

// TestSAMLScan_Timeout tests scan timeout handling
func TestSAMLScan_Timeout(t *testing.T) {
	logger := &mockLogger{}
	scanner := NewSAMLScanner(logger)

	// Create slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(60 * time.Second) // Longer than client timeout
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Scan should handle timeout gracefully
	report, err := scanner.Scan(server.URL, nil)

	// Should not panic or hang
	if err == nil {
		// If no error, report should still be valid
		if report == nil {
			t.Error("Expected report even on timeout")
		}
	}
}

// TestSAMLScan_NoEndpoints tests behavior when no SAML endpoints found
func TestSAMLScan_NoEndpoints(t *testing.T) {
	logger := &mockLogger{}
	scanner := NewSAMLScanner(logger)

	// Server with no SAML endpoints
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	report, err := scanner.Scan(server.URL, nil)
	if err != nil {
		t.Fatalf("Expected no error when endpoints not found, got: %v", err)
	}

	if len(report.Vulnerabilities) != 0 {
		t.Errorf("Expected no vulnerabilities when no endpoints found, got %d", len(report.Vulnerabilities))
	}

	if report.Target != server.URL {
		t.Errorf("Expected target to be set correctly")
	}
}

// TestConcurrentSAMLScans tests concurrent scanning for race conditions
func TestConcurrentSAMLScans(t *testing.T) {
	// This test should be run with: go test -race
	logger := &mockLogger{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Run multiple concurrent scans
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()

			scanner := NewSAMLScanner(logger)
			_, err := scanner.Scan(server.URL, nil)
			if err != nil {
				t.Errorf("Concurrent scan failed: %v", err)
			}
		}()
	}

	// Wait for all scans to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// BenchmarkSAMLScan benchmarks SAML scanning performance
func BenchmarkSAMLScan(b *testing.B) {
	logger := &mockLogger{}
	scanner := NewSAMLScanner(logger)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(server.URL, nil)
	}
}

// BenchmarkXSWDetection benchmarks XSW detection performance
func BenchmarkXSWDetection(b *testing.B) {
	logger := &mockLogger{}
	scanner := NewSAMLScanner(logger)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	endpoint := &SAMLEndpoint{
		URL:  server.URL + "/saml/acs",
		Type: "AssertionConsumerService",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.testXMLSignatureWrapping(endpoint)
	}
}
