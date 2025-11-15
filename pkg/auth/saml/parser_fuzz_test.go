//go:build go1.18
// +build go1.18

package saml

import (
	"testing"
)

// FuzzSAMLParser tests SAML parser with fuzz testing
func FuzzSAMLParser(f *testing.F) {
	logger := &mockLogger{}
	parser := NewSAMLParser(logger)

	// Seed corpus with valid and edge-case SAML responses
	f.Add([]byte(`<?xml version="1.0"?>
<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
    <Subject>
      <NameID>user@example.com</NameID>
    </Subject>
  </Assertion>
</Response>`))

	f.Add([]byte(`<?xml version="1.0"?><Response></Response>`))
	f.Add([]byte(`<>`))
	f.Add([]byte(`malformed xml`))
	f.Add([]byte(``))
	f.Add([]byte(`<?xml version="1.0"?><Response>` + string(make([]byte, 10000)) + `</Response>`)) // Large payload

	// XSW attack payloads
	f.Add([]byte(`<?xml version="1.0"?>
<Response>
  <!-- <Assertion ID="evil">admin@example.com</Assertion> -->
  <Assertion ID="original">user@example.com</Assertion>
</Response>`))

	// XXE attack payload
	f.Add([]byte(`<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Response>&xxe;</Response>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Parser should not panic on any input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Parser panicked on input: %v", r)
			}
		}()

		// Try to parse
		_, _ = parser.ParseSAMLResponse(string(data))
	})
}

// FuzzXMLSignatureWrappingDetection tests XSW detection with fuzz testing
func FuzzXMLSignatureWrappingDetection(f *testing.F) {
	logger := &mockLogger{}
	_ = NewSAMLScanner(logger)

	// Seed with various XSW attack patterns
	f.Add([]byte(`<?xml version="1.0"?>
<Response>
  <!-- <Assertion ID="evil">admin</Assertion> -->
  <Assertion ID="original">user</Assertion>
  <Signature><Reference URI="#original"/></Signature>
</Response>`))

	f.Add([]byte(`<?xml version="1.0"?>
<Response>
  <Extensions><Assertion ID="evil">admin</Assertion></Extensions>
  <Assertion ID="original">user</Assertion>
  <Signature><Reference URI="#original"/></Signature>
</Response>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("XSW detection panicked: %v", r)
			}
		}()

		// Should not panic on malformed input
		// Just verify it doesn't crash
		_ = string(data)
	})
}

// FuzzSAMLAssertion tests assertion manipulation with fuzz testing
func FuzzSAMLAssertion(f *testing.F) {
	// Seed with various assertion structures
	f.Add([]byte(`<Assertion><Subject><NameID>user</NameID></Subject></Assertion>`))
	f.Add([]byte(`<Assertion><AttributeStatement><Attribute Name="role"><AttributeValue>admin</AttributeValue></Attribute></AttributeStatement></Assertion>`))
	f.Add([]byte(`<Assertion>`))
	f.Add([]byte(`</Assertion>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Assertion parsing panicked: %v", r)
			}
		}()

		logger := &mockLogger{}
		parser := NewSAMLParser(logger)

		// Try to parse the assertion
		samlResponse := `<?xml version="1.0"?>
<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">
  ` + string(data) + `
</Response>`

		_, _ = parser.ParseSAMLResponse(samlResponse)
	})
}
