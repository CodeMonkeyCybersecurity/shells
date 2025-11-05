// +build go1.18

package oauth2

import (
	"encoding/base64"
	"testing"
)

// FuzzJWTParser tests JWT parsing with fuzz testing
func FuzzJWTParser(f *testing.F) {
	logger := &mockLogger{}
	analyzer := NewJWTAnalyzer(logger)

	// Seed corpus with valid and edge-case JWTs
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.signature")
	f.Add("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0.")
	f.Add("not.a.jwt")
	f.Add("..")
	f.Add("")
	f.Add("a")
	f.Add(string(make([]byte, 10000))) // Large payload

	// Malformed JWTs
	f.Add("eyJhbGciOiJIUzI1NiJ9.malformed")
	f.Add("header.payload")
	f.Add("......")

	f.Fuzz(func(t *testing.T, token string) {
		// Parser should not panic on any input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("JWT parser panicked on input: %v", r)
			}
		}()

		// Try to analyze the token
		_ = analyzer.AnalyzeToken(token)
	})
}

// FuzzJWTHeader tests JWT header parsing
func FuzzJWTHeader(f *testing.F) {
	logger := &mockLogger{}
	analyzer := NewJWTAnalyzer(logger)

	// Seed with various header structures
	f.Add([]byte(`{"alg":"HS256","typ":"JWT"}`))
	f.Add([]byte(`{"alg":"none"}`))
	f.Add([]byte(`{"alg":"RS256","kid":"test"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"alg":null}`))
	f.Add([]byte(`malformed json`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, header []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Header parsing panicked: %v", r)
			}
		}()

		// Create JWT with fuzzed header
		headerB64 := base64.RawURLEncoding.EncodeToString(header)
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
		token := headerB64 + "." + payload + ".signature"

		_ = analyzer.AnalyzeToken(token)
	})
}

// FuzzJWTPayload tests JWT payload parsing
func FuzzJWTPayload(f *testing.F) {
	logger := &mockLogger{}
	analyzer := NewJWTAnalyzer(logger)

	// Seed with various payload structures
	f.Add([]byte(`{"sub":"test","admin":true}`))
	f.Add([]byte(`{"exp":1234567890}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"nested":{"deep":{"value":"test"}}}`))
	f.Add([]byte(`malformed`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, payload []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Payload parsing panicked: %v", r)
			}
		}()

		// Create JWT with fuzzed payload
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
		payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
		token := header + "." + payloadB64 + ".signature"

		_ = analyzer.AnalyzeToken(token)
	})
}

// FuzzJWTAlgorithmConfusion tests algorithm confusion with various inputs
func FuzzJWTAlgorithmConfusion(f *testing.F) {
	logger := &mockLogger{}
	analyzer := NewJWTAnalyzer(logger)

	// Seed with algorithm values
	f.Add("none")
	f.Add("None")
	f.Add("NONE")
	f.Add("HS256")
	f.Add("RS256")
	f.Add("ES256")
	f.Add("PS256")
	f.Add("")
	f.Add("invalid")
	f.Add(string(make([]byte, 1000)))

	f.Fuzz(func(t *testing.T, alg string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Algorithm confusion test panicked: %v", r)
			}
		}()

		// Create JWT with fuzzed algorithm
		header := `{"alg":"` + alg + `","typ":"JWT"}`
		headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
		token := headerB64 + "." + payload + "."

		vulns := analyzer.AnalyzeToken(token)

		// Should detect 'none' algorithm variants
		if alg == "none" || alg == "None" || alg == "NONE" {
			if len(vulns) == 0 {
				t.Error("Expected 'none' algorithm to be detected as vulnerable")
			}
		}
	})
}
