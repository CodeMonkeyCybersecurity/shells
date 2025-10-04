package validation

import (
	"testing"
)

func TestValidateTarget_Localhost(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{"localhost", "localhost"},
		{"127.0.0.1", "127.0.0.1"},
		{"http://localhost", "http://localhost"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"::1", "::1"},
		{"0.0.0.0", "0.0.0.0"},
		{"local domain", "myserver.local"},
		{"internal domain", "server.internal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateTarget(tt.target)
			if result.Valid {
				t.Errorf("ValidateTarget(%q) should reject localhost/private targets", tt.target)
			}
			if result.Error == nil {
				t.Errorf("ValidateTarget(%q) should return error for private targets", tt.target)
			}
		})
	}
}

func TestValidateTarget_PrivateIPs(t *testing.T) {
	privateIPs := []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"http://10.0.0.1",
		"https://172.16.5.10:8080",
		"http://192.168.0.1/api",
	}

	for _, ip := range privateIPs {
		t.Run(ip, func(t *testing.T) {
			result := ValidateTarget(ip)
			if result.Valid {
				t.Errorf("ValidateTarget(%q) should reject private IP addresses", ip)
			}
		})
	}
}

func TestValidateTarget_ValidDomains(t *testing.T) {
	tests := []struct {
		target       string
		expectedType string
	}{
		{"example.com", "domain"},
		{"api.example.com", "domain"},
		{"test.sub.domain.com", "domain"},
		{"example-site.co.uk", "domain"},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			result := ValidateTarget(tt.target)
			if !result.Valid {
				t.Errorf("ValidateTarget(%q) should accept valid domain, got error: %v", tt.target, result.Error)
			}
			if result.TargetType != tt.expectedType {
				t.Errorf("ValidateTarget(%q) type = %v, want %v", tt.target, result.TargetType, tt.expectedType)
			}
			if result.NormalizedURL != "https://"+tt.target {
				t.Errorf("ValidateTarget(%q) normalized = %v, want %v", tt.target, result.NormalizedURL, "https://"+tt.target)
			}
		})
	}
}

func TestValidateTarget_ValidURLs(t *testing.T) {
	tests := []struct {
		target string
	}{
		{"https://example.com"},
		{"http://api.example.com"},
		{"https://example.com:8443"},
		{"https://example.com/api/v1"},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			result := ValidateTarget(tt.target)
			if !result.Valid {
				t.Errorf("ValidateTarget(%q) should accept valid URL, got error: %v", tt.target, result.Error)
			}
			if result.TargetType != "url" {
				t.Errorf("ValidateTarget(%q) type = %v, want url", tt.target, result.TargetType)
			}
			if result.NormalizedURL != tt.target {
				t.Errorf("ValidateTarget(%q) normalized = %v, want %v", tt.target, result.NormalizedURL, tt.target)
			}
		})
	}
}

func TestValidateTarget_ValidIPs(t *testing.T) {
	publicIPs := []struct {
		ip string
	}{
		{"1.1.1.1"},
		{"8.8.8.8"},
		{"142.250.185.46"}, // google.com
	}

	for _, tt := range publicIPs {
		t.Run(tt.ip, func(t *testing.T) {
			result := ValidateTarget(tt.ip)
			if !result.Valid {
				t.Errorf("ValidateTarget(%q) should accept public IP, got error: %v", tt.ip, result.Error)
			}
			if result.TargetType != "ip" {
				t.Errorf("ValidateTarget(%q) type = %v, want ip", tt.ip, result.TargetType)
			}
		})
	}
}

func TestValidateTarget_Email(t *testing.T) {
	tests := []struct {
		email          string
		expectedDomain string
	}{
		{"admin@example.com", "example.com"},
		{"test.user@subdomain.example.com", "subdomain.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			result := ValidateTarget(tt.email)
			if !result.Valid {
				t.Errorf("ValidateTarget(%q) should accept email, got error: %v", tt.email, result.Error)
			}
			if result.TargetType != "email" {
				t.Errorf("ValidateTarget(%q) type = %v, want email", tt.email, result.TargetType)
			}
			expectedNormalized := "https://" + tt.expectedDomain
			if result.NormalizedURL != expectedNormalized {
				t.Errorf("ValidateTarget(%q) normalized = %v, want %v", tt.email, result.NormalizedURL, expectedNormalized)
			}
			if len(result.Warnings) == 0 {
				t.Errorf("ValidateTarget(%q) should have warning about email->domain conversion", tt.email)
			}
		})
	}
}

func TestValidateTarget_IPRange(t *testing.T) {
	// Private IP ranges should be rejected
	privateRanges := []string{
		"192.168.1.0/24",
		"10.0.0.0/16",
		"172.16.0.0/12",
	}

	for _, ipRange := range privateRanges {
		t.Run(ipRange+"_private", func(t *testing.T) {
			result := ValidateTarget(ipRange)
			if result.Valid {
				t.Errorf("ValidateTarget(%q) should reject private IP range", ipRange)
			}
			if result.Error == nil {
				t.Errorf("ValidateTarget(%q) should return error for private IP range", ipRange)
			}
		})
	}

	// Public IP ranges should be accepted with warnings
	publicRanges := []string{
		"8.8.8.0/24", // Google DNS range
		"1.1.1.0/24", // Cloudflare range
	}

	for _, ipRange := range publicRanges {
		t.Run(ipRange+"_public", func(t *testing.T) {
			result := ValidateTarget(ipRange)
			if !result.Valid {
				t.Errorf("ValidateTarget(%q) should accept public IP range, got error: %v", ipRange, result.Error)
			}
			if result.TargetType != "ip_range" {
				t.Errorf("ValidateTarget(%q) type = %v, want ip_range", ipRange, result.TargetType)
			}
			if len(result.Warnings) == 0 {
				t.Errorf("ValidateTarget(%q) should have warning about IP range scanning", ipRange)
			}
		})
	}
}

func TestValidateTarget_CompanyName(t *testing.T) {
	tests := []string{
		"Acme Corporation",
		"Test Company Inc",
		"MyStartup",
	}

	for _, company := range tests {
		t.Run(company, func(t *testing.T) {
			result := ValidateTarget(company)
			if !result.Valid {
				t.Errorf("ValidateTarget(%q) should accept company name, got error: %v", company, result.Error)
			}
			if result.TargetType != "company" {
				t.Errorf("ValidateTarget(%q) type = %v, want company", company, result.TargetType)
			}
			if len(result.Warnings) == 0 {
				t.Errorf("ValidateTarget(%q) should have warning about company name discovery", company)
			}
		})
	}
}

func TestValidateTarget_Empty(t *testing.T) {
	result := ValidateTarget("")
	if result.Valid {
		t.Error("ValidateTarget(\"\") should reject empty string")
	}
	if result.Error == nil {
		t.Error("ValidateTarget(\"\") should return error for empty string")
	}
}

func TestValidateTarget_Invalid(t *testing.T) {
	invalid := []string{
		"://invalid",
		"not a valid anything!@#",
		"ht!tp://bad.com",
	}

	for _, target := range invalid {
		t.Run(target, func(t *testing.T) {
			result := ValidateTarget(target)
			if result.Valid {
				t.Errorf("ValidateTarget(%q) should reject invalid input", target)
			}
		})
	}
}
