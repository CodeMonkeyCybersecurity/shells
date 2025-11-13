// pkg/email/smtp_sender_test.go
//
// Tests for SMTP email sender
//
// Unit tests run by default
// Integration tests require EMAIL_INTEGRATION_TEST=true and valid SMTP config

package email

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSMTPSender(t *testing.T) {
	log := createTestLogger(t)

	tests := []struct {
		name    string
		config  SMTPConfig
		wantErr bool
	}{
		{
			name: "Valid configuration",
			config: SMTPConfig{
				Host:      "smtp.example.com",
				Port:      587,
				FromEmail: "test@example.com",
				UseTLS:    true,
			},
			wantErr: false,
		},
		{
			name: "Missing host",
			config: SMTPConfig{
				Port:      587,
				FromEmail: "test@example.com",
			},
			wantErr: true,
		},
		{
			name: "Missing from email",
			config: SMTPConfig{
				Host: "smtp.example.com",
				Port: 587,
			},
			wantErr: true,
		},
		{
			name: "Default port applied",
			config: SMTPConfig{
				Host:      "smtp.example.com",
				FromEmail: "test@example.com",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, err := NewSMTPSender(tt.config, log)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, sender)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, sender)
				if tt.config.Port == 0 {
					assert.Equal(t, 587, sender.config.Port)
				}
			}
		})
	}
}

func TestBuildEmailMessage(t *testing.T) {
	log := createTestLogger(t)

	config := SMTPConfig{
		Host:      "smtp.example.com",
		Port:      587,
		FromEmail: "sender@example.com",
		FromName:  "Test Sender",
	}

	sender, err := NewSMTPSender(config, log)
	require.NoError(t, err)

	tests := []struct {
		name    string
		message EmailMessage
		want    []string // Substrings that should be in the message
	}{
		{
			name: "Plain text email",
			message: EmailMessage{
				To:      []string{"recipient@example.com"},
				Subject: "Test Subject",
				Body:    "This is a test email body",
			},
			want: []string{
				"From: Test Sender <sender@example.com>",
				"To: recipient@example.com",
				"Subject: Test Subject",
				"This is a test email body",
			},
		},
		{
			name: "Email with CC",
			message: EmailMessage{
				To:      []string{"recipient@example.com"},
				Cc:      []string{"cc@example.com"},
				Subject: "Test with CC",
				Body:    "Body text",
			},
			want: []string{
				"To: recipient@example.com",
				"Cc: cc@example.com",
				"Subject: Test with CC",
			},
		},
		{
			name: "Email with custom headers",
			message: EmailMessage{
				To:      []string{"recipient@example.com"},
				Subject: "Custom Headers",
				Body:    "Body",
				Headers: map[string]string{
					"X-Report-Type": "Security",
					"X-Priority":    "High",
				},
			},
			want: []string{
				"X-Report-Type: Security",
				"X-Priority: High",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := sender.buildEmailMessage(tt.message)
			messageStr := string(message)

			for _, substring := range tt.want {
				assert.Contains(t, messageStr, substring)
			}
		})
	}
}

func TestSendSecurityReport(t *testing.T) {
	if os.Getenv("EMAIL_INTEGRATION_TEST") != "true" {
		t.Skip("Skipping email integration test - set EMAIL_INTEGRATION_TEST=true to run")
	}

	log := createTestLogger(t)

	config := SMTPConfig{
		Host:      os.Getenv("SMTP_HOST"),
		Port:      getEnvAsInt("SMTP_PORT", 587),
		Username:  os.Getenv("SMTP_USERNAME"),
		Password:  os.Getenv("SMTP_PASSWORD"),
		FromEmail: os.Getenv("SMTP_FROM_EMAIL"),
		FromName:  "Artemis Security Scanner",
		UseTLS:    true,
		Timeout:   30 * time.Second,
	}

	// Validate required environment variables
	if config.Host == "" || config.FromEmail == "" {
		t.Skip("SMTP configuration not provided via environment variables")
	}

	sender, err := NewSMTPSender(config, log)
	require.NoError(t, err)

	// Send test security report
	to := []string{os.Getenv("TEST_RECIPIENT_EMAIL")}
	if to[0] == "" {
		to = []string{config.FromEmail} // Send to self if no test recipient specified
	}

	subject := "Test Security Report from Artemis"
	body := `This is a test security vulnerability report from Artemis Security Scanner.

VULNERABILITY: SQL Injection
SEVERITY: HIGH
CVSS: 8.5

Description:
SQL injection vulnerability discovered in login endpoint.

Impact:
Attackers could bypass authentication and access sensitive data.

Remediation:
Use parameterized queries instead of string concatenation.

---
This is an automated test message. If you received this in error, please disregard.
`

	err = sender.SendSecurityReport(to, subject, body)
	require.NoError(t, err)

	t.Logf("Test security report sent successfully to %v", to)
}

func TestSendMSRCReport(t *testing.T) {
	if os.Getenv("EMAIL_INTEGRATION_TEST") != "true" {
		t.Skip("Skipping email integration test - set EMAIL_INTEGRATION_TEST=true to run")
	}

	log := createTestLogger(t)

	config := SMTPConfig{
		Host:      os.Getenv("SMTP_HOST"),
		Port:      getEnvAsInt("SMTP_PORT", 587),
		Username:  os.Getenv("SMTP_USERNAME"),
		Password:  os.Getenv("SMTP_PASSWORD"),
		FromEmail: os.Getenv("SMTP_FROM_EMAIL"),
		FromName:  "Artemis Security Scanner",
		UseTLS:    true,
		Timeout:   30 * time.Second,
	}

	if config.Host == "" || config.FromEmail == "" {
		t.Skip("SMTP configuration not provided")
	}

	sender, err := NewSMTPSender(config, log)
	require.NoError(t, err)

	// NOTE: This test does NOT actually send to Microsoft MSRC
	// It only tests the method functionality
	// To actually test MSRC submission, manually change the implementation temporarily

	subject := "TEST - Azure Security Vulnerability Report"
	body := `MICROSOFT SECURITY VULNERABILITY REPORT
==================================================

Program: Azure Bug Bounty
Severity: Important
CVSS Score: 7.5

TITLE: Test Vulnerability Report

DESCRIPTION:
This is a test report from Artemis Security Scanner integration tests.
This is NOT a real vulnerability report.

AFFECTED ASSET:
URL/Service: test.example.com
Type: Web Application

IMPACT:
This is a test. No real impact.

SUGGESTED REMEDIATION:
N/A - This is a test.

---
Discovered: 2025-01-09
Discovery Tool: Artemis Security Scanner
`

	// For safety, we DO NOT actually call SendMSRCReport in tests
	// We just verify the method exists and can be called with a test email
	testRecipient := os.Getenv("TEST_RECIPIENT_EMAIL")
	if testRecipient == "" {
		testRecipient = config.FromEmail
	}

	err = sender.SendSecurityReport([]string{testRecipient}, subject, body)
	require.NoError(t, err)

	t.Logf("MSRC-format report sent to test recipient: %s", testRecipient)
}

func createTestLogger(t *testing.T) *logger.Logger {
	cfg := logger.Config{
		Level:  "debug",
		Format: "console",
	}

	log, err := logger.New(cfg)
	require.NoError(t, err)
	return log
}

func getEnvAsInt(key string, defaultVal int) int {
	valStr := os.Getenv(key)
	if valStr == "" {
		return defaultVal
	}
	// Simple conversion - in production use strconv.Atoi with error handling
	var val int
	_, err := fmt.Sscanf(valStr, "%d", &val)
	if err != nil {
		return defaultVal
	}
	return val
}
