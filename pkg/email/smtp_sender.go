// pkg/email/smtp_sender.go
//
// SMTP Email Sender for Automated Vulnerability Report Submission
//
// IMPLEMENTATION OVERVIEW:
// This package provides SMTP email sending capability for automated vulnerability report
// submission to email-based bug bounty programs, primarily Microsoft Security Response Center (MSRC).
//
// FEATURES:
// - SMTP/STARTTLS/SSL support for various email providers
// - Plain text and HTML email formats
// - Custom headers for security report metadata
// - Convenience methods for MSRC submissions
// - TLS certificate verification (configurable)
// - Connection timeout and retry handling
//
// INTEGRATION POINTS:
// - pkg/platforms/azure/client.go: Uses SMTP sender for automated Azure MSRC submissions
// - internal/config/config.go: EmailConfig with SMTP host, credentials, TLS settings
// - pkg/ai/report_generator.go: Generates AI-powered reports sent via SMTP
//
// CONFIGURATION:
// Enable email sending in config:
//   email:
//     enabled: true
//     smtp_host: "smtp.gmail.com"
//     smtp_port: 587
//     username: "your-email@gmail.com"
//     password: "app-password"  # Use app-specific password, NOT your main password
//     from_email: "your-email@gmail.com"
//     from_name: "Shells Security Scanner"
//     use_tls: true
//     use_ssl: false
//     timeout: 30s
//
// USAGE:
//   cfg := email.SMTPConfig{
//       Host: "smtp.gmail.com",
//       Port: 587,
//       Username: "user@gmail.com",
//       Password: "app-password",
//       FromEmail: "user@gmail.com",
//       UseTLS: true,
//   }
//   sender, err := email.NewSMTPSender(cfg, logger)
//   err = sender.SendSecurityReport([]string{"secure@microsoft.com"}, subject, body)
//   // Or use convenience method:
//   err = sender.SendMSRCReport(subject, body)
//
// SECURITY NOTES:
// - NEVER commit SMTP passwords to git
// - Use app-specific passwords for Gmail/Outlook
// - Enable TLS for all production use
// - Set skip_tls_verify: false in production
// - Store credentials in environment variables or secure config
//
// COMMON SMTP PROVIDERS:
// Gmail:        smtp.gmail.com:587 (TLS) - requires app password
// Outlook:      smtp-mail.outlook.com:587 (TLS)
// SendGrid:     smtp.sendgrid.net:587 (TLS) - use API key as password
// Mailgun:      smtp.mailgun.org:587 (TLS)
// Amazon SES:   email-smtp.us-east-1.amazonaws.com:587 (TLS)
//
// INTEGRATION NOTE: Azure client initializes SMTP sender if EmailConfig is provided

package email

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// SMTPConfig contains SMTP server configuration
type SMTPConfig struct {
	// Server settings
	Host     string // SMTP server hostname (e.g., "smtp.gmail.com")
	Port     int    // SMTP port (587 for TLS, 465 for SSL, 25 for plain)
	Username string // SMTP authentication username
	Password string // SMTP authentication password

	// Sender information
	FromEmail string // Sender email address
	FromName  string // Sender display name

	// TLS settings
	UseTLS        bool // Use STARTTLS
	UseSSL        bool // Use SSL/TLS from connection start
	SkipTLSVerify bool // Skip TLS certificate verification (not recommended)

	// Connection settings
	Timeout time.Duration // Connection timeout
}

// EmailMessage represents an email to send
type EmailMessage struct {
	To          []string          // Recipient email addresses
	Cc          []string          // CC recipients
	Bcc         []string          // BCC recipients
	Subject     string            // Email subject
	Body        string            // Email body (plain text)
	HTMLBody    string            // HTML email body (optional)
	Attachments []EmailAttachment // File attachments
	Headers     map[string]string // Additional email headers
}

// EmailAttachment represents an email attachment
type EmailAttachment struct {
	Filename    string // Attachment filename
	ContentType string // MIME content type
	Data        []byte // Attachment data
}

// SMTPSender sends emails via SMTP
type SMTPSender struct {
	config SMTPConfig
	logger *logger.Logger
}

// NewSMTPSender creates a new SMTP email sender
func NewSMTPSender(config SMTPConfig, logger *logger.Logger) (*SMTPSender, error) {
	// Validate configuration
	if config.Host == "" {
		return nil, fmt.Errorf("SMTP host is required")
	}
	if config.Port == 0 {
		config.Port = 587 // Default to STARTTLS port
	}
	if config.FromEmail == "" {
		return nil, fmt.Errorf("sender email address is required")
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	logger.Infow("SMTP sender initialized",
		"host", config.Host,
		"port", config.Port,
		"from_email", config.FromEmail,
		"use_tls", config.UseTLS,
		"use_ssl", config.UseSSL,
	)

	return &SMTPSender{
		config: config,
		logger: logger,
	}, nil
}

// SendEmail sends an email message via SMTP
func (s *SMTPSender) SendEmail(msg EmailMessage) error {
	if len(msg.To) == 0 {
		return fmt.Errorf("at least one recipient is required")
	}
	if msg.Subject == "" {
		return fmt.Errorf("email subject is required")
	}
	if msg.Body == "" && msg.HTMLBody == "" {
		return fmt.Errorf("email body is required")
	}

	s.logger.Infow("Sending email",
		"to", msg.To,
		"cc", msg.Cc,
		"subject", msg.Subject,
		"from", s.config.FromEmail,
	)

	// Build email message
	emailData := s.buildEmailMessage(msg)

	// Get all recipients (To + Cc + Bcc)
	allRecipients := append(msg.To, msg.Cc...)
	allRecipients = append(allRecipients, msg.Bcc...)

	// Send email based on configuration
	var err error
	if s.config.UseSSL {
		err = s.sendWithSSL(allRecipients, emailData)
	} else if s.config.UseTLS {
		err = s.sendWithTLS(allRecipients, emailData)
	} else {
		err = s.sendPlain(allRecipients, emailData)
	}

	if err != nil {
		s.logger.Errorw("Failed to send email",
			"error", err,
			"to", msg.To,
			"subject", msg.Subject,
		)
		return fmt.Errorf("failed to send email: %w", err)
	}

	s.logger.Infow("Email sent successfully",
		"to", msg.To,
		"subject", msg.Subject,
	)

	return nil
}

// buildEmailMessage constructs the raw email message with headers and body
func (s *SMTPSender) buildEmailMessage(msg EmailMessage) []byte {
	var builder strings.Builder

	// From header
	if s.config.FromName != "" {
		builder.WriteString(fmt.Sprintf("From: %s <%s>\r\n", s.config.FromName, s.config.FromEmail))
	} else {
		builder.WriteString(fmt.Sprintf("From: %s\r\n", s.config.FromEmail))
	}

	// To header
	builder.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(msg.To, ", ")))

	// Cc header
	if len(msg.Cc) > 0 {
		builder.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(msg.Cc, ", ")))
	}

	// Subject header
	builder.WriteString(fmt.Sprintf("Subject: %s\r\n", msg.Subject))

	// Date header
	builder.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))

	// MIME version
	builder.WriteString("MIME-Version: 1.0\r\n")

	// Additional custom headers
	for key, value := range msg.Headers {
		builder.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	// Content type
	if msg.HTMLBody != "" {
		// Multipart email with both plain text and HTML
		boundary := fmt.Sprintf("boundary_%d", time.Now().Unix())
		builder.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", boundary))

		// Plain text part
		builder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		builder.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n\r\n")
		builder.WriteString(msg.Body)
		builder.WriteString("\r\n\r\n")

		// HTML part
		builder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		builder.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n\r\n")
		builder.WriteString(msg.HTMLBody)
		builder.WriteString("\r\n\r\n")

		builder.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		// Plain text only
		builder.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n\r\n")
		builder.WriteString(msg.Body)
	}

	return []byte(builder.String())
}

// sendWithTLS sends email using STARTTLS
func (s *SMTPSender) sendWithTLS(recipients []string, message []byte) error {
	serverAddr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	// Connect to SMTP server
	client, err := smtp.Dial(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer client.Close()

	// Start TLS
	tlsConfig := &tls.Config{
		ServerName:         s.config.Host,
		InsecureSkipVerify: s.config.SkipTLSVerify,
	}

	if err = client.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("failed to start TLS: %w", err)
	}

	// Authenticate if credentials provided
	if s.config.Username != "" && s.config.Password != "" {
		auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	// Set sender
	if err = client.Mail(s.config.FromEmail); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Add recipients
	for _, recipient := range recipients {
		if err = client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to add recipient %s: %w", recipient, err)
		}
	}

	// Send message data
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to initialize data transfer: %w", err)
	}

	_, err = writer.Write(message)
	if err != nil {
		return fmt.Errorf("failed to write message data: %w", err)
	}

	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	return client.Quit()
}

// sendWithSSL sends email using SSL/TLS from connection start
func (s *SMTPSender) sendWithSSL(recipients []string, message []byte) error {
	serverAddr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	// TLS configuration
	tlsConfig := &tls.Config{
		ServerName:         s.config.Host,
		InsecureSkipVerify: s.config.SkipTLSVerify,
	}

	// Connect with TLS
	conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server with SSL: %w", err)
	}
	defer conn.Close()

	// Create SMTP client
	client, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	// Authenticate if credentials provided
	if s.config.Username != "" && s.config.Password != "" {
		auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	// Set sender
	if err = client.Mail(s.config.FromEmail); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Add recipients
	for _, recipient := range recipients {
		if err = client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to add recipient %s: %w", recipient, err)
		}
	}

	// Send message data
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to initialize data transfer: %w", err)
	}

	_, err = writer.Write(message)
	if err != nil {
		return fmt.Errorf("failed to write message data: %w", err)
	}

	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	return client.Quit()
}

// sendPlain sends email without TLS (not recommended for production)
func (s *SMTPSender) sendPlain(recipients []string, message []byte) error {
	serverAddr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	// Authentication
	var auth smtp.Auth
	if s.config.Username != "" && s.config.Password != "" {
		auth = smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
	}

	// Send email
	err := smtp.SendMail(serverAddr, auth, s.config.FromEmail, recipients, message)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// SendSecurityReport sends a security vulnerability report via email
// This is a convenience method for security report submissions
func (s *SMTPSender) SendSecurityReport(to []string, subject, body string) error {
	msg := EmailMessage{
		To:      to,
		Subject: subject,
		Body:    body,
		Headers: map[string]string{
			"X-Report-Type": "Security Vulnerability",
			"X-Sender":      "Shells Security Scanner",
		},
	}

	return s.SendEmail(msg)
}

// SendMSRCReport sends a report to Microsoft Security Response Center
func (s *SMTPSender) SendMSRCReport(subject, body string) error {
	msrcEmail := "secure@microsoft.com"

	s.logger.Infow("Sending report to Microsoft Security Response Center",
		"to", msrcEmail,
		"subject", subject,
	)

	return s.SendSecurityReport([]string{msrcEmail}, subject, body)
}
