package vulntest

import (
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// SMTPClient handles SMTP vulnerability testing
type SMTPClient struct {
	timeout time.Duration
}

// NewSMTPClient creates a new SMTP testing client
func NewSMTPClient() *SMTPClient {
	return &SMTPClient{
		timeout: 5 * time.Second, // Faster timeout for bug bounty
	}
}

// TestOpenRelay checks if the SMTP server is an open relay
func (s *SMTPClient) TestOpenRelay(host string, port int) (bool, string, error) {
	// Use net.JoinHostPort for proper IPv6 support
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// Try to connect
	conn, err := net.DialTimeout("tcp", addr, s.timeout)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	// Set deadline for all operations
	conn.SetDeadline(time.Now().Add(s.timeout))

	// Read banner
	banner := make([]byte, 1024)
	n, err := conn.Read(banner)
	if err != nil {
		return false, "", err
	}

	// Send EHLO
	_, err = conn.Write([]byte("EHLO testdomain.com\r\n"))
	if err != nil {
		return false, "", err
	}

	// Read EHLO response
	response := make([]byte, 1024)
	n, err = conn.Read(response)
	if err != nil {
		return false, "", err
	}

	// Try to send mail without auth
	// MAIL FROM with external domain
	_, err = conn.Write([]byte("MAIL FROM:<test@external-domain.com>\r\n"))
	if err != nil {
		return false, "", err
	}

	// Read response
	n, err = conn.Read(response)
	if err != nil {
		return false, "", err
	}

	mailFromResp := string(response[:n])
	if !strings.HasPrefix(mailFromResp, "250") {
		return false, "MAIL FROM rejected", nil
	}

	// RCPT TO with another external domain (classic open relay test)
	_, err = conn.Write([]byte("RCPT TO:<victim@another-external.com>\r\n"))
	if err != nil {
		return false, "", err
	}

	// Read response
	n, err = conn.Read(response)
	if err != nil {
		return false, "", err
	}

	rcptToResp := string(response[:n])

	// If we get 250 OK, it's likely an open relay
	if strings.HasPrefix(rcptToResp, "250") {
		evidence := fmt.Sprintf("SMTP server accepted relay from test@external-domain.com to victim@another-external.com without authentication. Response: %s", rcptToResp)

		// Send QUIT to be polite
		conn.Write([]byte("QUIT\r\n"))

		return true, evidence, nil
	}

	return false, "Relay not allowed", nil
}

// TestSMTPAuth tests for authentication bypass or weak auth
func (s *SMTPClient) TestSMTPAuth(host string, port int, username, password string) (bool, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	// Try standard SMTP auth
	auth := smtp.PlainAuth("", username, password, host)

	// Just try to authenticate, don't send mail
	client, err := smtp.Dial(addr)
	if err != nil {
		return false, err
	}
	defer client.Close()

	// Try EHLO first
	if err := client.Hello("testdomain.com"); err != nil {
		return false, err
	}

	// Try AUTH
	if err := client.Auth(auth); err != nil {
		// Auth failed
		return false, nil
	}

	// Auth succeeded
	client.Quit()
	return true, nil
}

// CheckSMTPBanner gets the SMTP banner for fingerprinting
func (s *SMTPClient) CheckSMTPBanner(host string, port int) (string, error) {
	// Use net.JoinHostPort for proper IPv6 support
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", addr, s.timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Read banner
	banner := make([]byte, 1024)
	n, err := conn.Read(banner)
	if err != nil {
		return "", err
	}

	return string(banner[:n]), nil
}
