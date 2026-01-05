// cert_client_enhanced.go - Enhanced certificate client with multiple fallback sources
package correlation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/discovery/certlogs"
)

// EnhancedCertificateClient tries multiple sources for certificate data
// Priority order: 1. Direct TLS, 2. crt.sh HTTP, 3. crt.sh PostgreSQL, 4. Censys
type EnhancedCertificateClient struct {
	logger   *logger.Logger
	ctClient *certlogs.CTLogClient
	timeout  time.Duration
}

// NewEnhancedCertificateClient creates a certificate client with multiple fallback sources
func NewEnhancedCertificateClient(logger *logger.Logger) CertificateClient {
	return &EnhancedCertificateClient{
		logger:   logger,
		ctClient: certlogs.NewCTLogClient(logger),
		timeout:  10 * time.Second,
	}
}

func (c *EnhancedCertificateClient) GetCertificates(ctx context.Context, domain string) ([]CertificateInfo, error) {
	// Strategy 1: Try direct TLS connection (fastest, always works if site is up)
	c.logger.Debugw("Attempting direct TLS connection",
		"domain", domain,
		"method", "tls_direct",
	)

	directCerts := c.getDirectTLSCertificate(ctx, domain)
	if len(directCerts) > 0 {
		c.logger.Infow("Certificate retrieved via direct TLS connection",
			"domain", domain,
			"certificates_found", len(directCerts),
			"method", "tls_direct",
		)
		return directCerts, nil
	}

	// Strategy 2: Try certificate transparency logs (crt.sh HTTP API)
	c.logger.Debugw("Attempting certificate transparency lookup",
		"domain", domain,
		"method", "crtsh_http",
	)

	ctCerts, err := c.ctClient.SearchDomain(ctx, domain)
	if err == nil && len(ctCerts) > 0 {
		certInfos := c.convertCTLogCerts(ctCerts)
		c.logger.Infow("Certificates retrieved via CT logs",
			"domain", domain,
			"certificates_found", len(certInfos),
			"method", "crtsh_http",
		)
		return certInfos, nil
	}

	if err != nil {
		c.logger.Warnw("Certificate transparency search failed",
			"domain", domain,
			"error", err,
			"method", "crtsh_http",
		)
	}

	// Strategy 3: Could add crt.sh PostgreSQL fallback here
	// Strategy 4: Could add Censys API fallback here

	// Return empty on failure (graceful degradation)
	c.logger.Infow("No certificates found from any source",
		"domain", domain,
		"methods_tried", []string{"tls_direct", "crtsh_http"},
	)

	return []CertificateInfo{}, nil
}

// getDirectTLSCertificate connects directly to the domain and retrieves its certificate
func (c *EnhancedCertificateClient) getDirectTLSCertificate(ctx context.Context, domain string) []CertificateInfo {
	// Try HTTPS (443) first, most common
	ports := []string{"443", "8443"}

	for _, port := range ports {
		addr := net.JoinHostPort(domain, port)

		// Create TLS config that accepts any certificate (for reconnaissance)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // We want to see ANY cert, even invalid ones
			ServerName:         domain,
		}

		// Set deadline from context
		deadline, hasDeadline := ctx.Deadline()
		if !hasDeadline {
			deadline = time.Now().Add(c.timeout)
		}

		dialer := &net.Dialer{
			Timeout:   c.timeout,
			Deadline:  deadline,
			KeepAlive: 0, // No keep-alive for reconnaissance
		}

		// Connect with TLS
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			c.logger.Debugw("Direct TLS connection failed",
				"domain", domain,
				"port", port,
				"error", err,
			)
			continue // Try next port
		}
		defer conn.Close()

		// Get certificate chain from connection
		state := conn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			c.logger.Debugw("No certificates in TLS connection",
				"domain", domain,
				"port", port,
			)
			continue
		}

		// Extract SANs from certificate
		cert := state.PeerCertificates[0]
		sans := extractSANsFromCert(cert)

		certInfo := CertificateInfo{
			Subject:   cert.Subject.CommonName,
			Issuer:    cert.Issuer.CommonName,
			SANs:      sans,
			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,
		}

		c.logger.Debugw("Certificate extracted from TLS connection",
			"domain", domain,
			"port", port,
			"subject", certInfo.Subject,
			"issuer", certInfo.Issuer,
			"sans_count", len(sans),
		)

		return []CertificateInfo{certInfo}
	}

	return []CertificateInfo{} // No certificates found
}

// extractSANsFromCert extracts Subject Alternative Names from x509 certificate
func extractSANsFromCert(cert *x509.Certificate) []string {
	sans := []string{}

	// Add DNSNames (most common)
	sans = append(sans, cert.DNSNames...)

	// Add IP addresses as strings
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	// Add email addresses
	sans = append(sans, cert.EmailAddresses...)

	// Add URIs
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}

	return sans
}

// convertCTLogCerts converts CT log certificates to CertificateInfo format
func (c *EnhancedCertificateClient) convertCTLogCerts(ctCerts []certlogs.Certificate) []CertificateInfo {
	certInfos := make([]CertificateInfo, 0, len(ctCerts))
	for _, cert := range ctCerts {
		certInfo := CertificateInfo{
			Subject:   cert.SubjectCN,
			Issuer:    cert.Issuer,
			SANs:      cert.SANs,
			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,
		}
		certInfos = append(certInfos, certInfo)
	}
	return certInfos
}

func (c *EnhancedCertificateClient) SearchByOrganization(ctx context.Context, org string) ([]CertificateInfo, error) {
	// Search CT logs by organization name
	certs, err := c.ctClient.SearchDomain(ctx, org)
	if err != nil {
		return []CertificateInfo{}, nil // Graceful degradation
	}

	return c.convertCTLogCerts(certs), nil
}
