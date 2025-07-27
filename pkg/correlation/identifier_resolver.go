// pkg/correlation/identifier_resolver.go
package correlation

import (
	"context"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// IdentifierInfo contains parsed identifier information
type IdentifierInfo struct {
	Type     IdentifierType
	Value    string
	Domain   string // Extracted domain if applicable
	Company  string // Extracted company name if known
	Metadata map[string]string
}

// IdentifierResolver resolves various identifiers to organization information
type IdentifierResolver struct {
	logger *logger.Logger
}

// NewIdentifierResolver creates a new identifier resolver
func NewIdentifierResolver(logger *logger.Logger) *IdentifierResolver {
	return &IdentifierResolver{logger: logger}
}

// ParseIdentifier determines the type and extracts information from an identifier
func (ir *IdentifierResolver) ParseIdentifier(identifier string) (*IdentifierInfo, error) {
	identifier = strings.TrimSpace(identifier)

	// Check email
	if addr, err := mail.ParseAddress(identifier); err == nil {
		parts := strings.Split(addr.Address, "@")
		if len(parts) == 2 {
			return &IdentifierInfo{
				Type:   TypeEmail,
				Value:  addr.Address,
				Domain: parts[1],
				Metadata: map[string]string{
					"local_part": parts[0],
				},
			}, nil
		}
	}

	// Check URL
	if u, err := url.Parse(identifier); err == nil && u.Host != "" {
		return &IdentifierInfo{
			Type:   TypeURL,
			Value:  identifier,
			Domain: u.Host,
			Metadata: map[string]string{
				"scheme": u.Scheme,
				"path":   u.Path,
			},
		}, nil
	}

	// Check IP
	if ip := net.ParseIP(identifier); ip != nil {
		return &IdentifierInfo{
			Type:  TypeIP,
			Value: identifier,
			Metadata: map[string]string{
				"version": getIPVersion(ip),
			},
		}, nil
	}

	// Check IP Range
	if _, _, err := net.ParseCIDR(identifier); err == nil {
		return &IdentifierInfo{
			Type:  TypeIPRange,
			Value: identifier,
		}, nil
	}

	// Check ASN
	if strings.HasPrefix(strings.ToUpper(identifier), "AS") {
		asnStr := strings.TrimPrefix(strings.ToUpper(identifier), "AS")
		if isNumeric(asnStr) {
			return &IdentifierInfo{
				Type:  "asn",
				Value: identifier,
				Metadata: map[string]string{
					"asn_number": asnStr,
				},
			}, nil
		}
	}

	// Check domain pattern
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	if domainRegex.MatchString(identifier) {
		return &IdentifierInfo{
			Type:   TypeDomain,
			Value:  identifier,
			Domain: identifier,
		}, nil
	}

	// Check LinkedIn URL
	if strings.Contains(identifier, "linkedin.com/company/") {
		company := extractLinkedInCompany(identifier)
		return &IdentifierInfo{
			Type:    "linkedin",
			Value:   identifier,
			Company: company,
			Metadata: map[string]string{
				"platform": "linkedin",
			},
		}, nil
	}

	// Check GitHub
	if strings.Contains(identifier, "github.com/") {
		org := extractGitHubOrg(identifier)
		return &IdentifierInfo{
			Type:    "github",
			Value:   identifier,
			Company: org,
			Metadata: map[string]string{
				"platform": "github",
			},
		}, nil
	}

	// Default to company name
	return &IdentifierInfo{
		Type:    TypeCompanyName,
		Value:   identifier,
		Company: identifier,
	}, nil
}

// ResolveToOrganization resolves an identifier to organization details using enhanced correlator
func (ir *IdentifierResolver) ResolveToOrganization(ctx context.Context, info *IdentifierInfo, ec *EnhancedOrganizationCorrelator) (*Organization, error) {
	ir.logger.Info("Resolving identifier to organization",
		"type", info.Type,
		"value", info.Value)

	switch info.Type {
	case TypeEmail:
		return ec.DiscoverFromEmail(ctx, info.Value)
	case TypeDomain:
		return ec.DiscoverFromDomain(ctx, info.Domain)
	case TypeIP:
		return ec.DiscoverFromIP(ctx, info.Value)
	case TypeIPRange:
		return ec.DiscoverFromIPRange(ctx, info.Value)
	case "asn":
		return ec.DiscoverFromASN(ctx, info.Value)
	case TypeCompanyName:
		return ec.DiscoverFromCompanyName(ctx, info.Company)
	case "linkedin":
		return ec.DiscoverFromLinkedIn(ctx, info.Value)
	case "github":
		return ec.DiscoverFromGitHub(ctx, info.Value)
	default:
		return nil, fmt.Errorf("unsupported identifier type: %s", info.Type)
	}
}
