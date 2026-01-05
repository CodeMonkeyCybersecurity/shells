// internal/discovery/intelligent_scanner_selector.go
package discovery

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	pkgdiscovery "github.com/CodeMonkeyCybersecurity/shells/pkg/discovery"
)

// ScannerType represents a type of scanner
type ScannerType string

const (
	ScannerTypeNmap          ScannerType = "nmap"
	ScannerTypeNuclei        ScannerType = "nuclei"
	ScannerTypeSSL           ScannerType = "ssl"
	ScannerTypeSCIM          ScannerType = "scim"
	ScannerTypeSmuggling     ScannerType = "smuggling"
	ScannerTypeAuth          ScannerType = "auth"
	ScannerTypeWebCrawl      ScannerType = "webcrawl"
	ScannerTypeAPI           ScannerType = "api"
	ScannerTypeMail          ScannerType = "mail"
	ScannerTypeCloudEnum     ScannerType = "cloud_enum"
	ScannerTypeFuzz          ScannerType = "fuzz"
	ScannerTypeBusinessLogic ScannerType = "business_logic"
)

// ScannerRecommendation represents a recommended scanner with context
type ScannerRecommendation struct {
	Scanner   ScannerType
	Priority  int // 1-100, higher is more important
	Reason    string
	Arguments []string // Scanner-specific arguments
	Targets   []string // Specific targets for this scanner
}

// IntelligentScannerSelector selects appropriate scanners based on target context
type IntelligentScannerSelector struct {
	logger *logger.Logger
}

// NewIntelligentScannerSelector creates a new scanner selector
func NewIntelligentScannerSelector(logger *logger.Logger) *IntelligentScannerSelector {
	return &IntelligentScannerSelector{
		logger: logger,
	}
}

// SelectScanners recommends scanners based on the discovered context
func (s *IntelligentScannerSelector) SelectScanners(session *DiscoverySession) []ScannerRecommendation {
	recommendations := []ScannerRecommendation{}

	// Get target context from session metadata
	var targetContext *pkgdiscovery.TargetContext
	if session.DiscoveryTarget != nil && session.DiscoveryTarget.Metadata != nil {
		if ctx, ok := session.DiscoveryTarget.Metadata["target_context"].(*pkgdiscovery.TargetContext); ok {
			targetContext = ctx
		}
	}

	// If no context, recommend basic scanners
	if targetContext == nil {
		s.logger.Warn("No target context available, recommending basic scanners")
		return s.recommendBasicScanners(session)
	}

	s.logger.Info("Selecting scanners based on context",
		"primary_service", targetContext.PrimaryService,
		"is_mail_server", targetContext.IsMailServer,
		"is_web_app", targetContext.IsWebApp,
		"is_api", targetContext.IsAPI,
		"auth_methods", len(targetContext.AuthMethods),
	)

	// Always recommend basic reconnaissance
	recommendations = append(recommendations, s.recommendReconScanners(targetContext)...)

	// Service-specific scanners
	if targetContext.IsMailServer {
		recommendations = append(recommendations, s.recommendMailScanners(targetContext)...)
	}

	if targetContext.IsWebApp {
		recommendations = append(recommendations, s.recommendWebAppScanners(targetContext)...)
	}

	if targetContext.IsAPI {
		recommendations = append(recommendations, s.recommendAPIScanners(targetContext)...)
	}

	// Authentication-specific scanners
	if targetContext.HasAuthentication || len(targetContext.AuthMethods) > 0 {
		recommendations = append(recommendations, s.recommendAuthScanners(targetContext)...)
	}

	// Technology-specific scanners
	recommendations = append(recommendations, s.recommendTechScanners(targetContext)...)

	// Port-specific scanners
	recommendations = append(recommendations, s.recommendPortScanners(targetContext)...)

	// Cloud-specific scanners
	if s.detectCloudServices(targetContext) {
		recommendations = append(recommendations, s.recommendCloudScanners(targetContext)...)
	}

	// Remove duplicates and sort by priority
	recommendations = s.deduplicateAndSort(recommendations)

	s.logger.Info("Scanner selection completed",
		"total_recommendations", len(recommendations),
		"top_scanner", s.getTopScanner(recommendations),
	)

	return recommendations
}

// recommendBasicScanners provides basic scanning recommendations
func (s *IntelligentScannerSelector) recommendBasicScanners(session *DiscoverySession) []ScannerRecommendation {
	target := session.Target.Value

	return []ScannerRecommendation{
		{
			Scanner:   ScannerTypeNmap,
			Priority:  90,
			Reason:    "Basic port scanning and service detection",
			Arguments: []string{"-sV", "-sC", "-O"},
			Targets:   []string{target},
		},
		{
			Scanner:   ScannerTypeNuclei,
			Priority:  85,
			Reason:    "Vulnerability scanning with community templates",
			Arguments: []string{"-severity", "critical,high,medium"},
			Targets:   []string{target},
		},
		{
			Scanner:  ScannerTypeSSL,
			Priority: 80,
			Reason:   "SSL/TLS configuration analysis",
			Targets:  []string{target},
		},
	}
}

// recommendReconScanners provides reconnaissance scanner recommendations
func (s *IntelligentScannerSelector) recommendReconScanners(ctx *pkgdiscovery.TargetContext) []ScannerRecommendation {
	recs := []ScannerRecommendation{}

	// Always do port scanning
	recs = append(recs, ScannerRecommendation{
		Scanner:   ScannerTypeNmap,
		Priority:  95,
		Reason:    "Comprehensive port and service discovery",
		Arguments: []string{"-sV", "-sC", "-O", "-p-"},
		Targets:   []string{ctx.Target},
	})

	// SSL scanning for HTTPS services
	if s.hasHTTPS(ctx) {
		recs = append(recs, ScannerRecommendation{
			Scanner:  ScannerTypeSSL,
			Priority: 85,
			Reason:   "SSL/TLS configuration and vulnerability analysis",
			Targets:  s.getHTTPSTargets(ctx),
		})
	}

	return recs
}

// recommendMailScanners provides mail-specific scanner recommendations
func (s *IntelligentScannerSelector) recommendMailScanners(ctx *pkgdiscovery.TargetContext) []ScannerRecommendation {
	recs := []ScannerRecommendation{
		{
			Scanner:   ScannerTypeMail,
			Priority:  90,
			Reason:    "Mail server security assessment",
			Arguments: []string{"--full-test"},
			Targets:   []string{ctx.Target},
		},
		{
			Scanner:   ScannerTypeAuth,
			Priority:  85,
			Reason:    "Mail authentication testing (SMTP, IMAP, POP3)",
			Arguments: []string{"--protocol", "mail"},
			Targets:   s.getMailAuthTargets(ctx),
		},
	}

	// If webmail interfaces found, add web scanning
	if s.hasWebmail(ctx) {
		recs = append(recs, ScannerRecommendation{
			Scanner:   ScannerTypeWebCrawl,
			Priority:  80,
			Reason:    "Webmail interface discovery and analysis",
			Arguments: []string{"--focus-auth"},
			Targets:   s.getWebmailTargets(ctx),
		})
	}

	return recs
}

// recommendWebAppScanners provides web application scanner recommendations
func (s *IntelligentScannerSelector) recommendWebAppScanners(ctx *pkgdiscovery.TargetContext) []ScannerRecommendation {
	recs := []ScannerRecommendation{
		{
			Scanner:   ScannerTypeWebCrawl,
			Priority:  90,
			Reason:    "Web application crawling and endpoint discovery",
			Arguments: []string{"--depth", "3"},
			Targets:   s.getWebTargets(ctx),
		},
		{
			Scanner:   ScannerTypeNuclei,
			Priority:  88,
			Reason:    "Web vulnerability scanning",
			Arguments: []string{"-tags", "web"},
			Targets:   s.getWebTargets(ctx),
		},
		{
			Scanner:  ScannerTypeSmuggling,
			Priority: 75,
			Reason:   "HTTP request smuggling detection",
			Targets:  s.getWebTargets(ctx),
		},
		{
			Scanner:   ScannerTypeFuzz,
			Priority:  70,
			Reason:    "Parameter and path fuzzing",
			Arguments: []string{"--wordlist", "common"},
			Targets:   s.getWebTargets(ctx),
		},
	}

	// Add business logic testing for high-value targets
	if s.hasHighValueEndpoints(ctx) {
		recs = append(recs, ScannerRecommendation{
			Scanner:   ScannerTypeBusinessLogic,
			Priority:  85,
			Reason:    "Business logic vulnerability testing",
			Arguments: []string{"--focus", "auth,payment"},
			Targets:   s.getHighValueTargets(ctx),
		})
	}

	return recs
}

// recommendAPIScanners provides API-specific scanner recommendations
func (s *IntelligentScannerSelector) recommendAPIScanners(ctx *pkgdiscovery.TargetContext) []ScannerRecommendation {
	recs := []ScannerRecommendation{
		{
			Scanner:   ScannerTypeAPI,
			Priority:  92,
			Reason:    "API endpoint discovery and testing",
			Arguments: []string{"--discover-spec"},
			Targets:   s.getAPITargets(ctx),
		},
		{
			Scanner:   ScannerTypeSCIM,
			Priority:  80,
			Reason:    "SCIM endpoint security testing",
			Arguments: []string{"--test-all"},
			Targets:   s.getSCIMTargets(ctx),
		},
		{
			Scanner:   ScannerTypeFuzz,
			Priority:  75,
			Reason:    "API parameter fuzzing",
			Arguments: []string{"--type", "api"},
			Targets:   s.getAPITargets(ctx),
		},
	}

	return recs
}

// recommendAuthScanners provides authentication-specific scanner recommendations
func (s *IntelligentScannerSelector) recommendAuthScanners(ctx *pkgdiscovery.TargetContext) []ScannerRecommendation {
	recs := []ScannerRecommendation{
		{
			Scanner:   ScannerTypeAuth,
			Priority:  95,
			Reason:    fmt.Sprintf("Authentication testing for %d auth methods", len(ctx.AuthMethods)),
			Arguments: []string{"--all-protocols"},
			Targets:   []string{ctx.Target},
		},
	}

	// Add specific auth protocol scanners
	for _, authMethod := range ctx.AuthMethods {
		authLower := strings.ToLower(authMethod)

		if strings.Contains(authLower, "saml") {
			recs = append(recs, ScannerRecommendation{
				Scanner:   ScannerTypeAuth,
				Priority:  90,
				Reason:    "SAML authentication vulnerability testing",
				Arguments: []string{"--protocol", "saml", "--test", "golden-saml,xsw"},
				Targets:   []string{ctx.Target},
			})
		}

		if strings.Contains(authLower, "oauth") || strings.Contains(authLower, "jwt") {
			recs = append(recs, ScannerRecommendation{
				Scanner:   ScannerTypeAuth,
				Priority:  90,
				Reason:    "OAuth2/JWT vulnerability testing",
				Arguments: []string{"--protocol", "oauth2", "--test", "jwt-attacks"},
				Targets:   []string{ctx.Target},
			})
		}
	}

	return recs
}

// recommendTechScanners provides technology-specific scanner recommendations
func (s *IntelligentScannerSelector) recommendTechScanners(ctx *pkgdiscovery.TargetContext) []ScannerRecommendation {
	recs := []ScannerRecommendation{}

	for _, tech := range ctx.Technologies {
		techLower := strings.ToLower(tech)

		// WordPress specific
		if strings.Contains(techLower, "wordpress") {
			recs = append(recs, ScannerRecommendation{
				Scanner:   ScannerTypeNuclei,
				Priority:  85,
				Reason:    "WordPress vulnerability scanning",
				Arguments: []string{"-tags", "wordpress"},
				Targets:   s.getWebTargets(ctx),
			})
		}

		// Jenkins specific
		if strings.Contains(techLower, "jenkins") {
			recs = append(recs, ScannerRecommendation{
				Scanner:   ScannerTypeNuclei,
				Priority:  90,
				Reason:    "Jenkins vulnerability scanning",
				Arguments: []string{"-tags", "jenkins"},
				Targets:   s.getWebTargets(ctx),
			})
		}

		// API frameworks
		if strings.Contains(techLower, "graphql") {
			recs = append(recs, ScannerRecommendation{
				Scanner:   ScannerTypeAPI,
				Priority:  88,
				Reason:    "GraphQL introspection and testing",
				Arguments: []string{"--type", "graphql"},
				Targets:   s.getAPITargets(ctx),
			})
		}
	}

	return recs
}

// recommendPortScanners provides port-specific scanner recommendations
func (s *IntelligentScannerSelector) recommendPortScanners(ctx *pkgdiscovery.TargetContext) []ScannerRecommendation {
	recs := []ScannerRecommendation{}

	// Check for specific ports
	for _, port := range ctx.Ports {
		switch port.Port {
		case 3389: // RDP
			recs = append(recs, ScannerRecommendation{
				Scanner:   ScannerTypeNuclei,
				Priority:  80,
				Reason:    "RDP vulnerability scanning",
				Arguments: []string{"-tags", "rdp"},
				Targets:   []string{fmt.Sprintf("%s:%d", ctx.Target, port.Port)},
			})
		case 445: // SMB
			recs = append(recs, ScannerRecommendation{
				Scanner:   ScannerTypeNuclei,
				Priority:  85,
				Reason:    "SMB vulnerability scanning",
				Arguments: []string{"-tags", "smb"},
				Targets:   []string{fmt.Sprintf("%s:%d", ctx.Target, port.Port)},
			})
		}
	}

	return recs
}

// recommendCloudScanners provides cloud-specific scanner recommendations
func (s *IntelligentScannerSelector) recommendCloudScanners(ctx *pkgdiscovery.TargetContext) []ScannerRecommendation {
	return []ScannerRecommendation{
		{
			Scanner:   ScannerTypeCloudEnum,
			Priority:  80,
			Reason:    "Cloud service enumeration",
			Arguments: []string{"--providers", "aws,azure,gcp"},
			Targets:   []string{ctx.Target},
		},
	}
}

// Helper methods

func (s *IntelligentScannerSelector) hasHTTPS(ctx *pkgdiscovery.TargetContext) bool {
	for _, port := range ctx.Ports {
		if port.Port == 443 || port.Port == 8443 {
			return true
		}
	}
	return false
}

func (s *IntelligentScannerSelector) getHTTPSTargets(ctx *pkgdiscovery.TargetContext) []string {
	targets := []string{}
	for _, port := range ctx.Ports {
		if port.Port == 443 || port.Port == 8443 {
			targets = append(targets, fmt.Sprintf("%s:%d", ctx.Target, port.Port))
		}
	}
	return targets
}

func (s *IntelligentScannerSelector) hasWebmail(ctx *pkgdiscovery.TargetContext) bool {
	if meta, ok := ctx.Metadata["/webmail"]; ok {
		return meta != nil
	}
	return false
}

func (s *IntelligentScannerSelector) getWebmailTargets(ctx *pkgdiscovery.TargetContext) []string {
	// This would be populated from discovered webmail URLs
	return []string{ctx.Target + "/webmail"}
}

func (s *IntelligentScannerSelector) getMailAuthTargets(ctx *pkgdiscovery.TargetContext) []string {
	targets := []string{}
	for _, port := range ctx.Ports {
		switch port.Service {
		case "smtp", "smtps", "submission", "imap", "imaps", "pop3", "pop3s":
			targets = append(targets, fmt.Sprintf("%s:%d", ctx.Target, port.Port))
		}
	}
	return targets
}

func (s *IntelligentScannerSelector) getWebTargets(ctx *pkgdiscovery.TargetContext) []string {
	targets := []string{}
	for _, port := range ctx.Ports {
		if port.Port == 80 || port.Port == 443 || port.Port == 8080 || port.Port == 8443 {
			protocol := "http"
			if port.Port == 443 || port.Port == 8443 {
				protocol = "https"
			}
			targets = append(targets, fmt.Sprintf("%s://%s:%d", protocol, ctx.Target, port.Port))
		}
	}
	return targets
}

func (s *IntelligentScannerSelector) getAPITargets(ctx *pkgdiscovery.TargetContext) []string {
	// Look for API-specific endpoints
	targets := []string{}
	for _, subdomain := range ctx.Subdomains {
		if strings.Contains(subdomain, "api") {
			targets = append(targets, subdomain)
		}
	}
	if len(targets) == 0 && ctx.IsAPI {
		targets = s.getWebTargets(ctx)
	}
	return targets
}

func (s *IntelligentScannerSelector) getSCIMTargets(ctx *pkgdiscovery.TargetContext) []string {
	// Look for SCIM endpoints
	targets := []string{}
	for _, target := range s.getWebTargets(ctx) {
		targets = append(targets, target+"/scim/v2")
	}
	return targets
}

func (s *IntelligentScannerSelector) hasHighValueEndpoints(ctx *pkgdiscovery.TargetContext) bool {
	// Check metadata for high-value indicators
	highValueKeywords := []string{"admin", "payment", "login", "auth", "api"}

	for key := range ctx.Metadata {
		for _, keyword := range highValueKeywords {
			if strings.Contains(strings.ToLower(key), keyword) {
				return true
			}
		}
	}

	return false
}

func (s *IntelligentScannerSelector) getHighValueTargets(ctx *pkgdiscovery.TargetContext) []string {
	// This would extract specific high-value endpoints
	return s.getWebTargets(ctx)
}

func (s *IntelligentScannerSelector) detectCloudServices(ctx *pkgdiscovery.TargetContext) bool {
	// Check for cloud provider indicators
	cloudIndicators := []string{"cloudflare", "aws", "azure", "gcp", "cloudfront"}

	for _, tech := range ctx.Technologies {
		for _, indicator := range cloudIndicators {
			if strings.Contains(strings.ToLower(tech), indicator) {
				return true
			}
		}
	}

	return false
}

func (s *IntelligentScannerSelector) deduplicateAndSort(recs []ScannerRecommendation) []ScannerRecommendation {
	// Simple deduplication by scanner type and target
	seen := make(map[string]bool)
	unique := []ScannerRecommendation{}

	for _, rec := range recs {
		key := fmt.Sprintf("%s-%s", rec.Scanner, strings.Join(rec.Targets, ","))
		if !seen[key] {
			seen[key] = true
			unique = append(unique, rec)
		}
	}

	// Sort by priority (highest first)
	for i := 0; i < len(unique)-1; i++ {
		for j := i + 1; j < len(unique); j++ {
			if unique[i].Priority < unique[j].Priority {
				unique[i], unique[j] = unique[j], unique[i]
			}
		}
	}

	return unique
}

func (s *IntelligentScannerSelector) getTopScanner(recs []ScannerRecommendation) string {
	if len(recs) > 0 {
		return string(recs[0].Scanner)
	}
	return "none"
}
