// internal/discovery/context_aware_discovery.go
package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	pkgdiscovery "github.com/CodeMonkeyCybersecurity/shells/pkg/discovery"
)

// ContextAwareDiscovery performs intelligent discovery based on target context
type ContextAwareDiscovery struct {
	config            *DiscoveryConfig
	logger            *logger.Logger
	serviceClassifier *pkgdiscovery.ServiceClassifier
	mailAnalyzer      *pkgdiscovery.MailServerAnalyzer
}

// NewContextAwareDiscovery creates a new context-aware discovery module
func NewContextAwareDiscovery(config *DiscoveryConfig, logger *logger.Logger) *ContextAwareDiscovery {
	return &ContextAwareDiscovery{
		config:            config,
		logger:            logger,
		serviceClassifier: pkgdiscovery.NewServiceClassifier(logger),
		mailAnalyzer:      pkgdiscovery.NewMailServerAnalyzer(logger),
	}
}

func (c *ContextAwareDiscovery) Name() string  { return "context_aware_discovery" }
func (c *ContextAwareDiscovery) Priority() int { return 95 } // Higher priority to run first

func (c *ContextAwareDiscovery) CanHandle(target *Target) bool {
	// This module can handle any target to provide context
	return true
}

func (c *ContextAwareDiscovery) Discover(ctx context.Context, target *Target, session *DiscoverySession) (*DiscoveryResult, error) {
	result := &DiscoveryResult{
		Assets:        []*Asset{},
		Relationships: []*Relationship{},
		Source:        c.Name(),
	}

	// Extract the actual target value
	targetValue := c.extractTargetValue(target)
	if targetValue == "" {
		return result, nil
	}

	c.logger.Info("Starting context-aware discovery",
		"target", targetValue,
		"type", target.Type,
	)

	// First, classify the target to understand what we're dealing with
	targetContext, err := c.serviceClassifier.ClassifyTarget(ctx, targetValue)
	if err != nil {
		c.logger.Error("Failed to classify target", "error", err)
		// Continue anyway
		targetContext = &pkgdiscovery.TargetContext{
			Target: targetValue,
		}
	}

	// Store context in session for other modules to use
	if session.DiscoveryTarget != nil {
		if session.DiscoveryTarget.Metadata == nil {
			session.DiscoveryTarget.Metadata = make(map[string]interface{})
		}
		session.DiscoveryTarget.Metadata["target_context"] = targetContext
	}

	// Log discovered context
	c.logger.Info("Target classification completed",
		"target", targetValue,
		"primary_service", targetContext.PrimaryService,
		"is_mail_server", targetContext.IsMailServer,
		"is_web_app", targetContext.IsWebApp,
		"is_api", targetContext.IsAPI,
		"open_ports", len(targetContext.Ports),
		"technologies", strings.Join(targetContext.Technologies, ", "),
		"auth_methods", strings.Join(targetContext.AuthMethods, ", "),
		"organization", targetContext.Organization,
	)

	// If it's a mail server, perform deep mail analysis
	if targetContext.IsMailServer {
		c.logger.Info("Target identified as mail server, performing specialized analysis")

		mailInfo, err := c.mailAnalyzer.AnalyzeMailServer(ctx, targetValue)
		if err != nil {
			c.logger.Error("Mail server analysis failed", "error", err)
		} else {
			// Convert mail server info to assets
			c.processMailServerInfo(mailInfo, result)
		}
	}

	// Add discovered subdomains as assets
	for _, subdomain := range targetContext.Subdomains {
		asset := &Asset{
			Type:         AssetTypeSubdomain,
			Value:        subdomain,
			Domain:       c.extractBaseDomain(subdomain),
			Source:       c.Name(),
			Confidence:   0.9,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
			Metadata: map[string]string{
				"discovery_method": "dns_enumeration",
			},
		}
		result.Assets = append(result.Assets, asset)
	}

	// Add related domains as assets
	for _, domain := range targetContext.RelatedDomains {
		asset := &Asset{
			Type:         AssetTypeDomain,
			Value:        domain,
			Domain:       domain,
			Source:       c.Name(),
			Confidence:   0.8,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
			Metadata: map[string]string{
				"discovery_method": "context_analysis",
				"relationship":     "related",
			},
		}
		result.Assets = append(result.Assets, asset)
	}

	// Add discovered services as assets
	for _, service := range targetContext.Services {
		asset := &Asset{
			Type:         AssetTypeService,
			Value:        fmt.Sprintf("%s:%d", targetValue, service.Port),
			Title:        fmt.Sprintf("%s on port %d", service.Type, service.Port),
			Port:         service.Port,
			Technology:   []string{string(service.Type)},
			Source:       c.Name(),
			Confidence:   service.Confidence,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
			Metadata: map[string]string{
				"service_type": string(service.Type),
				"protocol":     service.Protocol,
				"version":      service.Version,
			},
		}

		if service.Banner != "" {
			asset.Metadata["banner"] = service.Banner
		}

		result.Assets = append(result.Assets, asset)
	}

	// Add authentication endpoints as high-value assets
	for _, authMethod := range targetContext.AuthMethods {
		asset := &Asset{
			Type:         AssetTypeAuthentication,
			Value:        authMethod,
			Title:        fmt.Sprintf("%s Authentication", authMethod),
			Domain:       targetValue,
			Source:       c.Name(),
			Confidence:   0.95,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
			Tags:         []string{"authentication", "high-value"},
			Metadata: map[string]string{
				"auth_type": authMethod,
			},
		}
		result.Assets = append(result.Assets, asset)
	}

	c.logger.Info("Context-aware discovery completed",
		"target", targetValue,
		"assets_found", len(result.Assets),
		"mail_servers", targetContext.IsMailServer,
		"web_apps", targetContext.IsWebApp,
		"apis", targetContext.IsAPI,
	)

	return result, nil
}

func (c *ContextAwareDiscovery) processMailServerInfo(info *pkgdiscovery.MailServerInfo, result *DiscoveryResult) {
	// Add mail servers as assets
	for _, mailServer := range info.MailServers {
		asset := &Asset{
			Type:         AssetTypeMailServer,
			Value:        mailServer.Hostname,
			IP:           mailServer.IP,
			Title:        fmt.Sprintf("Mail Server (Priority: %d)", mailServer.Priority),
			Source:       c.Name(),
			Confidence:   0.95,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
			Tags:         []string{"mail-server", "high-value"},
			Metadata: map[string]string{
				"mx_priority": fmt.Sprintf("%d", mailServer.Priority),
			},
		}

		// Add service information
		var services []string
		for _, svc := range mailServer.Services {
			services = append(services, fmt.Sprintf("%s:%d", svc.Type, svc.Port))
		}
		asset.Metadata["services"] = strings.Join(services, ",")

		result.Assets = append(result.Assets, asset)
	}

	// Add webmail interfaces as high-value assets
	for _, webmailURL := range info.WebmailURLs {
		asset := &Asset{
			Type:         AssetTypeURL,
			Value:        webmailURL,
			Title:        "Webmail Interface",
			Domain:       info.Domain,
			Source:       c.Name(),
			Confidence:   0.9,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
			Tags:         []string{"webmail", "authentication", "high-value"},
			Metadata: map[string]string{
				"interface_type": "webmail",
			},
		}
		result.Assets = append(result.Assets, asset)
	}

	// Add admin panels as critical assets
	for _, adminURL := range info.AdminPanelURLs {
		asset := &Asset{
			Type:         AssetTypeAdminPanel,
			Value:        adminURL,
			Title:        "Mail Admin Panel",
			Domain:       info.Domain,
			Source:       c.Name(),
			Confidence:   0.9,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
			Tags:         []string{"admin-panel", "authentication", "critical"},
			Priority:     90, // High priority
			Metadata: map[string]string{
				"panel_type": "mail_admin",
			},
		}
		result.Assets = append(result.Assets, asset)
	}

	// Add authentication methods
	for _, authMethod := range info.AuthMethods {
		asset := &Asset{
			Type:         AssetTypeAuthentication,
			Value:        authMethod.Endpoint,
			Title:        fmt.Sprintf("%s Authentication", authMethod.Service),
			Domain:       info.Domain,
			Source:       c.Name(),
			Confidence:   0.95,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
			Tags:         []string{"authentication", "mail-auth"},
			Metadata: map[string]string{
				"service":      authMethod.Service,
				"methods":      strings.Join(authMethod.Methods, ","),
				"requires_tls": fmt.Sprintf("%v", authMethod.RequiresTLS),
			},
		}
		result.Assets = append(result.Assets, asset)
	}

	// Add organization information if found
	if info.Organization != "" {
		// Store in session metadata
		c.logger.Info("Found organization from mail server analysis",
			"organization", info.Organization,
			"domain", info.Domain,
		)
	}
}

func (c *ContextAwareDiscovery) extractTargetValue(target *Target) string {
	switch target.Type {
	case TargetTypeDomain:
		return target.Value
	case TargetTypeEmail:
		if domain, exists := target.Metadata["domain"]; exists {
			return domain
		}
		// Extract domain from email
		parts := strings.Split(target.Value, "@")
		if len(parts) == 2 {
			return parts[1]
		}
	case TargetTypeURL:
		if host, exists := target.Metadata["host"]; exists {
			return host
		}
	case TargetTypeIP:
		return target.Value
	}
	return target.Value
}

func (c *ContextAwareDiscovery) extractBaseDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return hostname
}
