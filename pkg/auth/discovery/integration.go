// pkg/auth/discovery/integration.go
package discovery

import (
	"context"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"net"
	"strings"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

// AuthDiscoveryIntegrationModule integrates comprehensive auth discovery with the main engine
type AuthDiscoveryIntegrationModule struct {
	comprehensiveAuth *ComprehensiveAuthDiscovery
	logger            *logger.Logger
}

// NewAuthDiscoveryIntegrationModule creates a new auth discovery module
func NewAuthDiscoveryIntegrationModule(logger *logger.Logger) *AuthDiscoveryIntegrationModule {
	return &AuthDiscoveryIntegrationModule{
		comprehensiveAuth: NewComprehensiveAuthDiscovery(logger),
		logger:            logger,
	}
}

// Implement the DiscoveryModule interface
func (a *AuthDiscoveryIntegrationModule) Name() string {
	return "comprehensive_auth_discovery"
}

func (a *AuthDiscoveryIntegrationModule) Priority() int {
	return 95 // High priority - auth is critical
}

func (a *AuthDiscoveryIntegrationModule) CanHandle(target *discovery.Target) bool {
	// We can discover auth for any target type
	return true
}

func (a *AuthDiscoveryIntegrationModule) Discover(ctx context.Context, target *discovery.Target, session *discovery.DiscoverySession) (*discovery.DiscoveryResult, error) {
	a.logger.Info("Starting comprehensive auth discovery module",
		"target", target.Value,
		"type", target.Type)

	// Run comprehensive discovery
	inventory, err := a.comprehensiveAuth.DiscoverAll(ctx, target.Value)
	if err != nil {
		return nil, fmt.Errorf("auth discovery failed: %w", err)
	}

	// Convert to discovery assets
	result := &discovery.DiscoveryResult{
		Assets:        a.convertToAssets(inventory),
		Relationships: a.extractRelationships(inventory),
		Source:        a.Name(),
	}

	// Log summary
	a.logger.Info("Auth discovery completed",
		"total_assets", len(result.Assets),
		"relationships", len(result.Relationships))

	return result, nil
}

// convertToAssets converts auth inventory to discovery assets
func (a *AuthDiscoveryIntegrationModule) convertToAssets(inventory *AuthInventory) []*discovery.Asset {
	var assets []*discovery.Asset

	// Convert network auth methods
	if inventory.NetworkAuth != nil {
		// LDAP endpoints
		for _, ldap := range inventory.NetworkAuth.LDAP {
			asset := &discovery.Asset{
				Type:       discovery.AssetTypeAuth,
				Value:      fmt.Sprintf("ldap://%s:%d", ldap.Host, ldap.Port),
				Title:      "LDAP Authentication",
				Technology: []string{"LDAP", ldap.Type},
				Metadata: map[string]string{
					"auth_type":      "ldap",
					"anonymous_bind": fmt.Sprintf("%t", ldap.AnonymousBindAllowed),
					"vendor":         ldap.VendorName,
				},
				Source:     a.Name(),
				Confidence: 0.95,
				Priority:   int(discovery.PriorityHigh),
			}

			// Mark as high value if it allows enumeration
			if ldap.UserEnumerationPossible {
				asset.Tags = append(asset.Tags, "user_enumeration")
				asset.Priority = int(discovery.PriorityCritical)
			}

			assets = append(assets, asset)
		}

		// Kerberos endpoints
		for _, krb := range inventory.NetworkAuth.Kerberos {
			asset := &discovery.Asset{
				Type:       discovery.AssetTypeAuth,
				Value:      fmt.Sprintf("kerberos://%s:%d", krb.Host, krb.Port),
				Title:      "Kerberos Authentication",
				Technology: []string{"Kerberos"},
				Metadata: map[string]string{
					"auth_type": "kerberos",
					"realm":     krb.Realm,
				},
				Source:     a.Name(),
				Confidence: 0.95,
				Priority:   int(discovery.PriorityHigh),
			}
			assets = append(assets, asset)
		}

		// Continue for other network auth types...
	}

	// Convert web auth methods
	if inventory.WebAuth != nil {
		// Form-based logins
		for _, form := range inventory.WebAuth.FormLogin {
			asset := &discovery.Asset{
				Type:  discovery.AssetTypeLogin,
				Value: form.URL,
				Title: "Form-based Login",
				Metadata: map[string]string{
					"auth_type":      "form",
					"submit_url":     form.SubmitURL,
					"has_csrf":       fmt.Sprintf("%t", form.CSRFToken),
					"username_field": form.UsernameField,
				},
				Source:     a.Name(),
				Confidence: 0.9,
				Priority:   int(discovery.PriorityHigh),
			}
			assets = append(assets, asset)
		}

		// OAuth2 endpoints
		for _, oauth := range inventory.WebAuth.OAuth2 {
			asset := &discovery.Asset{
				Type:       discovery.AssetTypeAPI,
				Value:      oauth.AuthorizeURL,
				Title:      "OAuth2 Authentication",
				Technology: []string{"OAuth2"},
				Metadata: map[string]string{
					"auth_type":    "oauth2",
					"token_url":    oauth.TokenURL,
					"pkce_support": fmt.Sprintf("%t", oauth.PKCE),
				},
				Source:     a.Name(),
				Confidence: 0.95,
				Priority:   int(discovery.PriorityHigh),
			}

			// If client ID is exposed, it's critical
			if oauth.ClientID != "" {
				asset.Tags = append(asset.Tags, "client_id_exposed")
				asset.Priority = int(discovery.PriorityCritical)
			}

			assets = append(assets, asset)
		}

		// SAML endpoints
		for _, saml := range inventory.WebAuth.SAML {
			asset := &discovery.Asset{
				Type:       discovery.AssetTypeAuth,
				Value:      saml.MetadataURL,
				Title:      "SAML Authentication",
				Technology: []string{"SAML"},
				Metadata: map[string]string{
					"auth_type": "saml",
					"sso_url":   saml.SSOURL,
					"entity_id": saml.EntityID,
				},
				Source:     a.Name(),
				Confidence: 0.95,
				Priority:   int(discovery.PriorityHigh),
			}
			assets = append(assets, asset)
		}

		// WebAuthn endpoints
		for _, webauthn := range inventory.WebAuth.WebAuthn {
			asset := &discovery.Asset{
				Type:       discovery.AssetTypeAuth,
				Value:      webauthn.RegisterURL,
				Title:      "WebAuthn/FIDO2 Authentication",
				Technology: []string{"WebAuthn", "FIDO2"},
				Metadata: map[string]string{
					"auth_type":   "webauthn",
					"login_url":   webauthn.LoginURL,
					"attestation": webauthn.AttestationType,
				},
				Source:     a.Name(),
				Confidence: 0.95,
				Priority:   int(discovery.PriorityMedium), // Usually well-implemented
			}
			assets = append(assets, asset)
		}
	}

	// Convert custom auth methods
	for _, custom := range inventory.CustomAuth {
		asset := &discovery.Asset{
			Type:  discovery.AssetTypeAuth,
			Value: custom.Endpoint,
			Title: fmt.Sprintf("Custom Authentication (%s)", custom.Type),
			Metadata: map[string]string{
				"auth_type":   "custom",
				"custom_type": custom.Type,
				"confidence":  fmt.Sprintf("%.2f", custom.Confidence),
			},
			Source:     a.Name(),
			Confidence: custom.Confidence,
			Priority:   int(discovery.PriorityMedium),
		}

		// Add indicators as tags
		for _, indicator := range custom.Indicators {
			asset.Tags = append(asset.Tags, indicator)
		}

		assets = append(assets, asset)
	}

	return assets
}

// extractRelationships finds relationships between auth methods
func (a *AuthDiscoveryIntegrationModule) extractRelationships(inventory *AuthInventory) []*discovery.Relationship {
	var relationships []*discovery.Relationship

	// Link SAML and OAuth2 if they appear to be related
	if inventory.WebAuth != nil {
		// Check if OAuth2 and SAML share the same domain
		samlDomains := make(map[string]*SAMLEndpoint)
		for i, saml := range inventory.WebAuth.SAML {
			domain := a.extractDomain(saml.MetadataURL)
			samlDomains[domain] = &inventory.WebAuth.SAML[i]
		}

		for _, oauth := range inventory.WebAuth.OAuth2 {
			domain := a.extractDomain(oauth.AuthorizeURL)
			if saml, exists := samlDomains[domain]; exists {
				rel := &discovery.Relationship{
					Type:   discovery.RelationType("federated_auth"),
					Source: oauth.AuthorizeURL,
					Target: saml.MetadataURL,
					Weight: 0.8,
					Metadata: map[string]string{
						"description": "OAuth2 and SAML on same domain - likely federated",
					},
				}
				relationships = append(relationships, rel)
			}
		}

		// Link form logins to API endpoints
		for _, form := range inventory.WebAuth.FormLogin {
			formDomain := a.extractDomain(form.URL)

			// Check if any OAuth2 endpoints match
			for _, oauth := range inventory.WebAuth.OAuth2 {
				if a.extractDomain(oauth.AuthorizeURL) == formDomain {
					rel := &discovery.Relationship{
						Type:   discovery.RelationType("alternative_auth"),
						Source: form.URL,
						Target: oauth.AuthorizeURL,
						Weight: 0.7,
						Metadata: map[string]string{
							"description": "Form login and OAuth2 available",
						},
					}
					relationships = append(relationships, rel)
				}
			}
		}
	}

	// Link network auth to web auth
	if inventory.NetworkAuth != nil && inventory.WebAuth != nil {
		// LDAP to form login relationships
		for _, ldap := range inventory.NetworkAuth.LDAP {
			for _, form := range inventory.WebAuth.FormLogin {
				// Simple heuristic: if they're on the same network
				if a.sameNetwork(ldap.Host, a.extractHost(form.URL)) {
					rel := &discovery.Relationship{
						Type:   discovery.RelationType("backend_auth"),
						Source: form.URL,
						Target: fmt.Sprintf("ldap://%s:%d", ldap.Host, ldap.Port),
						Weight: 0.6,
						Metadata: map[string]string{
							"description": "Form login likely uses LDAP backend",
						},
					}
					relationships = append(relationships, rel)
				}
			}
		}
	}

	return relationships
}

// extractDomain extracts domain from URL
func (a *AuthDiscoveryIntegrationModule) extractDomain(url string) string {
	if strings.HasPrefix(url, "http://") {
		url = url[7:]
	} else if strings.HasPrefix(url, "https://") {
		url = url[8:]
	}

	// Remove path
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	// Remove port
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	return url
}

// sameNetwork checks if two hosts are in the same network
func (a *AuthDiscoveryIntegrationModule) sameNetwork(host1, host2 string) bool {
	// Simple heuristic: check if they're in the same /24 network
	ip1 := net.ParseIP(host1)
	ip2 := net.ParseIP(host2)

	if ip1 == nil || ip2 == nil {
		// If either is not an IP, check domain similarity
		return a.extractDomain(host1) == a.extractDomain(host2)
	}

	// Check if in same /24 network
	mask := net.CIDRMask(24, 32)
	return ip1.Mask(mask).Equal(ip2.Mask(mask))
}

// extractHost extracts host from URL
func (a *AuthDiscoveryIntegrationModule) extractHost(url string) string {
	if strings.HasPrefix(url, "http://") {
		url = url[7:]
	} else if strings.HasPrefix(url, "https://") {
		url = url[8:]
	}

	// Remove path
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	// Remove port to get just the host
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	return url
}

// Integration with the main discovery flow
func (a *AuthDiscoveryModule) PostProcess(assets []*discovery.Asset) []*discovery.Asset {
	// Enhance assets with additional auth context
	for _, asset := range assets {
		// If it's a web server, check for auth endpoints
		if asset.Type == discovery.AssetTypeURL || asset.Type == discovery.AssetTypeService {
			a.enhanceWithAuthInfo(asset)
		}
	}

	return assets
}

// enhanceWithAuthInfo adds auth information to existing assets
func (a *AuthDiscoveryModule) enhanceWithAuthInfo(asset *discovery.Asset) {
	// Quick check for common auth endpoints
	authEndpoints := []string{
		"/login", "/signin", "/auth", "/oauth/authorize",
		"/saml/metadata", "/.well-known/openid-configuration",
	}

	for _, endpoint := range authEndpoints {
		checkURL := asset.Value + endpoint
		// Quick HEAD request to check existence
		if a.checkEndpointExists(checkURL) {
			if asset.Metadata == nil {
				asset.Metadata = make(map[string]string)
			}
			asset.Metadata["has_auth_endpoints"] = "true"
			asset.Tags = append(asset.Tags, "authentication")

			// Increase priority if auth is found
			if asset.Priority < int(discovery.PriorityHigh) {
				asset.Priority = int(discovery.PriorityHigh)
			}
			break
		}
	}
}

func (a *AuthDiscoveryModule) checkEndpointExists(url string) bool {
	resp, err := a.httpClient.Head(url)
	if err != nil {
		return false
	}
	defer httpclient.CloseBody(resp)

	// Consider 200-399 as success
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

// Helper to register this module with the discovery engine
func RegisterAuthDiscoveryModule(engine *discovery.Engine, logger *logger.Logger) {
	module := NewAuthDiscoveryModule(logger)
	engine.RegisterModule(module)
}
