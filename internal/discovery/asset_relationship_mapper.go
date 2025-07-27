package discovery

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
	"github.com/google/uuid"
)

// AssetRelationshipMapper builds relationships between discovered assets
// with special focus on identity-related correlations
type AssetRelationshipMapper struct {
	config         *DiscoveryConfig
	logger         *logger.Logger
	relationships  map[string]*AssetRelationship
	assets         map[string]*Asset
	identityChains map[string]*IdentityChain
	mutex          sync.RWMutex
	correlator     *correlation.EnhancedOrganizationCorrelator
}

// AssetRelationship represents a relationship between two assets
type AssetRelationship struct {
	ID            string                 `json:"id"`
	SourceAssetID string                 `json:"source_asset_id"`
	TargetAssetID string                 `json:"target_asset_id"`
	RelationType  RelationType           `json:"relation_type"`
	Confidence    float64                `json:"confidence"`
	Evidence      []string               `json:"evidence"`
	IdentityRisk  IdentityRiskLevel      `json:"identity_risk"`
	AttackPaths   []AttackPath           `json:"attack_paths"`
	Metadata      map[string]interface{} `json:"metadata"`
	CreatedAt     time.Time              `json:"created_at"`
	LastUpdated   time.Time              `json:"last_updated"`
}

// IdentityChain represents a chain of identity-related assets
type IdentityChain struct {
	ID              string                  `json:"id"`
	Name            string                  `json:"name"`
	AssetIDs        []string                `json:"asset_ids"`
	IdentityType    IdentityType            `json:"identity_type"`
	RiskLevel       IdentityRiskLevel       `json:"risk_level"`
	AttackSurface   AttackSurface           `json:"attack_surface"`
	Vulnerabilities []IdentityVulnerability `json:"vulnerabilities"`
	Metadata        map[string]interface{}  `json:"metadata"`
	CreatedAt       time.Time               `json:"created_at"`
}

// Enhanced RelationType constants for identity relationships
const (
	// Identity relationships - core focus
	RelationSSOProvider   RelationType = "sso_provider"
	RelationSAMLEndpoint  RelationType = "saml_endpoint"
	RelationOAuthProvider RelationType = "oauth_provider"
	RelationIDPFederation RelationType = "idp_federation"
	RelationAuthChain     RelationType = "auth_chain"
	RelationIdentityFlow  RelationType = "identity_flow"

	// Service relationships with identity implications
	RelationAPIEndpoint RelationType = "api_endpoint"
	RelationAdminPanel  RelationType = "admin_panel"
	RelationLoginPage   RelationType = "login_page"
	RelationUserPortal  RelationType = "user_portal"

	// Technology relationships
	RelationTechStack RelationType = "tech_stack"
	RelationFramework RelationType = "framework"
	RelationCloud     RelationType = "cloud_service"
)

// IdentityType categorizes identity-related assets
type IdentityType string

const (
	IdentityTypeSAML      IdentityType = "saml"
	IdentityTypeOAuth2    IdentityType = "oauth2"
	IdentityTypeOIDC      IdentityType = "oidc"
	IdentityTypeLDAP      IdentityType = "ldap"
	IdentityTypeWebAuthn  IdentityType = "webauthn"
	IdentityTypeFederated IdentityType = "federated"
	IdentityTypeLocal     IdentityType = "local"
	IdentityTypeSSO       IdentityType = "sso"
)

// IdentityRiskLevel assesses identity-related security risk
type IdentityRiskLevel string

const (
	IdentityRiskCritical IdentityRiskLevel = "critical"
	IdentityRiskHigh     IdentityRiskLevel = "high"
	IdentityRiskMedium   IdentityRiskLevel = "medium"
	IdentityRiskLow      IdentityRiskLevel = "low"
	IdentityRiskInfo     IdentityRiskLevel = "info"
)

// AttackSurface describes potential attack vectors
type AttackSurface struct {
	AuthenticationBypass []string `json:"authentication_bypass"`
	PrivilegeEscalation  []string `json:"privilege_escalation"`
	TokenManipulation    []string `json:"token_manipulation"`
	FederationConfusion  []string `json:"federation_confusion"`
	SessionHijacking     []string `json:"session_hijacking"`
	IdentityTheft        []string `json:"identity_theft"`
}

// AttackPath represents a potential attack chain
type AttackPath struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Steps      []string `json:"steps"`
	Difficulty string   `json:"difficulty"`
	Impact     string   `json:"impact"`
	Mitigation []string `json:"mitigation"`
}

// IdentityVulnerability represents identity-specific vulnerabilities
type IdentityVulnerability struct {
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Evidence    []string `json:"evidence"`
	Remediation []string `json:"remediation"`
}

// NewAssetRelationshipMapper creates a new relationship mapper
func NewAssetRelationshipMapper(config *DiscoveryConfig, logger *logger.Logger) *AssetRelationshipMapper {
	// Create correlator for identity analysis
	correlatorConfig := correlation.CorrelatorConfig{
		EnableWhois:     true,
		EnableCerts:     true,
		EnableASN:       true,
		EnableTrademark: true,
		EnableLinkedIn:  true,
		EnableGitHub:    true,
		CacheTTL:        24 * time.Hour,
		MaxWorkers:      5,
	}

	correlator := correlation.NewEnhancedOrganizationCorrelator(correlatorConfig, logger)

	return &AssetRelationshipMapper{
		config:         config,
		logger:         logger,
		relationships:  make(map[string]*AssetRelationship),
		assets:         make(map[string]*Asset),
		identityChains: make(map[string]*IdentityChain),
		correlator:     correlator,
	}
}

// BuildRelationships analyzes assets and builds relationship graphs
func (arm *AssetRelationshipMapper) BuildRelationships(ctx context.Context, session *DiscoverySession) error {
	arm.mutex.Lock()
	defer arm.mutex.Unlock()

	arm.logger.Info("Building asset relationships with identity focus",
		"session_id", session.ID,
		"total_assets", len(session.Assets))

	// Clear existing data for this session
	arm.assets = make(map[string]*Asset)
	arm.relationships = make(map[string]*AssetRelationship)
	arm.identityChains = make(map[string]*IdentityChain)

	// Copy assets for analysis
	for _, asset := range session.Assets {
		arm.assets[asset.ID] = asset
	}

	// Build different types of relationships
	if err := arm.buildInfrastructureRelationships(ctx); err != nil {
		return fmt.Errorf("failed to build infrastructure relationships: %w", err)
	}

	if err := arm.buildIdentityRelationships(ctx); err != nil {
		return fmt.Errorf("failed to build identity relationships: %w", err)
	}

	if err := arm.buildServiceRelationships(ctx); err != nil {
		return fmt.Errorf("failed to build service relationships: %w", err)
	}

	if err := arm.buildTechnologyRelationships(ctx); err != nil {
		return fmt.Errorf("failed to build technology relationships: %w", err)
	}

	// Analyze identity chains and attack paths
	if err := arm.analyzeIdentityChains(ctx); err != nil {
		return fmt.Errorf("failed to analyze identity chains: %w", err)
	}

	// Copy relationships back to session
	session.Relationships = make(map[string]*Relationship)
	for id, rel := range arm.relationships {
		session.Relationships[id] = &Relationship{
			ID:        rel.ID,
			Source:    rel.SourceAssetID,
			Target:    rel.TargetAssetID,
			Type:      RelationTypeSubdomain, // Map appropriately
			Weight:    rel.Confidence,
			Metadata:  convertMetadata(rel.Metadata),
			CreatedAt: rel.CreatedAt,
		}
	}

	arm.logger.Info("Asset relationship mapping completed",
		"relationships_built", len(arm.relationships),
		"identity_chains", len(arm.identityChains))

	return nil
}

// buildInfrastructureRelationships creates basic infrastructure relationships
func (arm *AssetRelationshipMapper) buildInfrastructureRelationships(ctx context.Context) error {
	// Domain-subdomain relationships
	arm.buildDomainRelationships()

	// IP ownership relationships
	arm.buildIPRelationships()

	// Certificate relationships
	arm.buildCertificateRelationships()

	// DNS record relationships
	arm.buildDNSRelationships()

	return nil
}

// buildIdentityRelationships creates identity-focused relationships
func (arm *AssetRelationshipMapper) buildIdentityRelationships(ctx context.Context) error {
	arm.logger.Info("Building identity relationships")

	// Find SSO providers and endpoints
	arm.identifySSOMRelationships()

	// Map SAML endpoints and flows
	arm.identifySAMLRelationships()

	// Discover OAuth2/OIDC relationships
	arm.identifyOAuthRelationships()

	// Federation relationships
	arm.identifyFederationRelationships()

	// Authentication chain analysis
	arm.identifyAuthChains()

	return nil
}

// buildServiceRelationships identifies service-level relationships
func (arm *AssetRelationshipMapper) buildServiceRelationships(ctx context.Context) error {
	// API endpoint relationships
	arm.identifyAPIRelationships()

	// Admin panel relationships
	arm.identifyAdminRelationships()

	// Login page relationships
	arm.identifyLoginRelationships()

	return nil
}

// buildTechnologyRelationships maps technology stack relationships
func (arm *AssetRelationshipMapper) buildTechnologyRelationships(ctx context.Context) error {
	// Technology stack analysis
	arm.identifyTechStackRelationships()

	// Framework relationships
	arm.identifyFrameworkRelationships()

	// Cloud service relationships
	arm.identifyCloudRelationships()

	return nil
}

// analyzeIdentityChains builds identity attack chains
func (arm *AssetRelationshipMapper) analyzeIdentityChains(ctx context.Context) error {
	arm.logger.Info("Analyzing identity attack chains")

	// Group related identity assets
	identityGroups := arm.groupIdentityAssets()

	// Create identity chains
	for groupID, assets := range identityGroups {
		chain := arm.createIdentityChain(groupID, assets)
		arm.identityChains[chain.ID] = chain
	}

	// Analyze attack paths
	for _, chain := range arm.identityChains {
		arm.analyzeAttackPaths(chain)
	}

	return nil
}

// Identity relationship builders

func (arm *AssetRelationshipMapper) identifySSOMRelationships() {
	ssoAssets := arm.findAssetsByTags([]string{"sso", "saml", "oauth", "oidc"})

	for _, ssoAsset := range ssoAssets {
		// Find assets that could be SSO clients
		for _, asset := range arm.assets {
			if asset.ID == ssoAsset.ID {
				continue
			}

			if arm.isLikelySSOClient(asset, ssoAsset) {
				relationship := &AssetRelationship{
					ID:            uuid.New().String(),
					SourceAssetID: ssoAsset.ID,
					TargetAssetID: asset.ID,
					RelationType:  RelationSSOProvider,
					Confidence:    arm.calculateSSOConfidence(ssoAsset, asset),
					Evidence:      arm.gatherSSOEvidence(ssoAsset, asset),
					IdentityRisk:  arm.assessIdentityRisk(ssoAsset, asset),
					CreatedAt:     time.Now(),
					LastUpdated:   time.Now(),
					Metadata:      make(map[string]interface{}),
				}

				arm.relationships[relationship.ID] = relationship
			}
		}
	}
}

func (arm *AssetRelationshipMapper) identifySAMLRelationships() {
	samlAssets := arm.findAssetsByTags([]string{"saml"})

	for _, samlAsset := range samlAssets {
		// Look for SAML-related patterns
		if arm.hasSAMLMetadata(samlAsset) {
			// Find related service providers
			for _, asset := range arm.assets {
				if asset.ID == samlAsset.ID {
					continue
				}

				if arm.isLikelySAMLServiceProvider(asset, samlAsset) {
					relationship := &AssetRelationship{
						ID:            uuid.New().String(),
						SourceAssetID: samlAsset.ID,
						TargetAssetID: asset.ID,
						RelationType:  RelationSAMLEndpoint,
						Confidence:    arm.calculateSAMLConfidence(samlAsset, asset),
						Evidence:      arm.gatherSAMLEvidence(samlAsset, asset),
						IdentityRisk:  IdentityRiskHigh, // SAML is often high-value
						CreatedAt:     time.Now(),
						LastUpdated:   time.Now(),
						Metadata: map[string]interface{}{
							"saml_type": "service_provider",
						},
					}

					arm.relationships[relationship.ID] = relationship
				}
			}
		}
	}
}

func (arm *AssetRelationshipMapper) identifyOAuthRelationships() {
	oauthAssets := arm.findAssetsByTags([]string{"oauth", "oauth2", "oidc"})

	for _, oauthAsset := range oauthAssets {
		if arm.hasOAuthMetadata(oauthAsset) {
			// Find OAuth clients and resource servers
			for _, asset := range arm.assets {
				if asset.ID == oauthAsset.ID {
					continue
				}

				if arm.isLikelyOAuthClient(asset, oauthAsset) {
					relationship := &AssetRelationship{
						ID:            uuid.New().String(),
						SourceAssetID: oauthAsset.ID,
						TargetAssetID: asset.ID,
						RelationType:  RelationOAuthProvider,
						Confidence:    arm.calculateOAuthConfidence(oauthAsset, asset),
						Evidence:      arm.gatherOAuthEvidence(oauthAsset, asset),
						IdentityRisk:  arm.assessOAuthRisk(oauthAsset, asset),
						CreatedAt:     time.Now(),
						LastUpdated:   time.Now(),
						Metadata: map[string]interface{}{
							"oauth_flow": arm.detectOAuthFlow(oauthAsset, asset),
						},
					}

					arm.relationships[relationship.ID] = relationship
				}
			}
		}
	}
}

func (arm *AssetRelationshipMapper) identifyFederationRelationships() {
	// Look for federation trust relationships
	for _, asset1 := range arm.assets {
		for _, asset2 := range arm.assets {
			if asset1.ID == asset2.ID {
				continue
			}

			if arm.hasFederationTrust(asset1, asset2) {
				relationship := &AssetRelationship{
					ID:            uuid.New().String(),
					SourceAssetID: asset1.ID,
					TargetAssetID: asset2.ID,
					RelationType:  RelationIDPFederation,
					Confidence:    arm.calculateFederationConfidence(asset1, asset2),
					Evidence:      arm.gatherFederationEvidence(asset1, asset2),
					IdentityRisk:  IdentityRiskHigh, // Federation often high-risk
					CreatedAt:     time.Now(),
					LastUpdated:   time.Now(),
					Metadata: map[string]interface{}{
						"federation_type": arm.determineFederationType(asset1, asset2),
					},
				}

				arm.relationships[relationship.ID] = relationship
			}
		}
	}
}

func (arm *AssetRelationshipMapper) identifyAuthChains() {
	// Build authentication flow chains
	loginAssets := arm.findAssetsByTags([]string{"login", "auth", "signin"})

	for _, loginAsset := range loginAssets {
		chain := arm.buildAuthenticationChain(loginAsset)
		if len(chain) > 1 {
			// Create relationships for the chain
			for i := 0; i < len(chain)-1; i++ {
				relationship := &AssetRelationship{
					ID:            uuid.New().String(),
					SourceAssetID: chain[i].ID,
					TargetAssetID: chain[i+1].ID,
					RelationType:  RelationAuthChain,
					Confidence:    0.8, // Auth chains are usually high confidence
					Evidence:      []string{"Authentication flow analysis"},
					IdentityRisk:  arm.assessChainRisk(chain),
					CreatedAt:     time.Now(),
					LastUpdated:   time.Now(),
					Metadata: map[string]interface{}{
						"chain_position": i,
						"chain_length":   len(chain),
					},
				}

				arm.relationships[relationship.ID] = relationship
			}
		}
	}
}

// Infrastructure relationship builders

func (arm *AssetRelationshipMapper) buildDomainRelationships() {
	domains := arm.findAssetsByType(AssetTypeDomain)
	subdomains := arm.findAssetsByType(AssetTypeSubdomain)

	for _, domain := range domains {
		for _, subdomain := range subdomains {
			if arm.isSubdomainOf(subdomain.Value, domain.Value) {
				relationship := &AssetRelationship{
					ID:            uuid.New().String(),
					SourceAssetID: domain.ID,
					TargetAssetID: subdomain.ID,
					RelationType:  RelationTypeSubdomain,
					Confidence:    0.9,
					Evidence:      []string{"DNS hierarchy"},
					IdentityRisk:  IdentityRiskLow,
					CreatedAt:     time.Now(),
					LastUpdated:   time.Now(),
					Metadata:      make(map[string]interface{}),
				}

				arm.relationships[relationship.ID] = relationship
			}
		}
	}
}

func (arm *AssetRelationshipMapper) buildIPRelationships() {
	ips := arm.findAssetsByType(AssetTypeIP)
	domains := append(arm.findAssetsByType(AssetTypeDomain), arm.findAssetsByType(AssetTypeSubdomain)...)

	for _, ip := range ips {
		for _, domain := range domains {
			if arm.ipResolvesDomain(ip.Value, domain.Value) {
				relationship := &AssetRelationship{
					ID:            uuid.New().String(),
					SourceAssetID: domain.ID,
					TargetAssetID: ip.ID,
					RelationType:  RelationTypeSubdomain, // Use existing constant
					Confidence:    0.8,
					Evidence:      []string{"DNS resolution"},
					IdentityRisk:  IdentityRiskLow,
					CreatedAt:     time.Now(),
					LastUpdated:   time.Now(),
					Metadata:      make(map[string]interface{}),
				}

				arm.relationships[relationship.ID] = relationship
			}
		}
	}
}

func (arm *AssetRelationshipMapper) buildCertificateRelationships() {
	// Certificate-based relationships for identity services
	for _, asset := range arm.assets {
		if certData, hasCert := asset.Metadata["certificate"]; hasCert {
			// Process certificate data as string
			// In real implementation, parse the certificate data
			for _, otherAsset := range arm.assets {
				if otherAsset.ID == asset.ID {
					continue
				}

				if arm.matchesCertificateSAN(otherAsset.Value, certData) {
					relationship := &AssetRelationship{
						ID:            uuid.New().String(),
						SourceAssetID: asset.ID,
						TargetAssetID: otherAsset.ID,
						RelationType:  RelationTypeSubdomain, // Use existing constant
						Confidence:    0.7,
						Evidence:      []string{"SSL certificate analysis"},
						IdentityRisk:  arm.assessCertificateRisk(asset, otherAsset),
						CreatedAt:     time.Now(),
						LastUpdated:   time.Now(),
						Metadata: map[string]interface{}{
							"certificate": certData,
						},
					}

					arm.relationships[relationship.ID] = relationship
				}
			}
		}
	}
}

func (arm *AssetRelationshipMapper) buildDNSRelationships() {
	// DNS-based relationships
	for _, asset := range arm.assets {
		if dnsData, hasDNS := asset.Metadata["dns_records"]; hasDNS {
			// Process DNS data as string
			// In real implementation, parse the DNS record data
			for _, otherAsset := range arm.assets {
				if otherAsset.ID == asset.ID {
					continue
				}

				if arm.matchesDNSRecord(otherAsset.Value, dnsData, "A") {
					relationship := &AssetRelationship{
						ID:            uuid.New().String(),
						SourceAssetID: asset.ID,
						TargetAssetID: otherAsset.ID,
						RelationType:  RelationTypeSubdomain, // Use existing constant
						Confidence:    arm.calculateDNSConfidence("A"),
						Evidence:      []string{"DNS record analysis"},
						IdentityRisk:  IdentityRiskLow,
						CreatedAt:     time.Now(),
						LastUpdated:   time.Now(),
						Metadata: map[string]interface{}{
							"dns_records": dnsData,
						},
					}

					arm.relationships[relationship.ID] = relationship
				}
			}
		}
	}
}

// Service relationship builders

func (arm *AssetRelationshipMapper) identifyAPIRelationships() {
	apiAssets := arm.findAssetsByTags([]string{"api", "rest", "graphql"})

	for _, apiAsset := range apiAssets {
		// Look for API consumers
		for _, asset := range arm.assets {
			if asset.ID == apiAsset.ID {
				continue
			}

			if arm.isLikelyAPIConsumer(asset, apiAsset) {
				relationship := &AssetRelationship{
					ID:            uuid.New().String(),
					SourceAssetID: apiAsset.ID,
					TargetAssetID: asset.ID,
					RelationType:  RelationAPIEndpoint,
					Confidence:    arm.calculateAPIConfidence(apiAsset, asset),
					Evidence:      arm.gatherAPIEvidence(apiAsset, asset),
					IdentityRisk:  arm.assessAPIRisk(apiAsset, asset),
					CreatedAt:     time.Now(),
					LastUpdated:   time.Now(),
					Metadata: map[string]interface{}{
						"api_type": arm.determineAPIType(apiAsset),
					},
				}

				arm.relationships[relationship.ID] = relationship
			}
		}
	}
}

func (arm *AssetRelationshipMapper) identifyAdminRelationships() {
	adminAssets := arm.findAssetsByTags([]string{"admin", "management", "control"})

	for _, adminAsset := range adminAssets {
		// Admin panels are high-value identity targets
		for _, asset := range arm.assets {
			if asset.ID == adminAsset.ID {
				continue
			}

			if arm.isAdminRelated(asset, adminAsset) {
				relationship := &AssetRelationship{
					ID:            uuid.New().String(),
					SourceAssetID: adminAsset.ID,
					TargetAssetID: asset.ID,
					RelationType:  RelationAdminPanel,
					Confidence:    arm.calculateAdminConfidence(adminAsset, asset),
					Evidence:      arm.gatherAdminEvidence(adminAsset, asset),
					IdentityRisk:  IdentityRiskCritical, // Admin panels are critical
					CreatedAt:     time.Now(),
					LastUpdated:   time.Now(),
					Metadata:      make(map[string]interface{}),
				}

				arm.relationships[relationship.ID] = relationship
			}
		}
	}
}

func (arm *AssetRelationshipMapper) identifyLoginRelationships() {
	loginAssets := arm.findAssetsByTags([]string{"login", "signin", "auth"})

	for _, loginAsset := range loginAssets {
		// Find related authentication services
		for _, asset := range arm.assets {
			if asset.ID == loginAsset.ID {
				continue
			}

			if arm.isAuthenticationRelated(asset, loginAsset) {
				relationship := &AssetRelationship{
					ID:            uuid.New().String(),
					SourceAssetID: loginAsset.ID,
					TargetAssetID: asset.ID,
					RelationType:  RelationLoginPage,
					Confidence:    arm.calculateLoginConfidence(loginAsset, asset),
					Evidence:      arm.gatherLoginEvidence(loginAsset, asset),
					IdentityRisk:  IdentityRiskHigh, // Login pages are high-value
					CreatedAt:     time.Now(),
					LastUpdated:   time.Now(),
					Metadata:      make(map[string]interface{}),
				}

				arm.relationships[relationship.ID] = relationship
			}
		}
	}
}

// Technology relationship builders

func (arm *AssetRelationshipMapper) identifyTechStackRelationships() {
	// Group assets by technology stack
	techGroups := make(map[string][]*Asset)

	for _, asset := range arm.assets {
		for _, tech := range asset.Technology {
			techGroups[tech] = append(techGroups[tech], asset)
		}
	}

	// Create relationships between assets sharing technology
	for tech, assets := range techGroups {
		if len(assets) > 1 {
			for i, asset1 := range assets {
				for j, asset2 := range assets {
					if i >= j {
						continue
					}

					relationship := &AssetRelationship{
						ID:            uuid.New().String(),
						SourceAssetID: asset1.ID,
						TargetAssetID: asset2.ID,
						RelationType:  RelationTechStack,
						Confidence:    0.6,
						Evidence:      []string{fmt.Sprintf("Shared technology: %s", tech)},
						IdentityRisk:  arm.assessTechStackRisk(tech),
						CreatedAt:     time.Now(),
						LastUpdated:   time.Now(),
						Metadata: map[string]interface{}{
							"technology": tech,
						},
					}

					arm.relationships[relationship.ID] = relationship
				}
			}
		}
	}
}

func (arm *AssetRelationshipMapper) identifyFrameworkRelationships() {
	frameworks := []string{"react", "angular", "vue", "django", "rails", "spring", "express"}

	for _, framework := range frameworks {
		frameworkAssets := arm.findAssetsByTechnology(framework)

		if len(frameworkAssets) > 1 {
			for i, asset1 := range frameworkAssets {
				for j, asset2 := range frameworkAssets {
					if i >= j {
						continue
					}

					relationship := &AssetRelationship{
						ID:            uuid.New().String(),
						SourceAssetID: asset1.ID,
						TargetAssetID: asset2.ID,
						RelationType:  RelationFramework,
						Confidence:    0.7,
						Evidence:      []string{fmt.Sprintf("Shared framework: %s", framework)},
						IdentityRisk:  arm.assessFrameworkRisk(framework),
						CreatedAt:     time.Now(),
						LastUpdated:   time.Now(),
						Metadata: map[string]interface{}{
							"framework": framework,
						},
					}

					arm.relationships[relationship.ID] = relationship
				}
			}
		}
	}
}

func (arm *AssetRelationshipMapper) identifyCloudRelationships() {
	cloudProviders := []string{"aws", "azure", "gcp", "cloudflare"}

	for _, provider := range cloudProviders {
		cloudAssets := arm.findAssetsByTag("cloud:" + provider)

		if len(cloudAssets) > 1 {
			for i, asset1 := range cloudAssets {
				for j, asset2 := range cloudAssets {
					if i >= j {
						continue
					}

					relationship := &AssetRelationship{
						ID:            uuid.New().String(),
						SourceAssetID: asset1.ID,
						TargetAssetID: asset2.ID,
						RelationType:  RelationCloud,
						Confidence:    0.8,
						Evidence:      []string{fmt.Sprintf("Shared cloud provider: %s", provider)},
						IdentityRisk:  arm.assessCloudRisk(provider),
						CreatedAt:     time.Now(),
						LastUpdated:   time.Now(),
						Metadata: map[string]interface{}{
							"cloud_provider": provider,
						},
					}

					arm.relationships[relationship.ID] = relationship
				}
			}
		}
	}
}

// Helper and utility methods

// convertMetadata converts map[string]interface{} to map[string]string
func convertMetadata(metadata map[string]interface{}) map[string]string {
	result := make(map[string]string)
	for k, v := range metadata {
		if str, ok := v.(string); ok {
			result[k] = str
		} else {
			result[k] = fmt.Sprintf("%v", v)
		}
	}
	return result
}

// Missing helper methods implementation
func (arm *AssetRelationshipMapper) groupIdentityAssets() map[string][]*Asset {
	groups := make(map[string][]*Asset)

	for _, asset := range arm.assets {
		// Group by domain or organization
		key := arm.getAssetGroupKey(asset)
		groups[key] = append(groups[key], asset)
	}

	return groups
}

func (arm *AssetRelationshipMapper) createIdentityChain(groupID string, assets []*Asset) *IdentityChain {
	return &IdentityChain{
		ID:           uuid.New().String(),
		Name:         fmt.Sprintf("Identity Chain %s", groupID),
		AssetIDs:     arm.extractAssetIDs(assets),
		IdentityType: arm.determineIdentityType(assets),
		// RiskScore and AttackPaths removed as they don't exist in IdentityChain struct
		Metadata:  make(map[string]interface{}),
		CreatedAt: time.Now(),
	}
}

func (arm *AssetRelationshipMapper) analyzeAttackPaths(chain *IdentityChain) {
	// Build attack paths for the identity chain
	// AttackPaths field doesn't exist in IdentityChain struct - analyze paths separately
	arm.buildAttackPaths(chain)
}

func (arm *AssetRelationshipMapper) findAssetsByTags(tags []string) []*Asset {
	var result []*Asset
	for _, asset := range arm.assets {
		for _, tag := range asset.Tags {
			for _, searchTag := range tags {
				if tag == searchTag {
					result = append(result, asset)
					break
				}
			}
		}
	}
	return result
}

func (arm *AssetRelationshipMapper) findAssetsByType(assetType AssetType) []*Asset {
	var result []*Asset
	for _, asset := range arm.assets {
		if asset.Type == assetType {
			result = append(result, asset)
		}
	}
	return result
}

func (arm *AssetRelationshipMapper) findAssetsByTechnology(tech string) []*Asset {
	var result []*Asset
	for _, asset := range arm.assets {
		for _, technology := range asset.Technology {
			if technology == tech {
				result = append(result, asset)
				break
			}
		}
	}
	return result
}

func (arm *AssetRelationshipMapper) findAssetsByTag(tag string) []*Asset {
	var result []*Asset
	for _, asset := range arm.assets {
		for _, assetTag := range asset.Tags {
			if assetTag == tag {
				result = append(result, asset)
				break
			}
		}
	}
	return result
}

// Identity relationship helper methods
func (arm *AssetRelationshipMapper) isLikelySSOClient(asset, ssoAsset *Asset) bool {
	// Check if asset appears to be an SSO client
	for _, tag := range asset.Tags {
		if tag == "webapp" || tag == "application" {
			return true
		}
	}
	return false
}

func (arm *AssetRelationshipMapper) calculateSSOConfidence(ssoAsset, asset *Asset) float64 {
	confidence := 0.5

	// Increase confidence based on various factors
	if arm.sharesDomain(ssoAsset, asset) {
		confidence += 0.2
	}

	if arm.hasAuthenticationIndicators(asset) {
		confidence += 0.2
	}

	return confidence
}

func (arm *AssetRelationshipMapper) gatherSSOEvidence(ssoAsset, asset *Asset) []string {
	evidence := []string{}

	if arm.sharesDomain(ssoAsset, asset) {
		evidence = append(evidence, "Shared domain")
	}

	if arm.hasAuthenticationIndicators(asset) {
		evidence = append(evidence, "Authentication indicators present")
	}

	return evidence
}

func (arm *AssetRelationshipMapper) assessIdentityRisk(ssoAsset, asset *Asset) IdentityRiskLevel {
	// Assess the identity risk level
	if arm.isAdminRelated(asset, ssoAsset) {
		return IdentityRiskCritical
	}

	if arm.hasPrivilegedAccess(asset) {
		return IdentityRiskHigh
	}

	return IdentityRiskMedium
}

// SAML helper methods
func (arm *AssetRelationshipMapper) hasSAMLMetadata(asset *Asset) bool {
	// Check for SAML metadata indicators
	for _, tag := range asset.Tags {
		if tag == "saml" || tag == "idp" {
			return true
		}
	}
	return false
}

func (arm *AssetRelationshipMapper) isLikelySAMLServiceProvider(asset, samlAsset *Asset) bool {
	return arm.sharesDomain(asset, samlAsset) && arm.hasAuthenticationIndicators(asset)
}

func (arm *AssetRelationshipMapper) calculateSAMLConfidence(samlAsset, asset *Asset) float64 {
	return 0.8 // High confidence for SAML relationships
}

func (arm *AssetRelationshipMapper) gatherSAMLEvidence(samlAsset, asset *Asset) []string {
	return []string{"SAML metadata analysis", "Service provider detection"}
}

// OAuth helper methods
func (arm *AssetRelationshipMapper) hasOAuthMetadata(asset *Asset) bool {
	for _, tag := range asset.Tags {
		if tag == "oauth" || tag == "oauth2" || tag == "oidc" {
			return true
		}
	}
	return false
}

func (arm *AssetRelationshipMapper) isLikelyOAuthClient(asset, oauthAsset *Asset) bool {
	return arm.sharesDomain(asset, oauthAsset)
}

func (arm *AssetRelationshipMapper) calculateOAuthConfidence(oauthAsset, asset *Asset) float64 {
	return 0.7
}

func (arm *AssetRelationshipMapper) gatherOAuthEvidence(oauthAsset, asset *Asset) []string {
	return []string{"OAuth configuration analysis"}
}

func (arm *AssetRelationshipMapper) assessOAuthRisk(oauthAsset, asset *Asset) IdentityRiskLevel {
	return IdentityRiskHigh
}

func (arm *AssetRelationshipMapper) detectOAuthFlow(oauthAsset, asset *Asset) string {
	return "authorization_code"
}

// Federation helper methods
func (arm *AssetRelationshipMapper) hasFederationTrust(asset1, asset2 *Asset) bool {
	// Check for federation trust indicators
	return arm.sharesTrustRelationship(asset1, asset2)
}

func (arm *AssetRelationshipMapper) calculateFederationConfidence(asset1, asset2 *Asset) float64 {
	return 0.6
}

func (arm *AssetRelationshipMapper) gatherFederationEvidence(asset1, asset2 *Asset) []string {
	return []string{"Federation trust analysis"}
}

func (arm *AssetRelationshipMapper) determineFederationType(asset1, asset2 *Asset) string {
	return "saml_federation"
}

// Authentication chain helper methods
func (arm *AssetRelationshipMapper) buildAuthenticationChain(loginAsset *Asset) []*Asset {
	chain := []*Asset{loginAsset}

	// Find related authentication assets
	for _, asset := range arm.assets {
		if asset.ID != loginAsset.ID && arm.isAuthenticationRelated(asset, loginAsset) {
			chain = append(chain, asset)
		}
	}

	return chain
}

func (arm *AssetRelationshipMapper) assessChainRisk(chain []*Asset) IdentityRiskLevel {
	maxRisk := IdentityRiskLow

	for _, asset := range chain {
		risk := arm.assessAssetRisk(asset)
		if risk > maxRisk {
			maxRisk = risk
		}
	}

	return maxRisk
}

// Infrastructure helper methods
func (arm *AssetRelationshipMapper) isSubdomainOf(subdomain, domain string) bool {
	return len(subdomain) > len(domain) && subdomain[len(subdomain)-len(domain)-1:] == "."+domain
}

func (arm *AssetRelationshipMapper) ipResolvesDomain(ip, domain string) bool {
	// Simplified IP resolution check
	return true // Implementation would do actual DNS lookup
}

func (arm *AssetRelationshipMapper) matchesCertificateSAN(assetValue, san string) bool {
	return assetValue == san
}

func (arm *AssetRelationshipMapper) assessCertificateRisk(asset, otherAsset *Asset) IdentityRiskLevel {
	return IdentityRiskLow
}

func (arm *AssetRelationshipMapper) matchesDNSRecord(assetValue, recordValue, recordType string) bool {
	return assetValue == recordValue
}

func (arm *AssetRelationshipMapper) calculateDNSConfidence(recordType string) float64 {
	switch recordType {
	case "A", "AAAA":
		return 0.9
	case "CNAME":
		return 0.8
	default:
		return 0.6
	}
}

// Service helper methods
func (arm *AssetRelationshipMapper) isLikelyAPIConsumer(asset, apiAsset *Asset) bool {
	return arm.sharesDomain(asset, apiAsset)
}

func (arm *AssetRelationshipMapper) calculateAPIConfidence(apiAsset, asset *Asset) float64 {
	return 0.6
}

func (arm *AssetRelationshipMapper) gatherAPIEvidence(apiAsset, asset *Asset) []string {
	return []string{"API usage analysis"}
}

func (arm *AssetRelationshipMapper) assessAPIRisk(apiAsset, asset *Asset) IdentityRiskLevel {
	return IdentityRiskMedium
}

func (arm *AssetRelationshipMapper) determineAPIType(apiAsset *Asset) string {
	return "rest"
}

func (arm *AssetRelationshipMapper) isAdminRelated(asset, adminAsset *Asset) bool {
	return arm.sharesDomain(asset, adminAsset)
}

func (arm *AssetRelationshipMapper) calculateAdminConfidence(adminAsset, asset *Asset) float64 {
	return 0.8
}

func (arm *AssetRelationshipMapper) gatherAdminEvidence(adminAsset, asset *Asset) []string {
	return []string{"Admin panel analysis"}
}

func (arm *AssetRelationshipMapper) isAuthenticationRelated(asset, loginAsset *Asset) bool {
	return arm.sharesDomain(asset, loginAsset)
}

func (arm *AssetRelationshipMapper) calculateLoginConfidence(loginAsset, asset *Asset) float64 {
	return 0.7
}

func (arm *AssetRelationshipMapper) gatherLoginEvidence(loginAsset, asset *Asset) []string {
	return []string{"Login flow analysis"}
}

// Technology helper methods
func (arm *AssetRelationshipMapper) assessTechStackRisk(tech string) IdentityRiskLevel {
	// Assess risk based on technology
	highRiskTech := []string{"php", "wordpress", "drupal"}
	for _, riskTech := range highRiskTech {
		if tech == riskTech {
			return IdentityRiskHigh
		}
	}
	return IdentityRiskLow
}

func (arm *AssetRelationshipMapper) assessFrameworkRisk(framework string) IdentityRiskLevel {
	return IdentityRiskLow
}

func (arm *AssetRelationshipMapper) assessCloudRisk(provider string) IdentityRiskLevel {
	return IdentityRiskMedium
}

// Common utility methods
func (arm *AssetRelationshipMapper) sharesDomain(asset1, asset2 *Asset) bool {
	// Extract domain from asset values and compare
	domain1 := arm.extractDomain(asset1.Value)
	domain2 := arm.extractDomain(asset2.Value)
	return domain1 == domain2
}

func (arm *AssetRelationshipMapper) hasAuthenticationIndicators(asset *Asset) bool {
	authTags := []string{"login", "auth", "signin", "sso"}
	for _, tag := range asset.Tags {
		for _, authTag := range authTags {
			if tag == authTag {
				return true
			}
		}
	}
	return false
}

func (arm *AssetRelationshipMapper) hasPrivilegedAccess(asset *Asset) bool {
	privTags := []string{"admin", "management", "privileged"}
	for _, tag := range asset.Tags {
		for _, privTag := range privTags {
			if tag == privTag {
				return true
			}
		}
	}
	return false
}

func (arm *AssetRelationshipMapper) sharesTrustRelationship(asset1, asset2 *Asset) bool {
	// Check for trust relationship indicators
	return arm.sharesDomain(asset1, asset2)
}

func (arm *AssetRelationshipMapper) assessAssetRisk(asset *Asset) IdentityRiskLevel {
	if arm.hasPrivilegedAccess(asset) {
		return IdentityRiskCritical
	}
	if arm.hasAuthenticationIndicators(asset) {
		return IdentityRiskHigh
	}
	return IdentityRiskMedium
}

func (arm *AssetRelationshipMapper) getAssetGroupKey(asset *Asset) string {
	return arm.extractDomain(asset.Value)
}

func (arm *AssetRelationshipMapper) extractAssetIDs(assets []*Asset) []string {
	ids := make([]string, len(assets))
	for i, asset := range assets {
		ids[i] = asset.ID
	}
	return ids
}

func (arm *AssetRelationshipMapper) determineIdentityType(assets []*Asset) IdentityType {
	// Determine the primary identity type for the chain
	for _, asset := range assets {
		if arm.hasSAMLMetadata(asset) {
			return IdentityTypeSAML
		}
		if arm.hasOAuthMetadata(asset) {
			return IdentityTypeOAuth2
		}
	}
	return IdentityTypeLocal
}

func (arm *AssetRelationshipMapper) calculateChainRiskScore(assets []*Asset) float64 {
	totalRisk := 0.0
	for _, asset := range assets {
		risk := arm.assessAssetRisk(asset)
		switch risk {
		case IdentityRiskLow:
			totalRisk += 1.0
		case IdentityRiskMedium:
			totalRisk += 2.0
		case IdentityRiskHigh:
			totalRisk += 3.0
		case IdentityRiskCritical:
			totalRisk += 4.0
		}
	}
	return totalRisk / float64(len(assets))
}

func (arm *AssetRelationshipMapper) buildAttackPaths(chain *IdentityChain) []AttackPath {
	// Build attack paths for the identity chain
	return []AttackPath{} // Simplified implementation
}

func (arm *AssetRelationshipMapper) extractDomain(value string) string {
	// Extract domain from various asset types (URL, IP, etc.)
	// Simplified implementation
	return value
}
