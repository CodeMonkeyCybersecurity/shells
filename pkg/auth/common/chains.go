package common

import (
	"fmt"
	"strings"
)

// ChainPattern represents a pattern for attack chains
type ChainPattern struct {
	Name          string
	Description   string
	Steps         []string
	Prerequisites []string
	Impact        string
	Severity      string
}

// AuthChainAnalyzer analyzes authentication bypass chains
type AuthChainAnalyzer struct {
	logger Logger
}

// NewAuthChainAnalyzer creates a new chain analyzer
func NewAuthChainAnalyzer(logger Logger) *AuthChainAnalyzer {
	return &AuthChainAnalyzer{
		logger: logger,
	}
}

// FindBypassChains finds authentication bypass chains
func (a *AuthChainAnalyzer) FindBypassChains(config AuthConfiguration, vulnerabilities []Vulnerability) []AttackChain {
	chains := []AttackChain{}

	// Common bypass patterns
	patterns := []ChainPattern{
		{
			Name:        "WebAuthn to Password Downgrade",
			Description: "Bypass WebAuthn by downgrading to password authentication",
			Steps:       []string{"WEBAUTHN_REGISTRATION", "ACCOUNT_RECOVERY", "PASSWORD_RESET"},
			Impact:      "Bypass strong authentication",
			Severity:    "HIGH",
		},
		{
			Name:        "OAuth2 to SAML Confusion",
			Description: "Confuse OAuth2 and SAML authentication flows",
			Steps:       []string{"OAUTH2_LOGIN", "SAML_ASSERTION", "SESSION_FIXATION"},
			Impact:      "Authentication bypass through protocol confusion",
			Severity:    "CRITICAL",
		},
		{
			Name:        "SAML to Local Account Takeover",
			Description: "Use SAML vulnerabilities for local account takeover",
			Steps:       []string{"SAML_LOGIN", "PROFILE_UPDATE", "EMAIL_CHANGE"},
			Impact:      "Complete account takeover",
			Severity:    "CRITICAL",
		},
		{
			Name:        "JWT to Session Upgrade",
			Description: "Forge JWT tokens to escalate privileges",
			Steps:       []string{"JWT_WEAK_SECRET", "TOKEN_FORGE", "PRIVILEGE_ESCALATION"},
			Impact:      "Administrative access",
			Severity:    "CRITICAL",
		},
		{
			Name:        "Federation Bypass Chain",
			Description: "Bypass federation trust through confused deputy",
			Steps:       []string{"FEDERATION_DISCOVERY", "TRUST_CONFUSION", "IDENTITY_SPOOFING"},
			Impact:      "Authenticate as any federated user",
			Severity:    "CRITICAL",
		},
	}

	for _, pattern := range patterns {
		if chain := a.detectChain(config, vulnerabilities, pattern); chain != nil {
			chains = append(chains, *chain)
		}
	}

	// Look for cross-protocol chains
	crossChains := a.findCrossProtocolChains(config, vulnerabilities)
	chains = append(chains, crossChains...)

	return chains
}

// detectChain detects if a specific chain pattern is possible
func (a *AuthChainAnalyzer) detectChain(config AuthConfiguration, vulnerabilities []Vulnerability, pattern ChainPattern) *AttackChain {
	// Check if we have the required protocols
	protocolMap := make(map[AuthProtocol]bool)
	for _, endpoint := range config.Endpoints {
		protocolMap[endpoint.Protocol] = true
	}

	// Check if we have relevant vulnerabilities
	vulnTypes := make(map[string][]Vulnerability)
	for _, vuln := range vulnerabilities {
		vulnTypes[vuln.Type] = append(vulnTypes[vuln.Type], vuln)
	}

	// Build attack steps
	steps := []AttackStep{}
	stepSuccess := true

	for i, stepType := range pattern.Steps {
		step := AttackStep{
			Order:       i + 1,
			Technique:   stepType,
			Description: a.getStepDescription(stepType),
			Success:     false,
		}

		// Check if we can execute this step
		if a.canExecuteStep(stepType, protocolMap, vulnTypes) {
			step.Success = true
			step.Protocol = a.getStepProtocol(stepType)

			// Add evidence from relevant vulnerabilities
			if vulns, exists := vulnTypes[a.getVulnTypeForStep(stepType)]; exists {
				for _, vuln := range vulns {
					step.Evidence = append(step.Evidence, vuln.Evidence...)
				}
			}
		} else {
			stepSuccess = false
		}

		steps = append(steps, step)
	}

	// Only return chain if all steps are possible
	if stepSuccess && len(steps) > 1 {
		return &AttackChain{
			ID:            fmt.Sprintf("CHAIN_%s", strings.ToUpper(strings.ReplaceAll(pattern.Name, " ", "_"))),
			Name:          pattern.Name,
			Description:   pattern.Description,
			Steps:         steps,
			Impact:        pattern.Impact,
			Severity:      pattern.Severity,
			Prerequisites: pattern.Prerequisites,
			Mitigations:   a.generateMitigations(pattern),
		}
	}

	return nil
}

// findCrossProtocolChains finds chains across different protocols
func (a *AuthChainAnalyzer) findCrossProtocolChains(config AuthConfiguration, vulnerabilities []Vulnerability) []AttackChain {
	chains := []AttackChain{}

	// Group vulnerabilities by protocol
	protocolVulns := make(map[AuthProtocol][]Vulnerability)
	for _, vuln := range vulnerabilities {
		protocolVulns[vuln.Protocol] = append(protocolVulns[vuln.Protocol], vuln)
	}

	// Find high-impact cross-protocol combinations
	if len(protocolVulns) >= 2 {
		protocols := make([]AuthProtocol, 0, len(protocolVulns))
		for protocol := range protocolVulns {
			protocols = append(protocols, protocol)
		}

		// Check for specific high-value combinations
		combinations := []struct {
			protocols []AuthProtocol
			name      string
			impact    string
		}{
			{
				protocols: []AuthProtocol{ProtocolSAML, ProtocolOAuth2},
				name:      "SAML-OAuth2 Confusion",
				impact:    "Federation confusion leading to authentication bypass",
			},
			{
				protocols: []AuthProtocol{ProtocolWebAuthn, ProtocolOAuth2},
				name:      "WebAuthn-OAuth2 Downgrade",
				impact:    "Bypass strong authentication through OAuth2 fallback",
			},
			{
				protocols: []AuthProtocol{ProtocolOIDC, ProtocolJWT},
				name:      "OIDC-JWT Confusion",
				impact:    "Token confusion leading to privilege escalation",
			},
		}

		for _, combo := range combinations {
			if a.hasAllProtocols(protocols, combo.protocols) {
				chain := a.buildCrossProtocolChain(combo, protocolVulns)
				if chain != nil {
					chains = append(chains, *chain)
				}
			}
		}
	}

	return chains
}

// buildCrossProtocolChain builds a cross-protocol attack chain
func (a *AuthChainAnalyzer) buildCrossProtocolChain(combo struct {
	protocols []AuthProtocol
	name      string
	impact    string
}, protocolVulns map[AuthProtocol][]Vulnerability) *AttackChain {

	steps := []AttackStep{}
	order := 1

	for _, protocol := range combo.protocols {
		if vulns, exists := protocolVulns[protocol]; exists {
			// Use the highest severity vulnerability for this protocol
			var highestVuln *Vulnerability
			for _, vuln := range vulns {
				if highestVuln == nil || a.getSeverityScore(vuln.Severity) > a.getSeverityScore(highestVuln.Severity) {
					highestVuln = &vuln
				}
			}

			if highestVuln != nil {
				step := AttackStep{
					Order:       order,
					Protocol:    protocol,
					Technique:   highestVuln.Type,
					Description: highestVuln.Description,
					Success:     true,
					Evidence:    highestVuln.Evidence,
				}
				steps = append(steps, step)
				order++
			}
		}
	}

	if len(steps) >= 2 {
		return &AttackChain{
			ID:          fmt.Sprintf("CROSS_PROTOCOL_%s", strings.ToUpper(strings.ReplaceAll(combo.name, " ", "_"))),
			Name:        combo.name,
			Description: fmt.Sprintf("Cross-protocol attack chain involving %s", combo.name),
			Steps:       steps,
			Impact:      combo.impact,
			Severity:    "CRITICAL",
			Prerequisites: []string{
				"Multiple authentication protocols enabled",
				"Vulnerable implementations in each protocol",
			},
			Mitigations: []string{
				"Implement protocol isolation",
				"Use consistent security controls across protocols",
				"Implement proper session management",
			},
		}
	}

	return nil
}

// Helper functions

func (a *AuthChainAnalyzer) getStepDescription(stepType string) string {
	descriptions := map[string]string{
		"WEBAUTHN_REGISTRATION": "Register malicious WebAuthn authenticator",
		"ACCOUNT_RECOVERY":      "Initiate account recovery process",
		"PASSWORD_RESET":        "Reset password to bypass WebAuthn",
		"OAUTH2_LOGIN":          "Authenticate via OAuth2 provider",
		"SAML_ASSERTION":        "Inject malicious SAML assertion",
		"SESSION_FIXATION":      "Fix session to gain access",
		"SAML_LOGIN":            "Authenticate via SAML",
		"PROFILE_UPDATE":        "Update user profile information",
		"EMAIL_CHANGE":          "Change email address",
		"JWT_WEAK_SECRET":       "Exploit weak JWT secret",
		"TOKEN_FORGE":           "Forge JWT token",
		"PRIVILEGE_ESCALATION":  "Escalate privileges",
		"FEDERATION_DISCOVERY":  "Discover federation endpoints",
		"TRUST_CONFUSION":       "Confuse trust relationships",
		"IDENTITY_SPOOFING":     "Spoof user identity",
	}

	if desc, exists := descriptions[stepType]; exists {
		return desc
	}
	return stepType
}

func (a *AuthChainAnalyzer) canExecuteStep(stepType string, protocols map[AuthProtocol]bool, vulns map[string][]Vulnerability) bool {
	// Map step types to required protocols and vulnerabilities
	requirements := map[string]struct {
		protocol AuthProtocol
		vulnType string
	}{
		"WEBAUTHN_REGISTRATION": {ProtocolWebAuthn, "WebAuthn Vulnerability"},
		"OAUTH2_LOGIN":          {ProtocolOAuth2, "OAuth2 Vulnerability"},
		"SAML_ASSERTION":        {ProtocolSAML, "SAML Vulnerability"},
		"SAML_LOGIN":            {ProtocolSAML, "SAML Vulnerability"},
		"JWT_WEAK_SECRET":       {ProtocolJWT, "JWT Vulnerability"},
	}

	if req, exists := requirements[stepType]; exists {
		return protocols[req.protocol] && len(vulns[req.vulnType]) > 0
	}

	return true // Default to true for generic steps
}

func (a *AuthChainAnalyzer) getStepProtocol(stepType string) AuthProtocol {
	protocolMap := map[string]AuthProtocol{
		"WEBAUTHN_REGISTRATION": ProtocolWebAuthn,
		"OAUTH2_LOGIN":          ProtocolOAuth2,
		"SAML_ASSERTION":        ProtocolSAML,
		"SAML_LOGIN":            ProtocolSAML,
		"JWT_WEAK_SECRET":       ProtocolJWT,
	}

	if protocol, exists := protocolMap[stepType]; exists {
		return protocol
	}

	return ""
}

func (a *AuthChainAnalyzer) getVulnTypeForStep(stepType string) string {
	vulnMap := map[string]string{
		"WEBAUTHN_REGISTRATION": "WebAuthn Vulnerability",
		"OAUTH2_LOGIN":          "OAuth2 Vulnerability",
		"SAML_ASSERTION":        "SAML Vulnerability",
		"SAML_LOGIN":            "SAML Vulnerability",
		"JWT_WEAK_SECRET":       "JWT Vulnerability",
	}

	if vulnType, exists := vulnMap[stepType]; exists {
		return vulnType
	}

	return ""
}

func (a *AuthChainAnalyzer) generateMitigations(pattern ChainPattern) []string {
	mitigations := []string{
		"Implement defense in depth",
		"Use consistent security controls across authentication methods",
		"Implement proper session management",
		"Use secure defaults",
		"Regular security assessments",
	}

	// Add pattern-specific mitigations
	switch pattern.Name {
	case "WebAuthn to Password Downgrade":
		mitigations = append(mitigations, "Disable password fallback after WebAuthn registration")
	case "OAuth2 to SAML Confusion":
		mitigations = append(mitigations, "Implement protocol isolation")
	case "JWT to Session Upgrade":
		mitigations = append(mitigations, "Use strong JWT secrets and regular rotation")
	}

	return mitigations
}

func (a *AuthChainAnalyzer) hasAllProtocols(available []AuthProtocol, required []AuthProtocol) bool {
	availableMap := make(map[AuthProtocol]bool)
	for _, protocol := range available {
		availableMap[protocol] = true
	}

	for _, protocol := range required {
		if !availableMap[protocol] {
			return false
		}
	}

	return true
}

func (a *AuthChainAnalyzer) getSeverityScore(severity string) int {
	scores := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
	}

	if score, exists := scores[severity]; exists {
		return score
	}

	return 0
}
