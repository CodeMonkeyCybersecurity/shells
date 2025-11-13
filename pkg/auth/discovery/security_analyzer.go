package discovery

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

// SecurityAnalyzer analyzes authentication implementations for security features and vulnerabilities
type SecurityAnalyzer struct {
	logger *logger.Logger
}

// NewSecurityAnalyzer creates a new security analyzer
func NewSecurityAnalyzer(logger *logger.Logger) *SecurityAnalyzer {
	return &SecurityAnalyzer{
		logger: logger,
	}
}

// AnalyzeImplementation analyzes an auth implementation for security features and vulnerabilities
func (s *SecurityAnalyzer) AnalyzeImplementation(impl *AuthImplementation) ([]string, []string) {
	var features []string
	var vulnerabilities []string

	s.logger.Debug("Analyzing authentication implementation security",
		"type", impl.Type,
		"domain", impl.Domain)

	switch impl.Type {
	case AuthTypeOAuth2, AuthTypeOIDC:
		features = append(features,
			"Token-based authentication",
			"Delegated authorization",
			"Scope-based access control",
		)

		// Check for PKCE
		if s.hasTokenEndpointAuth(impl) {
			features = append(features, "Client authentication at token endpoint")
		} else {
			vulnerabilities = append(vulnerabilities,
				"Public client without PKCE - vulnerable to authorization code interception",
			)
		}

		// Check for state parameter
		if s.hasStateParameter(impl) {
			features = append(features, "State parameter for CSRF protection")
		} else {
			vulnerabilities = append(vulnerabilities,
				"Missing state parameter - vulnerable to CSRF attacks",
			)
		}

		// Common OAuth2 vulnerabilities
		vulnerabilities = append(vulnerabilities,
			"Potential redirect URI manipulation if not properly validated",
			"Possible authorization code replay if not properly handled",
			"JWT algorithm confusion attacks if JWT tokens are used",
		)

	case AuthTypeSAML:
		features = append(features,
			"XML-based assertions",
			"Single Sign-On capabilities",
			"Attribute-based access control",
		)

		vulnerabilities = append(vulnerabilities,
			"Potential XML signature wrapping vulnerabilities",
			"Possible SAML replay attacks if assertions not properly validated",
		)

		// Check for encryption
		if metadata, ok := impl.Metadata["encryption"]; ok && metadata == "true" {
			features = append(features, "SAML assertions encrypted")
		} else {
			vulnerabilities = append(vulnerabilities,
				"SAML assertions not encrypted",
			)
		}

	case AuthTypeWebAuthn, AuthTypeFIDO2:
		features = append(features,
			"Phishing-resistant authentication",
			"No password to steal or phish",
			"Hardware-backed credentials",
			"Cryptographically secure",
			"Replay attack protection",
		)

		// WebAuthn has very few vulnerabilities when properly implemented
		// Check for user verification
		if !s.hasUserVerification(impl) {
			vulnerabilities = append(vulnerabilities,
				"User verification may not be required",
			)
		}

	case AuthTypeJWT:
		// Check JWT implementation
		jwtVulns, jwtFeatures := s.analyzeJWT(impl)
		vulnerabilities = append(vulnerabilities, jwtVulns...)
		features = append(features, jwtFeatures...)

	case AuthTypeLDAP:
		vulnerabilities = append(vulnerabilities,
			"Potential LDAP injection if user input not sanitized",
			"Anonymous bind may be allowed",
		)

		// Check for LDAPS
		hasLDAPS := false
		for _, endpoint := range impl.Endpoints {
			if strings.HasPrefix(endpoint.URL, "ldaps://") {
				hasLDAPS = true
				break
			}
		}

		if hasLDAPS {
			features = append(features, "LDAP over SSL/TLS (LDAPS)")
		} else {
			vulnerabilities = append(vulnerabilities,
				"LDAP traffic not encrypted",
			)
		}

	case AuthTypeAPIKey:
		features = append(features, "Simple API authentication")
		vulnerabilities = append(vulnerabilities,
			"API keys are long-lived credentials",
			"No automatic expiration",
			"Difficult to rotate without service disruption",
		)

		// Check where API key is sent
		for _, endpoint := range impl.Endpoints {
			for _, param := range endpoint.Parameters {
				if param.Type == "api_key" && param.Location == "query" {
					vulnerabilities = append(vulnerabilities,
						"API key transmitted in URL query parameters - may be logged",
					)
				}
			}
		}

	case AuthTypeBasicAuth:
		vulnerabilities = append(vulnerabilities,
			"Credentials transmitted in base64 encoding (not encryption)",
			"Vulnerable to credential theft if not over HTTPS",
			"No built-in session management",
			"Credentials sent with every request",
		)

	case AuthTypeDigestAuth:
		features = append(features, "Challenge-response mechanism")
		vulnerabilities = append(vulnerabilities,
			"Vulnerable to rainbow table attacks",
			"Uses MD5 which is cryptographically weak",
			"Susceptible to man-in-the-middle attacks",
		)

	case AuthTypeFormLogin:
		features = append(features, "User-friendly login interface")
		vulnerabilities = append(vulnerabilities,
			"Vulnerable to credential stuffing attacks",
			"Potential for SQL injection if not properly parameterized",
			"Session fixation if sessions not properly managed",
			"CSRF attacks if no proper token protection",
		)
	}

	// General security checks
	generalFeatures, generalVulns := s.analyzeGeneralSecurity(impl)
	features = append(features, generalFeatures...)
	vulnerabilities = append(vulnerabilities, generalVulns...)

	// Check for MFA
	if s.hasMFA(impl) {
		features = append(features, "Multi-factor authentication available")
	} else {
		vulnerabilities = append(vulnerabilities,
			"No multi-factor authentication detected",
		)
	}

	// Remove duplicates
	features = deduplicateStrings(features)
	vulnerabilities = deduplicateStrings(vulnerabilities)

	s.logger.Debug("Security analysis completed",
		"features", len(features),
		"vulnerabilities", len(vulnerabilities))

	return features, vulnerabilities
}

func (s *SecurityAnalyzer) analyzeJWT(impl *AuthImplementation) ([]string, []string) {
	var vulnerabilities []string
	var features []string

	features = append(features, "Token-based authentication")

	// Common JWT vulnerabilities
	vulnerabilities = append(vulnerabilities,
		"Potential algorithm confusion attacks (alg: none, RS256 to HS256)",
		"Possible weak secret keys for HMAC algorithms",
		"JWT secrets may be hardcoded or predictable",
		"No token revocation mechanism",
	)

	// Check if refresh tokens are used
	hasRefresh := false
	for _, flow := range impl.Flows {
		for _, step := range flow.Steps {
			for _, param := range step.Parameters {
				if param.Name == "refresh_token" {
					hasRefresh = true
					break
				}
			}
		}
	}

	if hasRefresh {
		features = append(features, "Refresh token support")
	}

	return vulnerabilities, features
}

func (s *SecurityAnalyzer) analyzeGeneralSecurity(impl *AuthImplementation) ([]string, []string) {
	var features []string
	var vulnerabilities []string

	// Check for rate limiting indicators
	hasRateLimit := false
	for _, endpoint := range impl.Endpoints {
		if headers, ok := endpoint.Headers["X-RateLimit-Limit"]; ok && headers != "" {
			hasRateLimit = true
			break
		}
	}

	if hasRateLimit {
		features = append(features, "Rate limiting implemented")
	} else {
		vulnerabilities = append(vulnerabilities,
			"No rate limiting detected - vulnerable to brute force attacks",
		)
	}

	// Check for CSRF protection
	hasCSRF := false
	for _, endpoint := range impl.Endpoints {
		for _, param := range endpoint.Parameters {
			if strings.Contains(strings.ToLower(param.Name), "csrf") ||
				param.Name == "_token" ||
				param.Name == "authenticity_token" {
				hasCSRF = true
				break
			}
		}
	}

	if hasCSRF {
		features = append(features, "CSRF protection tokens found")
	}

	// Check for security headers
	securityHeaders := []string{
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Content-Security-Policy",
	}

	foundHeaders := make(map[string]bool)
	for _, endpoint := range impl.Endpoints {
		for header := range endpoint.Headers {
			for _, secHeader := range securityHeaders {
				if strings.EqualFold(header, secHeader) {
					foundHeaders[secHeader] = true
				}
			}
		}
	}

	for header := range foundHeaders {
		features = append(features, fmt.Sprintf("Security header: %s", header))
	}

	// Check for password complexity requirements
	for _, flow := range impl.Flows {
		if flow.Type == "registration" || flow.Type == "password_reset" {
			for _, step := range flow.Steps {
				for _, param := range step.Parameters {
					if param.Type == "password" && len(param.Constraints) > 0 {
						features = append(features, "Password complexity requirements enforced")
						break
					}
				}
			}
		}
	}

	return features, vulnerabilities
}

func (s *SecurityAnalyzer) hasMFA(impl *AuthImplementation) bool {
	// Check endpoints
	for _, endpoint := range impl.Endpoints {
		if endpoint.Type == AuthTypeTOTP ||
			endpoint.Type == AuthTypeSMS ||
			endpoint.Type == AuthTypeU2F ||
			endpoint.Type == AuthTypePush {
			return true
		}
	}

	// Check flows
	for _, flow := range impl.Flows {
		if flow.RequiresMFA {
			return true
		}

		for _, step := range flow.Steps {
			if step.Type == "mfa_challenge" {
				return true
			}
		}
	}

	// Check metadata for MFA indicators
	for key, value := range impl.Metadata {
		if strings.Contains(strings.ToLower(key), "mfa") ||
			strings.Contains(strings.ToLower(key), "2fa") {
			if boolValue, ok := value.(bool); ok && boolValue {
				return true
			}
		}
	}

	return false
}

func (s *SecurityAnalyzer) hasTokenEndpointAuth(impl *AuthImplementation) bool {
	// Check OAuth2 token endpoint authentication
	for _, flow := range impl.Flows {
		for _, step := range flow.Steps {
			if step.Type == "token_exchange" || step.Type == "token_request" {
				for _, param := range step.Parameters {
					if param.Name == "client_secret" && param.Required {
						return true
					}
				}
			}
		}
	}
	return false
}

func (s *SecurityAnalyzer) hasStateParameter(impl *AuthImplementation) bool {
	// Check OAuth2 state parameter
	for _, flow := range impl.Flows {
		for _, step := range flow.Steps {
			if step.Type == "authorization_request" {
				for _, param := range step.Parameters {
					if param.Name == "state" {
						return true
					}
				}
			}
		}
	}
	return false
}

func (s *SecurityAnalyzer) hasUserVerification(impl *AuthImplementation) bool {
	// Check WebAuthn user verification
	for _, endpoint := range impl.Endpoints {
		if metadata, ok := endpoint.Metadata["user_verification"]; ok {
			if uv, ok := metadata.(string); ok && uv == "required" {
				return true
			}
		}
	}
	return false
}
