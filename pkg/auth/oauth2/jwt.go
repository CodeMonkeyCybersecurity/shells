package oauth2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/auth/common"
)

// JWTAnalyzer performs advanced JWT/JWS/JWE analysis
type JWTAnalyzer struct {
	logger common.Logger
}

// NewJWTAnalyzer creates a new JWT analyzer
func NewJWTAnalyzer(logger common.Logger) *JWTAnalyzer {
	return &JWTAnalyzer{
		logger: logger,
	}
}

// JWTHeader represents JWT header
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
	Jku string `json:"jku,omitempty"`
	X5u string `json:"x5u,omitempty"`
	X5c string `json:"x5c,omitempty"`
}

// JWTPayload represents JWT payload
type JWTPayload struct {
	Iss string      `json:"iss,omitempty"`
	Sub string      `json:"sub,omitempty"`
	Aud interface{} `json:"aud,omitempty"`
	Exp int64       `json:"exp,omitempty"`
	Nbf int64       `json:"nbf,omitempty"`
	Iat int64       `json:"iat,omitempty"`
	Jti string      `json:"jti,omitempty"`

	// Additional claims
	Claims map[string]interface{} `json:"-"`
}

// JWTAnalysis represents JWT analysis results
type JWTAnalysis struct {
	Token           string                 `json:"token"`
	Header          JWTHeader              `json:"header"`
	Payload         JWTPayload             `json:"payload"`
	Signature       string                 `json:"signature"`
	Valid           bool                   `json:"valid"`
	Vulnerabilities []common.Vulnerability `json:"vulnerabilities"`
	AttackVectors   []JWTAttackVector      `json:"attack_vectors"`
}

// JWTAttackVector represents a JWT attack vector
type JWTAttackVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Payload     string `json:"payload"`
	Severity    string `json:"severity"`
	Success     bool   `json:"success"`
}

// AnalyzeToken performs comprehensive JWT analysis
func (j *JWTAnalyzer) AnalyzeToken(token string) []common.Vulnerability {
	j.logger.Info("Starting JWT analysis", "token_length", len(token))

	vulnerabilities := []common.Vulnerability{}

	// Parse JWT
	analysis, err := j.parseJWT(token)
	if err != nil {
		j.logger.Error("Failed to parse JWT", "error", err)
		return vulnerabilities
	}

	// Run algorithm confusion tests
	algVulns := j.testAlgorithmConfusion(analysis)
	vulnerabilities = append(vulnerabilities, algVulns...)

	// Run key confusion tests
	keyVulns := j.testKeyConfusion(analysis)
	vulnerabilities = append(vulnerabilities, keyVulns...)

	// Run claim manipulation tests
	claimVulns := j.testClaimManipulation(analysis)
	vulnerabilities = append(vulnerabilities, claimVulns...)

	// Run header injection tests
	headerVulns := j.testHeaderInjection(analysis)
	vulnerabilities = append(vulnerabilities, headerVulns...)

	// Run signature tests
	sigVulns := j.testSignatureValidation(analysis)
	vulnerabilities = append(vulnerabilities, sigVulns...)

	j.logger.Info("JWT analysis completed", "vulnerabilities", len(vulnerabilities))

	return vulnerabilities
}

// parseJWT parses a JWT token
func (j *JWTAnalyzer) parseJWT(token string) (*JWTAnalysis, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	analysis := &JWTAnalysis{
		Token:           token,
		Vulnerabilities: []common.Vulnerability{},
		AttackVectors:   []JWTAttackVector{},
	}

	// Decode header
	headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	if err := json.Unmarshal(headerData, &analysis.Header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Decode payload
	payloadData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	if err := json.Unmarshal(payloadData, &analysis.Payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}

	// Store signature
	analysis.Signature = parts[2]

	return analysis, nil
}

// testAlgorithmConfusion tests for algorithm confusion attacks
func (j *JWTAnalyzer) testAlgorithmConfusion(analysis *JWTAnalysis) []common.Vulnerability {
	vulnerabilities := []common.Vulnerability{}

	// Test 1: None algorithm
	if analysis.Header.Alg == "none" {
		vuln := common.Vulnerability{
			ID:          "JWT_NONE_ALGORITHM",
			Type:        "Algorithm Confusion",
			Protocol:    common.ProtocolJWT,
			Severity:    "CRITICAL",
			Title:       "JWT None Algorithm Vulnerability",
			Description: "JWT uses 'none' algorithm allowing unsigned tokens",
			Impact:      "Attackers can forge JWT tokens without signatures",
			Evidence: []common.Evidence{
				{
					Type:        "JWT_Header",
					Description: "JWT header with none algorithm",
					Data:        fmt.Sprintf("alg: %s", analysis.Header.Alg),
				},
			},
			Remediation: common.Remediation{
				Description: "Disable 'none' algorithm support",
				Steps: []string{
					"Reject tokens with 'none' algorithm",
					"Implement algorithm whitelist",
					"Use strong signing algorithms",
				},
				Priority: "CRITICAL",
			},
			CVSS:      9.8,
			CWE:       "CWE-347",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// Test 2: Weak algorithms
	weakAlgorithms := []string{"HS1", "RS1", "ES1"}
	for _, weakAlg := range weakAlgorithms {
		if analysis.Header.Alg == weakAlg {
			vuln := common.Vulnerability{
				ID:          "JWT_WEAK_ALGORITHM",
				Type:        "Weak Algorithm",
				Protocol:    common.ProtocolJWT,
				Severity:    "HIGH",
				Title:       "JWT Weak Algorithm",
				Description: fmt.Sprintf("JWT uses weak algorithm: %s", weakAlg),
				Impact:      "Weak algorithms may be vulnerable to cryptographic attacks",
				Remediation: common.Remediation{
					Description: "Use strong signing algorithms",
					Steps: []string{
						"Use RS256 or ES256 algorithms",
						"Avoid SHA-1 based algorithms",
						"Implement algorithm validation",
					},
					Priority: "HIGH",
				},
				CVSS:      7.5,
				CWE:       "CWE-327",
				CreatedAt: time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	// Test 3: Algorithm downgrade
	if j.testAlgorithmDowngrade(analysis) {
		vuln := common.Vulnerability{
			ID:          "JWT_ALGORITHM_DOWNGRADE",
			Type:        "Algorithm Downgrade",
			Protocol:    common.ProtocolJWT,
			Severity:    "HIGH",
			Title:       "JWT Algorithm Downgrade",
			Description: "JWT algorithm can be downgraded to weaker methods",
			Impact:      "Attackers can downgrade to weaker algorithms",
			Remediation: common.Remediation{
				Description: "Implement strict algorithm validation",
				Steps: []string{
					"Validate algorithm against expected value",
					"Implement algorithm pinning",
					"Reject unexpected algorithms",
				},
				Priority: "HIGH",
			},
			CVSS:      7.5,
			CWE:       "CWE-757",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities
}

// testKeyConfusion tests for key confusion attacks
func (j *JWTAnalyzer) testKeyConfusion(analysis *JWTAnalysis) []common.Vulnerability {
	vulnerabilities := []common.Vulnerability{}

	// Test RS256 to HS256 confusion
	if analysis.Header.Alg == "RS256" && j.testRS256toHS256(analysis) {
		vuln := common.Vulnerability{
			ID:          "JWT_KEY_CONFUSION",
			Type:        "Key Confusion",
			Protocol:    common.ProtocolJWT,
			Severity:    "CRITICAL",
			Title:       "JWT Key Confusion (RS256 to HS256)",
			Description: "JWT vulnerable to RS256 to HS256 key confusion attack",
			Impact:      "Attackers can use public key as HMAC secret to forge tokens",
			Evidence: []common.Evidence{
				{
					Type:        "JWT_Attack",
					Description: "RS256 to HS256 confusion test",
					Data:        "Key confusion attack possible",
				},
			},
			Remediation: common.Remediation{
				Description: "Implement strict algorithm validation",
				Steps: []string{
					"Validate algorithm before key usage",
					"Use different keys for different algorithms",
					"Implement algorithm-key binding",
				},
				Priority: "CRITICAL",
			},
			CVSS:      9.8,
			CWE:       "CWE-347",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities
}

// testClaimManipulation tests for claim manipulation
func (j *JWTAnalyzer) testClaimManipulation(analysis *JWTAnalysis) []common.Vulnerability {
	vulnerabilities := []common.Vulnerability{}

	// Test critical claims
	criticalClaims := []string{"iss", "sub", "aud", "exp", "nbf", "iat"}

	for _, claim := range criticalClaims {
		if j.testClaimModification(analysis, claim) {
			vuln := common.Vulnerability{
				ID:          fmt.Sprintf("JWT_CLAIM_MANIPULATION_%s", strings.ToUpper(claim)),
				Type:        "Claim Manipulation",
				Protocol:    common.ProtocolJWT,
				Severity:    "HIGH",
				Title:       fmt.Sprintf("JWT %s Claim Manipulation", strings.ToUpper(claim)),
				Description: fmt.Sprintf("JWT %s claim can be manipulated", claim),
				Impact:      "Attackers can modify critical JWT claims",
				Remediation: common.Remediation{
					Description: "Implement proper claim validation",
					Steps: []string{
						"Validate all critical claims",
						"Implement claim constraints",
						"Use claim validation libraries",
					},
					Priority: "HIGH",
				},
				CVSS:      7.5,
				CWE:       "CWE-287",
				CreatedAt: time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities
}

// testHeaderInjection tests for header injection attacks
func (j *JWTAnalyzer) testHeaderInjection(analysis *JWTAnalysis) []common.Vulnerability {
	vulnerabilities := []common.Vulnerability{}

	// Test JKU injection
	if analysis.Header.Jku != "" && j.testJKUinjection(analysis) {
		vuln := common.Vulnerability{
			ID:          "JWT_JKU_INJECTION",
			Type:        "Header Injection",
			Protocol:    common.ProtocolJWT,
			Severity:    "CRITICAL",
			Title:       "JWT JKU Header Injection",
			Description: "JWT JKU header can be manipulated to point to attacker-controlled keys",
			Impact:      "Attackers can specify their own key server",
			Evidence: []common.Evidence{
				{
					Type:        "JWT_Header",
					Description: "JKU header injection test",
					Data:        fmt.Sprintf("jku: %s", analysis.Header.Jku),
				},
			},
			Remediation: common.Remediation{
				Description: "Validate JKU URLs",
				Steps: []string{
					"Implement JKU URL whitelist",
					"Validate JKU against known endpoints",
					"Use static key configuration",
				},
				Priority: "CRITICAL",
			},
			CVSS:      9.8,
			CWE:       "CWE-20",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// Test X5U injection
	if analysis.Header.X5u != "" && j.testX5Uinjection(analysis) {
		vuln := common.Vulnerability{
			ID:          "JWT_X5U_INJECTION",
			Type:        "Header Injection",
			Protocol:    common.ProtocolJWT,
			Severity:    "CRITICAL",
			Title:       "JWT X5U Header Injection",
			Description: "JWT X5U header can be manipulated to point to attacker-controlled certificates",
			Impact:      "Attackers can specify their own certificate chain",
			Remediation: common.Remediation{
				Description: "Validate X5U URLs",
				Steps: []string{
					"Implement X5U URL whitelist",
					"Validate certificates against trusted CAs",
					"Use static certificate configuration",
				},
				Priority: "CRITICAL",
			},
			CVSS:      9.8,
			CWE:       "CWE-20",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// Test Kid injection
	if analysis.Header.Kid != "" && j.testKidInjection(analysis) {
		vuln := common.Vulnerability{
			ID:          "JWT_KID_INJECTION",
			Type:        "Header Injection",
			Protocol:    common.ProtocolJWT,
			Severity:    "HIGH",
			Title:       "JWT Kid Header Injection",
			Description: "JWT Kid header vulnerable to injection attacks",
			Impact:      "Attackers can manipulate key ID to use different keys",
			Remediation: common.Remediation{
				Description: "Validate Kid parameter",
				Steps: []string{
					"Implement Kid validation",
					"Use Kid whitelist",
					"Sanitize Kid parameter",
				},
				Priority: "HIGH",
			},
			CVSS:      7.5,
			CWE:       "CWE-20",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities
}

// testSignatureValidation tests signature validation
func (j *JWTAnalyzer) testSignatureValidation(analysis *JWTAnalysis) []common.Vulnerability {
	vulnerabilities := []common.Vulnerability{}

	// Test signature stripping
	if j.testSignatureStripping(analysis) {
		vuln := common.Vulnerability{
			ID:          "JWT_SIGNATURE_STRIPPING",
			Type:        "Signature Validation",
			Protocol:    common.ProtocolJWT,
			Severity:    "CRITICAL",
			Title:       "JWT Signature Stripping",
			Description: "JWT signatures can be stripped and tokens still accepted",
			Impact:      "Attackers can remove signatures and forge tokens",
			Remediation: common.Remediation{
				Description: "Enforce signature validation",
				Steps: []string{
					"Always validate JWT signatures",
					"Reject unsigned tokens",
					"Implement signature verification",
				},
				Priority: "CRITICAL",
			},
			CVSS:      9.8,
			CWE:       "CWE-347",
			CreatedAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities
}

// Test helper methods

func (j *JWTAnalyzer) testAlgorithmDowngrade(analysis *JWTAnalysis) bool {
	// Test if algorithm can be downgraded
	return false // Placeholder
}

func (j *JWTAnalyzer) testRS256toHS256(analysis *JWTAnalysis) bool {
	// Test RS256 to HS256 confusion
	return false // Placeholder
}

func (j *JWTAnalyzer) testClaimModification(analysis *JWTAnalysis, claim string) bool {
	// Test if claim can be modified
	return false // Placeholder
}

func (j *JWTAnalyzer) testJKUinjection(analysis *JWTAnalysis) bool {
	// Test JKU injection
	return false // Placeholder
}

func (j *JWTAnalyzer) testX5Uinjection(analysis *JWTAnalysis) bool {
	// Test X5U injection
	return false // Placeholder
}

func (j *JWTAnalyzer) testKidInjection(analysis *JWTAnalysis) bool {
	// Test Kid injection
	return false // Placeholder
}

func (j *JWTAnalyzer) testSignatureStripping(analysis *JWTAnalysis) bool {
	// Test signature stripping
	return false // Placeholder
}

// GenerateAttackTokens generates JWT attack tokens
func (j *JWTAnalyzer) GenerateAttackTokens(originalToken string) []JWTAttackVector {
	attacks := []JWTAttackVector{}

	// None algorithm attack
	noneAttack := j.generateNoneAlgorithmAttack(originalToken)
	attacks = append(attacks, noneAttack)

	// Key confusion attack
	keyConfusionAttack := j.generateKeyConfusionAttack(originalToken)
	attacks = append(attacks, keyConfusionAttack)

	// Claim manipulation attack
	claimAttack := j.generateClaimManipulationAttack(originalToken)
	attacks = append(attacks, claimAttack)

	return attacks
}

func (j *JWTAnalyzer) generateNoneAlgorithmAttack(token string) JWTAttackVector {
	// Generate token with none algorithm
	parts := strings.Split(token, ".")

	// Create header with none algorithm
	header := map[string]interface{}{
		"alg": "none",
		"typ": "JWT",
	}

	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Use original payload
	payload := parts[1]

	// No signature for none algorithm
	attackToken := headerB64 + "." + payload + "."

	return JWTAttackVector{
		Name:        "None Algorithm Attack",
		Description: "JWT token with none algorithm",
		Payload:     attackToken,
		Severity:    "CRITICAL",
		Success:     false,
	}
}

func (j *JWTAnalyzer) generateKeyConfusionAttack(token string) JWTAttackVector {
	// Generate token with algorithm confusion
	parts := strings.Split(token, ".")

	// Create header with HS256 instead of RS256
	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Use original payload
	payload := parts[1]

	// Sign with public key as HMAC secret (this would be the actual attack)
	message := headerB64 + "." + payload
	signature := j.generateHMACSignature(message, "public_key_placeholder")

	attackToken := headerB64 + "." + payload + "." + signature

	return JWTAttackVector{
		Name:        "Key Confusion Attack",
		Description: "JWT token with RS256 to HS256 confusion",
		Payload:     attackToken,
		Severity:    "CRITICAL",
		Success:     false,
	}
}

func (j *JWTAnalyzer) generateClaimManipulationAttack(token string) JWTAttackVector {
	// Generate token with modified claims
	parts := strings.Split(token, ".")

	// Decode and modify payload
	payloadData, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]interface{}
	json.Unmarshal(payloadData, &payload)

	// Modify claims to escalate privileges
	payload["sub"] = "admin"
	payload["role"] = "administrator"
	payload["exp"] = time.Now().Add(365 * 24 * time.Hour).Unix()

	modifiedPayloadJSON, _ := json.Marshal(payload)
	modifiedPayloadB64 := base64.RawURLEncoding.EncodeToString(modifiedPayloadJSON)

	attackToken := parts[0] + "." + modifiedPayloadB64 + "." + parts[2]

	return JWTAttackVector{
		Name:        "Claim Manipulation Attack",
		Description: "JWT token with modified claims",
		Payload:     attackToken,
		Severity:    "HIGH",
		Success:     false,
	}
}

func (j *JWTAnalyzer) generateHMACSignature(message, key string) string {
	// Generate HMAC signature
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(message))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
