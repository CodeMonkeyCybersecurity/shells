// pkg/enrichment/enricher.go
package enrichment

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// ResultEnricher enriches scan findings with additional context
type ResultEnricher struct {
	cvssCalculator *CVSSCalculator
	exploitChecker *ExploitChecker
	assetAnalyzer  *AssetCriticalityAnalyzer
	impactAnalyzer *BusinessImpactAnalyzer
	cache          *EnrichmentCache
	httpClient     *http.Client
	config         EnricherConfig
}

// EnricherConfig holds configuration for result enrichment
type EnricherConfig struct {
	CVSSVersion     string
	ExploitDBAPIKey string
	NVDAPIKey       string
	CacheSize       int
	CacheTTL        time.Duration
	MaxConcurrency  int
	EnrichmentLevel string // basic, standard, comprehensive
}

// EnrichedFinding represents a finding with additional context
type EnrichedFinding struct {
	types.Finding
	CVSSScore        *CVSSScore            `json:"cvss_score"`
	ExploitInfo      *ExploitInformation   `json:"exploit_info"`
	AssetCriticality *AssetCriticality     `json:"asset_criticality"`
	BusinessImpact   *BusinessImpact       `json:"business_impact"`
	Remediation      *RemediationGuidance  `json:"remediation"`
	References       []Reference           `json:"references"`
	AffectedAssets   []AffectedAsset       `json:"affected_assets"`
	ThreatContext    *ThreatContext        `json:"threat_context"`
	ComplianceImpact []ComplianceViolation `json:"compliance_impact"`
}

// CVSSScore represents CVSS scoring information
type CVSSScore struct {
	Version            string      `json:"version"`
	BaseScore          float64     `json:"base_score"`
	TemporalScore      float64     `json:"temporal_score"`
	EnvironmentalScore float64     `json:"environmental_score"`
	Vector             string      `json:"vector"`
	Severity           string      `json:"severity"`
	Metrics            CVSSMetrics `json:"metrics"`
	Justification      string      `json:"justification"`
}

// CVSSMetrics holds detailed CVSS metrics
type CVSSMetrics struct {
	AttackVector        string `json:"attack_vector"`
	AttackComplexity    string `json:"attack_complexity"`
	PrivilegesRequired  string `json:"privileges_required"`
	UserInteraction     string `json:"user_interaction"`
	Scope               string `json:"scope"`
	Confidentiality     string `json:"confidentiality"`
	Integrity           string `json:"integrity"`
	Availability        string `json:"availability"`
	ExploitCodeMaturity string `json:"exploit_code_maturity,omitempty"`
	RemediationLevel    string `json:"remediation_level,omitempty"`
	ReportConfidence    string `json:"report_confidence,omitempty"`
}

// ExploitInformation contains exploit availability data
type ExploitInformation struct {
	ExploitAvailable  bool             `json:"exploit_available"`
	ExploitCount      int              `json:"exploit_count"`
	Sources           []ExploitSource  `json:"sources"`
	Exploits          []ExploitDetails `json:"exploits"`
	ActivelyExploited bool             `json:"actively_exploited"`
	ThreatActors      []string         `json:"threat_actors"`
	LastSeen          *time.Time       `json:"last_seen"`
}

// ExploitSource represents a source of exploit information
type ExploitSource struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Count       int       `json:"count"`
	LastChecked time.Time `json:"last_checked"`
}

// ExploitDetails contains details about a specific exploit
type ExploitDetails struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Author      string    `json:"author"`
	Type        string    `json:"type"`
	Platform    string    `json:"platform"`
	DateAdded   time.Time `json:"date_added"`
	Verified    bool      `json:"verified"`
	URL         string    `json:"url"`
}

// AssetCriticality represents the criticality of an affected asset
type AssetCriticality struct {
	Score           float64             `json:"score"`
	Level           string              `json:"level"` // critical, high, medium, low
	Factors         []CriticalityFactor `json:"factors"`
	BusinessValue   string              `json:"business_value"`
	DataSensitivity string              `json:"data_sensitivity"`
	Exposure        string              `json:"exposure"` // internet, internal, isolated
}

// CriticalityFactor represents a factor contributing to asset criticality
type CriticalityFactor struct {
	Name   string  `json:"name"`
	Weight float64 `json:"weight"`
	Value  string  `json:"value"`
	Impact float64 `json:"impact"`
}

// BusinessImpact represents the business impact of a vulnerability
type BusinessImpact struct {
	Description      string           `json:"description"`
	ImpactType       []string         `json:"impact_type"`
	AffectedServices []string         `json:"affected_services"`
	EstimatedCost    *CostEstimate    `json:"estimated_cost"`
	Likelihood       string           `json:"likelihood"`
	RiskRating       string           `json:"risk_rating"`
	Scenarios        []ImpactScenario `json:"scenarios"`
}

// CostEstimate represents estimated costs
type CostEstimate struct {
	DirectCost     float64 `json:"direct_cost"`
	IndirectCost   float64 `json:"indirect_cost"`
	ReputationCost float64 `json:"reputation_cost"`
	Currency       string  `json:"currency"`
	Confidence     string  `json:"confidence"`
}

// ImpactScenario represents a potential impact scenario
type ImpactScenario struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Probability float64 `json:"probability"`
	Impact      string  `json:"impact"`
}

// RemediationGuidance provides remediation information
type RemediationGuidance struct {
	Summary          string            `json:"summary"`
	Steps            []RemediationStep `json:"steps"`
	EstimatedEffort  string            `json:"estimated_effort"`
	Priority         string            `json:"priority"`
	Prerequisites    []string          `json:"prerequisites"`
	AlternativeFixes []string          `json:"alternative_fixes"`
	ValidationSteps  []string          `json:"validation_steps"`
}

// RemediationStep represents a single remediation step
type RemediationStep struct {
	Order       int      `json:"order"`
	Description string   `json:"description"`
	Commands    []string `json:"commands,omitempty"`
	References  []string `json:"references,omitempty"`
	Automated   bool     `json:"automated"`
}

// Reference represents an external reference
type Reference struct {
	Type   string `json:"type"` // cve, cwe, advisory, article, tool
	ID     string `json:"id"`
	URL    string `json:"url"`
	Title  string `json:"title"`
	Source string `json:"source"`
}

// AffectedAsset represents an asset affected by the vulnerability
type AffectedAsset struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	Version     string                 `json:"version,omitempty"`
	Location    string                 `json:"location"`
	Criticality string                 `json:"criticality"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ThreatContext provides threat intelligence context
type ThreatContext struct {
	ThreatLevel       string    `json:"threat_level"`
	ActiveCampaigns   []string  `json:"active_campaigns"`
	TargetedSectors   []string  `json:"targeted_sectors"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	TrendingScore     float64   `json:"trending_score"`
	ExploitPrediction float64   `json:"exploit_prediction"`
}

// ComplianceViolation represents a compliance framework violation
type ComplianceViolation struct {
	Framework           string `json:"framework"`
	Requirement         string `json:"requirement"`
	Description         string `json:"description"`
	Severity            string `json:"severity"`
	RemediationDeadline string `json:"remediation_deadline"`
}

// NewResultEnricher creates a new result enricher
func NewResultEnricher(config EnricherConfig) (*ResultEnricher, error) {
	if config.CacheSize == 0 {
		config.CacheSize = 1000
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 1 * time.Hour
	}
	if config.MaxConcurrency == 0 {
		config.MaxConcurrency = 10
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	enricher := &ResultEnricher{
		cvssCalculator: NewCVSSCalculator(config.CVSSVersion),
		exploitChecker: NewExploitChecker(config.ExploitDBAPIKey, httpClient),
		assetAnalyzer:  NewAssetCriticalityAnalyzer(),
		impactAnalyzer: NewBusinessImpactAnalyzer(),
		cache:          newEnrichmentCache(config.CacheSize, config.CacheTTL),
		httpClient:     httpClient,
		config:         config,
	}

	return enricher, nil
}

// EnrichFindings enriches multiple findings with additional context
func (e *ResultEnricher) EnrichFindings(ctx context.Context, findings []types.Finding) ([]EnrichedFinding, error) {
	enriched := make([]EnrichedFinding, len(findings))

	// Use semaphore to limit concurrency
	sem := make(chan struct{}, e.config.MaxConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := make([]error, 0)

	for i, finding := range findings {
		wg.Add(1)
		go func(idx int, f types.Finding) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			enrichedFinding, err := e.enrichSingleFinding(ctx, f)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("finding %s: %w", f.ID, err))
				mu.Unlock()

				// Still include the basic finding even if enrichment fails
				enriched[idx] = EnrichedFinding{Finding: f}
			} else {
				enriched[idx] = *enrichedFinding
			}
		}(i, finding)
	}

	wg.Wait()

	if len(errors) > 0 {
		// Return enriched findings even if some enrichments failed
		return enriched, fmt.Errorf("some enrichments failed: %v", errors)
	}

	return enriched, nil
}

// enrichSingleFinding enriches a single finding
func (e *ResultEnricher) enrichSingleFinding(ctx context.Context, finding types.Finding) (*EnrichedFinding, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("%s:%s", finding.Type, finding.Title)
	if cached, found := e.cache.Get(cacheKey); found && cached != nil {
		// Apply finding-specific data to cached enrichment
		if enrichedCached, ok := cached.(*EnrichedFinding); ok {
			enriched := *enrichedCached
			enriched.Finding = finding
			return &enriched, nil
		}
	}

	enriched := &EnrichedFinding{
		Finding: finding,
	}

	// Perform enrichments based on configuration level
	switch e.config.EnrichmentLevel {
	case "comprehensive":
		// All enrichments
		e.enrichComprehensive(ctx, enriched)
	case "standard":
		// Core enrichments only
		e.enrichStandard(ctx, enriched)
	default:
		// Basic enrichments
		e.enrichBasic(ctx, enriched)
	}

	// Cache the enrichment (without finding-specific data)
	e.cache.Set(cacheKey, enriched)

	return enriched, nil
}

// enrichBasic performs basic enrichment
func (e *ResultEnricher) enrichBasic(ctx context.Context, finding *EnrichedFinding) {
	var wg sync.WaitGroup

	// Calculate CVSS score
	wg.Add(1)
	go func() {
		defer wg.Done()
		finding.CVSSScore = e.cvssCalculator.CalculateScore(&finding.Finding)
	}()

	// Add references
	wg.Add(1)
	go func() {
		defer wg.Done()
		finding.References = e.gatherReferences(&finding.Finding)
	}()

	wg.Wait()
}

// enrichStandard performs standard enrichment
func (e *ResultEnricher) enrichStandard(ctx context.Context, finding *EnrichedFinding) {
	// Start with basic enrichment
	e.enrichBasic(ctx, finding)

	var wg sync.WaitGroup

	// Check exploit availability
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Extract CVEs from finding description/evidence and check exploits
		cves := []string{} // In real implementation, extract from finding
		exploitMap := e.exploitChecker.CheckExploits(ctx, cves)
		finding.ExploitInfo = &ExploitInformation{
			ExploitAvailable:  len(exploitMap) > 0,
			ExploitCount:      len(exploitMap),
			Sources:           []ExploitSource{},
			Exploits:          []ExploitDetails{},
			ActivelyExploited: false,
			ThreatActors:      []string{},
		}
	}()

	// Basic remediation guidance
	wg.Add(1)
	go func() {
		defer wg.Done()
		finding.Remediation = e.generateRemediation(&finding.Finding)
	}()

	wg.Wait()
}

// enrichComprehensive performs comprehensive enrichment
func (e *ResultEnricher) enrichComprehensive(ctx context.Context, finding *EnrichedFinding) {
	// Start with standard enrichment
	e.enrichStandard(ctx, finding)

	var wg sync.WaitGroup

	// Asset criticality analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		criticalityScore := e.assetAnalyzer.AnalyzeCriticality(finding.Finding.Evidence)
		finding.AssetCriticality = &AssetCriticality{
			Score:           criticalityScore,
			BusinessValue:   "Medium",
			DataSensitivity: "Medium",
			Exposure:        "Internal",
		}
	}()

	// Business impact analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		impactDescription := e.impactAnalyzer.AnalyzeImpact(finding.Finding.Evidence, finding.Finding.Type)
		finding.BusinessImpact = &BusinessImpact{
			Description:      impactDescription,
			ImpactType:       []string{"Security", "Operational"},
			AffectedServices: []string{},
			EstimatedCost: &CostEstimate{
				DirectCost:     1000,
				IndirectCost:   5000,
				ReputationCost: 10000,
				Currency:       "USD",
				Confidence:     "Medium",
			},
			Likelihood: "Medium",
			RiskRating: "Medium",
			Scenarios:  []ImpactScenario{},
		}
	}()

	// Threat context
	wg.Add(1)
	go func() {
		defer wg.Done()
		threatContext := e.gatherThreatContext(finding)
		finding.ThreatContext = &threatContext
	}()

	// Compliance impact
	wg.Add(1)
	go func() {
		defer wg.Done()
		finding.ComplianceImpact = e.assessComplianceImpact(finding)
	}()

	wg.Wait()
}

// gatherReferences gathers external references for a finding
func (e *ResultEnricher) gatherReferences(finding *types.Finding) []Reference {
	references := make([]Reference, 0)

	// Extract CVE references from evidence/description
	cves := e.extractCVEs(finding.Evidence + " " + finding.Description)
	for _, cve := range cves {
		references = append(references, Reference{
			Type:   "cve",
			ID:     cve,
			URL:    fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", cve),
			Title:  cve,
			Source: "MITRE",
		})

		// Add NVD reference
		references = append(references, Reference{
			Type:   "nvd",
			ID:     cve,
			URL:    fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve),
			Title:  fmt.Sprintf("NVD - %s", cve),
			Source: "NIST",
		})
	}

	// Extract CWE references from evidence/description
	cwes := e.extractCWEs(finding.Evidence + " " + finding.Description)
	for _, cwe := range cwes {
		cweID := strings.TrimPrefix(cwe, "CWE-")
		references = append(references, Reference{
			Type:   "cwe",
			ID:     cwe,
			URL:    fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", cweID),
			Title:  fmt.Sprintf("CWE-%s", cweID),
			Source: "MITRE",
		})
	}

	// Add OWASP references for common vulnerability types
	owaspRefs := e.getOWASPReferences(finding.Type)
	references = append(references, owaspRefs...)

	return references
}

// generateRemediation generates remediation guidance
func (e *ResultEnricher) generateRemediation(finding *types.Finding) *RemediationGuidance {
	remediation := &RemediationGuidance{
		Summary:  finding.Solution,
		Priority: e.calculateRemediationPriority(finding),
		Steps:    make([]RemediationStep, 0),
	}

	// Generate specific remediation steps based on vulnerability type
	switch finding.Type {
	case "SQL_INJECTION":
		remediation.Steps = e.getSQLInjectionRemediationSteps()
		remediation.EstimatedEffort = "4-8 hours"
	case "XSS":
		remediation.Steps = e.getXSSRemediationSteps()
		remediation.EstimatedEffort = "2-4 hours"
	case "SSRF":
		remediation.Steps = e.getSSRFRemediationSteps()
		remediation.EstimatedEffort = "4-6 hours"
	case "XXE":
		remediation.Steps = e.getXXERemediationSteps()
		remediation.EstimatedEffort = "2-3 hours"
	case "AUTHENTICATION_BYPASS":
		remediation.Steps = e.getAuthBypassRemediationSteps()
		remediation.EstimatedEffort = "8-16 hours"
	default:
		remediation.Steps = e.getGenericRemediationSteps()
		remediation.EstimatedEffort = "Variable"
	}

	// Add validation steps
	remediation.ValidationSteps = e.getValidationStepsForType(finding.Type)

	return remediation
}

// CVSSCalculator implementation
type CVSSCalculator struct {
	version string
}

func NewCVSSCalculator(version string) *CVSSCalculator {
	if version == "" {
		version = "3.1"
	}
	return &CVSSCalculator{version: version}
}

func (c *CVSSCalculator) CalculateScore(finding *types.Finding) *CVSSScore {
	// Map severity to estimated CVSS scores
	baseScore := 0.0
	severity := ""

	switch finding.Severity {
	case types.SeverityCritical:
		baseScore = 9.5
		severity = "Critical"
	case types.SeverityHigh:
		baseScore = 7.5
		severity = "High"
	case types.SeverityMedium:
		baseScore = 5.0
		severity = "Medium"
	case types.SeverityLow:
		baseScore = 3.0
		severity = "Low"
	case types.SeverityInfo:
		baseScore = 0.0
		severity = "None"
	}

	// Generate CVSS vector based on finding characteristics
	metrics := c.deriveMetrics(finding)
	vector := c.generateVector(metrics)

	return &CVSSScore{
		Version:       c.version,
		BaseScore:     baseScore,
		TemporalScore: baseScore * 0.95, // Slight reduction for temporal factors
		Vector:        vector,
		Severity:      severity,
		Metrics:       metrics,
		Justification: c.generateJustification(finding, metrics),
	}
}

func (c *CVSSCalculator) deriveMetrics(finding *types.Finding) CVSSMetrics {
	metrics := CVSSMetrics{
		AttackVector:       "NETWORK",
		AttackComplexity:   "LOW",
		PrivilegesRequired: "NONE",
		UserInteraction:    "NONE",
		Scope:              "UNCHANGED",
		Confidentiality:    "HIGH",
		Integrity:          "HIGH",
		Availability:       "LOW",
	}

	// Adjust based on finding type and characteristics
	if strings.Contains(finding.Description, "authenticated") {
		metrics.PrivilegesRequired = "LOW"
	}

	if strings.Contains(finding.Type, "XSS") {
		metrics.UserInteraction = "REQUIRED"
	}

	if strings.Contains(finding.Type, "DOS") || strings.Contains(finding.Type, "DENIAL") {
		metrics.Availability = "HIGH"
		metrics.Confidentiality = "NONE"
		metrics.Integrity = "NONE"
	}

	return metrics
}

func (c *CVSSCalculator) generateVector(metrics CVSSMetrics) string {
	return fmt.Sprintf("CVSS:%s/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
		c.version,
		metrics.AttackVector,
		metrics.AttackComplexity,
		metrics.PrivilegesRequired,
		metrics.UserInteraction,
		metrics.Scope,
		metrics.Confidentiality,
		metrics.Integrity,
		metrics.Availability,
	)
}

// gatherThreatContext gathers threat context for a finding
func (e *ResultEnricher) gatherThreatContext(finding *EnrichedFinding) ThreatContext {
	// In a real implementation, this would query threat intelligence sources
	return ThreatContext{
		ThreatLevel:       "Medium",
		ActiveCampaigns:   []string{},
		TargetedSectors:   []string{},
		FirstSeen:         time.Now(),
		LastSeen:          time.Now(),
		TrendingScore:     0.5,
		ExploitPrediction: 0.3,
	}
}

// assessComplianceImpact assesses compliance impact
func (e *ResultEnricher) assessComplianceImpact(finding *EnrichedFinding) []ComplianceViolation {
	violations := []ComplianceViolation{}

	// Map finding types to compliance frameworks
	if finding.Severity == types.SeverityCritical || finding.Severity == types.SeverityHigh {
		// Add relevant compliance impacts based on finding type
		if strings.Contains(finding.Type, "authentication") || strings.Contains(finding.Type, "password") {
			violations = append(violations, ComplianceViolation{
				Framework:           "PCI-DSS",
				Requirement:         "8.2.1",
				Description:         "Strong authentication requirements",
				Severity:            "High",
				RemediationDeadline: "30 days",
			})
		}

		if strings.Contains(finding.Type, "encryption") || strings.Contains(finding.Type, "crypto") {
			violations = append(violations, ComplianceViolation{
				Framework:           "SOC2",
				Requirement:         "CC6.1",
				Description:         "Encryption of data in transit",
				Severity:            "Medium",
				RemediationDeadline: "60 days",
			})
		}
	}

	return violations
}
