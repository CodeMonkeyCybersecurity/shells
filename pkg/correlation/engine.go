// pkg/correlation/engine.go
package correlation

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// Engine is the correlation engine that connects findings across sources
type Engine struct {
	logger           *logger.Logger
	graphDB          GraphDatabase
	patternMatcher   *PatternMatcher
	timelineAnalyzer *TimelineAnalyzer
	riskCalculator   *RiskCalculator
	exploitChainer   *ExploitChainer
}

// GraphDatabase represents the graph database for relationship mapping
type GraphDatabase interface {
	AddNode(node Node) error
	AddEdge(edge Edge) error
	FindPaths(start, end string, maxDepth int) []Path
	GetNeighbors(nodeID string) []Node
	RunQuery(query string) ([]Result, error)
}

// Node represents an entity in the graph
type Node struct {
	ID         string
	Type       NodeType
	Properties map[string]interface{}
	Timestamp  time.Time
}

// NodeType represents the type of node
type NodeType string

const (
	NodeTypeDomain       NodeType = "domain"
	NodeTypeIP           NodeType = "ip"
	NodeTypeEmail        NodeType = "email"
	NodeTypePerson       NodeType = "person"
	NodeTypeOrganization NodeType = "organization"
	NodeTypeService      NodeType = "service"
	NodeTypeEndpoint     NodeType = "endpoint"
	NodeTypeSecret       NodeType = "secret"
	NodeTypeTechnology   NodeType = "technology"
)

// Edge represents a relationship between nodes
type Edge struct {
	ID         string
	Source     string
	Target     string
	Type       EdgeType
	Properties map[string]interface{}
	Weight     float64
	Timestamp  time.Time
}

// EdgeType represents the type of relationship
type EdgeType string

const (
	EdgeTypeResolves    EdgeType = "resolves_to"
	EdgeTypeOwns        EdgeType = "owns"
	EdgeTypeUses        EdgeType = "uses"
	EdgeTypeExposes     EdgeType = "exposes"
	EdgeTypeConnectsTo  EdgeType = "connects_to"
	EdgeTypeRelatedTo   EdgeType = "related_to"
	EdgeTypeWasReplaced EdgeType = "was_replaced_by"
)

// CorrelatedInsight represents an insight derived from correlation
type CorrelatedInsight struct {
	ID           string
	Type         InsightType
	Title        string
	Description  string
	Severity     types.Severity
	Confidence   float64
	Evidence     []Evidence
	Timeline     []TimelineEvent
	AttackPath   *AttackPath
	Remediation  []RemediationStep
	RelatedNodes []string
}

// InsightType represents the type of correlated insight
type InsightType string

const (
	InsightTypeOriginServerExposed   InsightType = "origin_server_exposed"
	InsightTypeSubdomainTakeover     InsightType = "subdomain_takeover"
	InsightTypeAPIVersionVulnerable  InsightType = "api_version_vulnerable"
	InsightTypeSecurityDegradation   InsightType = "security_degradation"
	InsightTypeInfrastructureLeakage InsightType = "infrastructure_leakage"
	InsightTypeCredentialExposure    InsightType = "credential_exposure"
	InsightTypeAttackChainIdentified InsightType = "attack_chain_identified"
)

// NewEngine creates a new correlation engine
func NewEngine(logger *logger.Logger, graphDB GraphDatabase) *Engine {
	return &Engine{
		logger:           logger,
		graphDB:          graphDB,
		patternMatcher:   NewPatternMatcher(),
		timelineAnalyzer: NewTimelineAnalyzer(),
		riskCalculator:   NewRiskCalculator(),
		exploitChainer:   NewExploitChainer(),
	}
}

// Correlate performs correlation analysis on findings
func (e *Engine) Correlate(findings []types.Finding) []CorrelatedInsight {
	var insights []CorrelatedInsight

	// Build graph from findings
	e.buildGraph(findings)

	// Run correlation strategies
	strategies := []func([]types.Finding) []CorrelatedInsight{
		e.temporalCorrelation,
		e.infrastructureCorrelation,
		e.patternCorrelation,
		e.technologyCorrelation,
		e.securityPostureCorrelation,
		e.attackChainCorrelation,
	}

	for _, strategy := range strategies {
		strategyInsights := strategy(findings)
		insights = append(insights, strategyInsights...)
	}

	// Deduplicate and rank insights
	insights = e.deduplicateAndRankInsights(insights)

	e.logger.Info("Correlation completed",
		"findings", len(findings),
		"insights", len(insights))

	return insights
}

// temporalCorrelation identifies patterns across time
func (e *Engine) temporalCorrelation(findings []types.Finding) []CorrelatedInsight {
	var insights []CorrelatedInsight

	// Group findings by target and sort by time
	targetFindings := e.groupByTarget(findings)

	for target, targetFindingList := range targetFindings {
		// Build timeline
		timeline := e.timelineAnalyzer.BuildTimeline(targetFindingList)

		// Look for security degradation
		if degradation := e.detectSecurityDegradation(timeline); degradation != nil {
			insight := CorrelatedInsight{
				ID:          generateInsightID(),
				Type:        InsightTypeSecurityDegradation,
				Title:       fmt.Sprintf("Security Posture Degradation on %s", target),
				Description: degradation.Description,
				Severity:    types.SeverityHigh,
				Confidence:  degradation.Confidence,
				Timeline:    timeline,
				Evidence:    degradation.Evidence,
			}
			insights = append(insights, insight)
		}

		// Look for attack precursors
		if precursors := e.detectAttackPrecursors(timeline); len(precursors) > 0 {
			for _, precursor := range precursors {
				insights = append(insights, precursor)
			}
		}
	}

	return insights
}

// infrastructureCorrelation finds infrastructure relationships
func (e *Engine) infrastructureCorrelation(findings []types.Finding) []CorrelatedInsight {
	var insights []CorrelatedInsight

	// Extract infrastructure nodes
	infraNodes := e.extractInfrastructureNodes(findings)

	// Find shared infrastructure
	sharedInfra := e.findSharedInfrastructure(infraNodes)

	for _, shared := range sharedInfra {
		// Check if this reveals origin servers
		if e.isOriginServerCandidate(shared) {
			insight := CorrelatedInsight{
				ID:   generateInsightID(),
				Type: InsightTypeOriginServerExposed,
				Title: fmt.Sprintf("Potential Origin Server Discovered: %s",
					shared.Properties["ip"]),
				Description: e.buildOriginServerDescription(shared),
				Severity:    types.SeverityCritical,
				Confidence:  e.calculateOriginConfidence(shared),
				Evidence:    e.gatherOriginEvidence(shared),
			}
			insights = append(insights, insight)
		}

		// Check for infrastructure leakage
		if leakage := e.detectInfrastructureLeakage(shared); leakage != nil {
			insights = append(insights, *leakage)
		}
	}

	// Subdomain takeover detection
	takeoverCandidates := e.detectSubdomainTakeovers(infraNodes)
	for _, takeover := range takeoverCandidates {
		insights = append(insights, takeover)
	}

	return insights
}

// patternCorrelation identifies patterns across findings
func (e *Engine) patternCorrelation(findings []types.Finding) []CorrelatedInsight {
	var insights []CorrelatedInsight

	// Extract patterns from various sources
	domainPatterns := e.patternMatcher.ExtractDomainPatterns(findings)
	parameterPatterns := e.patternMatcher.ExtractParameterPatterns(findings)
	endpointPatterns := e.patternMatcher.ExtractEndpointPatterns(findings)

	// Generate predictions from patterns
	predictions := e.generatePredictionsFromPatterns(
		domainPatterns,
		parameterPatterns,
		endpointPatterns,
	)

	// Validate predictions
	for _, prediction := range predictions {
		if e.validatePrediction(prediction) {
			insight := CorrelatedInsight{
				ID:          generateInsightID(),
				Type:        InsightTypeInfrastructureLeakage,
				Title:       fmt.Sprintf("Pattern-Based Discovery: %s", prediction.Value),
				Description: fmt.Sprintf("Discovered %s through pattern analysis", prediction.Type),
				Severity:    e.calculatePredictionSeverity(prediction),
				Confidence:  prediction.Confidence,
				Evidence:    prediction.Evidence,
			}
			insights = append(insights, insight)
		}
	}

	return insights
}

// technologyCorrelation analyzes technology stack relationships
func (e *Engine) technologyCorrelation(findings []types.Finding) []CorrelatedInsight {
	var insights []CorrelatedInsight

	// Build technology graph
	techGraph := e.buildTechnologyGraph(findings)

	// Identify technology migrations
	migrations := e.detectTechnologyMigrations(techGraph)

	for _, migration := range migrations {
		// Check if old endpoints still exist
		if orphaned := e.findOrphanedEndpoints(migration); len(orphaned) > 0 {
			insight := CorrelatedInsight{
				ID:   generateInsightID(),
				Type: InsightTypeAPIVersionVulnerable,
				Title: fmt.Sprintf("Legacy %s Endpoints Still Active After Migration to %s",
					migration.OldTech, migration.NewTech),
				Description: e.buildMigrationDescription(migration, orphaned),
				Severity:    types.SeverityHigh,
				Confidence:  0.85,
				Evidence:    e.gatherMigrationEvidence(migration, orphaned),
			}
			insights = append(insights, insight)
		}
	}

	// Identify vulnerable technology combinations
	vulnCombos := e.detectVulnerableTechCombinations(techGraph)
	for _, combo := range vulnCombos {
		insights = append(insights, combo)
	}

	return insights
}

// securityPostureCorrelation tracks security changes over time
func (e *Engine) securityPostureCorrelation(findings []types.Finding) []CorrelatedInsight {
	var insights []CorrelatedInsight

	// Analyze security headers over time
	headerTimeline := e.buildSecurityHeaderTimeline(findings)

	for domain, timeline := range headerTimeline {
		// Detect removed security headers
		if removed := e.detectRemovedSecurityHeaders(timeline); len(removed) > 0 {
			insight := CorrelatedInsight{
				ID:          generateInsightID(),
				Type:        InsightTypeSecurityDegradation,
				Title:       fmt.Sprintf("Security Headers Removed from %s", domain),
				Description: e.buildSecurityHeaderDescription(removed),
				Severity:    types.SeverityMedium,
				Confidence:  0.95,
				Timeline:    e.convertToTimelineEvents(timeline),
				Evidence:    e.gatherHeaderEvidence(removed),
			}
			insights = append(insights, insight)
		}

		// Detect weakened security policies
		if weakened := e.detectWeakenedPolicies(timeline); len(weakened) > 0 {
			for _, policy := range weakened {
				insights = append(insights, policy)
			}
		}
	}

	return insights
}

// attackChainCorrelation identifies complete attack chains
func (e *Engine) attackChainCorrelation(findings []types.Finding) []CorrelatedInsight {
	var insights []CorrelatedInsight

	// Build attack graph
	attackGraph := e.exploitChainer.BuildAttackGraph(findings)

	// Find all attack paths
	attackPaths := e.exploitChainer.FindAttackPaths(attackGraph)

	// Score and filter paths
	viablePaths := e.filterViableAttackPaths(attackPaths)

	for _, path := range viablePaths {
		insight := CorrelatedInsight{
			ID:          generateInsightID(),
			Type:        InsightTypeAttackChainIdentified,
			Title:       fmt.Sprintf("%d-Step Attack Chain: %s", len(path.Steps), path.Goal),
			Description: e.buildAttackChainDescription(path),
			Severity:    e.calculateChainSeverity(path),
			Confidence:  path.Confidence,
			AttackPath:  &path,
			Evidence:    e.gatherChainEvidence(path),
			Remediation: e.generateRemediationSteps(path),
		}
		insights = append(insights, insight)
	}

	return insights
}

// CloudFlareArchiveCorrelation correlates CloudFlare with archive data
func (e *Engine) CloudFlareArchiveCorrelation(domain string) []CorrelatedInsight {
	var insights []CorrelatedInsight

	// Simplified correlation without external dependencies
	insight := CorrelatedInsight{
		ID:    generateInsightID(),
		Type:  InsightTypeOriginServerExposed,
		Title: fmt.Sprintf("Potential CloudFlare Origin Server Discovery: %s", domain),
		Description: fmt.Sprintf(
			"Domain %s may be using CloudFlare. Historical analysis could reveal origin servers.",
			domain,
		),
		Severity:   types.SeverityMedium,
		Confidence: 0.6,
		Evidence: []Evidence{
			{
				Type:        "domain_analysis",
				Description: fmt.Sprintf("Domain %s identified for CloudFlare analysis", domain),
				Source:      "Correlation Engine",
				Timestamp:   time.Now(),
			},
		},
	}
	insights = append(insights, insight)

	return insights
}

// Helper structures

// Evidence represents evidence for an insight
type Evidence struct {
	Type        string
	Description string
	Source      string
	Timestamp   time.Time
	Data        map[string]interface{}
}

// TimelineEvent represents an event in the timeline
type TimelineEvent struct {
	Timestamp   time.Time
	Type        string
	Description string
	Severity    types.Severity
	Source      string
}

// AttackPath represents a complete attack chain
type AttackPath struct {
	Goal       string
	Steps      []AttackStep
	Confidence float64
	Impact     string
	Difficulty string
}

// AttackStep represents a single step in an attack
type AttackStep struct {
	Order       int
	Description string
	Tool        string
	Confidence  float64
	Evidence    []Evidence
}

// RemediationStep represents a remediation action
type RemediationStep struct {
	Priority    int
	Action      string
	Description string
	Impact      string
	Difficulty  string
}

// Path represents a path in the graph
type Path struct {
	Nodes []Node
	Edges []Edge
	Score float64
}

// Result represents a graph query result
type Result struct {
	Data map[string]interface{}
}

// Prediction represents a predicted finding
type Prediction struct {
	Type       string
	Value      string
	Confidence float64
	Evidence   []Evidence
}

// SecurityDegradation represents security posture degradation
type SecurityDegradation struct {
	Description string
	Confidence  float64
	Evidence    []Evidence
	Timeline    []TimelineEvent
}

// TechnologyMigration represents a technology stack change
type TechnologyMigration struct {
	OldTech   string
	NewTech   string
	Timestamp time.Time
	Endpoints []string
}

// Helper functions

func (e *Engine) buildGraph(findings []types.Finding) {
	// Add nodes for each unique entity
	nodes := e.extractNodes(findings)
	for _, node := range nodes {
		if err := e.graphDB.AddNode(node); err != nil {
			e.logger.Error("Failed to add node", "node", node.ID, "error", err)
		}
	}

	// Add edges for relationships
	edges := e.extractEdges(findings)
	for _, edge := range edges {
		if err := e.graphDB.AddEdge(edge); err != nil {
			e.logger.Error("Failed to add edge", "edge", edge.ID, "error", err)
		}
	}
}

func (e *Engine) extractNodes(findings []types.Finding) []Node {
	nodeMap := make(map[string]Node)

	for _, finding := range findings {
		// Extract domain nodes
		if domain, ok := finding.Metadata["domain"].(string); ok {
			nodeID := fmt.Sprintf("domain:%s", domain)
			nodeMap[nodeID] = Node{
				ID:   nodeID,
				Type: NodeTypeDomain,
				Properties: map[string]interface{}{
					"name":     domain,
					"finding":  finding.Type,
					"severity": finding.Severity,
				},
				Timestamp: finding.CreatedAt,
			}
		}

		// Extract IP nodes
		if ip, ok := finding.Metadata["ip"].(string); ok {
			nodeID := fmt.Sprintf("ip:%s", ip)
			nodeMap[nodeID] = Node{
				ID:   nodeID,
				Type: NodeTypeIP,
				Properties: map[string]interface{}{
					"address":  ip,
					"finding":  finding.Type,
					"severity": finding.Severity,
				},
				Timestamp: finding.CreatedAt,
			}
		}

		// Extract email nodes
		if email, ok := finding.Metadata["email"].(string); ok {
			nodeID := fmt.Sprintf("email:%s", email)
			nodeMap[nodeID] = Node{
				ID:   nodeID,
				Type: NodeTypeEmail,
				Properties: map[string]interface{}{
					"address":  email,
					"finding":  finding.Type,
					"severity": finding.Severity,
				},
				Timestamp: finding.CreatedAt,
			}
		}

		// Extract service nodes
		if service, ok := finding.Metadata["service"].(string); ok {
			nodeID := fmt.Sprintf("service:%s", service)
			nodeMap[nodeID] = Node{
				ID:   nodeID,
				Type: NodeTypeService,
				Properties: map[string]interface{}{
					"name":     service,
					"finding":  finding.Type,
					"severity": finding.Severity,
				},
				Timestamp: finding.CreatedAt,
			}
		}
	}

	// Convert map to slice
	var nodes []Node
	for _, node := range nodeMap {
		nodes = append(nodes, node)
	}

	return nodes
}

func (e *Engine) extractEdges(findings []types.Finding) []Edge {
	var edges []Edge

	for _, finding := range findings {
		// Domain resolves to IP
		if domain, ok1 := finding.Metadata["domain"].(string); ok1 {
			if ip, ok2 := finding.Metadata["ip"].(string); ok2 {
				edge := Edge{
					ID:     generateEdgeID(),
					Source: fmt.Sprintf("domain:%s", domain),
					Target: fmt.Sprintf("ip:%s", ip),
					Type:   EdgeTypeResolves,
					Properties: map[string]interface{}{
						"finding": finding.Type,
					},
					Weight:    1.0,
					Timestamp: finding.CreatedAt,
				}
				edges = append(edges, edge)
			}
		}

		// Service runs on IP
		if service, ok1 := finding.Metadata["service"].(string); ok1 {
			if ip, ok2 := finding.Metadata["ip"].(string); ok2 {
				edge := Edge{
					ID:     generateEdgeID(),
					Source: fmt.Sprintf("service:%s", service),
					Target: fmt.Sprintf("ip:%s", ip),
					Type:   EdgeTypeUses,
					Properties: map[string]interface{}{
						"finding": finding.Type,
						"port":    finding.Metadata["port"],
					},
					Weight:    1.0,
					Timestamp: finding.CreatedAt,
				}
				edges = append(edges, edge)
			}
		}

		// Email associated with domain
		if email, ok1 := finding.Metadata["email"].(string); ok1 {
			if domain, ok2 := finding.Metadata["domain"].(string); ok2 {
				edge := Edge{
					ID:     generateEdgeID(),
					Source: fmt.Sprintf("email:%s", email),
					Target: fmt.Sprintf("domain:%s", domain),
					Type:   EdgeTypeRelatedTo,
					Properties: map[string]interface{}{
						"finding": finding.Type,
					},
					Weight:    0.8,
					Timestamp: finding.CreatedAt,
				}
				edges = append(edges, edge)
			}
		}
	}

	return edges
}

func (e *Engine) deduplicateAndRankInsights(insights []CorrelatedInsight) []CorrelatedInsight {
	// Deduplicate by calculating similarity
	unique := make(map[string]CorrelatedInsight)

	for _, insight := range insights {
		key := e.generateInsightKey(insight)

		if existing, exists := unique[key]; exists {
			// Merge evidence and increase confidence
			existing.Evidence = append(existing.Evidence, insight.Evidence...)
			existing.Confidence = (existing.Confidence + insight.Confidence) / 2
			unique[key] = existing
		} else {
			unique[key] = insight
		}
	}

	// Convert to slice
	var deduplicated []CorrelatedInsight
	for _, insight := range unique {
		deduplicated = append(deduplicated, insight)
	}

	// Rank by importance
	sort.Slice(deduplicated, func(i, j int) bool {
		// Primary sort by severity
		if deduplicated[i].Severity != deduplicated[j].Severity {
			return deduplicated[i].Severity > deduplicated[j].Severity
		}

		// Secondary sort by confidence
		return deduplicated[i].Confidence > deduplicated[j].Confidence
	})

	return deduplicated
}

func (e *Engine) generateInsightKey(insight CorrelatedInsight) string {
	// Generate a unique key based on insight properties
	parts := []string{
		string(insight.Type),
		fmt.Sprintf("%.2f", insight.Confidence),
	}

	// Add key evidence pieces
	for _, evidence := range insight.Evidence {
		parts = append(parts, evidence.Type)
	}

	return strings.Join(parts, "-")
}

func generateInsightID() string {
	return fmt.Sprintf("insight-%d", time.Now().UnixNano())
}

func generateEdgeID() string {
	return fmt.Sprintf("edge-%d", time.Now().UnixNano())
}

// Additional helper methods would be implemented here...
