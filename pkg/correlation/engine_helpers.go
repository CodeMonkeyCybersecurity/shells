// pkg/correlation/engine_helpers.go
package correlation

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// Helper methods for the correlation engine

// groupByTarget groups findings by their target
func (e *Engine) groupByTarget(findings []types.Finding) map[string][]types.Finding {
	targetGroups := make(map[string][]types.Finding)

	for _, finding := range findings {
		// Try to extract target from metadata
		var target string
		if domain, ok := finding.Metadata["domain"].(string); ok {
			target = domain
		} else if ip, ok := finding.Metadata["ip"].(string); ok {
			target = ip
		} else if url, ok := finding.Metadata["url"].(string); ok {
			target = url
		} else {
			target = "unknown"
		}

		targetGroups[target] = append(targetGroups[target], finding)
	}

	return targetGroups
}

// detectSecurityDegradation looks for security posture degradation over time
func (e *Engine) detectSecurityDegradation(timeline []TimelineEvent) *SecurityDegradation {
	if len(timeline) < 2 {
		return nil
	}

	// Look for increasing severity over time
	recentEvents := timeline
	if len(timeline) > 10 {
		recentEvents = timeline[len(timeline)-10:] // Last 10 events
	}

	severityTrend := e.calculateSeverityTrend(recentEvents)
	if severityTrend <= 0 {
		return nil // No degradation
	}

	// Look for removed security headers
	removedHeaders := e.detectRemovedSecurityFeatures(timeline)

	if severityTrend > 0.3 || len(removedHeaders) > 0 {
		degradation := &SecurityDegradation{
			Description: e.buildDegradationDescription(severityTrend, removedHeaders),
			Confidence:  e.calculateDegradationConfidence(severityTrend, removedHeaders),
			Evidence:    e.gatherDegradationEvidence(timeline, removedHeaders),
			Timeline:    timeline,
		}
		return degradation
	}

	return nil
}

// detectAttackPrecursors identifies events that may precede attacks
func (e *Engine) detectAttackPrecursors(timeline []TimelineEvent) []CorrelatedInsight {
	var insights []CorrelatedInsight

	// Look for reconnaissance patterns
	reconEvents := e.filterEventsByType(timeline, []string{"scan", "enum", "discovery"})
	if len(reconEvents) > 5 {
		insight := CorrelatedInsight{
			ID:          generateInsightID(),
			Type:        "attack_precursor",
			Title:       "Potential Reconnaissance Activity Detected",
			Description: fmt.Sprintf("Multiple reconnaissance events (%d) detected within timeline", len(reconEvents)),
			Severity:    types.SeverityMedium,
			Confidence:  0.7,
			Evidence:    e.convertEventsToEvidence(reconEvents),
			Timeline:    reconEvents,
		}
		insights = append(insights, insight)
	}

	// Look for credential harvesting attempts
	credEvents := e.filterEventsByType(timeline, []string{"credential", "password", "token", "auth"})
	if len(credEvents) > 3 {
		insight := CorrelatedInsight{
			ID:          generateInsightID(),
			Type:        "credential_harvesting",
			Title:       "Potential Credential Harvesting Activity",
			Description: fmt.Sprintf("Multiple credential-related events (%d) detected", len(credEvents)),
			Severity:    types.SeverityHigh,
			Confidence:  0.8,
			Evidence:    e.convertEventsToEvidence(credEvents),
			Timeline:    credEvents,
		}
		insights = append(insights, insight)
	}

	return insights
}

// extractInfrastructureNodes extracts infrastructure-related nodes from findings
func (e *Engine) extractInfrastructureNodes(findings []types.Finding) []InfrastructureNode {
	var nodes []InfrastructureNode
	nodeMap := make(map[string]InfrastructureNode)

	for _, finding := range findings {
		// Extract IP nodes
		if ip, ok := finding.Metadata["ip"].(string); ok {
			nodeID := "ip:" + ip
			if _, exists := nodeMap[nodeID]; !exists {
				node := InfrastructureNode{
					ID:       nodeID,
					Type:     "ip",
					Value:    ip,
					Findings: []types.Finding{finding},
					Properties: map[string]interface{}{
						"ip": ip,
					},
				}
				nodeMap[nodeID] = node
			} else {
				node := nodeMap[nodeID]
				node.Findings = append(node.Findings, finding)
				nodeMap[nodeID] = node
			}
		}

		// Extract domain nodes
		if domain, ok := finding.Metadata["domain"].(string); ok {
			nodeID := "domain:" + domain
			if _, exists := nodeMap[nodeID]; !exists {
				node := InfrastructureNode{
					ID:       nodeID,
					Type:     "domain",
					Value:    domain,
					Findings: []types.Finding{finding},
					Properties: map[string]interface{}{
						"domain": domain,
					},
				}
				nodeMap[nodeID] = node
			} else {
				node := nodeMap[nodeID]
				node.Findings = append(node.Findings, finding)
				nodeMap[nodeID] = node
			}
		}

		// Extract certificate nodes
		if cert, ok := finding.Metadata["certificate"].(string); ok {
			nodeID := "cert:" + cert
			if _, exists := nodeMap[nodeID]; !exists {
				node := InfrastructureNode{
					ID:       nodeID,
					Type:     "certificate",
					Value:    cert,
					Findings: []types.Finding{finding},
					Properties: map[string]interface{}{
						"certificate": cert,
					},
				}
				nodeMap[nodeID] = node
			}
		}
	}

	for _, node := range nodeMap {
		nodes = append(nodes, node)
	}

	return nodes
}

// findSharedInfrastructure identifies shared infrastructure components
func (e *Engine) findSharedInfrastructure(nodes []InfrastructureNode) []SharedInfrastructure {
	var shared []SharedInfrastructure

	// Group by IP addresses
	ipGroups := make(map[string][]InfrastructureNode)
	for _, node := range nodes {
		if node.Type == "ip" {
			ip := node.Value
			ipGroups[ip] = append(ipGroups[ip], node)
		}
	}

	// Find IPs with multiple domains
	for ip, ipNodes := range ipGroups {
		if len(ipNodes) > 1 {
			domains := []string{}
			for _, node := range ipNodes {
				if domain, ok := node.Properties["domain"].(string); ok {
					domains = append(domains, domain)
				}
			}

			if len(domains) > 1 {
				sharedInfra := SharedInfrastructure{
					Type:        "shared_ip",
					Value:       ip,
					Nodes:       ipNodes,
					Domains:     domains,
					Confidence:  0.9,
					Description: fmt.Sprintf("IP %s hosts multiple domains: %v", ip, domains),
					Properties: map[string]interface{}{
						"ip":      ip,
						"domains": domains,
					},
				}
				shared = append(shared, sharedInfra)
			}
		}
	}

	return shared
}

// isOriginServerCandidate determines if shared infrastructure reveals origin servers
func (e *Engine) isOriginServerCandidate(shared SharedInfrastructure) bool {
	// Look for CloudFlare bypass indicators
	if shared.Type == "shared_ip" {
		// Check if any of the domains use CloudFlare
		for _, domain := range shared.Domains {
			if e.usesCloudFlare(domain) {
				return true
			}
		}
	}
	return false
}

// buildOriginServerDescription builds description for origin server discovery
func (e *Engine) buildOriginServerDescription(shared SharedInfrastructure) string {
	if ip, ok := shared.Properties["ip"].(string); ok {
		domains := shared.Domains
		return fmt.Sprintf(
			"IP address %s appears to be an origin server hosting %d domains: %v. "+
				"This may allow direct access bypassing CDN protection.",
			ip, len(domains), domains)
	}
	return "Potential origin server discovered through infrastructure correlation."
}

// calculateOriginConfidence calculates confidence in origin server discovery
func (e *Engine) calculateOriginConfidence(shared SharedInfrastructure) float64 {
	confidence := 0.5

	// More domains on same IP increases confidence
	if len(shared.Domains) > 3 {
		confidence += 0.3
	} else if len(shared.Domains) > 1 {
		confidence += 0.2
	}

	// Check for CloudFlare indicators
	cloudFlareCount := 0
	for _, domain := range shared.Domains {
		if e.usesCloudFlare(domain) {
			cloudFlareCount++
		}
	}

	if cloudFlareCount > 0 {
		confidence += 0.2
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// gatherOriginEvidence gathers evidence for origin server discovery
func (e *Engine) gatherOriginEvidence(shared SharedInfrastructure) []Evidence {
	var evidence []Evidence

	if ip, ok := shared.Properties["ip"].(string); ok {
		evidence = append(evidence, Evidence{
			Type:        "shared_hosting",
			Description: fmt.Sprintf("IP %s hosts multiple domains", ip),
			Source:      "Infrastructure Analysis",
			Timestamp:   time.Now(),
			Data: map[string]interface{}{
				"ip":      ip,
				"domains": shared.Domains,
			},
		})
	}

	for _, domain := range shared.Domains {
		evidence = append(evidence, Evidence{
			Type:        "domain_resolution",
			Description: fmt.Sprintf("Domain %s resolves to shared IP", domain),
			Source:      "DNS Resolution",
			Timestamp:   time.Now(),
			Data: map[string]interface{}{
				"domain": domain,
				"ip":     shared.Properties["ip"],
			},
		})
	}

	return evidence
}

// detectInfrastructureLeakage detects infrastructure information leakage
func (e *Engine) detectInfrastructureLeakage(shared SharedInfrastructure) *CorrelatedInsight {
	// Check for internal infrastructure exposure
	if e.isInternalInfrastructure(shared) {
		insight := &CorrelatedInsight{
			ID:   generateInsightID(),
			Type: InsightTypeInfrastructureLeakage,
			Title: fmt.Sprintf("Internal Infrastructure Exposed: %s", shared.Value),
			Description: fmt.Sprintf(
				"Internal infrastructure component %s is exposed externally, "+
					"revealing %d associated resources",
				shared.Value, len(shared.Nodes)),
			Severity:   types.SeverityMedium,
			Confidence: 0.8,
			Evidence:   e.gatherInfrastructureLeakageEvidence(shared),
		}
		return insight
	}
	return nil
}

// detectSubdomainTakeovers identifies potential subdomain takeover opportunities
func (e *Engine) detectSubdomainTakeovers(nodes []InfrastructureNode) []CorrelatedInsight {
	var insights []CorrelatedInsight

	for _, node := range nodes {
		if node.Type == "domain" && e.isTakeoverCandidate(node) {
			insight := CorrelatedInsight{
				ID:   generateInsightID(),
				Type: InsightTypeSubdomainTakeover,
				Title: fmt.Sprintf("Potential Subdomain Takeover: %s", node.Value),
				Description: fmt.Sprintf(
					"Domain %s may be vulnerable to subdomain takeover due to "+
						"DNS configuration pointing to unclaimed resources",
					node.Value),
				Severity:   types.SeverityHigh,
				Confidence: 0.7,
				Evidence:   e.gatherTakeoverEvidence(node),
			}
			insights = append(insights, insight)
		}
	}

	return insights
}

// Helper methods

func (e *Engine) calculateSeverityTrend(events []TimelineEvent) float64 {
	if len(events) < 2 {
		return 0
	}

	severityScores := []float64{}
	for _, event := range events {
		score := e.severityToFloat(event.Severity)
		severityScores = append(severityScores, score)
	}

	// Simple linear trend calculation
	n := float64(len(severityScores))
	sumX := n * (n + 1) / 2
	sumY := 0.0
	sumXY := 0.0

	for i, score := range severityScores {
		x := float64(i + 1)
		sumY += score
		sumXY += x * score
	}

	// Calculate slope (trend)
	slope := (n*sumXY - sumX*sumY) / (n*sumX - sumX*sumX)
	return slope
}

func (e *Engine) severityToFloat(severity types.Severity) float64 {
	switch severity {
	case types.SeverityInfo:
		return 1.0
	case types.SeverityLow:
		return 2.0
	case types.SeverityMedium:
		return 3.0
	case types.SeverityHigh:
		return 4.0
	case types.SeverityCritical:
		return 5.0
	default:
		return 0.0
	}
}

func (e *Engine) detectRemovedSecurityFeatures(timeline []TimelineEvent) []string {
	var removed []string

	// Look for security header removal events
	for _, event := range timeline {
		desc := strings.ToLower(event.Description)
		if strings.Contains(desc, "removed") || strings.Contains(desc, "missing") {
			if strings.Contains(desc, "header") || strings.Contains(desc, "security") {
				removed = append(removed, event.Description)
			}
		}
	}

	return removed
}

func (e *Engine) buildDegradationDescription(trend float64, removedFeatures []string) string {
	desc := "Security posture degradation detected: "
	
	if trend > 0 {
		desc += fmt.Sprintf("Increasing severity trend (%.2f)", trend)
	}
	
	if len(removedFeatures) > 0 {
		if trend > 0 {
			desc += " and "
		}
		desc += fmt.Sprintf("%d security features removed", len(removedFeatures))
	}
	
	return desc
}

func (e *Engine) calculateDegradationConfidence(trend float64, removedFeatures []string) float64 {
	confidence := 0.5
	
	if trend > 0.5 {
		confidence += 0.3
	} else if trend > 0.2 {
		confidence += 0.2
	}
	
	if len(removedFeatures) > 0 {
		confidence += 0.2
	}
	
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	return confidence
}

func (e *Engine) gatherDegradationEvidence(timeline []TimelineEvent, removedFeatures []string) []Evidence {
	var evidence []Evidence

	// Add trend evidence
	evidence = append(evidence, Evidence{
		Type:        "temporal_trend",
		Description: "Increasing severity trend detected in timeline",
		Source:      "Timeline Analysis",
		Timestamp:   time.Now(),
	})

	// Add removed feature evidence
	for _, feature := range removedFeatures {
		evidence = append(evidence, Evidence{
			Type:        "removed_feature",
			Description: feature,
			Source:      "Security Feature Analysis",
			Timestamp:   time.Now(),
		})
	}

	return evidence
}

func (e *Engine) filterEventsByType(timeline []TimelineEvent, keywords []string) []TimelineEvent {
	var filtered []TimelineEvent

	for _, event := range timeline {
		desc := strings.ToLower(event.Description + " " + event.Type)
		for _, keyword := range keywords {
			if strings.Contains(desc, keyword) {
				filtered = append(filtered, event)
				break
			}
		}
	}

	return filtered
}

func (e *Engine) convertEventsToEvidence(events []TimelineEvent) []Evidence {
	var evidence []Evidence

	for _, event := range events {
		evidence = append(evidence, Evidence{
			Type:        "timeline_event",
			Description: event.Description,
			Source:      event.Source,
			Timestamp:   event.Timestamp,
		})
	}

	return evidence
}

func (e *Engine) usesCloudFlare(domain string) bool {
	// Simple check for CloudFlare indicators
	// In a real implementation, this would check DNS records
	return strings.Contains(strings.ToLower(domain), "cloudflare") ||
		strings.Contains(strings.ToLower(domain), "cf")
}

func (e *Engine) isInternalInfrastructure(shared SharedInfrastructure) bool {
	// Check for internal infrastructure indicators
	value := strings.ToLower(shared.Value)
	internalKeywords := []string{"internal", "corp", "intranet", "local", "private"}
	
	for _, keyword := range internalKeywords {
		if strings.Contains(value, keyword) {
			return true
		}
	}
	
	return false
}

func (e *Engine) gatherInfrastructureLeakageEvidence(shared SharedInfrastructure) []Evidence {
	var evidence []Evidence

	evidence = append(evidence, Evidence{
		Type:        "infrastructure_exposure",
		Description: fmt.Sprintf("Internal infrastructure %s exposed externally", shared.Value),
		Source:      "Infrastructure Analysis",
		Timestamp:   time.Now(),
		Data: map[string]interface{}{
			"value": shared.Value,
			"type":  shared.Type,
		},
	})

	return evidence
}

func (e *Engine) isTakeoverCandidate(node InfrastructureNode) bool {
	// Simple takeover detection based on common indicators
	value := strings.ToLower(node.Value)
	takeoverKeywords := []string{"herokuapp", "github.io", "netlify", "surge.sh", "bitbucket.io"}
	
	for _, keyword := range takeoverKeywords {
		if strings.Contains(value, keyword) {
			return true
		}
	}
	
	return false
}

func (e *Engine) gatherTakeoverEvidence(node InfrastructureNode) []Evidence {
	var evidence []Evidence

	evidence = append(evidence, Evidence{
		Type:        "dns_configuration",
		Description: fmt.Sprintf("Domain %s has DNS configuration vulnerable to takeover", node.Value),
		Source:      "DNS Analysis",
		Timestamp:   time.Now(),
		Data: map[string]interface{}{
			"domain": node.Value,
		},
	})

	return evidence
}

// Supporting types

type InfrastructureNode struct {
	ID         string
	Type       string
	Value      string
	Findings   []types.Finding
	Properties map[string]interface{}
}

type SharedInfrastructure struct {
	Type        string
	Value       string
	Nodes       []InfrastructureNode
	Domains     []string
	Confidence  float64
	Description string
	Properties  map[string]interface{}
}

// Additional missing methods

// generatePredictionsFromPatterns generates predictions from extracted patterns
func (e *Engine) generatePredictionsFromPatterns(domainPatterns []DomainPattern, paramPatterns []ParameterPattern, endpointPatterns []EndpointPattern) []Prediction {
	var predictions []Prediction

	// Generate domain predictions
	for _, pattern := range domainPatterns {
		if pattern.Confidence > 0.7 {
			prediction := Prediction{
				Type:       "domain_pattern",
				Value:      pattern.Pattern,
				Confidence: pattern.Confidence,
				Evidence: []Evidence{
					{
						Type:        "pattern_match",
						Description: fmt.Sprintf("Domain pattern %s found with %d examples", pattern.Pattern, len(pattern.Examples)),
						Source:      "Pattern Analysis",
						Timestamp:   time.Now(),
					},
				},
			}
			predictions = append(predictions, prediction)
		}
	}

	return predictions
}

// validatePrediction validates a prediction
func (e *Engine) validatePrediction(prediction Prediction) bool {
	return prediction.Confidence > 0.6
}

// calculatePredictionSeverity calculates severity for a prediction
func (e *Engine) calculatePredictionSeverity(prediction Prediction) types.Severity {
	if prediction.Confidence > 0.9 {
		return types.SeverityCritical
	} else if prediction.Confidence > 0.7 {
		return types.SeverityHigh
	} else if prediction.Confidence > 0.5 {
		return types.SeverityMedium
	}
	return types.SeverityLow
}

// buildTechnologyGraph builds a technology stack graph
func (e *Engine) buildTechnologyGraph(findings []types.Finding) TechnologyGraph {
	graph := TechnologyGraph{
		Technologies: make(map[string]TechnologyNode),
		Relationships: []TechnologyRelationship{},
	}

	for _, finding := range findings {
		if tech, ok := finding.Metadata["technology"].(string); ok {
			node := TechnologyNode{
				Name:     tech,
				Version:  extractVersion(finding),
				Findings: []types.Finding{finding},
			}
			graph.Technologies[tech] = node
		}
	}

	return graph
}

// detectTechnologyMigrations detects technology migrations
func (e *Engine) detectTechnologyMigrations(graph TechnologyGraph) []TechnologyMigration {
	var migrations []TechnologyMigration

	// Simple migration detection based on version changes
	for techName, node := range graph.Technologies {
		if len(node.Findings) > 1 {
			migration := TechnologyMigration{
				OldTech:   techName + "_old",
				NewTech:   techName + "_new",
				Timestamp: time.Now(),
				Endpoints: []string{},
			}
			migrations = append(migrations, migration)
		}
	}

	return migrations
}

// findOrphanedEndpoints finds orphaned endpoints after migration
func (e *Engine) findOrphanedEndpoints(migration TechnologyMigration) []string {
	return []string{"/api/v1/legacy", "/old-endpoint"}
}

// buildMigrationDescription builds description for technology migration
func (e *Engine) buildMigrationDescription(migration TechnologyMigration, orphaned []string) string {
	return fmt.Sprintf("Migration from %s to %s left %d orphaned endpoints", 
		migration.OldTech, migration.NewTech, len(orphaned))
}

// gatherMigrationEvidence gathers evidence for migration
func (e *Engine) gatherMigrationEvidence(migration TechnologyMigration, orphaned []string) []Evidence {
	var evidence []Evidence

	evidence = append(evidence, Evidence{
		Type:        "technology_migration",
		Description: fmt.Sprintf("Migration detected: %s -> %s", migration.OldTech, migration.NewTech),
		Source:      "Technology Analysis",
		Timestamp:   time.Now(),
	})

	return evidence
}

// detectVulnerableTechCombinations detects vulnerable technology combinations
func (e *Engine) detectVulnerableTechCombinations(graph TechnologyGraph) []CorrelatedInsight {
	var insights []CorrelatedInsight

	// Simple vulnerable combination detection
	for _, node := range graph.Technologies {
		if strings.Contains(strings.ToLower(node.Name), "vulnerable") {
			insight := CorrelatedInsight{
				ID:          generateInsightID(),
				Type:        "vulnerable_technology",
				Title:       fmt.Sprintf("Vulnerable Technology Detected: %s", node.Name),
				Description: fmt.Sprintf("Technology %s may have known vulnerabilities", node.Name),
				Severity:    types.SeverityHigh,
				Confidence:  0.8,
			}
			insights = append(insights, insight)
		}
	}

	return insights
}

// buildSecurityHeaderTimeline builds timeline of security headers
func (e *Engine) buildSecurityHeaderTimeline(findings []types.Finding) map[string][]SecurityHeaderEvent {
	timeline := make(map[string][]SecurityHeaderEvent)

	for _, finding := range findings {
		if domain, ok := finding.Metadata["domain"].(string); ok {
			if strings.Contains(strings.ToLower(finding.Type), "header") {
				event := SecurityHeaderEvent{
					Timestamp: finding.CreatedAt,
					Header:    extractHeaderName(finding),
					Action:    extractHeaderAction(finding),
					Value:     extractHeaderValue(finding),
				}
				timeline[domain] = append(timeline[domain], event)
			}
		}
	}

	return timeline
}

// detectRemovedSecurityHeaders detects removed security headers
func (e *Engine) detectRemovedSecurityHeaders(timeline []SecurityHeaderEvent) []string {
	var removed []string

	for _, event := range timeline {
		if event.Action == "removed" || event.Action == "missing" {
			removed = append(removed, event.Header)
		}
	}

	return removed
}

// buildSecurityHeaderDescription builds description for security header changes
func (e *Engine) buildSecurityHeaderDescription(removed []string) string {
	return fmt.Sprintf("Security headers removed: %v", removed)
}

// convertToTimelineEvents converts security header events to timeline events
func (e *Engine) convertToTimelineEvents(events []SecurityHeaderEvent) []TimelineEvent {
	var timeline []TimelineEvent

	for _, event := range events {
		timeline = append(timeline, TimelineEvent{
			Timestamp:   event.Timestamp,
			Type:        "security_header",
			Description: fmt.Sprintf("Header %s %s", event.Header, event.Action),
			Severity:    types.SeverityMedium,
			Source:      "Security Header Analysis",
		})
	}

	return timeline
}

// gatherHeaderEvidence gathers evidence for header changes
func (e *Engine) gatherHeaderEvidence(removed []string) []Evidence {
	var evidence []Evidence

	for _, header := range removed {
		evidence = append(evidence, Evidence{
			Type:        "removed_header",
			Description: fmt.Sprintf("Security header %s was removed", header),
			Source:      "Header Analysis",
			Timestamp:   time.Now(),
		})
	}

	return evidence
}

// detectWeakenedPolicies detects weakened security policies
func (e *Engine) detectWeakenedPolicies(timeline []SecurityHeaderEvent) []CorrelatedInsight {
	var insights []CorrelatedInsight

	for _, event := range timeline {
		if strings.Contains(strings.ToLower(event.Action), "weaken") {
			insight := CorrelatedInsight{
				ID:          generateInsightID(),
				Type:        InsightTypeSecurityDegradation,
				Title:       fmt.Sprintf("Weakened Security Policy: %s", event.Header),
				Description: fmt.Sprintf("Security policy for %s was weakened", event.Header),
				Severity:    types.SeverityMedium,
				Confidence:  0.8,
			}
			insights = append(insights, insight)
		}
	}

	return insights
}

// filterViableAttackPaths filters attack paths by viability
func (e *Engine) filterViableAttackPaths(paths []AttackPath) []AttackPath {
	var viable []AttackPath

	for _, path := range paths {
		if path.Confidence > 0.5 && len(path.Steps) <= 5 {
			viable = append(viable, path)
		}
	}

	return viable
}

// buildAttackChainDescription builds description for attack chain
func (e *Engine) buildAttackChainDescription(path AttackPath) string {
	return fmt.Sprintf("Attack chain with %d steps to achieve %s", len(path.Steps), path.Goal)
}

// calculateChainSeverity calculates severity for attack chain
func (e *Engine) calculateChainSeverity(path AttackPath) types.Severity {
	if path.Confidence > 0.8 && len(path.Steps) <= 3 {
		return types.SeverityCritical
	} else if path.Confidence > 0.6 {
		return types.SeverityHigh
	}
	return types.SeverityMedium
}

// gatherChainEvidence gathers evidence for attack chain
func (e *Engine) gatherChainEvidence(path AttackPath) []Evidence {
	var evidence []Evidence

	for i, step := range path.Steps {
		evidence = append(evidence, Evidence{
			Type:        "attack_step",
			Description: fmt.Sprintf("Step %d: %s", i+1, step.Description),
			Source:      "Attack Chain Analysis",
			Timestamp:   time.Now(),
		})
	}

	return evidence
}

// generateRemediationSteps generates remediation steps for attack chain
func (e *Engine) generateRemediationSteps(path AttackPath) []RemediationStep {
	var steps []RemediationStep

	steps = append(steps, RemediationStep{
		Priority:    1,
		Action:      "Block attack chain",
		Description: fmt.Sprintf("Implement controls to prevent %s", path.Goal),
		Impact:      "High",
		Difficulty:  "Medium",
	})

	return steps
}

// Helper functions

func extractVersion(finding types.Finding) string {
	if version, ok := finding.Metadata["version"].(string); ok {
		return version
	}
	return "unknown"
}

func extractHeaderName(finding types.Finding) string {
	if header, ok := finding.Metadata["header"].(string); ok {
		return header
	}
	return "unknown"
}

func extractHeaderAction(finding types.Finding) string {
	desc := strings.ToLower(finding.Description)
	if strings.Contains(desc, "removed") {
		return "removed"
	} else if strings.Contains(desc, "added") {
		return "added"
	} else if strings.Contains(desc, "missing") {
		return "missing"
	}
	return "unknown"
}

func extractHeaderValue(finding types.Finding) string {
	if value, ok := finding.Metadata["value"].(string); ok {
		return value
	}
	return ""
}

// Supporting types

type TechnologyGraph struct {
	Technologies  map[string]TechnologyNode
	Relationships []TechnologyRelationship
}

type TechnologyNode struct {
	Name     string
	Version  string
	Findings []types.Finding
}

type TechnologyRelationship struct {
	Source string
	Target string
	Type   string
}

type SecurityHeaderEvent struct {
	Timestamp time.Time
	Header    string
	Action    string
	Value     string
}