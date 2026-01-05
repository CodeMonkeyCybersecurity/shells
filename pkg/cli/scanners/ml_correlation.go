package scanners

// ML and Correlation Analysis Functions
//
// Extracted from cmd/root.go Phase 2 refactoring (2025-10-06)
// Contains machine learning vulnerability prediction and correlation analysis

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/cli/adapters"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/ml"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// RunMLPrediction uses machine learning to predict vulnerabilities
func (e *ScanExecutor) RunMLPrediction(ctx context.Context, target string) error {
	e.log.Infow("Running ML Vulnerability Prediction")

	// Create ML configuration
	analyzerConfig := ml.AnalyzerConfig{
		FingerprintDB:  "fingerprints.json",
		StrategyDB:     "strategies.json",
		CacheSize:      1000,
		CacheTTL:       30 * time.Minute,
		MaxConcurrency: 10,
		RequestTimeout: 30 * time.Second,
		UserAgent:      "Shells Security Scanner",
		UpdateInterval: 24 * time.Hour,
	}

	// Create tech stack analyzer
	techAnalyzer, err := ml.NewTechStackAnalyzer(analyzerConfig, e.log.WithComponent("ml-techstack"))
	if err != nil {
		e.log.LogError(ctx, err, "Failed to create tech stack analyzer")
		e.log.Errorw("ML Vulnerability Prediction failed",
			"reason", "tech analyzer init failed")
		return err
	}

	// Analyze technology stack
	techResult, err := techAnalyzer.AnalyzeTechStack(ctx, target)
	if err != nil {
		e.log.LogError(ctx, err, "Tech stack analysis failed", "target", target)
	} else if techResult != nil {
		// Log discovered technologies
		for _, tech := range techResult.Technologies {
			e.log.Debugw("Discovered technology",
				"name", tech.Name,
				"version", tech.Version,
				"confidence", tech.Confidence)
		}

		// Create findings for high-confidence vulnerabilities
		var findings []types.Finding
		for _, vuln := range techResult.Vulnerabilities {
			if vuln.Severity == "CRITICAL" || vuln.Severity == "HIGH" {
				finding := types.Finding{
					ID:          fmt.Sprintf("ml-tech-%s-%d", vuln.Technology, time.Now().Unix()),
					ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
					Type:        "ML Technology Vulnerability",
					Severity:    types.SeverityHigh,
					Title:       fmt.Sprintf("%s in %s", vuln.Type, vuln.Technology),
					Description: vuln.Description,
					Tool:        "ml-techstack",
					Evidence: fmt.Sprintf("Technology: %s, CVE: %s, Exploitable: %v",
						vuln.Technology, vuln.CVE, vuln.Exploitable),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}

				if vuln.Severity == "CRITICAL" {
					finding.Severity = types.SeverityCritical
				}

				findings = append(findings, finding)
			}
		}

		// Save findings
		if len(findings) > 0 && e.store != nil {
			if err := e.store.SaveFindings(ctx, findings); err != nil {
				e.log.LogError(ctx, err, "Failed to save ML tech findings")
			}
		}
	}

	// Create vulnerability predictor
	predictorConfig := ml.PredictorConfig{
		ModelPath:         "model.json",
		MinConfidence:     0.7,
		HistoryWindowDays: 30,
		CacheSize:         500,
		UpdateInterval:    6 * time.Hour,
		FeatureVersion:    "1.0",
	}

	// Create simple history store
	historyStore := adapters.NewMLHistoryStore(e.store, e.log)

	vulnPredictor, err := ml.NewVulnPredictor(predictorConfig, historyStore, e.log.WithComponent("ml-predictor"))
	if err != nil {
		e.log.LogError(ctx, err, "Failed to create vulnerability predictor")
		e.log.Warnw("ML Vulnerability Prediction completed partially")
		return nil // Don't fail completely
	}

	// Predict vulnerabilities
	predictionResult, err := vulnPredictor.PredictVulnerabilities(ctx, target)
	if err != nil {
		e.log.LogError(ctx, err, "Vulnerability prediction failed", "target", target)
	} else if predictionResult != nil {
		// Create findings for high-confidence predictions
		var findings []types.Finding
		for _, pred := range predictionResult.Predictions {
			if pred.Probability >= 0.75 {
				finding := types.Finding{
					ID:       fmt.Sprintf("ml-pred-%s-%d", pred.VulnerabilityType, time.Now().Unix()),
					ScanID:   fmt.Sprintf("scan-%d", time.Now().Unix()),
					Type:     "ML Predicted Vulnerability",
					Severity: types.SeverityMedium,
					Title: fmt.Sprintf("Predicted: %s (%.0f%% confidence)",
						pred.VulnerabilityType, pred.Probability*100),
					Description: pred.Description,
					Tool:        "ml-predictor",
					Evidence: fmt.Sprintf("Indicators: %v, False Positive Rate: %.2f",
						pred.Indicators, pred.FalsePositiveRate),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}

				// Adjust severity based on prediction
				switch pred.Severity {
				case "CRITICAL":
					finding.Severity = types.SeverityCritical
				case "HIGH":
					finding.Severity = types.SeverityHigh
				case "LOW":
					finding.Severity = types.SeverityLow
				}

				findings = append(findings, finding)
			}
		}

		// Log recommendations
		if len(predictionResult.RecommendedScans) > 0 {
			e.log.Infow("ML recommended scans",
				"target", target,
				"scans", predictionResult.RecommendedScans,
				"risk_score", predictionResult.RiskScore)
		}

		// Save findings
		if len(findings) > 0 && e.store != nil {
			if err := e.store.SaveFindings(ctx, findings); err != nil {
				e.log.LogError(ctx, err, "Failed to save ML prediction findings")
			}
		}
	}

	e.log.Infow("ML Vulnerability Prediction completed successfully")
	return nil
}

// mlHistoryStore and InMemoryGraphDB moved to cmd/internal/adapters package

// runCorrelationAnalysis performs correlation analysis on all collected findings
func (e *ScanExecutor) runCorrelationAnalysis(ctx context.Context, target string, findings []types.Finding) []types.Finding {
	e.log.WithContext(ctx).Debugw("Starting correlation analysis", "target", target, "findings_count", len(findings))

	if len(findings) < 2 {
		// Need at least 2 findings to correlate
		return []types.Finding{}
	}

	// Create correlation engine with in-memory graph database
	graphDB := adapters.NewInMemoryGraphDB()
	engine := correlation.NewEngine(e.log.WithComponent("correlation"), graphDB)

	// Run correlation analysis
	insights := engine.Correlate(findings)

	// Convert correlation insights to standard findings
	var correlationFindings []types.Finding
	for _, insight := range insights {
		finding := types.Finding{
			ID:          insight.ID,
			ScanID:      fmt.Sprintf("correlation-%d", time.Now().Unix()),
			Type:        string(insight.Type),
			Severity:    insight.Severity,
			Title:       insight.Title,
			Description: insight.Description,
			Tool:        "correlation-engine",
			Evidence:    buildCorrelationEvidence(insight),
			Solution:    buildCorrelationSolution(insight),
			Metadata: map[string]interface{}{
				"confidence":      insight.Confidence,
				"evidence_count":  len(insight.Evidence),
				"timeline_events": len(insight.Timeline),
				"attack_path":     insight.AttackPath != nil,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		correlationFindings = append(correlationFindings, finding)
	}

	e.log.WithContext(ctx).Infow("Correlation analysis completed",
		"target", target,
		"input_findings", len(findings),
		"correlation_insights", len(insights),
		"correlation_findings", len(correlationFindings))

	return correlationFindings
}

// buildCorrelationEvidence builds evidence string from correlation insight
func buildCorrelationEvidence(insight correlation.CorrelatedInsight) string {
	var evidence strings.Builder

	evidence.WriteString(fmt.Sprintf("Correlation Insight: %s\n", insight.Type))
	evidence.WriteString(fmt.Sprintf("Confidence: %.2f\n", insight.Confidence))

	if len(insight.Evidence) > 0 {
		evidence.WriteString("Supporting Evidence:\n")
		for i, ev := range insight.Evidence {
			if i >= 5 { // Limit to 5 pieces of evidence
				evidence.WriteString(fmt.Sprintf("... and %d more pieces of evidence\n", len(insight.Evidence)-5))
				break
			}
			evidence.WriteString(fmt.Sprintf("- %s: %s\n", ev.Type, ev.Description))
		}
	}

	if insight.AttackPath != nil {
		evidence.WriteString(fmt.Sprintf("Attack Chain: %d steps to %s\n",
			len(insight.AttackPath.Steps), insight.AttackPath.Goal))
	}

	return evidence.String()
}

// buildCorrelationSolution builds solution recommendations from correlation insight
func buildCorrelationSolution(insight correlation.CorrelatedInsight) string {
	var solution strings.Builder

	switch insight.Type {
	case correlation.InsightTypeOriginServerExposed:
		solution.WriteString("Ensure origin servers are not directly accessible from the internet. ")
		solution.WriteString("Configure proper firewall rules and use CDN protection.")
	case correlation.InsightTypeSubdomainTakeover:
		solution.WriteString("Remove or update DNS records pointing to unclaimed resources. ")
		solution.WriteString("Implement monitoring for subdomain takeover attempts.")
	case correlation.InsightTypeAPIVersionVulnerable:
		solution.WriteString("Properly decommission old API versions. ")
		solution.WriteString("Implement version sunset policies with proper redirects.")
	case correlation.InsightTypeSecurityDegradation:
		solution.WriteString("Review security posture changes. ")
		solution.WriteString("Restore removed security headers and strengthen security policies.")
	case correlation.InsightTypeInfrastructureLeakage:
		solution.WriteString("Prevent infrastructure information disclosure. ")
		solution.WriteString("Review server configurations and error messages.")
	case correlation.InsightTypeCredentialExposure:
		solution.WriteString("Immediately rotate exposed credentials. ")
		solution.WriteString("Implement secrets management and scanning.")
	case correlation.InsightTypeAttackChainIdentified:
		solution.WriteString("Review and mitigate the identified attack chain. ")
		solution.WriteString("Implement defense-in-depth controls to break the attack path.")
	default:
		solution.WriteString("Review correlation findings and implement appropriate security controls.")
	}

	// Add remediation steps if available
	if len(insight.Remediation) > 0 {
		solution.WriteString("\n\nSpecific Remediation Steps:\n")
		for _, step := range insight.Remediation {
			solution.WriteString(fmt.Sprintf("%d. %s: %s\n",
				step.Priority, step.Action, step.Description))
		}
	}

	return solution.String()
}
