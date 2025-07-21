// internal/discovery/ml_module.go
package discovery

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/ml"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// MLDiscovery uses machine learning for intelligent discovery and vulnerability prediction
type MLDiscovery struct {
	config        *DiscoveryConfig
	logger        *logger.Logger
	techAnalyzer  *ml.TechStackAnalyzer
	vulnPredictor *ml.VulnPredictor
}

// NewMLDiscovery creates a new ML-powered discovery module
func NewMLDiscovery(config *DiscoveryConfig, logger *logger.Logger) *MLDiscovery {
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

	techAnalyzer, err := ml.NewTechStackAnalyzer(analyzerConfig, logger)
	if err != nil {
		logger.Errorw("Failed to create tech stack analyzer", "error", err)
		// Create with minimal functionality
		techAnalyzer = nil
	}

	// Create vulnerability predictor configuration
	predictorConfig := ml.PredictorConfig{
		ModelPath:         "model.json",
		MinConfidence:     0.6,
		HistoryWindowDays: 30,
		CacheSize:         500,
		UpdateInterval:    6 * time.Hour,
		FeatureVersion:    "1.0",
	}

	// Create a simple history store adapter
	historyStore := &simpleHistoryStore{logger: logger}

	vulnPredictor, err := ml.NewVulnPredictor(predictorConfig, historyStore, logger)
	if err != nil {
		logger.Errorw("Failed to create vulnerability predictor", "error", err)
		vulnPredictor = nil
	}

	return &MLDiscovery{
		config:        config,
		logger:        logger.WithComponent("ml-discovery"),
		techAnalyzer:  techAnalyzer,
		vulnPredictor: vulnPredictor,
	}
}

func (m *MLDiscovery) Name() string  { return "ml_discovery" }
func (m *MLDiscovery) Priority() int { return 50 } // Run after basic discovery

func (m *MLDiscovery) CanHandle(target *Target) bool {
	// ML can enhance any target type with predictions
	return target.Type == TargetTypeDomain || target.Type == TargetTypeURL
}

func (m *MLDiscovery) Discover(ctx context.Context, target *Target, session *DiscoverySession) (*DiscoveryResult, error) {
	result := &DiscoveryResult{
		Assets:        []*Asset{},
		Relationships: []*Relationship{},
		Source:        m.Name(),
	}

	// Skip if ML components are not available
	if m.techAnalyzer == nil && m.vulnPredictor == nil {
		return result, nil
	}

	m.logger.Debug("Starting ML-powered discovery", "target", target.Value)

	// Analyze technology stack if we have a URL
	var techResult *ml.TechStackResult
	if target.Type == TargetTypeURL || target.Type == TargetTypeDomain {
		url := target.Value
		if target.Type == TargetTypeDomain {
			url = "https://" + target.Value
		}

		if m.techAnalyzer != nil {
			var err error
			techResult, err = m.techAnalyzer.AnalyzeTechStack(ctx, url)
			if err != nil {
				m.logger.Errorw("Tech stack analysis failed", "error", err)
			} else {
				// Add technology insights as metadata
				for _, tech := range techResult.Technologies {
					asset := &Asset{
						Type:       AssetTypeTechnology,
						Value:      fmt.Sprintf("%s %s", tech.Name, tech.Version),
						Domain:     target.Value,
						Technology: []string{tech.Name},
						Metadata: map[string]string{
							"version":    tech.Version,
							"category":   tech.Category,
							"confidence": fmt.Sprintf("%.2f", tech.Confidence),
						},
						Source:       m.Name(),
						Confidence:   tech.Confidence,
						DiscoveredAt: time.Now(),
						LastSeen:     time.Now(),
					}

					// Add CVEs if present
					if len(tech.CVEs) > 0 {
						asset.Metadata["cves"] = fmt.Sprintf("%v", tech.CVEs)
					}

					result.Assets = append(result.Assets, asset)
				}
			}
		}
	}

	// Predict vulnerabilities
	if m.vulnPredictor != nil {
		predictionResult, err := m.vulnPredictor.PredictVulnerabilities(ctx, target.Value)
		if err != nil {
			m.logger.Errorw("Vulnerability prediction failed", "error", err)
		} else {
			// Add predicted vulnerabilities as high-priority assets
			for _, pred := range predictionResult.Predictions {
				if pred.Probability >= 0.7 { // Only high-confidence predictions
					asset := &Asset{
						Type:   AssetTypeVulnerability,
						Value:  fmt.Sprintf("Predicted: %s (%.0f%%)", pred.VulnerabilityType, pred.Probability*100),
						Domain: target.Value,
						Title:  pred.Description,
						Metadata: map[string]string{
							"vulnerability_type": pred.VulnerabilityType,
							"probability":        fmt.Sprintf("%.2f", pred.Probability),
							"severity":           pred.Severity,
							"false_positive":     fmt.Sprintf("%.2f", pred.FalsePositiveRate),
						},
						Source:       m.Name(),
						Confidence:   pred.Probability,
						DiscoveredAt: time.Now(),
						LastSeen:     time.Now(),
					}

					// Mark as high-value if critical or high severity
					if pred.Severity == "CRITICAL" || pred.Severity == "HIGH" {
						// High-value assets are marked by metadata
						asset.Metadata["high_value"] = "true"
					}

					result.Assets = append(result.Assets, asset)
				}
			}

			// Add recommended scans as metadata
			if len(predictionResult.RecommendedScans) > 0 {
				recommendAsset := &Asset{
					Type:   AssetTypeMetadata,
					Value:  "ML Scan Recommendations",
					Domain: target.Value,
					Title:  fmt.Sprintf("Risk Score: %.1f/10", predictionResult.RiskScore),
					Metadata: map[string]string{
						"recommended_scans": fmt.Sprintf("%v", predictionResult.RecommendedScans),
						"risk_score":        fmt.Sprintf("%.1f", predictionResult.RiskScore),
						"confidence":        fmt.Sprintf("%.2f", predictionResult.Confidence),
					},
					Source:       m.Name(),
					Confidence:   0.9,
					DiscoveredAt: time.Now(),
					LastSeen:     time.Now(),
				}
				result.Assets = append(result.Assets, recommendAsset)
			}
		}
	}

	m.logger.Debug("ML discovery completed", "target", target.Value, "assets_found", len(result.Assets))
	return result, nil
}

// Simple history store implementation
type simpleHistoryStore struct {
	logger *logger.Logger
}

func (s *simpleHistoryStore) GetScanHistory(target string, window time.Duration) ([]types.Finding, error) {
	// In a real implementation, this would query the database
	return []types.Finding{}, nil
}

func (s *simpleHistoryStore) GetSimilarTargets(features map[string]interface{}, limit int) ([]ml.ScanTarget, error) {
	// In a real implementation, this would find similar targets from the database
	return []ml.ScanTarget{}, nil
}

func (s *simpleHistoryStore) StorePrediction(result *ml.PredictionResult) error {
	// In a real implementation, this would store predictions in the database
	s.logger.Debug("Storing ML prediction", "target", result.Target, "predictions", len(result.Predictions))
	return nil
}

func (s *simpleHistoryStore) GetPredictionAccuracy(predictionID string) (float64, error) {
	// In a real implementation, this would calculate accuracy from feedback
	return 0.85, nil // Default accuracy
}

// Asset type constants for ML
const (
	AssetTypeTechnology    AssetType = "technology"
	AssetTypeVulnerability AssetType = "vulnerability"
	AssetTypeMetadata      AssetType = "metadata"
)
