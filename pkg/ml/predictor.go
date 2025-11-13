// pkg/ml/predictor.go
package ml

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// VulnPredictor uses machine learning to predict vulnerabilities based on historical data
type VulnPredictor struct {
	model            *PredictionModel
	featureExtractor *FeatureExtractor
	historyStore     HistoryStore
	cache            *PredictionCache
	config           PredictorConfig
	logger           *logger.Logger
	mu               sync.RWMutex
}

// PredictorConfig holds configuration for the vulnerability predictor
type PredictorConfig struct {
	ModelPath         string
	MinConfidence     float64
	HistoryWindowDays int
	CacheSize         int
	UpdateInterval    time.Duration
	FeatureVersion    string
}

// PredictionModel represents the ML model for vulnerability prediction
type PredictionModel struct {
	Version      string                 `json:"version"`
	Features     []string               `json:"features"`
	Weights      map[string]float64     `json:"weights"`
	Patterns     []VulnerabilityPattern `json:"patterns"`
	TrainingDate time.Time              `json:"training_date"`
	Accuracy     float64                `json:"accuracy"`
}

// VulnerabilityPattern represents learned patterns from previous scans
type VulnerabilityPattern struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Conditions  []PatternCondition     `json:"conditions"`
	Probability float64                `json:"probability"`
	Severity    string                 `json:"severity"`
	CVEs        []string               `json:"cves"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PatternCondition represents conditions that indicate a vulnerability
type PatternCondition struct {
	Feature  string      `json:"feature"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	Weight   float64     `json:"weight"`
}

// FeatureExtractor extracts features from targets for prediction
type FeatureExtractor struct {
	extractors map[string]FeatureExtractorFunc
}

// FeatureExtractorFunc extracts a specific feature from a target
type FeatureExtractorFunc func(ctx context.Context, target *ScanTarget) (interface{}, error)

// ScanTarget represents a target with extracted features
type ScanTarget struct {
	URL           string                 `json:"url"`
	Technology    []string               `json:"technology"`
	Headers       map[string]string      `json:"headers"`
	ResponseCodes []int                  `json:"response_codes"`
	OpenPorts     []int                  `json:"open_ports"`
	Services      []string               `json:"services"`
	Features      map[string]interface{} `json:"features"`
	PreviousVulns []string               `json:"previous_vulns"`
	LastScanDate  time.Time              `json:"last_scan_date"`
}

// PredictionResult contains vulnerability predictions for a target
type PredictionResult struct {
	Target           string           `json:"target"`
	Predictions      []VulnPrediction `json:"predictions"`
	Confidence       float64          `json:"confidence"`
	RecommendedScans []string         `json:"recommended_scans"`
	RiskScore        float64          `json:"risk_score"`
	GeneratedAt      time.Time        `json:"generated_at"`
}

// VulnPrediction represents a predicted vulnerability
type VulnPrediction struct {
	VulnerabilityType string                 `json:"vulnerability_type"`
	Probability       float64                `json:"probability"`
	Severity          string                 `json:"severity"`
	CVEs              []string               `json:"cves,omitempty"`
	Description       string                 `json:"description"`
	Indicators        []string               `json:"indicators"`
	FalsePositiveRate float64                `json:"false_positive_rate"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// HistoryStore interface for accessing historical scan data
type HistoryStore interface {
	GetScanHistory(target string, window time.Duration) ([]types.Finding, error)
	GetSimilarTargets(features map[string]interface{}, limit int) ([]ScanTarget, error)
	StorePrediction(result *PredictionResult) error
	GetPredictionAccuracy(predictionID string) (float64, error)
}

// PredictionCache caches recent predictions
type PredictionCache struct {
	predictions map[string]*PredictionResult
	mu          sync.RWMutex
	maxSize     int
}

// NewVulnPredictor creates a new vulnerability predictor
func NewVulnPredictor(config PredictorConfig, store HistoryStore, log *logger.Logger) (*VulnPredictor, error) {
	model, err := loadModel(config.ModelPath)
	if err != nil {
		// Initialize with default model if loading fails
		model = createDefaultModel()
	}

	predictor := &VulnPredictor{
		model:            model,
		featureExtractor: createFeatureExtractor(),
		historyStore:     store,
		cache:            newPredictionCache(config.CacheSize),
		config:           config,
		logger:           log.WithComponent("vuln-predictor"),
	}

	// Start model update routine
	go predictor.updateModelPeriodically()

	return predictor, nil
}

// PredictVulnerabilities predicts potential vulnerabilities for a target
func (vp *VulnPredictor) PredictVulnerabilities(ctx context.Context, target string) (*PredictionResult, error) {
	// Check cache first
	if cached := vp.cache.get(target); cached != nil && time.Since(cached.GeneratedAt) < 1*time.Hour {
		return cached, nil
	}

	// Extract features from target
	scanTarget, err := vp.extractTargetFeatures(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("failed to extract features: %w", err)
	}

	// Get historical data
	history, err := vp.historyStore.GetScanHistory(target, time.Duration(vp.config.HistoryWindowDays)*24*time.Hour)
	if err != nil {
		// Continue without history, but log the error
		history = []types.Finding{}
	}

	// Get similar targets for comparison
	similarTargets, err := vp.historyStore.GetSimilarTargets(scanTarget.Features, 10)
	if err != nil {
		similarTargets = []ScanTarget{}
	}

	// Generate predictions
	predictions := vp.generatePredictions(scanTarget, history, similarTargets)

	// Calculate overall confidence and risk score
	confidence := vp.calculateConfidence(predictions)
	riskScore := vp.calculateRiskScore(predictions)

	result := &PredictionResult{
		Target:           target,
		Predictions:      predictions,
		Confidence:       confidence,
		RecommendedScans: vp.recommendScans(predictions),
		RiskScore:        riskScore,
		GeneratedAt:      time.Now(),
	}

	// Cache the result
	vp.cache.set(target, result)

	// Store prediction for future model training
	go vp.historyStore.StorePrediction(result)

	return result, nil
}

// extractTargetFeatures extracts ML features from a target
func (vp *VulnPredictor) extractTargetFeatures(ctx context.Context, target string) (*ScanTarget, error) {
	scanTarget := &ScanTarget{
		URL:      target,
		Features: make(map[string]interface{}),
	}

	// Run all feature extractors in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := make([]error, 0)

	for name, extractor := range vp.featureExtractor.extractors {
		wg.Add(1)
		go func(featureName string, extract FeatureExtractorFunc) {
			defer wg.Done()

			value, err := extract(ctx, scanTarget)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("%s: %w", featureName, err))
				mu.Unlock()
				return
			}

			mu.Lock()
			scanTarget.Features[featureName] = value
			mu.Unlock()
		}(name, extractor)
	}

	wg.Wait()

	if len(errors) > 0 {
		// Return partial features even if some extractors fail
		return scanTarget, fmt.Errorf("some features failed to extract: %v", errors)
	}

	return scanTarget, nil
}

// generatePredictions generates vulnerability predictions based on features and patterns
func (vp *VulnPredictor) generatePredictions(target *ScanTarget, history []types.Finding, similar []ScanTarget) []VulnPrediction {
	vp.mu.RLock()
	defer vp.mu.RUnlock()

	predictions := make([]VulnPrediction, 0)
	seen := make(map[string]bool)

	// Apply learned patterns
	for _, pattern := range vp.model.Patterns {
		if vp.matchesPattern(target, pattern) {
			prob := pattern.Probability

			// Adjust probability based on history
			prob = vp.adjustProbabilityFromHistory(prob, pattern.Name, history)

			// Adjust based on similar targets
			prob = vp.adjustProbabilityFromSimilar(prob, pattern.Name, similar)

			if prob >= vp.config.MinConfidence && !seen[pattern.Name] {
				predictions = append(predictions, VulnPrediction{
					VulnerabilityType: pattern.Name,
					Probability:       prob,
					Severity:          pattern.Severity,
					CVEs:              pattern.CVEs,
					Description:       vp.generateDescription(pattern, target),
					Indicators:        vp.getIndicators(pattern, target),
					FalsePositiveRate: vp.calculateFalsePositiveRate(pattern.ID),
					Metadata:          pattern.Metadata,
				})
				seen[pattern.Name] = true
			}
		}
	}

	// Sort by probability
	sortPredictionsByProbability(predictions)

	return predictions
}

// matchesPattern checks if a target matches a vulnerability pattern
func (vp *VulnPredictor) matchesPattern(target *ScanTarget, pattern VulnerabilityPattern) bool {
	matchCount := 0
	totalConditions := len(pattern.Conditions)

	for _, condition := range pattern.Conditions {
		if vp.evaluateCondition(target, condition) {
			matchCount++
		}
	}

	// Pattern matches if at least 70% of conditions are met
	return float64(matchCount)/float64(totalConditions) >= 0.7
}

// evaluateCondition evaluates a single pattern condition
func (vp *VulnPredictor) evaluateCondition(target *ScanTarget, condition PatternCondition) bool {
	feature, exists := target.Features[condition.Feature]
	if !exists {
		return false
	}

	switch condition.Operator {
	case "equals":
		return feature == condition.Value
	case "contains":
		return contains(feature, condition.Value)
	case "greater_than":
		return compareNumeric(feature, condition.Value, ">")
	case "less_than":
		return compareNumeric(feature, condition.Value, "<")
	case "matches":
		return matchesRegex(feature, condition.Value)
	case "in":
		return isIn(feature, condition.Value)
	default:
		return false
	}
}

// recommendScans recommends specific scans based on predictions
func (vp *VulnPredictor) recommendScans(predictions []VulnPrediction) []string {
	scanMap := make(map[string]float64)

	// Map vulnerability types to recommended scans
	vulnToScans := map[string][]string{
		"SQL_INJECTION":           {"sqlmap", "nuclei-sqli"},
		"XSS":                     {"xsstrike", "nuclei-xss"},
		"SSRF":                    {"ssrfmap", "nuclei-ssrf"},
		"XXE":                     {"xxe-scan", "nuclei-xxe"},
		"IDOR":                    {"autorize", "nuclei-idor"},
		"RACE_CONDITION":          {"race-the-web", "turbo-intruder"},
		"OAUTH2_MISCONFIGURATION": {"oauth2-scanner", "nuclei-oauth"},
		"JWT_VULNERABILITY":       {"jwt_tool", "nuclei-jwt"},
		"GRAPHQL_INJECTION":       {"graphql-cop", "nuclei-graphql"},
		"CORS_MISCONFIGURATION":   {"cors-scanner", "nuclei-cors"},
	}

	// Calculate scan priorities based on prediction probabilities
	for _, pred := range predictions {
		if scans, exists := vulnToScans[pred.VulnerabilityType]; exists {
			for _, scan := range scans {
				scanMap[scan] += pred.Probability
			}
		}
	}

	// Sort scans by priority
	return sortScansByPriority(scanMap)
}

// updateModelPeriodically updates the ML model based on new data
func (vp *VulnPredictor) updateModelPeriodically() {
	ticker := time.NewTicker(vp.config.UpdateInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := vp.updateModel(); err != nil {
			// Structured logging with otelzap
			vp.logger.Errorw("Failed to update ML prediction model",
				"error", err,
				"model_version", vp.model.Version,
				"operation", "model_update",
				"component", "ml_predictor",
			)
		}
	}
}

// updateModel updates the prediction model with new data
func (vp *VulnPredictor) updateModel() error {
	// This would typically involve:
	// 1. Fetching recent scan results
	// 2. Evaluating prediction accuracy
	// 3. Retraining or adjusting model weights
	// 4. Updating patterns based on new vulnerabilities

	// For now, we'll implement a simple weight adjustment
	vp.mu.Lock()
	defer vp.mu.Unlock()

	// Placeholder for model update logic
	vp.model.TrainingDate = time.Now()

	return nil
}

// Helper functions

func createDefaultModel() *PredictionModel {
	return &PredictionModel{
		Version: "1.0.0",
		Features: []string{
			"technology_stack",
			"open_ports",
			"response_codes",
			"header_analysis",
			"previous_vulnerabilities",
		},
		Weights: map[string]float64{
			"technology_stack":         0.3,
			"open_ports":               0.2,
			"response_codes":           0.1,
			"header_analysis":          0.2,
			"previous_vulnerabilities": 0.2,
		},
		Patterns:     getDefaultPatterns(),
		TrainingDate: time.Now(),
		Accuracy:     0.85,
	}
}

func createFeatureExtractor() *FeatureExtractor {
	return &FeatureExtractor{
		extractors: map[string]FeatureExtractorFunc{
			"technology_stack": extractTechnologyStack,
			"open_ports":       extractOpenPorts,
			"response_codes":   extractResponseCodes,
			"header_analysis":  extractHeaderAnalysis,
			"service_versions": extractServiceVersions,
		},
	}
}

func getDefaultPatterns() []VulnerabilityPattern {
	return []VulnerabilityPattern{
		{
			ID:   "pattern-sqli-001",
			Name: "SQL_INJECTION",
			Conditions: []PatternCondition{
				{Feature: "technology_stack", Operator: "contains", Value: "php", Weight: 0.3},
				{Feature: "response_codes", Operator: "contains", Value: 500, Weight: 0.2},
				{Feature: "url_parameters", Operator: "greater_than", Value: 2, Weight: 0.2},
			},
			Probability: 0.7,
			Severity:    "HIGH",
			CVEs:        []string{},
		},
		{
			ID:   "pattern-xss-001",
			Name: "XSS",
			Conditions: []PatternCondition{
				{Feature: "technology_stack", Operator: "contains", Value: "javascript", Weight: 0.2},
				{Feature: "input_fields", Operator: "greater_than", Value: 5, Weight: 0.3},
				{Feature: "csp_header", Operator: "equals", Value: nil, Weight: 0.3},
			},
			Probability: 0.6,
			Severity:    "MEDIUM",
			CVEs:        []string{},
		},
	}
}

// Placeholder implementations for feature extractors
func extractTechnologyStack(ctx context.Context, target *ScanTarget) (interface{}, error) {
	// Would perform technology detection
	return []string{"nginx", "php", "mysql"}, nil
}

func extractOpenPorts(ctx context.Context, target *ScanTarget) (interface{}, error) {
	// Would perform port scanning
	return []int{80, 443, 3306}, nil
}

func extractResponseCodes(ctx context.Context, target *ScanTarget) (interface{}, error) {
	// Would analyze HTTP response codes
	return []int{200, 301, 404}, nil
}

func extractHeaderAnalysis(ctx context.Context, target *ScanTarget) (interface{}, error) {
	// Would analyze security headers
	return map[string]bool{
		"x-frame-options": true,
		"csp":             false,
		"hsts":            true,
	}, nil
}

func extractServiceVersions(ctx context.Context, target *ScanTarget) (interface{}, error) {
	// Would extract service version information
	return map[string]string{
		"nginx": "1.18.0",
		"php":   "7.4.3",
	}, nil
}

// Missing helper functions and methods

// loadModel loads a prediction model from file
func loadModel(path string) (*PredictionModel, error) {
	// In a real implementation, this would load from a file
	// For now, return nil to trigger default model creation
	return nil, fmt.Errorf("model loading not implemented")
}

// newPredictionCache creates a new prediction cache
func newPredictionCache(size int) *PredictionCache {
	return &PredictionCache{
		predictions: make(map[string]*PredictionResult),
		maxSize:     size,
	}
}

// get retrieves a cached prediction
func (c *PredictionCache) get(target string) *PredictionResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.predictions[target]
}

// set stores a prediction in cache
func (c *PredictionCache) set(target string, result *PredictionResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple LRU: remove oldest if at capacity
	if len(c.predictions) >= c.maxSize {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range c.predictions {
			if oldestTime.IsZero() || v.GeneratedAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.GeneratedAt
			}
		}
		delete(c.predictions, oldestKey)
	}

	c.predictions[target] = result
}

// calculateConfidence calculates confidence based on multiple factors
func (vp *VulnPredictor) calculateConfidence(predictions []VulnPrediction) float64 {
	if len(predictions) == 0 {
		return 0.0
	}

	totalConfidence := 0.0
	for _, pred := range predictions {
		totalConfidence += pred.Probability
	}

	// Average confidence with adjustment for number of predictions
	avgConfidence := totalConfidence / float64(len(predictions))
	adjustment := math.Min(float64(len(predictions))/10.0, 1.0)

	return avgConfidence * adjustment
}

// calculateRiskScore calculates overall risk score
func (vp *VulnPredictor) calculateRiskScore(predictions []VulnPrediction) float64 {
	if len(predictions) == 0 {
		return 0.0
	}

	riskScore := 0.0
	severityWeights := map[string]float64{
		"CRITICAL": 1.0,
		"HIGH":     0.8,
		"MEDIUM":   0.5,
		"LOW":      0.2,
		"INFO":     0.1,
	}

	for _, pred := range predictions {
		weight := severityWeights[pred.Severity]
		riskScore += pred.Probability * weight
	}

	// Normalize to 0-10 scale
	return math.Min(riskScore*2, 10.0)
}

// adjustProbabilityFromHistory adjusts probability based on historical data
func (vp *VulnPredictor) adjustProbabilityFromHistory(prob float64, vulnType string, history []types.Finding) float64 {
	// Count occurrences of this vulnerability type in history
	count := 0
	for _, finding := range history {
		if finding.Type == vulnType {
			count++
		}
	}

	// Increase probability if found frequently in history
	if count > 0 {
		historicalFactor := math.Min(float64(count)/10.0, 0.3)
		prob = math.Min(prob+historicalFactor, 1.0)
	}

	return prob
}

// adjustProbabilityFromSimilar adjusts probability based on similar targets
func (vp *VulnPredictor) adjustProbabilityFromSimilar(prob float64, vulnType string, similar []ScanTarget) float64 {
	// In a real implementation, this would query similar targets
	// For now, just return the original probability
	return prob
}

// generateDescription generates a description for the prediction
func (vp *VulnPredictor) generateDescription(pattern VulnerabilityPattern, target *ScanTarget) string {
	return fmt.Sprintf("Potential %s vulnerability detected based on pattern matching",
		pattern.Name)
}

// getIndicators extracts indicators for a vulnerability
func (vp *VulnPredictor) getIndicators(pattern VulnerabilityPattern, target *ScanTarget) []string {
	var indicators []string

	for _, condition := range pattern.Conditions {
		if vp.evaluateCondition(target, condition) {
			indicators = append(indicators, fmt.Sprintf("%s %s %v",
				condition.Feature, condition.Operator, condition.Value))
		}
	}

	return indicators
}

// calculateFalsePositiveRate estimates false positive rate
func (vp *VulnPredictor) calculateFalsePositiveRate(patternID string) float64 {
	// In a real implementation, this would be based on feedback data
	// For now, return a default rate
	defaultRates := map[string]float64{
		"pattern-sqli-001": 0.15,
		"pattern-xss-001":  0.20,
		"pattern-xxe-001":  0.10,
		"pattern-ssrf-001": 0.25,
		"pattern-rce-001":  0.05,
	}

	if rate, exists := defaultRates[patternID]; exists {
		return rate
	}
	return 0.15 // Default rate
}

// sortPredictionsByProbability sorts predictions by probability descending
func sortPredictionsByProbability(predictions []VulnPrediction) {
	// Sort in place by probability descending
	for i := 0; i < len(predictions); i++ {
		for j := i + 1; j < len(predictions); j++ {
			if predictions[j].Probability > predictions[i].Probability {
				predictions[i], predictions[j] = predictions[j], predictions[i]
			}
		}
	}
}

// sortScansByPriority sorts scans by their priority score
func sortScansByPriority(scanMap map[string]float64) []string {
	type scanScore struct {
		scan  string
		score float64
	}

	scores := make([]scanScore, 0, len(scanMap))
	for scan, score := range scanMap {
		scores = append(scores, scanScore{scan, score})
	}

	// Sort by score descending
	for i := 0; i < len(scores); i++ {
		for j := i + 1; j < len(scores); j++ {
			if scores[j].score > scores[i].score {
				scores[i], scores[j] = scores[j], scores[i]
			}
		}
	}

	// Extract scan names
	result := make([]string, len(scores))
	for i, ss := range scores {
		result[i] = ss.scan
	}

	return result
}
