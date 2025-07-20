package discovery

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
)

// Engine is the main discovery engine
type Engine struct {
	parser   *TargetParser
	modules  map[string]DiscoveryModule
	config   *DiscoveryConfig
	sessions map[string]*DiscoverySession
	mutex    sync.RWMutex
	logger   *logger.Logger // Enhanced structured logger
}

// DiscoveryModule interface for discovery modules
type DiscoveryModule interface {
	Name() string
	Discover(ctx context.Context, target *Target, session *DiscoverySession) (*DiscoveryResult, error)
	CanHandle(target *Target) bool
	Priority() int
}

// NewEngine creates a new discovery engine
func NewEngine(discoveryConfig *DiscoveryConfig, structLog *logger.Logger) *Engine {
	if discoveryConfig == nil {
		discoveryConfig = DefaultDiscoveryConfig()
	}

	// Initialize enhanced structured logger
	if structLog == nil {
		// Create default logger if none provided
		var err error
		structLog, err = logger.New(config.LoggerConfig{Level: "debug", Format: "json"})
		if err != nil {
			// Fallback to default logger
			structLog, _ = logger.New(config.LoggerConfig{Level: "info", Format: "json"})
		}
	}
	structLog = structLog.WithComponent("discovery")

	engine := &Engine{
		parser:   NewTargetParser(),
		modules:  make(map[string]DiscoveryModule),
		config:   discoveryConfig,
		sessions: make(map[string]*DiscoverySession),
		logger:   structLog,
	}

	// Register default modules
	engine.RegisterModule(NewDomainDiscovery(discoveryConfig, structLog))
	engine.RegisterModule(NewNetworkDiscovery(discoveryConfig, structLog))
	engine.RegisterModule(NewTechnologyDiscovery(discoveryConfig, structLog))
	engine.RegisterModule(NewCompanyDiscovery(discoveryConfig, structLog))
	engine.RegisterModule(NewMLDiscovery(discoveryConfig, structLog))

	return engine
}

// RegisterModule registers a discovery module
func (e *Engine) RegisterModule(module DiscoveryModule) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	start := time.Now()
	moduleName := module.Name()
	priority := module.Priority()

	e.modules[moduleName] = module

	// Use both loggers for backward compatibility and enhanced logging
	e.logger.Info("Registered discovery module", "module", moduleName)

	e.logger.WithFields(
		"module", moduleName,
		"priority", priority,
		"total_modules", len(e.modules),
		"registration_duration_ms", time.Since(start).Milliseconds(),
	).Infow("Discovery module registered",
		"module_type", fmt.Sprintf("%T", module),
		"capabilities", "discovery",
	)
}

// StartDiscovery starts a new discovery session
func (e *Engine) StartDiscovery(rawTarget string) (*DiscoverySession, error) {
	start := time.Now()

	e.logger.WithFields(
		"raw_target", rawTarget,
		"operation", "StartDiscovery",
	).Infow("Starting discovery session")

	// Parse target
	parseStart := time.Now()
	target := e.parser.ParseTarget(rawTarget)
	if target.Type == TargetTypeUnknown {
		err := fmt.Errorf("unable to parse target: %s", rawTarget)
		e.logger.LogError(context.Background(), err, "discovery.StartDiscovery.parse",
			"raw_target", rawTarget,
			"parse_duration_ms", time.Since(parseStart).Milliseconds(),
		)
		return nil, err
	}

	e.logger.LogDuration(context.Background(), "discovery.target_parse", parseStart,
		"raw_target", rawTarget,
		"parsed_type", string(target.Type),
		"parsed_value", target.Value,
		"confidence", target.Confidence,
	)

	// Create session
	sessionID := uuid.New().String()
	session := &DiscoverySession{
		ID:              sessionID,
		Target:          *target,
		Assets:          make(map[string]*Asset),
		Relationships:   make(map[string]*Relationship),
		Status:          StatusPending,
		StartedAt:       time.Now(),
		Progress:        0.0,
		TotalDiscovered: 0,
		HighValueAssets: 0,
		Config:          e.config,
	}

	e.mutex.Lock()
	e.sessions[session.ID] = session
	totalSessions := len(e.sessions)
	e.mutex.Unlock()

	// Log with both loggers for compatibility
	e.logger.Info("Started discovery session", "session_id", session.ID, "target", target.Value, "type", target.Type)

	e.logger.WithFields(
		"session_id", sessionID,
		"target_value", target.Value,
		"target_type", string(target.Type),
		"target_confidence", target.Confidence,
		"total_sessions", totalSessions,
		"session_init_duration_ms", time.Since(start).Milliseconds(),
	).Infow("Discovery session created",
		"max_depth", e.config.MaxDepth,
		"max_assets", e.config.MaxAssets,
		"timeout", e.config.Timeout,
		"available_modules", len(e.modules),
	)

	// Start discovery in background
	go e.runDiscovery(session)

	return session, nil
}

// GetSession retrieves a discovery session
func (e *Engine) GetSession(sessionID string) (*DiscoverySession, error) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	session, exists := e.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	return session, nil
}

// ListSessions lists all discovery sessions
func (e *Engine) ListSessions() []*DiscoverySession {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	sessions := make([]*DiscoverySession, 0, len(e.sessions))
	for _, session := range e.sessions {
		sessions = append(sessions, session)
	}

	return sessions
}

// runDiscovery runs the discovery process
func (e *Engine) runDiscovery(session *DiscoverySession) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
	defer cancel()

	// Add structured logger context
	ctx, span := e.logger.StartOperation(ctx, "discovery.runDiscovery",
		"session_id", session.ID,
		"target_value", session.Target.Value,
		"target_type", string(session.Target.Type),
	)

	var finalErr error
	defer func() {
		e.logger.FinishOperation(ctx, span, "discovery.runDiscovery", start, finalErr)
	}()

	session.Status = StatusRunning
	defer func() {
		if session.Status == StatusRunning {
			session.Status = StatusCompleted
		}
		now := time.Now()
		session.CompletedAt = &now
		session.Progress = 100.0

		// Log session completion
		totalDuration := time.Since(start)
		e.logger.WithContext(ctx).Infow("Discovery session completed",
			"session_id", session.ID,
			"total_discovered", session.TotalDiscovered,
			"high_value_assets", session.HighValueAssets,
			"total_duration_ms", totalDuration.Milliseconds(),
			"final_status", string(session.Status),
			"error_count", len(session.Errors),
		)
	}()

	// Log with both loggers for compatibility
	e.logger.Info("Running discovery", "session_id", session.ID)

	e.logger.WithContext(ctx).Infow("Starting discovery execution",
		"session_id", session.ID,
		"target_value", session.Target.Value,
		"target_type", string(session.Target.Type),
		"timeout", e.config.Timeout,
		"max_depth", e.config.MaxDepth,
		"max_assets", e.config.MaxAssets,
	)

	// Get applicable modules
	moduleStart := time.Now()
	modules := e.getApplicableModules(&session.Target)
	totalModules := len(modules)

	e.logger.LogDuration(ctx, "discovery.get_applicable_modules", moduleStart,
		"session_id", session.ID,
		"total_modules", totalModules,
		"target_type", string(session.Target.Type),
	)

	if totalModules == 0 {
		finalErr = fmt.Errorf("no applicable modules found for target type: %s", session.Target.Type)
		e.logger.Warn("No applicable modules found", "target_type", session.Target.Type)
		e.logger.LogError(ctx, finalErr, "discovery.no_modules",
			"session_id", session.ID,
			"target_type", string(session.Target.Type),
			"available_modules", len(e.modules),
		)
		session.Status = StatusFailed
		return
	}

	// Log module execution plan
	moduleNames := make([]string, len(modules))
	for i, mod := range modules {
		moduleNames[i] = mod.Name()
	}

	e.logger.WithContext(ctx).Infow("Starting parallel module execution",
		"session_id", session.ID,
		"module_count", totalModules,
		"modules", moduleNames,
		"execution_timeout", e.config.Timeout,
	)

	// Run modules in parallel
	var wg sync.WaitGroup
	resultsChan := make(chan *DiscoveryResult, totalModules)

	for i, module := range modules {
		wg.Add(1)
		go func(mod DiscoveryModule, index int) {
			defer wg.Done()

			modStart := time.Now()
			modName := mod.Name()

			// Log with both loggers
			e.logger.Debug("Running module", "module", modName, "session_id", session.ID)

			modCtx, modSpan := e.logger.StartSpanWithAttributes(ctx,
				fmt.Sprintf("discovery.module.%s", modName),
				[]attribute.KeyValue{
					attribute.String("module_name", modName),
					attribute.String("session_id", session.ID),
					attribute.Int("module_index", index),
					attribute.Int("total_modules", totalModules),
				},
			)
			defer modSpan.End()

			e.logger.WithContext(modCtx).Debugw("Starting module execution",
				"module", modName,
				"session_id", session.ID,
				"module_index", index,
				"module_priority", mod.Priority(),
			)

			result, err := mod.Discover(modCtx, &session.Target, session)
			modDuration := time.Since(modStart)

			if err != nil {
				e.logger.Error("Module discovery failed", "module", modName, "error", err)
				e.logger.LogError(modCtx, err, "discovery.module.failed",
					"module", modName,
					"session_id", session.ID,
					"duration_ms", modDuration.Milliseconds(),
				)
				session.Errors = append(session.Errors, fmt.Sprintf("%s: %v", modName, err))
				return
			}

			if result != nil {
				result.Source = modName
				resultsChan <- result

				e.logger.WithContext(modCtx).Debugw("Module execution completed",
					"module", modName,
					"session_id", session.ID,
					"assets_discovered", len(result.Assets),
					"duration_ms", modDuration.Milliseconds(),
				)
			} else {
				e.logger.WithContext(modCtx).Debugw("Module completed with no results",
					"module", modName,
					"session_id", session.ID,
					"duration_ms", modDuration.Milliseconds(),
				)
			}

			// Update progress
			progress := float64(index+1) / float64(totalModules) * 100.0
			session.Progress = progress

			e.logger.LogScanProgress(modCtx, session.ID, progress, "running", map[string]interface{}{
				"completed_modules": index + 1,
				"total_modules":     totalModules,
				"current_module":    modName,
			})

		}(module, i)
	}

	// Wait for all modules to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Process results
	for result := range resultsChan {
		e.processDiscoveryResult(session, result)
	}

	// Post-process assets
	e.postProcessAssets(session)

	e.logger.Info("Discovery completed",
		"session_id", session.ID,
		"total_assets", session.TotalDiscovered,
		"high_value_assets", session.HighValueAssets)
}

// getApplicableModules returns modules that can handle the target
func (e *Engine) getApplicableModules(target *Target) []DiscoveryModule {
	var modules []DiscoveryModule

	for _, module := range e.modules {
		if module.CanHandle(target) {
			modules = append(modules, module)
		}
	}

	// Sort by priority
	for i := 0; i < len(modules)-1; i++ {
		for j := i + 1; j < len(modules); j++ {
			if modules[i].Priority() < modules[j].Priority() {
				modules[i], modules[j] = modules[j], modules[i]
			}
		}
	}

	return modules
}

// processDiscoveryResult processes results from a discovery module
func (e *Engine) processDiscoveryResult(session *DiscoverySession, result *DiscoveryResult) {
	if result == nil {
		return
	}

	// Add assets
	for _, asset := range result.Assets {
		if len(session.Assets) >= e.config.MaxAssets {
			e.logger.Warn("Maximum assets reached", "max", e.config.MaxAssets)
			break
		}

		// Check for duplicates
		existingAsset := e.findExistingAsset(session, asset)
		if existingAsset != nil {
			// Update existing asset
			existingAsset.LastSeen = time.Now()
			if asset.Confidence > existingAsset.Confidence {
				existingAsset.Confidence = asset.Confidence
			}
			// Merge metadata
			for k, v := range asset.Metadata {
				existingAsset.Metadata[k] = v
			}
			// Merge technologies
			existingAsset.Technology = mergeTechnologies(existingAsset.Technology, asset.Technology)
			continue
		}

		// Add new asset
		asset.ID = uuid.New().String()
		asset.Priority = int(CalculateAssetPriority(asset))
		session.Assets[asset.ID] = asset
		session.TotalDiscovered++

		if IsHighValueAsset(asset) {
			session.HighValueAssets++
			e.logger.Info("High-value asset discovered",
				"asset", asset.Value,
				"type", asset.Type,
				"session_id", session.ID)
		}
	}

	// Add relationships
	for _, relationship := range result.Relationships {
		relationship.ID = uuid.New().String()
		session.Relationships[relationship.ID] = relationship
	}
}

// findExistingAsset finds if an asset already exists
func (e *Engine) findExistingAsset(session *DiscoverySession, newAsset *Asset) *Asset {
	for _, existingAsset := range session.Assets {
		if existingAsset.Type == newAsset.Type &&
			existingAsset.Value == newAsset.Value {
			return existingAsset
		}
	}
	return nil
}

// mergeTechnologies merges two technology arrays
func mergeTechnologies(existing, new []string) []string {
	techMap := make(map[string]bool)

	// Add existing technologies
	for _, tech := range existing {
		techMap[tech] = true
	}

	// Add new technologies
	for _, tech := range new {
		techMap[tech] = true
	}

	// Convert back to slice
	result := make([]string, 0, len(techMap))
	for tech := range techMap {
		result = append(result, tech)
	}

	return result
}

// postProcessAssets performs post-processing on discovered assets
func (e *Engine) postProcessAssets(session *DiscoverySession) {
	// Create relationships between assets
	e.createAssetRelationships(session)

	// Tag assets
	e.tagAssets(session)

	// Calculate final priorities
	e.calculateFinalPriorities(session)
}

// createAssetRelationships creates relationships between discovered assets
func (e *Engine) createAssetRelationships(session *DiscoverySession) {
	assets := make([]*Asset, 0, len(session.Assets))
	for _, asset := range session.Assets {
		assets = append(assets, asset)
	}

	// Create domain-subdomain relationships
	for i, asset1 := range assets {
		for j, asset2 := range assets {
			if i == j {
				continue
			}

			// Check if asset2 is a subdomain of asset1
			if asset1.Type == AssetTypeDomain && asset2.Type == AssetTypeSubdomain {
				if isSubdomainOf(asset2.Value, asset1.Value) {
					relationship := &Relationship{
						ID:        uuid.New().String(),
						Source:    asset1.ID,
						Target:    asset2.ID,
						Type:      RelationTypeSubdomain,
						Weight:    0.8,
						Metadata:  make(map[string]string),
						CreatedAt: time.Now(),
					}
					session.Relationships[relationship.ID] = relationship
				}
			}
		}
	}
}

// isSubdomainOf checks if subdomain is a subdomain of domain
func isSubdomainOf(subdomain, domain string) bool {
	return subdomain != domain && (subdomain == domain ||
		(len(subdomain) > len(domain) &&
			subdomain[len(subdomain)-len(domain)-1:] == "."+domain))
}

// tagAssets adds tags to assets based on their characteristics
func (e *Engine) tagAssets(session *DiscoverySession) {
	for _, asset := range session.Assets {
		tags := []string{}

		// Add technology-based tags
		for _, tech := range asset.Technology {
			tags = append(tags, "tech:"+tech)
		}

		// Add type-based tags
		tags = append(tags, "type:"+string(asset.Type))

		// Add priority-based tags
		switch AssetPriority(asset.Priority) {
		case PriorityCritical:
			tags = append(tags, "priority:critical")
		case PriorityHigh:
			tags = append(tags, "priority:high")
		case PriorityMedium:
			tags = append(tags, "priority:medium")
		case PriorityLow:
			tags = append(tags, "priority:low")
		}

		// Add high-value tag
		if IsHighValueAsset(asset) {
			tags = append(tags, "high-value")
		}

		asset.Tags = tags
	}
}

// calculateFinalPriorities calculates final priorities based on relationships
func (e *Engine) calculateFinalPriorities(session *DiscoverySession) {
	// Boost priority of assets with many relationships
	relationshipCounts := make(map[string]int)

	for _, relationship := range session.Relationships {
		relationshipCounts[relationship.Source]++
		relationshipCounts[relationship.Target]++
	}

	for assetID, asset := range session.Assets {
		relationshipCount := relationshipCounts[assetID]

		// Boost priority based on relationship count
		if relationshipCount >= 5 {
			if asset.Priority < int(PriorityCritical) {
				asset.Priority = int(PriorityCritical)
			}
		} else if relationshipCount >= 3 {
			if asset.Priority < int(PriorityHigh) {
				asset.Priority = int(PriorityHigh)
			}
		}
	}
}

// GetHighValueAssets returns high-value assets from a session
func (e *Engine) GetHighValueAssets(sessionID string) ([]*Asset, error) {
	session, err := e.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	var highValueAssets []*Asset
	for _, asset := range session.Assets {
		if IsHighValueAsset(asset) {
			highValueAssets = append(highValueAssets, asset)
		}
	}

	return highValueAssets, nil
}

// GetAssetsByType returns assets of a specific type from a session
func (e *Engine) GetAssetsByType(sessionID string, assetType AssetType) ([]*Asset, error) {
	session, err := e.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	var assets []*Asset
	for _, asset := range session.Assets {
		if asset.Type == assetType {
			assets = append(assets, asset)
		}
	}

	return assets, nil
}

// StopDiscovery stops a running discovery session
func (e *Engine) StopDiscovery(sessionID string) error {
	session, err := e.GetSession(sessionID)
	if err != nil {
		return err
	}

	if session.Status == StatusRunning {
		session.Status = StatusPaused
		e.logger.Info("Discovery session stopped", "session_id", sessionID)
	}

	return nil
}
