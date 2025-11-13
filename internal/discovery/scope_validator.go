package discovery

import (
	"strings"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/scope"
)

// ScopeValidator validates discovered assets against scope
type ScopeValidator struct {
	scopeManager scope.ScopeManager
	logger       *logger.Logger
	enabled      bool
}

// NewScopeValidator creates a new scope validator
func NewScopeValidator(scopeManager scope.ScopeManager, logger *logger.Logger, enabled bool) *ScopeValidator {
	return &ScopeValidator{
		scopeManager: scopeManager,
		logger:       logger,
		enabled:      enabled,
	}
}

// ValidateAsset validates a single asset
func (sv *ScopeValidator) ValidateAsset(asset *Asset) (*scope.ValidationResult, error) {
	if !sv.enabled {
		// If scope validation is disabled, everything is in scope
		return &scope.ValidationResult{
			Asset:  asset.Value,
			Status: scope.ScopeStatusInScope,
			Reason: "Scope validation disabled",
		}, nil
	}

	return sv.scopeManager.ValidateAsset(asset.Value)
}

// FilterAssets filters assets based on scope
func (sv *ScopeValidator) FilterAssets(assets []*Asset) ([]*Asset, error) {
	if !sv.enabled {
		return assets, nil
	}

	// Extract asset values for batch validation
	values := make([]string, len(assets))
	for i, asset := range assets {
		values[i] = asset.Value
	}

	// Batch validate
	results, err := sv.scopeManager.ValidateBatch(values)
	if err != nil {
		return nil, err
	}

	// Filter in-scope assets
	var inScope []*Asset
	for i, result := range results {
		if result.Status == scope.ScopeStatusInScope {
			// Add scope metadata to asset
			if assets[i].Metadata == nil {
				assets[i].Metadata = make(map[string]string)
			}
			assets[i].Metadata["scope_status"] = string(result.Status)
			if result.Program != nil {
				assets[i].Metadata["scope_program"] = result.Program.Name
			}
			if len(result.Restrictions) > 0 {
				assets[i].Metadata["scope_restrictions"] = strings.Join(result.Restrictions, ",")
			}

			inScope = append(inScope, assets[i])
		} else {
			sv.logger.Debug("Asset filtered out of scope",
				"asset", assets[i].Value,
				"reason", result.Reason)
		}
	}

	sv.logger.Info("Scope filtering completed",
		"total", len(assets),
		"in_scope", len(inScope),
		"filtered", len(assets)-len(inScope))

	return inScope, nil
}
