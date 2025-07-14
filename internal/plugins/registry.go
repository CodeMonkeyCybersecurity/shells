package plugins

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/scim"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/smuggling"
)

// RegisterDefaultPlugins registers all default scanners with the plugin manager
func RegisterDefaultPlugins(pm core.PluginManager, logger *logger.Logger) error {
	// Register SCIM scanner
	if err := pm.Register(scim.NewScanner()); err != nil {
		return fmt.Errorf("failed to register SCIM scanner: %w", err)
	}
	
	// Register HTTP Request Smuggling scanner
	if err := pm.Register(smuggling.NewScanner()); err != nil {
		return fmt.Errorf("failed to register smuggling scanner: %w", err)
	}
	
	return nil
}

// GetScannerByType returns a scanner for the given scan type
func GetScannerByType(pm core.PluginManager, scanType string) (core.Scanner, error) {
	switch scanType {
	case "scim":
		return pm.Get("scim")
	case "smuggling":
		return pm.Get("smuggling")
	default:
		return nil, fmt.Errorf("unknown scan type: %s", scanType)
	}
}

// ListAvailableScanners returns a list of all available scanners
func ListAvailableScanners(pm core.PluginManager) []string {
	return pm.List()
}