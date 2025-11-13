package plugins

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/core"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/plugins/api"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/plugins/browser"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/plugins/fuzzer"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/plugins/httpx"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/plugins/javascript"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/plugins/nmap"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/plugins/nuclei"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/plugins/oauth2"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/plugins/oob"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/plugins/ssl"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/scim"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/smuggling"
)

// RegisterDefaultPlugins registers all default scanners with the plugin manager
func RegisterDefaultPlugins(pm core.PluginManager, logger *logger.Logger) error {
	// Create a basic logger interface adapter for plugins that need it
	logAdapter := &loggerAdapter{logger: logger}

	// Register SCIM scanner
	if err := pm.Register(scim.NewScanner()); err != nil {
		return fmt.Errorf("failed to register SCIM scanner: %w", err)
	}

	// Register HTTP Request Smuggling scanner
	if err := pm.Register(smuggling.NewScanner()); err != nil {
		return fmt.Errorf("failed to register smuggling scanner: %w", err)
	}

	// Register Nmap scanner
	nmapCfg := config.NmapConfig{
		BinaryPath: "nmap",
		Profiles: map[string]string{
			"default": "-sS -sV -O",
			"quick":   "-sS -F",
			"full":    "-sS -sV -O -A",
		},
	}
	if err := pm.Register(nmap.NewScanner(nmapCfg, logAdapter)); err != nil {
		return fmt.Errorf("failed to register Nmap scanner: %w", err)
	}

	// Register SSL scanner
	sslCfg := config.SSLConfig{
		Timeout:         30 * time.Second,
		CheckRevocation: true,
	}
	if err := pm.Register(ssl.NewScanner(sslCfg, logAdapter)); err != nil {
		return fmt.Errorf("failed to register SSL scanner: %w", err)
	}

	// Register OAuth2 scanner
	if err := pm.Register(oauth2.NewScanner(logAdapter)); err != nil {
		return fmt.Errorf("failed to register OAuth2 scanner: %w", err)
	}

	// Register JavaScript analyzer
	if err := pm.Register(javascript.NewJSAnalyzer(logAdapter)); err != nil {
		return fmt.Errorf("failed to register JavaScript analyzer: %w", err)
	}

	// Register Browser analyzer
	browserCfg := browser.BrowserConfig{
		Headless:      true,
		DisableImages: true,
		DisableCSS:    true,
		Timeout:       30 * time.Second,
	}
	if err := pm.Register(browser.NewChromedpAnalyzer(browserCfg, logAdapter)); err != nil {
		return fmt.Errorf("failed to register browser analyzer: %w", err)
	}

	// Register GraphQL scanner
	if err := pm.Register(api.NewGraphQLScanner(logAdapter)); err != nil {
		return fmt.Errorf("failed to register GraphQL scanner: %w", err)
	}

	// Register HTTPx scanner
	httpxCfg := httpx.HTTPXConfig{
		Threads:    50,
		Timeout:    30 * time.Second,
		RateLimit:  150,
		BinaryPath: "httpx",
	}
	if err := pm.Register(httpx.NewScanner(httpxCfg, logAdapter)); err != nil {
		return fmt.Errorf("failed to register HTTPx scanner: %w", err)
	}

	// Register Nuclei scanner
	nucleiCfg := nuclei.NucleiConfig{
		BinaryPath:    "nuclei",
		TemplatesPath: "nuclei-templates",
		Concurrency:   25,
		RateLimit:     150,
		BulkSize:      25,
		Timeout:       30 * time.Second,
	}
	if err := pm.Register(nuclei.NewScanner(nucleiCfg, logAdapter)); err != nil {
		return fmt.Errorf("failed to register Nuclei scanner: %w", err)
	}

	// Register Interactsh scanner (stub implementation)
	oobCfg := oob.OOBConfig{
		PollDuration:         30 * time.Second,
		CollaboratorDuration: 5 * time.Minute,
	}
	scanner, err := oob.NewInteractshScanner(oobCfg, logAdapter)
	if err != nil {
		return fmt.Errorf("failed to create Interactsh scanner: %w", err)
	}
	if err := pm.Register(scanner); err != nil {
		return fmt.Errorf("failed to register Interactsh scanner: %w", err)
	}

	// Register OAuth2 Fuzzer
	oauth2FuzzerCfg := fuzzer.OAuth2Config{
		MaxPermutations:  100,
		ParallelRequests: 10,
		Timeout:          30,
	}
	if err := pm.Register(fuzzer.NewOAuth2Fuzzer(oauth2FuzzerCfg, logAdapter)); err != nil {
		return fmt.Errorf("failed to register OAuth2 fuzzer: %w", err)
	}

	return nil
}

// GetScannerByType returns a scanner for the given scan type
func GetScannerByType(pm core.PluginManager, scanType string) (core.Scanner, error) {
	scanner, err := pm.Get(scanType)
	if err != nil {
		return nil, fmt.Errorf("scanner not found: %s", scanType)
	}
	return scanner, nil
}

// ListAvailableScanners returns a list of all available scanners
func ListAvailableScanners(pm core.PluginManager) []string {
	return pm.List()
}

// loggerAdapter adapts the internal logger to the interface expected by plugins
type loggerAdapter struct {
	logger *logger.Logger
}

func (l *loggerAdapter) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Infow(msg, keysAndValues...)
}

func (l *loggerAdapter) Error(msg string, keysAndValues ...interface{}) {
	l.logger.Errorw(msg, keysAndValues...)
}

func (l *loggerAdapter) Debug(msg string, keysAndValues ...interface{}) {
	l.logger.Debugw(msg, keysAndValues...)
}

func (l *loggerAdapter) Warn(msg string, keysAndValues ...interface{}) {
	l.logger.Warnw(msg, keysAndValues...)
}
