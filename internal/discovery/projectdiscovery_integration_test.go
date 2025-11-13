// internal/discovery/projectdiscovery_integration_test.go
//
// Integration tests for ProjectDiscovery tool modules

package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProjectDiscoveryModulesRegistration verifies all PD modules register correctly
func TestProjectDiscoveryModulesRegistration(t *testing.T) {
	// Create test logger
	log, err := logger.New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	// Create discovery config
	discoveryConfig := DefaultDiscoveryConfig()
	discoveryConfig.MaxDepth = 3
	discoveryConfig.MaxAssets = 1000
	discoveryConfig.Timeout = 30 * time.Second

	// Create engine
	engine := NewEngine(discoveryConfig, log)

	// Verify ProjectDiscovery modules are registered
	expectedModules := []string{
		"subfinder", // Subdomain enumeration
		"httpx",     // HTTP probing
		"dnsx",      // DNS resolution
		"tlsx",      // Certificate transparency
		"katana",    // Web crawling
	}

	for _, moduleName := range expectedModules {
		t.Run("Module_"+moduleName, func(t *testing.T) {
			engine.mutex.RLock()
			module, exists := engine.modules[moduleName]
			engine.mutex.RUnlock()

			assert.True(t, exists, "Module %s should be registered", moduleName)
			if exists {
				assert.Equal(t, moduleName, module.Name())
				assert.Greater(t, module.Priority(), 0, "Module priority should be > 0")
			}
		})
	}
}

// TestSubfinderModule tests subfinder module basic functionality
func TestSubfinderModule(t *testing.T) {
	log, err := logger.New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	discoveryConfig := DefaultDiscoveryConfig()
	module := NewSubfinderModule(discoveryConfig, log)

	// Test module properties
	assert.Equal(t, "subfinder", module.Name())
	assert.Equal(t, 90, module.Priority())

	// Test CanHandle
	domainTarget := &Target{Type: TargetTypeDomain, Value: "example.com"}
	assert.True(t, module.CanHandle(domainTarget))

	ipTarget := &Target{Type: TargetTypeIP, Value: "192.168.1.1"}
	assert.False(t, module.CanHandle(ipTarget))

	// Test Discover (mock implementation)
	ctx := context.Background()
	session := &DiscoverySession{
		ID:     "test-session",
		Target: *domainTarget,
		Assets: make(map[string]*Asset),
	}

	result, err := module.Discover(ctx, domainTarget, session)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "subfinder", result.Source)
	assert.Greater(t, len(result.Assets), 0, "Should discover mock subdomains")
}

// TestHttpxModule tests httpx module basic functionality
func TestHttpxModule(t *testing.T) {
	log, err := logger.New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	discoveryConfig := DefaultDiscoveryConfig()
	module := NewHttpxModule(discoveryConfig, log)

	assert.Equal(t, "httpx", module.Name())
	assert.Equal(t, 70, module.Priority())

	// Test CanHandle
	urlTarget := &Target{Type: TargetTypeURL, Value: "https://example.com"}
	assert.True(t, module.CanHandle(urlTarget))

	emailTarget := &Target{Type: TargetTypeEmail, Value: "test@example.com"}
	assert.False(t, module.CanHandle(emailTarget))
}

// TestDnsxModule tests dnsx module basic functionality
func TestDnsxModule(t *testing.T) {
	log, err := logger.New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	discoveryConfig := DefaultDiscoveryConfig()
	module := NewDnsxModule(discoveryConfig, log)

	assert.Equal(t, "dnsx", module.Name())
	assert.Equal(t, 85, module.Priority())

	domainTarget := &Target{Type: TargetTypeDomain, Value: "example.com"}
	assert.True(t, module.CanHandle(domainTarget))
}

// TestTlsxModule tests tlsx module basic functionality
func TestTlsxModule(t *testing.T) {
	log, err := logger.New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	discoveryConfig := DefaultDiscoveryConfig()
	module := NewTlsxModule(discoveryConfig, log)

	assert.Equal(t, "tlsx", module.Name())
	assert.Equal(t, 80, module.Priority())

	domainTarget := &Target{Type: TargetTypeDomain, Value: "example.com"}
	assert.True(t, module.CanHandle(domainTarget))
}

// TestKatanaModule tests katana module basic functionality
func TestKatanaModule(t *testing.T) {
	log, err := logger.New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	discoveryConfig := DefaultDiscoveryConfig()
	module := NewKatanaModule(discoveryConfig, log)

	assert.Equal(t, "katana", module.Name())
	assert.Equal(t, 60, module.Priority())

	urlTarget := &Target{Type: TargetTypeURL, Value: "https://example.com"}
	assert.True(t, module.CanHandle(urlTarget))
}

// TestModulePriorityOrdering verifies modules execute in correct priority order
func TestModulePriorityOrdering(t *testing.T) {
	log, err := logger.New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	discoveryConfig := DefaultDiscoveryConfig()

	// Create all modules
	subfinder := NewSubfinderModule(discoveryConfig, log)
	httpx := NewHttpxModule(discoveryConfig, log)
	dnsx := NewDnsxModule(discoveryConfig, log)
	tlsx := NewTlsxModule(discoveryConfig, log)
	katana := NewKatanaModule(discoveryConfig, log)

	// Verify priority ordering: subfinder (90) > dnsx (85) > tlsx (80) > httpx (70) > katana (60)
	assert.Greater(t, subfinder.Priority(), dnsx.Priority(), "subfinder should have higher priority than dnsx")
	assert.Greater(t, dnsx.Priority(), tlsx.Priority(), "dnsx should have higher priority than tlsx")
	assert.Greater(t, tlsx.Priority(), httpx.Priority(), "tlsx should have higher priority than httpx")
	assert.Greater(t, httpx.Priority(), katana.Priority(), "httpx should have higher priority than katana")
}
