// internal/orchestrator/factory_test.go
//
// Factory Pattern Tests
//
// Validates the EngineFactory builder pattern correctly initializes
// all engine dependencies with proper configuration propagation.

package orchestrator

import (
	"testing"
	"time"
)

// TestFactoryBuildComplete validates factory creates fully initialized engine
func TestFactoryBuildComplete(t *testing.T) {
	store := NewMockResultStore()
	telemetry := NewMockTelemetry()
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := CreateTestConfig()

	// Create factory
	factory := NewEngineFactory(store, telemetry, logger, config)
	if factory == nil {
		t.Fatal("Factory is nil")
	}

	// Build engine
	engine, err := factory.Build()
	if err != nil {
		t.Fatalf("Factory Build() failed: %v", err)
	}

	// Verify all core components initialized
	if engine.store == nil {
		t.Error("Store is nil")
	}
	if engine.telemetry == nil {
		t.Error("Telemetry is nil")
	}
	if engine.logger == nil {
		t.Error("Logger is nil")
	}
	if engine.rateLimiter == nil {
		t.Error("Rate limiter is nil")
	}
	if engine.scannerManager == nil {
		t.Error("Scanner manager is nil")
	}
	if engine.outputFormatter == nil {
		t.Error("Output formatter is nil")
	}
	if engine.persistenceManager == nil {
		t.Error("Persistence manager is nil")
	}

	t.Log("SUCCESS: Factory builds complete engine with all components")
}

// TestFactoryConfigPropagation validates config settings propagate correctly
func TestFactoryConfigPropagation(t *testing.T) {
	store := NewMockResultStore()
	telemetry := NewMockTelemetry()
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create config with specific values
	config := BugBountyConfig{
		MaxAssets:          100,
		MaxDepth:           3,
		DiscoveryTimeout:   1 * time.Minute,
		ScanTimeout:        2 * time.Minute,
		TotalTimeout:       10 * time.Minute,
		RateLimitPerSecond: 5.0,
		RateLimitBurst:     10,
		ShowProgress:       true,
	}

	factory := NewEngineFactory(store, telemetry, logger, config)
	engine, err := factory.Build()
	if err != nil {
		t.Fatalf("Factory Build() failed: %v", err)
	}

	// Verify config was stored
	if engine.config.MaxAssets != 100 {
		t.Errorf("MaxAssets not propagated: got %d, want 100", engine.config.MaxAssets)
	}
	if engine.config.MaxDepth != 3 {
		t.Errorf("MaxDepth not propagated: got %d, want 3", engine.config.MaxDepth)
	}
	if engine.config.RateLimitPerSecond != 5.0 {
		t.Errorf("RateLimitPerSecond not propagated: got %f, want 5.0", engine.config.RateLimitPerSecond)
	}

	t.Log("SUCCESS: Configuration propagates correctly to engine")
}

// TestFactoryScannerRegistration validates scanners are registered based on config
func TestFactoryScannerRegistration(t *testing.T) {
	store := NewMockResultStore()
	telemetry := NewMockTelemetry()
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Enable specific scanners via config
	config := CreateTestConfig()
	config.EnableAuthTesting = true
	config.EnableSCIMTesting = true
	config.EnableAPITesting = true

	factory := NewEngineFactory(store, telemetry, logger, config)
	engine, err := factory.Build()
	if err != nil {
		t.Fatalf("Factory Build() failed: %v", err)
	}

	// Check scanner manager has scanners registered
	scanners := engine.scannerManager.List()
	if len(scanners) == 0 {
		t.Error("No scanners registered in manager")
	}

	// Verify specific scanners are present
	_, hasAuth := engine.scannerManager.Get("authentication")
	_, hasSCIM := engine.scannerManager.Get("scim")
	_, hasAPI := engine.scannerManager.Get("api")

	if !hasAuth {
		t.Error("Authentication scanner not registered despite EnableAuthTesting=true")
	}
	if !hasSCIM {
		t.Error("SCIM scanner not registered despite EnableSCIMTesting=true")
	}
	if !hasAPI {
		t.Error("API scanner not registered despite EnableAPITesting=true")
	}

	t.Logf("SUCCESS: Factory registered %d scanners based on config", len(scanners))
}

// TestFactoryRateLimiter validates rate limiter initialization
func TestFactoryRateLimiter(t *testing.T) {
	store := NewMockResultStore()
	telemetry := NewMockTelemetry()
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := CreateTestConfig()
	config.RateLimitPerSecond = 10.0
	config.RateLimitBurst = 20

	factory := NewEngineFactory(store, telemetry, logger, config)
	engine, err := factory.Build()
	if err != nil {
		t.Fatalf("Factory Build() failed: %v", err)
	}

	if engine.rateLimiter == nil {
		t.Fatal("Rate limiter is nil")
	}

	// Test rate limiter is accessible via getter
	limiter := engine.GetRateLimiter()
	if limiter == nil {
		t.Error("GetRateLimiter() returned nil")
	}

	t.Log("SUCCESS: Rate limiter initialized and accessible")
}

// TestFactoryWithMinimalConfig validates engine builds with bare minimum config
func TestFactoryWithMinimalConfig(t *testing.T) {
	store := NewMockResultStore()
	telemetry := NewMockTelemetry()
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Minimal config - all scanners disabled
	config := BugBountyConfig{
		MaxAssets:             10,
		MaxDepth:              1,
		DiscoveryTimeout:      10 * time.Second,
		ScanTimeout:           10 * time.Second,
		TotalTimeout:          1 * time.Minute,
		EnableDNS:             false,
		EnablePortScan:        false,
		EnableWebCrawl:        false,
		EnableAuthTesting:     false,
		EnableSCIMTesting:     false,
		EnableAPITesting:      false,
		EnableIDORTesting:     false,
		EnableGraphQLTesting:  false,
		EnableServiceFingerprint: false,
		EnableNucleiScan:      false,
		RateLimitPerSecond:    1.0,
		RateLimitBurst:        2,
		ShowProgress:          false,
	}

	factory := NewEngineFactory(store, telemetry, logger, config)
	engine, err := factory.Build()
	if err != nil {
		t.Fatalf("Factory Build() failed with minimal config: %v", err)
	}

	// Engine should still be valid even with all scanners disabled
	if engine == nil {
		t.Fatal("Engine is nil")
	}
	if engine.scannerManager == nil {
		t.Fatal("Scanner manager is nil")
	}

	t.Log("SUCCESS: Factory builds valid engine with minimal config")
}

// TestFactoryHelperMethods validates individual builder methods
func TestFactoryHelperMethods(t *testing.T) {
	store := NewMockResultStore()
	telemetry := NewMockTelemetry()
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := CreateTestConfig()
	factory := NewEngineFactory(store, telemetry, logger, config)

	t.Run("buildRateLimiter", func(t *testing.T) {
		limiter := factory.buildRateLimiter()
		if limiter == nil {
			t.Error("buildRateLimiter returned nil")
		}
	})

	t.Run("buildDiscoveryEngine", func(t *testing.T) {
		engine := factory.buildDiscoveryEngine()
		if engine == nil {
			t.Error("buildDiscoveryEngine returned nil")
		}
	})

	t.Run("buildOutputFormatter", func(t *testing.T) {
		formatter := factory.buildOutputFormatter()
		if formatter == nil {
			t.Error("buildOutputFormatter returned nil")
		}
		if formatter.logger == nil {
			t.Error("OutputFormatter logger is nil")
		}
	})

	t.Run("buildPersistenceManager", func(t *testing.T) {
		enricher := factory.buildEnricher()
		checkpointMgr := factory.buildCheckpointManager()
		persistenceMgr := factory.buildPersistenceManager(enricher, checkpointMgr)
		if persistenceMgr == nil {
			t.Error("buildPersistenceManager returned nil")
		}
		if persistenceMgr.store == nil {
			t.Error("PersistenceManager store is nil")
		}
	})

	t.Log("SUCCESS: All factory helper methods create valid components")
}

// TestFactoryIdempotent validates multiple Build() calls create independent engines
func TestFactoryIdempotent(t *testing.T) {
	store := NewMockResultStore()
	telemetry := NewMockTelemetry()
	logger, err := CreateTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	config := CreateTestConfig()
	factory := NewEngineFactory(store, telemetry, logger, config)

	// Build twice
	engine1, err1 := factory.Build()
	engine2, err2 := factory.Build()

	if err1 != nil {
		t.Fatalf("First Build() failed: %v", err1)
	}
	if err2 != nil {
		t.Fatalf("Second Build() failed: %v", err2)
	}

	// Engines should be different instances
	if engine1 == engine2 {
		t.Error("Factory Build() returned same instance twice (not creating new engines)")
	}

	// But should have same configuration
	if engine1.config.MaxAssets != engine2.config.MaxAssets {
		t.Error("Engines have different config (factory state not consistent)")
	}

	t.Log("SUCCESS: Factory Build() creates independent engines each call")
}
