package logger

import (
	"context"
	"testing"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  config.LoggerConfig
		wantErr bool
	}{
		{
			name: "valid json config",
			config: config.LoggerConfig{
				Level:  "debug",
				Format: "json",
			},
			wantErr: false,
		},
		{
			name: "valid console config",
			config: config.LoggerConfig{
				Level:  "info",
				Format: "console",
			},
			wantErr: false,
		},
		{
			name: "invalid level",
			config: config.LoggerConfig{
				Level:  "invalid",
				Format: "json",
			},
			wantErr: true,
		},
		{
			name:    "empty config uses defaults",
			config:  config.LoggerConfig{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := New(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, logger)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, logger)
			}
		})
	}
}

func TestLoggerMethods(t *testing.T) {
	logger, err := New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	// Test basic logging methods
	logger.Info("test info message")
	logger.Infow("test structured info", "key", "value", "number", 42)

	logger.Debug("test debug message")
	logger.Debugw("test structured debug", "key", "value")

	logger.Warn("test warn message")
	logger.Warnw("test structured warn", "key", "value")

	logger.Error("test error message")
	logger.Errorw("test structured error", "key", "value")
}

func TestWithContext(t *testing.T) {
	logger, err := New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	// Create context with trace
	ctx := context.Background()

	// Test logging with context
	contextLogger := logger.WithContext(ctx)
	contextLogger.Info("test with context")
	contextLogger.Debug("debug with context")
	contextLogger.Warn("warn with context")
	contextLogger.Error("error with context")
}

func TestStartOperation(t *testing.T) {
	logger, err := New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	ctx := context.Background()

	// Test starting an operation
	newCtx, span := logger.StartOperation(ctx, "test.operation",
		"key1", "value1",
		"key2", 123,
	)

	assert.NotNil(t, newCtx)
	assert.NotNil(t, span)

	// Should be able to end the span
	span.End()
}

func TestWithFields(t *testing.T) {
	logger, err := New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	// Test creating logger with additional fields
	fieldLogger := logger.WithFields("component", "test", "version", "1.0")
	assert.NotNil(t, fieldLogger)

	// Field logger should log with additional fields
	fieldLogger.Info("test from field logger")
}

func TestWithComponent(t *testing.T) {
	logger, err := New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	// Test creating component logger
	componentLogger := logger.WithComponent("test-component")
	assert.NotNil(t, componentLogger)
	componentLogger.Info("test from component logger")
}

func TestWithTarget(t *testing.T) {
	logger, err := New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	// Test creating target logger
	targetLogger := logger.WithTarget("https://example.com")
	assert.NotNil(t, targetLogger)
	targetLogger.Info("test from target logger")
}

func TestWithScanID(t *testing.T) {
	logger, err := New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	// Test creating scan ID logger
	scanLogger := logger.WithScanID("scan-12345")
	assert.NotNil(t, scanLogger)
	scanLogger.Info("test from scan logger")
}

func TestWithTool(t *testing.T) {
	logger, err := New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	// Test creating tool logger
	toolLogger := logger.WithTool("nmap")
	assert.NotNil(t, toolLogger)
	toolLogger.Info("test from tool logger")
}

func TestWithModule(t *testing.T) {
	logger, err := New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	// Test creating module logger
	moduleLogger := logger.WithModule("scanner")
	assert.NotNil(t, moduleLogger)
	moduleLogger.Info("test from module logger")
}

func TestWith(t *testing.T) {
	logger, err := New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	// Test creating child logger with additional fields
	childLogger := logger.With("component", "test", "version", "1.0")
	assert.NotNil(t, childLogger)

	// Child logger should log with additional fields
	childLogger.Info("test from child logger")
}

func TestSync(t *testing.T) {
	logger, err := New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	// Test sync doesn't panic (may return error on stderr sync in some environments)
	err = logger.Sync()
	// Sync can return error in test environments, so we just ensure it doesn't panic
	t.Logf("Sync result: %v", err)
}

func TestLoggerConcurrency(t *testing.T) {
	logger, err := New(config.LoggerConfig{Level: "debug", Format: "json"})
	require.NoError(t, err)

	// Test concurrent logging
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			logger.Infow("concurrent log", "goroutine", id)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
