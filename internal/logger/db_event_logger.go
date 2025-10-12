// internal/logger/db_event_logger.go
package logger

import (
	"context"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
)

// DBEventLogger wraps a logger and automatically saves important events to the database
type DBEventLogger struct {
	*Logger
	store  core.ResultStore
	scanID string
}

// NewDBEventLogger creates a logger that saves events to both stdout and database
func NewDBEventLogger(logger *Logger, store core.ResultStore, scanID string) *DBEventLogger {
	return &DBEventLogger{
		Logger: logger,
		store:  store,
		scanID: scanID,
	}
}

// Infow logs and saves important info events to database
func (l *DBEventLogger) Infow(msg string, keysAndValues ...interface{}) {
	// Call parent logger
	l.Logger.Infow(msg, keysAndValues...)

	// Save to database if this is a significant event
	if l.shouldSaveEvent(msg) {
		metadata := l.extractMetadata(keysAndValues)
		component := l.extractComponent(keysAndValues)

		// Save event asynchronously so it doesn't slow down the scan
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := l.store.SaveScanEvent(ctx, l.scanID, "info", component, msg, metadata); err != nil {
				// Log error but don't fail the scan
				l.Logger.Errorw("Failed to save scan event to database",
					"error", err,
					"scan_id", l.scanID,
					"component", component,
					"message", msg,
				)
			}
		}()
	}
}

// Warnw logs and saves warning events to database
func (l *DBEventLogger) Warnw(msg string, keysAndValues ...interface{}) {
	// Call parent logger
	l.Logger.Warnw(msg, keysAndValues...)

	// Always save warnings to database
	metadata := l.extractMetadata(keysAndValues)
	component := l.extractComponent(keysAndValues)

	go func() {
		ctx := context.Background()
		l.store.SaveScanEvent(ctx, l.scanID, "warning", component, msg, metadata)
	}()
}

// Errorw logs and saves error events to database
func (l *DBEventLogger) Errorw(msg string, keysAndValues ...interface{}) {
	// Call parent logger
	l.Logger.Errorw(msg, keysAndValues...)

	// Always save errors to database
	metadata := l.extractMetadata(keysAndValues)
	component := l.extractComponent(keysAndValues)

	go func() {
		ctx := context.Background()
		l.store.SaveScanEvent(ctx, l.scanID, "error", component, msg, metadata)
	}()
}

// shouldSaveEvent determines if an event is significant enough to save to database
func (l *DBEventLogger) shouldSaveEvent(msg string) bool {
	// Save ALL events - complete scan history for UI
	return true
}

// extractMetadata converts key-value pairs to map
func (l *DBEventLogger) extractMetadata(keysAndValues []interface{}) map[string]interface{} {
	metadata := make(map[string]interface{})

	for i := 0; i < len(keysAndValues)-1; i += 2 {
		if key, ok := keysAndValues[i].(string); ok {
			// Skip "component" as it's extracted separately
			if key != "component" {
				metadata[key] = keysAndValues[i+1]
			}
		}
	}

	return metadata
}

// extractComponent gets the component field from key-value pairs
func (l *DBEventLogger) extractComponent(keysAndValues []interface{}) string {
	for i := 0; i < len(keysAndValues)-1; i += 2 {
		if key, ok := keysAndValues[i].(string); ok && key == "component" {
			if component, ok := keysAndValues[i+1].(string); ok {
				return component
			}
		}
	}
	return "orchestrator" // default
}

// contains checks if string contains substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
