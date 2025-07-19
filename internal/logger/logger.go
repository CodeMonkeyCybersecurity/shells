package logger

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"go.opentelemetry.io/contrib/bridges/otelzap"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	*zap.SugaredLogger
	otelCore   *otelzap.Core
	tracer     trace.Tracer
	baseLogger *zap.Logger
}

// LogLevel represents the severity of log entries
type LogLevel int8

const (
	DebugLevel LogLevel = iota - 1
	InfoLevel
	WarnLevel
	ErrorLevel
	DPanicLevel
	PanicLevel
	FatalLevel
)

func New(cfg config.LoggerConfig) (*Logger, error) {
	var zapConfig zap.Config

	if cfg.Format == "console" {
		zapConfig = zap.NewDevelopmentConfig()
		zapConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		zapConfig.EncoderConfig.TimeKey = "timestamp"
		zapConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	} else {
		zapConfig = zap.NewProductionConfig()
		zapConfig.EncoderConfig.TimeKey = "timestamp"
		zapConfig.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	}

	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}
	zapConfig.Level = zap.NewAtomicLevelAt(level)

	if len(cfg.OutputPaths) > 0 {
		zapConfig.OutputPaths = cfg.OutputPaths
	}

	// Add standard fields for security scanning context
	zapConfig.InitialFields = map[string]interface{}{
		"service":     "shells",
		"version":     "1.0.0", // TODO: Get from build info
		"component":   "logger",
		"environment": "production", // TODO: Get from config
	}

	baseLogger, err := zapConfig.Build(
		zap.AddCallerSkip(1),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build logger: %w", err)
	}

	// Create otelzap core for automatic OpenTelemetry log correlation
	otelCore := otelzap.NewCore("shells",
		otelzap.WithAttributes(
			attribute.String("service", "shells"),
			attribute.String("version", "1.0.0"),
		),
	)

	// Create a tee core that writes to both standard zap and otelzap
	core := zapcore.NewTee(baseLogger.Core(), otelCore)
	enhancedLogger := zap.New(core, zap.AddCallerSkip(1), zap.AddStacktrace(zapcore.ErrorLevel))

	tracer := otel.Tracer("shells/logger")

	return &Logger{
		SugaredLogger: enhancedLogger.Sugar(),
		otelCore:      otelCore,
		tracer:        tracer,
		baseLogger:    enhancedLogger,
	}, nil
}

// Enhanced context-aware logging methods

func (l *Logger) WithContext(ctx context.Context) *Logger {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		spanCtx := span.SpanContext()
		return &Logger{
			SugaredLogger: l.With(
				"trace_id", spanCtx.TraceID().String(),
				"span_id", spanCtx.SpanID().String(),
			),
			otelCore:   l.otelCore,
			tracer:     l.tracer,
			baseLogger: l.baseLogger,
		}
	}
	return l
}

func (l *Logger) WithFields(fields ...interface{}) *Logger {
	return &Logger{
		SugaredLogger: l.With(fields...),
		otelCore:      l.otelCore,
		tracer:        l.tracer,
		baseLogger:    l.baseLogger,
	}
}

func (l *Logger) WithComponent(component string) *Logger {
	return l.WithFields("component", component)
}

func (l *Logger) WithTarget(target string) *Logger {
	return l.WithFields("target", target)
}

func (l *Logger) WithScanID(scanID string) *Logger {
	return l.WithFields("scan_id", scanID)
}

func (l *Logger) WithTool(tool string) *Logger {
	return l.WithFields("tool", tool)
}

func (l *Logger) WithModule(module string) *Logger {
	return l.WithFields("module", module)
}

func (l *Logger) WithTracer(tracer trace.Tracer) *Logger {
	newLogger := *l
	newLogger.tracer = tracer
	return &newLogger
}

// Span and tracing utilities

func (l *Logger) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if l.tracer == nil {
		l.tracer = otel.Tracer("shells/default")
	}
	return l.tracer.Start(ctx, name, opts...)
}

func (l *Logger) StartSpanWithAttributes(ctx context.Context, name string, attrs []attribute.KeyValue, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if len(attrs) > 0 {
		opts = append(opts, trace.WithAttributes(attrs...))
	}
	return l.StartSpan(ctx, name, opts...)
}

// Performance and timing logging

func (l *Logger) LogDuration(ctx context.Context, operation string, start time.Time, fields ...interface{}) {
	duration := time.Since(start)

	allFields := []interface{}{
		"operation", operation,
		"duration_ms", duration.Milliseconds(),
		"duration", duration.String(),
	}
	allFields = append(allFields, fields...)

	l.WithContext(ctx).Infow("Operation completed", allFields...)

	// Add span event if in span context
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.AddEvent("operation_completed", trace.WithAttributes(
			attribute.String("operation", operation),
			attribute.Int64("duration_ms", duration.Milliseconds()),
		))
	}
}

func (l *Logger) LogSlowOperation(ctx context.Context, operation string, duration time.Duration, threshold time.Duration, fields ...interface{}) {
	if duration > threshold {
		allFields := []interface{}{
			"operation", operation,
			"duration_ms", duration.Milliseconds(),
			"threshold_ms", threshold.Milliseconds(),
			"slow_operation", true,
		}
		allFields = append(allFields, fields...)

		l.WithContext(ctx).Warnw("Slow operation detected", allFields...)

		if span := trace.SpanFromContext(ctx); span.IsRecording() {
			span.AddEvent("slow_operation", trace.WithAttributes(
				attribute.String("operation", operation),
				attribute.Int64("duration_ms", duration.Milliseconds()),
				attribute.Int64("threshold_ms", threshold.Milliseconds()),
			))
		}
	}
}

// Error logging with enhanced context

func (l *Logger) LogError(ctx context.Context, err error, operation string, fields ...interface{}) {
	if err == nil {
		return
	}

	allFields := []interface{}{
		"error", err.Error(),
		"operation", operation,
		"error_type", fmt.Sprintf("%T", err),
	}
	allFields = append(allFields, fields...)

	l.WithContext(ctx).Errorw("Operation failed", allFields...)

	// Mark span as error and add error event
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.AddEvent("error_occurred", trace.WithAttributes(
			attribute.String("operation", operation),
			attribute.String("error", err.Error()),
			attribute.String("error_type", fmt.Sprintf("%T", err)),
		))
	}
}

func (l *Logger) LogPanic(ctx context.Context, recovered interface{}, operation string, fields ...interface{}) {
	allFields := []interface{}{
		"panic", recovered,
		"operation", operation,
		"panic_type", fmt.Sprintf("%T", recovered),
	}
	allFields = append(allFields, fields...)

	l.WithContext(ctx).DPanicw("Panic recovered", allFields...)

	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.AddEvent("panic_recovered", trace.WithAttributes(
			attribute.String("operation", operation),
			attribute.String("panic", fmt.Sprintf("%v", recovered)),
		))
		span.SetStatus(codes.Error, fmt.Sprintf("panic: %v", recovered))
	}
}

// Security-specific logging methods

func (l *Logger) LogSecurityEvent(ctx context.Context, eventType string, severity string, details map[string]interface{}) {
	allFields := []interface{}{
		"security_event", true,
		"event_type", eventType,
		"severity", severity,
		"timestamp", time.Now().UTC(),
	}

	for k, v := range details {
		allFields = append(allFields, k, v)
	}

	l.WithContext(ctx).Infow("Security event detected", allFields...)

	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		attrs := []attribute.KeyValue{
			attribute.String("event_type", eventType),
			attribute.String("severity", severity),
		}
		for k, v := range details {
			attrs = append(attrs, attribute.String(k, fmt.Sprintf("%v", v)))
		}
		span.AddEvent("security_event", trace.WithAttributes(attrs...))
	}
}

func (l *Logger) LogVulnerability(ctx context.Context, vuln map[string]interface{}) {
	allFields := []interface{}{
		"vulnerability_detected", true,
	}

	for k, v := range vuln {
		allFields = append(allFields, k, v)
	}

	level := "info"
	if severity, ok := vuln["severity"].(string); ok {
		switch severity {
		case "critical", "high":
			level = "warn"
		case "medium":
			level = "info"
		default:
			level = "debug"
		}
	}

	switch level {
	case "warn":
		l.WithContext(ctx).Warnw("Vulnerability detected", allFields...)
	case "debug":
		l.WithContext(ctx).Debugw("Vulnerability detected", allFields...)
	default:
		l.WithContext(ctx).Infow("Vulnerability detected", allFields...)
	}

	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		attrs := []attribute.KeyValue{attribute.Bool("vulnerability", true)}
		for k, v := range vuln {
			attrs = append(attrs, attribute.String(k, fmt.Sprintf("%v", v)))
		}
		span.AddEvent("vulnerability_detected", trace.WithAttributes(attrs...))
	}
}

func (l *Logger) LogScanProgress(ctx context.Context, scanID string, progress float64, status string, details map[string]interface{}) {
	allFields := []interface{}{
		"scan_id", scanID,
		"progress", progress,
		"status", status,
		"scan_event", true,
	}

	for k, v := range details {
		allFields = append(allFields, k, v)
	}

	l.WithContext(ctx).Infow("Scan progress update", allFields...)

	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		attrs := []attribute.KeyValue{
			attribute.String("scan_id", scanID),
			attribute.Float64("progress", progress),
			attribute.String("status", status),
		}
		span.AddEvent("scan_progress", trace.WithAttributes(attrs...))
	}
}

func (l *Logger) LogDiscoveryEvent(ctx context.Context, assetType string, assetValue string, confidence float64, details map[string]interface{}) {
	allFields := []interface{}{
		"discovery_event", true,
		"asset_type", assetType,
		"asset_value", assetValue,
		"confidence", confidence,
	}

	for k, v := range details {
		allFields = append(allFields, k, v)
	}

	l.WithContext(ctx).Infow("Asset discovered", allFields...)

	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.AddEvent("asset_discovered", trace.WithAttributes(
			attribute.String("asset_type", assetType),
			attribute.String("asset_value", assetValue),
			attribute.Float64("confidence", confidence),
		))
	}
}

// HTTP and network logging

func (l *Logger) LogHTTPRequest(ctx context.Context, method, url string, statusCode int, duration time.Duration, fields ...interface{}) {
	allFields := []interface{}{
		"http_method", method,
		"http_url", url,
		"http_status", statusCode,
		"duration_ms", duration.Milliseconds(),
		"http_request", true,
	}
	allFields = append(allFields, fields...)

	level := "info"
	if statusCode >= 400 {
		level = "warn"
	}
	if statusCode >= 500 {
		level = "error"
	}

	switch level {
	case "error":
		l.WithContext(ctx).Errorw("HTTP request completed", allFields...)
	case "warn":
		l.WithContext(ctx).Warnw("HTTP request completed", allFields...)
	default:
		l.WithContext(ctx).Infow("HTTP request completed", allFields...)
	}

	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.AddEvent("http_request", trace.WithAttributes(
			attribute.String("method", method),
			attribute.String("url", url),
			attribute.Int("status_code", statusCode),
			attribute.Int64("duration_ms", duration.Milliseconds()),
		))

		if statusCode >= 400 {
			span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", statusCode))
		}
	}
}

// Database and storage logging

func (l *Logger) LogDatabaseOperation(ctx context.Context, operation string, table string, rowsAffected int64, duration time.Duration, fields ...interface{}) {
	allFields := []interface{}{
		"db_operation", operation,
		"db_table", table,
		"rows_affected", rowsAffected,
		"duration_ms", duration.Milliseconds(),
		"database_event", true,
	}
	allFields = append(allFields, fields...)

	l.WithContext(ctx).Debugw("Database operation completed", allFields...)

	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.AddEvent("database_operation", trace.WithAttributes(
			attribute.String("operation", operation),
			attribute.String("table", table),
			attribute.Int64("rows_affected", rowsAffected),
			attribute.Int64("duration_ms", duration.Milliseconds()),
		))
	}
}

// Context utilities

type contextKey struct{}

var loggerKey = contextKey{}

func FromContext(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(loggerKey).(*Logger); ok {
		return logger
	}
	logger, _ := New(config.LoggerConfig{Level: "info", Format: "json"})
	return logger
}

func WithLogger(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// Utility functions for common logging patterns

func (l *Logger) StartOperation(ctx context.Context, operation string, fields ...interface{}) (context.Context, trace.Span) {
	ctx, span := l.StartSpan(ctx, operation)

	allFields := []interface{}{
		"operation", operation,
		"operation_start", true,
	}
	allFields = append(allFields, fields...)

	l.WithContext(ctx).Debugw("Operation started", allFields...)

	return ctx, span
}

func (l *Logger) FinishOperation(ctx context.Context, span trace.Span, operation string, start time.Time, err error, fields ...interface{}) {
	defer span.End()

	duration := time.Since(start)

	allFields := []interface{}{
		"operation", operation,
		"duration_ms", duration.Milliseconds(),
		"operation_end", true,
	}
	allFields = append(allFields, fields...)

	if err != nil {
		l.LogError(ctx, err, operation, allFields...)
	} else {
		l.WithContext(ctx).Debugw("Operation completed successfully", allFields...)
		span.SetStatus(codes.Ok, "completed")
	}

	span.AddEvent("operation_finished", trace.WithAttributes(
		attribute.String("operation", operation),
		attribute.Int64("duration_ms", duration.Milliseconds()),
		attribute.Bool("success", err == nil),
	))
}
