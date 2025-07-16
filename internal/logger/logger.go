package logger

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	*zap.SugaredLogger
	tracer trace.Tracer
}

func New(cfg config.LoggerConfig) (*Logger, error) {
	var zapConfig zap.Config

	if cfg.Format == "console" {
		zapConfig = zap.NewDevelopmentConfig()
		zapConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		zapConfig = zap.NewProductionConfig()
	}

	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}
	zapConfig.Level = zap.NewAtomicLevelAt(level)

	if len(cfg.OutputPaths) > 0 {
		zapConfig.OutputPaths = cfg.OutputPaths
	}

	baseLogger, err := zapConfig.Build(
		zap.AddCallerSkip(1),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build logger: %w", err)
	}

	return &Logger{
		SugaredLogger: baseLogger.Sugar(),
	}, nil
}

func (l *Logger) WithContext(ctx context.Context) *Logger {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		spanCtx := span.SpanContext()
		return &Logger{
			SugaredLogger: l.With(
				"trace_id", spanCtx.TraceID().String(),
				"span_id", spanCtx.SpanID().String(),
			),
			tracer: l.tracer,
		}
	}
	return l
}

func (l *Logger) WithFields(fields ...interface{}) *Logger {
	return &Logger{
		SugaredLogger: l.With(fields...),
		tracer:        l.tracer,
	}
}

func (l *Logger) WithTracer(tracer trace.Tracer) *Logger {
	l.tracer = tracer
	return l
}

func (l *Logger) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if l.tracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}
	return l.tracer.Start(ctx, name, opts...)
}

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
