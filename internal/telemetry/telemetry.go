package telemetry

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/core"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

type telemetry struct {
	tracer         trace.Tracer
	meter          metric.Meter
	tracerProvider *sdktrace.TracerProvider

	scanCounter    metric.Int64Counter
	scanDuration   metric.Float64Histogram
	findingCounter metric.Int64Counter
	workerGauge    metric.Int64UpDownCounter
}

func New(ctx context.Context, cfg config.TelemetryConfig) (core.Telemetry, error) {
	if !cfg.Enabled {
		return &noopTelemetry{}, nil
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	var exporter sdktrace.SpanExporter

	switch cfg.ExporterType {
	case "otlp":
		client := otlptracehttp.NewClient(
			otlptracehttp.WithEndpoint(cfg.Endpoint),
			otlptracehttp.WithInsecure(),
		)
		exp, err := otlptrace.New(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
		}
		exporter = exp
	default:
		return nil, fmt.Errorf("unsupported exporter type: %s", cfg.ExporterType)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(cfg.SampleRate)),
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer := tp.Tracer(cfg.ServiceName)
	meter := otel.Meter(cfg.ServiceName)

	scanCounter, err := meter.Int64Counter("shells.scans.total",
		metric.WithDescription("Total number of scans"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	scanDuration, err := meter.Float64Histogram("shells.scan.duration",
		metric.WithDescription("Scan duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	findingCounter, err := meter.Int64Counter("shells.findings.total",
		metric.WithDescription("Total number of findings"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	workerGauge, err := meter.Int64UpDownCounter("shells.workers.active",
		metric.WithDescription("Number of active workers"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	return &telemetry{
		tracer:         tracer,
		meter:          meter,
		tracerProvider: tp,
		scanCounter:    scanCounter,
		scanDuration:   scanDuration,
		findingCounter: findingCounter,
		workerGauge:    workerGauge,
	}, nil
}

func (t *telemetry) RecordScan(scanType types.ScanType, duration float64, success bool) {
	ctx := context.Background()

	attrs := []attribute.KeyValue{
		attribute.String("scan.type", string(scanType)),
		attribute.Bool("scan.success", success),
	}

	t.scanCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	t.scanDuration.Record(ctx, duration, metric.WithAttributes(attrs...))
}

func (t *telemetry) RecordFinding(severity types.Severity) {
	ctx := context.Background()

	attrs := []attribute.KeyValue{
		attribute.String("finding.severity", string(severity)),
	}

	t.findingCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func (t *telemetry) RecordWorkerMetrics(status *types.WorkerStatus) {
	ctx := context.Background()

	attrs := []attribute.KeyValue{
		attribute.String("worker.id", status.ID),
		attribute.String("worker.status", status.Status),
	}

	if status.Status == "active" {
		t.workerGauge.Add(ctx, 1, metric.WithAttributes(attrs...))
	} else {
		t.workerGauge.Add(ctx, -1, metric.WithAttributes(attrs...))
	}
}

func (t *telemetry) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return t.tracerProvider.Shutdown(ctx)
}

type noopTelemetry struct{}

func (n *noopTelemetry) RecordScan(scanType types.ScanType, duration float64, success bool) {}
func (n *noopTelemetry) RecordFinding(severity types.Severity)                              {}
func (n *noopTelemetry) RecordWorkerMetrics(status *types.WorkerStatus)                     {}
func (n *noopTelemetry) Close() error                                                       { return nil }
