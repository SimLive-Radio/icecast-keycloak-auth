package observability

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

type OTelConfig struct {
	Endpoint               string
	Protocol               string
	Headers                map[string]string
	ExportInterval         time.Duration
	ServiceName            string
	ResourceAttributes     string
}

// InitOTel creates a MeterProvider backed by an OTLP push exporter. If the
// exporter cannot be initialized the provider falls back to a no-op reader so
// the service starts regardless (F-18). The returned shutdown function must be
// called on service exit.
func InitOTel(ctx context.Context, cfg OTelConfig, logger *slog.Logger) (otelmetric.Meter, func(context.Context) error, error) {
	res, err := buildResource(ctx, cfg.ServiceName, cfg.ResourceAttributes)
	if err != nil {
		logger.Warn("otel resource build failed, using default", slog.String("error", err.Error()))
		res = resource.Default()
	}

	var readerOpts []sdkmetric.Option
	readerOpts = append(readerOpts, sdkmetric.WithResource(res))

	if cfg.Endpoint == "" {
		logger.Info("otel exporter disabled: no endpoint configured")
	} else {
		exp, err := newExporter(ctx, cfg)
		if err != nil {
			logger.Warn("otel exporter init failed, metrics will not be exported",
				slog.String("error", err.Error()),
			)
		} else {
			reader := sdkmetric.NewPeriodicReader(exp,
				sdkmetric.WithInterval(cfg.ExportInterval),
			)
			readerOpts = append(readerOpts, sdkmetric.WithReader(reader))
		}
	}

	provider := sdkmetric.NewMeterProvider(readerOpts...)
	otel.SetMeterProvider(provider)

	meter := provider.Meter(cfg.ServiceName)
	shutdown := func(ctx context.Context) error {
		return provider.Shutdown(ctx)
	}

	return meter, shutdown, nil
}

func newExporter(ctx context.Context, cfg OTelConfig) (sdkmetric.Exporter, error) {
	switch cfg.Protocol {
	case "grpc":
		return newGRPCExporter(ctx, cfg)
	case "http/protobuf":
		return newHTTPExporter(ctx, cfg)
	default:
		return nil, fmt.Errorf("unsupported OTLP protocol: %s", cfg.Protocol)
	}
}

func newGRPCExporter(ctx context.Context, cfg OTelConfig) (sdkmetric.Exporter, error) {
	endpoint := cfg.Endpoint
	endpoint = strings.TrimPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")

	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(endpoint),
		otlpmetricgrpc.WithInsecure(),
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlpmetricgrpc.WithHeaders(cfg.Headers))
	}

	exp, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("grpc exporter: %w", err)
	}
	return exp, nil
}

func newHTTPExporter(ctx context.Context, cfg OTelConfig) (sdkmetric.Exporter, error) {
	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpointURL(cfg.Endpoint),
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(cfg.Headers))
	}

	exp, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("http exporter: %w", err)
	}
	return exp, nil
}

func buildResource(ctx context.Context, serviceName, resourceAttributes string) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		attribute.String("service.name", serviceName),
	}

	if resourceAttributes != "" {
		for _, pair := range strings.Split(resourceAttributes, ",") {
			parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(parts) == 2 {
				attrs = append(attrs, attribute.String(
					strings.TrimSpace(parts[0]),
					strings.TrimSpace(parts[1]),
				))
			}
		}
	}

	custom := resource.NewWithAttributes("", attrs...)
	return resource.Merge(custom, resource.Default())
}
