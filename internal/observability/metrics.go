package observability

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Recorder is the interface consumed by the handler. Defined here alongside
// the concrete implementation so the observability package is self-contained.
type Recorder interface {
	RecordAuthRequest(ctx context.Context, action, result string)
	RecordAuthDuration(ctx context.Context, action string, d time.Duration)
	RecordKeycloakRequest(ctx context.Context, result string)
	RecordKeycloakDuration(ctx context.Context, d time.Duration)
	RecordRoleDenied(ctx context.Context, requiredRole string)
}

type Metrics struct {
	authRequestsTotal       metric.Int64Counter
	authDurationSeconds     metric.Float64Histogram
	keycloakRequestsTotal   metric.Int64Counter
	keycloakDurationSeconds metric.Float64Histogram
	roleDeniedTotal         metric.Int64Counter
}

func NewMetrics(meter metric.Meter) (*Metrics, error) {
	authTotal, err := meter.Int64Counter("auth_requests_total",
		metric.WithDescription("Total auth requests by action and result"),
	)
	if err != nil {
		return nil, fmt.Errorf("create auth_requests_total: %w", err)
	}

	authDuration, err := meter.Float64Histogram("auth_duration_seconds",
		metric.WithDescription("Auth request latency"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("create auth_duration_seconds: %w", err)
	}

	kcTotal, err := meter.Int64Counter("keycloak_requests_total",
		metric.WithDescription("Total Keycloak token requests by result"),
	)
	if err != nil {
		return nil, fmt.Errorf("create keycloak_requests_total: %w", err)
	}

	kcDuration, err := meter.Float64Histogram("keycloak_duration_seconds",
		metric.WithDescription("Keycloak token request latency"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("create keycloak_duration_seconds: %w", err)
	}

	roleDenied, err := meter.Int64Counter("role_denied_total",
		metric.WithDescription("Auth requests denied due to missing client role"),
	)
	if err != nil {
		return nil, fmt.Errorf("create role_denied_total: %w", err)
	}

	return &Metrics{
		authRequestsTotal:       authTotal,
		authDurationSeconds:     authDuration,
		keycloakRequestsTotal:   kcTotal,
		keycloakDurationSeconds: kcDuration,
		roleDeniedTotal:         roleDenied,
	}, nil
}

func (m *Metrics) RecordAuthRequest(ctx context.Context, action, result string) {
	m.authRequestsTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("action", action),
			attribute.String("result", result),
		),
	)
}

func (m *Metrics) RecordAuthDuration(ctx context.Context, action string, d time.Duration) {
	m.authDurationSeconds.Record(ctx, d.Seconds(),
		metric.WithAttributes(attribute.String("action", action)),
	)
}

func (m *Metrics) RecordKeycloakRequest(ctx context.Context, result string) {
	m.keycloakRequestsTotal.Add(ctx, 1,
		metric.WithAttributes(attribute.String("result", result)),
	)
}

func (m *Metrics) RecordKeycloakDuration(ctx context.Context, d time.Duration) {
	m.keycloakDurationSeconds.Record(ctx, d.Seconds())
}

func (m *Metrics) RecordRoleDenied(ctx context.Context, requiredRole string) {
	m.roleDeniedTotal.Add(ctx, 1,
		metric.WithAttributes(attribute.String("required_role", requiredRole)),
	)
}

// NoopRecorder implements Recorder with no-ops. Useful in tests.
type NoopRecorder struct{}

func (NoopRecorder) RecordAuthRequest(context.Context, string, string)   {}
func (NoopRecorder) RecordAuthDuration(context.Context, string, time.Duration) {}
func (NoopRecorder) RecordKeycloakRequest(context.Context, string)       {}
func (NoopRecorder) RecordKeycloakDuration(context.Context, time.Duration) {}
func (NoopRecorder) RecordRoleDenied(context.Context, string)             {}
