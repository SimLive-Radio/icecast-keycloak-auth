package config_test

import (
	"strings"
	"testing"
	"time"

	"simliveradio.org/icecast-keycloak-auth/internal/config"
)

func setEnv(t *testing.T, pairs ...string) {
	t.Helper()
	for i := 0; i < len(pairs); i += 2 {
		t.Setenv(pairs[i], pairs[i+1])
	}
}

func requiredVars(t *testing.T) {
	t.Helper()
	setEnv(t,
		"KEYCLOAK_BASE_URL", "http://keycloak:8080",
		"KEYCLOAK_REALM", "myrealm",
		"KEYCLOAK_CLIENT_ID", "myclient",
		"REQUIRED_CLIENT_ROLE", "streamer",
	)
}

func TestLoad_Defaults(t *testing.T) {
	requiredVars(t)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080", cfg.ListenAddr)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.OTLPEndpoint != "http://localhost:4317" {
		t.Errorf("OTLPEndpoint = %q, want http://localhost:4317", cfg.OTLPEndpoint)
	}
	if cfg.OTLPProtocol != "grpc" {
		t.Errorf("OTLPProtocol = %q, want grpc", cfg.OTLPProtocol)
	}
	if cfg.MetricExportInterval != 15*time.Second {
		t.Errorf("MetricExportInterval = %v, want 15s", cfg.MetricExportInterval)
	}
	if cfg.OTELServiceName != "icecast-keycloak-auth" {
		t.Errorf("OTELServiceName = %q, want icecast-keycloak-auth", cfg.OTELServiceName)
	}
	if cfg.LokiServiceLabel != "icecast-auth" {
		t.Errorf("LokiServiceLabel = %q, want icecast-auth", cfg.LokiServiceLabel)
	}
	if cfg.LokiEnvLabel != "production" {
		t.Errorf("LokiEnvLabel = %q, want production", cfg.LokiEnvLabel)
	}
}

func TestLoad_RequiredVarsPresent(t *testing.T) {
	requiredVars(t)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.KeycloakBaseURL != "http://keycloak:8080" {
		t.Errorf("KeycloakBaseURL = %q", cfg.KeycloakBaseURL)
	}
	if cfg.KeycloakRealm != "myrealm" {
		t.Errorf("KeycloakRealm = %q", cfg.KeycloakRealm)
	}
	if cfg.KeycloakClientID != "myclient" {
		t.Errorf("KeycloakClientID = %q", cfg.KeycloakClientID)
	}
	if cfg.RequiredClientRole != "streamer" {
		t.Errorf("RequiredClientRole = %q", cfg.RequiredClientRole)
	}
}

func TestLoad_MissingKeycloakBaseURL(t *testing.T) {
	setEnv(t,
		"KEYCLOAK_REALM", "myrealm",
		"KEYCLOAK_CLIENT_ID", "myclient",
		"REQUIRED_CLIENT_ROLE", "streamer",
	)

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "KEYCLOAK_BASE_URL") {
		t.Errorf("error should mention KEYCLOAK_BASE_URL: %v", err)
	}
}

func TestLoad_MissingKeycloakRealm(t *testing.T) {
	setEnv(t,
		"KEYCLOAK_BASE_URL", "http://keycloak:8080",
		"KEYCLOAK_CLIENT_ID", "myclient",
		"REQUIRED_CLIENT_ROLE", "streamer",
	)

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "KEYCLOAK_REALM") {
		t.Errorf("error should mention KEYCLOAK_REALM: %v", err)
	}
}

func TestLoad_MissingKeycloakClientID(t *testing.T) {
	setEnv(t,
		"KEYCLOAK_BASE_URL", "http://keycloak:8080",
		"KEYCLOAK_REALM", "myrealm",
		"REQUIRED_CLIENT_ROLE", "streamer",
	)

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "KEYCLOAK_CLIENT_ID") {
		t.Errorf("error should mention KEYCLOAK_CLIENT_ID: %v", err)
	}
}

func TestLoad_MissingRequiredClientRole(t *testing.T) {
	setEnv(t,
		"KEYCLOAK_BASE_URL", "http://keycloak:8080",
		"KEYCLOAK_REALM", "myrealm",
		"KEYCLOAK_CLIENT_ID", "myclient",
	)

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "REQUIRED_CLIENT_ROLE") {
		t.Errorf("error should mention REQUIRED_CLIENT_ROLE: %v", err)
	}
}

func TestLoad_AllRequiredMissing_ReportsAll(t *testing.T) {
	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	for _, name := range []string{"KEYCLOAK_BASE_URL", "KEYCLOAK_REALM", "KEYCLOAK_CLIENT_ID", "REQUIRED_CLIENT_ROLE"} {
		if !strings.Contains(msg, name) {
			t.Errorf("error should mention %s: %v", name, err)
		}
	}
}

func TestLoad_InvalidLogLevel(t *testing.T) {
	requiredVars(t)
	t.Setenv("LOG_LEVEL", "verbose")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "LOG_LEVEL") {
		t.Errorf("error should mention LOG_LEVEL: %v", err)
	}
}

func TestLoad_InvalidOTLPProtocol(t *testing.T) {
	requiredVars(t)
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "OTEL_EXPORTER_OTLP_PROTOCOL") {
		t.Errorf("error should mention OTEL_EXPORTER_OTLP_PROTOCOL: %v", err)
	}
}

func TestLoad_InvalidMetricExportInterval(t *testing.T) {
	requiredVars(t)
	t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "notaduration")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "OTEL_METRIC_EXPORT_INTERVAL") {
		t.Errorf("error should mention OTEL_METRIC_EXPORT_INTERVAL: %v", err)
	}
}

func TestLoad_NegativeMetricExportInterval(t *testing.T) {
	requiredVars(t)
	t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "-5s")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestLoad_OTLPHeaders_Parsed(t *testing.T) {
	requiredVars(t)
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "Authorization=Bearer token123, X-Tenant=acme")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OTLPHeaders["Authorization"] != "Bearer token123" {
		t.Errorf("Authorization header = %q", cfg.OTLPHeaders["Authorization"])
	}
	if cfg.OTLPHeaders["X-Tenant"] != "acme" {
		t.Errorf("X-Tenant header = %q", cfg.OTLPHeaders["X-Tenant"])
	}
}

func TestLoad_CustomInterval(t *testing.T) {
	requiredVars(t)
	t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "30s")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MetricExportInterval != 30*time.Second {
		t.Errorf("MetricExportInterval = %v, want 30s", cfg.MetricExportInterval)
	}
}

func TestLoad_HTTPProtobufProtocol(t *testing.T) {
	requiredVars(t)
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OTLPProtocol != "http/protobuf" {
		t.Errorf("OTLPProtocol = %q, want http/protobuf", cfg.OTLPProtocol)
	}
}
