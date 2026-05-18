package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	ListenAddr             string
	KeycloakBaseURL        string
	KeycloakRealm          string
	KeycloakClientID       string
	KeycloakClientSecret   string
	RequiredClientRole     string
	IcecastAuthHeaderMode  string
	LogLevel               string
	OTLPEndpoint           string
	OTLPProtocol           string
	OTLPHeaders            map[string]string
	MetricExportInterval   time.Duration
	OTELServiceName        string
	OTELResourceAttributes string
	LokiServiceLabel       string
	LokiEnvLabel           string
}

func Load() (*Config, error) {
	var errs []string

	require := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			errs = append(errs, fmt.Sprintf("required env var %s is not set", name))
		}
		return v
	}

	optional := func(name, def string) string {
		if v := os.Getenv(name); v != "" {
			return v
		}
		return def
	}

	rawInterval := optional("OTEL_METRIC_EXPORT_INTERVAL", "15s")
	interval, err := time.ParseDuration(rawInterval)
	if err != nil {
		errs = append(errs, fmt.Sprintf("invalid OTEL_METRIC_EXPORT_INTERVAL %q: %v", rawInterval, err))
		interval = 15 * time.Second
	}
	if interval <= 0 {
		errs = append(errs, fmt.Sprintf("OTEL_METRIC_EXPORT_INTERVAL must be positive, got %q", rawInterval))
		interval = 15 * time.Second
	}

	otlpProtocol := optional("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")

	logLevel := optional("LOG_LEVEL", "info")
	switch logLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Sprintf("LOG_LEVEL must be one of debug/info/warn/error, got %q", logLevel))
	}

	authHeaderMode := strings.ToLower(strings.TrimSpace(optional("ICECAST_AUTH_HEADER_MODE", "modern")))
	switch authHeaderMode {
	case "modern", "legacy":
	default:
		errs = append(errs, fmt.Sprintf("ICECAST_AUTH_HEADER_MODE must be one of modern/legacy, got %q", authHeaderMode))
	}

	cfg := &Config{
		ListenAddr:             optional("LISTEN_ADDR", ":8080"),
		KeycloakBaseURL:        require("KEYCLOAK_BASE_URL"),
		KeycloakRealm:          require("KEYCLOAK_REALM"),
		KeycloakClientID:       require("KEYCLOAK_CLIENT_ID"),
		KeycloakClientSecret:   optional("KEYCLOAK_CLIENT_SECRET", ""),
		RequiredClientRole:     require("REQUIRED_CLIENT_ROLE"),
		IcecastAuthHeaderMode:  authHeaderMode,
		LogLevel:               logLevel,
		OTLPEndpoint:           optional("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
		OTLPProtocol:           otlpProtocol,
		OTLPHeaders:            parseHeaders(optional("OTEL_EXPORTER_OTLP_HEADERS", "")),
		MetricExportInterval:   interval,
		OTELServiceName:        optional("OTEL_SERVICE_NAME", "icecast-keycloak-auth"),
		OTELResourceAttributes: optional("OTEL_RESOURCE_ATTRIBUTES", ""),
		LokiServiceLabel:       optional("LOKI_SERVICE_LABEL", "icecast-auth"),
		LokiEnvLabel:           optional("LOKI_ENV_LABEL", "production"),
	}

	if cfg.OTLPEndpoint != "" && cfg.OTLPProtocol != "grpc" && cfg.OTLPProtocol != "http/protobuf" {
		errs = append(errs, fmt.Sprintf("OTEL_EXPORTER_OTLP_PROTOCOL must be 'grpc' or 'http/protobuf', got %q", cfg.OTLPProtocol))
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("configuration errors:\n  %s", strings.Join(errs, "\n  "))
	}

	return cfg, nil
}

func parseHeaders(s string) map[string]string {
	headers := make(map[string]string)
	if s == "" {
		return headers
	}
	for pair := range strings.SplitSeq(s, ",") {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}
