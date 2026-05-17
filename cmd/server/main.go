package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"simliveradio.org/icecast-keycloak-auth/internal/config"
	"simliveradio.org/icecast-keycloak-auth/internal/handler"
	"simliveradio.org/icecast-keycloak-auth/internal/keycloak"
	"simliveradio.org/icecast-keycloak-auth/internal/observability"
)

func main() {
	// Support a lightweight in-container health check by invoking the
	// service binary with `--health`. This allows healthchecks to run in a
	// scratch-based image without adding curl/wget.
	if len(os.Args) > 1 && os.Args[1] == "--health" {
		if err := doHealthCheck(); err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

// doHealthCheck performs a simple GET against the running server's /health
// endpoint using the configured listen address. It loads the normal
// configuration so environment problems are surfaced as failures.
func doHealthCheck() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	host := cfg.ListenAddr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	url := "http://" + host + "/health"

	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return nil
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := observability.NewLogger(cfg.LogLevel, cfg.LokiServiceLabel, cfg.LokiEnvLabel)

	ctx := context.Background()

	meter, shutdown, err := observability.InitOTel(ctx, observability.OTelConfig{
		Endpoint:           cfg.OTLPEndpoint,
		Protocol:           cfg.OTLPProtocol,
		Headers:            cfg.OTLPHeaders,
		ExportInterval:     cfg.MetricExportInterval,
		ServiceName:        cfg.OTELServiceName,
		ResourceAttributes: cfg.OTELResourceAttributes,
	}, logger)
	if err != nil {
		return fmt.Errorf("init otel: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := shutdown(shutdownCtx); err != nil {
			logger.Error("otel shutdown failed", "error", err)
		}
	}()

	metrics, err := observability.NewMetrics(meter)
	if err != nil {
		return fmt.Errorf("init metrics: %w", err)
	}

	kc := keycloak.NewHTTPClient(
		cfg.KeycloakBaseURL,
		cfg.KeycloakRealm,
		cfg.KeycloakClientID,
		cfg.KeycloakClientSecret,
	)

	authHandler := handler.NewAuthHandler(
		kc,
		cfg.KeycloakClientID,
		cfg.RequiredClientRole,
		metrics,
		logger,
	)

	mux := http.NewServeMux()
	mux.Handle("/auth", authHandler)
	mux.Handle("/health", &handler.HealthHandler{})

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("server starting", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("listen: %w", err)
		}
		close(serverErr)
	}()

	select {
	case err := <-serverErr:
		return err
	case sig := <-quit:
		logger.Info("shutting down", "signal", sig.String())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}

	return <-serverErr
}
