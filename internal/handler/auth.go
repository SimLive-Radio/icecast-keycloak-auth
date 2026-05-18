package handler

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"simliveradio.org/icecast-keycloak-auth/internal/keycloak"
	"simliveradio.org/icecast-keycloak-auth/internal/observability"
)

const actionStreamAuth = "stream_auth"

const (
	authHeaderModeModern = "modern"
	authHeaderModeLegacy = "legacy"
)

type AuthHandler struct {
	keycloak       keycloak.Client
	clientID       string
	requiredRole   string
	authHeaderMode string
	metrics        observability.Recorder
	logger         *slog.Logger
}

func NewAuthHandler(
	kc keycloak.Client,
	clientID string,
	requiredRole string,
	authHeaderMode string,
	metrics observability.Recorder,
	logger *slog.Logger,
) *AuthHandler {
	return &AuthHandler{
		keycloak:       kc,
		clientID:       clientID,
		requiredRole:   requiredRole,
		authHeaderMode: authHeaderMode,
		metrics:        metrics,
		logger:         logger,
	}
}

func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	action := r.FormValue("action")
	user := r.FormValue("user")
	ip := r.FormValue("ip")
	agent := r.FormValue("agent")

	// Non-stream_auth actions are always permitted without credential check.
	if action != actionStreamAuth {
		h.logger.Info("auth request",
			slog.String("action", action),
			slog.String("user", user),
			slog.String("ip", ip),
			slog.String("agent", agent),
			slog.String("result", "passthrough"),
		)
		h.writeAuthHeaders(w, http.StatusOK, "ok", "")
		return
	}

	pass := r.FormValue("pass")

	start := time.Now()
	result, code, reason := h.authenticate(r.Context(), user, pass)
	duration := time.Since(start)

	h.metrics.RecordAuthRequest(r.Context(), action, result)
	h.metrics.RecordAuthDuration(r.Context(), action, duration)

	h.logger.Info("auth request",
		slog.String("action", action),
		slog.String("user", user),
		slog.String("ip", ip),
		slog.String("result", result),
		slog.Int64("duration_ms", duration.Milliseconds()),
	)

	h.writeAuthHeaders(w, code, resultHeaderValue(code), reason)
}

func (h *AuthHandler) writeAuthHeaders(w http.ResponseWriter, code int, result, reason string) {
	if h.authHeaderMode == authHeaderModeLegacy {
		if code == http.StatusOK {
			w.Header().Set("icecast-auth-user", "1")
		} else if reason != "" {
			w.Header().Set("Icecast-Auth-Message", reason)
		}
		w.WriteHeader(code)
		return
	}

	w.Header().Set("x-icecast-auth-result", result)
	if reason != "" {
		w.Header().Set("x-icecast-auth-message", reason)
	}
	w.WriteHeader(code)
}

func resultHeaderValue(code int) string {
	if code == http.StatusOK {
		return "ok"
	}
	return "failed"
}

func (h *AuthHandler) authenticate(ctx context.Context, user, pass string) (string, int, string) {
	if user == "" || pass == "" {
		return "unauthorized", http.StatusUnauthorized, "Missing username or password"
	}

	kcStart := time.Now()
	token, err := h.keycloak.GetToken(ctx, user, pass)
	kcDuration := time.Since(kcStart)

	if err != nil {
		h.metrics.RecordKeycloakRequest(ctx, "error")
		h.metrics.RecordKeycloakDuration(ctx, kcDuration)
		h.logger.Warn("keycloak token request failed", slog.String("error", err.Error()))
		return "unauthorized", http.StatusUnauthorized, "Invalid credentials"
	}

	h.metrics.RecordKeycloakRequest(ctx, "success")
	h.metrics.RecordKeycloakDuration(ctx, kcDuration)

	hasRole, err := keycloak.HasClientRole(token, h.clientID, h.requiredRole)
	if err != nil {
		h.logger.Error("role check failed", slog.String("error", err.Error()))
		return "unauthorized", http.StatusUnauthorized, "Invalid token claims"
	}

	if !hasRole {
		h.metrics.RecordRoleDenied(ctx, h.requiredRole)
		return "forbidden", http.StatusForbidden, "Missing required role"
	}

	return "success", http.StatusOK, ""
}

type HealthHandler struct{}

func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
