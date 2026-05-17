package handler_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"simliveradio.org/icecast-keycloak-auth/internal/handler"
	"simliveradio.org/icecast-keycloak-auth/internal/observability"
)

// mockKeycloakClient implements keycloak.Client for unit tests.
type mockKeycloakClient struct {
	token string
	err   error
}

func (m *mockKeycloakClient) GetToken(_ context.Context, _, _ string) (string, error) {
	return m.token, m.err
}

func makeJWT(clientID string, roles []string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]interface{}{
		"resource_access": map[string]interface{}{
			clientID: map[string]interface{}{"roles": roles},
		},
	})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newHandler(kc *mockKeycloakClient) *handler.AuthHandler {
	return handler.NewAuthHandler(kc, "myclient", "streamer", observability.NoopRecorder{}, discardLogger())
}

func postForm(h http.Handler, fields map[string]string) *httptest.ResponseRecorder {
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// ─── Non-stream_auth actions ──────────────────────────────────────────────────

func TestAuthHandler_ListenerAdd_Returns200(t *testing.T) {
	h := newHandler(&mockKeycloakClient{})
	rr := postForm(h, map[string]string{"action": "listener_add", "user": "alice"})
	if rr.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rr.Code)
	}
	if rr.Header().Get("icecast-auth-user") != "1" {
		t.Error("missing icecast-auth-user: 1 header")
	}
}

func TestAuthHandler_ListenerRemove_Returns200(t *testing.T) {
	h := newHandler(&mockKeycloakClient{})
	rr := postForm(h, map[string]string{"action": "listener_remove", "user": "alice"})
	if rr.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rr.Code)
	}
}

func TestAuthHandler_UnknownAction_Returns200(t *testing.T) {
	h := newHandler(&mockKeycloakClient{})
	rr := postForm(h, map[string]string{"action": "mount_add"})
	if rr.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rr.Code)
	}
}

func TestAuthHandler_EmptyAction_Returns200(t *testing.T) {
	h := newHandler(&mockKeycloakClient{})
	rr := postForm(h, map[string]string{"action": ""})
	if rr.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rr.Code)
	}
}

// ─── stream_auth – credential checks ─────────────────────────────────────────

func TestAuthHandler_StreamAuth_EmptyUser_Returns401(t *testing.T) {
	h := newHandler(&mockKeycloakClient{token: makeJWT("myclient", []string{"streamer"})})
	rr := postForm(h, map[string]string{"action": "stream_auth", "user": "", "pass": "secret"})
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", rr.Code)
	}
}

func TestAuthHandler_StreamAuth_EmptyPass_Returns401(t *testing.T) {
	h := newHandler(&mockKeycloakClient{token: makeJWT("myclient", []string{"streamer"})})
	rr := postForm(h, map[string]string{"action": "stream_auth", "user": "alice", "pass": ""})
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", rr.Code)
	}
}

func TestAuthHandler_StreamAuth_KeycloakError_Returns401(t *testing.T) {
	h := newHandler(&mockKeycloakClient{err: errors.New("invalid credentials")})
	rr := postForm(h, map[string]string{"action": "stream_auth", "user": "alice", "pass": "wrong"})
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", rr.Code)
	}
}

func TestAuthHandler_StreamAuth_RoleMissing_Returns403(t *testing.T) {
	token := makeJWT("myclient", []string{"listener"}) // no "streamer"
	h := newHandler(&mockKeycloakClient{token: token})
	rr := postForm(h, map[string]string{"action": "stream_auth", "user": "alice", "pass": "secret"})
	if rr.Code != http.StatusForbidden {
		t.Errorf("code = %d, want 403", rr.Code)
	}
}

func TestAuthHandler_StreamAuth_Success_Returns200WithHeader(t *testing.T) {
	token := makeJWT("myclient", []string{"streamer"})
	h := newHandler(&mockKeycloakClient{token: token})
	rr := postForm(h, map[string]string{"action": "stream_auth", "user": "alice", "pass": "secret"})
	if rr.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rr.Code)
	}
	if rr.Header().Get("icecast-auth-user") != "1" {
		t.Error("missing icecast-auth-user: 1 header on success")
	}
}

// ─── HTTP method enforcement ──────────────────────────────────────────────────

func TestAuthHandler_GetMethod_Returns405(t *testing.T) {
	h := newHandler(&mockKeycloakClient{})
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("code = %d, want 405", rr.Code)
	}
}

func TestAuthHandler_PutMethod_Returns405(t *testing.T) {
	h := newHandler(&mockKeycloakClient{})
	req := httptest.NewRequest(http.MethodPut, "/auth", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("code = %d, want 405", rr.Code)
	}
}

// ─── Password never logged ────────────────────────────────────────────────────

func TestAuthHandler_PasswordNotInLogOutput(t *testing.T) {
	var logBuf strings.Builder
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	token := makeJWT("myclient", []string{"streamer"})
	h := handler.NewAuthHandler(
		&mockKeycloakClient{token: token},
		"myclient", "streamer",
		observability.NoopRecorder{},
		logger,
	)

	postForm(h, map[string]string{
		"action": "stream_auth",
		"user":   "alice",
		"pass":   "supersecretpassword",
	})

	if strings.Contains(logBuf.String(), "supersecretpassword") {
		t.Error("password appeared in log output")
	}
}

// ─── Metrics wiring ───────────────────────────────────────────────────────────

type capturingRecorder struct {
	observability.NoopRecorder
	authResults      []string
	keycloakResults  []string
	roleDeniedCalled bool
}

func (c *capturingRecorder) RecordAuthRequest(_ context.Context, _, result string) {
	c.authResults = append(c.authResults, result)
}

func (c *capturingRecorder) RecordKeycloakRequest(_ context.Context, result string) {
	c.keycloakResults = append(c.keycloakResults, result)
}

func (c *capturingRecorder) RecordRoleDenied(_ context.Context, _ string) {
	c.roleDeniedCalled = true
}

func (c *capturingRecorder) RecordAuthDuration(_ context.Context, _ string, _ time.Duration) {}
func (c *capturingRecorder) RecordKeycloakDuration(_ context.Context, _ time.Duration)       {}

func TestAuthHandler_Metrics_SuccessPath(t *testing.T) {
	rec := &capturingRecorder{}
	token := makeJWT("myclient", []string{"streamer"})
	h := handler.NewAuthHandler(
		&mockKeycloakClient{token: token},
		"myclient", "streamer", rec, discardLogger(),
	)
	postForm(h, map[string]string{"action": "stream_auth", "user": "alice", "pass": "secret"})

	if len(rec.authResults) != 1 || rec.authResults[0] != "success" {
		t.Errorf("authResults = %v, want [success]", rec.authResults)
	}
	if len(rec.keycloakResults) != 1 || rec.keycloakResults[0] != "success" {
		t.Errorf("keycloakResults = %v, want [success]", rec.keycloakResults)
	}
}

func TestAuthHandler_Metrics_KeycloakError(t *testing.T) {
	rec := &capturingRecorder{}
	h := handler.NewAuthHandler(
		&mockKeycloakClient{err: errors.New("bad creds")},
		"myclient", "streamer", rec, discardLogger(),
	)
	postForm(h, map[string]string{"action": "stream_auth", "user": "alice", "pass": "bad"})

	if len(rec.keycloakResults) != 1 || rec.keycloakResults[0] != "error" {
		t.Errorf("keycloakResults = %v, want [error]", rec.keycloakResults)
	}
}

func TestAuthHandler_Metrics_RoleDenied(t *testing.T) {
	rec := &capturingRecorder{}
	token := makeJWT("myclient", []string{"listener"})
	h := handler.NewAuthHandler(
		&mockKeycloakClient{token: token},
		"myclient", "streamer", rec, discardLogger(),
	)
	postForm(h, map[string]string{"action": "stream_auth", "user": "alice", "pass": "secret"})

	if !rec.roleDeniedCalled {
		t.Error("RecordRoleDenied was not called")
	}
	if len(rec.authResults) != 1 || rec.authResults[0] != "forbidden" {
		t.Errorf("authResults = %v, want [forbidden]", rec.authResults)
	}
}
