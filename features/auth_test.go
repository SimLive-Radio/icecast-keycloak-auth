package features_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"simliveradio.org/icecast-keycloak-auth/internal/handler"
	"simliveradio.org/icecast-keycloak-auth/internal/keycloak"
	"simliveradio.org/icecast-keycloak-auth/internal/observability"
)

const (
	testClientID  = "icecast-client"
	testRealm     = "testrealm"
	testRole      = "streamer"
	testValidUser = "alice"
	testValidPass = "correcthorsebatterystaple"
)

func buildHandler(t *testing.T, kcBaseURL string) http.Handler {
	t.Helper()
	kc := keycloak.NewHTTPClient(kcBaseURL, testRealm, testClientID, "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	authH := handler.NewAuthHandler(kc, testClientID, testRole, "modern", observability.NoopRecorder{}, logger)

	mux := http.NewServeMux()
	mux.Handle("/auth", authH)
	mux.Handle("/health", &handler.HealthHandler{})
	return mux
}

func doPost(t *testing.T, srv http.Handler, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	return rr
}

// F-26: stream_auth → Keycloak ok + role ok → 200
func TestFeature_StreamAuth_ValidCredentials_CorrectRole_Returns200(t *testing.T) {
	mk := newMockKeycloak(t, mockKeycloakConfig{
		validUser: testValidUser,
		validPass: testValidPass,
		clientID:  testClientID,
		roles:     []string{testRole},
	})
	h := buildHandler(t, mk.URL())

	rr := doPost(t, h, map[string]string{
		"action": "stream_auth",
		"user":   testValidUser,
		"pass":   testValidPass,
		"ip":     "203.0.113.1",
		"agent":  "Icecast/2.4",
	})

	if rr.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rr.Code)
	}
	if rr.Header().Get("x-icecast-auth-result") != "ok" {
		t.Error("missing x-icecast-auth-result: ok header")
	}
}

// F-27: stream_auth → Keycloak ok + role missing → 403
func TestFeature_StreamAuth_ValidCredentials_MissingRole_Returns403(t *testing.T) {
	mk := newMockKeycloak(t, mockKeycloakConfig{
		validUser: testValidUser,
		validPass: testValidPass,
		clientID:  testClientID,
		roles:     []string{"listener"}, // not "streamer"
	})
	h := buildHandler(t, mk.URL())

	rr := doPost(t, h, map[string]string{
		"action": "stream_auth",
		"user":   testValidUser,
		"pass":   testValidPass,
	})

	if rr.Code != http.StatusForbidden {
		t.Errorf("code = %d, want 403", rr.Code)
	}
	if rr.Header().Get("x-icecast-auth-result") != "failed" {
		t.Errorf("x-icecast-auth-result = %q, want %q", rr.Header().Get("x-icecast-auth-result"), "failed")
	}
	if rr.Header().Get("x-icecast-auth-message") != "Missing required role" {
		t.Errorf("x-icecast-auth-message = %q, want %q", rr.Header().Get("x-icecast-auth-message"), "Missing required role")
	}
}

// F-28: stream_auth → Keycloak 401 → 401
func TestFeature_StreamAuth_WrongPassword_Returns401(t *testing.T) {
	mk := newMockKeycloak(t, mockKeycloakConfig{
		validUser: testValidUser,
		validPass: testValidPass,
		clientID:  testClientID,
		roles:     []string{testRole},
	})
	h := buildHandler(t, mk.URL())

	rr := doPost(t, h, map[string]string{
		"action": "stream_auth",
		"user":   testValidUser,
		"pass":   "wrongpassword",
	})

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", rr.Code)
	}
	if rr.Header().Get("x-icecast-auth-result") != "failed" {
		t.Errorf("x-icecast-auth-result = %q, want %q", rr.Header().Get("x-icecast-auth-result"), "failed")
	}
	if rr.Header().Get("x-icecast-auth-message") != "Invalid credentials" {
		t.Errorf("x-icecast-auth-message = %q, want %q", rr.Header().Get("x-icecast-auth-message"), "Invalid credentials")
	}
}

// F-29: all non-stream_auth actions → 200
func TestFeature_ListenerAdd_Returns200(t *testing.T) {
	mk := newMockKeycloak(t, mockKeycloakConfig{})
	h := buildHandler(t, mk.URL())

	rr := doPost(t, h, map[string]string{
		"action": "listener_add",
		"user":   "bob",
		"ip":     "203.0.113.2",
	})

	if rr.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rr.Code)
	}
	if rr.Header().Get("x-icecast-auth-result") != "ok" {
		t.Error("missing x-icecast-auth-result: ok header")
	}
}

func TestFeature_ListenerRemove_Returns200(t *testing.T) {
	mk := newMockKeycloak(t, mockKeycloakConfig{})
	h := buildHandler(t, mk.URL())

	rr := doPost(t, h, map[string]string{
		"action": "listener_remove",
		"user":   "bob",
	})

	if rr.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rr.Code)
	}
}

func TestFeature_MountAdd_Returns200(t *testing.T) {
	mk := newMockKeycloak(t, mockKeycloakConfig{})
	h := buildHandler(t, mk.URL())

	rr := doPost(t, h, map[string]string{"action": "mount_add"})

	if rr.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rr.Code)
	}
}

// F-30: Keycloak unreachable → 401 + service continues running
func TestFeature_KeycloakUnreachable_Returns401_ServiceContinues(t *testing.T) {
	mk := newMockKeycloak(t, mockKeycloakConfig{
		validUser: testValidUser,
		validPass: testValidPass,
		clientID:  testClientID,
		roles:     []string{testRole},
	})
	kcURL := mk.URL()
	// Close the mock server to simulate unreachable Keycloak.
	mk.srv.Close()

	h := buildHandler(t, kcURL)

	rr := doPost(t, h, map[string]string{
		"action": "stream_auth",
		"user":   testValidUser,
		"pass":   testValidPass,
	})

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401 when Keycloak is unreachable", rr.Code)
	}
	if rr.Header().Get("x-icecast-auth-result") != "failed" {
		t.Errorf("x-icecast-auth-result = %q, want %q", rr.Header().Get("x-icecast-auth-result"), "failed")
	}
	if rr.Header().Get("x-icecast-auth-message") != "Invalid credentials" {
		t.Errorf("x-icecast-auth-message = %q, want %q", rr.Header().Get("x-icecast-auth-message"), "Invalid credentials")
	}

	// Verify the service continues to handle requests (non-stream_auth still works).
	rr2 := doPost(t, h, map[string]string{
		"action": "listener_add",
		"user":   "bob",
	})
	if rr2.Code != http.StatusOK {
		t.Errorf("service stopped responding after Keycloak failure: code = %d", rr2.Code)
	}
}

// F-26 extended: correct role among multiple roles
func TestFeature_StreamAuth_MultipleRoles_HasRequired_Returns200(t *testing.T) {
	mk := newMockKeycloak(t, mockKeycloakConfig{
		validUser: testValidUser,
		validPass: testValidPass,
		clientID:  testClientID,
		roles:     []string{"admin", testRole, "listener"},
	})
	h := buildHandler(t, mk.URL())

	rr := doPost(t, h, map[string]string{
		"action": "stream_auth",
		"user":   testValidUser,
		"pass":   testValidPass,
	})

	if rr.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rr.Code)
	}
}

// Health endpoint
func TestFeature_HealthEndpoint_Returns200(t *testing.T) {
	h := buildHandler(t, "http://unused")
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rr.Code)
	}
}

// POST /auth without credentials returns 401, not a crash.
func TestFeature_StreamAuth_EmptyCredentials_Returns401(t *testing.T) {
	mk := newMockKeycloak(t, mockKeycloakConfig{})
	h := buildHandler(t, mk.URL())

	rr := doPost(t, h, map[string]string{
		"action": "stream_auth",
		"user":   "",
		"pass":   "",
	})

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", rr.Code)
	}
	if rr.Header().Get("x-icecast-auth-result") != "failed" {
		t.Errorf("x-icecast-auth-result = %q, want %q", rr.Header().Get("x-icecast-auth-result"), "failed")
	}
	if rr.Header().Get("x-icecast-auth-message") != "Missing username or password" {
		t.Errorf("x-icecast-auth-message = %q, want %q", rr.Header().Get("x-icecast-auth-message"), "Missing username or password")
	}
}

func TestFeature_StreamAuth_LegacyMode_ReturnsLegacyHeader(t *testing.T) {
	mk := newMockKeycloak(t, mockKeycloakConfig{
		validUser: testValidUser,
		validPass: testValidPass,
		clientID:  testClientID,
		roles:     []string{testRole},
	})
	kc := keycloak.NewHTTPClient(mk.URL(), testRealm, testClientID, "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	authH := handler.NewAuthHandler(kc, testClientID, testRole, "legacy", observability.NoopRecorder{}, logger)
	mux := http.NewServeMux()
	mux.Handle("/auth", authH)

	rr := doPost(t, mux, map[string]string{
		"action": "stream_auth",
		"user":   testValidUser,
		"pass":   testValidPass,
	})

	if rr.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rr.Code)
	}
	if rr.Header().Get("icecast-auth-user") != "1" {
		t.Error("missing icecast-auth-user: 1 header")
	}
	if rr.Header().Get("x-icecast-auth-result") != "" {
		t.Error("unexpected x-icecast-auth-result header in legacy mode")
	}
}
