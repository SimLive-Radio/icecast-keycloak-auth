package keycloak_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"simliveradio.org/icecast-keycloak-auth/internal/keycloak"
)

func TestHTTPClient_GetToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.FormValue("grant_type") != "password" {
			t.Errorf("grant_type = %q", r.FormValue("grant_type"))
		}
		if r.FormValue("username") != "alice" {
			t.Errorf("username = %q", r.FormValue("username"))
		}
		// password must not appear in any log — just verify it arrived
		if r.FormValue("password") == "" {
			t.Error("password was empty")
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"access_token": "tok.payload.sig"}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	c := keycloak.NewHTTPClient(srv.URL, "realm", "client", "")
	token, err := c.GetToken(context.Background(), "alice", "secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "tok.payload.sig" {
		t.Errorf("token = %q", token)
	}
}

func TestHTTPClient_GetToken_WithClientSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.FormValue("client_secret") != "mysecret" {
			t.Errorf("client_secret = %q", r.FormValue("client_secret"))
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"access_token": "tok.payload.sig"}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	c := keycloak.NewHTTPClient(srv.URL, "realm", "client", "mysecret")
	_, err := c.GetToken(context.Background(), "alice", "secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHTTPClient_GetToken_WrongPassword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		if err := json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "Invalid user credentials",
		}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	c := keycloak.NewHTTPClient(srv.URL, "realm", "client", "")
	_, err := c.GetToken(context.Background(), "alice", "wrongpass")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention 401: %v", err)
	}
	// password must not appear in the error message
	if strings.Contains(err.Error(), "wrongpass") {
		t.Errorf("password must not appear in error: %v", err)
	}
}

func TestHTTPClient_GetToken_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
	}))
	defer srv.Close()

	c := keycloak.NewHTTPClient(srv.URL, "realm", "client", "")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.GetToken(ctx, "alice", "secret")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "keycloak request") {
		t.Errorf("error should mention keycloak request context: %v", err)
	}
}

func TestHTTPClient_GetToken_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte("not json")); err != nil {
			t.Fatalf("write response: %v", err)
		}
	}))
	defer srv.Close()

	c := keycloak.NewHTTPClient(srv.URL, "realm", "client", "")
	_, err := c.GetToken(context.Background(), "alice", "secret")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "decode keycloak response") {
		t.Errorf("error should mention decode: %v", err)
	}
}

func TestHTTPClient_GetToken_EmptyAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"access_token": ""})
	}))
	defer srv.Close()

	c := keycloak.NewHTTPClient(srv.URL, "realm", "client", "")
	_, err := c.GetToken(context.Background(), "alice", "secret")
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}

func TestHTTPClient_GetToken_ServerUnreachable(t *testing.T) {
	c := keycloak.NewHTTPClient("http://127.0.0.1:19999", "realm", "client", "")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := c.GetToken(ctx, "alice", "secret")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestHTTPClient_GetToken_URLContainsRealm(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"access_token": "tok.payload.sig"})
	}))
	defer srv.Close()

	c := keycloak.NewHTTPClient(srv.URL, "myrealm", "client", "")
	if _, err := c.GetToken(context.Background(), "alice", "secret"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "/realms/myrealm/protocol/openid-connect/token"
	if gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}
