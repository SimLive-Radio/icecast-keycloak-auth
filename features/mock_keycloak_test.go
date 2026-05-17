package features_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockKeycloakConfig struct {
	// validUser/validPass are the credentials that succeed.
	validUser string
	validPass string
	// roles are placed in resource_access[clientID].roles in the issued JWT.
	clientID string
	roles    []string
}

type mockKeycloak struct {
	srv *httptest.Server
	cfg mockKeycloakConfig
}

func newMockKeycloak(t *testing.T, cfg mockKeycloakConfig) *mockKeycloak {
	t.Helper()
	mk := &mockKeycloak{cfg: cfg}
	mk.srv = httptest.NewServer(http.HandlerFunc(mk.handler))
	t.Cleanup(mk.srv.Close)
	return mk
}

func (mk *mockKeycloak) URL() string {
	return mk.srv.URL
}

func (mk *mockKeycloak) handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user := r.FormValue("username")
	pass := r.FormValue("password")
	w.Header().Set("Content-Type", "application/json")

	if user != mk.cfg.validUser || pass != mk.cfg.validPass {
		w.WriteHeader(http.StatusUnauthorized)
		if err := json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "Invalid user credentials",
		}); err != nil {
			http.Error(w, "encode response", http.StatusInternalServerError)
		}
		return
	}

	token := buildJWT(mk.cfg.clientID, mk.cfg.roles)
	if err := json.NewEncoder(w).Encode(map[string]string{"access_token": token}); err != nil {
		http.Error(w, "encode response", http.StatusInternalServerError)
	}
}

func buildJWT(clientID string, roles []string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	claims := map[string]interface{}{
		"sub": "test-user",
		"resource_access": map[string]interface{}{
			clientID: map[string]interface{}{
				"roles": roles,
			},
		},
	}
	payloadJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))

	return header + "." + payload + "." + sig
}
