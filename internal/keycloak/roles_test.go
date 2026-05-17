package keycloak_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"simliveradio.org/icecast-keycloak-auth/internal/keycloak"
)

func makeTestJWT(clientID string, roles []string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	payload := map[string]interface{}{
		"sub": "user-123",
		"resource_access": map[string]interface{}{
			clientID: map[string]interface{}{
				"roles": roles,
			},
		},
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadJSON)

	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	return header + "." + payloadEnc + "." + sig
}

func makeEmptyResourceAccessJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-123"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	return header + "." + payload + "." + sig
}

func TestHasClientRole_RolePresent(t *testing.T) {
	token := makeTestJWT("myclient", []string{"streamer", "listener"})

	ok, err := keycloak.HasClientRole(token, "myclient", "streamer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected role to be present")
	}
}

func TestHasClientRole_RoleMissing(t *testing.T) {
	token := makeTestJWT("myclient", []string{"listener"})

	ok, err := keycloak.HasClientRole(token, "myclient", "streamer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected role to be absent")
	}
}

func TestHasClientRole_EmptyRoles(t *testing.T) {
	token := makeTestJWT("myclient", []string{})

	ok, err := keycloak.HasClientRole(token, "myclient", "streamer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected role to be absent with empty roles list")
	}
}

func TestHasClientRole_ClientNotInResourceAccess(t *testing.T) {
	token := makeTestJWT("other-client", []string{"streamer"})

	ok, err := keycloak.HasClientRole(token, "myclient", "streamer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected false when client is not in resource_access")
	}
}

func TestHasClientRole_NoResourceAccessClaim(t *testing.T) {
	token := makeEmptyResourceAccessJWT()

	ok, err := keycloak.HasClientRole(token, "myclient", "streamer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected false when resource_access claim is absent")
	}
}

func TestHasClientRole_InvalidJWTTwoParts(t *testing.T) {
	_, err := keycloak.HasClientRole("header.payload", "myclient", "streamer")
	if err == nil {
		t.Fatal("expected error for 2-part JWT")
	}
}

func TestHasClientRole_InvalidJWTOnePart(t *testing.T) {
	_, err := keycloak.HasClientRole("onlyone", "myclient", "streamer")
	if err == nil {
		t.Fatal("expected error for 1-part token")
	}
}

func TestHasClientRole_InvalidBase64Payload(t *testing.T) {
	token := "header.!!!invalid base64!!!.sig"
	_, err := keycloak.HasClientRole(token, "myclient", "streamer")
	if err == nil {
		t.Fatal("expected error for invalid base64 payload")
	}
	if !strings.Contains(err.Error(), "base64 decode") {
		t.Errorf("error should mention base64: %v", err)
	}
}

func TestHasClientRole_InvalidJSONPayload(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`not json`))
	token := header + "." + payload + ".sig"

	_, err := keycloak.HasClientRole(token, "myclient", "streamer")
	if err == nil {
		t.Fatal("expected error for invalid JSON payload")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("error should mention unmarshal: %v", err)
	}
}

func TestHasClientRole_MultipleRoles_ExactMatch(t *testing.T) {
	token := makeTestJWT("myclient", []string{"admin", "streamer", "listener"})

	ok, err := keycloak.HasClientRole(token, "myclient", "streamer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected streamer role to be found among multiple roles")
	}
}

func TestHasClientRole_NoPartialMatch(t *testing.T) {
	token := makeTestJWT("myclient", []string{"super-streamer"})

	ok, err := keycloak.HasClientRole(token, "myclient", "streamer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected no partial role match")
	}
}
