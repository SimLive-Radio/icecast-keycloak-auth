package keycloak

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type jwtClaims struct {
	ResourceAccess map[string]clientAccess `json:"resource_access"`
}

type clientAccess struct {
	Roles []string `json:"roles"`
}

// HasClientRole checks whether the JWT access token grants the named role
// for the given client. The token is not signature-verified because it was
// obtained directly from Keycloak over a trusted server-to-server call.
func HasClientRole(tokenString, clientID, role string) (bool, error) {
	claims, err := parseJWTPayload(tokenString)
	if err != nil {
		return false, fmt.Errorf("parse token: %w", err)
	}

	access, ok := claims.ResourceAccess[clientID]
	if !ok {
		return false, nil
	}

	for _, r := range access.Roles {
		if r == role {
			return true, nil
		}
	}

	return false, nil
}

func parseJWTPayload(tokenString string) (*jwtClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 parts separated by '.', got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("base64 decode payload: %w", err)
	}

	var claims jwtClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}

	return &claims, nil
}
