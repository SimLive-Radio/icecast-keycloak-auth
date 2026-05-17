package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client interface {
	GetToken(ctx context.Context, username, password string) (string, error)
}

type HTTPClient struct {
	baseURL      string
	realm        string
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

func NewHTTPClient(baseURL, realm, clientID, clientSecret string) *HTTPClient {
	return &HTTPClient{
		baseURL:      strings.TrimRight(baseURL, "/"),
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
}

func (c *HTTPClient) GetToken(ctx context.Context, username, password string) (token string, err error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, c.realm)

	body := url.Values{}
	body.Set("grant_type", "password")
	body.Set("client_id", c.clientID)
	body.Set("username", username)
	body.Set("password", password)
	body.Set("scope", "openid")
	if c.clientSecret != "" {
		body.Set("client_secret", c.clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode keycloak response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if tr.Error != "" {
			return "", fmt.Errorf("keycloak returned %d: %s", resp.StatusCode, tr.Error)
		}
		return "", fmt.Errorf("keycloak returned %d", resp.StatusCode)
	}

	if tr.AccessToken == "" {
		return "", fmt.Errorf("keycloak returned empty access token")
	}

	return tr.AccessToken, nil
}
