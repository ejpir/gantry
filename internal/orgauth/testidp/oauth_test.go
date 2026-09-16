package testidp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func oauthRequest(t *testing.T, client *http.Client, method, rawURL string, body io.Reader, contentType string) (*http.Response, map[string]any) {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), method, rawURL, body)
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var payload map[string]any
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 0 && strings.Contains(response.Header.Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatalf("decode %s: %v (%q)", rawURL, err, raw)
		}
	}
	return response, payload
}

func oauthPostForm(t *testing.T, provider *OAuthProvider, path string, values url.Values) (*http.Response, map[string]any) {
	t.Helper()
	return oauthRequest(t, provider.Server.Client(), http.MethodPost, provider.URL()+path, strings.NewReader(values.Encode()), "application/x-www-form-urlencoded")
}

func authorizeGrant(t *testing.T, provider *OAuthProvider, verifier, resource string) url.Values {
	t.Helper()
	hash := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"client_id":             {OAuthClientID},
		"scope":                 {OAuthScope},
		"resource":              {resource},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(hash[:])},
		"state":                 {strings.Repeat("s", 32)},
		"redirect_uri":          {"http://127.0.0.1:53693/callback"},
	}
	client := *provider.Server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, _ := oauthRequest(t, &client, http.MethodGet, provider.URL()+"/authorize?"+query.Encode(), nil, "")
	if response.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", response.StatusCode)
	}
	callback, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if callback.Scheme+"://"+callback.Host+callback.Path != query.Get("redirect_uri") || callback.Query().Get("state") != query.Get("state") || callback.Query().Get("code") == "" {
		t.Fatalf("invalid callback: %s", callback)
	}
	return url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {OAuthClientID},
		"resource":      {resource},
		"redirect_uri":  {query.Get("redirect_uri")},
		"code":          {callback.Query().Get("code")},
		"code_verifier": {verifier},
	}
}

func TestOAuthProviderPublicClientPKCERefreshAndMCP(t *testing.T) {
	provider := NewOAuth()
	defer provider.Close()

	response, metadata := oauthRequest(t, provider.Server.Client(), http.MethodGet, provider.URL()+"/.well-known/oauth-authorization-server", nil, "")
	if response.StatusCode != http.StatusOK || metadata["issuer"] != provider.URL() || metadata["token_endpoint"] != provider.URL()+"/token" {
		t.Fatalf("invalid authorization-server metadata: %#v", metadata)
	}

	verifier := oauth2.GenerateVerifier()
	grant := authorizeGrant(t, provider, verifier, provider.URL()+"/mcp")
	response, initial := oauthPostForm(t, provider, "/token", grant)
	if response.StatusCode != http.StatusOK || initial["access_token"] != MCPAccessPrefix+"0" || initial["refresh_token"] != MCPRefreshPrefix+"0" {
		t.Fatalf("initial token response: status=%d payload=%#v", response.StatusCode, initial)
	}
	refresh := url.Values{
		"grant_type": {"refresh_token"}, "client_id": {OAuthClientID},
		"resource": {provider.URL() + "/mcp"}, "refresh_token": {MCPRefreshPrefix + "0"},
	}
	response, rotated := oauthPostForm(t, provider, "/token", refresh)
	if response.StatusCode != http.StatusOK || rotated["access_token"] != MCPAccessPrefix+"1" || rotated["refresh_token"] != MCPRefreshPrefix+"1" {
		t.Fatalf("rotated token response: status=%d payload=%#v", response.StatusCode, rotated)
	}

	message := []byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"probe"}}`)
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, provider.URL()+"/mcp", bytes.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+MCPAccessPrefix+"1")
	response, err = provider.Server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Contains(raw, []byte("phase:1 auth=Bearer "+MCPAccessPrefix+"1")) {
		t.Fatalf("MCP response: status=%d body=%q error=%v", response.StatusCode, raw, err)
	}

	observations := provider.Observations()
	if observations.Exchanges != 1 || observations.Refreshes != 1 || len(observations.MCPPhases) != 1 || observations.MCPPhases[0] != 1 || len(observations.Errors) != 0 {
		t.Fatalf("unexpected observations: %+v", observations)
	}
	raw, err = json.Marshal(observations)
	if err != nil || bytes.Contains(raw, []byte(MCPAccessPrefix)) || bytes.Contains(raw, []byte(MCPRefreshPrefix)) || bytes.Contains(raw, []byte(verifier)) {
		t.Fatalf("observations leaked protocol secrets: %q", raw)
	}

	provider.Revoke()
	refresh.Set("refresh_token", MCPRefreshPrefix+"1")
	response, denied := oauthPostForm(t, provider, "/token", refresh)
	if response.StatusCode != http.StatusOK || denied["error"] != "invalid_grant" || provider.Observations().Rejections != 1 {
		t.Fatalf("revoked refresh response: status=%d payload=%#v", response.StatusCode, denied)
	}
}

func TestOAuthProviderDeviceAuthorization(t *testing.T) {
	provider := NewOAuth()
	defer provider.Close()

	response, device := oauthPostForm(t, provider, "/github/device", url.Values{"client_id": {GitHubClientID}, "scope": {GitHubScope}})
	if response.StatusCode != http.StatusOK || device["device_code"] != DeviceCode || device["user_code"] != UserCode {
		t.Fatalf("device response: status=%d payload=%#v", response.StatusCode, device)
	}
	grant := url.Values{
		"client_id": {GitHubClientID}, "device_code": {DeviceCode},
		"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"},
	}
	_, pending := oauthPostForm(t, provider, "/github/token", grant)
	if pending["error"] != "authorization_pending" {
		t.Fatalf("device poll was not pending: %#v", pending)
	}
	response, _ = oauthRequest(t, provider.Server.Client(), http.MethodGet, provider.URL()+"/device/verify?user_code="+UserCode, nil, "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("device approval status = %d", response.StatusCode)
	}
	_, token := oauthPostForm(t, provider, "/github/token", grant)
	if token["access_token"] != GitHubAccess {
		t.Fatalf("device token response: %#v", token)
	}
	observations := provider.Observations()
	if observations.Pending != 1 || observations.GitHubIssues != 1 || len(observations.Errors) != 0 {
		t.Fatalf("unexpected observations: %+v", observations)
	}
}

func TestOAuthProviderRejectsWrongBindingsAndSingleUseCode(t *testing.T) {
	provider := NewOAuth()
	defer provider.Close()

	grant := authorizeGrant(t, provider, oauth2.GenerateVerifier(), provider.URL()+"/mcp")
	grant.Set("resource", "https://wrong.example/mcp")
	response, _ := oauthPostForm(t, provider, "/token", grant)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong resource status = %d", response.StatusCode)
	}
	grant.Set("resource", provider.URL()+"/mcp")
	response, _ = oauthPostForm(t, provider, "/token", grant)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("reused code status = %d", response.StatusCode)
	}
	if len(provider.Observations().Errors) != 2 {
		t.Fatalf("rejections not observed: %+v", provider.Observations())
	}
}
