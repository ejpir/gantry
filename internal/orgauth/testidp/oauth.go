package testidp

// This file implements the disposable OAuth authorization server used by the
// real-VM custody battery. Unlike a response stub, it owns authorization codes,
// validates a public client's redirect and S256 PKCE proof, rotates refresh
// tokens, and binds access tokens to the MCP resource. Test-only control routes
// expose decisions and counters, never issued credentials.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/oauth2"
)

const (
	OAuthClientID    = "e2e-public-client"
	OAuthScope       = "mcp offline_access"
	GitHubClientID   = "Iv1.b507a08c87ecfe98"
	GitHubScope      = "repo read:org gist"
	GitHubAccess     = "e2e-github-access-canary"
	DeviceCode       = "e2e-private-device-canary"
	UserCode         = "E2E-TEST"
	MCPAccessPrefix  = "e2e-mcp-access-canary-"
	MCPRefreshPrefix = "e2e-mcp-refresh-canary-"
	ErrorCanary      = "e2e-token-error-body-canary"
)

const maxOAuthRequestBytes = 1 << 20

type oauthGrant struct {
	redirect, challenge, resource string
}

// OAuthObservations reports protocol decisions without exposing codes, PKCE
// verifiers, or access/refresh tokens.
type OAuthObservations struct {
	Pending      int      `json:"pending"`
	GitHubIssues int      `json:"github_issues"`
	Exchanges    int      `json:"exchanges"`
	Refreshes    int      `json:"refreshes"`
	Revoked      bool     `json:"revoked"`
	Rejections   int      `json:"rejections"`
	MCPPhases    []int    `json:"mcp_phases"`
	Errors       []string `json:"errors"`
}

// OAuthProvider is a loopback-only, disposable OAuth 2.0 authorization server
// and protected MCP resource. It automatically approves a synthetic user after
// browser navigation. It is protocol-real test infrastructure, not a production
// IdP or a vendor UI/MFA emulator.
type OAuthProvider struct {
	Server *httptest.Server

	mu            sync.Mutex
	approved      bool
	pending       int
	githubIssues  int
	codes         map[string]oauthGrant
	accessTokens  map[string]int
	refreshTokens map[string]int
	exchanges     int
	refreshes     int
	revoked       bool
	rejections    int
	mcpPhases     []int
	errors        []string
}

// NewOAuth starts a minimal authorization server on IPv4 loopback. HTTP is
// intentional: OAuth native-app loopback fixtures are the sole non-HTTPS
// endpoint class accepted by Gantry's host-owned provider configuration.
func NewOAuth() *OAuthProvider {
	provider := &OAuthProvider{
		codes: make(map[string]oauthGrant), accessTokens: make(map[string]int),
		refreshTokens: make(map[string]int),
	}
	provider.Server = httptest.NewUnstartedServer(provider)
	provider.Server.Config.ErrorLog = log.New(io.Discard, "", 0)
	provider.Server.Start()
	return provider
}

// Close stops the disposable provider.
func (provider *OAuthProvider) Close() {
	if provider != nil && provider.Server != nil {
		provider.Server.Close()
	}
}

// URL returns the provider's loopback origin.
func (provider *OAuthProvider) URL() string { return provider.Server.URL }

// Observations returns a race-safe copy of non-secret protocol counters.
func (provider *OAuthProvider) Observations() OAuthObservations {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.observationsLocked()
}

// Revoke makes the current refresh token and MCP access token unusable.
func (provider *OAuthProvider) Revoke() {
	provider.mu.Lock()
	provider.revoked = true
	provider.mu.Unlock()
}

func (provider *OAuthProvider) observationsLocked() OAuthObservations {
	return OAuthObservations{
		Pending: provider.pending, GitHubIssues: provider.githubIssues,
		Exchanges: provider.exchanges, Refreshes: provider.refreshes,
		Revoked: provider.revoked, Rejections: provider.rejections,
		MCPPhases: append([]int{}, provider.mcpPhases...), Errors: append([]string{}, provider.errors...),
	}
}

func (provider *OAuthProvider) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	writer.Header().Set("Cache-Control", "no-store")

	switch request.URL.Path {
	case "/.well-known/oauth-authorization-server":
		provider.metadata(writer, request)
	case "/authorize":
		provider.authorizeOAuth(writer, request)
	case "/token":
		provider.token(writer, request)
	case "/github/device":
		provider.githubDevice(writer, request)
	case "/github/token":
		provider.githubToken(writer, request)
	case "/device/verify":
		provider.deviceVerify(writer, request)
	case "/mcp":
		provider.mcp(writer, request)
	case "/test/observations":
		if request.Method != http.MethodGet {
			provider.reject(writer, http.StatusMethodNotAllowed, "observations method")
			return
		}
		provider.reply(writer, http.StatusOK, provider.observationsLocked())
	case "/test/revoke":
		if request.Method != http.MethodPost {
			provider.reject(writer, http.StatusMethodNotAllowed, "revoke method")
			return
		}
		provider.revoked = true
		provider.reply(writer, http.StatusOK, map[string]bool{"revoked": true})
	default:
		http.NotFound(writer, request)
	}
}

func (provider *OAuthProvider) metadata(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		provider.reject(writer, http.StatusMethodNotAllowed, "metadata method")
		return
	}
	provider.reply(writer, http.StatusOK, map[string]any{
		"issuer":                                provider.URL(),
		"authorization_endpoint":                provider.URL() + "/authorize",
		"token_endpoint":                        provider.URL() + "/token",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      strings.Fields(OAuthScope),
	})
}

func (provider *OAuthProvider) authorizeOAuth(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		provider.reject(writer, http.StatusMethodNotAllowed, "authorize method")
		return
	}
	query := request.URL.Query()
	redirect, err := url.Parse(single(query, "redirect_uri"))
	port, portErr := strconv.Atoi(redirect.Port())
	if err != nil || portErr != nil || redirect.Scheme != "http" || redirect.Hostname() != "127.0.0.1" || redirect.User != nil || redirect.Path != "/callback" || redirect.RawQuery != "" || redirect.Fragment != "" || port < 32768 || port > 65535 ||
		single(query, "client_id") != OAuthClientID || single(query, "scope") != OAuthScope || single(query, "resource") != provider.URL()+"/mcp" || single(query, "response_type") != "code" || single(query, "code_challenge_method") != "S256" || single(query, "state") == "" || len(single(query, "code_challenge")) != 43 {
		provider.reject(writer, http.StatusBadRequest, "invalid authorization request")
		return
	}
	code := oauth2.GenerateVerifier()
	provider.codes[code] = oauthGrant{redirect: redirect.String(), challenge: single(query, "code_challenge"), resource: single(query, "resource")}
	redirect.RawQuery = url.Values{"code": {code}, "state": {single(query, "state")}}.Encode()
	http.Redirect(writer, request, redirect.String(), http.StatusFound)
}

func (provider *OAuthProvider) token(writer http.ResponseWriter, request *http.Request) {
	form, ok := provider.form(writer, request)
	if !ok {
		return
	}
	switch single(form, "grant_type") {
	case "authorization_code":
		code := single(form, "code")
		grant, found := provider.codes[code]
		delete(provider.codes, code)
		verifier := single(form, "code_verifier")
		hash := sha256.Sum256([]byte(verifier))
		if !found || single(form, "client_id") != OAuthClientID || single(form, "resource") != provider.URL()+"/mcp" || len(verifier) < 43 || base64.RawURLEncoding.EncodeToString(hash[:]) != grant.challenge || single(form, "redirect_uri") != grant.redirect || single(form, "resource") != grant.resource {
			provider.rejectGrant(writer, "authorization code/PKCE binding")
			return
		}
		provider.exchanges++
		provider.reply(writer, http.StatusOK, provider.tokens(0, 1))
	case "refresh_token":
		refreshToken := single(form, "refresh_token")
		_, issued := provider.refreshTokens[refreshToken]
		delete(provider.refreshTokens, refreshToken) // rotation makes every attempt single-use
		if single(form, "client_id") != OAuthClientID || single(form, "resource") != provider.URL()+"/mcp" || !issued {
			provider.rejectGrant(writer, "refresh rotation binding")
			return
		}
		if provider.revoked {
			provider.rejections++
			provider.reply(writer, http.StatusOK, map[string]string{"error": "invalid_grant", "error_description": ErrorCanary})
			return
		}
		for accessToken := range provider.accessTokens {
			delete(provider.accessTokens, accessToken)
		}
		provider.refreshes++
		provider.reply(writer, http.StatusOK, provider.tokens(provider.refreshes, 3600))
	default:
		provider.rejectGrant(writer, "unsupported grant")
	}
}

func (provider *OAuthProvider) tokens(phase, expires int) map[string]any {
	accessToken := MCPAccessPrefix + strconv.Itoa(phase)
	refreshToken := MCPRefreshPrefix + strconv.Itoa(phase)
	provider.accessTokens[accessToken] = phase
	provider.refreshTokens[refreshToken] = phase
	return map[string]any{
		"access_token": accessToken, "refresh_token": refreshToken,
		"token_type": "Bearer", "expires_in": expires,
	}
}

func (provider *OAuthProvider) githubDevice(writer http.ResponseWriter, request *http.Request) {
	form, ok := provider.form(writer, request)
	if !ok {
		return
	}
	if single(form, "client_id") != GitHubClientID || single(form, "scope") != GitHubScope {
		provider.rejectGrant(writer, "GitHub device registration")
		return
	}
	provider.reply(writer, http.StatusOK, map[string]any{
		"device_code": DeviceCode, "user_code": UserCode,
		"verification_uri": provider.URL() + "/device/verify", "interval": 1, "expires_in": 120,
	})
}

func (provider *OAuthProvider) githubToken(writer http.ResponseWriter, request *http.Request) {
	form, ok := provider.form(writer, request)
	if !ok {
		return
	}
	if single(form, "client_id") != GitHubClientID || single(form, "grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || single(form, "device_code") != DeviceCode {
		provider.rejectGrant(writer, "GitHub device grant")
		return
	}
	if !provider.approved {
		provider.pending++
		provider.reply(writer, http.StatusOK, map[string]string{"error": "authorization_pending"})
		return
	}
	provider.githubIssues++
	provider.reply(writer, http.StatusOK, map[string]string{"access_token": GitHubAccess, "token_type": "bearer"})
}

func (provider *OAuthProvider) deviceVerify(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || single(request.URL.Query(), "user_code") != UserCode {
		provider.reject(writer, http.StatusBadRequest, "device approval")
		return
	}
	provider.approved = true
	provider.reply(writer, http.StatusOK, map[string]bool{"approved": true})
}

func (provider *OAuthProvider) mcp(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodDelete {
		provider.reply(writer, http.StatusOK, map[string]bool{"closed": true})
		return
	}
	if request.Method != http.MethodPost {
		provider.reject(writer, http.StatusMethodNotAllowed, "MCP method")
		return
	}
	authorization := request.Header.Get("Authorization")
	accessToken, hasBearer := strings.CutPrefix(authorization, "Bearer ")
	phase, issued := provider.accessTokens[accessToken]
	if provider.revoked || !hasBearer || !issued {
		provider.reject(writer, http.StatusBadRequest, "MCP credential binding")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxOAuthRequestBytes)
	var message struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	decoder := json.NewDecoder(request.Body)
	if decoder.Decode(&message) != nil {
		provider.reject(writer, http.StatusBadRequest, "MCP request JSON")
		return
	}
	if len(message.ID) == 0 {
		writer.WriteHeader(http.StatusAccepted)
		return
	}
	var result any
	switch message.Method {
	case "initialize":
		result = map[string]any{
			"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]string{"name": "oauth-e2e", "version": "1"},
		}
	case "tools/list":
		result = map[string]any{"tools": []map[string]any{{"name": "probe", "description": "Check custody delivery", "inputSchema": map[string]string{"type": "object"}}}}
	case "tools/call":
		if message.Params.Name != "probe" {
			provider.reject(writer, http.StatusBadRequest, "MCP tool binding")
			return
		}
		provider.mcpPhases = append(provider.mcpPhases, phase)
		result = map[string]any{"content": []map[string]string{{"type": "text", "text": fmt.Sprintf("phase:%d auth=%s", phase, authorization)}}}
	default:
		result = map[string]any{}
	}
	provider.reply(writer, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": message.ID, "result": result})
}

func (provider *OAuthProvider) form(writer http.ResponseWriter, request *http.Request) (url.Values, bool) {
	if request.Method != http.MethodPost {
		provider.reject(writer, http.StatusMethodNotAllowed, "grant method")
		return nil, false
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || request.URL.RawQuery != "" {
		provider.reject(writer, http.StatusBadRequest, "grant encoding")
		return nil, false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 16<<10)
	if request.ParseForm() != nil {
		provider.reject(writer, http.StatusBadRequest, "grant form")
		return nil, false
	}
	return request.PostForm, true
}

func single(values url.Values, key string) string {
	if len(values[key]) != 1 {
		return ""
	}
	return values[key][0]
}

func (provider *OAuthProvider) rejectGrant(writer http.ResponseWriter, reason string) {
	provider.errors = append(provider.errors, reason)
	provider.reply(writer, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
}

func (provider *OAuthProvider) reject(writer http.ResponseWriter, status int, reason string) {
	provider.errors = append(provider.errors, reason)
	provider.reply(writer, status, map[string]string{"error": "invalid_request"})
}

func (*OAuthProvider) reply(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}
