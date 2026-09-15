package sandbox

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/oauthprovider"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/credhelper"
	"github.com/ejpir/gantry/internal/sandbox/credhelper/credproto"
	"github.com/ejpir/gantry/internal/sandbox/oauthbridge"
	"github.com/ejpir/gantry/internal/sandbox/oauthtokens"
	"github.com/ejpir/gantry/internal/secret"
)

func genericCustody(t *testing.T, spec oauthprovider.Spec) *custodyManager {
	t.Helper()
	spec, err := oauthprovider.Normalize(spec)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	registry := oauthtokens.New()
	registry.AttachFile(t.TempDir())
	br := &broker{cfg: config.RunConfig{OAuthCustody: &enabled, OAuthProviders: []oauthprovider.Spec{spec}}, custodyRegistry: registry, secretStore: secret.NewStore(nil, nil), audit: &auditRing{}}
	cm := newCustodyManager(br, registry)
	cm.ensurePort = func(int) bool { return true }
	cm.pushAuthFile = func(string, oauthbridge.TokenResponse) error {
		t.Error("generic provider wrote guest auth file")
		return nil
	}
	t.Cleanup(func() { stopCustodyLoops(cm) })
	return cm
}

func stopCustodyLoops(cm *custodyManager) {
	cm.mu.Lock()
	loops := cm.loops
	cm.loops = map[string]*custodyRefreshLoop{}
	for _, loop := range loops {
		loop.cancel()
	}
	for _, flow := range cm.flows {
		if flow.timer != nil {
			flow.timer.Stop()
		}
	}
	cm.mu.Unlock()
	for _, loop := range loops {
		<-loop.done
	}
}

func TestGenericCustodyLoginRefreshMCPAndRestart(t *testing.T) {
	var refreshes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("client_id") != "host-client" || r.Form.Get("resource") != "https://mcp.example/mcp" {
			t.Error("host registration not used")
		}
		if r.Form.Get("grant_type") == "refresh_token" {
			refreshes.Add(1)
			if r.Form.Get("refresh_token") != "host-refresh" {
				t.Error("wrong refresh material")
			}
			_ = json.NewEncoder(w).Encode(oauthbridge.TokenResponse{AccessToken: "rotated-access", RefreshToken: "rotated-refresh", ExpiresIn: 3600})
			return
		}
		if r.Form.Get("code") != "browser-code" || len(r.Form.Get("code_verifier")) < 43 {
			t.Error("missing code/PKCE")
		}
		_ = json.NewEncoder(w).Encode(oauthbridge.TokenResponse{AccessToken: "host-access", RefreshToken: "host-refresh", ExpiresIn: 3600})
	}))
	defer srv.Close()
	cm := genericCustody(t, oauthprovider.Spec{Provider: "company-mcp", AuthorizeURL: "https://auth.example/authorize", TokenURL: srv.URL, ClientID: "host-client", Resource: "https://mcp.example/mcp"})
	resp := cm.handleOAuthOp(credproto.Request{Op: credproto.OpOAuthLogin, Provider: "company-mcp", ClientID: "guest-client", AuthorizeURL: "https://evil.example", RedirectURI: "http://evil.example", Verifier: "guest-proof"})
	if resp.Error != "" {
		t.Fatal(resp.Error)
	}
	auth, err := url.Parse(resp.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Host != "auth.example" || auth.Query().Get("client_id") != "host-client" || auth.Query().Get("resource") != "https://mcp.example/mcp" {
		t.Fatal("guest overrode host metadata")
	}
	cb, _ := url.Parse(auth.Query().Get("redirect_uri"))
	port, _ := loopbackPort(cb.String())
	cb.RawQuery = url.Values{"state": {resp.State}, "code": {"browser-code"}}.Encode()
	wrong := *cb
	wrong.Path = "/wrong"
	if cm.consumeCallback(port, &wrong) || cm.consumeCallback(port+1, cb) {
		t.Fatal("callback accepted for wrong target")
	}
	if st := cm.status(credproto.Request{Provider: "github", State: resp.State}); st.Error == "" {
		t.Fatal("cross-provider status accepted")
	}
	if !cm.consumeCallback(port, cb) {
		t.Fatal("callback not consumed")
	}
	if st := cm.status(credproto.Request{Provider: "company-mcp", State: resp.State}); !st.OK {
		t.Fatal(st.Error)
	}
	if cm.consumeCallback(port+1, cb) {
		t.Fatal("completed callback accepted on wrong port")
	}
	if name, _, res := cm.br.resolveCredential("mcp.example"); res != credhelper.NoBinding {
		t.Fatalf("MCP-only provider got a guest helper binding: %s", name)
	}

	cm.br.cfg.MCPRemotes = []string{"name=company,url=https://mcp.example/mcp,auth=custody:company-mcp"}
	d := daemonRuntime{cfg: cm.br.cfg, broker: cm.br}
	servers, err := d.resolveMCPServers()
	if err != nil {
		t.Fatal(err)
	}
	checkMCP := func(want string) {
		t.Helper()
		credential, err := servers[1].Credential()
		if err != nil {
			t.Fatal(err)
		}
		if credential.Headers["Authorization"] != "Bearer "+want {
			t.Fatal("MCP did not read live access token")
		}
		raw, _ := json.Marshal(credential)
		if strings.Contains(string(raw), "refresh") {
			t.Fatal("MCP received refresh token")
		}
	}
	checkMCP("host-access")
	set, _ := cm.registry.Get("company-mcp")
	set.Expiry = time.Now().Add(time.Second)
	if err := cm.registry.Put(set); err != nil {
		t.Fatal(err)
	}
	cm.startRefreshLoop(set.Provider)
	deadline := time.Now().Add(3 * time.Second)
	for {
		set, _ = cm.registry.Get(set.Provider)
		if set.AccessToken == "rotated-access" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("generic refresh did not run")
		}
		time.Sleep(time.Millisecond)
	}
	if count, rotated := refreshes.Load(), set.RefreshToken == "rotated-refresh"; count != 1 || !rotated {
		t.Fatalf("refresh requests = %d, rotated token captured = %t", count, rotated)
	}
	checkMCP("rotated-access")
	stopCustodyLoops(cm)
	// Restore through the actual disk schema rather than sharing memory.
	dir := t.TempDir()
	disk := oauthtokens.New()
	disk.AttachFile(dir)
	if err := disk.Put(set); err != nil {
		t.Fatal(err)
	}
	restored := oauthtokens.New()
	restored.AttachFile(dir)
	restarted := newCustodyManager(&broker{cfg: cm.br.cfg, custodyRegistry: restored, audit: cm.br.audit}, restored)
	restarted.pushAuthFile = cm.pushAuthFile
	t.Cleanup(func() { stopCustodyLoops(restarted) })
	restarted.restoreRestart()
	d.broker = restarted.br
	servers, err = d.resolveMCPServers()
	if err != nil {
		t.Fatal(err)
	}
	checkMCP("rotated-access")
	if err := restored.Delete(set.Provider); err != nil {
		t.Fatal(err)
	}
	if _, err := servers[1].Credential(); err == nil {
		t.Fatal("revoked MCP token was served")
	}
	for _, line := range cm.br.audit.tail() {
		for _, canary := range []string{"host-access", "host-refresh", "rotated-access", "rotated-refresh", "browser-code"} {
			if strings.Contains(line, canary) {
				t.Fatal("audit leaked OAuth material")
			}
		}
	}
}

func TestGitHubDeviceCustodyAndCredentialBinding(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("client_id") != "Iv1.b507a08c87ecfe98" {
			t.Error("wrong public GitHub client")
		}
		if r.URL.Path == "/device" {
			_ = json.NewEncoder(w).Encode(oauthbridge.DeviceAuthorization{DeviceCode: "private-device-code", UserCode: "ABCD-EFGH", VerificationURI: "https://github.com/login/device", ExpiresIn: 30, Interval: 1})
			return
		}
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || r.Form.Get("device_code") != "private-device-code" {
			t.Error("wrong device grant")
		}
		if polls.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(oauthbridge.TokenResponse{AccessToken: "github-access", TokenType: "bearer"}) // GitHub may issue no expiry or refresh token
	}))
	defer srv.Close()
	t.Setenv("GANTRY_OAUTH_DEVICE_URL_GITHUB", srv.URL+"/device")
	t.Setenv("GANTRY_OAUTH_TOKEN_URL_GITHUB", srv.URL+"/token")
	cm := genericCustody(t, oauthprovider.Spec{Provider: "unused", AuthorizeURL: "https://auth.example/authorize", TokenURL: srv.URL, ClientID: "unused"})
	cm.ensurePort = func(int) bool { t.Error("device login opened a callback listener"); return false }
	resp := cm.login("github")
	if resp.Error != "" {
		t.Fatal(resp.Error)
	}
	if resp.UserCode != "ABCD-EFGH" || resp.AuthorizeURL != "https://github.com/login/device" {
		t.Fatal("missing device instructions")
	}
	raw, _ := json.Marshal(resp)
	if strings.Contains(string(raw), "private-device-code") {
		t.Fatal("device token leaked to guest")
	}
	if st := cm.status(credproto.Request{Provider: "github", State: resp.State}); !st.OK {
		t.Fatal(st.Error)
	}
	broker := credhelper.New(cm.br.resolveCredential, func(host string) bool { return host == "github.com" }, cm.br.auditf)
	if got := broker.Decide(credproto.Request{Host: "github.com"}); got.Password != "github-access" || got.Username != credproto.Username {
		t.Fatal("GitHub helper did not deliver token")
	}
	if got := broker.Decide(credproto.Request{Host: "evil.example"}); got.Password != "" {
		t.Fatal("credential escaped binding/policy")
	}
	denied := credhelper.New(cm.br.resolveCredential, func(string) bool { return false }, nil)
	if got := denied.Decide(credproto.Request{Host: "github.com"}); got.Password != "" {
		t.Fatal("credential escaped egress policy")
	}
	cm.br.guestToolsReady.Store(true)
	env := strings.Join(cm.br.secretEnv(), "\n")
	if !strings.Contains(env, "GIT_CONFIG_COUNT=1") || strings.Contains(env, "github-access") {
		t.Fatal("helper not wired without ambient token")
	}
	set, _ := cm.registry.Get("github")
	set.Expiry = time.Now().Add(-time.Second)
	if err := cm.registry.Put(set); err != nil {
		t.Fatal(err)
	}
	if got := broker.Decide(credproto.Request{Host: "github.com"}); got.Password != "" {
		t.Fatal("expired credential was served")
	}
}

func TestCustomCustodyRejectsLegacyBeginAndChangedRegistration(t *testing.T) {
	cm := genericCustody(t, oauthprovider.Spec{Provider: "company", AuthorizeURL: "https://auth.example/authorize", TokenURL: "https://auth.example/token", ClientID: "public"})
	req := beginReq("state")
	req.Provider = "company"
	if resp := cm.begin(req); resp.Error == "" {
		t.Fatal("guest-defined custom registration accepted")
	}
	if resp := cm.login("unknown"); resp.Error == "" {
		t.Fatal("unconfigured provider accepted")
	}
	p, _ := cm.specFor("company")
	set := oauthtokens.TokenSet{Provider: p.Provider, AccessToken: "access", RefreshToken: "refresh", Registration: p.Fingerprint()}
	if err := cm.registry.Put(set); err != nil {
		t.Fatal(err)
	}
	cm.br.cfg.OAuthProviders[0].TokenURL = "https://changed.example/token"
	cm.restoreRestart()
	if _, held := cm.registry.Get(p.Provider); held {
		t.Fatal("tokens survived an endpoint rebind")
	}
}

func TestOAuthProviderFlagResolution(t *testing.T) {
	file := filepath.Join(t.TempDir(), "provider.json")
	if err := os.WriteFile(file, []byte(`{"name":"company","authorize_url":"https://auth.example/authorize","token_url":"https://auth.example/token","client_id":"client"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	options := config.DefaultRunOptions()
	options.OAuthCustody = true
	options.OAuthProviderFiles = []string{file}
	r := runResolver{options: options}
	if err := r.resolveSessionOptions(); err != nil {
		t.Fatal(err)
	}
	if len(r.cfg.OAuthProviders) != 1 || r.cfg.OAuthProviders[0].ClientID != "client" {
		t.Fatal("provider file not captured")
	}
	options.OAuthCustody = false
	r = runResolver{options: options}
	if err := r.resolveSessionOptions(); err == nil {
		t.Fatal("provider without custody accepted")
	}
}
