package sandbox

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/ejpir/gantry/internal/oauthprovider"
	"github.com/ejpir/gantry/internal/sandbox/credhelper"
	"github.com/ejpir/gantry/internal/sandbox/credhelper/credproto"
	"github.com/ejpir/gantry/internal/sandbox/oauthbridge"
	"github.com/ejpir/gantry/internal/secret"
)

func callbackPath(redirect string) string {
	u, err := url.Parse(redirect)
	if err != nil {
		return ""
	}
	if u.EscapedPath() == "" {
		return "/"
	}
	return u.EscapedPath()
}

func (cm *custodyManager) specFor(name string) (oauthprovider.Spec, bool) {
	return oauthprovider.Lookup(cm.br.cfg.OAuthProviders, name)
}

// login accepts only a registration name. No token endpoint, client ID,
// audience, verifier or credential binding can be supplied by the guest.
func (cm *custodyManager) login(name string) credproto.Response {
	spec, ok := cm.specFor(name)
	if !ok {
		return credproto.Response{Error: "custody: unknown provider; configure it on the host with -oauth-provider (built in: claude, codex, github)"}
	}
	if spec.Grant == oauthprovider.DeviceCode {
		return cm.loginDevice(spec)
	}
	authURL, state, verifier, redirect, err := spec.Authorization()
	if err != nil {
		return credproto.Response{Error: "custody: could not prepare authorization request"}
	}
	resp := cm.beginCode(spec, credproto.Request{
		Provider: spec.Provider, State: state, Verifier: verifier,
		ClientID: spec.ClientID, RedirectURI: redirect,
	})
	if resp.Error == "" {
		resp.AuthorizeURL, resp.State = authURL, state
	}
	return resp
}

func (cm *custodyManager) loginDevice(spec oauthprovider.Spec) credproto.Response {
	state, err := oauthprovider.RandomState()
	if err != nil {
		return credproto.Response{Error: "custody: could not generate login state"}
	}
	flow := &custodyFlow{state: state, provider: spec.Provider, spec: spec, clientID: spec.ClientID, claimed: true, done: make(chan struct{})}
	// Reserve a slot before contacting the provider. Device polling has its
	// own bounded context, so it does not use the browser-callback expiry.
	if err := cm.registerFlow(flow); err != nil {
		return credproto.Response{Error: err.Error()}
	}
	// Leave enough time for the reply within the credential socket's 5s
	// deadline; device authorization initiation is not the long-running poll.
	ctx, cancel := context.WithTimeout(context.Background(), custodyStatusWait)
	device, err := oauthbridge.BeginDeviceAuthorization(ctx, spec)
	cancel()
	if err != nil {
		cm.finish(flow, err)
		return credproto.Response{Error: err.Error()}
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), custodyFlowLifetime)
		defer cancel()
		tok, err := oauthbridge.PollDeviceAuthorization(ctx, spec, device)
		if err != nil {
			cm.finish(flow, err)
			return
		}
		cm.installTokens(flow, tok)
	}()
	cm.br.auditf("custody: device login for %s — awaiting browser authorization", spec.Provider)
	return credproto.Response{State: state, AuthorizeURL: device.VerificationURI, UserCode: device.UserCode}
}

// deliverAccessToken keeps generic custody separate from CLI auth-file shapes.
// MCP-only and credential-helper providers never write tokens into guest files.
func (cm *custodyManager) deliverAccessToken(name string, tok oauthbridge.TokenResponse) error {
	spec, ok := cm.specFor(name)
	if !ok {
		return fmt.Errorf("unknown custody registration")
	}
	if spec.GuestAuthFile == "" {
		return nil
	}
	return cm.pushAuthFile(name, tok)
}

// resolveCustodyCredential runs behind credhelper's egress gate. Explicit
// secrets take precedence; configured exact host bindings precede GitHub's
// built-in binding. There is no guest operation to create or change bindings.
func (br *broker) resolveCustodyCredential(host string) (string, secret.Value, credhelper.Resolution) {
	if br.custodyRegistry == nil {
		return "", "", credhelper.NoBinding
	}
	specs := oauthprovider.Clone(br.cfg.OAuthProviders)
	github, _ := oauthprovider.Builtin("github")
	specs = append(specs, github)
	for _, p := range specs {
		for _, binding := range p.CredentialHosts {
			if !strings.EqualFold(strings.TrimSuffix(binding, "."), strings.TrimSuffix(host, ".")) {
				continue
			}
			token, ok := br.custodyRegistry.AccessToken(p.Provider)
			if !ok {
				return "custody:" + p.Provider, "", credhelper.NoValue
			}
			return "custody:" + p.Provider, secret.Value(token), credhelper.OK
		}
	}
	return "", "", credhelper.NoBinding
}
