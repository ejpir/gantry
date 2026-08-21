package sandbox

// OAuth custody (docs/credential-brokering.md workstream 3): with
// -oauth-custody the daemon completes guest-initiated OAuth logins
// host-side. The refresh token never enters the guest; the guest auth
// file carries the current access token plus a sentinel refresh token,
// and refreshLoop pushes fresh access tokens ahead of expiry.
//
// Flow: gantry-guest `oauth login <provider>` generates PKCE material and
// sends oauth.begin over the trusted vsock broker channel. The daemon
// registers the pending flow, opens the loopback callback listener, and
// the provider's browser redirect is consumed by the bridge's custody
// hook (never replayed into the guest). The daemon exchanges code+verifier
// at the provider's token endpoint, stores the set in oauthtokens (0600
// disk sync under the sandbox dir so a daemon restart keeps sessions),
// pushes the guest auth file, and the guest's oauth.status poll observes
// completion.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/credhelper/credproto"
	"github.com/ejpir/gantry/internal/sandbox/oauthbridge"
	"github.com/ejpir/gantry/internal/sandbox/oauthtokens"
)

const (
	// custodyRefreshLeeway is how far ahead of expiry the loop refreshes.
	custodyRefreshLeeway = 5 * time.Minute
	// custodyStatusWait bounds one oauth.status long-poll; the broker's
	// 5s connection deadline must not be hit, so stay under it.
	custodyStatusWait = 4 * time.Second
	custodyPushOp     = "oauth custody auth-file push"
	custodyPushLimit  = 4 << 10
)

// custodyFlow is one in-flight login, keyed by OAuth state.
type custodyFlow struct {
	provider    string
	verifier    string
	clientID    string
	redirectURI string
	done        chan struct{}
	err         error
}

// custodyManager owns pending flows, the token registry, and the refresh
// loops for one sandbox daemon.
type custodyManager struct {
	br       *broker
	registry *oauthtokens.Registry
	// pushAuthFile defaults to pushGuestAuthFile (internal exec into the
	// guest); tests substitute a fake.
	pushAuthFile func(provider string, tok oauthbridge.TokenResponse) error
	// ensurePort defaults to the bridge's callback-port listener; tests
	// substitute a no-op so no host port is bound.
	ensurePort func(port int) bool

	mu       sync.Mutex
	flows    map[string]*custodyFlow
	finished map[string]error         // state -> terminal result, kept for the status poll
	loops    map[string]chan struct{} // provider -> stop signal
}

func newCustodyManager(br *broker, registry *oauthtokens.Registry) *custodyManager {
	cm := &custodyManager{
		br:       br,
		registry: registry,
		flows:    map[string]*custodyFlow{},
		finished: map[string]error{},
		loops:    map[string]chan struct{}{},
	}
	cm.pushAuthFile = cm.pushGuestAuthFile
	cm.ensurePort = br.oauth.EnsureCallbackPort
	return cm
}

// handleOAuthOp dispatches oauth.begin / oauth.status from the guest.
func (cm *custodyManager) handleOAuthOp(req credproto.Request) credproto.Response {
	switch req.Op {
	case credproto.OpOAuthBegin:
		return cm.begin(req)
	case credproto.OpOAuthStatus:
		return cm.status(req)
	}
	return credproto.Response{Error: "unknown oauth op"}
}

func (cm *custodyManager) begin(req credproto.Request) credproto.Response {
	spec, ok := oauthbridge.CustodySpecFor(req.Provider)
	if !ok {
		return credproto.Response{Error: fmt.Sprintf("custody: no custody support for provider %q (supported: claude, codex) — run without -oauth-custody", req.Provider)}
	}
	if req.State == "" || req.Verifier == "" || req.ClientID == "" || req.RedirectURI == "" {
		return credproto.Response{Error: "custody: oauth.begin needs state, verifier, clientId, redirectUri"}
	}
	// The redirect must be loopback; the daemon binds the callback port on
	// the host and anything else would strand the browser flow.
	port, err := loopbackPort(req.RedirectURI)
	if err != nil {
		return credproto.Response{Error: "custody: " + err.Error()}
	}
	if !cm.ensurePort(port) {
		return credproto.Response{Error: fmt.Sprintf("custody: callback port %d is not in the bridge's allowlist (codex 1455, pi 53692, or IANA dynamic 49152-65535)", port)}
	}

	cm.mu.Lock()
	delete(cm.finished, req.State) // a fresh begin supersedes an old result
	cm.flows[req.State] = &custodyFlow{
		provider:    strings.ToLower(req.Provider),
		verifier:    req.Verifier,
		clientID:    req.ClientID,
		redirectURI: req.RedirectURI,
		done:        make(chan struct{}),
	}
	cm.mu.Unlock()
	_ = spec // validated above; used at exchange time via CustodySpecFor
	cm.br.auditf("custody: oauth.begin for %s (state %.8s…) — awaiting browser callback on host port %d",
		req.Provider, req.State, port)
	return credproto.Response{Message: "custody flow registered; open the authorize URL in your host browser"}
}

// loopbackPort extracts the port from a loopback redirect URI.
func loopbackPort(redirectURI string) (int, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return 0, fmt.Errorf("bad redirectUri %q: %v", redirectURI, err)
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return 0, fmt.Errorf("redirectUri %q is not loopback", redirectURI)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 {
		return 0, fmt.Errorf("redirectUri %q has no usable port", redirectURI)
	}
	return port, nil
}

// consumeCallback is the bridge hook: match the callback's state to a
// pending flow and complete the exchange host-side. Returns true when the
// callback was consumed (never replayed into the guest).
func (cm *custodyManager) consumeCallback(port int, u *url.URL) bool {
	q := u.Query()
	state := q.Get("state")
	if state == "" {
		return false
	}
	cm.mu.Lock()
	flow, ok := cm.flows[state]
	cm.mu.Unlock()
	if !ok {
		return false // not ours: transparent bridge replays as usual
	}
	if errText := q.Get("error"); errText != "" {
		cm.finish(flow, fmt.Errorf("provider returned error: %s", errText))
		return true
	}
	code := q.Get("code")
	if code == "" {
		cm.finish(flow, fmt.Errorf("callback carried neither code nor error"))
		return true
	}
	go cm.exchange(flow, code)
	return true
}

func (cm *custodyManager) exchange(flow *custodyFlow, code string) {
	spec, _ := oauthbridge.CustodySpecFor(flow.provider)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, err := oauthbridge.ExchangeCode(ctx, spec, code, flow.verifier, flow.clientID, flow.redirectURI)
	if err != nil {
		cm.finish(flow, fmt.Errorf("token exchange: %w", err))
		return
	}
	set := oauthtokens.TokenSet{
		Provider:     flow.provider,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ClientID:     flow.clientID,
	}
	if tok.ExpiresIn > 0 {
		set.Expiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	if err := cm.registry.Put(set); err != nil {
		cm.br.auditf("custody: token disk sync failed (restart durability uncertain): %v", err)
	}
	if err := cm.pushAuthFile(flow.provider, tok); err != nil {
		cm.finish(flow, fmt.Errorf("guest auth-file push: %w", err))
		return
	}
	cm.startRefreshLoop(flow.provider)
	cm.br.auditf("custody: %s login complete — refresh token held on host, access token pushed to guest", flow.provider)
	cm.finish(flow, nil)
}

func (cm *custodyManager) finish(flow *custodyFlow, err error) {
	cm.mu.Lock()
	flow.err = err
	for k, f := range cm.flows {
		if f == flow {
			delete(cm.flows, k)
			cm.finished[k] = err // the status poll still needs the outcome
			break
		}
	}
	cm.mu.Unlock()
	close(flow.done)
}

// status long-polls one flow's completion (the guest polls in a loop; the
// broker connection deadline forces each poll to stay short).
func (cm *custodyManager) status(req credproto.Request) credproto.Response {
	cm.mu.Lock()
	if err, done := cm.finished[req.State]; done {
		delete(cm.finished, req.State) // terminal result delivered once
		cm.mu.Unlock()
		if err != nil {
			return credproto.Response{Error: err.Error()}
		}
		return credproto.Response{OK: true, Message: "login complete (custody: tokens held on host)"}
	}
	flow, ok := cm.flows[req.State]
	cm.mu.Unlock()
	if !ok {
		// Flow gone: either finished-and-reaped or never existed. The
		// registry is the durable record — a completed flow has a set.
		if _, held := cm.registry.Get(strings.ToLower(req.Provider)); held {
			return credproto.Response{OK: true, Message: "login complete (custody: tokens held on host)"}
		}
		return credproto.Response{Error: "custody: no such flow (expired or never begun)"}
	}
	select {
	case <-flow.done:
		if flow.err != nil {
			return credproto.Response{Error: flow.err.Error()}
		}
		return credproto.Response{OK: true, Message: "login complete (custody: tokens held on host)"}
	case <-time.After(custodyStatusWait):
		return credproto.Response{Message: "pending"}
	}
}

// pushGuestAuthFile writes the provider's auth file inside the guest via
// the internal exec channel (bounded capture, timeout, no user secrets in
// argv — the file content arrives base64 on stdin).
func (cm *custodyManager) pushGuestAuthFile(provider string, tok oauthbridge.TokenResponse) error {
	set, held := cm.registry.Get(provider)
	if !held {
		return fmt.Errorf("no token set held for %s", provider)
	}
	content, err := oauthbridge.RenderGuestAuthFile(provider, tok, set.Expiry)
	if err != nil {
		return err
	}
	spec, _ := oauthbridge.CustodySpecFor(provider)
	script := fmt.Sprintf(
		`umask 077; d=$(dirname "%s"); mkdir -p "$d"; base64 -d > "%s"`,
		spec.GuestAuthFile, spec.GuestAuthFile)
	stdin := strings.NewReader(base64.StdEncoding.EncodeToString(content))
	_, status, err := cm.br.internalExec(stdin, []string{"sh", "-c", script}, 30*time.Second, custodyPushLimit, custodyPushOp)
	if err != nil {
		return err
	}
	if status != 0 {
		return fmt.Errorf("guest write exited %d", status)
	}
	return nil
}

// startRefreshLoop runs one goroutine per provider: refresh ahead of
// expiry, re-capture rotated refresh tokens, push the fresh access token
// into the guest. Non-expiring or refresh-less sets need no loop. The
// loop ends when the set is deleted (provider revoked) or with the daemon
// process.
func (cm *custodyManager) startRefreshLoop(provider string) {
	cm.mu.Lock()
	if _, running := cm.loops[provider]; running {
		cm.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	cm.loops[provider] = stop
	cm.mu.Unlock()

	go func() {
		for {
			set, held := cm.registry.Get(provider)
			if !held {
				return
			}
			due, ok := set.RefreshDue(time.Now(), custodyRefreshLeeway)
			if !ok {
				return
			}
			wait := time.Until(due)
			if wait < 0 {
				wait = 0
			}
			select {
			case <-time.After(wait):
			case <-stop:
				return
			}

			spec, _ := oauthbridge.CustodySpecFor(provider)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			tok, err := oauthbridge.RefreshTokens(ctx, spec, set.RefreshToken, set.ClientID)
			cancel()
			if err != nil {
				// Transient failures retry on a short clock; an invalid
				// grant (the provider revoked the refresh token) drops the
				// set so the guest fails loudly and re-login is required.
				cm.br.auditf("custody: %s refresh failed: %v", provider, err)
				if strings.Contains(err.Error(), "400") || strings.Contains(err.Error(), "401") {
					_ = cm.registry.Delete(provider)
					return
				}
				select {
				case <-time.After(time.Minute):
				case <-stop:
					return
				}
				continue
			}
			next := oauthtokens.TokenSet{
				Provider:     provider,
				AccessToken:  tok.AccessToken,
				RefreshToken: tok.RefreshToken,
				ClientID:     set.ClientID,
			}
			if tok.RefreshToken == "" {
				next.RefreshToken = set.RefreshToken // provider did not rotate
			}
			if tok.ExpiresIn > 0 {
				next.Expiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
			}
			if err := cm.registry.Put(next); err != nil {
				cm.br.auditf("custody: %s token disk sync failed: %v", provider, err)
			}
			if err := cm.pushAuthFile(provider, tok); err != nil {
				cm.br.auditf("custody: %s auth-file push failed: %v", provider, err)
			} else {
				cm.br.auditf("custody: %s access token refreshed and pushed", provider)
			}
		}
	}()
}

// restoreRestart starts refresh loops for token sets recovered from disk
// after a daemon restart.
func (cm *custodyManager) restoreRestart() {
	for _, provider := range cm.registry.Providers() {
		cm.br.auditf("custody: %s session restored from disk; refresh loop resumed", provider)
		cm.startRefreshLoop(provider)
	}
}

// sortedProviders is for tests and diagnostics.
func (cm *custodyManager) sortedFlows() []string {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	out := make([]string, 0, len(cm.flows))
	for state := range cm.flows {
		out = append(out, state)
	}
	sort.Strings(out)
	return out
}
