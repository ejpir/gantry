package sandbox

// OAuth custody: the daemon owns provider registrations, login proof,
// exchange, persistence and refresh. The guest requests a registration by
// name via oauth.login and polls oauth.status. Code callbacks are consumed
// host-side; device authorization is polled on the host as well.
//
// Refresh tokens never enter the guest or MCP worker. Access-token delivery
// is independent of OAuth: built-in Claude/Codex adapters push auth files,
// while generic registrations stay host-only unless explicitly referenced by
// an MCP remote or bound to a credential-helper hostname.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/oauthprovider"
	"github.com/ejpir/gantry/internal/sandbox/credhelper/credproto"
	"github.com/ejpir/gantry/internal/sandbox/oauthbridge"
	"github.com/ejpir/gantry/internal/sandbox/oauthtokens"
)

const (
	// custodyRefreshLeeway is how far ahead of expiry the loop refreshes.
	custodyRefreshLeeway = 5 * time.Minute
	// A provider that repeatedly returns an already-due token must not make
	// the daemon hammer its token endpoint.
	custodyMinRefreshInterval = 30 * time.Second
	// Pending and completed flow state is bounded and expires with the browser
	// login window.
	custodyFlowLifetime     = 10 * time.Minute
	maxCustodyFlows         = 16
	maxCustodyResults       = 64
	maxCustodyStateBytes    = 256
	maxCustodyVerifierBytes = 256
	maxCustodyClientIDBytes = 256
	maxCustodyRedirectBytes = 2 << 10
	// custodyStatusWait bounds one oauth.status long-poll; the broker's
	// 5s connection deadline must not be hit, so stay under it.
	custodyStatusWait = 4 * time.Second
	custodyPushOp     = "oauth custody auth-file push"
	custodyPushLimit  = 4 << 10
)

// custodyFlow is one in-flight login, keyed by OAuth state.
type custodyFlow struct {
	state       string
	provider    string
	verifier    string
	clientID    string
	redirectURI string
	port        int
	spec        oauthprovider.Spec // snapshot; a guest cannot redirect exchanges
	done        chan struct{}
	err         error
	claimed     bool
	once        sync.Once
	timer       *time.Timer
}

type custodyResult struct {
	err          error
	at           time.Time
	provider     string
	port         int
	callbackPath string
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
	finished map[string]custodyResult // bounded terminal results retained for idempotent callbacks/status
	loops    map[string]chan struct{} // provider -> stop signal
}

func newCustodyManager(br *broker, registry *oauthtokens.Registry) *custodyManager {
	cm := &custodyManager{
		br:       br,
		registry: registry,
		flows:    map[string]*custodyFlow{},
		finished: map[string]custodyResult{},
		loops:    map[string]chan struct{}{},
	}
	cm.pushAuthFile = cm.pushGuestAuthFile
	cm.ensurePort = br.oauth.EnsureCallbackPort
	return cm
}

// handleOAuthOp dispatches oauth.begin / oauth.status from the guest.
func (cm *custodyManager) handleOAuthOp(req credproto.Request) credproto.Response {
	switch req.Op {
	case credproto.OpOAuthLogin:
		return cm.login(req.Provider)
	case credproto.OpOAuthBegin:
		return cm.begin(req)
	case credproto.OpOAuthStatus:
		return cm.status(req)
	}
	return credproto.Response{Error: "unknown oauth op"}
}

// begin preserves the protocol used by older Claude/Codex guest helpers.
// Configured registrations must use oauth.login: the host owns their client
// ID, redirect, resource, state and PKCE material, not the requesting guest.
func (cm *custodyManager) begin(req credproto.Request) credproto.Response {
	spec, ok := oauthbridge.CustodySpecFor(req.Provider)
	if !ok || spec.GuestAuthFile == "" {
		return credproto.Response{Error: "custody: provider requires oauth.login from an updated guest helper"}
	}
	return cm.beginCode(spec, req)
}

func (cm *custodyManager) beginCode(spec oauthprovider.Spec, req credproto.Request) credproto.Response {
	if req.State == "" || req.Verifier == "" || req.ClientID == "" || req.RedirectURI == "" {
		return credproto.Response{Error: "custody: oauth.begin needs state, verifier, clientId, redirectUri"}
	}
	if len(req.State) > maxCustodyStateBytes || len(req.Verifier) > maxCustodyVerifierBytes ||
		len(req.ClientID) > maxCustodyClientIDBytes || len(req.RedirectURI) > maxCustodyRedirectBytes {
		return credproto.Response{Error: "custody: oauth.begin field exceeds its size limit"}
	}
	// The redirect must be loopback; the daemon binds the callback port on
	// the host and anything else would strand the browser flow.
	port, err := loopbackPort(req.RedirectURI)
	if err != nil {
		return credproto.Response{Error: "custody: " + err.Error()}
	}
	flow := &custodyFlow{
		state:       req.State,
		provider:    spec.Provider,
		spec:        spec,
		verifier:    req.Verifier,
		clientID:    req.ClientID,
		redirectURI: req.RedirectURI,
		port:        port,
		done:        make(chan struct{}),
	}
	if err := cm.registerFlow(flow); err != nil {
		return credproto.Response{Error: err.Error()}
	}
	if !cm.ensurePort(port) {
		cm.finish(flow, fmt.Errorf("callback port %d could not be opened", port))
		return credproto.Response{Error: fmt.Sprintf("custody: callback port %d could not be opened (not allowed, already in use, or listener limit reached)", port)}
	}
	cm.br.auditf("custody: oauth.begin for %s — awaiting browser callback on host port %d", spec.Provider, port)
	return credproto.Response{Message: "custody flow registered; open the authorize URL in your host browser"}
}

func (cm *custodyManager) registerFlow(flow *custodyFlow) error {
	cm.mu.Lock()
	cm.cleanupFinishedLocked(time.Now())
	if _, exists := cm.flows[flow.state]; exists {
		cm.mu.Unlock()
		return fmt.Errorf("custody: a flow with that state is already pending")
	}
	if len(cm.flows) >= maxCustodyFlows {
		cm.mu.Unlock()
		return fmt.Errorf("custody: too many pending OAuth flows (max %d)", maxCustodyFlows)
	}
	delete(cm.finished, flow.state) // a fresh begin supersedes an old result
	cm.flows[flow.state] = flow
	flow.timer = time.AfterFunc(custodyFlowLifetime, func() {
		cm.expire(flow)
	})
	cm.mu.Unlock()
	return nil
}

// loopbackPort extracts the port from a loopback redirect URI.
func loopbackPort(redirectURI string) (int, error) {
	return oauthprovider.RedirectPort(redirectURI, false)
}

// consumeCallback is the bridge hook: match the callback's state to a
// pending flow and complete the exchange host-side. Returns true when the
// callback was consumed (never replayed into the guest).
func (cm *custodyManager) consumeCallback(port int, u *url.URL) bool {
	q := u.Query()
	state := q.Get("state")
	if state == "" || len(q["state"]) != 1 || len(q["code"]) > 1 || len(q["error"]) > 1 {
		return false
	}
	cm.mu.Lock()
	cm.cleanupFinishedLocked(time.Now())
	if result, done := cm.finished[state]; done {
		cm.mu.Unlock()
		return result.port == port && port != 0 && result.callbackPath == u.EscapedPath() // duplicate browser delivery for a completed custody flow
	}
	flow, ok := cm.flows[state]
	if !ok || flow.port != port || port == 0 || callbackPath(flow.redirectURI) != u.EscapedPath() {
		cm.mu.Unlock()
		return false // not ours: transparent bridge replays as usual
	}
	if flow.claimed {
		cm.mu.Unlock()
		return true // exactly one callback may exchange this authorization code
	}
	flow.claimed = true
	// The lifetime bounds waiting for a browser callback. Once claimed, the
	// token exchange has its own context deadline and must not race this timer
	// into reporting expiry while still installing a successful token set.
	if flow.timer != nil {
		flow.timer.Stop()
	}
	cm.mu.Unlock()
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, err := oauthbridge.ExchangeCode(ctx, flow.spec, code, flow.verifier, flow.clientID, flow.redirectURI)
	if err != nil {
		cm.finish(flow, fmt.Errorf("token exchange: %w", err))
		return
	}
	cm.installTokens(flow, tok)
}

func (cm *custodyManager) installTokens(flow *custodyFlow, tok oauthbridge.TokenResponse) {
	now := time.Now()
	set := oauthtokens.TokenSet{
		Provider:     flow.provider,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IDToken:      tok.IDToken,
		AccountID:    tok.AccountID,
		ClientID:     flow.clientID,
		Registration: flow.spec.Fingerprint(),
		Expiry:       tok.ExpiryAt(now),
	}
	if err := cm.registry.Put(set); err != nil {
		cm.br.auditf("custody: token disk sync failed (restart durability uncertain): %v", err)
	}
	if err := cm.deliverAccessToken(flow.provider, tok); err != nil {
		cm.finish(flow, fmt.Errorf("guest auth-file push: %w", err))
		return
	}
	cm.startRefreshLoop(flow.provider)
	cm.br.auditf("custody: %s login complete — tokens held on host; configured delivery ready", flow.provider)
	cm.finish(flow, nil)
}

func (cm *custodyManager) expire(flow *custodyFlow) {
	cm.mu.Lock()
	if cm.flows[flow.state] != flow || flow.claimed {
		cm.mu.Unlock()
		return
	}
	// Expiry and browser delivery race for the same claim under cm.mu.
	// Whichever wins owns finishing the flow.
	flow.claimed = true
	cm.mu.Unlock()
	cm.finish(flow, fmt.Errorf("OAuth flow expired after %s", custodyFlowLifetime))
}

func (cm *custodyManager) finish(flow *custodyFlow, err error) {
	flow.once.Do(func() {
		if flow.timer != nil {
			flow.timer.Stop()
		}
		cm.mu.Lock()
		flow.err = err
		if cm.flows[flow.state] == flow {
			delete(cm.flows, flow.state)
			cm.cleanupFinishedLocked(time.Now())
			for len(cm.finished) >= maxCustodyResults {
				var oldestState string
				var oldest time.Time
				for state, result := range cm.finished {
					if oldestState == "" || result.at.Before(oldest) {
						oldestState, oldest = state, result.at
					}
				}
				delete(cm.finished, oldestState)
			}
			cm.finished[flow.state] = custodyResult{err: err, at: time.Now(), provider: flow.provider, port: flow.port, callbackPath: callbackPath(flow.redirectURI)}
		}
		cm.mu.Unlock()
		close(flow.done)
	})
}

func (cm *custodyManager) cleanupFinishedLocked(now time.Time) {
	for state, result := range cm.finished {
		if now.Sub(result.at) >= custodyFlowLifetime {
			delete(cm.finished, state)
		}
	}
}

// status long-polls one flow's completion (the guest polls in a loop; the
// broker connection deadline forces each poll to stay short).
func (cm *custodyManager) status(req credproto.Request) credproto.Response {
	cm.mu.Lock()
	cm.cleanupFinishedLocked(time.Now())
	if result, done := cm.finished[req.State]; done && result.provider == strings.ToLower(req.Provider) {
		cm.mu.Unlock()
		if result.err != nil {
			return credproto.Response{Error: result.err.Error()}
		}
		return credproto.Response{OK: true, Message: "login complete (custody: tokens held on host)"}
	}
	flow, ok := cm.flows[req.State]
	cm.mu.Unlock()
	if !ok || flow.provider != strings.ToLower(req.Provider) {
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
	if tok.IDToken == "" {
		tok.IDToken = set.IDToken
	}
	if tok.AccountID == "" {
		tok.AccountID = set.AccountID
	}
	content, err := oauthbridge.RenderGuestAuthFile(provider, tok, set.Expiry)
	if err != nil {
		return err
	}
	spec, _ := cm.specFor(provider)
	script := fmt.Sprintf(
		`umask 077; p="%[1]s"; d=$(dirname "$p"); mkdir -p "$d"; tmp="$p.gantry-tmp.$$"; trap 'rm -f "$tmp"' EXIT; base64 -d > "$tmp" && mv -f "$tmp" "$p"`,
		spec.GuestAuthFile)
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
	// A new login replaces any sleeper built from the previous token set so
	// its new expiry takes effect immediately.
	if old := cm.loops[provider]; old != nil {
		close(old)
	}
	stop := make(chan struct{})
	cm.loops[provider] = stop
	cm.mu.Unlock()

	go func() {
		defer func() {
			cm.mu.Lock()
			if cm.loops[provider] == stop {
				delete(cm.loops, provider)
			}
			cm.mu.Unlock()
		}()
		var lastAttempt time.Time
		for {
			set, held := cm.registry.Get(provider)
			if !held {
				return
			}
			now := time.Now()
			due, ok := set.RefreshDue(now, custodyRefreshLeeway)
			if !ok {
				return
			}
			// The first already-due token refreshes immediately. Subsequent
			// attempts are floored so short-lived/broken provider responses
			// cannot create a hot loop.
			if floor := lastAttempt.Add(custodyMinRefreshInterval); !lastAttempt.IsZero() && due.Before(floor) {
				due = floor
			}
			wait := time.Until(due)
			if wait < 0 {
				wait = 0
			}
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-stop:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			}
			lastAttempt = time.Now()

			spec, supported := cm.specFor(provider)
			if !supported {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			tok, err := oauthbridge.RefreshTokens(ctx, spec, set.RefreshToken, set.ClientID)
			cancel()
			if err != nil {
				// Transient failures retry on a short clock; an invalid grant
				// drops the set so the guest fails loudly and re-login starts a
				// fresh scheduler.
				cm.br.auditf("custody: %s refresh failed: %v", provider, err)
				if oauthbridge.IsPermanentTokenError(err) {
					_, _ = cm.registry.UpdateIfCurrent(set, nil)
					return
				}
				retry := time.NewTimer(time.Minute)
				select {
				case <-retry.C:
				case <-stop:
					if !retry.Stop() {
						select {
						case <-retry.C:
						default:
						}
					}
					return
				}
				continue
			}
			next := oauthtokens.TokenSet{
				Provider:     provider,
				AccessToken:  tok.AccessToken,
				RefreshToken: tok.RefreshToken,
				IDToken:      tok.IDToken,
				AccountID:    tok.AccountID,
				ClientID:     set.ClientID,
				Registration: set.Registration,
				Expiry:       tok.ExpiryAt(time.Now()),
			}
			if next.RefreshToken == "" {
				next.RefreshToken = set.RefreshToken // provider did not rotate
			}
			if next.IDToken == "" {
				next.IDToken = set.IDToken
			}
			if next.AccountID == "" {
				next.AccountID = set.AccountID
			}
			updated, err := cm.registry.UpdateIfCurrent(set, &next)
			if err != nil {
				cm.br.auditf("custody: %s token disk sync failed: %v", provider, err)
			}
			if !updated {
				return
			}
			if err := cm.deliverAccessToken(provider, tok); err != nil {
				// Guest exec errors can carry guest-controlled output. Keep the
				// custody trail metadata-only.
				cm.br.auditf("custody: %s auth-file push failed", provider)
			} else if spec.GuestAuthFile != "" {
				cm.br.auditf("custody: %s access token refreshed and pushed", provider)
			} else {
				cm.br.auditf("custody: %s access token refreshed; configured delivery ready", provider)
			}
		}
	}()
}

// restoreRestart starts refresh loops for token sets recovered from disk
// after a daemon restart.
func (cm *custodyManager) restoreRestart() {
	for _, provider := range cm.registry.Providers() {
		spec, supported := cm.specFor(provider)
		if !supported {
			cm.br.auditf("custody: unsupported provider %s removed from token store", provider)
			_ = cm.registry.Delete(provider)
			continue
		}
		set, held := cm.registry.Get(provider)
		if !held {
			continue
		}
		_, builtin := oauthprovider.Builtin(provider)
		if (set.Registration != "" && set.Registration != spec.Fingerprint()) || (set.Registration == "" && !builtin) {
			cm.br.auditf("custody: %s registration changed; re-login required", provider)
			_ = cm.registry.Delete(provider)
			continue
		}
		if set.AccessToken == "" || (!set.Expiry.IsZero() && !time.Now().Before(set.Expiry)) {
			if set.RefreshToken == "" {
				cm.br.auditf("custody: unusable %s session removed from token store", provider)
				_ = cm.registry.Delete(provider)
				continue
			}
			if set.Expiry.IsZero() {
				set.Expiry = time.Now()
				if err := cm.registry.Put(set); err != nil {
					cm.br.auditf("custody: %s restart refresh scheduling could not be persisted", provider)
				}
			}
			cm.br.auditf("custody: %s session restored; awaiting immediate access-token refresh", provider)
		} else {
			tok := oauthbridge.TokenResponse{
				AccessToken: set.AccessToken,
				IDToken:     set.IDToken,
				AccountID:   set.AccountID,
			}
			if err := cm.deliverAccessToken(provider, tok); err != nil {
				cm.br.auditf("custody: %s restored auth-file push failed", provider)
			} else {
				cm.br.auditf("custody: %s session restored; configured delivery ready", provider)
			}
		}
		cm.startRefreshLoop(provider)
	}
}
