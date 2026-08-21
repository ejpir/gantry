package main

// gantry-guest oauth login <provider>: custody-mode OAuth. The helper
// generates the PKCE material and authorize URL in the guest (the CLI's
// flow stays guest-driven), then delegates the code EXCHANGE to the
// daemon over the trusted vsock broker channel. The refresh token never
// enters the guest; the daemon pushes fresh access tokens into the CLI's
// auth file. Usage:
//
//	gantry-guest oauth login claude
//
// With custody off the broker answers with an error and the CLI's own
// login flow (transparent bridge) should be used instead.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/credhelper/credproto"
)

// guestOAuthProviders are the public, loopback-bound client
// registrations for custody-supported CLIs. client_id and callback ports
// are public constants shipped in the CLIs themselves. Env overrides
// exist for tests (mock authorization server).
type guestOAuthProvider struct {
	authorizeURL string
	clientID     string
	callbackPort int
	scope        string
}

var guestOAuthProviders = map[string]guestOAuthProvider{
	"claude": {
		authorizeURL: "https://claude.ai/oauth/authorize",
		clientID:     "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
		callbackPort: 8485,
		scope:        "user:profile user:inference",
	},
	"codex": {
		authorizeURL: "https://auth.openai.com/oauth/authorize",
		clientID:     "app_EMoamEEZ73f0CkXaXp7hrann",
		callbackPort: 1455,
		scope:        "openid profile email offline_access",
	},
}

func envOverride(key string, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func randURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func runOAuth(args []string) {
	if len(args) != 2 || args[0] != "login" {
		fmt.Fprintln(os.Stderr, "usage: gantry-guest oauth login <provider>")
		os.Exit(2)
	}
	provider := args[1]
	p, ok := guestOAuthProviders[provider]
	if !ok {
		fmt.Fprintf(os.Stderr, "gantry-guest: no custody login for %q (supported: claude, codex)\n", provider)
		os.Exit(2)
	}
	p.authorizeURL = envOverride("GANTRY_OAUTH_AUTHORIZE_URL_"+upper(provider), p.authorizeURL)
	p.clientID = envOverride("GANTRY_OAUTH_CLIENT_ID_"+upper(provider), p.clientID)

	verifier, err := randURLSafe(32)
	if err != nil {
		fatal(err)
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state, err := randURLSafe(16)
	if err != nil {
		fatal(err)
	}
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", p.callbackPort)
	authURL := p.authorizeURL + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {p.clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {p.scope},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}.Encode()

	resp, err := oauthRoundTrip(credproto.Request{
		Op:           credproto.OpOAuthBegin,
		Provider:     provider,
		State:        state,
		Challenge:    challenge,
		Verifier:     verifier,
		AuthorizeURL: authURL,
		ClientID:     p.clientID,
		RedirectURI:  redirectURI,
	})
	if err != nil {
		fatal(err)
	}
	if resp.Error != "" {
		fmt.Fprintln(os.Stderr, "gantry-guest:", resp.Error)
		os.Exit(1)
	}
	fmt.Printf("Open this URL in your HOST browser to log in:\n\n%s\n\n", authURL)

	// Long-poll status: the broker's per-connection deadline keeps each
	// poll short; re-issue until the flow completes, fails, or times out.
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		st, err := oauthRoundTrip(credproto.Request{Op: credproto.OpOAuthStatus, Provider: provider, State: state})
		if err != nil {
			fatal(err)
		}
		if st.OK {
			fmt.Println(st.Message)
			return
		}
		if st.Error != "" {
			fmt.Fprintln(os.Stderr, "gantry-guest:", st.Error)
			os.Exit(1)
		}
		time.Sleep(2 * time.Second)
	}
	fmt.Fprintln(os.Stderr, "gantry-guest: login timed out waiting for the browser callback")
	os.Exit(1)
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gantry-guest:", err)
	os.Exit(1)
}

// oauthRoundTrip is askBroker with an arbitrary request (the credential
// path fixes op=get). Kept separate so credhelper's hot path is
// untouched.
func oauthRoundTrip(req credproto.Request) (credproto.Response, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return credproto.Response{}, err
	}
	return brokerRoundTrip(raw)
}
