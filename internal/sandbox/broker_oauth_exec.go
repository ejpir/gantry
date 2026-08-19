package sandbox

// oauth_bridge.go — transparent OAuth loopback callback bridge.
//
// Agent CLIs (codex, claude, pi, …) sign in with an OAuth authorization-code
// flow against a loopback listener INSIDE the sandbox (codex:
// http://localhost:1455/auth/callback, pi: http://localhost:53692/callback,
// claude: http://localhost:<random>/callback). The CLI prints the authorize
// URL and waits for the provider to redirect the browser to the loopback
// listener — but the browser runs on the HOST, where that port is not the
// sandbox listener. The redirect dies in the host's network stack and login
// never completes.
//
// The daemon already relays every exec session's stdout through the broker,
// so it sees the printed authorize URL. This bridge:
//
//  1. sniffs session output for OAuth loopback redirect URLs
//     (redirect_uri=…localhost:<port>…, or a bare
//     http://localhost:<port>/callback-style URL);
//  2. binds 127.0.0.1:<port> on the host (loopback only, never LAN);
//  3. when the host browser lands on it, replays the callback into the
//     sandbox with an internal exec running a bash /dev/tcp one-shot —
//     no helper binary, no image/rootfs changes, no MITM, no new egress:
//     the request is made by a process inside the guest netns, which is
//     exactly what the CLI's loopback listener expects;
//  4. relays the CLI's HTTP response (its "sign-in complete" page) back
//     to the browser and closes the listener once a callback carrying
//     code=/error= has been delivered.
//
// Security posture: the bridge is enabled by default, with per-sandbox and
// global opt-outs. Host listeners bind 127.0.0.1 only and are restricted to
// the documented fixed callback ports or the dynamic OAuth range. Listener
// count, replay concurrency, duration, request size, and response size are all
// bounded. Only GET path+query is replayed to guest loopback; browser headers
// and cookies never cross the boundary.
//
// This mirrors the reference sandbox stack's behavior (host-side callback
// listener + replay via in-sandbox exec) without its TLS-intercepting
// proxy.

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/sandbox/oauthbridge"
)

// oauthCapture drains all stdout so the guest process cannot block on a full
// pipe, but retains only the bounded prefix needed to parse the callback
// response. overflow is reported after the internal exec unwinds.
type oauthCapture struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	overflow bool
}

func (c *oauthCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	remaining := oauthbridge.MaxReplayResponseSize - c.buf.Len()
	if remaining > 0 {
		keep := len(p)
		if keep > remaining {
			keep = remaining
		}
		_, _ = c.buf.Write(p[:keep])
	}
	if len(p) > remaining {
		c.overflow = true
	}
	return len(p), nil
}

func (c *oauthCapture) snapshot() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...), c.overflow
}

// oauthExec runs a one-shot command inside the sandbox container and
// captures its stdout. It is a normal session exec, multiplexed over the
// daemon's single guest RPC connection like any concurrent `gantry exec`.
// User secrets are deliberately NOT injected into this internal process.
func (br *broker) oauthExec(args []string, timeout time.Duration) ([]byte, int, error) {
	if !br.limits.acquireSession() {
		return nil, 0, fmt.Errorf("sandbox session limit reached")
	}
	defer br.limits.releaseSession()

	var capture oauthCapture
	var status int
	if timeout <= 0 {
		timeout = oauthbridge.ReplayTimeout
	}
	killCh := make(chan struct{}, 1)
	var expired atomic.Bool
	timer := time.AfterFunc(timeout, func() {
		expired.Store(true)
		killCh <- struct{}{}
	})
	manifest := client.LoadShareManifest(br.dir)
	err := client.Session(br.rpc, client.SessionOptions{
		StreamSock:       br.streamSock,
		StreamDial:       br.streamDial,
		Shares:           manifest.Shares,
		ShareTransport:   manifest.Transport,
		RW:               br.cfg.RW,
		LayerSet:         br.cfg.LayerSet,
		Args:             args,
		ID:               "sb",
		ExecIntoExisting: true,
		ImgCfg:           br.cfg.ImageCfg,
		Environment:      br.cfg.ProxyEnvironment(),
		Quiet:            true,
		ExitStatus:       &status,
		KillCh:           killCh,
	}, strings.NewReader(""), &capture)
	_ = timer.Stop()
	stdout, overflow := capture.snapshot()
	return oauthReplayOutcome(stdout, status, err, overflow, expired.Load(), timeout)
}

// oauthReplayOutcome decides what a finished replay session reports. A fired
// timer feeds killCh, and the kill forces Session's Wait to fail — so a nil
// session error means the replay genuinely completed before the kill landed.
// timer.Stop cannot cancel an AfterFunc callback that is already running, so
// expired may be set on a successful session: trust the session result over
// the flag. The session's own error is preserved on every failure path so a
// genuine timeout stays distinguishable from a guest-side refusal.
func oauthReplayOutcome(stdout []byte, status int, err error, overflow, expired bool, timeout time.Duration) ([]byte, int, error) {
	switch {
	case err == nil && !overflow:
		return stdout, status, nil
	case overflow:
		if err != nil {
			return nil, status, fmt.Errorf("callback response exceeds %d bytes: %w", oauthbridge.MaxReplayResponseSize, err)
		}
		return nil, status, fmt.Errorf("callback response exceeds %d bytes", oauthbridge.MaxReplayResponseSize)
	case expired:
		if err != nil {
			return nil, status, fmt.Errorf("callback replay exceeded %s: %w", timeout, err)
		}
		return nil, status, fmt.Errorf("callback replay exceeded %s", timeout)
	}
	return stdout, status, err
}
