package sandbox

// internal_exec.go — one-shot internal exec into the sandbox container.
//
// The daemon sometimes needs to run a command inside the sandbox container
// itself: the OAuth loopback bridge replays browser callbacks this way
// (docs/oauth-login.md), and guest tooling delivery rides the same path.
// internalExec is a normal session exec, multiplexed over the daemon's
// single guest RPC connection like any concurrent `gantry exec` — but user
// secrets are deliberately NOT injected into these internal processes.
//
// Every call carries an op name ("oauth callback replay", "guest tool
// delivery", …) so timeout/overflow failures attribute to the caller, and
// explicit limits: a bounded stdout capture and a hard timeout that kills
// the session.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/image"
)

// defaultInternalExecTimeout bounds internal execs whose caller passes a
// non-positive timeout.
const defaultInternalExecTimeout = 15 * time.Second

// execCapture drains all stdout so the guest process cannot block on a full
// pipe, but retains only the bounded prefix needed to parse the response.
// overflow is reported after the internal exec unwinds.
type execCapture struct {
	max      int
	mu       sync.Mutex
	buf      bytes.Buffer
	overflow bool
}

func (c *execCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	remaining := c.max - c.buf.Len()
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

func (c *execCapture) snapshot() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...), c.overflow
}

// internalExec runs a one-shot command inside the sandbox container and
// captures its stdout. stdin may be nil (no input); maxResponse bounds the
// retained stdout; op names the caller for error attribution. User secrets
// are deliberately NOT injected into this internal process.
func (br *broker) internalExec(stdin io.Reader, args []string, timeout time.Duration, maxResponse int, op string) ([]byte, int, error) {
	return br.internalExecWithImageConfig(stdin, args, timeout, maxResponse, op, br.cfg.ImageCfg, false)
}

// internalExecAsRoot is reserved for trusted helpers which must install into
// or deliberately manage root-owned runtime state. User-requested commands
// continue through internalExec with the image identity.
func (br *broker) internalExecAsRoot(stdin io.Reader, args []string, timeout time.Duration, maxResponse int, op string) ([]byte, int, error) {
	return br.internalExecWithImageConfig(stdin, args, timeout, maxResponse, op, mcpLauncherImageConfig(br.cfg.ImageCfg), true)
}

func (br *broker) internalExecWithImageConfig(stdin io.Reader, args []string, timeout time.Duration, maxResponse int, op string, imageConfig *image.Config, holdSetupLocker bool) ([]byte, int, error) {
	if !br.limits.acquireSession() {
		return nil, 0, fmt.Errorf("sandbox session limit reached")
	}
	defer br.limits.releaseSession()

	capture := execCapture{max: maxResponse}
	var status int
	if timeout <= 0 {
		timeout = defaultInternalExecTimeout
	}
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	killCh := make(chan struct{}, 1)
	waitCtx, waitCancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer waitCancel()
	var expired atomic.Bool
	timer := time.AfterFunc(timeout, func() {
		expired.Store(true)
		killCh <- struct{}{}
	})
	manifest := client.LoadShareManifest(br.dir)
	err := client.Session(br.rpc, client.SessionOptions{
		StreamSock:      br.streamSock,
		StreamDial:      br.streamDial,
		SetupLocker:     &br.sessionSetupMu,
		HoldSetupLocker: holdSetupLocker,
		Shares:          manifest.Shares,
		ShareTransport:  manifest.Transport,
		RW:              br.cfg.RW,
		LayerSet:        br.cfg.LayerSet,
		Args:            args,
		ID:              "sb",
		SandboxSession:  true,
		ImgCfg:          imageConfig,
		Environment:     br.cfg.ProxyEnvironment(),
		Quiet:           true,
		ExitStatus:      &status,
		KillCh:          killCh,
		WaitContext:     waitCtx,
	}, stdin, &capture)
	_ = timer.Stop()
	stdout, overflow := capture.snapshot()
	return internalExecOutcome(stdout, status, err, overflow, expired.Load(), timeout, maxResponse, op)
}

// internalExecOutcome decides what a finished internal exec reports. A fired
// timer feeds killCh, and the kill forces Session's Wait to fail — so a nil
// session error means the exec genuinely completed before the kill landed.
// timer.Stop cannot cancel an AfterFunc callback that is already running, so
// expired may be set on a successful session: trust the session result over
// the flag. The session's own error is preserved on every failure path so a
// genuine timeout stays distinguishable from a guest-side refusal.
func internalExecOutcome(stdout []byte, status int, err error, overflow, expired bool, timeout time.Duration, maxResponse int, op string) ([]byte, int, error) {
	switch {
	case err == nil && !overflow:
		return stdout, status, nil
	case overflow:
		if err != nil {
			return nil, status, fmt.Errorf("%s response exceeds %d bytes: %w", op, maxResponse, err)
		}
		return nil, status, fmt.Errorf("%s response exceeds %d bytes", op, maxResponse)
	case expired:
		if err != nil {
			return nil, status, fmt.Errorf("%s exceeded %s: %w", op, timeout, err)
		}
		return nil, status, fmt.Errorf("%s exceeded %s", op, timeout)
	}
	return stdout, status, err
}
