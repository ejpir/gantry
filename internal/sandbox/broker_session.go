package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"time"

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
)

func newSessionExitEvent(status int, err error) controlproto.SessionExitEvent {
	ev := controlproto.SessionExitEvent{V: controlproto.SessionProtocolVersion, Exit: status}
	if err != nil {
		ev.Error = err.Error()
		ev.Exit = controlproto.SessionAbnormalExitCode
	}
	return ev
}

// sessionctl parks c as the control channel for the session with the
// same id until that session ends (or the client goes away). The client
// parks it BEFORE starting the session so an instant command can never
// lose its exit event. The handler blocks for the channel's lifetime
// because handle()'s deferred Close is the conn's owner.
func (br *broker) sessionctl(c net.Conn, input io.Reader, req controlproto.Request) {
	if req.V != controlproto.SessionProtocolVersion {
		_, _ = fmt.Fprintf(c, "{\"error\":\"unsupported session protocol version %d (want %d)\"}\n", req.V, controlproto.SessionProtocolVersion)
		return
	}
	if !br.limits.acquireParked() {
		_, _ = fmt.Fprintln(c, `{"error":"too many parked session control channels"}`)
		return
	}
	br.mu.Lock()
	if _, dup := br.sessionCtl[req.ID]; dup {
		br.mu.Unlock()
		br.limits.releaseParked()
		_, _ = fmt.Fprintln(c, `{"error":"duplicate session control id"}`)
		return
	}
	br.sessionCtl[req.ID] = c
	br.mu.Unlock()
	if _, err := fmt.Fprintln(c, `{"ok":true}`); err != nil {
		br.removeSessionControl(req.ID, c)
		return
	}
	_ = c.SetWriteDeadline(time.Time{})
	// A control channel carries no client bytes after the handshake, so a
	// completed read means the client went away. If the session op has
	// already taken ownership (entry deleted), cleanup is its job — this
	// handler then only unwinds. The handler itself can wait; a second
	// goroutine would add no concurrency and would complicate ownership.
	var b [1]byte
	_, _ = input.Read(b[:])
	br.removeSessionControl(req.ID, c)
}

// removeSessionControl removes an exact parked connection and releases its
// capacity. The identity check makes cleanup safe when an old handler wakes
// after its id has been reused.
func (br *broker) removeSessionControl(id string, c net.Conn) {
	br.mu.Lock()
	if br.sessionCtl[id] != c {
		br.mu.Unlock()
		return
	}
	delete(br.sessionCtl, id)
	br.mu.Unlock()
	br.limits.releaseParked()
}

var (
	errDuplicateSessionID = errors.New("duplicate session id")
	errNoSessionControl   = errors.New("no session control channel: dial op sessionctl with v=1 first")
)

func (br *broker) beginSession(id string, killCh chan struct{}) (net.Conn, error) {
	br.mu.Lock()
	if _, dup := br.sessions[id]; dup {
		br.mu.Unlock()
		return nil, errDuplicateSessionID
	}
	ctl, ok := br.sessionCtl[id]
	if !ok {
		br.mu.Unlock()
		return nil, errNoSessionControl
	}
	delete(br.sessionCtl, id)
	br.sessions[id] = killCh
	br.mu.Unlock()
	br.limits.releaseParked()
	return ctl, nil
}

func (br *broker) session(c net.Conn, stdin io.Reader, req controlproto.Request) {
	if !br.limits.acquireSession() {
		_, _ = fmt.Fprintln(c, `{"error":"too many active sessions"}`)
		return
	}
	defer br.limits.releaseSession()

	killCh := make(chan struct{})
	// The control channel must already be parked: the exit event is
	// written there before the data conn closes, so a fast command can
	// never lose it. Take ownership (the parked handler unwinds).
	ctl, beginErr := br.beginSession(req.ID, killCh)
	if beginErr != nil {
		_ = json.NewEncoder(c).Encode(struct {
			Error string `json:"error"`
		}{Error: beginErr.Error()})
		return
	}
	defer func() { _ = ctl.Close() }()
	defer func() {
		br.mu.Lock()
		delete(br.sessions, req.ID)
		br.mu.Unlock()
	}()

	if _, err := fmt.Fprintln(c, `{"ok":true}`); err != nil {
		return
	}
	_ = c.SetWriteDeadline(time.Time{})
	// no args defaulting here: client.Session applies the image's
	// Entrypoint+Cmd, then /bin/sh (the debian-filename heuristic that
	// used to live here predates image configs)
	manifest := client.LoadShareManifest(br.dir)
	var status int
	// Session stdout flows through the broker. The default-on OAuth bridge
	// sniffer can arm only bounded, approved host-side callback listeners;
	// per-sandbox and global settings can disable it.
	stdout := io.Writer(c)
	if br.oauth != nil {
		stdout = br.oauth.SniffWriter(stdout)
	}
	options := client.SessionOptions{
		StreamSock:     br.streamSock,
		StreamDial:     br.streamDial,
		SetupLocker:    &br.sessionSetupMu,
		Shares:         manifest.Shares,
		ShareTransport: manifest.Transport,
		Args:           req.Args,
		Cwd:            req.Cwd,
		Secrets:        br.secretEnv(),
		Environment:    br.cfg.ProxyEnvironment(),
		PathPrepend:    br.guestToolsPath(),
		// The workload base task owns the -image root. Dev Containers adds a
		// separate IDE base task; ordinary gantry exec never enters that root.
		SandboxSession: true,
		Cols:           req.Cols,
		Rows:           req.Rows,
		Terminal:       req.Terminal,
		Quiet:          req.Quiet,
		KillCh:         killCh,
		ExitStatus:     &status,
	}
	applySessionTarget(&options, br.sessionTarget(false))
	err := client.Session(br.rpc, options, stdin, stdout)
	if err != nil {
		_, _ = fmt.Fprintf(c, "\n[gantry] session error: %v\n", err)
		// The broker is the only process that still has the sandbox logs
		// while an attach client is connected. Include their tails in the
		// failure stream so CI and remote callers can diagnose guest boot
		// and daemon failures without guessing GANTRY_HOME.
		dumpTailTo(c, filepath.Join(br.dir, "daemon.log"))
		dumpTailTo(c, filepath.Join(br.dir, "console.log"))
	}
	// Exit event on the control channel, BEFORE the data conn closes
	// (handle()'s deferred Close runs when this handler returns): the
	// attach client drains the full data stream, sees EOF, and the event
	// is already queued for it. The deadline only bounds a wedged client
	// that stopped reading its control channel.
	ev := newSessionExitEvent(status, err)
	_ = ctl.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_ = json.NewEncoder(ctl).Encode(&ev)
}
