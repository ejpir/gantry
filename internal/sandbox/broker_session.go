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
	"github.com/ejpir/gantry/internal/secret"
)

// sessionProtocolVersion versions the session-control channel: the
// "sessionctl" request carries it and every sessionExitEvent echoes it,
// so agent integrations have a stable, checkable contract. Bump on any
// wire change.
const (
	sessionProtocolVersion  = 1
	sessionAbnormalExitCode = 255
)

// sessionExitEvent is the single message a session-control channel
// carries after the handshake: the task's exit status, delivered out of
// band (never inline in the stdio stream).
type sessionExitEvent struct {
	V     int    `json:"v"`
	Exit  int    `json:"exit"`
	Error string `json:"error,omitempty"`
}

func newSessionExitEvent(status int, err error) sessionExitEvent {
	ev := sessionExitEvent{V: sessionProtocolVersion, Exit: status}
	if err != nil {
		ev.Error = err.Error()
		ev.Exit = sessionAbnormalExitCode
	}
	return ev
}

// sessionctl parks c as the control channel for the session with the
// same id until that session ends (or the client goes away). The client
// parks it BEFORE starting the session so an instant command can never
// lose its exit event. The handler blocks for the channel's lifetime
// because handle()'s deferred Close is the conn's owner.
func (br *broker) sessionctl(c net.Conn, input io.Reader, req brokerRequest) {
	if req.V != sessionProtocolVersion {
		_, _ = fmt.Fprintf(c, "{\"error\":\"unsupported session protocol version %d (want %d)\"}\n", req.V, sessionProtocolVersion)
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

func (br *broker) session(c net.Conn, stdin io.Reader, req brokerRequest) {
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
		stdout = br.oauth.sniffWriter(stdout)
	}
	err := client.Session(br.rpc, client.SessionOptions{
		StreamSock:     br.streamSock,
		StreamDial:     br.streamDial,
		Shares:         manifest.Shares,
		ShareTransport: manifest.Transport,
		RW:             br.cfg.RW,
		LayerSet:       br.cfg.LayerSet,
		Args:           req.Args,
		Secrets:        secret.Env(br.secrets),
		// one VM = one container workload with a well-known id, so a
		// concurrent session can find it and Exec into it instead of
		// fighting over the rw rootfs stack with a second Create
		ID:               "sb",
		ExecIntoExisting: true,
		ImgCfg:           br.cfg.ImageCfg,
		Cols:             req.Cols,
		Rows:             req.Rows,
		Terminal:         req.Terminal,
		KillCh:           killCh,
		ExitStatus:       &status,
	}, stdin, stdout)
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
