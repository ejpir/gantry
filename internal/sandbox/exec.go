package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"
)

type capturedExecRequest struct {
	Context        context.Context
	Args           []string
	Cwd            string
	Stdin          io.Reader
	Timeout        time.Duration
	MaxOutputBytes int64
}

type capturedExecResult struct {
	ExitCode  int
	Output    []byte
	Truncated bool
}

var errCapturedExecTimeout = errors.New("exec timed out")
var errCapturedExecOutputLimit = errors.New("exec output limit exceeded")

// execSandboxCaptured runs a non-terminal process through the existing
// authenticated sandbox broker and captures a bounded combined output stream.
// It keeps the broker's out-of-band exit event, so guest bytes can never forge
// an exit status. The caller controls timeout and output limits.
func execSandboxCaptured(name string, request capturedExecRequest) (capturedExecResult, error) {
	if len(request.Args) == 0 {
		return capturedExecResult{}, fmt.Errorf("argv must not be empty")
	}
	if request.Timeout <= 0 {
		request.Timeout = 30 * time.Second
	}
	if request.MaxOutputBytes <= 0 {
		request.MaxOutputBytes = 1 << 20
	}
	if _, alive := sandboxPID(name); !alive {
		return capturedExecResult{}, fmt.Errorf("sandbox %q is not running", name)
	}
	baseContext := request.Context
	if baseContext == nil {
		baseContext = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseContext, request.Timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	id := newControlRequestID("manager-exec")
	dialer := net.Dialer{Timeout: controlHandshakeTimeout}

	ctl, err := dialer.DialContext(ctx, "unix", filepath.Join(sandboxDir(name), "ctl.sock"))
	if err != nil {
		return capturedExecResult{}, fmt.Errorf("connect session control: %w", err)
	}
	defer func() { _ = ctl.Close() }()
	_ = ctl.SetDeadline(deadline)
	stopControlCancel := context.AfterFunc(ctx, func() { _ = ctl.SetDeadline(time.Now()) })
	defer stopControlCancel()
	if err := json.NewEncoder(ctl).Encode(&brokerRequest{Op: "sessionctl", ID: id, V: sessionProtocolVersion}); err != nil {
		return capturedExecResult{}, fmt.Errorf("send session control: %w", err)
	}
	ctlR := bufio.NewReader(ctl)
	line, err := readBoundedLine(ctlR, controlMaxEventBytes)
	if err != nil {
		return capturedExecResult{}, fmt.Errorf("session control handshake: %w", err)
	}
	var response struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil || !response.OK {
		return capturedExecResult{}, fmt.Errorf("session control rejected: %s", strings.TrimSpace(string(line)))
	}

	data, err := dialer.DialContext(ctx, "unix", filepath.Join(sandboxDir(name), "ctl.sock"))
	if err != nil {
		return capturedExecResult{}, fmt.Errorf("connect session data: %w", err)
	}
	defer func() { _ = data.Close() }()
	_ = data.SetDeadline(deadline)
	stopDataCancel := context.AfterFunc(ctx, func() {
		_ = data.SetDeadline(time.Now())
		_ = killSandboxSession(name, id)
	})
	defer stopDataCancel()
	if err := json.NewEncoder(data).Encode(&brokerRequest{Op: "session", ID: id, Args: request.Args, Cwd: request.Cwd}); err != nil {
		return capturedExecResult{}, fmt.Errorf("send session request: %w", err)
	}
	dataR := bufio.NewReader(data)
	line, err = readBoundedLine(dataR, controlMaxEventBytes)
	if err != nil {
		return capturedExecResult{}, fmt.Errorf("session handshake: %w", err)
	}
	response = struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}{}
	if err := json.Unmarshal(line, &response); err != nil || !response.OK {
		return capturedExecResult{}, fmt.Errorf("session rejected: %s", strings.TrimSpace(string(line)))
	}

	stdin := request.Stdin
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(data, stdin)
		if unix, ok := data.(*net.UnixConn); ok {
			_ = unix.CloseWrite()
		}
		close(copyDone)
	}()

	limited := io.LimitReader(dataR, request.MaxOutputBytes+1)
	output, readErr := io.ReadAll(limited)
	truncated := int64(len(output)) > request.MaxOutputBytes
	if truncated {
		output = output[:request.MaxOutputBytes]
		_ = killSandboxSession(name, id)
	}
	<-copyDone
	if readErr != nil {
		if ctx.Err() != nil || errors.Is(readErr, os.ErrDeadlineExceeded) {
			_ = killSandboxSession(name, id)
			return capturedExecResult{Output: output, Truncated: truncated}, fmt.Errorf("%w: %v", errCapturedExecTimeout, ctx.Err())
		}
		return capturedExecResult{Output: output, Truncated: truncated}, fmt.Errorf("read session output: %w", readErr)
	}
	if truncated {
		return capturedExecResult{Output: output, Truncated: true}, errCapturedExecOutputLimit
	}
	event, err := readSessionExitEvent(ctlR)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, os.ErrDeadlineExceeded) {
			_ = killSandboxSession(name, id)
			return capturedExecResult{Output: output}, fmt.Errorf("%w: %v", errCapturedExecTimeout, ctx.Err())
		}
		return capturedExecResult{Output: output}, fmt.Errorf("read session exit: %w", err)
	}
	result := capturedExecResult{ExitCode: sessionExitCode(event), Output: output}
	if event.Error != "" {
		return result, errors.New(event.Error)
	}
	return result, nil
}

func killSandboxSession(name, id string) error {
	const killTimeout = time.Second
	connection, err := net.DialTimeout("unix", filepath.Join(sandboxDir(name), "ctl.sock"), killTimeout)
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(killTimeout))
	if err := json.NewEncoder(connection).Encode(&brokerRequest{Op: "kill", ID: id}); err != nil {
		return err
	}
	line, err := readBoundedLine(bufio.NewReader(connection), controlMaxResponseBytes)
	if err != nil {
		return err
	}
	var response struct {
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return err
	}
	if !response.OK && response.Error != "no such session" {
		return errors.New(response.Error)
	}
	return nil
}

func CmdSandboxExec(name string, argv []string) int {
	dir := sandboxDir(name)
	if _, alive := sandboxPID(name); !alive {
		fmt.Fprintf(os.Stderr, "gantry exec: sandbox %q is not running (start it with: gantry start %s)\n", name, name)
		return 1
	}
	args := argv
	if len(argv) > 0 && argv[0] == "--" {
		args = argv[1:]
	} else if len(argv) > 0 && !strings.HasPrefix(argv[0], "-") {
		fmt.Fprintf(os.Stderr, "gantry exec: unexpected argument %q (want: gantry exec %s [-- CMD ...])\n", argv[0], name)
		return 2
	} else if len(argv) > 0 {
		fmt.Fprintf(os.Stderr, "gantry exec: no flags supported in attach mode (want: gantry exec %s [-- CMD ...])\n", name)
		return 2
	}

	id := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)

	// Control channel FIRST (the broker requires it parked before the
	// session starts, so an instant command can never lose its exit
	// event). The exit status arrives here as a versioned JSON event,
	// leaving the session connection a pure byte pipe: guest output may
	// contain any byte sequence (NULs, fake markers) without colliding
	// with the protocol, and a missing event unambiguously means an
	// abnormal end — never a silent exit 0.
	ctl, err := net.DialTimeout("unix", filepath.Join(dir, "ctl.sock"), controlHandshakeTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry exec: broker: %v\n", err)
		return 1
	}
	defer func() { _ = ctl.Close() }()
	_ = ctl.SetDeadline(time.Now().Add(controlHandshakeTimeout))
	if err := json.NewEncoder(ctl).Encode(&brokerRequest{Op: "sessionctl", ID: id, V: sessionProtocolVersion}); err != nil {
		fmt.Fprintf(os.Stderr, "gantry exec: %v\n", err)
		return 1
	}
	ctlR := bufio.NewReader(ctl)
	ctlLine, err := readBoundedLine(ctlR, controlMaxEventBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry exec: broker control handshake: %v\n", err)
		return 1
	}
	var ctlResp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if json.Unmarshal(ctlLine, &ctlResp) != nil || !ctlResp.OK {
		fmt.Fprintf(os.Stderr, "gantry exec: broker rejected control channel: %s\n", strings.TrimSpace(string(ctlLine)))
		return 1
	}
	_ = ctl.SetDeadline(time.Time{})

	c, err := net.DialTimeout("unix", filepath.Join(dir, "ctl.sock"), controlHandshakeTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry exec: broker: %v\n", err)
		return 1
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(controlHandshakeTimeout))

	req := brokerRequest{Op: "session", ID: id, Args: args}
	req.Terminal = term.IsTerminal(int(os.Stdin.Fd()))
	if req.Terminal {
		if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
			req.Cols, req.Rows = uint32(w), uint32(h)
		}
	}
	if err := json.NewEncoder(c).Encode(&req); err != nil {
		fmt.Fprintf(os.Stderr, "gantry exec: %v\n", err)
		return 1
	}
	r := bufio.NewReader(c)
	line, err := readBoundedLine(r, controlMaxEventBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry exec: broker handshake: %v\n", err)
		return 1
	}
	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if json.Unmarshal(line, &resp) != nil || !resp.OK {
		fmt.Fprintf(os.Stderr, "gantry exec: broker rejected: %s\n", strings.TrimSpace(string(line)))
		return 1
	}
	_ = c.SetDeadline(time.Time{})

	if req.Terminal {
		if old, err := term.MakeRaw(int(os.Stdin.Fd())); err == nil {
			defer func() { _ = term.Restore(int(os.Stdin.Fd()), old) }()
		}
	}
	// ctrl-C: ask the broker to kill the task, keep the session attached.
	// Loop: every interrupt kills (a second ctrl-C is not swallowed).
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)
	defer signal.Stop(sigc)
	go func() {
		for range sigc {
			kc, err := net.DialTimeout("unix", filepath.Join(dir, "ctl.sock"), controlHandshakeTimeout)
			if err == nil {
				_ = kc.SetWriteDeadline(time.Now().Add(controlHandshakeTimeout))
				_ = json.NewEncoder(kc).Encode(&brokerRequest{Op: "kill", ID: id})
				_ = kc.Close()
			}
		}
	}()

	done := make(chan struct{})
	go func() { _, _ = io.Copy(c, os.Stdin) }()
	go func() {
		// r (not c): the handshake line came through the bufio reader.
		// The stream is a pure byte pipe now — no in-band status to strip.
		_, _ = io.Copy(os.Stdout, r)
		close(done)
	}()
	<-done
	// The broker wrote the exit event before closing the data conn, so it
	// is already queued in the normal case; the deadline only bounds a
	// wedged broker. A missing or garbled event is an abnormal end.
	_ = ctl.SetReadDeadline(time.Now().Add(30 * time.Second))
	ev, err := readSessionExitEvent(ctlR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\ngantry exec: session ended without an exit status (broker died?): %v\n", err)
		return sessionAbnormalExitCode
	}
	if ev.Error != "" {
		fmt.Fprintf(os.Stderr, "\ngantry exec: session infrastructure failure: %s\n", ev.Error)
	}
	return sessionExitCode(ev)
}

func sessionExitCode(ev sessionExitEvent) int {
	if ev.Error != "" {
		return sessionAbnormalExitCode
	}
	return ev.Exit
}

// readSessionExitEvent reads the single versioned JSON line the broker
// sends on the session-control channel when a session ends. EOF, garbage,
// or a version mismatch are all errors: callers must treat a missing
// event as an abnormal end (never a silent exit 0).
func readSessionExitEvent(r *bufio.Reader) (sessionExitEvent, error) {
	line, err := readBoundedLine(r, controlMaxEventBytes)
	if err != nil {
		return sessionExitEvent{}, err
	}
	var ev sessionExitEvent
	if err := json.Unmarshal(line, &ev); err != nil {
		return sessionExitEvent{}, fmt.Errorf("bad exit event: %w", err)
	}
	if ev.V != sessionProtocolVersion {
		return sessionExitEvent{}, fmt.Errorf("unsupported session protocol version %d", ev.V)
	}
	return ev, nil
}
