package sandbox

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// Sandbox names feed filepath.Join + os.RemoveAll: path traversal out of the
// sandbox root must be rejected before any subcommand sees the name.
func TestSandboxNameTraversal(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "../victim", "a/b", `a\b`, "a b", "a\u0000b"} {
		if layout.ValidName(bad) {
			t.Fatalf("layout.ValidName(%q) = true", bad)
		}
	}
	for _, good := range []string{"dev", "my-vm.2_test", "..ok"} {
		if !layout.ValidName(good) {
			t.Fatalf("layout.ValidName(%q) = false", good)
		}
	}
}

func TestBrokerShutdownRequestAcknowledgesAndNotifies(t *testing.T) {
	shutdown := make(chan struct{}, 1)
	br := &broker{
		sessions:   map[string]chan struct{}{},
		sessionCtl: map[string]net.Conn{},
		shutdown:   shutdown,
	}
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	go br.handle(server)
	if err := json.NewEncoder(client).Encode(controlproto.Request{Op: "daemon.shutdown", ID: "stop-1"}); err != nil {
		t.Fatal(err)
	}
	line, err := controlproto.ReadBoundedLine(bufio.NewReader(client), controlproto.MaxResponseBytes)
	if err != nil {
		t.Fatal(err)
	}
	var response daemonShutdownResponse
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Error != "" {
		t.Fatalf("shutdown response = %+v", response)
	}
	select {
	case <-shutdown:
	default:
		t.Fatal("shutdown notification was not published")
	}
}

// The exit status crosses the broker<->attach-client hop as a versioned
// JSON event on a separate control channel, never inline in the stdio
// stream (review finding: a guest program can emit any byte sequence,
// including a fake in-band marker, and a missing in-band marker used to
// look like exit 0). The event reader must reject everything that is not
// a well-formed, correctly-versioned line.
func TestReadSessionExitEvent(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		wantSt  int
		wantErr bool
	}{
		{"clean exit", `{"v":1,"exit":42}` + "\n", 42, false},
		{"zero exit", `{"v":1,"exit":0}` + "\n", 0, false},
		{"error field carried", `{"v":1,"exit":255,"error":"boom"}` + "\n", 255, false},
		{"wrong version", `{"v":2,"exit":0}` + "\n", 0, true},
		{"missing version", `{"exit":0}` + "\n", 0, true},
		{"garbage", "not json\n", 0, true},
		{"truncated json", `{"v":1,"exi`, 0, true},
		{"empty", "", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := readSessionExitEvent(bufio.NewReader(strings.NewReader(tc.line)))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("readSessionExitEvent(%q) succeeded, want error", tc.line)
				}
				return
			}
			if err != nil {
				t.Fatalf("readSessionExitEvent(%q): %v", tc.line, err)
			}
			if ev.Exit != tc.wantSt {
				t.Fatalf("exit = %d, want %d", ev.Exit, tc.wantSt)
			}
		})
	}
	if _, err := readSessionExitEvent(bufio.NewReader(strings.NewReader(`{"v":1,"exit":255,"error":"boom"}` + "\n"))); err != nil {
		t.Fatal(err)
	}
}

// A client/session transport failure is distinct from a command that exited
// successfully. Even a malformed or older broker event that pairs an error
// with exit 0 must never make automation report success.
func TestSessionInfrastructureErrorIsAbnormalExit(t *testing.T) {
	brokerEvent := newSessionExitEvent(0, errors.New("session transport failed"))
	if brokerEvent.Exit != controlproto.SessionAbnormalExitCode || brokerEvent.Error == "" {
		t.Fatalf("broker event = %+v, want nonzero abnormal infrastructure failure", brokerEvent)
	}

	ev, err := readSessionExitEvent(bufio.NewReader(strings.NewReader(
		`{"v":1,"exit":0,"error":"task Wait: connection reset"}` + "\n",
	)))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Error == "" {
		t.Fatal("error field was dropped")
	}
	if got := sessionExitCode(ev); got != controlproto.SessionAbnormalExitCode {
		t.Fatalf("exit = %d, want abnormal exit %d", got, controlproto.SessionAbnormalExitCode)
	}
}

// The control channel handshake: a parked sessionctl conn gets {"ok":true},
// is registered under the session id, carries exactly one event line when
// the session op takes ownership and finishes, and the parked handler
// unwinds afterwards (no goroutine or map leak).
func TestSessionCtlRegistrationAndEvent(t *testing.T) {
	br := &broker{
		sessions:   map[string]chan struct{}{},
		sessionCtl: map[string]net.Conn{},
	}
	clientEnd, serverEnd := net.Pipe()
	defer func() { _ = clientEnd.Close() }()
	handlerDone := make(chan struct{})
	go func() {
		br.sessionctl(serverEnd, serverEnd, controlproto.Request{Op: "sessionctl", ID: "s1", V: controlproto.SessionProtocolVersion})
		close(handlerDone)
	}()
	r := bufio.NewReader(clientEnd)
	line, err := controlproto.ReadBoundedLine(r, controlproto.MaxEventBytes)
	if err != nil {
		t.Fatalf("handshake read: %v", err)
	}
	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(line, &resp); err != nil || !resp.OK {
		t.Fatalf("handshake = %s, want ok", strings.TrimSpace(string(line)))
	}
	br.mu.Lock()
	ctl, ok := br.sessionCtl["s1"]
	br.mu.Unlock()
	if !ok || ctl == nil {
		t.Fatal("control channel not registered")
	}

	// Simulate the session op taking ownership and emitting the event
	// (broker.session does exactly this on session end). net.Pipe is
	// synchronous, so the write runs concurrently with the read below.
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		taken, err := br.beginSession("s1", make(chan struct{}))
		if err != nil {
			return
		}
		defer func() {
			br.mu.Lock()
			delete(br.sessions, "s1")
			br.mu.Unlock()
		}()
		if err := json.NewEncoder(taken).Encode(&controlproto.SessionExitEvent{V: controlproto.SessionProtocolVersion, Exit: 7}); err != nil {
			return
		}
		_ = taken.Close()
	}()

	ev, err := readSessionExitEvent(r)
	<-writeDone
	if err != nil {
		t.Fatalf("event read: %v", err)
	}
	if ev.Exit != 7 {
		t.Fatalf("exit = %d, want 7", ev.Exit)
	}
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("sessionctl handler did not unwind after takeover + close")
	}
	br.mu.Lock()
	left := len(br.sessionCtl)
	br.mu.Unlock()
	if left != 0 {
		t.Fatalf("sessionCtl leak: %d entries left", left)
	}
	if got := len(br.limits.parked); got != 0 {
		t.Fatalf("transferred control retained %d parked slot", got)
	}
}

// Version enforcement: a sessionctl request without the current protocol
// version is rejected and registers nothing.
func TestSessionCtlRejectsWrongVersion(t *testing.T) {
	br := &broker{
		sessions:   map[string]chan struct{}{},
		sessionCtl: map[string]net.Conn{},
	}
	clientEnd, serverEnd := net.Pipe()
	defer func() { _ = clientEnd.Close() }()
	go br.sessionctl(serverEnd, serverEnd, controlproto.Request{Op: "sessionctl", ID: "s1", V: 0})
	line, err := controlproto.ReadBoundedLine(bufio.NewReader(clientEnd), controlproto.MaxEventBytes)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(line), "unsupported session protocol version") {
		t.Fatalf("response = %s, want version rejection", strings.TrimSpace(string(line)))
	}
	br.mu.Lock()
	defer br.mu.Unlock()
	if len(br.sessionCtl) != 0 {
		t.Fatal("rejected handshake registered a channel")
	}
}

func TestSessionCtlConsumesBytesBufferedWithHandshake(t *testing.T) {
	br := &broker{sessions: map[string]chan struct{}{}, sessionCtl: map[string]net.Conn{}}
	clientEnd, serverEnd := net.Pipe()
	defer func() { _ = clientEnd.Close() }()
	handlerDone := make(chan struct{})
	go func() {
		br.handle(serverEnd)
		close(handlerDone)
	}()
	writeDone := make(chan error, 1)
	go func() {
		_, err := io.WriteString(clientEnd, `{"op":"sessionctl","id":"buffered","v":1}`+"\nX")
		writeDone <- err
	}()

	line, err := controlproto.ReadBoundedLine(bufio.NewReader(clientEnd), controlproto.MaxEventBytes)
	if err != nil || !strings.Contains(string(line), `"ok":true`) {
		t.Fatalf("sessionctl handshake = %q, %v", line, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("buffered control byte did not wake parked handler")
	}
	br.mu.Lock()
	remaining := len(br.sessionCtl)
	br.mu.Unlock()
	if remaining != 0 || len(br.limits.parked) != 0 {
		t.Fatalf("buffered disconnect leaked controls=%d slots=%d", remaining, len(br.limits.parked))
	}
}

// A session request without a parked control channel is refused BEFORE any
// guest work starts: silently falling back to in-band status is exactly the
// failure mode this protocol removes.
func TestSessionRequiresControlChannel(t *testing.T) {
	br := &broker{
		sessions:   map[string]chan struct{}{},
		sessionCtl: map[string]net.Conn{},
	}
	clientEnd, serverEnd := net.Pipe()
	defer func() { _ = clientEnd.Close() }()
	done := make(chan struct{})
	go func() {
		br.session(serverEnd, strings.NewReader(""), controlproto.Request{Op: "session", ID: "s1"})
		_ = serverEnd.Close()
		close(done)
	}()
	line, err := controlproto.ReadBoundedLine(bufio.NewReader(clientEnd), controlproto.MaxEventBytes)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(line), "no session control channel") {
		t.Fatalf("response = %s, want control-channel refusal", strings.TrimSpace(string(line)))
	}
	<-done
	br.mu.Lock()
	defer br.mu.Unlock()
	if len(br.sessions) != 0 {
		t.Fatal("refused session registered a kill channel")
	}
	if got := len(br.limits.sessions); got != 0 {
		t.Fatalf("refused session retained %d streaming slot", got)
	}
}

func TestBoundedControlLine(t *testing.T) {
	exact := strings.Repeat("x", controlproto.MaxRequestBytes-1) + "\n"
	line, err := controlproto.ReadBoundedLine(bufio.NewReader(strings.NewReader(exact)), controlproto.MaxRequestBytes)
	if err != nil || string(line) != exact {
		t.Fatalf("exact-limit line: len=%d err=%v", len(line), err)
	}

	tooLarge := strings.Repeat("x", controlproto.MaxRequestBytes) + "\n"
	if _, err := controlproto.ReadBoundedLine(bufio.NewReader(strings.NewReader(tooLarge)), controlproto.MaxRequestBytes); !errors.Is(err, controlproto.ErrFrameTooLarge) {
		t.Fatalf("oversized line error = %v, want %v", err, controlproto.ErrFrameTooLarge)
	}
	if line, err := controlproto.ReadBoundedLine(bufio.NewReader(strings.NewReader("truncated")), controlproto.MaxRequestBytes); !errors.Is(err, io.EOF) || string(line) != "truncated" {
		t.Fatalf("truncated line = %q, err=%v", line, err)
	}
}

func TestBrokerRejectsOversizedRequest(t *testing.T) {
	br := &broker{sessions: map[string]chan struct{}{}, sessionCtl: map[string]net.Conn{}}
	clientEnd, serverEnd := net.Pipe()
	done := make(chan struct{})
	go func() {
		br.handle(serverEnd)
		close(done)
	}()
	defer func() { _ = clientEnd.Close() }()

	payload := strings.Repeat("x", controlproto.MaxRequestBytes) + "\n"
	if _, err := clientEnd.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	line, err := controlproto.ReadBoundedLine(bufio.NewReader(clientEnd), controlproto.MaxEventBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(line), "request too large") {
		t.Fatalf("response = %s", strings.TrimSpace(string(line)))
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("oversized request handler did not exit")
	}
}

func TestBrokerConnectionLimitReleasesSlot(t *testing.T) {
	br := &broker{sessions: map[string]chan struct{}{}, sessionCtl: map[string]net.Conn{}}
	br.limits.connections = make(chan struct{}, 1)

	sock := filepath.Join(t.TempDir(), "ctl.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	serveDone := make(chan struct{})
	go func() {
		br.serve(ln)
		close(serveDone)
	}()
	defer func() {
		_ = ln.Close()
		<-serveDone
	}()

	first, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	waitForTest(t, func() bool { return len(br.limits.connections) == 1 }, "first connection admission")

	second, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := controlproto.ReadBoundedLine(bufio.NewReader(second), controlproto.MaxEventBytes)
	_ = second.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(line), "too many control connections") {
		t.Fatalf("overload response = %s", strings.TrimSpace(string(line)))
	}

	_ = first.Close()
	waitForTest(t, func() bool { return len(br.limits.connections) == 0 }, "connection slot release")
}

func TestSessionControlLimitReleasesSlot(t *testing.T) {
	br := &broker{sessions: map[string]chan struct{}{}, sessionCtl: map[string]net.Conn{}}
	br.limits.parked = make(chan struct{}, 1)

	first, firstDone := startSessionControlForTest(t, br, "first")
	readControlOKForTest(t, first)
	waitForTest(t, func() bool { return len(br.limits.parked) == 1 }, "parked control admission")

	second, secondDone := startSessionControlForTest(t, br, "second")
	line, err := controlproto.ReadBoundedLine(bufio.NewReader(second), controlproto.MaxEventBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(line), "too many parked") {
		t.Fatalf("parked overload response = %s", strings.TrimSpace(string(line)))
	}
	_ = second.Close()
	<-secondDone
	if got := len(br.limits.parked); got != 1 {
		t.Fatalf("rejected control changed occupied slots to %d", got)
	}

	_ = first.Close()
	<-firstDone
	waitForTest(t, func() bool {
		br.mu.Lock()
		defer br.mu.Unlock()
		return len(br.sessionCtl) == 0 && len(br.limits.parked) == 0
	}, "parked control cleanup")

	third, thirdDone := startSessionControlForTest(t, br, "third")
	readControlOKForTest(t, third)
	_ = third.Close()
	<-thirdDone
	waitForTest(t, func() bool { return len(br.limits.parked) == 0 }, "reused parked slot release")
}

func TestStreamingSessionLimitRejectsPromptly(t *testing.T) {
	br := &broker{sessions: map[string]chan struct{}{}, sessionCtl: map[string]net.Conn{}}
	br.limits.sessions = make(chan struct{}, 1)
	if !br.limits.acquireSession() {
		t.Fatal("failed to occupy test session slot")
	}
	defer br.limits.releaseSession()

	clientEnd, serverEnd := net.Pipe()
	done := make(chan struct{})
	go func() {
		br.session(serverEnd, strings.NewReader(""), controlproto.Request{Op: "session", ID: "busy"})
		_ = serverEnd.Close()
		close(done)
	}()
	defer func() { _ = clientEnd.Close() }()
	line, err := controlproto.ReadBoundedLine(bufio.NewReader(clientEnd), controlproto.MaxEventBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(line), "too many active sessions") {
		t.Fatalf("session overload response = %s", strings.TrimSpace(string(line)))
	}
	<-done
	if got := len(br.limits.sessions); got != 1 {
		t.Fatalf("rejected session changed occupied slots to %d", got)
	}
	if _, _, err := br.oauthExec([]string{"true"}, time.Second); err == nil || !strings.Contains(err.Error(), "session limit") {
		t.Fatalf("OAuth overload error = %v, want shared session-limit rejection", err)
	}
}

func startSessionControlForTest(t *testing.T, br *broker, id string) (net.Conn, <-chan struct{}) {
	t.Helper()
	clientEnd, serverEnd := net.Pipe()
	done := make(chan struct{})
	go func() {
		br.sessionctl(serverEnd, serverEnd, controlproto.Request{Op: "sessionctl", ID: id, V: controlproto.SessionProtocolVersion})
		_ = serverEnd.Close()
		close(done)
	}()
	return clientEnd, done
}

func readControlOKForTest(t *testing.T, c net.Conn) {
	t.Helper()
	line, err := controlproto.ReadBoundedLine(bufio.NewReader(c), controlproto.MaxEventBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(line), `"ok":true`) {
		t.Fatalf("control response = %s", strings.TrimSpace(string(line)))
	}
}

func waitForTest(t *testing.T, ready func() bool, what string) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if ready() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", what)
		case <-ticker.C:
		}
	}
}
