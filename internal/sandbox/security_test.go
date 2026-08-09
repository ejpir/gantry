package sandbox

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// Sandbox names feed filepath.Join + os.RemoveAll: path traversal out of the
// sandbox root must be rejected before any subcommand sees the name.
func TestSandboxNameTraversal(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "../victim", "a/b", `a\b`, "a b", "a\u0000b"} {
		if validSandboxName(bad) {
			t.Fatalf("validSandboxName(%q) = true", bad)
		}
	}
	for _, good := range []string{"dev", "my-vm.2_test", "..ok"} {
		if !validSandboxName(good) {
			t.Fatalf("validSandboxName(%q) = false", good)
		}
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
	if brokerEvent.Exit != sessionAbnormalExitCode || brokerEvent.Error == "" {
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
	if got := sessionExitCode(ev); got != sessionAbnormalExitCode {
		t.Fatalf("exit = %d, want abnormal exit %d", got, sessionAbnormalExitCode)
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
		br.sessionctl(serverEnd, brokerRequest{Op: "sessionctl", ID: "s1", V: sessionProtocolVersion})
		close(handlerDone)
	}()
	r := bufio.NewReader(clientEnd)
	line, err := r.ReadBytes('\n')
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
		br.mu.Lock()
		taken := br.sessionCtl["s1"]
		delete(br.sessionCtl, "s1")
		br.mu.Unlock()
		if taken == nil {
			return
		}
		if err := json.NewEncoder(taken).Encode(&sessionExitEvent{V: sessionProtocolVersion, Exit: 7}); err != nil {
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
	go br.sessionctl(serverEnd, brokerRequest{Op: "sessionctl", ID: "s1", V: 0})
	line, err := bufio.NewReader(clientEnd).ReadBytes('\n')
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
	go br.session(serverEnd, brokerRequest{Op: "session", ID: "s1"})
	line, err := bufio.NewReader(clientEnd).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(line), "no session control channel") {
		t.Fatalf("response = %s, want control-channel refusal", strings.TrimSpace(string(line)))
	}
	br.mu.Lock()
	defer br.mu.Unlock()
	if len(br.sessions) != 0 {
		t.Fatal("refused session registered a kill channel")
	}
}
