package sandbox

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestValidSandboxName(t *testing.T) {
	for name, want := range map[string]bool{
		"dev": true, "my-sandbox_1.2": true, "": false,
		"has space": false, "slash/x": false, strings.Repeat("a", 65): false,
	} {
		if got := validSandboxName(name); got != want {
			t.Errorf("validSandboxName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestCleanupSandboxRuntimePreservesConfiguration(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"sandbox.json", "network-traffic.json", "vmm.pid", "ready", "ctl.sock", "shares.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cleanupSandboxRuntime(dir)
	for _, name := range []string{"sandbox.json", "network-traffic.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("persistent file %s was removed: %v", name, err)
		}
	}
	for _, name := range []string{"vmm.pid", "ready", "ctl.sock", "shares.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("runtime file %s still exists (err=%v)", name, err)
		}
	}
}

func TestSandboxPIDLifecycle(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	name := "testbox"
	if _, alive := sandboxPID(name); alive {
		t.Fatal("phantom sandbox")
	}
	os.MkdirAll(sandboxDir(name), 0o755)
	os.WriteFile(filepath.Join(sandboxDir(name), "vmm.pid"), []byte("99999999"), 0o644)
	if _, alive := sandboxPID(name); alive {
		t.Fatal("stale pid treated as alive")
	}
	os.WriteFile(filepath.Join(sandboxDir(name), "vmm.pid"), []byte(strconv.Itoa(os.Getpid())), 0o644)
	if _, alive := sandboxPID(name); !alive {
		t.Fatal("current process not detected as alive")
	}
}

func brokerPipe(t *testing.T, br *broker, req string) string {
	t.Helper()
	server, clientConn := net.Pipe()
	defer clientConn.Close()
	go br.handle(server)
	if _, err := clientConn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var resp map[string]any
	if err := json.NewDecoder(clientConn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

func TestBrokerKillUnknownSession(t *testing.T) {
	br := &broker{sessions: map[string]chan struct{}{}}
	if got := brokerPipe(t, br, `{"op":"kill","id":"nope"}`+"\n"); !strings.Contains(got, "no such session") {
		t.Fatalf("resp = %s", got)
	}
}

func TestBrokerKillExistingSession(t *testing.T) {
	killCh := make(chan struct{})
	br := &broker{sessions: map[string]chan struct{}{"s1": killCh}}
	if got := brokerPipe(t, br, `{"op":"kill","id":"s1"}`+"\n"); !strings.Contains(got, `"ok":true`) {
		t.Fatalf("resp = %s", got)
	}
	select {
	case <-killCh: // closed
	default:
		t.Fatal("kill channel not closed")
	}
	if _, ok := br.sessions["s1"]; ok {
		t.Fatal("session not removed from map")
	}
}

func TestBrokerBadRequest(t *testing.T) {
	br := &broker{sessions: map[string]chan struct{}{}}
	if got := brokerPipe(t, br, "not json\n"); !strings.Contains(got, "bad request") {
		t.Fatalf("resp = %s", got)
	}
}
