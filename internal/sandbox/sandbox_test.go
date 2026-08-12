package sandbox

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
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
	for _, name := range []string{"sandbox.json", "network-traffic.json", "vmm.pid", "ready", daemonReadySocketName, "ctl.sock", "shares.json"} {
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
	for _, name := range []string{"vmm.pid", "ready", daemonReadySocketName, "ctl.sock", "shares.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("runtime file %s still exists (err=%v)", name, err)
		}
	}
}

func TestDaemonReadyNotification(t *testing.T) {
	ready, err := newDaemonReadyListener(t.TempDir())
	if err != nil {
		t.Skipf("local readiness sockets unavailable: %v", err)
	}
	defer ready.Close()

	if err := notifyDaemonReady(ready.path); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ready.result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for readiness event")
	}
}

func TestDaemonReadyNotificationDisabled(t *testing.T) {
	if err := notifyDaemonReady(""); err != nil {
		t.Fatal(err)
	}
}

func TestSandboxPIDLifecycle(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	name := "testbox"
	if _, alive := sandboxPID(name); alive {
		t.Fatal("phantom sandbox")
	}
	_ = os.MkdirAll(sandboxDir(name), 0o755)
	_ = os.WriteFile(filepath.Join(sandboxDir(name), "vmm.pid"), []byte("99999999"), 0o644)
	if _, alive := sandboxPID(name); alive {
		t.Fatal("stale pid treated as alive")
	}
	_ = os.WriteFile(filepath.Join(sandboxDir(name), "vmm.pid"), []byte(strconv.Itoa(os.Getpid())), 0o644)
	if _, alive := sandboxPID(name); !alive {
		t.Fatal("current process not detected as alive")
	}
}

func brokerPipe(t *testing.T, br *broker, req string) string {
	t.Helper()
	server, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	go br.handle(server)
	if _, err := clientConn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
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

func TestBrokerSetResources(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, RunConfig{MemMB: 512, VCPUs: 1})
	br := &broker{store: store, sessions: map[string]chan struct{}{}}
	vcpus := 3
	request := `{"op":"resources.set","id":"edit","resources":{"mem_mb":2048,"vcpus":3}}` + "\n"
	if runtime.GOOS == "windows" {
		vcpus = 1
		request = `{"op":"resources.set","id":"edit","resources":{"mem_mb":2048,"vcpus":1}}` + "\n"
	}
	if got := brokerPipe(t, br, request); !strings.Contains(got, `"ok":true`) {
		t.Fatalf("resp = %s", got)
	}
	cfg, err := readSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MemMB != 2048 || cfg.VCPUs != vcpus {
		t.Fatalf("resources = %d MiB/%d CPU", cfg.MemMB, cfg.VCPUs)
	}
}

func TestBrokerConfiguresShareForRestart(t *testing.T) {
	dir := t.TempDir()
	host := filepath.Join(dir, "host")
	if err := os.Mkdir(host, 0o700); err != nil {
		t.Fatal(err)
	}
	store := newTestConfigStore(t, dir, RunConfig{})
	manager, _, err := NewShareManager(dir, store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	br := &broker{store: store, shares: manager, sessions: map[string]chan struct{}{}}
	req := brokerRequest{
		Op: "share.configure", ID: "mount",
		Share: &brokerShareRequest{Spec: "code=" + host + "@/workspace", Persistent: true},
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	got := brokerPipe(t, br, string(raw)+"\n")
	if !strings.Contains(got, `"ok":true`) || !strings.Contains(got, `"ctrPath":"/workspace"`) {
		t.Fatalf("resp = %s", got)
	}
	if saved := store.Snapshot().Shares; len(saved) != 1 || !strings.Contains(saved[0], "@/workspace") {
		t.Fatalf("saved shares = %v", saved)
	}
}
