package sandbox

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/vmm"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/shares"

	"github.com/containerd/ttrpc"
	"golang.org/x/term"
)

// Sandbox lifecycle: create/start/stop/ls/delete + exec.
// A sandbox is a long-lived VMM daemon holding the single
// vsock dial-back ttrpc connection vminitd makes per VM lifetime
// (dialBackListener dials exactly once). `gantry exec <name>` is a thin
// client; the daemon multiplexes sessions over that one connection (ttrpc
// streams are independent, so concurrent exec sessions are fine).
//
// State per sandbox under ~/.gantry/sandboxes/<name>/:
//
//	sandbox.json      start configuration (images, rw, shares, net)
//	vmm.pid           daemon process id
//	ready             touched once the guest RPC connection is held
//	ctl.sock          session broker (JSON line, then raw stdio)
//	1025.sock         vsock dial-back accept target
//	listen-1026.sock  vsock stream listener
//	console.log       guest serial console
//	gvproxy.log       network backend log
//	daemon.log        daemon stdout/stderr

func sandboxRoot() string {
	if d := gutil.EnvOr("GANTRY_HOME", "MINIVM_HOME"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	newRoot := filepath.Join(home, ".gantry", "sandboxes")
	oldRoot := filepath.Join(home, ".minivm", "sandboxes")
	// one-time migration after the project rename
	if _, err := os.Stat(newRoot); os.IsNotExist(err) {
		if _, err := os.Stat(oldRoot); err == nil {
			os.MkdirAll(filepath.Dir(newRoot), 0o700)
			if err := os.Rename(oldRoot, newRoot); err == nil {
				fmt.Println("gantry: migrated sandboxes ~/.minivm -> ~/.gantry")
			}
		}
	}
	return newRoot
}

func sandboxDir(name string) string { return filepath.Join(sandboxRoot(), name) }

func validSandboxName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	// pure dots are path traversal (filepath.Join(root, "..") escapes the
	// sandbox root — and `delete` feeds the result to os.RemoveAll).
	if name == "." || name == ".." {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// ValidateSandboxName rejects names that are empty, overlong, pure dots
// (path traversal — `delete` feeds the joined path to os.RemoveAll) or
// contain anything but letters, digits and ._-. The CLI dispatch layer
// (main.go) turns the error into an exit code; the library itself never
// exits.
func ValidateSandboxName(name string) error {
	if !validSandboxName(name) {
		return fmt.Errorf("invalid sandbox name %q (letters, digits, ._-; not . or ..)", name)
	}
	return nil
}

func sandboxPID(name string) (int, bool) {
	b, err := os.ReadFile(filepath.Join(sandboxDir(name), "vmm.pid"))
	if err != nil {
		return 0, false
	}
	var pid int
	fmt.Sscanf(string(b), "%d", &pid)
	if pid <= 0 {
		return 0, false
	}
	if !procAlive(pid) {
		return pid, false // stale pid file
	}
	// A bare pid can be recycled by the OS into an unrelated process;
	// require the daemon's flock on vmm.lock as proof of life. Grace
	// window: between the spawner writing vmm.pid and the daemon
	// acquiring the lock, a fresh pid file alone counts as alive.
	if !sandboxLockHeld(sandboxDir(name)) {
		st, err := os.Stat(filepath.Join(sandboxDir(name), "vmm.pid"))
		if err != nil || time.Since(st.ModTime()) > 10*time.Second {
			return pid, false
		}
	}
	return pid, true
}

// ---------------- gantry start <name> [flags] ------------------------------

func CmdStart(argv []string) int {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	rf := RegisterRunFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: gantry start <name> [flags]   (name: letters, digits, ._-)

Create a long-lived sandbox VM running an OCI image; attach with
'gantry exec <name>' (docker-exec semantics, concurrent sessions OK).

examples:
  gantry start dev -image alpine:latest
  gantry start dev -image debian:bookworm-slim -cpus 2 -mem 1024
  gantry start dev -image ghcr.io/org/app@sha256:... -share code=$HOME/repos,ro
  gantry start agent -secret GITHUB_TOKEN -image python:3.12 -net-policy allow-github.json
  gantry start dev -runtime runsc -image alpine:latest
  gantry start dev -image ./my-rootfs.erofs

flags:`)
		fs.PrintDefaults()
	}
	if len(argv) > 0 && (argv[0] == "-h" || argv[0] == "--help") {
		fs.Usage()
		return 0
	}
	if len(argv) == 0 || strings.HasPrefix(argv[0], "-") || !validSandboxName(argv[0]) {
		fs.Usage()
		return 2
	}
	name, fargv := argv[0], argv[1:]

	rf.Name = name
	fs.Parse(fargv)
	cfg, warnings, err := rf.Resolve(fs, func(format string, a ...any) {
		fmt.Printf("gantry start: "+format+"\n", a...)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry start:", err)
		return 1
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "gantry start:", w)
	}
	secrets, _, err := rf.ResolveSecrets()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry start:", err)
		return 1
	}
	if len(secrets) > 0 && cfg.Net && cfg.NetPol == "" {
		fmt.Fprintf(os.Stderr, `gantry start: %d secret(s) injected with the default egress policy (internet
allowed). Consider -net-policy with a domain allowlist so an injected
agent cannot send them anywhere.
`, len(secrets))
	}

	return launchSandbox(name, cfg, secrets, true)
}

// CmdResume boots a stopped sandbox from its persisted configuration. The
// dashboard's Start action invokes the same CLI primitive asynchronously,
// avoiding duplicate daemon lifecycle code. Secret values are never persisted;
// configured names must be present in Gantry's current environment.
func CmdResume(name string) int {
	dir := sandboxDir(name)
	b, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry resume: sandbox %q has no saved configuration: %v\n", name, err)
		return 1
	}
	var cfg RunConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "gantry resume: sandbox %q has a corrupt configuration: %v\n", name, err)
		return 1
	}
	secrets := make(map[string]secret.Value, len(cfg.SecretNames))
	for _, secretName := range cfg.SecretNames {
		name, value, err := secret.Parse(secretName, os.LookupEnv)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry resume:", err)
			return 1
		}
		secrets[name] = value
	}
	return launchSandbox(name, cfg, secrets, false)
}

func launchSandbox(name string, cfg RunConfig, secrets map[string]secret.Value, replaceConfig bool) int {
	if _, alive := sandboxPID(name); alive {
		fmt.Fprintf(os.Stderr, "gantry start: sandbox %q is already running\n", name)
		return 1
	}

	dir := sandboxDir(name)
	if replaceConfig {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintln(os.Stderr, "gantry start:", err)
			return 1
		}
	}
	// 0700: the broker listens on ctl.sock with no authentication — the
	// directory mode is the entire access control between a local user
	// and a root shell inside the sandbox (plus its rw host shares).
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "gantry start:", err)
		return 1
	}
	cleanupSandboxRuntime(dir)
	if replaceConfig {
		b, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), b, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "gantry start:", err)
			return 1
		}
	} else {
		fmt.Printf("gantry start: using saved configuration for %q\n", name)
	}

	// Detached daemon: same binary, signed (this is why start goes through
	// scripts/run-macos.sh on macOS: build+codesign first).
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry start:", err)
		return 1
	}
	logf, err := os.Create(filepath.Join(dir, "daemon.log"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry start:", err)
		return 1
	}
	defer logf.Close()
	cmd := exec.Command(exe, "daemon", name)
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Stdin = strings.NewReader(secretsHandshakeJSON(secrets))
	detachDaemon(cmd)
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "gantry start: spawn daemon:", err)
		return 1
	}
	os.WriteFile(filepath.Join(dir, "vmm.pid"), []byte(fmt.Sprint(cmd.Process.Pid)), 0o600)
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	fmt.Printf("gantry start: sandbox %q booting (vmm pid %d)\n", name, cmd.Process.Pid)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if gutil.FileExists(filepath.Join(dir, "ready")) {
			fmt.Printf("gantry start: sandbox %q is up — attach with: gantry exec %s\n", name, name)
			return 0
		}
		select {
		case err := <-exited:
			fmt.Fprintf(os.Stderr, "gantry start: daemon exited during boot: %v\n", err)
			dumpTail(filepath.Join(dir, "console.log"))
			dumpTail(filepath.Join(dir, "daemon.log"))
			return 1
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "gantry start: timed out waiting for the guest RPC connection; see %s\n", dir)
	dumpTail(filepath.Join(dir, "console.log"))
	dumpTail(filepath.Join(dir, "daemon.log"))
	return 1
}

// ---------------- gantry daemon <name> (hidden, foreground) -----------------

func CmdDaemon(name string) int {
	// GANTRY_BOOT_TIMING=1: stamp boot phases into daemon.log so cold-boot
	// cost can be attributed (host setup vs. network vs. vmm.Prepare vs.
	// the guest boot up to the vsock dial-back). See scripts/bench-boot.sh.
	t0 := time.Now()
	bootLog := func(phase string) {
		if gutil.EnvOr("GANTRY_BOOT_TIMING") != "" {
			fmt.Fprintf(os.Stderr, "boot-timing: %-28s %8d ms\n", phase, time.Since(t0).Milliseconds())
		}
	}
	bootLog("daemon started")

	// the secrets handshake arrives on stdin before anything else
	secrets := readSecretsHandshake(os.Stdin)

	dir := sandboxDir(name)
	// tighten dirs created before the 0700 hardening (best-effort)
	os.Chmod(dir, 0o700)
	b, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon:", err)
		return 1
	}
	var cfg RunConfig
	if json.Unmarshal(b, &cfg) != nil {
		fmt.Fprintln(os.Stderr, "daemon: corrupt sandbox.json")
		return 1
	}
	if cfg.ImageDigest != "" && !gutil.FileExists(cfg.Image) {
		fmt.Fprintf(os.Stderr, "daemon: image %s not in cache; run `gantry image pull %s`\n", cfg.ImageDigest, cfg.ImageRef)
		return 1
	}

	// proof of life for sandboxPID: held until the process exits
	lock, err := holdSandboxLock(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon: another daemon holds the sandbox lock:", err)
		return 1
	}
	defer lock.Close()

	console, err := os.Create(filepath.Join(dir, "console.log"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon:", err)
		return 1
	}
	defer console.Close()

	nw, err := cfg.StartNetwork(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon:", err)
		return 1
	}
	defer nw.Close()
	bootLog("network up")
	if nw.Policy != nil {
		fmt.Fprintln(os.Stderr, "daemon: network policy:", nw.Policy.Describe())
	}

	configStore, err := LoadConfigStore(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon: config store:", err)
		return 1
	}
	shareManager, shareWarnings, err := NewShareManager(dir, configStore)
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon: shares:", err)
		return 1
	}
	defer shareManager.Close()
	for _, warning := range shareWarnings {
		fmt.Fprintln(os.Stderr, "daemon: shares:", warning)
	}
	portManager := NewPortManager(configStore, nw.Stack)

	var hostShares []vmm.Share
	if shareManager.Hub() == nil {
		hostShares, err = cfg.ParsedShares()
		if err != nil {
			fmt.Fprintln(os.Stderr, "daemon: bad share:", err)
			return 1
		}
	}
	opts, err := cfg.Opts(nw, hostShares, dir, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon:", err)
		return 1
	}
	opts.ShareHub = shareManager.Hub()
	opts.Console = console
	m, err := vmm.Prepare(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon:", err)
		return 1
	}
	bootLog("machine prepared (RAM+kernel)")
	if err := shareManager.Publish(); err != nil {
		fmt.Fprintln(os.Stderr, "daemon: share manifest:", err)
		return 1
	}

	// Create the RPC listener before booting: vminitd makes one dial-back
	// attempt, and a fast CI VM can otherwise beat net.Listen below.
	rpcSock := filepath.Join(dir, "1025.sock")
	rpcListener, err := client.ListenRPC(rpcSock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon:", err)
		return 1
	}

	guestErr := make(chan error, 1)
	go func() { guestErr <- vmm.Run(m) }()
	bootLog("vCPUs running; guest booting")

	// Hold the single dial-back connection for the VM's lifetime, while also
	// watching guestErr so a failed boot cannot leave CmdStart waiting for the
	// full timeout on a dead guest.
	type rpcResult struct {
		client *ttrpc.Client
		err    error
	}
	rpcCh := make(chan rpcResult, 1)
	go func() {
		rpc, err := client.AcceptRPCListener(rpcListener, rpcSock)
		rpcCh <- rpcResult{client: rpc, err: err}
	}()
	var rpc *ttrpc.Client
	select {
	case result := <-rpcCh:
		if result.err != nil {
			fmt.Fprintln(os.Stderr, "daemon:", result.err)
			return 1
		}
		rpc = result.client
	case err := <-guestErr:
		_ = rpcListener.Close()
		fmt.Fprintln(os.Stderr, "daemon: VM exited before guest RPC:", err)
		return 1
	}
	defer rpc.Close()
	os.WriteFile(filepath.Join(dir, "ready"), []byte("1\n"), 0o600)
	bootLog("guest RPC connected (READY)")
	fmt.Println("daemon: guest RPC connection held; broker on ctl.sock")

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)

	ln, err := net.Listen("unix", filepath.Join(dir, "ctl.sock"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon:", err)
		return 1
	}
	defer ln.Close()
	// Belt and braces under any umask: the 0700 dir is the real barrier,
	// but the socket inode should not be connectable on its own either
	// (Linux requires write permission on it; macOS consults the dir).
	_ = os.Chmod(filepath.Join(dir, "ctl.sock"), 0o600)

	br := &broker{
		cfg:        cfg,
		dir:        dir,
		rpc:        rpc,
		streamSock: filepath.Join(dir, "listen-1026.sock"),
		secrets:    secrets,
		store:      configStore,
		shares:     shareManager,
		ports:      portManager,
		netPolicy:  NewNetworkPolicyManager(configStore, nw.Policy, nw.Stack),
		sessions:   map[string]chan struct{}{},
	}
	go br.serve(ln)

	select {
	case s := <-sigc:
		fmt.Println("daemon: signal", s, "— shutting down")
		ln.Close() // no new broker sessions
		// Graceful stop (review finding 5): process exit is a power cut
		// for the guest, so flush while the RPC connection is still
		// held — guest filesystem sync first (bounded: the guest may be
		// wedged, and gantry stop escalates to SIGKILL), then host-side
		// device flush/close.
		client.SyncGuest(rpc, br.streamSock, "sb", 5*time.Second)
		// Stop an external gvproxy before closing the VM's packet socket;
		// otherwise its normal peer EOF is logged as an ERROR during teardown.
		if nw.Sock != "" {
			nw.CloseBackend()
		}
		if err := m.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "daemon: device shutdown:", err)
		}
		fmt.Println("daemon: shutdown complete")
		return 0
	case err := <-guestErr:
		fmt.Fprintln(os.Stderr, "daemon: VM exited:", err)
		return 1
	}
}

// broker accepts ctl connections. Protocol: one JSON request line, then
// (for "session") one JSON response line and the socket turns into raw
// bidirectional stdio until the task exits.
type broker struct {
	cfg        RunConfig
	dir        string
	rpc        *ttrpc.Client
	streamSock string
	store      *ConfigStore
	shares     *ShareManager
	ports      *PortManager
	netPolicy  *NetworkPolicyManager
	secrets    map[string]secret.Value // memory only, VM lifetime — never serialized

	mu       sync.Mutex
	sessions map[string]chan struct{}
}

// secretsHandshakeJSON renders the CLI→daemon handshake: one line of
// JSON on the daemon's stdin. Not argv (ps), not the environment
// (/proc/<pid>/environ persists), not a file (docs/secrets.md rule 1).
func secretsHandshakeJSON(secrets map[string]secret.Value) string {
	m := map[string]string{}
	for name, v := range secrets {
		m[name] = v.Raw() // the injection point
	}
	b, _ := json.Marshal(struct {
		Secrets map[string]string `json:"secrets"`
	}{m})
	return string(b) + "\n"
}

// readSecretsHandshake is the daemon side: read the one-line JSON object
// before anything else. A terminal stdin (manual `gantry daemon`) means
// no handshake; the deadline guards against a stalled pipe.
func readSecretsHandshake(r *os.File) map[string]secret.Value {
	st, err := r.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice != 0 {
		return nil
	}
	r.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(r).ReadBytes('\n')
	r.SetReadDeadline(time.Time{})
	if err != nil {
		return nil
	}
	var hs struct {
		Secrets map[string]string `json:"secrets"`
	}
	if json.Unmarshal(line, &hs) != nil {
		return nil
	}
	out := map[string]secret.Value{}
	for name, v := range hs.Secrets {
		out[name] = secret.Value(v)
	}
	return out
}

type brokerRequest struct {
	Op        string                      `json:"op"` // "session" | "kill" | "share.*" | "port.*" | "resources.set"
	ID        string                      `json:"id"`
	Args      []string                    `json:"args,omitempty"`
	Cols      uint32                      `json:"cols,omitempty"`
	Rows      uint32                      `json:"rows,omitempty"`
	Terminal  bool                        `json:"terminal,omitempty"`
	Share     *brokerShareRequest         `json:"share,omitempty"`
	Port      *brokerPortRequest          `json:"port,omitempty"`
	Resources *brokerResourceRequest      `json:"resources,omitempty"`
	NetPolicy *brokerNetworkPolicyRequest `json:"net_policy,omitempty"`
}

type brokerResourceRequest struct {
	MemMB uint `json:"mem_mb"`
	VCPUs int  `json:"vcpus"`
}

type brokerResourceResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type brokerShareRequest struct {
	Spec       string `json:"spec,omitempty"`
	Tag        string `json:"tag,omitempty"`
	Persistent bool   `json:"persistent"`
	Replace    bool   `json:"replace,omitempty"`
	Force      bool   `json:"force,omitempty"`
}

type brokerShareResponse struct {
	OK         bool           `json:"ok"`
	Error      string         `json:"error,omitempty"`
	Generation uint64         `json:"generation,omitempty"`
	Entry      *shares.Entry  `json:"entry,omitempty"`
	Shares     []shares.Entry `json:"shares,omitempty"`
}

type brokerPortRequest struct {
	Spec       string `json:"spec"`
	Persistent bool   `json:"persistent"`
}

type brokerPortResponse struct {
	OK    bool        `json:"ok"`
	Error string      `json:"error,omitempty"`
	Entry *PortEntry  `json:"entry,omitempty"`
	Ports []PortEntry `json:"ports,omitempty"`
}

func (br *broker) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// ctl.sock has no request authentication: the 0700 sandbox dir
		// plus this kernel-verified peer-UID check are the access
		// control, and the trust domain is the user account (a same-UID
		// process could present any credential we could issue — token or
		// TLS would be ceremony, not security). If this socket is EVER
		// relayed over TCP, real authentication (mTLS) is mandatory.
		if !peerSameUser(c) {
			fmt.Fprintln(os.Stderr, "daemon: rejected ctl.sock connection from a foreign UID")
			c.Close()
			continue
		}
		go br.handle(c)
	}
}

func (br *broker) handle(c net.Conn) {
	defer c.Close()
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return
	}
	var req brokerRequest
	if json.Unmarshal(line, &req) != nil || req.ID == "" {
		fmt.Fprintln(c, `{"error":"bad request"}`)
		return
	}
	switch req.Op {
	case "kill":
		br.mu.Lock()
		killCh, ok := br.sessions[req.ID]
		if ok {
			close(killCh)
			delete(br.sessions, req.ID)
		}
		br.mu.Unlock()
		if !ok {
			fmt.Fprintln(c, `{"error":"no such session"}`)
			return
		}
		fmt.Fprintln(c, `{"ok":true}`)
	case "share.add", "share.remove", "share.list", "share.configure":
		br.shareControl(c, req)
	case "port.publish", "port.unpublish", "port.list":
		br.portControl(c, req)
	case "resources.set":
		br.resourceControl(c, req)
	case "netpolicy.set", "netpolicy.get":
		br.networkPolicyControl(c, req)
	case "session":
		br.session(c, req)
	default:
		fmt.Fprintln(c, `{"error":"unknown op"}`)
	}
}

func (br *broker) resourceControl(c net.Conn, req brokerRequest) {
	respond := func(resp brokerResourceResponse) {
		_ = json.NewEncoder(c).Encode(&resp)
	}
	if br.store == nil {
		respond(brokerResourceResponse{Error: "config store unavailable"})
		return
	}
	if req.Resources == nil {
		respond(brokerResourceResponse{Error: "resource settings are required"})
		return
	}
	if err := br.store.SetResources(req.Resources.MemMB, req.Resources.VCPUs); err != nil {
		respond(brokerResourceResponse{Error: err.Error()})
		return
	}
	respond(brokerResourceResponse{OK: true})
}

func (br *broker) networkPolicyControl(c net.Conn, req brokerRequest) {
	respond := func(resp brokerNetworkPolicyResponse) {
		_ = json.NewEncoder(c).Encode(&resp)
	}
	if br.netPolicy == nil {
		respond(brokerNetworkPolicyResponse{Error: "network policy manager unavailable"})
		return
	}
	var entry NetworkPolicyEntry
	var err error
	if req.Op == "netpolicy.set" {
		if req.NetPolicy == nil {
			respond(brokerNetworkPolicyResponse{Error: "network policy settings are required"})
			return
		}
		entry, err = br.netPolicy.Set(req.NetPolicy.Path, req.NetPolicy.AllowLocal)
	} else {
		entry, err = br.netPolicy.Get()
	}
	if err != nil {
		respond(brokerNetworkPolicyResponse{Error: err.Error()})
		return
	}
	respond(brokerNetworkPolicyResponse{OK: true, Policy: &entry})
}

func (br *broker) shareControl(c net.Conn, req brokerRequest) {
	respond := func(resp brokerShareResponse) {
		_ = json.NewEncoder(c).Encode(&resp)
	}
	spec := brokerShareRequest{Persistent: true}
	if req.Share != nil {
		spec = *req.Share
	}
	var entry shares.Entry
	var err error
	if req.Op == "share.configure" {
		if br.store == nil {
			respond(brokerShareResponse{Error: "config store unavailable"})
			return
		}
		configured, configureErr := br.store.SetShareForRestart(spec.Spec, spec.Replace)
		if configureErr != nil {
			respond(brokerShareResponse{Error: configureErr.Error()})
			return
		}
		entry = shares.Entry{
			Tag: configured.Tag, Path: configured.Path, RO: configured.RO,
			UID: configured.UID, GID: configured.GID,
			VMPath:  shares.HubVMPath + "/" + configured.Tag,
			CtrPath: configuredShareTarget(configured), State: "restart",
		}
		respond(brokerShareResponse{OK: true, Entry: &entry})
		return
	}
	if br.shares == nil {
		respond(brokerShareResponse{Error: "share manager unavailable"})
		return
	}
	switch req.Op {
	case "share.add":
		entry, err = br.shares.Add(spec.Spec, spec.Persistent, spec.Replace)
	case "share.remove":
		entry, err = br.shares.Remove(spec.Tag, spec.Persistent, spec.Force)
	case "share.list":
		respond(brokerShareResponse{OK: true, Generation: br.shares.Generation(), Shares: br.shares.Entries()})
		return
	}
	if err != nil {
		respond(brokerShareResponse{Error: err.Error(), Generation: br.shares.Generation()})
		return
	}
	respond(brokerShareResponse{OK: true, Generation: br.shares.Generation(), Entry: &entry})
}

func (br *broker) portControl(c net.Conn, req brokerRequest) {
	respond := func(resp brokerPortResponse) {
		_ = json.NewEncoder(c).Encode(&resp)
	}
	if br.ports == nil {
		respond(brokerPortResponse{Error: "port manager unavailable"})
		return
	}
	spec := brokerPortRequest{Persistent: true}
	if req.Port != nil {
		spec = *req.Port
	}
	var entry PortEntry
	var err error
	switch req.Op {
	case "port.publish":
		entry, err = br.ports.Publish(spec.Spec, spec.Persistent)
	case "port.unpublish":
		entry, err = br.ports.Unpublish(spec.Spec, spec.Persistent)
	case "port.list":
		ports, lerr := br.ports.List()
		if lerr != nil {
			respond(brokerPortResponse{Error: lerr.Error()})
			return
		}
		respond(brokerPortResponse{OK: true, Ports: ports})
		return
	}
	if err != nil {
		respond(brokerPortResponse{Error: err.Error()})
		return
	}
	respond(brokerPortResponse{OK: true, Entry: &entry})
}

func (br *broker) session(c net.Conn, req brokerRequest) {
	killCh := make(chan struct{})
	br.mu.Lock()
	if _, dup := br.sessions[req.ID]; dup {
		br.mu.Unlock()
		fmt.Fprintln(c, `{"error":"duplicate session id"}`)
		return
	}
	br.sessions[req.ID] = killCh
	br.mu.Unlock()
	defer func() {
		br.mu.Lock()
		delete(br.sessions, req.ID)
		br.mu.Unlock()
	}()

	if _, err := fmt.Fprintln(c, `{"ok":true}`); err != nil {
		return
	}
	// no args defaulting here: client.Session applies the image's
	// Entrypoint+Cmd, then /bin/sh (the debian-filename heuristic that
	// used to live here predates image configs)
	manifest := client.LoadShareManifest(br.dir)
	var status int
	err := client.Session(br.rpc, client.SessionOptions{
		StreamSock:     br.streamSock,
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
	}, c, c)
	if err != nil {
		fmt.Fprintf(c, "\n[gantry] session error: %v\n", err)
		// The broker is the only process that still has the sandbox logs
		// while an attach client is connected. Include their tails in the
		// failure stream so CI and remote callers can diagnose guest boot
		// and daemon failures without guessing GANTRY_HOME.
		dumpTailTo(c, filepath.Join(br.dir, "daemon.log"))
		dumpTailTo(c, filepath.Join(br.dir, "console.log"))
	}
	// trailer for the attach client (cmdSandboxExec): the stream is raw at
	// this point, so frame the exit status between NULs — impossible to
	// confuse with terminal output.
	fmt.Fprintf(c, "\x00GANTRY-EXIT %d\x00", status)
}

// ---------------- gantry exec <name> [-- CMD] -------------------------------

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

	c, err := net.Dial("unix", filepath.Join(dir, "ctl.sock"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry exec: broker: %v\n", err)
		return 1
	}
	defer c.Close()

	id := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)
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
	line, err := r.ReadBytes('\n')
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

	if req.Terminal {
		if old, err := term.MakeRaw(int(os.Stdin.Fd())); err == nil {
			defer term.Restore(int(os.Stdin.Fd()), old)
		}
	}
	// ctrl-C: ask the broker to kill the task, keep the session attached.
	// Loop: every interrupt kills (a second ctrl-C is not swallowed).
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)
	defer signal.Stop(sigc)
	go func() {
		for range sigc {
			kc, err := net.Dial("unix", filepath.Join(dir, "ctl.sock"))
			if err == nil {
				json.NewEncoder(kc).Encode(&brokerRequest{Op: "kill", ID: id})
				kc.Close()
			}
		}
	}()

	done := make(chan struct{})
	go func() { io.Copy(c, os.Stdin) }()
	statusCh := make(chan int, 1)
	go func() {
		// r (not c): the handshake line came through the bufio reader.
		// Hold back a trailer's worth of tail bytes so the broker's
		// "\x00GANTRY-EXIT <n>\x00" marker can be stripped and parsed.
		statusCh <- copyStrippingExitTrailer(os.Stdout, r)
		close(done)
	}()
	<-done
	return <-statusCh
}

// exitTrailer frames the task's exit status at the end of a broker session
// stream (see broker.session). NULs can't appear in terminal output.
const exitTrailerPrefix = "\x00GANTRY-EXIT "

// maxExitStatusDigits bounds the decimal representation of a valid status:
// 10 digits cover int32, 19 cover int64 (strconv.IntSize is 32 or 64).
// Anything longer can never parse as a status, so parseExitTrailer rejects
// it — which also bounds how much guest output the hold buffer below may
// retain while waiting for the terminating NUL. A guest streaming
// "\x00GANTRY-EXIT " + digits forever must not grow host memory without
// limit (maxExitTrailerHold enforces the same ceiling at the buffer layer).
const maxExitStatusDigits = 10 + (strconv.IntSize-32)*9/32

// maxExitTrailerHold is the longest byte sequence that can still become a
// valid trailer; copyStrippingExitTrailer flushes anything held beyond it.
const maxExitTrailerHold = len(exitTrailerPrefix) + maxExitStatusDigits

// copyStrippingExitTrailer copies r to w, stripping the broker's exit-status
// trailer and returning the status (0 if absent). Bytes pass through
// UNHELD until a NUL arrives — NULs never appear in terminal output, so
// interactive per-character echo is not delayed (an earlier version held
// back 32 bytes unconditionally and broke exactly that).
func copyStrippingExitTrailer(w io.Writer, r io.Reader) int {
	var hold []byte // bytes since an undecided NUL; empty in the common case
	status := 0
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			data := append(hold, buf[:n]...)
			hold = nil
			if i := bytes.IndexByte(data, 0); i < 0 {
				w.Write(data)
			} else {
				w.Write(data[:i])
				hold = append([]byte(nil), data[i:]...)
				if len(hold) > maxExitTrailerHold {
					w.Write(hold) // provably never becomes a trailer
					hold = nil
				} else if st, ok, undecided := parseExitTrailer(hold); !undecided {
					if ok {
						status = st
					} else {
						w.Write(hold) // NUL turned out to be data
					}
					hold = nil
				}
			}
		}
		if err != nil {
			break
		}
	}
	// EOF: decide any remaining held bytes
	if len(hold) > 0 {
		if st, ok, _ := parseExitTrailer(hold); ok {
			status = st
		} else {
			w.Write(hold)
		}
	}
	return status
}

// parseExitTrailer inspects bytes starting with NUL: it returns (status,
// true, false) for a complete "\x00GANTRY-EXIT <n>\x00" trailer, (_, false,
// true) while b could still be a prefix of one, and (_, false, false) once
// b provably isn't one.
func parseExitTrailer(b []byte) (int, bool, bool) {
	magic := exitTrailerPrefix
	if len(b) < len(magic) {
		if string(b) == magic[:len(b)] {
			return 0, false, true // could still become the trailer
		}
		return 0, false, false
	}
	if string(b[:len(magic)]) != magic {
		return 0, false, false
	}
	rest := b[len(magic):]
	for i, c := range rest {
		if c == 0 {
			if i == 0 {
				return 0, false, false // "GANTRY-EXIT \x00" is not a status
			}
			v, err := strconv.Atoi(string(rest[:i]))
			if err != nil {
				return 0, false, false
			}
			return v, true, false
		}
		if c < '0' || c > '9' {
			return 0, false, false
		}
		if i+1 > maxExitStatusDigits {
			return 0, false, false // too many digits to ever parse as a status
		}
	}
	return 0, false, true // digits so far, terminator not seen yet
}

// ---------------- gantry ls / stop / delete ---------------------------------

func CmdLs() int {
	ents, err := os.ReadDir(sandboxRoot())
	if err != nil || len(ents) == 0 {
		fmt.Println("no sandboxes (create one with: gantry start <name>)")
		return 0
	}
	fmt.Printf("%-20s %-10s %-8s %-24s %s\n", "NAME", "STATE", "PID", "SECRETS", "IMAGE")
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		state, pidStr := "stopped", "-"
		if pid, alive := sandboxPID(name); alive {
			state, pidStr = "running", fmt.Sprint(pid)
		}
		image, secrets := "-", "-"
		if b, err := os.ReadFile(filepath.Join(sandboxDir(name), "sandbox.json")); err == nil {
			var cfg RunConfig
			if json.Unmarshal(b, &cfg) == nil {
				image = filepath.Base(cfg.Image)
				if cfg.RW {
					image += " (rw)"
				}
				if len(cfg.SecretNames) > 0 {
					secrets = strings.Join(cfg.SecretNames, ",")
				}
			}
		}
		fmt.Printf("%-20s %-10s %-8s %-24s %s\n", name, state, pidStr, secrets, image)
	}
	return 0
}

func CmdStop(name string) int {
	pid, alive := sandboxPID(name)
	if !alive {
		fmt.Fprintf(os.Stderr, "gantry stop: sandbox %q is not running\n", name)
		return 1
	}
	procTerminate(pid)
	// Grace window: the daemon's shutdown path syncs the guest and
	// flushes devices (bounded internally at ~5s) — give it room before
	// escalating to a power cut (review finding 5).
	for i := 0; i < 120; i++ {
		if !procAlive(pid) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if procAlive(pid) {
		procKill(pid)
	}
	// kill the sandbox's gvproxy too (defers don't run if the daemon was
	// SIGKILLed, orphaning it)
	dir := sandboxDir(name)
	if b, err := os.ReadFile(filepath.Join(dir, "gvproxy.pid")); err == nil {
		var gpid int
		if fmt.Sscanf(string(b), "%d", &gpid); gpid > 0 {
			procKill(gpid)
		}
	}
	// Clean runtime files; sandbox.json stays so CmdResume and the dashboard
	// can boot the same VM configuration again.
	cleanupSandboxRuntime(dir)
	fmt.Printf("gantry stop: sandbox %q stopped\n", name)
	return 0
}

func cleanupSandboxRuntime(dir string) {
	for _, f := range []string{"vmm.pid", "gvproxy.pid", "ready", "ctl.sock", "1025.sock", "listen-1026.sock", "net.sock", "net.sock.client", "gvproxy-api.sock", "shares.json"} {
		_ = os.Remove(filepath.Join(dir, f))
	}
}

func CmdDelete(name string) int {
	if _, alive := sandboxPID(name); alive {
		if rc := CmdStop(name); rc != 0 {
			return rc
		}
	}
	if err := os.RemoveAll(sandboxDir(name)); err != nil {
		fmt.Fprintln(os.Stderr, "gantry delete:", err)
		return 1
	}
	forgetRWLayer(name)
	fmt.Printf("gantry delete: sandbox %q deleted\n", name)
	return 0
}

// ---------------- shared helpers ---------------------------------------------

func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func dumpTail(path string) {
	dumpTailTo(os.Stderr, path)
}

func dumpTailTo(w io.Writer, path string) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return
	}
	if len(b) > 4096 {
		b = b[len(b)-4096:]
	}
	fmt.Fprintf(w, "---- last bytes of %s ----\n%s\n----\n", filepath.Base(path), b)
}
