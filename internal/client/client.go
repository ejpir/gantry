// Package client is the ttrpc control-plane client for the nerdbox guest
// agent (vminitd) running inside a gantry VM. It is shared by the hostctl
// binary (two-terminal/debug flow) and by `gantry exec` (single-command
// sbx-style flow).
package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/containerd/api/types"
	tasktypes "github.com/containerd/containerd/api/types/task"
	bundle "github.com/containerd/nerdbox/api/services/bundle/v1"
	mountapi "github.com/containerd/nerdbox/api/services/mount/v1"
	system "github.com/containerd/nerdbox/api/services/system/v1"
	"github.com/containerd/ttrpc"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/term"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ShellOptions configures one interactive container session.
type ShellOptions struct {
	RPCSock    string // unix socket accepting vminitd's vsock dial-back
	StreamSock string // unix socket forwarding guest stream port 1026
	Share      bool   // mount every share from the VMM's shares.json
	RW         bool   // writable overlay root: erofs /dev/vdb + ext4 /dev/vdc
	Args       []string
	ID         string // bundle/task id; default "shell"
}

// ShareEntry mirrors gantry's shareManifestEntry in shares.json.
type ShareEntry struct {
	Tag     string `json:"tag"`
	Path    string `json:"path"`
	RO      bool   `json:"ro,omitempty"`
	VMPath  string `json:"vmPath"`
	CtrPath string `json:"ctrPath"`
}

type shareManifest struct {
	Shares []ShareEntry `json:"shares"`
}

// LoadShares reads the manifest gantry wrote next to the RPC socket. A
// missing manifest simply means "no shares".
func LoadShares(rpcSock string) []ShareEntry {
	b, err := os.ReadFile(filepath.Join(filepath.Dir(rpcSock), "shares.json"))
	if err != nil {
		return nil
	}
	var m shareManifest
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m.Shares
}

// AcceptRPC waits for vminitd's vsock dial-back and returns a ttrpc client.
func AcceptRPC(rpcSock string) (*ttrpc.Client, error) {
	os.Remove(rpcSock)
	ln, err := net.Listen("unix", rpcSock)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", rpcSock, err)
	}
	defer ln.Close()
	fmt.Printf("client: listening on %s — start the VM now\n", rpcSock)
	conn, err := ln.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept: %w", err)
	}
	fmt.Println("client: guest connected over vsock dial-back")
	return ttrpc.NewClient(conn), nil
}

// Info queries the guest system service.
func Info(rpcSock string) error {
	client, err := AcceptRPC(rpcSock)
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := system.NewTTRPCSystemClient(client).Info(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("Info RPC: %w", err)
	}
	fmt.Println("client: Info RPC succeeded!")
	fmt.Printf("  vminitd version: %s\n", resp.Version)
	fmt.Printf("  kernel:          %s\n", resp.KernelVersion)
	return nil
}

// startStream opens one stream:// connection to the guest streaming service
// (vsock port 1026, forwarded by gantry to streamSock) and performs the
// length-prefixed stream-ID handshake from nerdbox's vsock-streaming doc.
func startStream(streamSock, id string) (net.Conn, error) {
	c, err := net.DialTimeout("unix", streamSock, 30*time.Second)
	if err != nil {
		return nil, err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(id)))
	if _, err := c.Write(append(hdr[:], id...)); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		c.Close()
		return nil, fmt.Errorf("stream %s: ack: %w", id, err)
	}
	ack := make([]byte, binary.BigEndian.Uint32(hdr[:]))
	if _, err := io.ReadFull(c, ack); err != nil {
		c.Close()
		return nil, fmt.Errorf("stream %s: ack body: %w", id, err)
	}
	if string(ack) != id {
		c.Close()
		return nil, fmt.Errorf("stream %s: rejected: %s", id, ack)
	}
	return c, nil
}

func streamID(prefix string) string {
	var b [4]byte
	rand.Read(b[:])
	return fmt.Sprintf("%s-%s", prefix, base64.RawURLEncoding.EncodeToString(b[:]))
}

// SessionOptions configures one container session over an established
// ttrpc connection (see Session). Progress messages go to the session's
// stdout.
type SessionOptions struct {
	StreamSock string
	Shares     []ShareEntry
	RW         bool
	Args       []string
	ID         string
	Cols, Rows uint32          // initial pty size; 0 skips ResizePty
	KillCh     <-chan struct{} // optional: first receive SIGKILLs the task
	Quiet      bool            // suppress progress messages
	ExitStatus *int            // optional: set to the task's exit status
	// ExecIntoExisting allows docker-exec semantics: when the task already
	// runs in the VM, start a new process inside it (task.v3 Exec)
	// instead of Create-ing a second container (which would fail — the rw
	// rootfs stack mounts exactly once).
	ExecIntoExisting bool
}

func init() {
	// typeurl.MarshalAny refuses unregistered types; register the OCI
	// process spec the same way containerd's client does (the TypeUrl is
	// cosmetic here — vminitd only json-unmarshals the Value).
	typeurl.Register(&specs.Process{}, "types.containerd.io", "opencontainers/runtime-spec", "1", "Process")
}

// Session runs one container session to completion over an existing ttrpc
// connection: bundle upload, optional virtio-fs mounts, task create/start,
// stdio relay, wait, cleanup. Callers own the connection, the terminal, and
// the IO ends — this is what lets a sandbox daemon multiplex many sessions
// over the single dial-back connection vminitd makes (see dialBackListener:
// it dials once per VM lifetime).
func Session(client *ttrpc.Client, opts SessionOptions, stdin io.Reader, stdout io.Writer) error {
	if len(opts.Args) == 0 {
		opts.Args = []string{"/bin/sh"}
	}
	if opts.ID == "" {
		opts.ID = "shell"
	}
	logf := func(format string, a ...any) {
		if !opts.Quiet {
			fmt.Fprintf(stdout, "client: "+format+"\n", a...)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	id := opts.ID
	shares := opts.Shares

	// Concurrent sessions must not each Create a container: the rw rootfs
	// stack (ext4 + overlay upperdir) can be mounted only once, so the
	// second Create dies with "upperdir is in-use"/EBUSY. Docker
	// semantics instead: if the task already runs in this VM, Exec a new
	// process into the SAME container (task.v3 Exec).
	tc := task.NewTTRPCTaskClient(client)
	if opts.ExecIntoExisting {
		if st, err := tc.State(ctx, &task.StateRequest{ID: id}); err == nil {
			if st.Status == tasktypes.Status_RUNNING {
				logf("task %s already running; attaching a new exec process", id)
				return sessionExec(client, tc, opts, id, stdin, stdout)
			}
			// Stale task left by a session that died without cleanup:
			// delete it so the Create below succeeds.
			logf("task %s exists but is %s; removing stale task", id, st.Status)
			dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
			tc.Delete(dctx, &task.DeleteRequest{ID: id})
			dcancel()
		}
	}

	cfg, err := ConfigJSON(shares, opts.RW, opts.Args)
	if err != nil {
		return err
	}

	// 1. upload the bundle (config.json) — vminitd writes it under
	//    /run/bundles/<id>/ and returns the path
	bresp, err := bundle.NewTTRPCBundleClient(client).Create(ctx, &bundle.CreateRequest{
		ID: id,
		Files: map[string][]byte{
			"config.json": []byte(cfg),
			// vminitd always loads this file after crun create. An empty
			// Networks list is the supported no-network configuration.
			"nw-config.json": []byte(`{"Networks":[]}`),
		},
	})
	if err != nil {
		// The bundle API is Create-only and vminitd never removes
		// /run/bundles/<id>: after a container exits, the dir lingers
		// and every later session failed here with "file exists".
		// Reusing it is fine — task Create rewrites what it needs.
		// (Caveat: the previous session's config.json stays, so args
		// changes across sessions need a sandbox restart.)
		if !strings.Contains(err.Error(), "file exists") && !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("bundle Create: %w", err)
		}
		bresp = &bundle.CreateResponse{Bundle: "/run/bundles/" + id}
		logf("reusing existing bundle at %s", bresp.Bundle)
	} else {
		logf("bundle created at %s", bresp.Bundle)
	}

	var mountClient mountapi.TTRPCMountService
	if len(shares) > 0 {
		mountClient = mountapi.NewTTRPCMountClient(client)
		specs := make([]*mountapi.MountSpec, 0, len(shares))
		for _, s := range shares {
			spec := &mountapi.MountSpec{Type: "virtiofs", Source: s.Tag, Target: s.VMPath}
			if s.RO {
				spec.Options = []string{"ro"}
			}
			specs = append(specs, spec)
		}
		if _, err := mountClient.MountAll(ctx, &mountapi.MountAllRequest{Mounts: specs}); err != nil {
			return fmt.Errorf("mount virtio-fs shares: %w", err)
		}
		for _, s := range shares {
			mode := "rw"
			if s.RO {
				mode = "ro"
			}
			logf("share %-12s %-30s -> %s -> container %s (%s)", s.Tag, s.Path, s.VMPath, s.CtrPath, mode)
		}
	}

	// 2. open stdio streams BEFORE Create so the guest can claim them
	type stream struct {
		id   string
		conn net.Conn
	}
	open := func(prefix string) (*stream, error) {
		s := &stream{id: streamID(prefix)}
		c, err := startStream(opts.StreamSock, s.id)
		if err != nil {
			return nil, err
		}
		s.conn = c
		return s, nil
	}
	stdinStream, err := open("stdin")
	if err != nil {
		return fmt.Errorf("stdin stream: %w", err)
	}
	defer stdinStream.conn.Close()
	stdoutStream, err := open("stdout")
	if err != nil {
		return fmt.Errorf("stdout stream: %w", err)
	}
	defer stdoutStream.conn.Close()

	// 3. create + start the task. Read-only mode mounts /dev/vdb (erofs)
	// directly; RW stacks an ext4 rwlayer over it with overlayfs — the
	// same lower/ro + upper/rw design as sbx's rwlayer.img. The {{mount N}}
	// templates are resolved by the guest's mountutil against earlier
	// staged mounts.
	_, err = tc.Create(ctx, &task.CreateTaskRequest{
		ID:       id,
		Bundle:   bresp.Bundle,
		Rootfs:   RootfsMounts(opts.RW),
		Terminal: true,
		Stdin:    "stream://" + stdinStream.id,
		Stdout:   "stream://" + stdoutStream.id,
	})
	if err != nil {
		// Lost the race with a concurrent session: it created the
		// container between our State probe and our Create — Exec into
		// the winner's container instead.
		if opts.ExecIntoExisting && strings.Contains(err.Error(), "already exists") {
			return sessionExec(client, tc, opts, id, stdin, stdout)
		}
		// A failed Create leaves the bundle's rootfs stack mounted in the
		// VM; without cleanup the NEXT exec on this sandbox dies with
		// "upperdir is in-use"/busy. Best-effort teardown so a retry
		// works without restarting the sandbox.
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dcancel()
		tc.Delete(dctx, &task.DeleteRequest{ID: id})
		if mountClient != nil {
			for _, target := range []string{
				bresp.Bundle + "/rootfs",
				bresp.Bundle + "/mounts/1",
				bresp.Bundle + "/mounts/0",
			} {
				mountClient.Unmount(dctx, &mountapi.UnmountRequest{Target: target})
			}
		}
		return fmt.Errorf("task Create: %w\n(see the VM console for vminitd logs)", err)
	}
	logf("task created")
	if _, err := tc.Start(ctx, &task.StartRequest{ID: id}); err != nil {
		return fmt.Errorf("task Start: %w", err)
	}
	logf("task started — shell is live (type 'exit' to leave)")

	if opts.Cols > 0 && opts.Rows > 0 {
		tc.ResizePty(ctx, &task.ResizePtyRequest{ID: id, Width: opts.Cols, Height: opts.Rows})
	}

	// 4. relay IO
	go io.Copy(stdinStream.conn, stdin)
	stdoutDone := make(chan struct{})
	go func() {
		io.Copy(stdout, stdoutStream.conn)
		close(stdoutDone)
	}()

	// a kill signal (ctrl-C in one-shot mode, daemon RPC in sandbox mode)
	// kills the task rather than just dropping the connection
	if opts.KillCh != nil {
		go func() {
			<-opts.KillCh
			tc.Kill(context.Background(), &task.KillRequest{ID: id, Signal: uint32(syscall.SIGKILL), All: true})
		}()
	}

	// 5. wait for exit, then clean up
	wctx := context.Background() // no deadline: wait as long as the shell lives
	resp, werr := tc.Wait(wctx, &task.WaitRequest{ID: id})
	// stdout CloseWrite is ordered before the guest's exit event; give the
	// relay a moment to drain the final bytes before printing host messages.
	select {
	case <-stdoutDone:
	case <-time.After(2 * time.Second):
	}
	if werr != nil {
		fmt.Fprintf(stdout, "\nclient: Wait: %v\n", werr)
	} else {
		fmt.Fprintf(stdout, "\nclient: task exited, status %d\n", resp.ExitStatus)
		if opts.ExitStatus != nil {
			*opts.ExitStatus = int(resp.ExitStatus)
		}
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	tc.Delete(dctx, &task.DeleteRequest{ID: id})
	if mountClient != nil {
		for i := len(shares) - 1; i >= 0; i-- {
			if _, err := mountClient.Unmount(dctx, &mountapi.UnmountRequest{Target: shares[i].VMPath}); err != nil {
				fmt.Fprintf(stdout, "client: unmount share %s: %v\n", shares[i].Tag, err)
			}
		}
	}
	logf("done")
	return werr
}

// sessionExec runs a session as a new process inside an already-running
// container (task.v3 Exec) — the second-and-later `gantry exec <name>`
// path. No bundle, no mounts, no Delete: the container and its lifecycle
// belong to the session that created it.
func sessionExec(client *ttrpc.Client, tc task.TTRPCTaskService, opts SessionOptions, id string, stdin io.Reader, stdout io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	logf := func(format string, a ...any) {
		if !opts.Quiet {
			fmt.Fprintf(stdout, "client: "+format+"\n", a...)
		}
	}

	// stdio streams, same protocol as Session
	open := func(prefix string) (net.Conn, string, error) {
		sid := streamID(prefix)
		c, err := startStream(opts.StreamSock, sid)
		return c, sid, err
	}
	stdinConn, stdinID, err := open("stdin")
	if err != nil {
		return fmt.Errorf("stdin stream: %w", err)
	}
	defer stdinConn.Close()
	stdoutConn, stdoutID, err := open("stdout")
	if err != nil {
		return fmt.Errorf("stdout stream: %w", err)
	}
	defer stdoutConn.Close()
	logf("exec: stdio streams open, sending Exec")

	execID := fmt.Sprintf("%s-exec-%d", id, time.Now().UnixNano())
	proc := &specs.Process{
		Terminal: true,
		User:     specs.User{UID: 0, GID: 0},
		Args:     opts.Args,
		Env:      []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "TERM=xterm", "PS1=exec# "},
		Cwd:      "/",
	}
	specAny, err := typeurl.MarshalAny(proc)
	if err != nil {
		return err
	}
	specPB := &anypb.Any{TypeUrl: specAny.GetTypeUrl(), Value: specAny.GetValue()}
	if _, err := tc.Exec(ctx, &task.ExecProcessRequest{
		ID:       id,
		ExecID:   execID,
		Terminal: true,
		Stdin:    "stream://" + stdinID,
		Stdout:   "stream://" + stdoutID,
		Spec:     specPB,
	}); err != nil {
		return fmt.Errorf("task Exec: %w", err)
	}
	// task.v3 is two-phase: Exec only registers the process; Start with
	// the ExecID is what actually spawns it. (Skipping Start was the
	// concurrent-exec hang: Wait blocked on a process that never ran.)
	if _, err := tc.Start(ctx, &task.StartRequest{ID: id, ExecID: execID}); err != nil {
		return fmt.Errorf("task Start(exec): %w", err)
	}
	logf("exec process started in container %s (type 'exit' to leave)", id)

	if opts.Cols > 0 && opts.Rows > 0 {
		tc.ResizePty(ctx, &task.ResizePtyRequest{ID: id, ExecID: execID, Width: opts.Cols, Height: opts.Rows})
	}

	go io.Copy(stdinConn, stdin)
	stdoutDone := make(chan struct{})
	go func() {
		io.Copy(stdout, stdoutConn)
		close(stdoutDone)
	}()
	if opts.KillCh != nil {
		go func() {
			<-opts.KillCh
			tc.Kill(context.Background(), &task.KillRequest{ID: id, ExecID: execID, Signal: uint32(syscall.SIGKILL)})
		}()
	}

	resp, werr := tc.Wait(context.Background(), &task.WaitRequest{ID: id, ExecID: execID})
	select {
	case <-stdoutDone:
	case <-time.After(2 * time.Second):
	}
	if werr != nil {
		fmt.Fprintf(stdout, "\nclient: Wait: %v\n", werr)
	} else {
		fmt.Fprintf(stdout, "\nclient: exec exited, status %d\n", resp.ExitStatus)
		if opts.ExitStatus != nil {
			*opts.ExitStatus = int(resp.ExitStatus)
		}
	}
	return werr
}

// Shell runs one interactive session as a one-shot client: accept the
// guest's dial-back, own the local terminal, and delegate to Session.
func Shell(opts ShellOptions) error {
	if len(opts.Args) == 0 {
		opts.Args = []string{"/bin/sh"}
	}
	var shares []ShareEntry
	if opts.Share {
		shares = LoadShares(opts.RPCSock)
		if len(shares) == 0 {
			return fmt.Errorf("no shares exported by the VMM\n(start gantry with -share TAG=/absolute/host/path[,ro]; see shares.json next to the RPC socket)")
		}
	}

	client, err := AcceptRPC(opts.RPCSock)
	if err != nil {
		return err
	}
	defer client.Close()

	sess := SessionOptions{
		StreamSock: opts.StreamSock,
		Shares:     shares,
		RW:         opts.RW,
		Args:       opts.Args,
		ID:         opts.ID,
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		old, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err == nil {
			defer term.Restore(int(os.Stdin.Fd()), old)
		}
		if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
			sess.Cols, sess.Rows = uint32(w), uint32(h)
		}
	}
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)
	defer signal.Stop(sigc)
	killCh := make(chan struct{})
	var killOnce sync.Once
	kill := func() { killOnce.Do(func() { close(killCh) }) }
	go func() { <-sigc; kill() }()
	sess.KillCh = killCh
	defer kill()

	return Session(client, sess, os.Stdin, os.Stdout)
}

// RootfsMounts describes how the guest assembles the container rootfs.
func RootfsMounts(rw bool) []*types.Mount {
	if !rw {
		return []*types.Mount{{Type: "erofs", Source: "/dev/vdb", Options: []string{"ro"}}}
	}
	return []*types.Mount{
		{Type: "erofs", Source: "/dev/vdb", Options: []string{"ro"}},
		{Type: "ext4", Source: "/dev/vdc", Options: []string{"rw"}},
		{Type: "format/overlay", Source: "overlay", Options: []string{
			"lowerdir={{mount 0}}",
			"upperdir={{mount 1}}/upper",
			"workdir={{mount 1}}/work",
		}},
	}
}

// ConfigJSON renders the OCI runtime config for the shell container.
func ConfigJSON(shares []ShareEntry, rw bool, args []string) (string, error) {
	cfg := `{
  "ociVersion": "1.1.0",
  "process": {
    "terminal": true,
    "user": {"uid": 0, "gid": 0},
    "args": ARGS,
    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "TERM=xterm", "PS1=container# "],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],
      "effective": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],
      "permitted": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"]
    },
    "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 65536, "soft": 65536}]
  },
  "root": {"path": "rootfs", "readonly": ROOTRO},
  "hostname": "nerdbox",
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid","strictatime","mode=755","size=65536k"]},
    {"destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid","noexec","newinstance","ptmxmode=0666","mode=0620"]},
    {"destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": ["nosuid","noexec","nodev","mode=1777","size=65536k"]},
    {"destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue", "options": ["nosuid","noexec","nodev"]},
    {"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid","noexec","nodev","ro"]},
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid","nodev","mode=1777"]},
    {"destination": "/etc/resolv.conf", "type": "bind", "source": "/etc/resolv.conf", "options": ["rbind","rprivate","ro"]},
    {"destination": "/etc/hosts", "type": "bind", "source": "/etc/hosts", "options": ["rbind","rprivate","ro"]}
  ],
  "linux": {
    "namespaces": [
      {"type": "pid"},
      {"type": "ipc"},
      {"type": "uts"},
      {"type": "mount"}
    ],
    "maskedPaths": ["/proc/acpi","/proc/asound","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/sys/firmware","/proc/scsi"],
    "readonlyPaths": ["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"]
  }
}`
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	rootRO := "true"
	if rw {
		rootRO = "false"
	}
	cfg = strings.NewReplacer("ARGS", string(argsJSON), "ROOTRO", rootRO).Replace(cfg)
	if len(shares) == 0 {
		return cfg, nil
	}
	var extra []string
	// Per-tag mountpoints live under /host. The container rootfs is
	// read-only EROFS, so put a tmpfs there when crun needs to create
	// subdirectories. (A lone "hostshare" binds at /host directly.)
	for _, s := range shares {
		if s.CtrPath != "/host" {
			extra = append(extra, `    {"destination": "/host", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid","nodev","rw"]}`)
			break
		}
	}
	for _, s := range shares {
		opts := `"rbind","rprivate"`
		if s.RO {
			opts += `,"ro"`
		}
		extra = append(extra, fmt.Sprintf(`    {"destination": %q, "type": "bind", "source": %q, "options": [%s]}`,
			s.CtrPath, s.VMPath, opts))
	}
	const anchor = `    {"destination": "/etc/hosts", "type": "bind", "source": "/etc/hosts", "options": ["rbind","rprivate","ro"]}`
	return strings.Replace(cfg, anchor, anchor+",\n"+strings.Join(extra, ",\n"), 1), nil
}
