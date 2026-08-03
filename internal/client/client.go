// Package client is the ttrpc control-plane client for the nerdbox guest
// agent (vminitd) running inside a gantry VM. It is shared by the hostctl
// binary (two-terminal/debug flow) and by `gantry exec` (single-command
// flow).
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

	"gantry/internal/image"
	"gantry/internal/shares"

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
	RPCSock     string       // unix socket accepting vminitd's vsock dial-back
	RPCListener net.Listener // pre-created RPCSock listener, when booting a VM
	StreamSock  string       // unix socket forwarding guest stream port 1026
	Share       bool         // mount every share from the VMM's shares.json
	RW          bool         // writable overlay root: erofs /dev/vdb + ext4 /dev/vdc
	Args        []string
	ID          string        // bundle/task id; default "shell"
	ImgCfg      *image.Config // resolved image config (nil = defaults)
	Secrets     []string      // NAME=value pairs, process-spec only (docs/secrets.md)
	// ExitStatus, when set, receives the task's exit status so one-shot
	// callers (`gantry exec -- false`) can propagate it as their own
	// exit code instead of reporting success for a failed command.
	ExitStatus *int
}

// ShareEntry is one entry of the VMM's shares.json (schema shared with
// internal/vmm via internal/shares).
type ShareEntry = shares.Entry

// LoadShareManifest reads the manifest gantry wrote next to the RPC socket.
// A missing or legacy manifest simply means "no hub transport".
func LoadShareManifest(dir string) shares.Manifest {
	b, err := os.ReadFile(filepath.Join(dir, "shares.json"))
	if err != nil {
		return shares.Manifest{}
	}
	var m shares.Manifest
	if json.Unmarshal(b, &m) != nil {
		return shares.Manifest{}
	}
	return m
}

// LoadShares reads the entries of the manifest gantry wrote next to the RPC
// socket. A missing manifest simply means "no shares".
func LoadShares(dir string) []ShareEntry {
	return LoadShareManifest(dir).Shares
}

// ListenRPC creates the host endpoint before a VM is started. vminitd makes
// a single vsock dial-back attempt, so the listener must exist before the
// guest can boot; otherwise a fast VM can lose the connection race.
func ListenRPC(rpcSock string) (net.Listener, error) {
	_ = os.Remove(rpcSock)
	ln, err := net.Listen("unix", rpcSock)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", rpcSock, err)
	}
	return ln, nil
}

// AcceptRPCListener waits for vminitd's vsock dial-back on a listener that was
// created before the VM started. The listener is closed after the connection
// is accepted (or on error).
func AcceptRPCListener(ln net.Listener, rpcSock string) (*ttrpc.Client, error) {
	defer ln.Close()
	fmt.Printf("client: listening on %s — start the VM now\n", rpcSock)
	conn, err := ln.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept: %w", err)
	}
	fmt.Println("client: guest connected over vsock dial-back")
	return ttrpc.NewClient(conn), nil
}

// AcceptRPC waits for vminitd's vsock dial-back and returns a ttrpc client.
// Callers that start a VM should use ListenRPC first to remove the startup
// race; this convenience wrapper preserves the original API for callers that
// start the VM elsewhere.
func AcceptRPC(rpcSock string) (*ttrpc.Client, error) {
	ln, err := ListenRPC(rpcSock)
	if err != nil {
		return nil, err
	}
	return AcceptRPCListener(ln, rpcSock)
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

// vminitd returns plain ttrpc "Unknown" errors — there are no typed
// error codes — so the recovery paths below match on message text.
// These are the strings vminitd / the OCI runtime / the kernel actually
// produce; keep every call site on these constants so the matching
// lives in exactly one place.
const (
	errTextBundleExists = "file exists"    // bundle.Create on a lingering /run/bundles/<id>
	errTextTaskExists   = "already exists" // task.Create for a live container
	errTextMountBusy    = "busy"           // single-instance erofs already mounted
	errTextMountInUse   = "in-use"         // overlay upperdir still referenced
)

// rwlayerHint appends actionable guidance when a Create failure smells
// like rwlayer corruption: ESTALE ("stale file handle") and EBADMSG
// ("bad message") are the mount errors a damaged ext4 produces (unclean
// VM shutdown — gantry stop is a power cut).
func rwlayerHint(err error, rw bool) string {
	if !rw || err == nil {
		return ""
	}
	if strings.Contains(err.Error(), "stale file handle") || strings.Contains(err.Error(), "bad message") {
		return "\n(the rwlayer looks corrupted — recreate it with ./scripts/mkrwlayer.sh artifacts/rwlayer.ext4 512, or e2fsck it)"
	}
	return ""
}

func errHas(err error, subs ...string) bool {
	for _, s := range subs {
		if strings.Contains(err.Error(), s) {
			return true
		}
	}
	return false
}

// ensureBundle uploads config.json for id and returns the bundle path.
// The bundle API is Create-only and vminitd never removes
// /run/bundles/<id>: after a container exits, the dir lingers, so a
// fresh Create would fail "file exists". reused=true means the old
// bundle — including the previous config.json, so args changes need a
// sandbox restart — is still in place.
func ensureBundle(ctx context.Context, client *ttrpc.Client, id string, cfg string, logf func(string, ...any)) (bundlePath string, reused bool, err error) {
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
		if !errHas(err, errTextBundleExists, errTextTaskExists) {
			return "", false, fmt.Errorf("bundle Create: %w", err)
		}
		b := "/run/bundles/" + id
		logf("reusing existing bundle at %s", b)
		return b, true, nil
	}
	logf("bundle created at %s", bresp.Bundle)
	return bresp.Bundle, false, nil
}

// mountShares exports the virtio-fs tags into the VM. Hub manifests mount
// one permanent transport; legacy manifests mount each per-share device.
func mountShares(ctx context.Context, mc mountapi.TTRPCMountService, entries []ShareEntry, transport *shares.Transport, logf func(string, ...any)) error {
	if transport != nil {
		if _, err := mc.MountAll(ctx, &mountapi.MountAllRequest{Mounts: []*mountapi.MountSpec{{
			Type: "virtiofs", Source: transport.Tag, Target: transport.VMPath,
		}}}); err != nil {
			if !errHas(err, errTextMountBusy) {
				return fmt.Errorf("mount virtio-fs share hub: %w", err)
			}
			logf("share hub %-6s already mounted at %s", transport.Tag, transport.VMPath)
		} else {
			logf("share hub %-6s %-28s -> %s", transport.Tag, "(dynamic)", transport.VMPath)
		}
		for _, s := range entries {
			mode := "rw"
			if s.RO {
				mode = "ro"
			}
			logf("share %-12s %-30s -> %s -> container %s (%s, %s)", s.Tag, s.Path, s.VMPath, s.CtrPath, mode, defaultShareState(s.State))
		}
		return nil
	}
	if len(entries) == 0 {
		return nil
	}
	specs := make([]*mountapi.MountSpec, 0, len(entries))
	for _, s := range entries {
		spec := &mountapi.MountSpec{Type: "virtiofs", Source: s.Tag, Target: s.VMPath}
		if s.RO {
			spec.Options = []string{"ro"}
		}
		specs = append(specs, spec)
	}
	if _, err := mc.MountAll(ctx, &mountapi.MountAllRequest{Mounts: specs}); err != nil {
		return fmt.Errorf("mount virtio-fs shares: %w", err)
	}
	for _, s := range entries {
		mode := "rw"
		if s.RO {
			mode = "ro"
		}
		logf("share %-12s %-30s -> %s -> container %s (%s)", s.Tag, s.Path, s.VMPath, s.CtrPath, mode)
	}
	return nil
}

func defaultShareState(state string) string {
	if state == "" {
		return "active"
	}
	return state
}

// unmountStack best-effort tears down a bundle's rootfs mount stack.
// Necessary because vminitd's task Delete unmounts only the overlay, and
// erofs is single-instance: a leftover mounts/0 makes the next Create
// fail EBUSY, and no RPC can remove it later.
func unmountStack(ctx context.Context, mc mountapi.TTRPCMountService, bundlePath string) {
	for _, target := range []string{
		bundlePath + "/rootfs",
		bundlePath + "/mounts/1",
		bundlePath + "/mounts/0",
	} {
		mc.Unmount(ctx, &mountapi.UnmountRequest{Target: target})
	}
}

// awaitRunning polls until task id is RUNNING — used after losing a
// Create race to a concurrent session, whose container is still coming
// up.
func awaitRunning(ctx context.Context, tc task.TTRPCTaskService, id string) bool {
	for range 50 {
		st, err := tc.State(ctx, &task.StateRequest{ID: id})
		if err == nil && st.Status == tasktypes.Status_RUNNING {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// awaitGone polls until task id no longer exists (Delete is async).
func awaitGone(ctx context.Context, tc task.TTRPCTaskService, id string) {
	for range 50 {
		if _, err := tc.State(ctx, &task.StateRequest{ID: id}); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// SessionOptions configures one container session over an established
// ttrpc connection (see Session). Progress messages go to the session's
// stdout.
type SessionOptions struct {
	StreamSock string
	Shares     []ShareEntry
	// ShareTransport, when non-nil, is the hub manifest's one virtio-fs
	// device. Shares are logical children beneath it and may change while
	// the sandbox runs.
	ShareTransport *shares.Transport
	RW             bool
	Args           []string
	ID             string
	Cols, Rows     uint32          // initial pty size; 0 skips ResizePty
	Terminal       bool            // allocate a pty; false uses pipe stdio
	KillCh         <-chan struct{} // optional: first receive SIGKILLs the task
	Quiet          bool            // suppress progress messages
	ExitStatus     *int            // optional: set to the task's exit status
	// ExecIntoExisting allows docker-exec semantics: when the task already
	// runs in the VM, start a new process inside it (task.v3 Exec)
	// instead of Create-ing a second container (which would fail — the rw
	// rootfs stack mounts exactly once).
	ExecIntoExisting bool
	// ImgCfg is the resolved OCI image config (env/entrypoint/cmd/user/
	// workdir). nil keeps the historical defaults.
	ImgCfg *image.Config
	// Secrets are NAME=value pairs injected into the session's process
	// spec ONLY (docs/secrets.md): they travel over ttrpc inside the
	// Exec request and are never written to any file, host or guest —
	// which is why one-shot sessions route through the Exec path rather
	// than the bundle (config.json persists inside the guest).
	Secrets []string
}

func init() {
	// typeurl.MarshalAny refuses unregistered types; register the OCI
	// process spec the same way containerd's client does (the TypeUrl is
	// cosmetic here — vminitd only json-unmarshals the Value).
	typeurl.Register(&specs.Process{}, "types.containerd.io", "opencontainers/runtime-spec", "1", "Process")
}

// resolveArgs implements the session command precedence: explicit
// -- CMD > image Entrypoint+Cmd > /bin/sh.
func resolveArgs(args []string, cfg *image.Config) []string {
	if eff := cfg.Command(args); len(eff) > 0 {
		return eff
	}
	return []string{"/bin/sh"}
}

// Session runs one container session to completion over an existing ttrpc
// connection: bundle upload, optional virtio-fs mounts, task create/start,
// stdio relay, wait, cleanup. Callers own the connection, the terminal, and
// the IO ends — this is what lets a sandbox daemon multiplex many sessions
// over the single dial-back connection vminitd makes (see dialBackListener:
// it dials once per VM lifetime).
func Session(client *ttrpc.Client, opts SessionOptions, stdin io.Reader, stdout io.Writer) error {
	// args precedence: explicit -- CMD > image Entrypoint+Cmd > /bin/sh
	opts.Args = resolveArgs(opts.Args, opts.ImgCfg)
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

	tc := task.NewTTRPCTaskClient(client)
	if opts.ExecIntoExisting {
		// Docker-sandbox semantics: the VM runs ONE long-lived container
		// (stub init) and every session is a task.v3 Exec into it.
		// Create happens exactly once per sandbox, so the single-instance
		// erofs rootfs stack is mounted exactly once and never needs
		// unmounting — vminitd's task Delete unmounts only the overlay,
		// leaving mounts/0,1 behind with no RPC able to remove them,
		// which made every re-Create fail EBUSY.
		if err := ensureSandboxContainer(client, tc, ctx, opts, logf); err != nil {
			return err
		}
		return sessionExec(client, tc, opts, id, stdin, stdout)
	}

	cfg, err := ConfigJSONWithTransport(shares, opts.ShareTransport, opts.RW, opts.Args, opts.ImgCfg)
	if err != nil {
		return err
	}

	// 1. upload the bundle (config.json) — vminitd writes it under
	//    /run/bundles/<id>/ and returns the path
	mountClient := mountapi.NewTTRPCMountClient(client)
	bundlePath, reused, err := ensureBundle(ctx, client, id, cfg, logf)
	if err != nil {
		return err
	}
	if reused {
		// A leftover rootfs stack can also survive (daemon crash,
		// killed session): erofs is single-instance, so a stale mount
		// makes the next Create fail EBUSY. Best-effort clear first.
		uctx, ucancel := context.WithTimeout(ctx, 5*time.Second)
		unmountStack(uctx, mountClient, bundlePath)
		ucancel()
	}

	if err := mountShares(ctx, mountClient, shares, opts.ShareTransport, logf); err != nil {
		return err
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
	// same lower/ro + upper/rw design as the reference rwlayer.img. The {{mount N}}
	// templates are resolved by the guest's mountutil against earlier
	// staged mounts.
	_, err = tc.Create(ctx, &task.CreateTaskRequest{
		ID:       id,
		Bundle:   bundlePath,
		Rootfs:   RootfsMounts(opts.RW),
		Terminal: opts.Terminal,
		Stdin:    "stream://" + stdinStream.id,
		Stdout:   "stream://" + stdoutStream.id,
	})
	if err != nil {
		// Lost the race with a concurrent session: it created the
		// container between our State probe and our Create — Exec into
		// the winner's container instead.
		if opts.ExecIntoExisting && errHas(err, errTextTaskExists) {
			return sessionExec(client, tc, opts, id, stdin, stdout)
		}
		// Two sessions can both miss the State probe and race into
		// Create; the loser gets EBUSY from the rootfs stack (its own
		// attempt mounted nothing — the failure is at the first mount).
		// Poll briefly: if the winner's task is up, Exec into it.
		if opts.ExecIntoExisting && errHas(err, errTextMountBusy, errTextMountInUse) && awaitRunning(ctx, tc, id) {
			logf("lost create race; attaching to the running container")
			return sessionExec(client, tc, opts, id, stdin, stdout)
		}
		// A failed Create leaves the bundle's rootfs stack mounted in the
		// VM; without cleanup the NEXT exec on this sandbox dies with
		// "upperdir is in-use"/busy. Best-effort teardown so a retry
		// works without restarting the sandbox.
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dcancel()
		tc.Delete(dctx, &task.DeleteRequest{ID: id})
		unmountStack(dctx, mountClient, bundlePath)
		return fmt.Errorf("task Create: %w%s\n(see the VM console for vminitd logs)", err, rwlayerHint(err, opts.RW))
	}
	logf("task created")
	if _, err := tc.Start(ctx, &task.StartRequest{ID: id}); err != nil {
		return fmt.Errorf("task Start: %w", err)
	}
	logf("task started — shell is live (type 'exit' to leave)")

	if opts.Terminal && opts.Cols > 0 && opts.Rows > 0 {
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
	dctx, dcancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer dcancel()
	tc.Delete(dctx, &task.DeleteRequest{ID: id})
	// Delete is asynchronous; the rootfs stack is only safe to unmount
	// once the task is really gone, and it MUST be unmounted: erofs is
	// single-instance, so a leftover mount makes the next Create fail
	// EBUSY ("device or resource busy" at mounts/0).
	awaitGone(dctx, tc, id)
	if opts.ShareTransport != nil {
		if _, err := mountClient.Unmount(dctx, &mountapi.UnmountRequest{Target: opts.ShareTransport.VMPath}); err != nil {
			fmt.Fprintf(stdout, "client: unmount share hub: %v\n", err)
		}
	} else {
		for i := len(shares) - 1; i >= 0; i-- {
			if _, err := mountClient.Unmount(dctx, &mountapi.UnmountRequest{Target: shares[i].VMPath}); err != nil {
				fmt.Fprintf(stdout, "client: unmount share %s: %v\n", shares[i].Tag, err)
			}
		}
	}
	unmountStack(dctx, mountClient, bundlePath)
	logf("done")
	return werr
}

// containerInitArgs is the long-lived stub a sandbox container runs as
// init (ExecIntoExisting mode). User sessions never touch it: they Exec
// their own processes in. It only dies when the sandbox (VM) stops.
// The stub uses null stdio and no terminal; tying its lifetime to a session
// pty makes it vulnerable to a hangup before the first Exec.
var containerInitArgs = []string{"/bin/sh", "-c", "while :; do sleep 86400; done"}

// ensureSandboxContainer makes sure the sandbox's long-lived container
// exists and is RUNNING, creating it (stub init) if not.
func ensureSandboxContainer(client *ttrpc.Client, tc task.TTRPCTaskService, ctx context.Context, opts SessionOptions, logf func(string, ...any)) error {
	id := opts.ID
	st, err := tc.State(ctx, &task.StateRequest{ID: id})
	if err == nil && st.Status == tasktypes.Status_RUNNING {
		return nil
	}
	if err == nil {
		// Stale task (e.g. its init was killed): remove and recreate.
		logf("task %s exists but is %s; recreating the sandbox container", id, st.Status)
		dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
		tc.Delete(dctx, &task.DeleteRequest{ID: id})
		awaitGone(dctx, tc, id)
		dcancel()
	}

	cfg, err := configJSONWithTransport(opts.Shares, opts.ShareTransport, opts.RW, containerInitArgs, nil, false)
	if err != nil {
		return err
	}
	bundlePath, _, err := ensureBundle(ctx, client, id, cfg, logf)
	if err != nil {
		return err
	}

	mountClient := mountapi.NewTTRPCMountClient(client)
	if err := mountShares(ctx, mountClient, opts.Shares, opts.ShareTransport, logf); err != nil {
		return err
	}

	_, err = tc.Create(ctx, &task.CreateTaskRequest{
		ID:       id,
		Bundle:   bundlePath,
		Rootfs:   RootfsMounts(opts.RW),
		Terminal: false,
	})
	if err != nil {
		if errHas(err, errTextTaskExists) {
			return nil // someone else won the create race
		}
		if errHas(err, errTextMountBusy, errTextMountInUse) && awaitRunning(ctx, tc, id) {
			return nil // lost the race; the winner's container is up
		}
		return fmt.Errorf("task Create: %w%s\n(see the VM console for vminitd logs)", err, rwlayerHint(err, opts.RW))
	}
	if _, err := tc.Start(ctx, &task.StartRequest{ID: id}); err != nil {
		return fmt.Errorf("task Start: %w", err)
	}
	logf("sandbox container %s is up (long-lived init; sessions attach as exec)", id)
	return nil
}

// sessionExec runs a session as a new process inside an already-running
// container (task.v3 Exec) — every `gantry exec <name>` takes this path.
// No bundle, no mounts, no Delete: the container and its lifecycle
// belong to the sandbox, not to any one session.
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
	uid, gid := opts.ImgCfg.IDs()
	proc := &specs.Process{
		Terminal: opts.Terminal,
		User:     specs.User{UID: uid, GID: gid},
		Args:     opts.Args,
		// No PS1 override: the image's own shell setup (or the shell's
		// compiled default) produces the familiar prompt; an injected
		// spartan PS1 read as "bash didn't start" to users.
		// Secrets come last: the user's explicit choice overrides an
		// image variable of the same name.
		Env: append(opts.ImgCfg.EnvWith("TERM=xterm"), opts.Secrets...),
		Cwd: opts.ImgCfg.WorkdirOr(),
	}
	specAny, err := typeurl.MarshalAny(proc)
	if err != nil {
		return err
	}
	specPB := &anypb.Any{TypeUrl: specAny.GetTypeUrl(), Value: specAny.GetValue()}
	if _, err := tc.Exec(ctx, &task.ExecProcessRequest{
		ID:       id,
		ExecID:   execID,
		Terminal: opts.Terminal,
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

	if opts.Terminal && opts.Cols > 0 && opts.Rows > 0 {
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

// sessionOptions builds the one-shot session. ImgCfg is propagated so
// the image's entrypoint/cmd/env/user/workdir actually apply (they were
// silently dropped when Shell pre-defaulted Args to /bin/sh — Session's
// image-aware resolution never saw an empty Args); Args stay untouched
// so Session can apply the image defaults.
func (opts ShellOptions) sessionOptions(shares []ShareEntry) SessionOptions {
	return SessionOptions{
		StreamSock: opts.StreamSock,
		Shares:     shares,
		RW:         opts.RW,
		Args:       opts.Args,
		ID:         opts.ID,
		ImgCfg:     opts.ImgCfg,
		Secrets:    opts.Secrets,
		ExitStatus: opts.ExitStatus,
		// One-shot sessions go through the same stub-init + Exec path as
		// sandbox sessions: the bundle's config.json persists inside the
		// guest for the VM's life, so it must never carry secrets (or
		// the image env — which was silently dropped here before).
		ExecIntoExisting: true,
	}
}

// Shell runs one interactive session as a one-shot client: accept the
// guest's dial-back, own the local terminal, and delegate to Session.
func Shell(opts ShellOptions) error {
	var shares []ShareEntry
	if opts.Share {
		shares = LoadShares(filepath.Dir(opts.RPCSock))
		if len(shares) == 0 {
			return fmt.Errorf("no shares exported by the VMM\n(start gantry with -share TAG=/absolute/host/path[,ro]; see shares.json next to the RPC socket)")
		}
	}

	var client *ttrpc.Client
	var err error
	if opts.RPCListener != nil {
		client, err = AcceptRPCListener(opts.RPCListener, opts.RPCSock)
	} else {
		client, err = AcceptRPC(opts.RPCSock)
	}
	if err != nil {
		return err
	}
	defer client.Close()

	sess := opts.sessionOptions(shares)
	sess.Terminal = term.IsTerminal(int(os.Stdin.Fd()))
	if sess.Terminal {
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

	err = Session(client, sess, os.Stdin, os.Stdout)
	if opts.RW {
		// Process exit is a power cut for the VM: flush the guest's
		// writable layer while the RPC connection is still held, or the
		// ext4 upper can be left mid-journal (review finding 5).
		id := sess.ID
		if id == "" {
			id = "shell" // Session's default bundle/task id
		}
		SyncGuest(client, opts.StreamSock, id, 5*time.Second)
	}
	return err
}

// SyncGuest asks the guest to flush its filesystems — "/bin/sync" exec'd
// inside the workload container — before the VM is torn down. This is
// the graceful half of VM shutdown (review finding 5): without it, stop
// is a power cut for persistent disks and a corrupt writable layer is
// the EXPECTED failure mode. Bounded by timeout; on expiry the sync
// process is SIGKILLed and the caller proceeds to forced termination.
// A no-op when the workload container never ran (nothing was mounted).
func SyncGuest(client *ttrpc.Client, streamSock, containerID string, timeout time.Duration) {
	tc := task.NewTTRPCTaskClient(client)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	st, err := tc.State(ctx, &task.StateRequest{ID: containerID})
	cancel()
	if err != nil || st.Status != tasktypes.Status_RUNNING {
		return
	}
	killCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		Session(client, SessionOptions{
			StreamSock:       streamSock,
			Args:             []string{"/bin/sync"},
			ID:               containerID,
			ExecIntoExisting: true,
			Quiet:            true,
			KillCh:           killCh,
		}, strings.NewReader(""), io.Discard)
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		close(killCh) // SIGKILLs the sync exec; the caller must not wait longer
	}
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
			// The nerdbox arm64 kernel builds with
			// CONFIG_OVERLAY_FS_INDEX=y, which makes "index" default
			// ON for every overlay mount — and index's origin
			// verification (exportfs fh decode of the upper root)
			// fails the whole mount with ESTALE when the rwlayer is
			// damaged or carries xattrs from a previous image pairing.
			// We need neither the inode index nor NFS export; pin
			// both index and xino off explicitly (x86_64 kernels
			// default them off already). gVisor's sentry ignores
			// unknown overlay options, so runsc is unaffected.
			"index=off",
			"xino=off",
		}},
	}
}

// ConfigJSON renders the OCI runtime config for a terminal shell container.
// img is the resolved image config (nil for direct .erofs files and for
// the stub init, which is gantry's process, not the image's): it drives
// env (image values win, gantry's are defaults-if-absent), the run user,
// and the working dir.
func ConfigJSON(shares []ShareEntry, rw bool, args []string, img *image.Config) (string, error) {
	return configJSONWithTransport(shares, nil, rw, args, img, true)
}

// ConfigJSONWithTransport renders a hub-aware config for sandbox tests and
// callers that have a versioned share manifest.
func ConfigJSONWithTransport(shares []ShareEntry, transport *shares.Transport, rw bool, args []string, img *image.Config) (string, error) {
	return configJSONWithTransport(shares, transport, rw, args, img, true)
}

// configJSON is also used for the sandbox's long-lived stub init. That
// process deliberately has null stdio and no terminal, so its lifetime is
// independent of any session pty.
func configJSON(shares []ShareEntry, rw bool, args []string, img *image.Config, terminal bool) (string, error) {
	return configJSONWithTransport(shares, nil, rw, args, img, terminal)
}

func configJSONWithTransport(shares []ShareEntry, transport *shares.Transport, rw bool, args []string, img *image.Config, terminal bool) (string, error) {
	cfg := `{
  "ociVersion": "1.1.0",
  "process": {
    "terminal": TERMINAL,
    "user": USERJSON,
    "args": ARGS,
    "env": ENVJSON,
    "cwd": CWDJSON,
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
	uid, gid := img.IDs()
	userJSON, _ := json.Marshal(struct {
		UID uint32 `json:"uid"`
		GID uint32 `json:"gid"`
	}{uid, gid})
	envJSON, _ := json.Marshal(img.EnvWith("TERM=xterm"))
	cwdJSON, _ := json.Marshal(img.WorkdirOr())
	rootRO := "true"
	if rw {
		rootRO = "false"
	}
	terminalJSON := "false"
	if terminal {
		terminalJSON = "true"
	}
	cfg = strings.NewReplacer("ARGS", string(argsJSON), "ROOTRO", rootRO,
		"TERMINAL", terminalJSON, "USERJSON", string(userJSON),
		"ENVJSON", string(envJSON), "CWDJSON", string(cwdJSON)).Replace(cfg)
	if transport == nil && len(shares) == 0 {
		return cfg, nil
	}
	var extra []string
	if transport != nil {
		// The hub binds make crun create their targets (/run/gantry/shares,
		// /host) inside the container rootfs, which is impossible on a
		// read-only root. Shares and live hot-add are writable-root-only;
		// on rw=false the hub stays guest-side so shareless RO boots work.
		if rw {
			extra = append(extra, hubShareMounts(shares, transport)...)
		}
	} else {
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
	}
	if len(extra) == 0 {
		return cfg, nil
	}
	const anchor = `    {"destination": "/etc/hosts", "type": "bind", "source": "/etc/hosts", "options": ["rbind","rprivate","ro"]}`
	return strings.Replace(cfg, anchor, anchor+",\n"+strings.Join(extra, ",\n"), 1), nil
}

// hubShareMounts binds the permanent hub into the long-lived sandbox
// container once. Logical shares are then just directory entries beneath
// /host, so live additions are visible to already-running processes.
func hubShareMounts(entries []ShareEntry, transport *shares.Transport) []string {
	if transport == nil {
		return nil
	}
	mount := func(destination, source string, ro bool) string {
		opts := `"rbind","rprivate"`
		if ro {
			opts += `,"ro"`
		}
		return fmt.Sprintf(`    {"destination": %q, "type": "bind", "source": %q, "options": [%s]}`, destination, source, opts)
	}
	joinVM := func(elem string) string {
		return strings.TrimRight(transport.VMPath, "/") + "/" + elem
	}
	var out []string
	// An internal stable path remains reachable even when a compatibility
	// alias covers /host.
	out = append(out, mount(shares.HubInternalPath, transport.VMPath, false))
	coverHost := false
	for _, s := range entries {
		ctr := s.CtrPath
		if ctr == "" {
			ctr = shares.HubHostPath + "/" + s.Tag
		}
		if ctr == shares.HubHostPath {
			coverHost = true
			break
		}
	}
	if !coverHost {
		out = append(out, mount(shares.HubHostPath, transport.VMPath, false))
	}
	for _, s := range entries {
		ctr := s.CtrPath
		if ctr == "" {
			ctr = shares.HubHostPath + "/" + s.Tag
		}
		// The hub-root bind already provides default paths. Explicit aliases
		// are separate binds so their RO flag is guest-enforced too.
		if ctr == shares.HubHostPath+"/"+s.Tag || ctr == shares.HubInternalPath+"/"+s.Tag {
			continue
		}
		out = append(out, mount(ctr, joinVM(s.Tag), s.RO))
	}
	return out
}
