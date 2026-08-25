package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/shares"

	v3 "github.com/containerd/containerd/api/runtime/task/v3"
	tasktypes "github.com/containerd/containerd/api/types/task"
	bundle "github.com/containerd/nerdbox/api/services/bundle/v1"
	mountapi "github.com/containerd/nerdbox/api/services/mount/v1"
	"github.com/containerd/ttrpc"
	"github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	errTextBundleExists = "file exists"
	errTextTaskExists   = "already exists"
	errTextMountBusy    = "busy"
	errTextMountInUse   = "in-use"
)

// SessionOptions configures one container session over an established ttrpc
// connection. Callers retain ownership of the connection and IO endpoints.
// WindowSize is a terminal size update supplied by protocol frontends such
// as the SSH gateway.
type WindowSize struct {
	Cols uint32
	Rows uint32
}

type SessionOptions struct {
	StreamSock string
	// StreamDial replaces the Unix forwarding path in split-worker mode.
	StreamDial func() (net.Conn, error)
	Shares     []ShareEntry
	// ShareTransport is the persistent sandbox's multiplexed hub. Nil selects
	// the direct-run per-device protocol.
	ShareTransport *shares.Transport
	RW             bool
	// LayerSet replaces the flattened image with native multi-device EROFS.
	LayerSet   *LayerSet
	Args       []string
	ID         string
	Cols, Rows uint32
	Terminal   bool
	// Resize carries terminal-size changes after process start. Nil means the
	// initial Cols/Rows are the only size request.
	Resize <-chan WindowSize
	KillCh <-chan struct{}
	Quiet  bool
	// ExitStatus receives a successfully waited process's numeric status.
	ExitStatus *int
	// SandboxSession shares the persistent sandbox rootfs while giving this
	// command an isolated task and PID namespace.
	SandboxSession bool
	// ImgCfg provides the image environment, user, command, and default working dir.
	ImgCfg *image.Config
	// Cwd overrides the image working directory for this process. It is a guest
	// path and is used by programmatic exec clients; empty preserves ImgCfg.
	Cwd string
	// Secrets enter only an ephemeral session config that vminitd scrubs
	// before starting untrusted code.
	Secrets []string
	// Environment contains non-secret runtime overrides. It is applied to the
	// persistent base and each isolated session, after image variables and Secrets.
	Environment []string
	// PathPrepend prepends guest directories to the process PATH (after the
	// image value, before replacements) — used to expose /run/gantry/bin
	// when guest tools are installed, without clobbering the image PATH.
	PathPrepend []string
}

func resolveArgs(args []string, config *image.Config) []string {
	if resolved := config.Command(args); len(resolved) != 0 {
		return resolved
	}
	return []string{"/bin/sh"}
}

func errHas(err error, fragments ...string) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	for _, fragment := range fragments {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}

// taskCreateMayHaveCommitted distinguishes a server response from a transport
// failure. A response that reports an existing task also means this setup may
// have reused an idempotent share mount. In either case, destructive rollback
// cannot prove that the resources are unrelated to a live task.
func taskCreateMayHaveCommitted(err error) bool {
	if errHas(err, errTextTaskExists, errTextMountBusy, errTextMountInUse) {
		return true
	}
	_, acknowledged := status.FromError(err)
	return !acknowledged
}

func rwlayerHint(err error, rw bool) string {
	if !rw || err == nil {
		return ""
	}
	if errHas(err, "stale file handle", "bad message") {
		return "\n(the rwlayer looks corrupted — recreate it with ./scripts/mkrwlayer.sh artifacts/rwlayer.ext4 512, or e2fsck it)"
	}
	return ""
}

func ensureBundle(ctx context.Context, client *ttrpc.Client, id, config string, logf func(string, ...any)) (bundlePath string, reused bool, err error) {
	response, err := bundle.NewTTRPCBundleClient(client).Create(ctx, &bundle.CreateRequest{
		ID: id,
		Files: map[string][]byte{
			"config.json":    []byte(config),
			"nw-config.json": []byte(`{"Networks":[]}`),
		},
	})
	if err != nil {
		if !errHas(err, errTextBundleExists, errTextTaskExists) {
			return "", false, fmt.Errorf("bundle Create: %w", err)
		}
		path := "/run/bundles/" + id
		logf("reusing existing bundle at %s", path)
		return path, true, nil
	}
	logf("bundle created at %s", response.Bundle)
	return response.Bundle, false, nil
}

func unmountStack(ctx context.Context, client mountapi.TTRPCMountService, bundlePath string) {
	for _, target := range []string{
		bundlePath + "/rootfs",
		bundlePath + "/mounts/1",
		bundlePath + "/mounts/0",
	} {
		_, _ = client.Unmount(ctx, &mountapi.UnmountRequest{Target: target})
	}
}

func awaitRunning(ctx context.Context, client v3.TTRPCTaskService, id string) bool {
	return awaitTask(ctx, client, id, taskRunning)
}

func awaitGone(ctx context.Context, client v3.TTRPCTaskService, id string) {
	_ = awaitTask(ctx, client, id, taskGone)
}

type taskCondition uint8

const (
	taskRunning taskCondition = iota
	taskGone
)

func awaitTask(ctx context.Context, client v3.TTRPCTaskService, id string, condition taskCondition) bool {
	for range 50 {
		state, err := client.State(ctx, &v3.StateRequest{ID: id})
		reached := condition == taskGone && err != nil
		if condition == taskRunning {
			reached = err == nil && state.Status == tasktypes.Status_RUNNING
		}
		if reached {
			return true
		}
		if !sleepContext(ctx, 100*time.Millisecond) {
			return false
		}
	}
	return false
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func cleanupContainer(ctx context.Context, taskClient v3.TTRPCTaskService, mountClient mountapi.TTRPCMountService, options SessionOptions, bundlePath string, unmountOwnedShares bool, report func(string, ...any)) error {
	if _, err := taskClient.Delete(ctx, &v3.DeleteRequest{ID: options.ID}); err != nil {
		return fmt.Errorf("task Delete: %w", err)
	}
	if !awaitTask(ctx, taskClient, options.ID, taskGone) {
		return fmt.Errorf("task %q did not disappear after Delete", options.ID)
	}
	if unmountOwnedShares {
		unmountShares(ctx, mountClient, options.Shares, options.ShareTransport, report)
	}
	unmountStack(ctx, mountClient, bundlePath)
	return nil
}

const (
	guestBundleService            = "containerd.vminitd.services.bundle.v1.Bundle"
	runtimeStdioPassthroughMarker = "io.gantry.runtime-stdio-passthrough"
)

func callGuestBundle(ctx context.Context, client *ttrpc.Client, method, id string) error {
	var response emptypb.Empty
	if err := client.Call(ctx, guestBundleService, method, &bundle.CreateRequest{ID: id}, &response); err != nil {
		return fmt.Errorf("bundle %s: %w", method, err)
	}
	return nil
}

// mountSetup owns only share mounts established by this setup attempt. Commit
// hands them to the task lifecycle; otherwise rollback uses an independent
// bounded context because the setup context is often the reason setup failed.
type mountSetup struct {
	client    mountapi.TTRPCMountService
	options   SessionOptions
	owned     bool
	committed bool
}

func beginMountSetup(ctx context.Context, client mountapi.TTRPCMountService, options SessionOptions, logf func(string, ...any)) (*mountSetup, error) {
	setup := &mountSetup{client: client, options: options}
	var err error
	setup.owned, err = mountShares(ctx, client, options.Shares, options.ShareTransport, logf)
	if err != nil {
		setup.rollback()
		return nil, err
	}
	return setup, nil
}

func (s *mountSetup) commit() { s.committed = true }

func (s *mountSetup) rollback() {
	if s == nil || s.committed {
		return
	}
	s.committed = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if s.owned {
		unmountShares(ctx, s.client, s.options.Shares, s.options.ShareTransport, func(string, ...any) {})
	}
}

func sessionKillRequest(id string) *v3.KillRequest {
	return &v3.KillRequest{ID: id, Signal: uint32(syscall.SIGKILL), All: true}
}

func runtimeStdioPassthroughConfig(encoded string) (string, error) {
	var config runtimeConfig
	if err := json.Unmarshal([]byte(encoded), &config); err != nil {
		return "", fmt.Errorf("decode runtime stdio config: %w", err)
	}
	if config.Annotations == nil {
		config.Annotations = make(map[string]string)
	}
	// crunshim normally captures runtime diagnostics so runsc's parked
	// infrastructure processes cannot retain a pipe and wedge Create. A
	// non-terminal workload task uses those same descriptors for process IO,
	// however, and therefore needs explicit passthrough.
	config.Annotations[runtimeStdioPassthroughMarker] = "true"
	result, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("encode runtime stdio config: %w", err)
	}
	return string(result), nil
}

func isolatedSessionConfig(encoded string, options SessionOptions) (string, error) {
	var config runtimeConfig
	if err := json.Unmarshal([]byte(encoded), &config); err != nil {
		return "", fmt.Errorf("decode isolated session config: %w", err)
	}
	config.Process.Env = prependPath(
		processEnvironment(options.ImgCfg, options.Secrets, options.Environment),
		options.PathPrepend,
	)
	// The recursively bind-mounted sandbox rootfs already includes the base
	// container's /tmp mount. Mounting a new tmpfs here would give every exec
	// a private, empty /tmp and break persistent-sandbox semantics across
	// sessions. Namespace-specific mounts such as /proc and /dev remain fresh.
	mounts := config.Mounts[:0]
	for _, mount := range config.Mounts {
		if mount.Destination != "/tmp" {
			mounts = append(mounts, mount)
		}
	}
	config.Mounts = mounts
	result, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("encode isolated session config: %w", err)
	}
	return string(result), nil
}

// Session runs one container session through bundle creation, share mounting,
// task lifecycle, and stream relay.
func Session(client *ttrpc.Client, options SessionOptions, stdin io.Reader, stdout io.Writer) (resultErr error) {
	options.Args = resolveArgs(options.Args, options.ImgCfg)
	if options.ID == "" {
		options.ID = "shell"
	}
	logf := func(format string, args ...any) {
		if !options.Quiet {
			_, _ = fmt.Fprintf(stdout, "client: "+format+"\n", args...)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	taskClient := v3.NewTTRPCTaskClient(client)
	rootfsMounts := options.RootfsMountsFor()
	mountSessionShares := true
	isolatedSession := false
	if options.SandboxSession {
		baseID := options.ID
		if err := ensureSandboxContainer(client, taskClient, ctx, options, logf); err != nil {
			return err
		}
		// Each session is the init process of a dedicated container and PID
		// namespace. Its rootfs bind-mounts the long-lived sandbox root, retaining
		// Docker-like filesystem state without letting descendants survive session
		// exit or Kill(All). The base task owns the image/share mounts.
		options.ID = nextSessionTaskID(baseID)
		options.SandboxSession = false
		rootfsMounts = sandboxSessionRootfs(baseID)
		mountSessionShares = false
		isolatedSession = true
	}

	config, err := configJSONWithTransportCwdEnv(options.Shares, options.ShareTransport, options.RW, options.Args, options.ImgCfg, options.Terminal, options.Cwd, options.Environment)
	if err != nil {
		return err
	}
	if isolatedSession {
		config, err = isolatedSessionConfig(config, options)
		if err != nil {
			return err
		}
	}
	if !options.Terminal {
		config, err = runtimeStdioPassthroughConfig(config)
		if err != nil {
			return err
		}
	}
	mountClient := mountapi.NewTTRPCMountClient(client)
	bundlePath, _, err := ensureBundle(ctx, client, options.ID, config, logf)
	if err != nil {
		return err
	}
	removeSessionBundle := !mountSessionShares
	bundleCleanupSafe := removeSessionBundle // no task has been created yet
	if removeSessionBundle {
		defer func() {
			deleteCtx, deleteCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer deleteCancel()
			if !bundleCleanupSafe {
				// An ambiguous Create may have committed, so deleting its bundle is
				// unsafe. Scrubbing its credentials is always fail-closed: this host
				// will never send Start for the generated session ID.
				if err := callGuestBundle(deleteCtx, client, "Scrub", options.ID); err != nil {
					resultErr = errors.Join(resultErr, err)
				}
				return
			}
			if err := callGuestBundle(deleteCtx, client, "Delete", options.ID); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
		}()
	}
	setup := &mountSetup{client: mountClient, options: options}
	if mountSessionShares {
		setup, err = beginMountSetup(ctx, mountClient, options, logf)
		if err != nil {
			return err
		}
	} else {
		setup.commit()
	}
	defer setup.rollback()

	streams, err := options.openStreams()
	if err != nil {
		return err
	}
	defer streams.close()
	if removeSessionBundle {
		// NewContainer mounts the rootfs before invoking the OCI runtime. A
		// rejected Create can therefore leave a live mount beneath the bundle.
		// Older guests deleted bundles recursively, which traversed that mount
		// and whiteouted the shared writable rootfs before failing with EBUSY.
		// After Create is attempted, only a successful task cleanup proves the
		// bundle safe to delete; failures are scrubbed and reclaimed at VM exit.
		bundleCleanupSafe = false
	}
	_, err = taskClient.Create(ctx, &v3.CreateTaskRequest{
		ID:       options.ID,
		Bundle:   bundlePath,
		Rootfs:   rootfsMounts,
		Terminal: options.Terminal,
		Stdin:    "stream://" + streams.stdin.id,
		Stdout:   "stream://" + streams.stdout.id,
	})
	if err != nil {
		if taskCreateMayHaveCommitted(err) {
			setup.commit()
			bundleCleanupSafe = false
		}
		// Create did not establish exclusive task ownership. Deleting the ID or
		// unmounting its stack here could tear down a concurrent creator that
		// won the same ID. A definite server rejection rolls back direct mounts;
		// an ambiguous transport failure retains them for status recovery.
		return fmt.Errorf("task Create: %w%s\n(see the VM console for vminitd logs)", err, rwlayerHint(err, options.RW))
	}
	setup.commit()
	bundleCleanupSafe = false // the task now owns files beneath the bundle
	if removeSessionBundle {
		// Secrets exist in config.json only while the task is created and cannot
		// run. Remove the process spec before Start; a scrub failure fails closed.
		if scrubErr := callGuestBundle(ctx, client, "Scrub", options.ID); scrubErr != nil {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cleanupCancel()
			cleanupErr := cleanupContainer(cleanupCtx, taskClient, mountClient, options, bundlePath, false, func(string, ...any) {})
			if cleanupErr == nil {
				bundleCleanupSafe = true
			}
			return errors.Join(scrubErr, cleanupErr)
		}
	}
	logf("task created")
	// Attach the relays before Start so output from a process which runs to
	// completion during Start cannot race ahead of the host-side reader.
	stdoutDone := streams.relayOutput(stdout)
	if _, err := taskClient.Start(ctx, &v3.StartRequest{ID: options.ID}); err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		cleanupErr := cleanupContainer(cleanupCtx, taskClient, mountClient, options, bundlePath, setup.owned, func(string, ...any) {})
		if cleanupErr == nil {
			bundleCleanupSafe = removeSessionBundle
		}
		return errors.Join(fmt.Errorf("task Start: %w", err), cleanupErr)
	}
	// Preserve fast process output by attaching stdout before Start while
	// deferring stdin data and EOF until the guest has committed stdio setup.
	streams.relayInput(stdin)
	logf("task started — shell is live (type 'exit' to leave)")
	if options.Terminal && options.Cols != 0 && options.Rows != 0 {
		_, _ = taskClient.ResizePty(ctx, &v3.ResizePtyRequest{ID: options.ID, Width: options.Cols, Height: options.Rows})
	}
	resizeDone := make(chan struct{})
	if options.Terminal && options.Resize != nil {
		go func() {
			for {
				select {
				case size, ok := <-options.Resize:
					if !ok {
						return
					}
					if size.Cols == 0 || size.Rows == 0 {
						continue
					}
					resizeCtx, resizeCancel := context.WithTimeout(context.Background(), 5*time.Second)
					_, _ = taskClient.ResizePty(resizeCtx, &v3.ResizePtyRequest{ID: options.ID, Width: size.Cols, Height: size.Rows})
					resizeCancel()
				case <-resizeDone:
					return
				}
			}
		}()
	}
	defer close(resizeDone)

	stopKill := watchKill(options.KillCh, func() {
		killCtx, killCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer killCancel()
		_, _ = taskClient.Kill(killCtx, sessionKillRequest(options.ID))
	})
	defer stopKill()

	response, waitErr := taskClient.Wait(context.Background(), &v3.WaitRequest{ID: options.ID})
	if waitErr != nil {
		if !options.Quiet {
			_, _ = fmt.Fprintf(stdout, "\nclient: Wait: %v\n", waitErr)
		}
	} else {
		if !options.Quiet {
			_, _ = fmt.Fprintf(stdout, "\nclient: task exited, status %d\n", response.ExitStatus)
		}
		if options.ExitStatus != nil {
			*options.ExitStatus = int(response.ExitStatus)
		}
	}

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cleanupCancel()
	cleanupErr := cleanupContainer(cleanupCtx, taskClient, mountClient, options, bundlePath, setup.owned, func(format string, args ...any) {
		if !options.Quiet {
			_, _ = fmt.Fprintf(stdout, format, args...)
		}
	})
	if cleanupErr == nil {
		bundleCleanupSafe = removeSessionBundle
	}
	// runsc's create path leaves its sandbox/gofer processes holding the task
	// stream descriptors. Delete stops that infrastructure and closes the last
	// writers; only then can the relay observe EOF and finish draining output.
	awaitOutput(stdoutDone)
	logf("done")
	return errors.Join(waitErr, cleanupErr)
}

const sandboxAnchorPath = "/dev/.gantry-session-anchor"

var containerInitArgs = []string{sandboxAnchorPath, "session-anchor"}

func sandboxContainerConfig(options SessionOptions) (string, error) {
	encoded, err := configJSONWithTransportCwdEnv(options.Shares, options.ShareTransport, options.RW,
		containerInitArgs, options.ImgCfg, false, "", options.Environment)
	if err != nil {
		return "", err
	}
	var config runtimeConfig
	if err := json.Unmarshal([]byte(encoded), &config); err != nil {
		return "", fmt.Errorf("decode sandbox container config: %w", err)
	}
	// Never execute the workload image merely to keep its rootfs mounted. The
	// trusted guest vminitd binary exposes only a signal-waiting anchor mode and
	// is mounted after /dev's tmpfs so even read-only/distroless images work.
	config.Process.Cwd = "/"
	config.Process.User = specs.User{UID: 65534, GID: 65534}
	config.Process.NoNewPrivileges = true
	config.Process.Capabilities = &specs.LinuxCapabilities{}
	config.Mounts = append(config.Mounts, specs.Mount{
		Destination: sandboxAnchorPath,
		Type:        "bind",
		Source:      "/sbin/vminitd",
		Options:     []string{"rbind", "rprivate", "ro"},
	})
	result, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("encode sandbox container config: %w", err)
	}
	return string(result), nil
}

func ensureSandboxContainer(client *ttrpc.Client, taskClient v3.TTRPCTaskService, ctx context.Context, options SessionOptions, logf func(string, ...any)) error {
	state, err := taskClient.State(ctx, &v3.StateRequest{ID: options.ID})
	if err == nil && state.Status == tasktypes.Status_RUNNING {
		return nil
	}
	if err == nil {
		// Another session may have won Create but not reached Start yet. Never
		// delete a task merely because we observed a transitional state: that
		// would let a concurrent loser tear down the winner's container.
		if awaitRunning(ctx, taskClient, options.ID) {
			return nil
		}
		return fmt.Errorf("sandbox task %q exists in state %s and did not reach running", options.ID, state.Status)
	}

	config, err := sandboxContainerConfig(options)
	if err != nil {
		return err
	}
	bundlePath, _, err := ensureBundle(ctx, client, options.ID, config, logf)
	if err != nil {
		return err
	}
	mountClient := mountapi.NewTTRPCMountClient(client)
	setup, err := beginMountSetup(ctx, mountClient, options, logf)
	if err != nil {
		return err
	}
	return finishSandboxContainerSetup(ctx, taskClient, setup, options, bundlePath, logf)
}

// finishSandboxContainerSetup is the ownership boundary between guest mounts
// and the long-lived sandbox task. Only a definitive Create rejection permits
// rollback; a competing task or transport failure retains relationship-
// ambiguous resources. Once Create succeeds, cleanup may delete the owned task.
func finishSandboxContainerSetup(ctx context.Context, taskClient v3.TTRPCTaskService, setup *mountSetup, options SessionOptions, bundlePath string, logf func(string, ...any)) error {
	defer setup.rollback()
	_, err := taskClient.Create(ctx, &v3.CreateTaskRequest{
		ID:       options.ID,
		Bundle:   bundlePath,
		Rootfs:   options.RootfsMountsFor(),
		Terminal: false,
	})
	if err != nil {
		if errHas(err, errTextTaskExists, errTextMountBusy, errTextMountInUse) {
			// MountAll is idempotent and cannot tell us whether this setup or
			// the task winner established an identical mount. Retain it even if
			// the competing task subsequently fails to reach RUNNING.
			setup.commit()
			if awaitRunning(ctx, taskClient, options.ID) {
				return nil
			}
			return fmt.Errorf("task Create raced with an existing task that did not reach running state: %w", err)
		}
		if taskCreateMayHaveCommitted(err) {
			setup.commit()
		}
		// This caller has no exclusive task ownership, so it must not delete the
		// shared task ID or unmount another creator's stack. A definite server
		// rejection may roll back direct mounts; an ambiguous transport failure
		// retains them for status recovery.
		return fmt.Errorf("task Create: %w%s\n(see the VM console for vminitd logs)", err, rwlayerHint(err, options.RW))
	}
	setup.commit()
	if _, err := taskClient.Start(ctx, &v3.StartRequest{ID: options.ID}); err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		cleanupErr := cleanupContainer(cleanupCtx, taskClient, setup.client, options, bundlePath, setup.owned, func(string, ...any) {})
		return errors.Join(fmt.Errorf("task Start: %w", err), cleanupErr)
	}
	logf("sandbox container %s is up (long-lived init; sessions attach as exec)", options.ID)
	return nil
}
