package client

import (
	"context"
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
	"google.golang.org/grpc/status"
)

const (
	errTextBundleExists = "file exists"
	errTextTaskExists   = "already exists"
	errTextMountBusy    = "busy"
	errTextMountInUse   = "in-use"
)

// SessionOptions configures one container session over an established ttrpc
// connection. Callers retain ownership of the connection and IO endpoints.
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
	KillCh     <-chan struct{}
	Quiet      bool
	// ExitStatus receives a successfully waited process's numeric status.
	ExitStatus *int
	// ExecIntoExisting gives sandbox sessions docker-exec semantics.
	ExecIntoExisting bool
	// ImgCfg provides the image environment, user, command, and working dir.
	ImgCfg *image.Config
	// Secrets enter only the in-memory process spec, never config.json.
	Secrets []string
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

func cleanupContainer(ctx context.Context, taskClient v3.TTRPCTaskService, mountClient mountapi.TTRPCMountService, options SessionOptions, bundlePath string, unmountOwnedShares bool, report func(string, ...any)) {
	_, _ = taskClient.Delete(ctx, &v3.DeleteRequest{ID: options.ID})
	awaitGone(ctx, taskClient, options.ID)
	if unmountOwnedShares {
		unmountShares(ctx, mountClient, options.Shares, options.ShareTransport, report)
	}
	unmountStack(ctx, mountClient, bundlePath)
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

// Session runs one container session through bundle creation, share mounting,
// task lifecycle, and stream relay.
func Session(client *ttrpc.Client, options SessionOptions, stdin io.Reader, stdout io.Writer) error {
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
	if options.ExecIntoExisting {
		if err := ensureSandboxContainer(client, taskClient, ctx, options, logf); err != nil {
			return err
		}
		return sessionExec(taskClient, options, options.ID, stdin, stdout)
	}

	config, err := ConfigJSONWithTransport(options.Shares, options.ShareTransport, options.RW, options.Args, options.ImgCfg)
	if err != nil {
		return err
	}
	mountClient := mountapi.NewTTRPCMountClient(client)
	bundlePath, _, err := ensureBundle(ctx, client, options.ID, config, logf)
	if err != nil {
		return err
	}
	setup, err := beginMountSetup(ctx, mountClient, options, logf)
	if err != nil {
		return err
	}
	defer setup.rollback()

	streams, err := options.openStreams()
	if err != nil {
		return err
	}
	defer streams.close()
	_, err = taskClient.Create(ctx, &v3.CreateTaskRequest{
		ID:       options.ID,
		Bundle:   bundlePath,
		Rootfs:   options.RootfsMountsFor(),
		Terminal: options.Terminal,
		Stdin:    "stream://" + streams.stdin.id,
		Stdout:   "stream://" + streams.stdout.id,
	})
	if err != nil {
		if taskCreateMayHaveCommitted(err) {
			setup.commit()
		}
		// Create did not establish exclusive task ownership. Deleting the ID or
		// unmounting its stack here could tear down a concurrent creator that
		// won the same ID. A definite server rejection rolls back direct mounts;
		// an ambiguous transport failure retains them for status recovery.
		return fmt.Errorf("task Create: %w%s\n(see the VM console for vminitd logs)", err, rwlayerHint(err, options.RW))
	}
	setup.commit()
	logf("task created")
	if _, err := taskClient.Start(ctx, &v3.StartRequest{ID: options.ID}); err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		cleanupContainer(cleanupCtx, taskClient, mountClient, options, bundlePath, setup.owned, func(string, ...any) {})
		return fmt.Errorf("task Start: %w", err)
	}
	logf("task started — shell is live (type 'exit' to leave)")
	if options.Terminal && options.Cols != 0 && options.Rows != 0 {
		_, _ = taskClient.ResizePty(ctx, &v3.ResizePtyRequest{ID: options.ID, Width: options.Cols, Height: options.Rows})
	}

	stdoutDone := streams.relay(stdin, stdout)
	stopKill := watchKill(options.KillCh, func() {
		killCtx, killCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer killCancel()
		_, _ = taskClient.Kill(killCtx, &v3.KillRequest{ID: options.ID, Signal: uint32(syscall.SIGKILL), All: true})
	})
	defer stopKill()

	response, waitErr := taskClient.Wait(context.Background(), &v3.WaitRequest{ID: options.ID})
	awaitOutput(stdoutDone)
	if waitErr != nil {
		_, _ = fmt.Fprintf(stdout, "\nclient: Wait: %v\n", waitErr)
	} else {
		_, _ = fmt.Fprintf(stdout, "\nclient: task exited, status %d\n", response.ExitStatus)
		if options.ExitStatus != nil {
			*options.ExitStatus = int(response.ExitStatus)
		}
	}

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cleanupCancel()
	cleanupContainer(cleanupCtx, taskClient, mountClient, options, bundlePath, setup.owned, func(format string, args ...any) {
		_, _ = fmt.Fprintf(stdout, format, args...)
	})
	logf("done")
	return waitErr
}

var containerInitArgs = []string{"/bin/sh", "-c", "while :; do sleep 86400; done"}

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

	config, err := configJSONWithTransport(options.Shares, options.ShareTransport, options.RW, containerInitArgs, nil, false)
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
		cleanupContainer(cleanupCtx, taskClient, setup.client, options, bundlePath, setup.owned, func(string, ...any) {})
		return fmt.Errorf("task Start: %w", err)
	}
	logf("sandbox container %s is up (long-lived init; sessions attach as exec)", options.ID)
	return nil
}
