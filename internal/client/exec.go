package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/containerd/containerd/api/runtime/task/v3"
	tasktypes "github.com/containerd/containerd/api/types/task"
	"github.com/containerd/ttrpc"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/types/known/anypb"
)

func init() {
	typeurl.Register(&specs.Process{}, "types.containerd.io", "opencontainers/runtime-spec", "1", "Process")
}

var sessionExecSequence atomic.Uint64

// nextSessionExecID remains unique when several host sessions arrive within
// one guest clock tick. That is common under WHPX: Linux's early wall clock
// can return the same UnixNano value to concurrent goroutines, and the shim
// rejects the second process as AlreadyExists.
func nextSessionExecID(containerID string) string {
	return fmt.Sprintf("%s-exec-%d-%d", containerID, time.Now().UnixNano(), sessionExecSequence.Add(1))
}

// sessionExec runs a process inside the sandbox's long-lived container. It
// owns only the process and its streams; the container belongs to the sandbox.
func sessionExec(taskClient task.TTRPCTaskService, options SessionOptions, id string, stdin io.Reader, stdout io.Writer) (resultErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	logf := func(format string, args ...any) {
		if !options.Quiet {
			_, _ = fmt.Fprintf(stdout, "client: "+format+"\n", args...)
		}
	}

	streams, err := options.openStreams()
	if err != nil {
		return err
	}
	defer streams.close()
	logf("exec: stdio streams open, sending Exec")

	execID := nextSessionExecID(id)
	uid, gid := options.ImgCfg.IDs()
	process := &specs.Process{
		Terminal: options.Terminal,
		User:     specs.User{UID: uid, GID: gid},
		Args:     options.Args,
		Env:      prependPath(processEnvironment(options.ImgCfg, options.Secrets, options.Environment), options.PathPrepend),
		Cwd:      options.workingDir(),
	}
	encoded, err := typeurl.MarshalAny(process)
	if err != nil {
		return err
	}
	spec := &anypb.Any{TypeUrl: encoded.GetTypeUrl(), Value: encoded.GetValue()}
	if _, err := taskClient.Exec(ctx, &task.ExecProcessRequest{
		ID:       id,
		ExecID:   execID,
		Terminal: options.Terminal,
		Stdin:    "stream://" + streams.stdin.id,
		Stdout:   "stream://" + streams.stdout.id,
		Spec:     spec,
	}); err != nil {
		return fmt.Errorf("task Exec: %w", err)
	}
	// Wait reports process state but does not release the shim's exec/process
	// and stream bookkeeping. Delete owns that final transition and must run on
	// Start and Wait failures as well as the normal exit path.
	defer func() {
		deleteCtx, deleteCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer deleteCancel()
		if _, err := taskClient.Delete(deleteCtx, &task.DeleteRequest{ID: id, ExecID: execID}); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("task Delete(exec): %w", err))
		}
	}()
	// Attach the relays before Start. A short-lived process can write and exit
	// inside Start; attaching afterwards loses that output before the guest
	// stream endpoint is drained.
	stdoutDone := streams.relayOutput(stdout)
	if _, err := taskClient.Start(ctx, &task.StartRequest{ID: id, ExecID: execID}); err != nil {
		return fmt.Errorf("task Start(exec): %w", err)
	}
	// Start stdout before task Start so fast output cannot be lost, but do not
	// send or close stdin until Start has committed the process's stdio setup.
	streams.relayInput(stdin)
	logf("exec process started in container %s (type 'exit' to leave)", id)
	if options.Terminal && options.Cols != 0 && options.Rows != 0 {
		_, _ = taskClient.ResizePty(ctx, &task.ResizePtyRequest{ID: id, ExecID: execID, Width: options.Cols, Height: options.Rows})
	}

	stopKill := watchKill(options.KillCh, func() {
		killCtx, killCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer killCancel()
		_, _ = taskClient.Kill(killCtx, &task.KillRequest{ID: id, ExecID: execID, Signal: uint32(syscall.SIGKILL)})
	})
	defer stopKill()

	response, waitErr := taskClient.Wait(context.Background(), &task.WaitRequest{ID: id, ExecID: execID})
	awaitOutput(stdoutDone)
	if waitErr != nil {
		_, _ = fmt.Fprintf(stdout, "\nclient: Wait: %v\n", waitErr)
	} else {
		_, _ = fmt.Fprintf(stdout, "\nclient: exec exited, status %d\n", response.ExitStatus)
		if options.ExitStatus != nil {
			*options.ExitStatus = int(response.ExitStatus)
		}
	}
	return waitErr
}

// SyncGuest asks a running workload container to flush its filesystems.
func SyncGuest(client *ttrpc.Client, streamSock, containerID string, timeout time.Duration) {
	SyncGuestDial(client, nil, streamSock, containerID, timeout)
}

// SyncGuestDial is SyncGuest with an optional split-worker stream dialer.
func SyncGuestDial(client *ttrpc.Client, dial func() (net.Conn, error), streamSock, containerID string, timeout time.Duration) {
	taskClient := task.NewTTRPCTaskClient(client)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	state, err := taskClient.State(ctx, &task.StateRequest{ID: containerID})
	cancel()
	if err != nil || state.Status != tasktypes.Status_RUNNING {
		return
	}

	kill := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_ = Session(client, SessionOptions{
			StreamSock:       streamSock,
			StreamDial:       dial,
			Args:             []string{"/bin/sync"},
			ID:               containerID,
			ExecIntoExisting: true,
			Quiet:            true,
			KillCh:           kill,
		}, strings.NewReader(""), io.Discard)
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		close(kill)
	}
}
