package client

// spike.go — multi-container guest spike (docs/kubernetes-runtimeclass.md,
// Phase K0). Verifies that one booted guest can host several independent
// task.v3 containers concurrently: the core assumption behind the
// one-VM-per-Pod Kubernetes RuntimeClass design. It speaks only to the
// guest's nerdbox vminitd — no containerd, CNI, or Kubernetes is involved.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ejpir/gantry/internal/image"

	v3 "github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/containerd/api/types"
	tasktypes "github.com/containerd/containerd/api/types/task"
	bundle "github.com/containerd/nerdbox/api/services/bundle/v1"
	mountapi "github.com/containerd/nerdbox/api/services/mount/v1"
	"github.com/containerd/ttrpc"
)

// SpikeOptions configures MultiContainerSpike. The guest-facing fields mirror
// what the daemon hands to ordinary sessions; Report receives the
// human-readable pass/fail transcript.
type SpikeOptions struct {
	StreamSock string
	StreamDial func() (net.Conn, error)
	ImgCfg     *image.Config
	LayerSet   *LayerSet
	Report     io.Writer
}

// MultiContainerSpike runs the multi-container guest spike against the
// vminitd at the other end of client. A nil return means every assertion
// passed; the transcript on options.Report records each step either way.
func MultiContainerSpike(client *ttrpc.Client, options SpikeOptions) error {
	s := newMCSpike(client, options.StreamSock, options.StreamDial, options.Report)
	s.opts = options
	return s.runMultiContainer()
}

// newMCSpike wires the production guest services. Tests construct mcSpike
// directly with fakes.
func newMCSpike(client *ttrpc.Client, streamSock string, streamDial func() (net.Conn, error), report io.Writer) *mcSpike {
	return &mcSpike{
		task:    v3.NewTTRPCTaskClient(client),
		mount:   mountapi.NewTTRPCMountClient(client),
		bundle:  bundle.NewTTRPCBundleClient(client),
		streams: SessionOptions{StreamSock: streamSock, StreamDial: streamDial},
		report:  report,
		owned:   map[string]string{},
	}
}

// runMultiContainer is the MultiContainerSpike scenario.
func (s *mcSpike) runMultiContainer() error {
	_, _ = fmt.Fprintln(s.report, "mc-spike: multi-container guest spike (docs/kubernetes-runtimeclass.md, Phase K0)")
	err := s.runSpike()
	_, _ = fmt.Fprintf(s.report, "mc-spike: %d/%d assertions passed\n", s.passed, s.steps)
	return err
}

// mcSpike holds one spike run's state. owned tracks created task ID → bundle
// path so a failed assertion still releases every guest resource the run
// acquired. The service fields are interfaces so unit tests can drive the
// scenario with a fake guest.
type mcSpike struct {
	task    v3.TTRPCTaskService
	mount   mountapi.TTRPCMountService
	bundle  bundle.TTRPCBundleService
	streams SessionOptions
	opts    SpikeOptions
	report  io.Writer

	ownedMu sync.Mutex
	owned   map[string]string
	steps   int
	passed  int
}

// runSpike executes the scenario and always releases acquired guest
// resources. It returns the first failed assertion, if any.
func (s *mcSpike) runSpike() error {
	defer s.cleanup()
	if s.report == nil {
		s.report = io.Discard
	}
	s.steps = 5
	steps := []struct {
		name string
		run  func() (string, error)
	}{
		{"create+start long-lived container with arbitrary ID", s.assertArbitraryID},
		{"concurrent second container keeps own exit status and output", s.assertConcurrentContainer},
		{"deleting one container leaves the other running", s.assertIndependentTeardown},
		{"isolated session tasks share one root with independent streams and exit codes", s.assertConcurrentSessionTasks},
		{"killing one container leaves the guest healthy", s.assertKillAndGuestHealth},
	}
	for _, step := range steps {
		detail, err := step.run()
		if err != nil {
			_, _ = fmt.Fprintf(s.report, "mc-spike: FAIL %s: %v\n", step.name, err)
			return fmt.Errorf("%s: %w", step.name, err)
		}
		s.passed++
		_, _ = fmt.Fprintf(s.report, "mc-spike: PASS %s — %s\n", step.name, detail)
	}
	return nil
}

// assertArbitraryID: a long-lived container under an ID that is not "sb"
// reaches RUNNING. This is the entire multi-task premise in one step.
func (s *mcSpike) assertArbitraryID() (string, error) {
	pid, err := s.startLongLived("mc-a", containerInitArgs)
	if err != nil {
		return "", err
	}
	if !s.running("mc-a") {
		return "", fmt.Errorf("mc-a is not running after Start")
	}
	return fmt.Sprintf("mc-a running (guest pid %d)", pid), nil
}

// assertConcurrentContainer: while mc-a is up, a second container with its
// own bundle, rootfs mount, and stdio streams runs to completion with its
// own exit status and output.
func (s *mcSpike) assertConcurrentContainer() (string, error) {
	status, out, err := s.runToCompletion("mc-b", []string{"/bin/sh", "-c", "echo spike-b-marker; exit 42"})
	if err != nil {
		return "", err
	}
	if status != 42 {
		return "", fmt.Errorf("mc-b exit status %d, want 42", status)
	}
	if !strings.Contains(out, "spike-b-marker") {
		return "", fmt.Errorf("mc-b output missing its marker: %q", out)
	}
	if !s.running("mc-a") {
		return "", fmt.Errorf("mc-a is not running after mc-b exited")
	}
	return "mc-b exited 42 with intact output while mc-a stayed running", nil
}

// assertIndependentTeardown: deleting mc-b (task + bundle mounts) does not
// disturb mc-a.
func (s *mcSpike) assertIndependentTeardown() (string, error) {
	s.deleteTask("mc-b")
	if !s.running("mc-a") {
		return "", fmt.Errorf("mc-a is not running after mc-b was deleted")
	}
	return "mc-b deleted; mc-a unaffected", nil
}

// assertConcurrentSessionTasks: two concurrent containers bind the rootfs
// owned by mc-a. Each command is PID 1 in its own PID namespace, matching the
// production session lifecycle that prevents background descendants escaping.
func (s *mcSpike) assertConcurrentSessionTasks() (string, error) {
	type outcome struct {
		name   string
		status int
		out    string
		err    error
	}
	start := func(name, script string) <-chan outcome {
		ch := make(chan outcome, 1)
		go func() {
			config, err := configJSONWithTransportCwdEnv(nil, nil, false,
				[]string{"/bin/sh", "-c", script}, s.opts.ImgCfg, false, "", nil)
			if err != nil {
				ch <- outcome{name: name, status: -1, err: err}
				return
			}
			status, out, err := s.runToCompletionCustom(name, config, sandboxSessionRootfs("mc-a"))
			ch <- outcome{name, status, out, err}
		}()
		return ch
	}
	one := start("exec-one", "echo spike-exec-one; exit 7")
	two := start("exec-two", "echo spike-exec-two; exit 9")
	want := map[string]int{"exec-one": 7, "exec-two": 9}
	for _, ch := range []<-chan outcome{one, two} {
		result := <-ch
		if result.err != nil {
			return "", fmt.Errorf("%s: %w", result.name, result.err)
		}
		if result.status != want[result.name] {
			return "", fmt.Errorf("%s exit status %d, want %d", result.name, result.status, want[result.name])
		}
		if !strings.Contains(result.out, "spike-"+result.name) {
			return "", fmt.Errorf("%s output missing its marker: %q", result.name, result.out)
		}
	}
	return "session tasks shared mc-a's root while retaining isolated output and lifecycle", nil
}

// assertKillAndGuestHealth: SIGKILL-all on mc-a tears it down, and a fresh
// container created afterwards still runs cleanly — killing one task did not
// poison the guest agent or the VM.
func (s *mcSpike) assertKillAndGuestHealth() (string, error) {
	killCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := s.task.Kill(killCtx, &v3.KillRequest{ID: "mc-a", Signal: uint32(syscall.SIGKILL), All: true}); err != nil {
		return "", fmt.Errorf("kill mc-a: %w", err)
	}
	if _, err := s.waitExit("mc-a", 15*time.Second); err != nil {
		return "", fmt.Errorf("wait mc-a after kill: %w", err)
	}
	s.deleteTask("mc-a")
	status, out, err := s.runToCompletion("mc-d", []string{"/bin/sh", "-c", "echo spike-guest-alive; exit 0"})
	if err != nil {
		return "", err
	}
	if status != 0 {
		return "", fmt.Errorf("mc-d exit status %d, want 0", status)
	}
	if !strings.Contains(out, "spike-guest-alive") {
		return "", fmt.Errorf("mc-d output missing its marker: %q", out)
	}
	s.deleteTask("mc-d")
	return "mc-a killed and deleted; fresh mc-d ran to a clean exit 0", nil
}

// startLongLived creates and starts a container with no stdio streams (the
// same shape as the standalone "sb" init) and returns its guest PID.
func (s *mcSpike) startLongLived(id string, args []string) (uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	config, err := configJSONWithTransportCwdEnv(nil, nil, false, args, s.opts.ImgCfg, false, "", nil)
	if err != nil {
		return 0, err
	}
	bundlePath, err := s.ensureBundle(ctx, id, config)
	if err != nil {
		return 0, err
	}
	response, err := s.task.Create(ctx, &v3.CreateTaskRequest{
		ID:     id,
		Bundle: bundlePath,
		Rootfs: s.rootfsMounts(),
	})
	if err != nil {
		return 0, fmt.Errorf("task Create: %w", err)
	}
	s.recordOwned(id, bundlePath)
	if _, err := s.task.Start(ctx, &v3.StartRequest{ID: id}); err != nil {
		return 0, fmt.Errorf("task Start: %w", err)
	}
	if !awaitRunning(ctx, s.task, id) {
		return 0, fmt.Errorf("task did not reach running state")
	}
	return response.Pid, nil
}

// runToCompletion creates id with args and dedicated stdio streams, waits for
// its exit, and returns the exit status plus everything the process wrote.
// The task is left created so callers can assert post-exit state; deleteTask
// owns the final transition.
func (s *mcSpike) runToCompletion(id string, args []string) (int, string, error) {
	config, err := configJSONWithTransportCwdEnv(nil, nil, false, args, s.opts.ImgCfg, false, "", nil)
	if err != nil {
		return -1, "", err
	}
	return s.runToCompletionCustom(id, config, s.rootfsMounts())
}

// runToCompletionCustom is runToCompletion with an explicit OCI config and
// rootfs mount chain, so spikes can control the rootfs assembly directly.
func (s *mcSpike) runToCompletionCustom(id, config string, rootfs []*types.Mount) (int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bundlePath, err := s.ensureBundle(ctx, id, config)
	if err != nil {
		return -1, "", err
	}
	streams, err := s.streams.openStreams()
	if err != nil {
		return -1, "", fmt.Errorf("open stdio streams: %w", err)
	}
	defer streams.close()
	if _, err := s.task.Create(ctx, &v3.CreateTaskRequest{
		ID:     id,
		Bundle: bundlePath,
		Rootfs: rootfs,
		Stdin:  "stream://" + streams.stdin.id,
		Stdout: "stream://" + streams.stdout.id,
	}); err != nil {
		return -1, "", fmt.Errorf("task Create: %w", err)
	}
	s.recordOwned(id, bundlePath)
	var out syncBuffer
	// Attach the output relay before Start so a fast process cannot race ahead
	// of the host reader (mirrors Session).
	stdoutDone := streams.relayOutput(&out)
	if _, err := s.task.Start(ctx, &v3.StartRequest{ID: id}); err != nil {
		return -1, out.String(), fmt.Errorf("task Start: %w", err)
	}
	// Defer stdin EOF until Start committed the guest stdio setup.
	streams.relayInput(strings.NewReader(""))
	response, waitErr := s.waitExit(id, 60*time.Second)
	awaitOutput(stdoutDone)
	if waitErr != nil {
		return -1, out.String(), fmt.Errorf("task Wait: %w", waitErr)
	}
	return int(response.ExitStatus), out.String(), nil
}

// waitExit blocks until id's init process exits or the timeout expires.
func (s *mcSpike) waitExit(id string, timeout time.Duration) (*v3.WaitResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return s.task.Wait(ctx, &v3.WaitRequest{ID: id})
}

// running reports whether id currently exists in RUNNING state.
func (s *mcSpike) running(id string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	state, err := s.task.State(ctx, &v3.StateRequest{ID: id})
	return err == nil && state.Status == tasktypes.Status_RUNNING
}

// deleteTask removes id's task and unwinds its bundle mounts, then forgets
// it. Best effort: the guest is about to be powered off either way.
func (s *mcSpike) recordOwned(id, bundlePath string) {
	s.ownedMu.Lock()
	s.owned[id] = bundlePath
	s.ownedMu.Unlock()
}

func (s *mcSpike) deleteTask(id string) {
	s.ownedMu.Lock()
	bundlePath, ok := s.owned[id]
	if ok {
		delete(s.owned, id)
	}
	s.ownedMu.Unlock()
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = s.task.Delete(ctx, &v3.DeleteRequest{ID: id})
	awaitGone(ctx, s.task, id)
	unmountStack(ctx, s.mount, bundlePath)
}

// cleanup kills and deletes any tasks still owned after a failed assertion.
func (s *mcSpike) cleanup() {
	s.ownedMu.Lock()
	ids := make([]string, 0, len(s.owned))
	for id := range s.owned {
		ids = append(ids, id)
	}
	s.ownedMu.Unlock()
	for _, id := range ids {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = s.task.Kill(ctx, &v3.KillRequest{ID: id, Signal: uint32(syscall.SIGKILL), All: true})
		cancel()
		s.deleteTask(id)
	}
}

// ensureBundle mirrors the session path: create the vminitd bundle, or reuse
// the one a previous attempt left behind.
func (s *mcSpike) ensureBundle(ctx context.Context, id, config string) (string, error) {
	response, err := s.bundle.Create(ctx, &bundle.CreateRequest{
		ID: id,
		Files: map[string][]byte{
			"config.json":    []byte(config),
			"nw-config.json": []byte(`{"Networks":[]}`),
		},
	})
	if err != nil {
		if errHas(err, errTextBundleExists, errTextTaskExists) {
			return "/run/bundles/" + id, nil
		}
		return "", fmt.Errorf("bundle Create: %w", err)
	}
	return response.Bundle, nil
}

// rootfsMounts renders the guest rootfs mount chain. Spike containers always
// mount the image read-only: a second writable ext4/overlay stack would fight
// over the same rwlayer device, and read-only is all the assertions need.
func (s *mcSpike) rootfsMounts() []*types.Mount {
	if s.opts.LayerSet != nil {
		return rootfsMountsDevs(false, s.opts.LayerSet.FSMetaDev(), s.opts.LayerSet.LayerDevs(), "")
	}
	return RootfsMounts(false)
}

// mountShareHub mounts the permanent virtio-fs hub in the guest root mount
// namespace. Guest containers then see exports beneath vmPath. Mounting is
// idempotent: an existing mount reports busy.
func (s *mcSpike) mountShareHub(tag, vmPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := s.mount.MountAll(ctx, &mountapi.MountAllRequest{Mounts: []*mountapi.MountSpec{{
		Type: "virtiofs", Source: tag, Target: vmPath,
	}}})
	if err != nil && !errHas(err, errTextMountBusy) {
		return fmt.Errorf("mount share hub: %w", err)
	}
	return nil
}

// hubBindRootfs assembles a task rootfs by bind-mounting one hub export as
// the bundle rootfs — the transport the Kubernetes RuntimeClass design
// (docs/kubernetes-runtimeclass.md) plans for containerd snapshots.
func hubBindRootfs(exportGuestPath string) []*types.Mount {
	return []*types.Mount{{Type: "bind", Source: exportGuestPath, Options: []string{"rbind"}}}
}

// syncBuffer is a bytes.Buffer that is safe for one relay goroutine to write
// while the spike reads after Wait.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
