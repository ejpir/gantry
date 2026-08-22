package client

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"

	v3 "github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/containerd/api/types"
	tasktypes "github.com/containerd/containerd/api/types/task"
	bundle "github.com/containerd/nerdbox/api/services/bundle/v1"
	mountapi "github.com/containerd/nerdbox/api/services/mount/v1"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/types/known/emptypb"
)

// The fake guest below answers the spike's ttrpc surface (task v3, bundle v1,
// mount v1, stream handshake) the way a well-behaved vminitd would, so the
// spike's sequencing and assertions are exercised without booting a VM.

// scriptRe matches the spike's workload convention: "echo <marker>; exit <n>".
var scriptRe = regexp.MustCompile(`echo ([a-z0-9-]+); exit ([0-9]+)`)

// fakeStreamHub is the guest end of the stream forwarding socket: it claims
// stream IDs with the length-prefixed echo handshake and lets the fake task
// service write stdout data to the right stream.
type fakeStreamHub struct {
	mu    sync.Mutex
	conns map[string]net.Conn
}

func newFakeStreamHub() *fakeStreamHub {
	return &fakeStreamHub{conns: map[string]net.Conn{}}
}

func (h *fakeStreamHub) dial() (net.Conn, error) {
	client, server := net.Pipe()
	go h.serve(server)
	return client, nil
}

func (h *fakeStreamHub) serve(conn net.Conn) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		_ = conn.Close()
		return
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > maxStreamHandshakeString {
		_ = conn.Close()
		return
	}
	id := make([]byte, n)
	if _, err := io.ReadFull(conn, id); err != nil {
		_ = conn.Close()
		return
	}
	h.mu.Lock()
	h.conns[string(id)] = conn
	h.mu.Unlock()
	_, _ = conn.Write(lenBuf[:])
	_, _ = conn.Write(id)
}

// writeClose streams data to the claimed stream and closes it, ending the
// host-side output relay. It runs in a goroutine because net.Pipe is
// synchronous and the relay may not be reading yet.
func (h *fakeStreamHub) writeClose(id, data string) {
	go func() {
		h.mu.Lock()
		conn := h.conns[id]
		h.mu.Unlock()
		if conn == nil {
			return
		}
		if data != "" {
			_, _ = io.WriteString(conn, data)
		}
		_ = conn.Close()
	}()
}

// fakeBundleService records bundle files by path so the fake task service can
// read back the workload args, like vminitd does from disk.
type fakeBundleService struct {
	mu    sync.Mutex
	files map[string]map[string][]byte
}

func newFakeBundleService() *fakeBundleService {
	return &fakeBundleService{files: map[string]map[string][]byte{}}
}

func (s *fakeBundleService) Create(_ context.Context, req *bundle.CreateRequest) (*bundle.CreateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := "/run/bundles/" + req.ID
	if _, exists := s.files[path]; exists {
		return nil, fmt.Errorf("bundle %s: file exists", path)
	}
	s.files[path] = req.Files
	return &bundle.CreateResponse{Bundle: path}, nil
}

func (s *fakeBundleService) args(path string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var config struct {
		Process struct {
			Args []string `json:"args"`
		} `json:"process"`
	}
	if err := json.Unmarshal(s.files[path]["config.json"], &config); err != nil {
		return nil
	}
	return config.Process.Args
}

type fakeMountService struct {
	mu        sync.Mutex
	unmounted []string
	mounted   []*mountapi.MountSpec
}

func (s *fakeMountService) MountAll(_ context.Context, req *mountapi.MountAllRequest) (*mountapi.MountAllResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mounted = append(s.mounted, req.Mounts...)
	return &mountapi.MountAllResponse{}, nil
}

func (s *fakeMountService) Unmount(_ context.Context, req *mountapi.UnmountRequest) (*mountapi.UnmountResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unmounted = append(s.unmounted, req.Target)
	return &mountapi.UnmountResponse{}, nil
}

func (s *fakeMountService) UnmountAll(context.Context, *mountapi.UnmountAllRequest) (*mountapi.UnmountAllResponse, error) {
	return &mountapi.UnmountAllResponse{}, nil
}

func (s *fakeMountService) targets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.unmounted...)
}

func (s *fakeMountService) specs() []*mountapi.MountSpec {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*mountapi.MountSpec(nil), s.mounted...)
}

// fakeProcess is one container init or exec process in the fake guest.
type fakeProcess struct {
	status  tasktypes.Status
	stdout  string
	args    []string
	exit    uint32
	stopped chan struct{}
	once    sync.Once
}

// fakeTaskService is a state-machine vminitd. Containers and execs whose
// script matches scriptRe run to completion with that marker and exit code;
// anything else runs until killed.
type fakeTaskService struct {
	v3.TTRPCTaskService

	mu      sync.Mutex
	bundles *fakeBundleService
	hub     *fakeStreamHub
	tasks   map[string]*fakeProcess
	execs   map[string]map[string]*fakeProcess
	rootfs  map[string][]*types.Mount
	nextPid uint32
	// evilExit flips short-lived exit codes to 1, simulating a guest that
	// cannot propagate exit status correctly.
	evilExit bool
	// rejectNewIDs simulates a vminitd that only accepts the standalone "sb"
	// container ID.
	rejectNewIDs bool

	kills   int
	deletes int
}

func newFakeTaskService(bundles *fakeBundleService, hub *fakeStreamHub) *fakeTaskService {
	return &fakeTaskService{
		bundles: bundles,
		hub:     hub,
		tasks:   map[string]*fakeProcess{},
		execs:   map[string]map[string]*fakeProcess{},
		rootfs:  map[string][]*types.Mount{},
		nextPid: 1000,
	}
}

// scriptBehavior extracts the marker and exit code from an "echo X; exit N"
// script, or reports a long-running process. The rootfs spike's checker
// binary (/spikecheck ...) reports as a short, clean exit.
func scriptBehavior(args []string) (marker string, exit uint32, longRunning bool) {
	if len(args) >= 1 && args[0] == "/spikecheck" {
		return "spikecheck-ok", 0, false
	}
	if len(args) != 3 || args[1] != "-c" {
		return "", 0, true
	}
	match := scriptRe.FindStringSubmatch(args[2])
	if match == nil {
		return "", 0, true
	}
	var code uint32
	_, _ = fmt.Sscanf(match[2], "%d", &code)
	return match[1], code, false
}

// runToExit drives a scripted short-lived process to its exit; long-running
// processes stay RUNNING until Kill.
func (s *fakeTaskService) runToExit(process *fakeProcess) {
	marker, exit, longRunning := scriptBehavior(process.args)
	if longRunning {
		return
	}
	if s.evilExit {
		exit = 1
	}
	s.hub.writeClose(process.stdout, marker+"\n")
	s.mu.Lock()
	process.exit = exit
	process.status = tasktypes.Status_STOPPED
	s.mu.Unlock()
	process.once.Do(func() { close(process.stopped) })
}

func (s *fakeTaskService) Create(_ context.Context, req *v3.CreateTaskRequest) (*v3.CreateTaskResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rejectNewIDs && req.ID != "sb" {
		return nil, fmt.Errorf("task %s: unsupported container id", req.ID)
	}
	if _, exists := s.tasks[req.ID]; exists {
		return nil, fmt.Errorf("task %s: already exists", req.ID)
	}
	s.tasks[req.ID] = &fakeProcess{
		status:  tasktypes.Status_CREATED,
		stdout:  strings.TrimPrefix(req.Stdout, "stream://"),
		args:    s.bundles.args(req.Bundle),
		stopped: make(chan struct{}),
	}
	s.rootfs[req.ID] = req.Rootfs
	s.nextPid++
	return &v3.CreateTaskResponse{Pid: s.nextPid}, nil
}

func (s *fakeTaskService) Start(_ context.Context, req *v3.StartRequest) (*v3.StartResponse, error) {
	s.mu.Lock()
	process := s.tasks[req.ID]
	if req.ExecID != "" {
		process = s.execs[req.ID][req.ExecID]
	}
	s.mu.Unlock()
	if process == nil {
		return nil, fmt.Errorf("task %s: not found", req.ID)
	}
	process.status = tasktypes.Status_RUNNING
	s.runToExit(process)
	return &v3.StartResponse{}, nil
}

func (s *fakeTaskService) Exec(_ context.Context, req *v3.ExecProcessRequest) (*emptypb.Empty, error) {
	decoded, err := typeurl.UnmarshalAny(req.Spec)
	if err != nil {
		return nil, fmt.Errorf("exec spec: %w", err)
	}
	process, ok := decoded.(*specs.Process)
	if !ok {
		return nil, fmt.Errorf("exec spec type %T, want *specs.Process", decoded)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tasks[req.ID] == nil {
		return nil, fmt.Errorf("task %s: not found", req.ID)
	}
	if s.execs[req.ID] == nil {
		s.execs[req.ID] = map[string]*fakeProcess{}
	}
	s.execs[req.ID][req.ExecID] = &fakeProcess{
		status:  tasktypes.Status_CREATED,
		stdout:  strings.TrimPrefix(req.Stdout, "stream://"),
		args:    process.Args,
		stopped: make(chan struct{}),
	}
	return &emptypb.Empty{}, nil
}

func (s *fakeTaskService) State(_ context.Context, req *v3.StateRequest) (*v3.StateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	process := s.tasks[req.ID]
	if req.ExecID != "" {
		process = s.execs[req.ID][req.ExecID]
	}
	if process == nil {
		return nil, fmt.Errorf("task %s: not found", req.ID)
	}
	return &v3.StateResponse{ID: req.ID, ExecID: req.ExecID, Status: process.status}, nil
}

func (s *fakeTaskService) Wait(ctx context.Context, req *v3.WaitRequest) (*v3.WaitResponse, error) {
	s.mu.Lock()
	process := s.tasks[req.ID]
	if req.ExecID != "" {
		process = s.execs[req.ID][req.ExecID]
	}
	s.mu.Unlock()
	if process == nil {
		return nil, fmt.Errorf("task %s: not found", req.ID)
	}
	select {
	case <-process.stopped:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return &v3.WaitResponse{ExitStatus: process.exit}, nil
}

func (s *fakeTaskService) Kill(_ context.Context, req *v3.KillRequest) (*emptypb.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kills++
	stop := func(process *fakeProcess) {
		if process == nil || process.status == tasktypes.Status_STOPPED {
			return
		}
		process.exit = 137
		process.status = tasktypes.Status_STOPPED
		process.once.Do(func() { close(process.stopped) })
	}
	if req.ExecID != "" {
		stop(s.execs[req.ID][req.ExecID])
		return &emptypb.Empty{}, nil
	}
	stop(s.tasks[req.ID])
	if req.All {
		for _, process := range s.execs[req.ID] {
			stop(process)
		}
	}
	return &emptypb.Empty{}, nil
}

func (s *fakeTaskService) Delete(_ context.Context, req *v3.DeleteRequest) (*v3.DeleteResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	if req.ExecID != "" {
		delete(s.execs[req.ID], req.ExecID)
		return &v3.DeleteResponse{}, nil
	}
	if s.tasks[req.ID] == nil {
		return nil, fmt.Errorf("task %s: not found", req.ID)
	}
	delete(s.tasks, req.ID)
	delete(s.execs, req.ID)
	return &v3.DeleteResponse{}, nil
}

// fakeGuest assembles the fake services and constructs a spike against them.
type fakeGuest struct {
	spike  *mcSpike
	mounts *fakeMountService
	tasks  *fakeTaskService
	report *strings.Builder
}

func newFakeGuest(report *strings.Builder) *fakeGuest {
	hub := newFakeStreamHub()
	bundles := newFakeBundleService()
	tasks := newFakeTaskService(bundles, hub)
	mounts := &fakeMountService{}
	return &fakeGuest{
		mounts: mounts,
		tasks:  tasks,
		report: report,
		spike: &mcSpike{
			task:    tasks,
			mount:   mounts,
			bundle:  bundles,
			streams: SessionOptions{StreamDial: hub.dial},
			report:  report,
			owned:   map[string]string{},
		},
	}
}

func TestMultiContainerSpikeHappyPath(t *testing.T) {
	var report strings.Builder
	guest := newFakeGuest(&report)
	if err := guest.spike.runSpike(); err != nil {
		t.Fatalf("runSpike: %v\ntranscript:\n%s", err, report.String())
	}
	if guest.spike.passed != guest.spike.steps {
		t.Fatalf("passed %d of %d steps\ntranscript:\n%s", guest.spike.passed, guest.spike.steps, report.String())
	}
	transcript := report.String()
	for _, want := range []string{
		"PASS create+start long-lived container with arbitrary ID",
		"PASS concurrent second container",
		"PASS deleting one container",
		"PASS concurrent execs",
		"PASS killing one container",
	} {
		if !strings.Contains(transcript, want) {
			t.Errorf("transcript missing %q:\n%s", want, transcript)
		}
	}
	// Every bundle rootfs mount stack the spike created was unwound again.
	if len(guest.mounts.targets()) == 0 {
		t.Error("no bundle mounts were unwound")
	}
	if len(guest.spike.owned) != 0 {
		t.Errorf("spike still owns tasks after cleanup: %v", guest.spike.owned)
	}
}

func TestMultiContainerSpikeDetectsWrongExitStatus(t *testing.T) {
	var report strings.Builder
	guest := newFakeGuest(&report)
	guest.tasks.evilExit = true
	err := guest.spike.runSpike()
	if err == nil {
		t.Fatalf("runSpike succeeded against a guest that corrupts exit status:\n%s", report.String())
	}
	if !strings.Contains(err.Error(), "exit status") {
		t.Errorf("error %v does not name the exit-status corruption", err)
	}
	// mc-b was created before the failure and must have been cleaned up.
	if len(guest.spike.owned) != 0 {
		t.Errorf("failed spike left owned tasks: %v", guest.spike.owned)
	}
	if guest.tasks.kills == 0 || guest.tasks.deletes == 0 {
		t.Error("cleanup did not kill/delete the leftover tasks")
	}
}

func TestMultiContainerSpikeDetectsIDRejection(t *testing.T) {
	var report strings.Builder
	guest := newFakeGuest(&report)
	guest.tasks.rejectNewIDs = true
	err := guest.spike.runSpike()
	if err == nil {
		t.Fatalf("runSpike succeeded against a single-container guest:\n%s", report.String())
	}
	if !strings.Contains(err.Error(), "arbitrary ID") {
		t.Errorf("error %v does not name the failed premise", err)
	}
	if !strings.Contains(report.String(), "FAIL create+start long-lived container with arbitrary ID") {
		t.Errorf("transcript does not record the failing step:\n%s", report.String())
	}
}

func TestSpikeSyncBuffer(t *testing.T) {
	var buffer syncBuffer
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = fmt.Fprintf(&buffer, "line %d\n", i)
		}()
	}
	wg.Wait()
	if got := strings.Count(buffer.String(), "line "); got != 8 {
		t.Fatalf("got %d lines, want 8", got)
	}
}

func TestSpikeRootfsMountsAreReadOnly(t *testing.T) {
	spike := &mcSpike{}
	mounts := spike.rootfsMounts()
	if len(mounts) != 1 {
		t.Fatalf("flattened rootfs chain has %d mounts, want 1 (RO image only)", len(mounts))
	}
	for _, option := range mounts[0].Options {
		if option == "rw" {
			t.Fatal("spike rootfs must be read-only: two writable stacks would fight over the rwlayer device")
		}
	}
	spike.opts.LayerSet = &LayerSet{FSMeta: "/dev/vdb", Layers: []string{"/dev/vdc"}}
	mounts = spike.rootfsMounts()
	if len(mounts) != 1 {
		t.Fatalf("layerset rootfs chain has %d mounts, want 1 (RO fsmeta only)", len(mounts))
	}
}
