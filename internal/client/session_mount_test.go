package client

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/shares"

	v3 "github.com/containerd/containerd/api/runtime/task/v3"
	tasktypes "github.com/containerd/containerd/api/types/task"
	mountapi "github.com/containerd/nerdbox/api/services/mount/v1"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

type mountSetupService struct {
	mu       sync.Mutex
	mountErr error
	targets  []string
}

func (s *mountSetupService) MountAll(context.Context, *mountapi.MountAllRequest) (*mountapi.MountAllResponse, error) {
	return &mountapi.MountAllResponse{}, s.mountErr
}

func (s *mountSetupService) Unmount(_ context.Context, request *mountapi.UnmountRequest) (*mountapi.UnmountResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targets = append(s.targets, request.Target)
	return &mountapi.UnmountResponse{}, nil
}

func (*mountSetupService) UnmountAll(context.Context, *mountapi.UnmountAllRequest) (*mountapi.UnmountAllResponse, error) {
	return &mountapi.UnmountAllResponse{}, nil
}

func (s *mountSetupService) unmounted() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.targets...)
}

type sandboxSetupTask struct {
	v3.TTRPCTaskService

	mu        sync.Mutex
	createErr error
	state     func(context.Context) (*v3.StateResponse, error)
	creates   int
	starts    int
	deletes   int
}

func (s *sandboxSetupTask) State(ctx context.Context, _ *v3.StateRequest) (*v3.StateResponse, error) {
	s.mu.Lock()
	state := s.state
	s.mu.Unlock()
	if state == nil {
		return nil, errors.New("task not found")
	}
	return state(ctx)
}

func (s *sandboxSetupTask) Create(context.Context, *v3.CreateTaskRequest) (*v3.CreateTaskResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creates++
	return &v3.CreateTaskResponse{}, s.createErr
}

func (s *sandboxSetupTask) Start(context.Context, *v3.StartRequest) (*v3.StartResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.starts++
	return &v3.StartResponse{}, nil
}

func (s *sandboxSetupTask) Delete(context.Context, *v3.DeleteRequest) (*v3.DeleteResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	return &v3.DeleteResponse{}, nil
}

func (s *sandboxSetupTask) calls() (creates, starts, deletes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.creates, s.starts, s.deletes
}

func TestRecordSessionExitStatus(t *testing.T) {
	status := 0
	recordSessionExitStatus(&status, nil, errors.New("Wait transport failed"))
	if status != 255 {
		t.Fatalf("failed Wait status = %d, want 255", status)
	}

	recordSessionExitStatus(&status, &v3.WaitResponse{ExitStatus: 7}, nil)
	if status != 7 {
		t.Fatalf("successful Wait status = %d, want 7", status)
	}
	// A caller that does not request status propagation remains supported.
	recordSessionExitStatus(nil, nil, errors.New("ignored"))
}

func TestBeginMountSetupRollsBackPartialMountFailure(t *testing.T) {
	service := &mountSetupService{mountErr: errors.New("partial mount")}
	options := SessionOptions{
		Shares: []ShareEntry{
			{Tag: "first", VMPath: "/run/mnt/first"},
			{Tag: "second", VMPath: "/run/mnt/second"},
		},
	}
	if _, err := beginMountSetup(context.Background(), service, options, func(string, ...any) {}); err == nil {
		t.Fatal("beginMountSetup succeeded")
	}
	want := []string{
		"/run/mnt/second",
		"/run/mnt/first",
	}
	if got := service.unmounted(); !reflect.DeepEqual(got, want) {
		t.Fatalf("rollback targets = %q, want %q", got, want)
	}
}

func TestMountSetupCommitRetainsDirectMounts(t *testing.T) {
	service := new(mountSetupService)
	options := SessionOptions{Shares: []ShareEntry{{Tag: "code", VMPath: "/run/mnt/code"}}}
	setup, err := beginMountSetup(context.Background(), service, options, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	setup.commit()
	setup.rollback()
	if got := service.unmounted(); len(got) != 0 {
		t.Fatalf("committed setup unmounted %q", got)
	}
}

func TestMountSetupTreatsSuccessfulHubMountAsSandboxOwned(t *testing.T) {
	service := new(mountSetupService)
	options := SessionOptions{ShareTransport: &shares.Transport{Tag: "hostshare", VMPath: "/run/mnt/hub"}}
	setup, err := beginMountSetup(context.Background(), service, options, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if setup.owned {
		t.Fatal("session claimed ownership of the sandbox share hub")
	}
	setup.rollback()
	if got := service.unmounted(); len(got) != 0 {
		t.Fatalf("session rollback unmounted sandbox share hub: %q", got)
	}
}

func TestMountSetupDoesNotUnmountBusyShareHub(t *testing.T) {
	service := &mountSetupService{mountErr: errors.New("mount busy")}
	options := SessionOptions{ShareTransport: &shares.Transport{Tag: "hostshare", VMPath: "/run/mnt/hub"}}
	setup, err := beginMountSetup(context.Background(), service, options, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}

	// A later setup failure belongs to this caller, but the existing mount
	// belongs to the session that won the MountAll race.
	setup.rollback()
	if got := service.unmounted(); len(got) != 0 {
		t.Fatalf("rollback unmounted another session's targets: %q", got)
	}
}

func TestSandboxSetupLoserDoesNotUnmountBusyHub(t *testing.T) {
	service := &mountSetupService{mountErr: errors.New("mount busy")}
	options := SessionOptions{
		ID:             "sandbox",
		ShareTransport: &shares.Transport{Tag: "hostshare", VMPath: "/run/mnt/hub"},
	}
	setup, err := beginMountSetup(context.Background(), service, options, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	task := &sandboxSetupTask{createErr: errors.New("create transport failed")}
	if err := finishSandboxContainerSetup(context.Background(), task, setup, options, "/run/bundles/sandbox", func(string, ...any) {}); err == nil {
		t.Fatal("finishSandboxContainerSetup succeeded")
	}

	if got := service.unmounted(); len(got) != 0 {
		t.Fatalf("losing setup unmounted winner's hub: %q", got)
	}
	creates, starts, deletes := task.calls()
	if creates != 1 || starts != 0 || deletes != 0 {
		t.Fatalf("task calls = create:%d start:%d delete:%d", creates, starts, deletes)
	}
}

func TestSandboxSetupAlreadyExistsWaitsForRunning(t *testing.T) {
	service := &mountSetupService{mountErr: errors.New("mount busy")}
	options := SessionOptions{
		ID:             "sandbox",
		ShareTransport: &shares.Transport{Tag: "hostshare", VMPath: "/run/mnt/hub"},
	}
	setup, err := beginMountSetup(context.Background(), service, options, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}

	var stateCalls atomic.Int32
	stateEntered := make(chan int, 2)
	releaseRunning := make(chan struct{})
	defer func() {
		select {
		case <-releaseRunning:
		default:
			close(releaseRunning)
		}
	}()
	task := &sandboxSetupTask{
		createErr: errors.New("task already exists"),
		state: func(context.Context) (*v3.StateResponse, error) {
			call := int(stateCalls.Add(1))
			stateEntered <- call
			if call == 1 {
				return &v3.StateResponse{Status: tasktypes.Status_CREATED}, nil
			}
			<-releaseRunning
			return &v3.StateResponse{Status: tasktypes.Status_RUNNING}, nil
		},
	}
	done := make(chan error, 1)
	go func() {
		done <- finishSandboxContainerSetup(context.Background(), task, setup, options, "/run/bundles/sandbox", func(string, ...any) {})
	}()

	for want := 1; want <= 2; want++ {
		select {
		case got := <-stateEntered:
			if got != want {
				t.Fatalf("State call = %d, want %d", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for State call %d", want)
		}
	}
	select {
	case err := <-done:
		t.Fatalf("setup returned before RUNNING was observed: %v", err)
	default:
	}
	close(releaseRunning)
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	if got := service.unmounted(); len(got) != 0 {
		t.Fatalf("successful racing setup unmounted winner's hub: %q", got)
	}
	creates, starts, deletes := task.calls()
	if creates != 1 || starts != 0 || deletes != 0 {
		t.Fatalf("task calls = create:%d start:%d delete:%d", creates, starts, deletes)
	}
}

func TestSandboxSetupRaceFailureRetainsIdempotentMount(t *testing.T) {
	service := new(mountSetupService)
	options := SessionOptions{
		ID:     "sandbox",
		Shares: []ShareEntry{{Tag: "code", VMPath: "/run/mnt/code"}},
	}
	setup, err := beginMountSetup(context.Background(), service, options, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	task := &sandboxSetupTask{
		createErr: errors.New("task already exists"),
		state: func(context.Context) (*v3.StateResponse, error) {
			return &v3.StateResponse{Status: tasktypes.Status_CREATED}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := finishSandboxContainerSetup(ctx, task, setup, options, "/run/bundles/sandbox", func(string, ...any) {}); err == nil {
		t.Fatal("finishSandboxContainerSetup succeeded")
	}
	if got := service.unmounted(); len(got) != 0 {
		t.Fatalf("racing setup unmounted a potentially shared mount: %q", got)
	}
}

func TestSandboxSetupDefiniteCreateRejectionRollsBackDirectMount(t *testing.T) {
	service := new(mountSetupService)
	options := SessionOptions{
		ID:     "sandbox",
		Shares: []ShareEntry{{Tag: "code", VMPath: "/run/mnt/code"}},
	}
	setup, err := beginMountSetup(context.Background(), service, options, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	task := &sandboxSetupTask{createErr: grpcstatus.Error(codes.InvalidArgument, "invalid config")}
	if err := finishSandboxContainerSetup(context.Background(), task, setup, options, "/run/bundles/sandbox", func(string, ...any) {}); err == nil {
		t.Fatal("finishSandboxContainerSetup succeeded")
	}
	if got, want := service.unmounted(), []string{"/run/mnt/code"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rollback targets = %q, want %q", got, want)
	}
}
