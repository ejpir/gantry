package manager

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
	"github.com/ejpir/gantry/internal/policyfeed"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"
)

type policyRolloutLifecycle struct {
	lock     *os.File
	stops    int
	starts   int
	applies  int
	startErr error
}

func (l *policyRolloutLifecycle) Start(_ context.Context, request lifecycle.StartRequest, _ lifecycle.Observer) (lifecycle.StartResult, error) {
	if request.Mode != lifecycle.Resume {
		return lifecycle.StartResult{}, os.ErrInvalid
	}
	l.starts++
	if l.startErr != nil {
		err := l.startErr
		l.startErr = nil
		return lifecycle.StartResult{}, err
	}
	return lifecycle.StartResult{Name: request.Name}, nil
}

func (l *policyRolloutLifecycle) Stop(name string) error {
	l.stops++
	if l.lock != nil {
		_ = l.lock.Close()
		l.lock = nil
	}
	_ = os.Remove(filepath.Join(layout.Dir(name), "vmm.pid"))
	return nil
}

func (*policyRolloutLifecycle) Delete(string) error { return nil }
func (*policyRolloutLifecycle) Exec(context.Context, string, ExecRequest) (ExecResult, error) {
	return ExecResult{}, nil
}
func (l *policyRolloutLifecycle) ApplyOrganizationPolicy(_ context.Context, name string, snapshot *policy.Config) error {
	l.applies++
	store, err := config.LoadConfigStore(layout.Dir(name))
	if err != nil {
		return err
	}
	return store.SetOrganizationPolicy(snapshot)
}

func TestOrganizationPolicyControlledRestart(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	if err := layout.EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	name := "dev"
	dir := layout.Dir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.WriteSandboxConfig(dir, config.RunConfig{MemMB: 512, VCPUs: 1}); err != nil {
		t.Fatal(err)
	}
	lock, err := layout.HoldLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vmm.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		_ = lock.Close()
		t.Fatal(err)
	}
	backend := &policyRolloutLifecycle{lock: lock}
	service := newManagerService(backend)
	candidate := policytest.Signed(t, policy.Profile{})
	if err := service.setOrganizationPolicyLocked(context.Background(), name, candidate, true, nil); err != nil {
		t.Fatal(err)
	}
	if backend.stops != 1 || backend.starts != 1 {
		t.Fatalf("stop/start = %d/%d, want 1/1", backend.stops, backend.starts)
	}
	saved, err := config.ReadSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !sameOrganizationPolicy(saved.OrgPolicy, candidate) {
		t.Fatal("candidate policy was not persisted")
	}
	if _, err := os.Stat(policyRolloutMarkerPath(name)); !os.IsNotExist(err) {
		t.Fatalf("rollout marker remains after success: %v", err)
	}
}

func TestOrganizationPolicyControlledRestartRetriesFailedResume(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	if err := layout.EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	name := "dev"
	dir := layout.Dir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.WriteSandboxConfig(dir, config.RunConfig{MemMB: 512, VCPUs: 1}); err != nil {
		t.Fatal(err)
	}
	lock, err := layout.HoldLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vmm.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		_ = lock.Close()
		t.Fatal(err)
	}
	backend := &policyRolloutLifecycle{lock: lock, startErr: errors.New("boot failed")}
	service := newManagerService(backend)
	candidate := policytest.Signed(t, policy.Profile{})
	if err := service.setOrganizationPolicyLocked(context.Background(), name, candidate, true, nil); err == nil || !strings.Contains(err.Error(), "remains stopped") {
		t.Fatalf("first rollout error = %v", err)
	}
	if _, err := os.Stat(policyRolloutMarkerPath(name)); err != nil {
		t.Fatalf("rollout marker missing after failed resume: %v", err)
	}
	if err := service.setOrganizationPolicyLocked(context.Background(), name, candidate, true, nil); err != nil {
		t.Fatal(err)
	}
	if backend.stops != 1 || backend.starts != 2 {
		t.Fatalf("stop/start = %d/%d, want 1/2", backend.stops, backend.starts)
	}
	if _, err := os.Stat(policyRolloutMarkerPath(name)); !os.IsNotExist(err) {
		t.Fatalf("rollout marker remains after retry: %v", err)
	}
}

func TestOrganizationPolicyControlledRestartRecoversResume(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	if err := layout.EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	name := "dev"
	dir := layout.Dir(name)
	candidate := policytest.Signed(t, policy.Profile{})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.WriteSandboxConfig(dir, config.RunConfig{MemMB: 512, VCPUs: 1, OrgPolicy: candidate}); err != nil {
		t.Fatal(err)
	}
	if err := writePolicyRolloutMarker(name, policyConfigDigest(candidate)); err != nil {
		t.Fatal(err)
	}
	backend := &policyRolloutLifecycle{}
	service := newManagerService(backend)
	if err := service.setOrganizationPolicyLocked(context.Background(), name, candidate, true, nil); err != nil {
		t.Fatal(err)
	}
	if backend.stops != 0 || backend.starts != 1 {
		t.Fatalf("stop/start = %d/%d, want 0/1", backend.stops, backend.starts)
	}
	if _, err := os.Stat(policyRolloutMarkerPath(name)); !os.IsNotExist(err) {
		t.Fatalf("rollout marker remains after recovery: %v", err)
	}
}

func TestOrganizationPolicyRunningUpdateAppliesLive(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	if err := layout.EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	name := "dev"
	dir := layout.Dir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.WriteSandboxConfig(dir, config.RunConfig{MemMB: 512, VCPUs: 1}); err != nil {
		t.Fatal(err)
	}
	lock, err := layout.HoldLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := os.WriteFile(filepath.Join(dir, "vmm.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &policyRolloutLifecycle{lock: lock}
	service := newManagerService(backend)
	candidate := policytest.Signed(t, policy.Profile{})
	if err := service.setOrganizationPolicyLocked(context.Background(), name, candidate, false, nil); err != nil {
		t.Fatal(err)
	}
	if backend.stops != 0 || backend.starts != 0 || backend.applies != 1 {
		t.Fatalf("stop/start/apply = %d/%d/%d, want 0/0/1", backend.stops, backend.starts, backend.applies)
	}
	saved, err := config.ReadSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !sameOrganizationPolicy(saved.OrgPolicy, candidate) {
		t.Fatal("live candidate policy was not persisted")
	}
}

func TestReceivedOrganizationPolicyFansOutToRunningAndStoppedSandboxes(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	if err := layout.EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"running", "stopped"} {
		dir := layout.Dir(name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := config.WriteSandboxConfig(dir, config.RunConfig{MemMB: 512, VCPUs: 1}); err != nil {
			t.Fatal(err)
		}
	}
	lock, err := layout.HoldLock(layout.Dir("running"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := os.WriteFile(filepath.Join(layout.Dir("running"), "vmm.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	backend := &policyRolloutLifecycle{lock: lock}
	service := newManagerService(backend)
	candidate := policytest.Signed(t, policy.Profile{})
	if err := service.applyReceivedOrganizationPolicy(context.Background(), feedUpdate(t, candidate)); err != nil {
		t.Fatal(err)
	}
	if backend.applies != 1 || backend.stops != 0 || backend.starts != 0 {
		t.Fatalf("apply/stop/start = %d/%d/%d, want 1/0/0", backend.applies, backend.stops, backend.starts)
	}
	for _, name := range []string{"running", "stopped"} {
		saved, err := config.ReadSandboxConfig(layout.Dir(name))
		if err != nil {
			t.Fatal(err)
		}
		if !sameOrganizationPolicy(saved.OrgPolicy, candidate) {
			t.Fatalf("sandbox %s did not receive organization generation", name)
		}
	}
	if _, running := layout.PID("running"); !running {
		t.Fatal("live organization-wide rollout stopped the successful running sandbox")
	}
	if !sameOrganizationPolicy(service.organizationPolicy, candidate) {
		t.Fatal("manager did not publish the organization policy for future creates")
	}
}

type blockingFeedLifecycle struct {
	entered chan struct{}
	release chan struct{}
	started chan lifecycle.StartRequest
}

func (l *blockingFeedLifecycle) Start(_ context.Context, request lifecycle.StartRequest, _ lifecycle.Observer) (lifecycle.StartResult, error) {
	l.started <- request
	return lifecycle.StartResult{Name: request.Name}, nil
}

func (*blockingFeedLifecycle) Stop(string) error   { return nil }
func (*blockingFeedLifecycle) Delete(string) error { return nil }

func (*blockingFeedLifecycle) Exec(context.Context, string, ExecRequest) (ExecResult, error) {
	return ExecResult{}, nil
}

func (l *blockingFeedLifecycle) ApplyOrganizationPolicy(ctx context.Context, name string, snapshot *policy.Config) error {
	close(l.entered)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.release:
	}
	store, err := config.LoadConfigStore(layout.Dir(name))
	if err != nil {
		return err
	}
	return store.SetOrganizationPolicy(snapshot)
}

func TestReceivedOrganizationPolicyBlocksConcurrentCreateUntilPublication(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	if err := layout.EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	dir := layout.Dir("existing")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.WriteSandboxConfig(dir, config.RunConfig{MemMB: 512, VCPUs: 1}); err != nil {
		t.Fatal(err)
	}
	lock, err := layout.HoldLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := os.WriteFile(filepath.Join(dir, "vmm.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	backend := &blockingFeedLifecycle{
		entered: make(chan struct{}), release: make(chan struct{}),
		started: make(chan lifecycle.StartRequest, 1),
	}
	service := newManagerService(backend)
	candidate := policytest.Signed(t, policy.Profile{})
	update := feedUpdate(t, candidate)
	rolloutDone := make(chan error, 1)
	go func() {
		rolloutDone <- service.applyReceivedOrganizationPolicy(context.Background(), update)
	}()
	select {
	case <-backend.entered:
	case <-time.After(2 * time.Second):
		close(backend.release)
		t.Fatal("feed rollout did not enter live target")
	}
	responseCode := make(chan int, 1)
	go func() {
		response := managerRequest(t, service, http.MethodPost, "/v1/sandboxes", `{"name":"concurrent","image":"cached.example/image"}`, nil)
		responseCode <- response.Code
	}()
	select {
	case request := <-backend.started:
		close(backend.release)
		t.Fatalf("create crossed feed publication barrier: %+v", request)
	case <-time.After(100 * time.Millisecond):
	}
	close(backend.release)
	select {
	case err := <-rolloutDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("feed rollout did not finish after release")
	}
	select {
	case request := <-backend.started:
		if !sameOrganizationPolicy(request.Options.OrganizationSnapshot, candidate) {
			t.Fatal("concurrent create did not inherit the published generation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent create did not resume after policy publication")
	}
	select {
	case code := <-responseCode:
		if code != http.StatusCreated {
			t.Fatalf("concurrent create status = %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent create response did not finish")
	}
}

type failingFeedLifecycle struct {
	lock    *os.File
	stopped int
}

func (*failingFeedLifecycle) Start(context.Context, lifecycle.StartRequest, lifecycle.Observer) (lifecycle.StartResult, error) {
	return lifecycle.StartResult{}, nil
}

func (l *failingFeedLifecycle) Stop(name string) error {
	l.stopped++
	if l.lock != nil {
		_ = l.lock.Close()
		l.lock = nil
	}
	_ = os.Remove(filepath.Join(layout.Dir(name), "vmm.pid"))
	return nil
}

func (*failingFeedLifecycle) Delete(string) error { return nil }

func (*failingFeedLifecycle) Exec(context.Context, string, ExecRequest) (ExecResult, error) {
	return ExecResult{}, nil
}

func (*failingFeedLifecycle) ApplyOrganizationPolicy(context.Context, string, *policy.Config) error {
	return errors.New("live reconciliation failed")
}

func TestReceivedOrganizationPolicyStopsFailedTargetAndContinuesFanout(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	if err := layout.EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bad", "zz-stopped"} {
		dir := layout.Dir(name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := config.WriteSandboxConfig(dir, config.RunConfig{MemMB: 512, VCPUs: 1}); err != nil {
			t.Fatal(err)
		}
	}
	lock, err := layout.HoldLock(layout.Dir("bad"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := os.WriteFile(filepath.Join(layout.Dir("bad"), "vmm.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	backend := &failingFeedLifecycle{lock: lock}
	service := newManagerService(backend)
	candidate := policytest.Signed(t, policy.Profile{})
	err = service.applyReceivedOrganizationPolicy(context.Background(), feedUpdate(t, candidate))
	if err == nil || !strings.Contains(err.Error(), "sandbox bad") {
		t.Fatalf("aggregate rollout error = %v", err)
	}
	var rollout *policyfeed.RolloutError
	if !errors.As(err, &rollout) || rollout.Failed != 1 || rollout.Total != 2 {
		t.Fatalf("rollout counts = %#v, want 1 of 2 failed", rollout)
	}
	if backend.stopped != 1 {
		t.Fatalf("fail-closed stops = %d, want 1", backend.stopped)
	}
	if _, running := layout.PID("bad"); running {
		t.Fatal("failed organization-policy target remains running")
	}
	response := managerRequest(t, service, http.MethodPost, "/v1/sandboxes/bad/start", "", nil)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "has not accepted the active organization-wide policy") {
		t.Fatalf("failed target restart = %d %s", response.Code, response.Body.String())
	}
	saved, err := config.ReadSandboxConfig(layout.Dir("zz-stopped"))
	if err != nil {
		t.Fatal(err)
	}
	if !sameOrganizationPolicy(saved.OrgPolicy, candidate) {
		t.Fatal("fanout stopped after the first failed target")
	}
	if !sameOrganizationPolicy(service.organizationPolicy, candidate) {
		t.Fatal("failed fanout did not retain the mandatory policy for later creates")
	}
}

func TestReceivedOrganizationPolicyPublishesAdmissionBeforeEnumeration(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(root, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GANTRY_HOME", root)
	service := newManagerService(functionLifecycle{})
	candidate := policytest.Signed(t, policy.Profile{})
	if err := service.applyReceivedOrganizationPolicy(context.Background(), feedUpdate(t, candidate)); err == nil {
		t.Fatal("unreadable sandbox root unexpectedly completed rollout")
	}
	if !sameOrganizationPolicy(service.organizationPolicy, candidate) {
		t.Fatal("enumeration failure left manager admission unmanaged")
	}
}

func TestReceivedOrganizationPolicyIsInheritedAndCannotBeCleared(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	candidate := policytest.Signed(t, policy.Profile{})
	var started lifecycle.StartRequest
	service := newManagerService(functionLifecycle{
		start: func(_ context.Context, request lifecycle.StartRequest, _ lifecycle.Observer) (lifecycle.StartResult, error) {
			started = request
			return lifecycle.StartResult{Name: request.Name}, nil
		},
	})
	if err := service.applyReceivedOrganizationPolicy(context.Background(), feedUpdate(t, candidate)); err != nil {
		t.Fatal(err)
	}
	response := managerRequest(t, service, http.MethodPost, "/v1/sandboxes", `{"name":"future","image":"cached.example/image"}`, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", response.Code, response.Body.String())
	}
	if !sameOrganizationPolicy(started.Options.OrganizationSnapshot, candidate) {
		t.Fatal("new sandbox did not inherit the active organization-wide policy")
	}
	response = managerRequest(t, service, http.MethodPut, "/v1/sandboxes/future/policy", `{"clear":true}`, nil)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "organization-wide policy feed controls") {
		t.Fatalf("policy clear = %d %s", response.Code, response.Body.String())
	}
}

func feedUpdate(t *testing.T, snapshot *policy.Config) policyfeed.Update {
	t.Helper()
	engine, err := policy.New(snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	return policyfeed.Update{Generation: 1, Snapshot: snapshot, Info: engine.Info()}
}
