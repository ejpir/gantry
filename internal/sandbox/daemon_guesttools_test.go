package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/config"
)

func TestMCPReadyTimeoutCoversBothGuestToolDeliveryAttempts(t *testing.T) {
	if got := sandboxDaemonReadyTimeout(config.RunConfig{}); got != defaultSandboxDaemonReadyTimeout {
		t.Fatalf("ordinary ready timeout = %s, want %s", got, defaultSandboxDaemonReadyTimeout)
	}
	if got := sandboxDaemonReadyTimeout(config.RunConfig{SSH: true, DevContainers: true}); got != defaultSandboxDaemonReadyTimeout {
		t.Fatalf("async SSH/Dev Containers ready timeout = %s, want %s", got, defaultSandboxDaemonReadyTimeout)
	}
	got := sandboxDaemonReadyTimeout(config.RunConfig{MCP: true})
	if wantMin := 2*guestToolsTimeout + time.Second; got < wantMin {
		t.Fatalf("MCP ready timeout = %s, want at least %s", got, wantMin)
	}
}

func TestSSHWaitsForAsynchronousGuestToolsDelivery(t *testing.T) {
	br := &broker{guestToolsDone: make(chan struct{})}
	result := make(chan bool, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		result <- br.waitForGuestTools(context.Background(), false)
	}()
	<-started
	select {
	case <-result:
		t.Fatal("SSH wait returned before guest-tools delivery completed")
	default:
	}

	br.guestToolsReady.Store(true)
	br.finishGuestToolsDelivery(false)
	br.finishGuestToolsDelivery(false) // completion is idempotent across shutdown paths
	if ready := <-result; !ready {
		t.Fatal("SSH wait did not observe delivered guest tools")
	}
}

func TestSSHGuestToolsWaitReportsFailureAndCancellation(t *testing.T) {
	failed := &broker{guestToolsDone: make(chan struct{})}
	failed.finishGuestToolsDelivery(false)
	if failed.waitForGuestTools(context.Background(), false) {
		t.Fatal("failed guest-tools delivery reported ready")
	}

	pending := &broker{guestToolsDone: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if pending.waitForGuestTools(ctx, false) {
		t.Fatal("canceled SSH request reported guest tools ready")
	}
}

func TestMCPAndDevContainersSplitSynchronousAndAsyncHelperDelivery(t *testing.T) {
	plan := planGuestToolsDelivery(config.RunConfig{SSH: true, DevContainers: true, MCP: true})
	if !plan.workloadRequired || plan.workloadAsync || !plan.ideAsync {
		t.Fatalf("MCP+IDE helper plan = %+v", plan)
	}
	sshOnly := planGuestToolsDelivery(config.RunConfig{SSH: true})
	if sshOnly.workloadRequired || !sshOnly.workloadAsync || sshOnly.ideAsync {
		t.Fatalf("SSH-only helper plan = %+v", sshOnly)
	}
}

func TestGuestToolsReadinessIsIndependentPerOCIRoot(t *testing.T) {
	br := &broker{guestToolsDone: make(chan struct{}), ideToolsDone: make(chan struct{})}
	br.guestToolsReady.Store(true)
	br.finishGuestToolsDelivery(false)
	if !br.waitForGuestTools(context.Background(), false) {
		t.Fatal("workload helper did not report ready")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if br.waitForGuestTools(ctx, true) {
		t.Fatal("IDE helper inherited workload readiness")
	}
	br.ideToolsReady.Store(true)
	br.finishGuestToolsDelivery(true)
	if !br.waitForGuestTools(context.Background(), true) {
		t.Fatal("IDE helper did not report ready")
	}
}

func TestGuestToolsTargetsSeparateWorkloadAndIDE(t *testing.T) {
	ideOnly := guestToolsTargets(config.RunConfig{SSH: true, DevContainers: true})
	if len(ideOnly) != 1 || !ideOnly[0].ide {
		t.Fatalf("IDE-only helper targets = %+v", ideOnly)
	}
	both := guestToolsTargets(config.RunConfig{
		SSH: true, DevContainers: true, MCP: true,
	})
	if len(both) != 2 || both[0].ide || !both[1].ide {
		t.Fatalf("workload+IDE helper targets = %+v", both)
	}
	workloadOnly := guestToolsTargets(config.RunConfig{SSH: true})
	if len(workloadOnly) != 1 || workloadOnly[0].ide {
		t.Fatalf("workload helper targets = %+v", workloadOnly)
	}
}

func TestGuestToolsStageBaseAvoidsWindowsTemp(t *testing.T) {
	sandboxDir := filepath.Join("state", "sandboxes", "dev")
	want := filepath.Dir(sandboxDir)
	if got := guestToolsStageBase("windows", sandboxDir); got != want {
		t.Fatalf("Windows stage base = %q, want state root %q", got, want)
	}
	if got := guestToolsStageBase("windows", ""); got != "" {
		t.Fatalf("Windows stage base without sandbox state = %q, want empty", got)
	}
	if got := guestToolsStageBase("linux", sandboxDir); got != "" {
		t.Fatalf("Linux stage base = %q, want OS temporary directory", got)
	}
}

func TestStopGuestToolsDeliveryCancelsAndJoinsOwners(t *testing.T) {
	d := &daemonRuntime{}
	ctx, done, ok := d.beginGuestToolsDelivery()
	if !ok {
		t.Fatal("first guest-tools delivery was refused")
	}
	canceled := make(chan struct{})
	release := make(chan struct{})
	ownerExited := make(chan struct{})
	go func() {
		defer close(ownerExited)
		defer done()
		<-ctx.Done()
		close(canceled)
		<-release
	}()

	stopReturned := make(chan struct{})
	go func() {
		d.stopGuestToolsDelivery()
		close(stopReturned)
	}()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("teardown did not cancel guest-tools delivery")
	}
	select {
	case <-stopReturned:
		t.Fatal("teardown returned before guest-tools owner exited")
	default:
	}
	close(release)
	select {
	case <-ownerExited:
	case <-time.After(time.Second):
		t.Fatal("guest-tools owner did not exit")
	}
	select {
	case <-stopReturned:
	case <-time.After(time.Second):
		t.Fatal("teardown did not join guest-tools owner")
	}
	if _, _, ok := d.beginGuestToolsDelivery(); ok {
		t.Fatal("delivery began after teardown started")
	}

	// Deferred close calls stop a second time; idempotence must not block.
	secondStop := make(chan struct{})
	go func() {
		d.stopGuestToolsDelivery()
		close(secondStop)
	}()
	select {
	case <-secondStop:
	case <-time.After(time.Second):
		t.Fatal("second guest-tools stop blocked")
	}
}

func TestGuestToolsStagingIsAttemptScoped(t *testing.T) {
	base := t.TempDir()
	payload := []byte("guest-helper")
	wantErr := errors.New("injected delivery failure")
	var attempts []string
	for range 2 {
		var stageDir string
		err := withGuestToolsStage(base, payload, func(dir string) error {
			stageDir = dir
			attempts = append(attempts, dir)
			got, err := os.ReadFile(filepath.Join(dir, "gantry-guest"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(payload) {
				t.Fatalf("staged payload = %q, want %q", got, payload)
			}
			return wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("staging callback error = %v, want %v", err, wantErr)
		}
		if _, err := os.Stat(stageDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("attempt staging directory still exists: %s (%v)", stageDir, err)
		}
	}
	if len(attempts) != 2 || attempts[0] == attempts[1] {
		t.Fatalf("retry staging directories = %v, want two distinct attempts", attempts)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("staging base retained retry artifacts: %v", entries)
	}
}

func TestParseGuestToolsVerificationIgnoresSessionDiagnostics(t *testing.T) {
	const wantSum = "e6a4c87f683ab0c07fd85517986f5a488c5359b19b1314546ec2d12a2e76bb23"
	transcript := []byte("client: task started — shell is live\n" +
		"client: bytes sha256 task\n" +
		"GANTRY_GUEST_TOOLS_VERIFY 2556066 " + wantSum + "\n" +
		"client: task exited, status 0\n")
	size, sum := parseGuestToolsVerification(transcript)
	if size != "2556066" || sum != wantSum {
		t.Fatalf("verification = (%q, %q), want (%q, %q)", size, sum, "2556066", wantSum)
	}
}

func TestParseGuestToolsVerificationRequiresTaggedValidDigest(t *testing.T) {
	transcript := []byte("2556066\n" +
		"e6a4c87f683ab0c07fd85517986f5a488c5359b19b1314546ec2d12a2e76bb23  /run/gantry/bin/gantry-guest\n" +
		"GANTRY_GUEST_TOOLS_VERIFY 2556066 not-a-digest\n")
	size, sum := parseGuestToolsVerification(transcript)
	if size != "" || sum != "" {
		t.Fatalf("verification = (%q, %q), want invalid record rejected", size, sum)
	}
}
