package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/shares"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func newGuestToolsShareManager(t *testing.T, org *policy.Config) (*ShareManager, *config.ConfigStore) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state", "sandboxes")
	t.Setenv("GANTRY_HOME", root)
	dir := filepath.Join(root, "dev")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store := newTestConfigStore(t, dir, config.RunConfig{RW: true, OrgPolicy: org})
	m, _, err := NewShareManager(dir, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m, store
}

func TestGuestToolsShareWorksWithDefaultDenyWithoutGrantingDirectoryAccess(t *testing.T) {
	m, store := newGuestToolsShareManager(t, policytest.Signed(t, policy.Profile{}))
	hostDir := t.TempDir()
	for _, tag := range []string{guestToolsShareTag, "gantry-guest-tools-lookalike", "ordinary"} {
		if _, err := m.Add(tag+"="+hostDir+",ro", false, true); err == nil || !strings.Contains(err.Error(), "denied mount.read") {
			t.Fatalf("tag %s bypassed organization mount policy: %v", tag, err)
		}
	}
	payload := []byte("only the daemon-provisioned helper")
	failedInstall := errors.New("install failed")
	var priorPath string
	for _, installErr := range []error{nil, failedInstall} {
		var entry shares.Entry
		err := m.WithGuestToolsShare(context.Background(), payload, func(got shares.Entry) error {
			entry = got
			if !got.RO || got.Tag != guestToolsShareTag || got.CtrPath != "/host/gantry-tools" || got.State != "active" {
				t.Fatalf("unexpected payload export: %+v", got)
			}
			files, err := os.ReadDir(got.Path)
			if err != nil || len(files) != 1 || files[0].Name() != "gantry-guest" {
				t.Fatalf("not a single-file payload: %v %v", files, err)
			}
			raw, err := os.ReadFile(filepath.Join(got.Path, "gantry-guest"))
			if err != nil || string(raw) != string(payload) {
				t.Fatalf("payload = %q, %v", raw, err)
			}
			if d := m.governance.Evaluate(context.Background(), policy.MountRead, policy.Resource{Path: got.Path}); d.Effect != "deny" {
				t.Fatalf("delivery widened mount policy: %+v", d)
			}
			if got := store.Snapshot().Shares; len(got) != 0 {
				t.Fatalf("bootstrap persisted a mount grant: %v", got)
			}
			return installErr
		})
		if !errors.Is(err, installErr) {
			t.Fatalf("delivery = %v, want %v", err, installErr)
		}
		if _, err := os.Stat(entry.Path); !os.IsNotExist(err) {
			t.Fatalf("staging survived delivery: %v", err)
		}
		if entry.Path == "" || entry.Path == priorPath {
			t.Fatal("retry did not own a fresh payload directory")
		}
		priorPath = entry.Path
		for _, got := range m.Entries() {
			if got.State == "active" || got.State == "draining" {
				t.Fatalf("payload still accessible after delivery: %+v", got)
			}
		}
	}
}

func TestGuestToolsShareCannotBeReplacedRemovedOrPromotedByOrdinaryAPI(t *testing.T) {
	// Without an organization policy all these ordinary mutations would be
	// allowed. Their rejection must come from active payload ownership.
	m, store := newGuestToolsShareManager(t, nil)
	other := t.TempDir()
	err := m.WithGuestToolsShare(context.Background(), []byte("helper"), func(entry shares.Entry) error {
		for _, spec := range []string{guestToolsShareTag + "=" + other + ",ro", guestToolsShareTag + "=" + entry.Path + ",ro", guestToolsShareTag + "=" + entry.Path} {
			if _, err := m.Add(spec, true, true); err == nil || !strings.Contains(err.Error(), "reserved for guest-tools") {
				t.Fatalf("payload mutation: %v", err)
			}
		}
		if _, err := m.ConfigureRestart(guestToolsShareTag+"="+entry.Path+",ro", true); err == nil || !strings.Contains(err.Error(), "reserved for guest-tools") {
			t.Fatalf("payload persisted through restart configuration: %v", err)
		}
		for _, force := range []bool{false, true} {
			if _, err := m.Remove(guestToolsShareTag, true, force); err == nil || !strings.Contains(err.Error(), "reserved for guest-tools") {
				t.Fatalf("payload removal: %v", err)
			}
		}
		if err := m.WithGuestToolsShare(context.Background(), []byte("replacement"), func(shares.Entry) error { t.Fatal("overlapping delivery entered callback"); return nil }); err == nil {
			t.Fatal("overlapping delivery succeeded")
		}
		if len(store.Snapshot().Shares) != 0 {
			t.Fatal("payload promoted to persistent user mount")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A user tag is not silently overwritten by a subsequent delivery either.
	entry, err := m.Add(guestToolsShareTag+"="+other+",ro", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.WithGuestToolsShare(context.Background(), []byte("helper"), func(shares.Entry) error { t.Fatal("delivery replaced user export"); return nil }); err == nil {
		t.Fatal("user export overwritten")
	}
	if got := m.Entries(); len(got) != 1 || got[0].Path != entry.Path {
		t.Fatalf("user export changed: %v", got)
	}
}

type guestToolsDeadlinePolicy struct {
	mu      sync.RWMutex
	expires time.Time
}

func (p *guestToolsDeadlinePolicy) Authorize(context.Context, string, policy.Resource) error {
	return nil
}

func (p *guestToolsDeadlinePolicy) Evaluate(context.Context, string, policy.Resource) policy.Decision {
	return policy.Decision{Effect: "allow", Reason: "test"}
}

func (p *guestToolsDeadlinePolicy) ExpiresAt() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.expires
}

func (p *guestToolsDeadlinePolicy) SetDeadline(deadline time.Time) {
	p.mu.Lock()
	p.expires = deadline
	p.mu.Unlock()
}

func TestGuestToolsShareRespectsExpiryAndCancellation(t *testing.T) {
	m, _ := newGuestToolsShareManager(t, nil)
	governance := &guestToolsDeadlinePolicy{}
	setDeadline := func(deadline time.Time) {
		governance.SetDeadline(deadline)
		m.mu.Lock()
		defer m.mu.Unlock()
		m.governance = governance
		m.policyDeadline = deadline
		m.hub.SetDeadline(deadline)
	}
	setDeadline(time.Now().Add(time.Hour))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.WithGuestToolsShare(ctx, []byte("helper"), func(shares.Entry) error { t.Fatal("canceled delivery used payload"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	err := m.WithGuestToolsShare(context.Background(), []byte("helper"), func(shares.Entry) error {
		setDeadline(time.Now().Add(-time.Second))
		if n, status := m.Hub().HandleRequest(nil, nil); n != 0 || status != fuse.EACCES {
			t.Fatalf("expired infrastructure export served a request: %d %v", n, status)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.WithGuestToolsShare(context.Background(), []byte("helper"), func(shares.Entry) error { t.Fatal("expired delivery used payload"); return nil }); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired admission: %v", err)
	}
}

func TestGuestToolsStageBaseAvoidsWindowsTempAndProtectedState(t *testing.T) {
	appRoot := t.TempDir()
	sandboxRoot := filepath.Join(appRoot, "sandboxes")
	t.Setenv("GANTRY_HOME", sandboxRoot)
	sandboxDir := filepath.Join(sandboxRoot, "dev")
	want := appRoot + "-guest-tools"
	if got := guestToolsStageBase("windows", sandboxDir); got != want {
		t.Fatalf("Windows stage base = %q, want %q", got, want)
	}
	if got := guestToolsStageBase("windows", ""); got != "" {
		t.Fatalf("Windows stage without state = %q", got)
	}
	if got := guestToolsStageBase("linux", sandboxDir); got != "" {
		t.Fatalf("Linux stage = %q, want OS temp", got)
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
			t.Fatalf("callback error = %v, want %v", err, wantErr)
		}
		if _, err := os.Stat(stageDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("staging directory still exists: %s (%v)", stageDir, err)
		}
	}
	if attempts[0] == attempts[1] {
		t.Fatalf("retry staging directories = %v", attempts)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("staging retained artifacts: %v", entries)
	}
}
