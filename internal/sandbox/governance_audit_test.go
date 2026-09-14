package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlcmd"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func newPolicyAuditDaemon(t *testing.T) *daemonRuntime {
	t.Helper()
	t.Setenv("GANTRY_HOME", t.TempDir())
	const name = "audit-test"
	dir := layout.Dir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	d := &daemonRuntime{
		name: name, dir: dir, audit: &auditRing{},
		cfg: config.RunConfig{OrgPolicy: policytest.Signed(t, policy.Profile{
			Rules: []policy.Rule{{ID: "credential", Effect: "allow", Action: policy.CredentialUse, Host: "github.com"}},
		})},
	}
	if err := d.loadOrganizationPolicy(); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestOrganizationAuditPersistsBeforeBrokerAndAfterRestart(t *testing.T) {
	d := newPolicyAuditDaemon(t)
	// Initial mount admission precedes broker construction. A failed boot
	// must leave policy provenance in the stopped command's audit.log too.
	const resourceCanary = "PRIVATE-RESOURCE-NOT-FOR-AUDIT"
	denied := d.governance.Evaluate(context.Background(), policy.MountRead, policy.Resource{Path: filepath.Join(d.dir, resourceCanary)})
	if denied.Effect != "deny" || d.broker != nil {
		t.Fatal("test did not exercise a denied pre-broker decision")
	}
	assertStoppedPolicyAudit(t, d, denied)

	// All subsequent producers borrow the same sink writer, not a new file
	// writer/rotation lock. Decisions of both effects must survive shutdown.
	d.broker = &broker{dir: d.dir, audit: d.audit}
	d.broker.auditf("mcp: session open")
	allowed := d.governance.Evaluate(context.Background(), policy.CredentialUse, policy.Resource{Host: "github.com"})
	if allowed.Effect != "allow" {
		t.Fatalf("approved credential: %+v", allowed)
	}
	assertStoppedPolicyAudit(t, d, denied, allowed)
	before, err := controlcmd.AuditTail(d.name)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(before, "\n"), resourceCanary) {
		t.Fatal("persistent policy audit leaked resource data")
	}

	// A fresh daemon ring must append to, not overwrite, the persisted trail.
	restarted := &daemonRuntime{name: d.name, dir: d.dir, cfg: d.cfg, audit: &auditRing{}}
	if err := restarted.loadOrganizationPolicy(); err != nil {
		t.Fatal(err)
	}
	last := restarted.governance.Evaluate(context.Background(), policy.CredentialUse, policy.Resource{Host: "denied.example"})
	assertStoppedPolicyAudit(t, restarted, denied, allowed, last)
	after, err := controlcmd.AuditTail(d.name)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before)+1 || !reflect.DeepEqual(after[:len(before)], before) {
		t.Fatalf("restart lost history: before=%v after=%v", before, after)
	}
}

func assertStoppedPolicyAudit(t *testing.T, d *daemonRuntime, want ...policy.Decision) {
	t.Helper()
	// No ctl.sock is created. Exercise the real command's stopped fallback,
	// rather than merely checking the live ring or reading daemon.log.
	lines, err := controlcmd.AuditTail(d.name)
	if err != nil {
		t.Fatal(err)
	}
	var got []policy.Decision
	for _, line := range lines {
		if raw, ok := strings.CutPrefix(line, "policy: "); ok {
			var decision policy.Decision
			if err := json.Unmarshal([]byte(raw), &decision); err != nil {
				t.Fatalf("invalid persisted decision: %v", err)
			}
			got = append(got, decision)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("persisted provenance: got=%+v want=%+v", got, want)
	}
}

func TestOrganizationAndBrokerAuditShareRotationAndOrdering(t *testing.T) {
	d := newPolicyAuditDaemon(t)
	br := &broker{dir: d.dir, audit: d.audit}
	path := filepath.Join(d.dir, "audit.log")
	seed := strings.Repeat("old-event\n", auditLogCap/len("old-event\n")+1)
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	// Both paths race the first rotation. Every new event must survive once,
	// in exactly the same order as its live-ring counterpart.
	const producers = 48
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range producers {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			d.governance.Evaluate(context.Background(), policy.CredentialUse, policy.Resource{Host: "denied.example"})
		}()
		go func() {
			defer wg.Done()
			<-start
			br.auditf("mcp: event-%d", i)
		}()
	}
	close(start)
	wg.Wait()
	live := d.audit.tail()
	if len(live) != 2*producers {
		t.Fatalf("live count=%d", len(live))
	}
	persisted, err := controlcmd.AuditTail(d.name)
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted) < len(live) || !reflect.DeepEqual(persisted[len(persisted)-len(live):], live) {
		t.Fatalf("rotation lost/reordered events: persisted=%v live=%v", persisted, live)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > auditLogCap {
		t.Fatalf("audit did not rotate: %d bytes", info.Size())
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("audit mode=%v, want 0600", info.Mode().Perm())
	}
}

func TestOrganizationAuditDiskFailureKeepsLiveDecision(t *testing.T) {
	d := newPolicyAuditDaemon(t)
	if err := os.Mkdir(filepath.Join(d.dir, "audit.log"), 0o700); err != nil {
		t.Fatal(err)
	}
	decision := d.governance.Evaluate(context.Background(), policy.CredentialUse, policy.Resource{Host: "github.com"})
	if decision.Effect != "allow" {
		t.Fatalf("audit disk failure changed authorization: %+v", decision)
	}
	lines := d.audit.tail()
	if len(lines) != 1 || !strings.Contains(lines[0], `"effect":"allow"`) {
		t.Fatalf("live audit lost decision after disk failure: %v", lines)
	}
}
