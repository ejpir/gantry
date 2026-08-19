package importer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dryRunTestPlan(t *testing.T) *dockerImportPlan {
	t.Helper()
	rt := &dockerRuntime{}
	rt.Spec.RuntimeName = "codex-dev"
	rt.Spec.Services.Domains = map[string]string{"api.github.com": ""}
	return &dockerImportPlan{
		sourceName: "codex-dev",
		targetName: "codex-dev",
		runtime:    rt,
	}
}

// TestPrepareDryRunIsReadOnly: --dry-run promises "without changing
// anything". With GANTRY_HOME pointed at an empty directory the guest
// assets are missing, so any ensure/download attempt would fail under the
// sandbox firewall — a successful prepare proves none happened — and the
// netpol path must be resolved without the file being written.
func TestPrepareDryRunIsReadOnly(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	plan := dryRunTestPlan(t)
	if err := plan.prepare(t.TempDir(), func(string, ...any) {}, true); err != nil {
		t.Fatal(err)
	}
	if plan.config.Kernel == "" || plan.config.Rootfs == "" {
		t.Fatalf("dry-run config lost kernel/rootfs: %+v", plan.config)
	}
	if _, err := os.Stat(plan.config.Kernel); !os.IsNotExist(err) {
		t.Fatalf("dry-run staged a kernel at %s", plan.config.Kernel)
	}
	if plan.config.NetPol == "" {
		t.Fatal("dry-run config lost the imported netpol path")
	}
	if _, err := os.Stat(plan.config.NetPol); !os.IsNotExist(err) {
		t.Fatalf("dry-run wrote netpol file %s", plan.config.NetPol)
	}
	netpolDir := filepath.Dir(plan.config.NetPol)
	if _, err := os.Stat(netpolDir); !os.IsNotExist(err) {
		t.Fatalf("dry-run created netpol directory %s", netpolDir)
	}
}

// TestPersistNetpolRunsAfterResolution: the policy file is written only by
// the post-clone step, carrying exactly the imported domains.
func TestPersistNetpolRunsAfterResolution(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	plan := dryRunTestPlan(t)
	if err := plan.prepare(t.TempDir(), func(string, ...any) {}, true); err != nil {
		t.Fatal(err)
	}
	if err := plan.persistNetpol(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(plan.config.NetPol)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "api.github.com") {
		t.Fatalf("persisted netpol = %s", b)
	}
}

func TestPersistNetpolWithoutServicesIsANoOp(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	plan := dryRunTestPlan(t)
	plan.runtime.Spec.Services.Domains = nil
	if err := plan.prepare(t.TempDir(), func(string, ...any) {}, true); err != nil {
		t.Fatal(err)
	}
	if plan.config.NetPol != "" {
		t.Fatalf("netpol path = %q, want empty", plan.config.NetPol)
	}
	if err := plan.persistNetpol(); err != nil {
		t.Fatal(err)
	}
}
