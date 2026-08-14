package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/shares"
)

func TestDashboardSnapshotLoadsSandboxData(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	for _, name := range []string{"zeta", "alpha"} {
		if err := os.MkdirAll(sandboxDir(name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rwLayer := filepath.Join(t.TempDir(), "alpha.ext4")
	if err := os.WriteFile(rwLayer, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(rwLayer, 2<<30); err != nil {
		t.Fatal(err)
	}
	writeDashboardTestConfig(t, "alpha", RunConfig{
		Image: "/cache/alpine.erofs", ImageRef: "alpine:latest", Runtime: "crun", Kernel: "/cache/gantry-kernel-arm64",
		RW: true, RWLayer: rwLayer, RWLayerSizeMiB: 1024, Net: true, MemMB: 768, VCPUs: 2,
		Shares: []string{"code=/tmp"}, Ports: []string{"127.0.0.1:8080:80"}, SecretNames: []string{"TOKEN"},
	})
	traffic := netpol.TrafficSnapshot{
		Version: 1, TXBytes: 1200, RXBytes: 3400, DroppedPackets: 2,
		Entries: []netpol.TrafficEntry{{
			Host: "example.com", Address: "93.184.216.34", Protocol: "tcp", Port: 443,
			Allowed: true, TXBytes: 1200, RXBytes: 3400, LastSeen: time.Now(),
		}},
	}
	trafficJSON, err := json.Marshal(traffic)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandboxDir("alpha"), netpol.TrafficFileName), trafficJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := loadDashboardSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Sandboxes) != 2 || got.Sandboxes[0].Name != "alpha" || got.Sandboxes[1].Name != "zeta" {
		t.Fatalf("sandboxes = %#v, want alpha then zeta", got.Sandboxes)
	}
	alpha := got.Sandboxes[0]
	if alpha.Image != "alpine:latest" || !alpha.RW || !alpha.Net || alpha.Secrets != "TOKEN" {
		t.Fatalf("alpha metadata = %#v", alpha)
	}
	if alpha.Runtime != "crun" || alpha.MemMB != 768 || alpha.VCPUs != 2 || alpha.Shares != 1 {
		t.Fatalf("alpha runtime metadata = %#v", alpha)
	}
	if alpha.Kernel != "/cache/gantry-kernel-arm64" || alpha.RWLayer != rwLayer || alpha.DiskSizeMiB != 2048 || alpha.Ports != 1 {
		t.Fatalf("alpha storage metadata = %#v", alpha)
	}
	if alpha.TXBytes != 1200 || alpha.RXBytes != 3400 || alpha.DroppedPackets != 2 {
		t.Fatalf("alpha traffic totals = %#v", alpha)
	}
	if len(got.Traffic) != 2 || got.Traffic[0].Host != "example.com" || got.Traffic[1].Host != "unclassified traffic" || got.Traffic[1].Allowed {
		t.Fatalf("traffic rows = %#v", got.Traffic)
	}
	if len(got.Rules) != 4 || got.Rules[0].Target != "IPv6 and non-IPv4 traffic" || !got.Rules[3].Error {
		t.Fatalf("rule rows = %#v", got.Rules)
	}
	if len(got.Mounts) != 2 || got.Mounts[0].Tag != "code" || got.Mounts[0].Guest != "/host/code" || got.Mounts[1].Error == "" {
		t.Fatalf("mount rows = %#v", got.Mounts)
	}
	if len(got.Secrets) != 1 || got.Secrets[0].Sandbox != "alpha" || got.Secrets[0].Name != "TOKEN" || got.Secrets[0].State != "required next start" {
		t.Fatalf("secret rows = %#v", got.Secrets)
	}
	if !got.Sandboxes[1].ConfigError {
		t.Fatal("missing sandbox.json should be surfaced on the card")
	}
}

func TestDashboardDiskSizeFallsBackToConfiguredCapacity(t *testing.T) {
	cfg := RunConfig{RWLayer: filepath.Join(t.TempDir(), "missing.ext4"), RWLayerSizeMiB: 4096}
	if got := dashboardDiskSizeMiB(cfg); got != 4096 {
		t.Fatalf("disk size = %d MiB, want configured 4096 MiB", got)
	}
}

func TestDashboardMountsMergeLiveAndDesiredState(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	name := "live"
	if err := os.MkdirAll(sandboxDir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := `{
		"version":2,
		"generation":3,
		"transport":{"tag":"gantry-shares","vmPath":"/run/mnt/gantry-shares"},
		"shares":[{"tag":"code","path":"/tmp/code","vmPath":"/run/mnt/gantry-shares/code","ctrPath":"/host/code","state":"active"}]
	}`
	if err := os.WriteFile(filepath.Join(sandboxDir(name), "shares.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	rows, live := loadDashboardMounts(name, RunConfig{Shares: []string{"code=/tmp/code@/workspace"}}, true)
	if !live || len(rows) != 1 || rows[0].Guest != "/workspace" || rows[0].State != "restart" {
		t.Fatalf("pending rows=%#v live=%v", rows, live)
	}
}

func TestDashboardMountsPreserveLiveErrorDuringDrift(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	name := "live"
	if err := os.MkdirAll(sandboxDir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := `{
		"version":2,
		"transport":{"tag":"gantry-shares","vmPath":"/run/mnt/gantry-shares"},
		"shares":[{"tag":"code","path":"/old","ctrPath":"/host/code","state":"error"}]
	}`
	if err := os.WriteFile(filepath.Join(sandboxDir(name), "shares.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	rows, live := loadDashboardMounts(name, RunConfig{Shares: []string{"code=/new"}}, true)
	if !live || len(rows) != 1 || rows[0].Host != "/new" || rows[0].State != "error" || rows[0].Error == "" {
		t.Fatalf("live error lost during merge: rows=%#v live=%v", rows, live)
	}
}

func TestDashboardPlansShareAndPortInputs(t *testing.T) {
	service := dashboardService{}
	share, err := service.PlanShare(dashboardapi.ShareRequest{
		Sandbox: "dev", Tag: "code", Path: "/tmp/code", Owner: "1000:1001",
		ReadOnly: true, Running: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if share.Spec != "code=/tmp/code,ro,uid=1000,gid=1001" || !share.Live || share.Mountpoint != "/host/code" {
		t.Fatalf("share plan = %#v", share)
	}
	if _, err := service.PlanShare(dashboardapi.ShareRequest{Tag: "code", Path: "/tmp", Owner: "agent"}); err == nil {
		t.Fatal("named share owner was accepted")
	}
	edge, err := service.PlanShare(dashboardapi.ShareRequest{
		Tag: "edge", Path: "/tmp/project,ro", Mountpoint: "/workspace/@cache,ro",
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := shares.ParseSpec(edge.Spec)
	if err != nil {
		t.Fatalf("parse planned edge share %q: %v", edge.Spec, err)
	}
	if parsed.Path != "/tmp/project,ro" || parsed.CtrPath != "/workspace/@cache,ro" || parsed.RO {
		t.Fatalf("planned edge share changed meaning: %#v", parsed)
	}

	port, err := service.PlanPort(dashboardapi.PortRequest{Bind: "0.0.0.0:8080", Guest: "80"})
	if err != nil || port != "0.0.0.0:8080:80" {
		t.Fatalf("port plan = %q, %v", port, err)
	}
	if _, err := service.PlanPort(dashboardapi.PortRequest{Guest: "[::]:80"}); err == nil {
		t.Fatal("guest field accepted a bind address")
	}
	if _, err := service.PlanPort(dashboardapi.PortRequest{Bind: "example.com:8080", Guest: "80"}); err == nil {
		t.Fatal("hostname bind was accepted")
	}
}

func TestDashboardTrafficRulesPersistForAllProtocols(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	name := "dev"
	if err := os.MkdirAll(sandboxDir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDashboardTestConfig(t, name, RunConfig{Net: true, MemMB: 512, VCPUs: 1})
	service := dashboardService{}
	if err := service.AddNetworkRule(dashboardapi.RuleRequest{
		Sandbox: name, Action: "deny", Target: "203.0.113.9", Proto: "any",
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.AddNetworkRule(dashboardapi.RuleRequest{
		Sandbox: name, Action: "allow", Target: "203.0.113.9", Proto: "icmp",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := readSandboxConfig(sandboxDir(name))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := netpol.Load(cfg.NetPol)
	if err != nil {
		t.Fatal(err)
	}
	summaries := policy.RuleSummaries()
	if len(policy.Rules) != 2 || summaries[1].Protocol != "icmp" || summaries[2].Protocol != "any" {
		t.Fatalf("persisted policy rules = %#v", summaries)
	}

	if err := service.RemoveTrafficRule(dashboardapi.Traffic{
		Sandbox: name, Address: "203.0.113.9", Protocol: "icmp",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err = readSandboxConfig(sandboxDir(name))
	if err != nil {
		t.Fatal(err)
	}
	policy, err = netpol.Load(cfg.NetPol)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Rules) != 1 || policy.RuleSummaries()[1].Protocol != "any" {
		t.Fatalf("traffic removal left rules = %#v", policy.RuleSummaries())
	}
}

func TestDashboardDomainRuleCanBeRemoved(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	name := "dev"
	if err := os.MkdirAll(sandboxDir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"default":"deny","allowDomains":["example.com","api.github.com"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeDashboardTestConfig(t, name, RunConfig{Net: true, MemMB: 512, VCPUs: 1, NetPol: policyPath})

	service := dashboardService{}
	if err := service.RemoveNetworkRule(dashboardapi.Rule{
		Sandbox: name, Target: "example.com", Source: "domain",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := readSandboxConfig(sandboxDir(name))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := netpol.Load(cfg.NetPol)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.AllowDomains) != 1 || policy.AllowDomains[0] != "api.github.com" {
		t.Fatalf("domains after dashboard removal = %v", policy.AllowDomains)
	}
	if err := service.RemoveNetworkRule(dashboardapi.Rule{Sandbox: name, Source: "default"}); err == nil {
		t.Fatal("default posture row removal succeeded")
	}
}

func TestDashboardShareRemovalForceClassification(t *testing.T) {
	if dashboardShareRemovalNeedsForce(dashboardapi.Mount{Tag: "code", Guest: "/host/code"}) {
		t.Fatal("default hub mount requires force")
	}
	if !dashboardShareRemovalNeedsForce(dashboardapi.Mount{Tag: "workspace", Guest: "/workspace"}) {
		t.Fatal("explicit container alias does not require force")
	}
}

func writeDashboardTestConfig(t *testing.T, name string, cfg RunConfig) {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandboxDir(name), "sandbox.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDashboardKernelChoicesMatchHostArchitecture(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GANTRY_ARTIFACTS", dir)
	arch := "arm64"
	if runtime.GOARCH == "amd64" {
		arch = "x86_64"
	}
	name := "gantry-kernel-" + arch
	if err := os.WriteFile(filepath.Join(dir, name), []byte("kernel"), 0o600); err != nil {
		t.Fatal(err)
	}
	choices := (dashboardService{}).KernelChoices()
	if len(choices) != 1 || filepath.Base(choices[0]) != name {
		t.Fatalf("kernel choices = %v", choices)
	}
}
