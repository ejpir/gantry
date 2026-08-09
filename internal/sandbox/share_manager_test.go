//go:build linux || darwin

package sandbox

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/shares"
	"github.com/ejpir/gantry/internal/virtio"
)

func newTestShareManager(t *testing.T, specs ...string) (*ShareManager, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := RunConfig{Kernel: "/kernel", Rootfs: "/rootfs", Image: "/image", Shares: specs, MemMB: 512, RW: true}
	manager, warnings, err := NewShareManager(dir, newTestConfigStore(t, dir, cfg))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if manager.Hub() == nil {
		t.Fatal("share hub unavailable")
	}
	t.Cleanup(func() { _ = manager.Close() })
	return manager, dir
}

func TestShareManagerLiveAddPersistsAndPublishes(t *testing.T) {
	manager, dir := newTestShareManager(t)
	if err := manager.Publish(); err != nil {
		t.Fatal(err)
	}
	shareDir := t.TempDir()
	entry, err := manager.Add("code="+shareDir+",ro", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Tag != "code" || !entry.RO || entry.CtrPath != "/host/code" || entry.State != "active" {
		t.Fatalf("entry: %+v", entry)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg RunConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(shareDir)
	if err != nil {
		t.Fatal(err)
	}
	wantSpec := "code=" + canonical + ",ro"
	if len(cfg.Shares) != 1 || cfg.Shares[0] != wantSpec {
		t.Fatalf("persisted shares = %v, want [%s]", cfg.Shares, wantSpec)
	}

	raw, err = os.ReadFile(filepath.Join(dir, "shares.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest shares.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Version != shares.ManifestVersion || manifest.Generation != 1 || manifest.Transport == nil {
		t.Fatalf("manifest: %+v", manifest)
	}
	if manifest.Transport.Tag != shares.HubTag || manifest.Transport.VMPath != shares.HubVMPath {
		t.Fatalf("transport: %+v", manifest.Transport)
	}
	if len(manifest.Shares) != 1 || manifest.Shares[0].CtrPath != "/host/code" {
		t.Fatalf("manifest shares: %+v", manifest.Shares)
	}
}

func TestShareManagerPersistsGuestOwnership(t *testing.T) {
	manager, dir := newTestShareManager(t)
	shareDir := t.TempDir()
	entry, err := manager.Add("code="+shareDir+",uid=1000,gid=1000", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if entry.UID == nil || entry.GID == nil || *entry.UID != 1000 || *entry.GID != 1000 {
		t.Fatalf("entry ownership = uid=%v gid=%v", entry.UID, entry.GID)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg RunConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 1 || !strings.HasSuffix(cfg.Shares[0], ",uid=1000,gid=1000") {
		t.Fatalf("persisted shares = %v", cfg.Shares)
	}
}

func TestShareManagerRejectsOverlapAndDuplicateContainerTarget(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	manager, _ := newTestShareManager(t)
	if _, err := manager.Add("root="+root, true, false); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Add("child="+child, true, false); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("overlapping share error = %v", err)
	}
	if _, err := manager.Add("root=/tmp", true, false); err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("conflicting duplicate error = %v", err)
	}
	if entry, err := manager.Add("root="+root, true, false); err != nil || entry.Tag != "root" {
		t.Fatalf("idempotent duplicate: entry=%+v err=%v", entry, err)
	}
}

func TestShareManagerRemoveUpdatesConfig(t *testing.T) {
	dir := t.TempDir()
	spec := "code=" + dir + ",ro"
	manager, sandboxDir := newTestShareManager(t, spec)
	if err := manager.Publish(); err != nil {
		t.Fatal(err)
	}
	entry, err := manager.Remove("code", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Tag != "code" {
		t.Fatalf("removed entry: %+v", entry)
	}
	raw, err := os.ReadFile(filepath.Join(sandboxDir, "sandbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg RunConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 0 {
		t.Fatalf("removed share still persisted: %v", cfg.Shares)
	}
	if manager.Hub().Export("code") != nil {
		t.Fatal("removed share still visible in hub")
	}
}

func TestShareManagerForceRemovesExplicitContainerAlias(t *testing.T) {
	dir := t.TempDir()
	manager, sandboxDir := newTestShareManager(t, "workspace="+dir+"@/workspace")
	if err := manager.Publish(); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Remove("workspace", true, false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("non-force alias removal error = %v", err)
	}
	if _, err := manager.Remove("workspace", true, true); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(sandboxDir, "sandbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg RunConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 0 {
		t.Fatalf("removed aliased share still persisted: %v", cfg.Shares)
	}
}

func TestShareManagerHostshareNormalizesToHubChild(t *testing.T) {
	dir := t.TempDir()
	sandboxDir := t.TempDir()
	store := newTestConfigStore(t, sandboxDir, RunConfig{Shares: []string{"hostshare=" + dir}, RW: true})
	manager, warnings, err := NewShareManager(sandboxDir, store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "/host/hostshare") {
		t.Fatalf("warnings: %v", warnings)
	}
	entries := manager.Entries()
	if len(entries) != 1 || entries[0].CtrPath != "/host/hostshare" {
		t.Fatalf("entries: %+v", entries)
	}
}

func TestBrokerShareControl(t *testing.T) {
	manager, _ := newTestShareManager(t)
	br := &broker{sessions: map[string]chan struct{}{}, shares: manager}
	dir := t.TempDir()
	resp := brokerPipe(t, br, `{"op":"share.add","id":"s1","share":{"spec":"code=`+dir+`,ro","persistent":false}}`+"\n")
	if !strings.Contains(resp, `"ok":true`) || !strings.Contains(resp, `"tag":"code"`) {
		t.Fatalf("add resp = %s", resp)
	}
	resp = brokerPipe(t, br, `{"op":"share.list","id":"s2","share":{"persistent":true}}`+"\n")
	if !strings.Contains(resp, `"ctrPath":"/host/code"`) {
		t.Fatalf("list resp = %s", resp)
	}
	resp = brokerPipe(t, br, `{"op":"share.remove","id":"s3","share":{"tag":"code","persistent":false,"force":true}}`+"\n")
	if !strings.Contains(resp, `"ok":true`) {
		t.Fatalf("remove resp = %s", resp)
	}
}

// TestShareManagerReplaceIsTransactional: the candidate is prepared and
// persisted before the live export is swapped atomically; the old share
// stays in the retired (revoked, draining) set instead of vanishing first.
func TestShareManagerReplaceIsTransactional(t *testing.T) {
	manager, dir := newTestShareManager(t)
	if err := manager.Publish(); err != nil {
		t.Fatal(err)
	}
	oldDir := t.TempDir()
	newDir := t.TempDir()
	if _, err := manager.Add("code="+oldDir, true, false); err != nil {
		t.Fatal(err)
	}
	entry, err := manager.Add("code="+newDir+",ro", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if !entry.RO {
		t.Errorf("replaced entry RO = false, want true: %+v", entry)
	}
	canonicalNew, _ := filepath.EvalSymlinks(newDir)
	if got := manager.Hub().Export("code").Path; got != canonicalNew {
		t.Errorf("live export path = %q, want %q", got, canonicalNew)
	}
	// persisted config carries exactly the replacement spec
	raw, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg RunConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 1 || cfg.Shares[0] != "code="+canonicalNew+",ro" {
		t.Errorf("persisted shares = %v, want exactly [code=%s,ro]", cfg.Shares, canonicalNew)
	}
	// Revoke of the swapped-out export is asserted wire-level in
	// TestShareHubSwapRevokesReplacedExport; without a FUSE session the
	// old export drains instantly and leaves no retired entry here.
}

// TestShareManagerBrokeredReplaceKeepsOneActiveExport pins the split-VMM
// ownership model: starting the request relay must not detach the manager's
// hub or replace its local serving backend. A later replacement therefore
// updates the one supervisor-owned namespace and cannot leave a second
// bookkeeping-only export claiming to be active.
func TestShareManagerBrokeredReplaceKeepsOneActiveExport(t *testing.T) {
	oldDir := t.TempDir()
	manager, _ := newTestShareManager(t, "code="+oldDir)
	hub := manager.Hub()
	oldExport := hub.Export("code")
	if oldExport == nil {
		t.Fatal("boot export missing")
	}

	server, client := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- hub.ServeBroker(server) }()
	proxy, err := virtio.NewShareHubProxy(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()

	// This is the invariant the removed workerShareServing path violated:
	// split mode serves the same hub; it does not exchange the manager's
	// backend for a remote mirror.
	local, ok := manager.serving.(localShareServing)
	if !ok || local.hub != hub || manager.Hub() != hub {
		t.Fatalf("broker detached supervisor hub: serving=%T hub=%p want=%p", manager.serving, manager.Hub(), hub)
	}

	newDir := t.TempDir()
	entry, err := manager.Add("code="+newDir+",ro", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if entry.State != "active" || !entry.RO {
		t.Fatalf("replacement entry: %+v", entry)
	}
	if oldExport.State() == virtio.ShareExportActive {
		t.Fatalf("replaced export remained active: %+v", oldExport)
	}
	exports := hub.Exports()
	if len(exports) != 1 || exports[0].Tag != "code" || exports[0] == oldExport || exports[0].State() != virtio.ShareExportActive {
		t.Fatalf("live hub exports after replacement: %+v", exports)
	}
	active := 0
	for _, got := range manager.Entries() {
		if got.Tag == "code" && got.State == "active" {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("active code entries after brokered replacement = %d, want 1: %+v", active, manager.Entries())
	}

	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("ServeBroker after peer close: %v", err)
	}
}

// TestShareManagerPromoteEphemeralToPersistent: re-adding an identical
// share with --persist must persist it instead of hitting the no-op fast
// path.
func TestShareManagerPromoteEphemeralToPersistent(t *testing.T) {
	manager, dir := newTestShareManager(t)
	if err := manager.Publish(); err != nil {
		t.Fatal(err)
	}
	shareDir := t.TempDir()
	spec := "code=" + shareDir
	if _, err := manager.Add(spec, false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Add(spec, true, false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg RunConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	canonical, _ := filepath.EvalSymlinks(shareDir)
	if len(cfg.Shares) != 1 || cfg.Shares[0] != "code="+canonical {
		t.Errorf("persisted shares = %v, want exactly [code=%s]", cfg.Shares, canonical)
	}
}
