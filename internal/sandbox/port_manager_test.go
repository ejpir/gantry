package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/vnet"
)

type portBackendStub struct {
	forwards     []vnet.Forward
	publishErr   error
	unpublishErr error
	publishes    int
	unpublishes  int
}

func (b *portBackendStub) Publish(proto, local, remote string) error {
	b.publishes++
	return b.publishErr
}

func (b *portBackendStub) Unpublish(proto, local string) error {
	b.unpublishes++
	return b.unpublishErr
}

func (b *portBackendStub) Forwards() ([]vnet.Forward, error) {
	return append([]vnet.Forward(nil), b.forwards...), nil
}

func (b *portBackendStub) SetPolicy(*netpol.Policy) error { return nil }

func newTestPortManager(t *testing.T) (*PortManager, string) {
	t.Helper()
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, RunConfig{Ports: []string{"127.0.0.1:18080:80"}})
	stack, err := vnet.Start([6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stack.Close)
	return NewPortManager(store, newLocalBackend(stack, nil)), dir
}

func readSavedPorts(t *testing.T, dir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg RunConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.Ports
}

func TestPortManagerPublishListUnpublish(t *testing.T) {
	m, dir := newTestPortManager(t)

	// The saved boot mapping lists as "saved" (the test stack was started
	// without static forwards), a live publish joins it as "bound".
	entry, err := m.Publish("9090", true)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if entry.Mapping.HostPort == 0 || entry.Mapping.GuestPort != 9090 || entry.State != "bound" {
		t.Fatalf("publish entry: %+v", entry)
	}
	hostPort := entry.Mapping.HostPort

	entries, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, e := range entries {
		states[e.Mapping.Short()] = e.State
	}
	if states[fmt.Sprintf("%d→9090", hostPort)] != "bound" || states["18080→80"] != "saved" {
		t.Fatalf("list: %+v", states)
	}

	// Persistence: the new mapping joined the saved set.
	saved := readSavedPorts(t, dir)
	if len(saved) != 2 {
		t.Fatalf("saved ports: %v", saved)
	}
	stored, parseErr := ParsePortSpec(saved[1])
	if parseErr != nil || stored.HostPort != hostPort || stored.GuestPort != 9090 {
		t.Fatalf("saved ports: %v", saved)
	}

	// Duplicate publish is refused.
	if _, err := m.Publish(fmt.Sprintf("%d:9090", hostPort), true); err == nil {
		t.Fatal("duplicate publish succeeded")
	}

	// Unpublish by any spec form identifying the same host listener.
	if _, err := m.Unpublish(fmt.Sprintf("%d:9090", hostPort), true); err != nil {
		t.Fatalf("unpublish: %v", err)
	}
	entries, _ = m.List()
	for _, e := range entries {
		if e.Mapping.HostPort == hostPort {
			t.Fatalf("mapping survived unpublish: %+v", e)
		}
	}
	if saved := readSavedPorts(t, dir); len(saved) != 1 {
		t.Fatalf("saved ports after unpublish: %v", saved)
	}
}

// Ephemeral publishes never touch sandbox.json; unpublish of a mapping that
// was never published is an error, not a silent success.
func TestPortManagerEphemeralAndMissing(t *testing.T) {
	m, dir := newTestPortManager(t)
	if _, err := m.Publish("9091", false); err != nil {
		t.Fatal(err)
	}
	if saved := readSavedPorts(t, dir); len(saved) != 1 {
		t.Fatalf("ephemeral publish persisted: %v", saved)
	}
	if _, err := m.Unpublish("19999:9999", false); err == nil {
		t.Fatal("unpublish of a missing mapping succeeded")
	}
}

// Auto-assign resolves a concrete free host port before anything is
// persisted or bound, so the saved spec is always concrete.
func TestPortManagerAutoAssign(t *testing.T) {
	m, dir := newTestPortManager(t)
	entry, err := m.Publish("9092", true)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Mapping.HostPort == 0 {
		t.Fatal("auto-assign left host port at 0")
	}
	saved := readSavedPorts(t, dir)
	m2, err := ParsePortSpec(saved[1])
	if err != nil || m2.HostPort != entry.Mapping.HostPort {
		t.Fatalf("saved spec %q does not carry the assigned port %+v", saved[1], m2)
	}
}

// Regression: share and port managers used to keep private RunConfig copies
// and rewrite sandbox.json wholesale, so a port publish after a persistent
// share add dropped the share from disk (and vice versa). Both must mutate
// through the shared ConfigStore.
func TestConfigStoreShareAndPortMutationsCoexist(t *testing.T) {
	dir := t.TempDir()
	shareDir := t.TempDir()
	// One store shared by both managers — the daemon's construction. Two
	// stores over one file would reintroduce the clobbering one level up.
	store := newTestConfigStore(t, dir, RunConfig{RW: true})
	stack, err := vnet.Start([6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stack.Close)
	m := NewPortManager(store, newLocalBackend(stack, nil))
	shareManager, _, err := NewShareManager(dir, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shareManager.Close() })

	if _, err := shareManager.Add("data="+shareDir, true, false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Publish("9093", true); err != nil {
		t.Fatal(err)
	}
	if _, err := shareManager.Add("more="+t.TempDir(), true, false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Publish("9094", true); err != nil {
		t.Fatal(err)
	}

	cfg, err := readSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 2 {
		t.Fatalf("shares clobbered: %v", cfg.Shares)
	}
	if len(cfg.Ports) != 2 {
		t.Fatalf("ports clobbered: %v", cfg.Ports)
	}
}

// Auto-assign probes the requested bind address: a wildcard publish must not
// hand out a port that is only free on loopback.
func TestNormalizePortSpecProbesRequestedBind(t *testing.T) {
	spec, err := NormalizePortSpec("0.0.0.0:0:8080")
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParsePortSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if m.HostIP != "0.0.0.0" || m.HostPort == 0 {
		t.Fatalf("wildcard auto-assign: %+v", m)
	}
	ln, err := net.Listen("tcp", m.Local())
	if err != nil {
		t.Fatalf("assigned port not bindable on the wildcard address: %v", err)
	}
	_ = ln.Close()
}

func TestPortManagerReportsPublishRollbackFailure(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "sandbox")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store := newTestConfigStore(t, dir, RunConfig{})
	if err := os.Rename(dir, filepath.Join(parent, "moved")); err != nil {
		t.Fatal(err)
	}

	rollbackErr := errors.New("injected unpublish failure")
	backend := &portBackendStub{unpublishErr: rollbackErr}
	manager := NewPortManager(store, backend)
	if _, err := manager.Publish("127.0.0.1:18123:80", true); !errors.Is(err, rollbackErr) {
		t.Fatalf("Publish error = %v, want rollback failure", err)
	}
	if backend.publishes != 1 || backend.unpublishes != 1 {
		t.Fatalf("backend calls = publish %d, unpublish %d", backend.publishes, backend.unpublishes)
	}
}

func TestPortManagerReportsUnpublishRestoreFailure(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "sandbox")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	const spec = "127.0.0.1:18124:80"
	store := newTestConfigStore(t, dir, RunConfig{Ports: []string{spec}})
	if err := os.Rename(dir, filepath.Join(parent, "moved")); err != nil {
		t.Fatal(err)
	}

	rollbackErr := errors.New("injected publish failure")
	backend := &portBackendStub{
		forwards:   []vnet.Forward{{Protocol: "tcp", Local: "127.0.0.1:18124", Remote: "192.168.127.2:80"}},
		publishErr: rollbackErr,
	}
	manager := NewPortManager(store, backend)
	if _, err := manager.Unpublish(spec, true); !errors.Is(err, rollbackErr) {
		t.Fatalf("Unpublish error = %v, want restore failure", err)
	}
	if backend.unpublishes != 1 || backend.publishes != 1 {
		t.Fatalf("backend calls = unpublish %d, publish %d", backend.unpublishes, backend.publishes)
	}
}

func TestPortManagerDoesNotRollbackCommittedDurabilityErrors(t *testing.T) {
	wantErr := errors.New("injected directory sync failure")

	t.Run("publish", func(t *testing.T) {
		store := newTestConfigStore(t, t.TempDir(), RunConfig{})
		store.write = func(string, []byte, os.FileMode) error {
			return &atomicfile.CommitError{Err: wantErr}
		}
		backend := &portBackendStub{}
		manager := NewPortManager(store, backend)
		entry, err := manager.Publish("127.0.0.1:18125:80", true)
		if !atomicfile.Committed(err) || !errors.Is(err, wantErr) {
			t.Fatalf("Publish error = %v, want committed %v", err, wantErr)
		}
		if entry.State != "bound" || backend.publishes != 1 || backend.unpublishes != 0 {
			t.Fatalf("Publish result = %+v, backend calls publish=%d unpublish=%d",
				entry, backend.publishes, backend.unpublishes)
		}
		if got := store.Snapshot().Ports; len(got) != 1 || got[0] != "127.0.0.1:18125:80" {
			t.Fatalf("committed published ports = %v", got)
		}
	})

	t.Run("unpublish", func(t *testing.T) {
		const spec = "127.0.0.1:18126:80"
		store := newTestConfigStore(t, t.TempDir(), RunConfig{Ports: []string{spec}})
		store.write = func(string, []byte, os.FileMode) error {
			return &atomicfile.CommitError{Err: wantErr}
		}
		backend := &portBackendStub{forwards: []vnet.Forward{{
			Protocol: "tcp",
			Local:    "127.0.0.1:18126",
			Remote:   "192.168.127.2:80",
		}}}
		manager := NewPortManager(store, backend)
		entry, err := manager.Unpublish(spec, true)
		if !atomicfile.Committed(err) || !errors.Is(err, wantErr) {
			t.Fatalf("Unpublish error = %v, want committed %v", err, wantErr)
		}
		if entry.State != "unpublished" || backend.unpublishes != 1 || backend.publishes != 0 {
			t.Fatalf("Unpublish result = %+v, backend calls unpublish=%d publish=%d",
				entry, backend.unpublishes, backend.publishes)
		}
		if got := store.Snapshot().Ports; len(got) != 0 {
			t.Fatalf("committed published ports = %v", got)
		}
	})
}
