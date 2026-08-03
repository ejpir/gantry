package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gantry/internal/vnet"
)

func newTestPortManager(t *testing.T) (*PortManager, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := RunConfig{Ports: []string{"127.0.0.1:18080:80"}}
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	stack, err := vnet.Start([6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stack.Close)
	return NewPortManager(dir, cfg, stack), dir
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
	entry, err := m.Publish("19090:9090", true)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if entry.Mapping.HostPort != 19090 || entry.Mapping.GuestPort != 9090 || entry.State != "bound" {
		t.Fatalf("publish entry: %+v", entry)
	}

	entries, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, e := range entries {
		states[e.Mapping.Short()] = e.State
	}
	if states["19090→9090"] != "bound" || states["18080→80"] != "saved" {
		t.Fatalf("list: %+v", states)
	}

	// Persistence: the new mapping joined the saved set.
	saved := readSavedPorts(t, dir)
	if len(saved) != 2 || saved[1] != "127.0.0.1:19090:9090" {
		t.Fatalf("saved ports: %v", saved)
	}

	// Duplicate publish is refused.
	if _, err := m.Publish("19090:9090", true); err == nil {
		t.Fatal("duplicate publish succeeded")
	}

	// Unpublish by any spec form identifying the same host listener.
	if _, err := m.Unpublish("19090:9090", true); err != nil {
		t.Fatalf("unpublish: %v", err)
	}
	entries, _ = m.List()
	for _, e := range entries {
		if e.Mapping.HostPort == 19090 {
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
	if _, err := m.Publish("19091:9091", false); err != nil {
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
