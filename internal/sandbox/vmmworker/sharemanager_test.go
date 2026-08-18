//go:build linux || darwin

package vmmworker

import (
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
)

// newTestShareManager builds a share manager over a temp sandbox directory so
// the worker can be handed a real hub.
func newTestShareManager(t *testing.T, specs ...string) (*control.ShareManager, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.RunConfig{Kernel: "/kernel", Rootfs: "/rootfs", Image: "/image", Shares: specs, MemMB: 512, VCPUs: 1, RW: true}
	if err := config.WriteSandboxConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadConfigStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	manager, warnings, err := control.NewShareManager(dir, store)
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
