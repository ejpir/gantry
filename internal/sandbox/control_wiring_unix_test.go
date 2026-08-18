//go:build linux || darwin

package sandbox

// Broker wiring for the share manager. Live shares need a mounted hub, which
// only the Unix share filesystem provides, so this half of the broker's
// control-plane dispatch is tested apart from control_wiring_test.go.

import (
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
)

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

// newTestShareManager builds a share manager over a temp sandbox directory.
// The facade's tests use it to wire a broker or a VMM worker to a real hub.
func newTestShareManager(t *testing.T, specs ...string) (*control.ShareManager, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.RunConfig{Kernel: "/kernel", Rootfs: "/rootfs", Image: "/image", Shares: specs, MemMB: 512, RW: true}
	manager, warnings, err := control.NewShareManager(dir, newTestConfigStore(t, dir, cfg))
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
