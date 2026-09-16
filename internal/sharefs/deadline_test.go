//go:build linux || darwin || windows

package sharefs

import (
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestHubPolicyDeadlineBlocksExistingRequestPath(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	hub.SetDeadline(time.Now().Add(-time.Second))
	// Reject before parsing/dispatch, so no existing inode or handle can make
	// an expired request reach the backing filesystem.
	if n, status := hub.HandleRequest(nil, nil); n != 0 || status != fuse.EACCES {
		t.Fatalf("expired request=(%d,%v)", n, status)
	}
}

func TestHubLivePolicyBarrierAndPerExportAccess(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	export := publishHubShare(t, hub, "code", t.TempDir(), false)
	if !export.usable() {
		t.Fatal("new export is not usable")
	}
	hub.SetPolicyBlocked(true)
	if n, status := hub.HandleRequest(nil, nil); n != 0 || status != fuse.EACCES {
		t.Fatalf("policy barrier request=(%d,%v)", n, status)
	}
	hub.SetPolicyAccess(time.Now().Add(time.Hour), map[string]bool{"code": true})
	hub.SetPolicyBlocked(false)
	if export.usable() || !export.PolicyDenied() {
		t.Fatal("policy-denied export remained usable")
	}
	hub.SetPolicyAccess(time.Time{}, nil)
	if !export.usable() || export.PolicyDenied() {
		t.Fatal("later policy generation did not restore export")
	}
}
