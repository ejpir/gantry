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
