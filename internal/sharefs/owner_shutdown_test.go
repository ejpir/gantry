//go:build linux || darwin || windows

package sharefs

import (
	"sync/atomic"
	"testing"
	"time"

	sharelifecycle "github.com/ejpir/gantry/internal/sharefs/lifecycle"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestHubConcurrentCloseJoinsResourceRelease(t *testing.T) {
	assertConcurrentCloseJoins(t, true)
}

func TestServerConcurrentCloseJoinsResourceRelease(t *testing.T) {
	assertConcurrentCloseJoins(t, false)
}

func TestClosedOwnersRejectRequestsAndNewCapabilities(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	if err := hub.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := hub.Prepare("code", t.TempDir(), false); err == nil {
		t.Fatal("closed hub prepared a new root capability")
	}
	if _, err := hub.Remove("code", true); err == nil {
		t.Fatal("closed hub admitted namespace removal")
	}
	if _, status := hub.HandleRequest(nil, nil); status != fuse.EIO {
		t.Fatalf("closed hub request status = %v, want EIO", status)
	}

	server := &Server{}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, status := server.HandleRequest(nil, nil); status != fuse.EIO {
		t.Fatalf("closed server request status = %v, want EIO", status)
	}
}

func assertConcurrentCloseJoins(t *testing.T, hubOwner bool) {
	t.Helper()
	releaseEntered := make(chan struct{})
	releaseContinue := make(chan struct{})
	var releases atomic.Int32
	export := &Export{release: func() {
		releases.Add(1)
		close(releaseEntered)
		<-releaseContinue
	}}

	var closeOwner func() error
	var phase func() sharelifecycle.Phase
	if hubOwner {
		hub := &Hub{
			exports: map[string]*Export{"code": export},
			all:     map[*Export]struct{}{export: {}},
		}
		closeOwner = hub.Close
		phase = hub.lifecycle.Phase
	} else {
		server := &Server{export: export}
		closeOwner = server.Close
		phase = server.lifecycle.Phase
	}

	leaderDone := make(chan error, 1)
	go func() { leaderDone <- closeOwner() }()
	select {
	case <-releaseEntered:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not begin resource release")
	}
	if got := phase(); got != sharelifecycle.Stopping {
		t.Fatalf("phase during release = %d, want stopping", got)
	}
	followerDone := make(chan error, 1)
	go func() { followerDone <- closeOwner() }()
	select {
	case err := <-followerDone:
		t.Fatalf("duplicate Close returned before resource release: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseContinue)
	for name, done := range map[string]<-chan error{"leader": leaderDone, "follower": followerDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s Close: %v", name, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s Close did not join shutdown", name)
		}
	}
	if got := phase(); got != sharelifecycle.Closed {
		t.Fatalf("terminal phase = %d, want closed", got)
	}
	if got := releases.Load(); got != 1 {
		t.Fatalf("root releases = %d, want 1", got)
	}
}
