//go:build linux || darwin || windows

package sharefs

import (
	"testing"
	"time"
)

func TestShareHubSwapDrainsInflightRequests(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	publishHubShare(t, hub, "code", t.TempDir(), false)
	prepared, _, err := hub.Prepare("code", t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}

	// Model a request which has entered HandleRequest but has not completed.
	hub.request.RLock()
	done := make(chan error, 1)
	go func() {
		_, _, swapErr := hub.Swap(prepared)
		done <- swapErr
	}()
	select {
	case err := <-done:
		hub.request.RUnlock()
		t.Fatalf("Swap completed before the in-flight request drained: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	hub.request.RUnlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
