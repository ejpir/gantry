//go:build linux || darwin || windows

package sharefs

import (
	"sync"
	"testing"
	"time"
)

const finishDrainTestTimeout = 5 * time.Second

func wrapExportReleaseForTest(t *testing.T, export *Export) <-chan struct{} {
	t.Helper()
	released := make(chan struct{})
	original := export.release
	var once sync.Once
	export.release = func() {
		once.Do(func() { close(released) })
		if original != nil {
			original()
		}
	}
	return released
}

func assertReleasePending(t *testing.T, released <-chan struct{}) {
	t.Helper()
	select {
	case <-released:
		t.Fatal("export resources released while a request was still active")
	case <-time.After(50 * time.Millisecond):
	}
}

func awaitRelease(t *testing.T, released <-chan struct{}) {
	t.Helper()
	select {
	case <-released:
	case <-time.After(finishDrainTestTimeout):
		t.Fatal("export resources were not released after requests drained")
	}
}

func TestHubExportFinishDrainsActiveRequest(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	prepared, _, err := hub.Prepare("code", t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	export, err := hub.Publish(prepared)
	if err != nil {
		prepared.Close()
		t.Fatal(err)
	}
	released := wrapExportReleaseForTest(t, export)
	export.advanceState(ExportDraining)

	finishReturned := make(chan struct{})
	allowUnlock := make(chan struct{})
	requestDone := make(chan struct{})
	go func() {
		hub.request.RLock()
		export.finish()
		close(finishReturned)
		<-allowUnlock
		hub.request.RUnlock()
		close(requestDone)
	}()
	select {
	case <-finishReturned:
	case <-time.After(finishDrainTestTimeout):
		t.Fatal("export finish deadlocked attempting to upgrade the request lock")
	}
	assertReleasePending(t, released)
	if state := export.State(); state != ExportRevoked {
		t.Fatalf("export state while release is queued = %s, want revoked", state)
	}
	close(allowUnlock)
	select {
	case <-requestDone:
	case <-time.After(finishDrainTestTimeout):
		t.Fatal("simulated request did not release its read lock")
	}
	awaitRelease(t, released)
	if state := export.State(); state != ExportGone {
		t.Fatalf("export state after release = %s, want gone", state)
	}
}

func TestServerExportFinishDrainsActiveRequest(t *testing.T) {
	server, err := NewServer("code", t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	released := wrapExportReleaseForTest(t, server.export)
	server.export.advanceState(ExportDraining)

	finishReturned := make(chan struct{})
	allowUnlock := make(chan struct{})
	requestDone := make(chan struct{})
	go func() {
		server.request.RLock()
		server.export.finish()
		close(finishReturned)
		<-allowUnlock
		server.request.RUnlock()
		close(requestDone)
	}()
	select {
	case <-finishReturned:
	case <-time.After(finishDrainTestTimeout):
		t.Fatal("export finish deadlocked attempting to upgrade the request lock")
	}
	assertReleasePending(t, released)
	if state := server.export.State(); state != ExportRevoked {
		t.Fatalf("export state while release is queued = %s, want revoked", state)
	}
	close(allowUnlock)
	select {
	case <-requestDone:
	case <-time.After(finishDrainTestTimeout):
		t.Fatal("simulated request did not release its read lock")
	}
	awaitRelease(t, released)
	if state := server.export.State(); state != ExportGone {
		t.Fatalf("export state after release = %s, want gone", state)
	}
}

func TestHubCloseCompletesQueuedExportFinish(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	prepared, _, err := hub.Prepare("code", t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	export, err := hub.Publish(prepared)
	if err != nil {
		prepared.Close()
		t.Fatal(err)
	}
	released := wrapExportReleaseForTest(t, export)
	export.advanceState(ExportDraining)

	hub.request.RLock()
	export.finish()
	assertReleasePending(t, released)
	closed := make(chan error, 1)
	go func() { closed <- hub.Close() }()
	select {
	case err := <-closed:
		hub.request.RUnlock()
		t.Fatalf("Hub.Close completed while a request was active: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	hub.request.RUnlock()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(finishDrainTestTimeout):
		t.Fatal("Hub.Close did not complete after the active request drained")
	}
	select {
	case <-released:
	default:
		t.Fatal("Hub.Close returned before a queued export release completed")
	}
	if state := export.State(); state != ExportGone {
		t.Fatalf("export state after Hub.Close = %s, want gone", state)
	}
}

func TestServerCloseCompletesQueuedExportFinish(t *testing.T) {
	server, err := NewServer("code", t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	released := wrapExportReleaseForTest(t, server.export)
	server.export.advanceState(ExportDraining)

	server.request.RLock()
	server.export.finish()
	assertReleasePending(t, released)
	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	select {
	case err := <-closed:
		server.request.RUnlock()
		t.Fatalf("Server.Close completed while a request was active: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	server.request.RUnlock()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(finishDrainTestTimeout):
		t.Fatal("Server.Close did not complete after the active request drained")
	}
	select {
	case <-released:
	default:
		t.Fatal("Server.Close returned before a queued export release completed")
	}
	if state := server.export.State(); state != ExportGone {
		t.Fatalf("export state after Server.Close = %s, want gone", state)
	}
}

func TestHubPublishWaitsForActiveRequest(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	prepared, _, err := hub.Prepare("code", t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(prepared.Close)

	hub.request.RLock()
	published := make(chan error, 1)
	go func() {
		_, err := hub.Publish(prepared)
		published <- err
	}()
	select {
	case err := <-published:
		hub.request.RUnlock()
		t.Fatalf("publish completed while a request was active: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	hub.request.RUnlock()

	select {
	case err := <-published:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(finishDrainTestTimeout):
		t.Fatal("publish did not complete after active request drained")
	}
}
