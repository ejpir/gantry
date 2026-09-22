package manager

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestLifecycleAdmissionCloseReleasesOwnedLocksOnce(t *testing.T) {
	service := newManagerService(stubLifecycle{})
	defer service.cancel()
	admission, status, err := service.acquireLifecycleAdmission(context.Background(), "start", "dev")
	if err != nil {
		t.Fatalf("acquire status %d: %v", status, err)
	}
	if got := len(service.lifecycleSlots); got != 1 {
		t.Fatalf("occupied lifecycle slots = %d, want 1", got)
	}
	admission.Close()
	admission.Close()
	if got := len(service.lifecycleSlots); got != 0 {
		t.Fatalf("occupied lifecycle slots after Close = %d, want 0", got)
	}
	if !service.organizationPolicyMu.TryLock() {
		t.Fatal("organization policy read lock was not released")
	}
	service.organizationPolicyMu.Unlock()
	lock := service.sandboxLock("dev")
	if !lock.TryLock() {
		t.Fatal("sandbox execution lock was not released")
	}
	lock.Unlock()
}

func TestLifecycleAdmissionCancellationReleasesPartialOwnership(t *testing.T) {
	service := newManagerService(stubLifecycle{})
	defer service.cancel()
	lock := service.sandboxLock("dev")
	lock.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	admission, status, err := service.acquireLifecycleAdmission(ctx, "start", "dev")
	lock.Unlock()
	if admission != nil || !errors.Is(err, context.Canceled) || status != http.StatusRequestTimeout {
		t.Fatalf("canceled admission = (%v, %d, %v)", admission, status, err)
	}
	if got := len(service.lifecycleSlots); got != 0 {
		t.Fatalf("occupied lifecycle slots after cancellation = %d, want 0", got)
	}
	if !service.organizationPolicyMu.TryLock() {
		t.Fatal("organization policy lock leaked after cancellation")
	}
	service.organizationPolicyMu.Unlock()
}
