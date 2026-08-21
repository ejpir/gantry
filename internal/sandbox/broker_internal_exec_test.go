package sandbox

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestInternalExecOutcomeTrustsCompletedSessionOverExpiredFlag covers the
// AfterFunc race: timer.Stop cannot retract a callback that already stored
// expired=true, but the kill it triggered forces Session's Wait to fail —
// so a nil session error means the exec really did complete.
func TestInternalExecOutcomeTrustsCompletedSessionOverExpiredFlag(t *testing.T) {
	stdout, status, err := internalExecOutcome([]byte("HTTP/1.0 200 OK"), 0, nil, false, true, 15*time.Second,
		256<<10, "oauth callback replay")
	if err != nil {
		t.Fatalf("completed exec reported as failed: %v", err)
	}
	if status != 0 || string(stdout) != "HTTP/1.0 200 OK" {
		t.Fatalf("stdout/status = %q/%d", stdout, status)
	}
}

func TestInternalExecOutcome(t *testing.T) {
	waitErr := errors.New("task Wait: killed")
	for _, tc := range []struct {
		name     string
		err      error
		overflow bool
		expired  bool
		want     string
		wantWrap bool
	}{
		{"timeout keeps the kill cause", waitErr, false, true, "oauth callback replay exceeded", true},
		{"overflow keeps the session error", waitErr, true, false, "exceeds", true},
		{"overflow beats the expired flag", nil, true, true, "exceeds", false},
		{"ordinary session failure passes through", waitErr, false, false, "task Wait", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := internalExecOutcome(nil, 0, tc.err, tc.overflow, tc.expired, 15*time.Second,
				256<<10, "oauth callback replay")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
			if tc.wantWrap && !errors.Is(err, waitErr) {
				t.Fatalf("err = %v, want it to wrap the session error", err)
			}
		})
	}
}

// TestInternalExecOutcomeAttributesOp verifies the caller's op name lands in
// the error so a timeout during guest tool delivery is not reported as an
// OAuth replay failure.
func TestInternalExecOutcomeAttributesOp(t *testing.T) {
	_, _, err := internalExecOutcome(nil, 0, errors.New("killed"), false, true, 5*time.Second,
		1<<20, "guest tool delivery")
	if err == nil || !strings.Contains(err.Error(), "guest tool delivery exceeded 5s") {
		t.Fatalf("err = %v, want op attribution", err)
	}
}
