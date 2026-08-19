package sandbox

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestOAuthReplayOutcomeTrustsCompletedSessionOverExpiredFlag covers the
// AfterFunc race: timer.Stop cannot retract a callback that already stored
// expired=true, but the kill it triggered forces Session's Wait to fail —
// so a nil session error means the replay really did complete.
func TestOAuthReplayOutcomeTrustsCompletedSessionOverExpiredFlag(t *testing.T) {
	stdout, status, err := oauthReplayOutcome([]byte("HTTP/1.0 200 OK"), 0, nil, false, true, 15*time.Second)
	if err != nil {
		t.Fatalf("completed replay reported as failed: %v", err)
	}
	if status != 0 || string(stdout) != "HTTP/1.0 200 OK" {
		t.Fatalf("stdout/status = %q/%d", stdout, status)
	}
}

func TestOAuthReplayOutcome(t *testing.T) {
	waitErr := errors.New("task Wait: killed")
	for _, tc := range []struct {
		name     string
		err      error
		overflow bool
		expired  bool
		want     string
		wantWrap bool
	}{
		{"timeout keeps the kill cause", waitErr, false, true, "callback replay exceeded", true},
		{"overflow keeps the session error", waitErr, true, false, "exceeds", true},
		{"overflow beats the expired flag", nil, true, true, "exceeds", false},
		{"ordinary session failure passes through", waitErr, false, false, "task Wait", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := oauthReplayOutcome(nil, 0, tc.err, tc.overflow, tc.expired, 15*time.Second)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
			if tc.wantWrap && !errors.Is(err, waitErr) {
				t.Fatalf("err = %v, want it to wrap the session error", err)
			}
		})
	}
}
