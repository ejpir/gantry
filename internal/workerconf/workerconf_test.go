package workerconf

import (
	"encoding/json"
	"os"
	"testing"
)

func TestReportFailed(t *testing.T) {
	rep := Report{Results: []PropertyResult{
		{Property: PropFSRead, State: StateEnforced},
		{Property: PropNetDial, State: StateUnenforced},
		{Property: PropExec, State: StateIndeterminate},
	}}
	failed := rep.Failed(PropFSRead, PropNetDial, PropExec)
	if len(failed) != 2 || failed[0] != PropNetDial || failed[1] != PropExec {
		t.Fatalf("Failed: %v", failed)
	}
	if got := rep.Property("nope").State; got != StateUnavailable {
		t.Fatalf("unknown property: %q", got)
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	rep := Report{
		Platform: "linux", Mode: "auto", Applied: true,
		Notes:   []string{"mount tier: private tmpfs root"},
		Results: []PropertyResult{{Property: PropFSRead, State: StateEnforced, Detail: "open: EPERM"}},
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Applied || back.Property(PropFSRead).State != StateEnforced || back.Notes[0] == "" {
		t.Fatalf("round-trip: %+v", back)
	}
}

func TestDisabledReport(t *testing.T) {
	rep := DisabledReport("darwin", "off")
	if len(rep.Failed(PropFSRead, PropNetDial, PropExec, PropFSWrite, PropProcEnum)) != 5 {
		t.Fatalf("disabled report must fail every required property: %+v", rep)
	}
}

// TestVerifyUnconfined: probes on an ordinary process must read
// "unenforced" (or at worst indeterminate), never "enforced" — a
// confined-looking result here would mean the probes lie, which would
// make required-mode boots refuse everything.
func TestVerifyUnconfined(t *testing.T) {
	rep := &Report{Platform: "test"}
	Verify(DefaultSpec(2, ""), rep)
	for _, p := range rep.Results {
		if p.State == StateEnforced {
			t.Errorf("%s claims enforced on an unconfined process (detail: %s)", p.Property, p.Detail)
		}
	}
	if got := rep.Property(PropFSRead).State; got != StateUnenforced {
		t.Errorf("fs-read unconfined: %q, want unenforced", got)
	}
	if got := rep.Property(PropExec).State; got != StateUnenforced {
		t.Errorf("exec unconfined: %q, want unenforced", got)
	}
	// Loopback port 1 refuses on any ordinary host.
	if got := rep.Property(PropNetDial).State; got != StateUnenforced {
		t.Errorf("net-dial unconfined: %q, want unenforced", got)
	}
}

func TestDefaultSpec(t *testing.T) {
	s := DefaultSpec(8, "/x")
	if !s.NoNetwork || !s.NoExec || !s.NoNewPaths || !s.NoProcX || s.KeepFDs != 8 || s.ConfRoot != "/x" {
		t.Fatalf("DefaultSpec: %+v", s)
	}
	if os.Getenv("WORKERCONF_HELPER") == "1" {
		t.Fatal("helper leaked into the test body")
	}
}
