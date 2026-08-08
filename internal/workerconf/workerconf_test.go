package workerconf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestBuildSeatbeltProfile(t *testing.T) {
	spec := DefaultSpec(12, "")
	spec.StateDir = "/Users/test/.gantry/sandboxes/dev"
	spec.FileAllow = []FileAllowance{
		{Path: "/Users/test/project", Write: true},
		{Path: "/Users/test/shared refs", Write: false},
		{Path: `/Users/test/we"ird\path`, Write: false},
	}
	p := buildSeatbeltProfile(spec)
	for _, want := range []string{
		"(version 1)",
		"(deny default)",
		"(allow signal (target self))",
		"(allow mach-lookup)",
		"(allow sysctl-read)",
		`(literal "/dev/null")`,
		`(allow file-write* (subpath "/Users/test/.gantry/sandboxes/dev"))`,
		`(subpath "/Users/test/project")`,
		`(subpath "/Users/test/shared refs")`,
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("profile missing %q:\n%s", want, p)
		}
	}
	// Escaping: quotes and backslashes must not break the SBPL literal.
	if !strings.Contains(p, `/Users/test/we\"ird\\path`) {
		t.Fatalf("profile escaping wrong:\n%s", p)
	}
	// RO root must never appear under a write rule: the only
	// file-write* rules are the /dev literals, the state dir, and the
	// RW export block.
	writeLines := 0
	for _, line := range strings.Split(p, "\n") {
		if strings.HasPrefix(line, "(allow file-read* file-write*") {
			writeLines++
			if strings.Contains(line, "shared refs") {
				t.Fatalf("RO export in a write rule: %s", line)
			}
		}
	}
	if writeLines != 2 { // /dev line + rw-exports block header
		t.Fatalf("unexpected write rules (%d):\n%s", writeLines, p)
	}
	// Rule order: (deny default) is the ONLY deny rule line and comes
	// first; nothing but allows and comments may follow (SBPL
	// later-wins).
	var denyLines []string
	for _, line := range strings.Split(p, "\n") {
		if strings.HasPrefix(line, "(deny") {
			denyLines = append(denyLines, line)
		}
	}
	if len(denyLines) != 1 || denyLines[0] != "(deny default)" {
		t.Fatalf("a deny rule follows an allow (SBPL later-wins): %v\n%s", denyLines, p)
	}
}

func TestBuildSeatbeltProfileEmpty(t *testing.T) {
	p := buildSeatbeltProfile(DefaultSpec(8, ""))
	if strings.Contains(p, "subpath") {
		t.Fatalf("no allowances expected:\n%s", p)
	}
}

// TestBuildSeatbeltProfileCanonicalizes: macOS matches rules against
// REAL paths and /var, /tmp are symlinks — a spec path behind a
// symlink must land in the profile resolved (the M2 spike's rw-export
// DENIED (!!) without this).
func TestBuildSeatbeltProfileCanonicalizes(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "linked-export")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	spec := DefaultSpec(8, "")
	spec.FileAllow = []FileAllowance{{Path: link, Write: true}}
	p := buildSeatbeltProfile(spec)
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p, `(subpath "`+resolved+`")`) {
		t.Fatalf("profile lacks the resolved path %q:\n%s", resolved, p)
	}
	if strings.Contains(p, "linked-export") && resolved != link {
		t.Fatalf("profile kept the symlink form:\n%s", p)
	}
}
