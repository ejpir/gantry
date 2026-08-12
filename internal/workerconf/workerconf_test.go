package workerconf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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
	if len(rep.Failed(PropFSRead, PropNetDial, PropExec, PropFSWrite, PropFDTable, PropProcEnum, PropProcSignal)) != 7 {
		t.Fatalf("disabled report must fail every required property: %+v", rep)
	}
	if got := rep.Property(PropProcSignal).State; got != StateDisabled {
		t.Fatalf("disabled report proc-signal = %q, want disabled", got)
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
	// Loopback port 1 refuses on any ordinary host; filtered CI
	// environments may silently drop instead (dial timeout reports
	// indeterminate). Either is honest — the lie would be "enforced",
	// asserted above.
	if got := rep.Property(PropNetDial).State; got != StateUnenforced && got != StateIndeterminate {
		t.Errorf("net-dial unconfined: %q, want unenforced or indeterminate", got)
	}
	if runtime.GOOS == "darwin" {
		if got := rep.Property(PropProcSignal).State; got != StateUnenforced && got != StateIndeterminate {
			t.Errorf("proc-signal unconfined: %q, want unenforced or indeterminate", got)
		}
	} else {
		if got := rep.Property(PropProcSignal).State; got != StateUnavailable {
			t.Errorf("proc-signal on %s: %q, want unavailable", runtime.GOOS, got)
		}
		for _, result := range rep.Results {
			if result.Property == PropProcSignal {
				t.Errorf("proc-signal must be omitted from %s Verify results: %+v", runtime.GOOS, result)
			}
		}
	}
}

func TestEvaluateProcSignalProbe(t *testing.T) {
	tests := []struct {
		name      string
		noProcX   bool
		parentPID int
		selfErr   error
		parentErr error
		want      string
		wantCalls int
	}{
		{name: "disabled", parentPID: 200, want: StateDisabled, wantCalls: 0},
		{name: "self positive control denied", noProcX: true, parentPID: 200, selfErr: syscall.EPERM, want: StateIndeterminate, wantCalls: 1},
		{name: "parent signal-zero permitted", noProcX: true, parentPID: 200, want: StateIndeterminate, wantCalls: 2},
		{name: "parent denied", noProcX: true, parentPID: 200, parentErr: syscall.EPERM, want: StateEnforced, wantCalls: 2},
		{name: "parent disappeared", noProcX: true, parentPID: 200, parentErr: syscall.ESRCH, want: StateIndeterminate, wantCalls: 2},
		{name: "unexpected error", noProcX: true, parentPID: 200, parentErr: syscall.EIO, want: StateIndeterminate, wantCalls: 2},
		{name: "reparented", noProcX: true, parentPID: 1, want: StateIndeterminate, wantCalls: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls []int
			got := evaluateProcSignalProbe(tc.noProcX, 100, tc.parentPID, func(pid int) error {
				calls = append(calls, pid)
				if pid == 100 {
					return tc.selfErr
				}
				return tc.parentErr
			})
			if got.Property != PropProcSignal || got.State != tc.want {
				t.Fatalf("result = %+v, want %s", got, tc.want)
			}
			if len(calls) != tc.wantCalls {
				t.Fatalf("signal calls = %v, want %d calls", calls, tc.wantCalls)
			}
		})
	}
}

func TestDefaultSpec(t *testing.T) {
	s := DefaultSpec(8, "/x")
	if s.Profile != ProfileVMM || !s.NoNetwork || !s.NoExec || !s.NoNewPaths || !s.NoProcX || s.KeepFDs != 8 || s.ConfRoot != "/x" {
		t.Fatalf("DefaultSpec: %+v", s)
	}
	if os.Getenv("WORKERCONF_HELPER") == "1" {
		t.Fatal("helper leaked into the test body")
	}
}

func TestNetworkSpecIsRoleSpecific(t *testing.T) {
	s := NetworkSpec(4, "/netroot")
	if s.Profile != ProfileNetwork || s.NoNetwork || !s.NoExec || !s.NoNewPaths || !s.NoProcX {
		t.Fatalf("NetworkSpec: %+v", s)
	}
	if s.KeepFDs != 4 || s.ConfRoot != "/netroot" || len(s.ReadFiles) == 0 {
		t.Fatalf("NetworkSpec resources: %+v", s)
	}
	if len(s.FileAllow) != 0 {
		t.Fatalf("network worker acquired host write/subtree authority: %+v", s)
	}
}

func TestBuildSeatbeltProfile(t *testing.T) {
	spec := DefaultSpec(12, "")
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
		"(allow sysctl-read\n",
		`(literal "/dev/null")`,
		`(subpath "/Users/test/project")`,
		`(subpath "/Users/test/shared refs")`,
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("profile missing %q:\n%s", want, p)
		}
	}
	var signalRules []string
	for _, line := range strings.Split(p, "\n") {
		if strings.HasPrefix(line, "(allow signal") {
			signalRules = append(signalRules, line)
		}
	}
	if len(signalRules) != 1 || signalRules[0] != "(allow signal (target self))" {
		t.Fatalf("profile must allow only self-signaling, got %v:\n%s", signalRules, p)
	}
	if strings.Contains(p, "mach-lookup") {
		t.Fatalf("profile grants ambient Mach service discovery:\n%s", p)
	}
	// Trusted sandbox state and broker-owned logs carry no path grant.
	for _, forbidden := range []string{"sandbox.json", "console.log", "worker-vmm.log", "worker-net.log"} {
		if strings.Contains(p, forbidden) {
			t.Fatalf("profile grants access to trusted path %q:\n%s", forbidden, p)
		}
	}
	// Escaping: quotes and backslashes must not break the SBPL literal.
	if !strings.Contains(p, `/Users/test/we\"ird\\path`) {
		t.Fatalf("profile escaping wrong:\n%s", p)
	}
	// RO root must never appear under a write rule: the only
	// file-write* rules are the /dev literals and the RW export block.
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

func TestBuildNetworkSeatbeltProfile(t *testing.T) {
	spec := NetworkSpec(4, "")
	profile := buildSeatbeltProfile(spec)
	for _, rule := range []string{
		`(allow network-bind (local ip "*:*")`,
		`(allow network-inbound (local ip "*:*")`,
		`(allow network-outbound (remote ip "*:*")`,
	} {
		if !strings.Contains(profile, rule) {
			t.Fatalf("network profile lacks %q:\n%s", rule, profile)
		}
	}
	for _, forbidden := range []string{
		"(allow network*)", "(allow network-inbound)", "(allow network-outbound)",
		"(allow mach-lookup)", "system-socket", "file-write*\n", "process-fork", "process-exec",
	} {
		if strings.Contains(profile, forbidden) {
			t.Fatalf("network profile contains forbidden authority %q:\n%s", forbidden, profile)
		}
	}
	for _, name := range seatbeltRuntimeSysctls {
		if !strings.Contains(profile, `(sysctl-name "`+name+`")`) {
			t.Fatalf("network profile lacks runtime sysctl %q:\n%s", name, profile)
		}
	}
	if strings.Contains(profile, "(allow sysctl-read)") || strings.Contains(profile, "kern.proc") {
		t.Fatalf("network profile grants broad/process sysctl reads:\n%s", profile)
	}
	for _, path := range spec.ReadFiles {
		escapedRaw := sbplEscape(path)
		resolved := sbplEscape(sbplPath(path))
		if !strings.Contains(profile, `(allow file-read* (literal "`+escapedRaw+`"))`) {
			t.Fatalf("network profile lacks literal resolver read %q:\n%s", escapedRaw, profile)
		}
		if resolved != escapedRaw && !strings.Contains(profile, `(allow file-read* (literal "`+resolved+`"))`) {
			t.Fatalf("network profile lacks canonicalized resolver read %q:\n%s", resolved, profile)
		}
		for _, dir := range []string{filepath.Dir(path), filepath.Dir(sbplPath(path))} {
			escapedDir := sbplEscape(dir)
			if strings.Contains(profile, `(subpath "`+escapedDir+`")`) {
				t.Fatalf("literal resolver grant %q broadened to parent %q:\n%s", path, dir, profile)
			}
		}
	}
	var metadataRule strings.Builder
	metadataRule.WriteString("(allow file-read-metadata\n")
	for _, path := range seatbeltNetworkConfigMetadata {
		metadataRule.WriteString(`	(literal "` + sbplEscape(path) + `")` + "\n")
		if strings.Contains(profile, `(subpath "`+sbplEscape(path)+`")`) {
			t.Fatalf("resolver metadata grant %q broadened to a subpath:\n%s", path, profile)
		}
	}
	metadataRule.WriteString(")\n")
	if !strings.Contains(profile, metadataRule.String()) {
		t.Fatalf("network profile lacks exact resolver metadata rule:\n%s", profile)
	}
	for _, forbidden := range []string{"worker-net.log", "console.log", "worker-vmm.log"} {
		if strings.Contains(profile, forbidden) {
			t.Fatalf("network profile grants broker-owned log path %q:\n%s", forbidden, profile)
		}
	}
	for _, forbidden := range []string{probeReadPath, sbplPath(probeReadPath)} {
		if strings.Contains(profile, `(literal "`+sbplEscape(forbidden)+`")`) {
			t.Fatalf("network profile grants verifier read target %q:\n%s", forbidden, profile)
		}
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
	// The profile text carries the SBPL-escaped form of the resolved
	// path (backslashes doubled on windows).
	if !strings.Contains(p, `(subpath "`+sbplEscape(resolved)+`")`) {
		t.Fatalf("profile lacks the resolved path %q:\n%s", resolved, p)
	}
	if strings.Contains(p, "linked-export") && resolved != link {
		t.Fatalf("profile kept the symlink form:\n%s", p)
	}
}
