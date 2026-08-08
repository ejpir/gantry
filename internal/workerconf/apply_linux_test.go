package workerconf

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestApplyConfined re-executes this test binary inside
// CLONE_NEWUSER|CLONE_NEWNS, applies the full confinement stack, churns
// the runtime (threads/GC must survive the TSYNC'd filter), and prints
// the Verify report as JSON. The parent asserts every probe flipped to
// enforced. When the kernel refuses unprivileged user namespaces
// (Ubuntu 24.04+ AppArmor policy, restricted containers) the test
// SKIPS WITH A REPORT — it never fakes a pass.
func TestApplyConfined(t *testing.T) {
	if os.Getenv("WORKERCONF_HELPER") == "1" {
		confinedHelper()
		return
	}
	root := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestApplyConfined", "-test.v")
	cmd.Env = append(os.Environ(), "WORKERCONF_HELPER=1", "WORKERCONF_ROOT="+root)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.CombinedOutput()
	text := string(out)
	if err != nil {
		if strings.Contains(text, "operation not permitted") || strings.Contains(text, "permission denied") {
			t.Skipf("unprivileged userns unavailable on this host (AppArmor-restricted or container policy): %v\n%s", err, text)
		}
		t.Fatalf("helper failed: %v\n%s", err, text)
	}
	// The helper's report is the one line starting with {"platform".
	var rep Report
	found := false
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "{\"platform\"") {
			continue
		}
		if err := json.Unmarshal([]byte(line), &rep); err != nil {
			t.Fatalf("report unmarshal: %v\n%s", err, text)
		}
		found = true
	}
	if !found {
		t.Fatalf("no report in helper output:\n%s", text)
	}
	if !rep.Applied {
		t.Fatalf("nothing applied: %+v\n%s", rep, text)
	}
	// Restricted userns (Ubuntu 24.04+ AppArmor blocks mounts inside an
	// unprivileged userns — exactly what CI runners enforce): the mount
	// tier is unavailable but the seccomp tier MUST hold. Assert the
	// seccomp-covered probes, then skip-with-report — never fake a
	// pass, never demand what the environment cannot give.
	mountOK := !strings.Contains(strings.Join(rep.Notes, " "), "mount tier unavailable")
	if !mountOK {
		for _, name := range []string{PropNetDial, PropExec} {
			if got := rep.Property(name).State; got != StateEnforced {
				t.Errorf("%s = %q (%s), want enforced even in the degraded tier", name, got, rep.Property(name).Detail)
			}
		}
		t.Skipf("mount tier unavailable in this environment (restricted userns); seccomp tier verified, notes: %v", rep.Notes)
	}
	for _, name := range []string{PropFSRead, PropFSWrite, PropNetDial, PropExec, PropProcEnum} {
		if got := rep.Property(name).State; got != StateEnforced {
			t.Errorf("%s = %q (%s), want enforced\nnotes: %v", name, got, rep.Property(name).Detail, rep.Notes)
		}
	}
	if strings.Contains(strings.Join(rep.Notes, " "), "seccomp tier unavailable") {
		t.Errorf("seccomp tier failed to install: %v", rep.Notes)
	}
}

// confinedHelper runs inside the re-executed process: confine, churn
// the runtime, verify, print the report. Stdout is line-buffered
// THROUGH the confinement (fd 1 survives close_range by spec).
func confinedHelper() {
	spec := DefaultSpec(2, os.Getenv("WORKERCONF_ROOT"))
	rep, applyErr := Apply(spec)
	if applyErr != nil {
		rep.Notes = append(rep.Notes, "apply: "+applyErr.Error())
	}
	// Churn: force thread creation + GC under the filter before probing.
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					time.Sleep(2 * time.Millisecond)
				}
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	close(done)
	Verify(spec, rep)
	data, _ := json.Marshal(rep)
	_, _ = os.Stdout.Write(append(data, '\n'))
}
