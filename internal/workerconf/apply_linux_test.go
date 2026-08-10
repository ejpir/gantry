package workerconf

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestApplyConfined re-executes this test binary inside
// CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID, applies the full confinement stack, churns
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
	cmd.Env = append(os.Environ(), "WORKERCONF_HELPER=1", "WORKERCONF_ROOT="+root,
		"WORKERCONF_OUTER_PID="+strconv.Itoa(os.Getpid()))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.CombinedOutput()
	text := string(out)
	if err != nil {
		if namespaceTestUnavailable(err, text) {
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
	if !strings.Contains(text, "PID-NAMESPACE-CROSS-TGKILL-HIDDEN") {
		t.Fatalf("helper did not prove its outside victim is hidden:\n%s", text)
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
		for _, name := range []string{PropFSRead, PropFSWrite, PropNetDial, PropExec, PropFDTable, PropSyscall, PropProcEnum, PropTaskLimit} {
			if got := rep.Property(name).State; got != StateEnforced {
				t.Errorf("%s = %q (%s), want enforced even in the degraded tier", name, got, rep.Property(name).Detail)
			}
		}
		t.Skipf("mount tier unavailable in this environment (restricted userns); seccomp tier verified, notes: %v", rep.Notes)
	}
	for _, name := range []string{PropFSRead, PropFSWrite, PropNetDial, PropExec, PropFDTable, PropSyscall, PropProcEnum, PropTaskLimit} {
		if got := rep.Property(name).State; got != StateEnforced {
			t.Errorf("%s = %q (%s), want enforced\nnotes: %v", name, got, rep.Property(name).Detail, rep.Notes)
		}
	}
	if strings.Contains(strings.Join(rep.Notes, " "), "seccomp tier unavailable") {
		t.Errorf("seccomp tier failed to install: %v", rep.Notes)
	}
}

func namespaceTestUnavailable(err error, output string) bool {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EUSERS) {
		return true
	}
	text := strings.ToLower(output)
	for _, fragment := range []string{
		"operation not permitted", "permission denied",
		"no space left on device", "too many users",
	} {
		if strings.Contains(text, fragment) {
			return true
		}
	}
	return false
}

func TestCopyPrivateConfigRejectsDevices(t *testing.T) {
	err := copyPrivateConfig(t.TempDir(), "/dev/null")
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("copyPrivateConfig(/dev/null) = %v, want regular-file rejection", err)
	}
}

// confinedHelper runs inside the re-executed process: confine, churn
// the runtime, verify, print the report. Stdout is line-buffered
// THROUGH the confinement (fd 1 survives close_range by spec).
func confinedHelper() {
	if pid := os.Getpid(); pid != 1 {
		_, _ = os.Stderr.WriteString("helper: PID namespace init has PID " + strconv.Itoa(pid) + ", want 1\n")
		os.Exit(2)
	}
	if ppid := os.Getppid(); ppid != 0 {
		_, _ = os.Stderr.WriteString("helper: PID namespace parent is " + strconv.Itoa(ppid) + ", want 0\n")
		os.Exit(2)
	}
	outerPID, err := strconv.Atoi(os.Getenv("WORKERCONF_OUTER_PID"))
	if err != nil || outerPID <= 1 {
		_, _ = os.Stderr.WriteString("helper: invalid outside victim PID\n")
		os.Exit(2)
	}
	// Signal zero is non-delivering. ESRCH here directly proves the live,
	// same-UID parent is outside this PID namespace rather than merely hidden
	// by the later /proc pivot or denied by seccomp.
	if _, _, errno := syscall.RawSyscall(unix.SYS_TGKILL, uintptr(outerPID), uintptr(outerPID), 0); errno != syscall.ESRCH {
		_, _ = os.Stderr.WriteString("helper: outside-victim tgkill returned " + errno.Error() + ", want ESRCH\n")
		os.Exit(2)
	}
	_, _ = os.Stdout.WriteString("PID-NAMESPACE-CROSS-TGKILL-HIDDEN\n")
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
