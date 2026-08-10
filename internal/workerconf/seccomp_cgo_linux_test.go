package workerconf

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// TestSeccompAllowsCgoPthreadButNotProcessClone covers the distinction that
// ordinary goroutine churn cannot: glibc pthread_create first uses clone3 on
// current Linux, receives the filter's intentional ENOSYS, falls back to
// clone(CLONE_THREAD), and joins successfully. A process-like clone remains
// EPERM. The helper is built on demand so workerconf itself stays cgo-free.
func TestSeccompAllowsCgoPthreadButNotProcessClone(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a cgo probe binary")
	}
	if runtime.GOOS != "linux" || os.Getenv("CGO_ENABLED") == "0" {
		t.Skip("Linux cgo probe")
	}
	binary := filepath.Join(t.TempDir(), "workerconf-cgothread")
	build := exec.Command("go", "build", "-o", binary, "./testdata/cgothread")
	if output, err := build.CombinedOutput(); err != nil {
		t.Skipf("cgo compiler unavailable: %v\n%s", err, output)
	}
	cmd := exec.Command(binary)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cgo confinement probe: %v\n%s", err, output)
	}
	text := string(output)
	for _, marker := range []string{"CGO-PTHREAD-OK", "PROCESS-CLONE-DENIED"} {
		if !strings.Contains(text, marker) {
			t.Fatalf("probe output lacks %s:\n%s", marker, text)
		}
	}

	namespaced := exec.Command(binary)
	namespaced.Env = append(os.Environ(),
		"WORKERCONF_CGO_NAMESPACED=1",
		"WORKERCONF_ROOT="+t.TempDir(),
	)
	namespaced.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	output, err = namespaced.CombinedOutput()
	if err != nil {
		if namespaceTestUnavailable(err, string(output)) {
			t.Skipf("unprivileged userns unavailable: %v\n%s", err, output)
		}
		t.Fatalf("namespaced cgo confinement probe: %v\n%s", err, output)
	}
	for _, marker := range []string{"CGO-PTHREAD-OK", "TASK-LIMIT-ENFORCED", "PROCESS-CLONE-DENIED"} {
		if !strings.Contains(string(output), marker) {
			t.Fatalf("namespaced probe output lacks %s:\n%s", marker, output)
		}
	}
}
