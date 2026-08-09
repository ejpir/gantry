package workerconf

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSeccompTGKillRestricted verifies the namespace-less auto-mode safety
// net: Go may signal threads in its own thread group, but a compromised worker
// cannot use tgkill against another same-UID process. Signal zero performs the
// kernel permission/existence check without delivering a signal.
func TestSeccompTGKillRestricted(t *testing.T) {
	if os.Getenv("WORKERCONF_TGKILL_HELPER") == "1" {
		tgkillHelper()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestSeccompTGKillRestricted")
	cmd.Env = append(os.Environ(),
		"WORKERCONF_TGKILL_HELPER=1",
		"WORKERCONF_TGKILL_TARGET="+strconv.Itoa(os.Getpid()),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tgkill helper failed: %v\n%s", err, out)
	}
	for _, marker := range []string{
		"CROSS-TGKILL-PREFILTER-OK", "CROSS-AFFINITY-PREFILTER-OK",
		"FCNTL-SETOWN-PREFILTER-OK",
		"SELF-TGKILL-OK", "CROSS-TGKILL-DENIED",
		"SELF-AFFINITY-OK", "CROSS-AFFINITY-DENIED",
		"SAFE-FCNTL-OK", "FCNTL-SIGNAL-CMDS-DENIED",
	} {
		if !strings.Contains(string(out), marker) {
			t.Fatalf("tgkill helper output lacks %q:\n%s", marker, out)
		}
	}
}

func tgkillHelper() {
	target, err := strconv.Atoi(os.Getenv("WORKERCONF_TGKILL_TARGET"))
	if err != nil || target <= 0 {
		fmt.Fprintln(os.Stderr, "invalid target TGID")
		os.Exit(2)
	}
	// Establish that the same-UID process outside this helper is a real,
	// addressable target; otherwise a post-filter ESRCH could masquerade as
	// successful confinement.
	if _, _, errno := syscall.RawSyscall(unix.SYS_TGKILL, uintptr(target), uintptr(target), 0); errno != 0 {
		fmt.Fprintln(os.Stderr, "pre-filter cross-process tgkill:", errno)
		os.Exit(2)
	}
	fmt.Println("CROSS-TGKILL-PREFILTER-OK")
	var affinity unix.CPUSet
	if err := unix.SchedGetaffinity(target, &affinity); err != nil {
		fmt.Fprintln(os.Stderr, "pre-filter cross-process sched_getaffinity:", err)
		os.Exit(2)
	}
	fmt.Println("CROSS-AFFINITY-PREFILTER-OK")
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "socketpair:", err)
		os.Exit(2)
	}
	defer func(fd int) { _ = unix.Close(fd) }(fds[0])
	defer func(fd int) { _ = unix.Close(fd) }(fds[1])
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_SETOWN, target); err != nil {
		fmt.Fprintln(os.Stderr, "pre-filter F_SETOWN:", err)
		os.Exit(2)
	}
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_SETOWN, 0); err != nil {
		fmt.Fprintln(os.Stderr, "pre-filter reset F_SETOWN:", err)
		os.Exit(2)
	}
	fmt.Println("FCNTL-SETOWN-PREFILTER-OK")
	if err := installSeccomp(); err != nil {
		fmt.Fprintln(os.Stderr, "install seccomp:", err)
		os.Exit(2)
	}

	self := os.Getpid()
	if _, _, errno := syscall.RawSyscall(unix.SYS_TGKILL, uintptr(self), uintptr(self), 0); errno != 0 {
		fmt.Fprintln(os.Stderr, "self tgkill:", errno)
		os.Exit(1)
	}
	fmt.Println("SELF-TGKILL-OK")
	if _, _, errno := syscall.RawSyscall(unix.SYS_TGKILL, uintptr(target), uintptr(target), 0); errno != syscall.EPERM {
		fmt.Fprintf(os.Stderr, "cross-process tgkill errno = %v, want EPERM\n", errno)
		os.Exit(1)
	}
	fmt.Println("CROSS-TGKILL-DENIED")
	if err := unix.SchedGetaffinity(0, &affinity); err != nil {
		fmt.Fprintln(os.Stderr, "self sched_getaffinity:", err)
		os.Exit(1)
	}
	fmt.Println("SELF-AFFINITY-OK")
	if err := unix.SchedGetaffinity(target, &affinity); err != syscall.EPERM {
		fmt.Fprintf(os.Stderr, "cross-process sched_getaffinity error = %v, want EPERM\n", err)
		os.Exit(1)
	}
	fmt.Println("CROSS-AFFINITY-DENIED")
	flags, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFL, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "safe F_GETFL:", err)
		os.Exit(1)
	}
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_SETFL, flags); err != nil {
		fmt.Fprintln(os.Stderr, "safe F_SETFL:", err)
		os.Exit(1)
	}
	fmt.Println("SAFE-FCNTL-OK")
	for name, cmd := range map[string]int{
		"F_SETOWN": unix.F_SETOWN,
		"F_SETSIG": unix.F_SETSIG,
	} {
		if _, err := unix.FcntlInt(uintptr(fds[0]), cmd, target); err != syscall.EPERM {
			fmt.Fprintf(os.Stderr, "%s error = %v, want EPERM\n", name, err)
			os.Exit(1)
		}
	}
	if _, _, errno := syscall.RawSyscall(unix.SYS_FCNTL, uintptr(fds[0]), uintptr(unix.F_SETOWN_EX), 0); errno != syscall.EPERM {
		fmt.Fprintf(os.Stderr, "F_SETOWN_EX errno = %v, want EPERM\n", errno)
		os.Exit(1)
	}
	fmt.Println("FCNTL-SIGNAL-CMDS-DENIED")
}
