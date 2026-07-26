// crunshim is installed as /sbin/crun in the gVisor rootfs variant
// (mkrootfs-gvisor.sh). Two jobs:
//
//  1. fixDev — nerdbox's vminitd leaves /dev bare in the namespace the
//     runtime runs in; runsc allocates the console pty parent-side
//     (kr/pty opens /dev/ptmx, then /dev/pts/N) and spawns its gofer with
//     /dev/null stdio, so install a proper device set first.
//  2. supervise — run runsc as a child, mirroring its output and, on
//     failure, dumping the captured tail to /dev/console (the VM kernel
//     console → the gantry daemon log). runsc writes its diagnostics to
//     a --log file inside the VM and the sentry's stderr is /dev/null,
//     so without this a dying sentry surfaces only as "waiting for
//     sandbox to start: EOF".
package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const realRuntime = "/sbin/crun.runsc"

func main() {
	fixDev()
	os.Exit(supervise(insertFlags(os.Args)))
}

// insertFlags adds runsc global flags (before the subcommand) and
// rewrites --log to /dev/console. runsc propagates --log to the gofer
// and boot children, so this puts the SENTRY's own boot log — which
// otherwise dies with the process inside the VM — onto the VM kernel
// console (→ the gantry daemon log). --debug maximizes what it says.
func insertFlags(args []string) []string {
	out := []string{args[0]}
	// --TESTONLY-unsafe-nonroot: skip runsc's minimal-chroot setup for the
	// sandbox process. That step fails silently (stderr is /dev/null) in
	// this VM, and the chroot is defense-in-depth we can trade away: the
	// gantry VM itself is the outer isolation boundary.
	for _, f := range []string{"--debug", "--alsologtostderr", "--TESTONLY-unsafe-nonroot"} {
		present := false
		for _, a := range args[1:] {
			if a == f || strings.HasPrefix(a, f+"=") {
				present = true
				break
			}
		}
		if !present {
			out = append(out, f)
		}
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "--log" && i+1 < len(args) {
			out = append(out, a, "/dev/console")
			i++
			continue
		}
		if strings.HasPrefix(a, "--log=") {
			out = append(out, "--log=/dev/console")
			continue
		}
		out = append(out, a)
	}
	return out
}

// supervise runs runsc as a child, passing stdio through while teeing a
// tail buffer; on failure the tail goes to /dev/console. Exit status is
// propagated exactly (containerd maps runtime exit codes).
func supervise(args []string) int {
	cmd := exec.Command(realRuntime, args[1:]...)
	cmd.Args[0] = args[0]
	tail := &tailBuf{limit: 32 << 10}
	cmd.Stdin = os.Stdin
	cmd.Stdout = io.MultiWriter(os.Stdout, tail)
	cmd.Stderr = io.MultiWriter(os.Stderr, tail)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "crunshim: start %s: %v\n", realRuntime, err)
		return 127
	}
	// forward termination signals (containerd cancels the runtime on
	// timeouts) to the child
	sigc := make(chan os.Signal, 4)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		for s := range sigc {
			if cmd.Process != nil {
				cmd.Process.Signal(s)
			}
		}
	}()
	// a hung runsc (deadlock waiting on gofer/sandbox sync) is otherwise
	// invisible: after 25s send SIGQUIT - the Go runtime prints all
	// goroutine stacks to stderr, which our tail captures - then dump
	timed := time.AfterFunc(25*time.Second, func() {
		if cmd.Process != nil {
			cmd.Process.Signal(syscall.SIGQUIT)
		}
		time.Sleep(2 * time.Second)
		if c, err := os.OpenFile("/dev/console", os.O_WRONLY, 0); err == nil {
			fmt.Fprintf(c, "\ncrunshim: runsc still running after 25s, sent SIGQUIT\n----- runsc output tail -----\n%s\n----- end -----\n", tail.String())
			c.Close()
		}
	})
	defer timed.Stop()
	err := cmd.Wait()
	signal.Stop(sigc)
	if err != nil {
		if c, cerr := os.OpenFile("/dev/console", os.O_WRONLY, 0); cerr == nil {
			fmt.Fprintf(c, "\ncrunshim: runsc failed: %v\n----- runsc output tail -----\n%s\n----- end -----\n", err, tail.String())
			c.Close()
		}
		if cmd.ProcessState != nil {
			if code := cmd.ProcessState.ExitCode(); code >= 0 {
				return code
			}
		}
		return 1
	}
	return 0
}

// tailBuf keeps the last `limit` bytes written.
type tailBuf struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func (t *tailBuf) Write(p []byte) (int, error) {
	t.mu.Lock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.limit {
		t.buf = t.buf[len(t.buf)-t.limit:]
	}
	t.mu.Unlock()
	return len(p), nil
}

func (t *tailBuf) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

func fixDev() {
	// Whatever namespace vminitd spawns us in, it is the namespace runsc
	// will use — verify /dev is complete here and repair it if not.
	// stderr lands in vminitd's runtime error chain, so report findings.
	nullOK := exists("/dev/null")
	ptmxOK := exists("/dev/ptmx")
	if !nullOK || !ptmxOK {
		fmt.Fprintf(os.Stderr, "crunshim: /dev incomplete (null=%v ptmx=%v), installing tmpfs device set\n", nullOK, ptmxOK)
		if err := syscall.Mount("tmpfs", "/dev", "tmpfs", 0, "mode=755"); err != nil {
			fmt.Fprintf(os.Stderr, "crunshim: tmpfs mount on /dev failed: %v\n", err)
			return
		}
		for _, n := range []struct {
			name         string
			major, minor uint32
			mode         uint32
		}{
			{"null", 1, 3, 0o666},
			{"zero", 1, 5, 0o666},
			{"full", 1, 7, 0o666},
			{"random", 1, 8, 0o666},
			{"urandom", 1, 9, 0o666},
			{"tty", 5, 0, 0o666},
			{"console", 5, 1, 0o600},
			{"ptmx", 5, 2, 0o666},
		} {
			if err := mknod("/dev/"+n.name, n.major, n.minor, n.mode); err != nil {
				fmt.Fprintf(os.Stderr, "crunshim: mknod /dev/%s: %v\n", n.name, err)
			}
		}
		// conventional symlinks some tools expect
		os.Symlink("/proc/self/fd", "/dev/fd")
		os.Symlink("/proc/self/fd/0", "/dev/stdin")
		os.Symlink("/proc/self/fd/1", "/dev/stdout")
		os.Symlink("/proc/self/fd/2", "/dev/stderr")
	}
	if !exists("/dev/pts") {
		_ = syscall.Mkdir("/dev/pts", 0o755)
	}
	// kr/pty resolves the slave to /dev/pts/N — devpts must be mounted.
	if !isMountPoint("/dev/pts") {
		if err := syscall.Mount("devpts", "/dev/pts", "devpts", 0, "mode=620,ptmxmode=666"); err != nil {
			fmt.Fprintf(os.Stderr, "crunshim: devpts mount: %v\n", err)
		}
	}
	// runsc wires the sandbox child's stdin/stdout/stderr to /dev/null,
	// so a boot process dying before logger init (which is exactly what
	// we are debugging) vanishes without a trace. Point /dev/null at the
	// VM console: pre-logger panics/fatals become visible in the gantry
	// daemon log. Noisy, but this rootfs exists for gVisor bring-up.
	if exists("/dev/console") {
		os.Remove("/dev/null")
		if err := os.Symlink("/dev/console", "/dev/null"); err != nil {
			fmt.Fprintf(os.Stderr, "crunshim: /dev/null -> /dev/console: %v\n", err)
		}
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// isMountPoint reports whether path is a mount point (device or parent
// differs from its parent dir — cheap check, no mountinfo parsing).
func isMountPoint(path string) bool {
	var st, pst syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return false
	}
	if err := syscall.Stat(path+"/..", &pst); err != nil {
		return false
	}
	return st.Dev != pst.Dev || st.Ino == pst.Ino
}

func mknod(path string, major, minor, mode uint32) error {
	dev := int((major << 8) | minor) // valid for majors < 4096, minors < 256
	return syscall.Mknod(path, syscall.S_IFCHR|mode, dev)
}
