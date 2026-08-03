//go:build linux

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
	"strconv"
	"strings"
	"syscall"
	"time"
)

// realRuntime is a var so tests can point supervise at a helper process.
var realRuntime = "/sbin/crun.runsc"

// debugMode reports whether verbose runsc logging is requested via the
// kernel cmdline: the host sets GANTRY_EXTRA_CMDLINE="crunshim.debug=1"
// (GANTRY_EXTRA_CMDLINE is inserted into the guest cmdline by gantry).
func debugMode() bool {
	b, err := os.ReadFile("/proc/cmdline")
	return err == nil && strings.Contains(string(b), "crunshim.debug=1")
}

func main() {
	debug := debugMode()
	if debug {
		if c, err := os.OpenFile("/dev/console", os.O_WRONLY, 0); err == nil {
			fmt.Fprintf(c, "crunshim: start args=%v\n", os.Args[1:])
			c.Close()
		}
	}
	fixDev(debug)
	os.Exit(supervise(insertFlags(os.Args, debug), debug))
}

// insertFlags adjusts runsc's global flags (before the subcommand).
//
//	--debug + --log→/dev/console (debug mode only): runsc propagates
//	--log to the gofer and boot children, so this puts the SENTRY's own
//	boot log — which otherwise dies with the process inside the VM — onto
//	the VM kernel console (→ the gantry daemon log).
//
//	--alsologtostderr is deliberately NEVER injected: the boot child's
//	stderr is the container pty (stdio-fds), and gVisor emits the banner
//	+ full config dump to every emitter sequentially — the pty master is
//	not drained during Create, so the small pty buffer fills and the boot
//	child deadlocks in n_tty_write before logging a byte anywhere.
func insertFlags(args []string, debug bool) []string {
	out := []string{args[0]}
	// --network=host: runsc's default "sandbox" network is an isolated
	// netstack with no upstream (loopback only, DNS dies with "network
	// unreachable"). Our crun containers share the VM's netns; host mode
	// preserves that. Network isolation is the gantry VM + netpol's job.
	// (--TESTONLY-unsafe-nonroot is history: the sentry runs in runsc's
	// minimal chroot again — it was never the problem; the 16K page size
	// and the pty stderr buffer were.)
	// --directfs=false: under directfs the SENTRY (which runs with no
	// capabilities, doing host syscalls itself) cannot write virtio-fs
	// shares owned by a non-root host uid -> container writes fail with
	// EPERM. The gofer keeps CAP_DAC_OVERRIDE/FOWNER, so route all fs
	// access through it.
	inject := []string{"--network=host", "--directfs=false"}
	if debug {
		// In runsc >= 2026, --log is only the fatal-error logger; real
		// debug logs go to --debug-log and are discarded when unset.
		inject = append(inject, "--debug", "--debug-log", "/dev/console")
	}
	for _, f := range inject {
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
		if debug && a == "--log" && i+1 < len(args) {
			out = append(out, a, "/dev/console")
			i++
			continue
		}
		if debug && strings.HasPrefix(a, "--log=") {
			out = append(out, "--log=/dev/console")
			continue
		}
		out = append(out, a)
	}
	return out
}

// supervise runs runsc as a child and propagates its exit status exactly
// (containerd maps runtime exit codes).
//
// The child's stdout/stderr go to a temp file, NOT a pipe: os/exec skips
// its copy goroutines for *os.File, so cmd.Wait returns the instant the
// child exits. With a pipe, Wait also blocks on pipe EOF — and runsc >=
// 2026-07 leaves parked create/start grandchildren (gofer, sandbox)
// holding the inherited pipe for the container's whole lifetime. That
// wedged every Create (the "sb" hang); in debug the watchdog then
// SIGQUIT'd the healthy sandbox. The file is replayed to our stderr
// after Wait, preserving containerd's runtime-error UX, and its tail is
// dumped to /dev/console on failure (a dying sentry surfaces only as
// "waiting for sandbox to start: EOF" otherwise).
func supervise(args []string, debug bool) int {
	cmd := exec.Command(realRuntime, args[1:]...)
	cmd.Args[0] = args[0]
	cmd.Stdin = os.Stdin
	stdio, err := os.CreateTemp("", "crunshim-stdio-*.log")
	if err != nil {
		fmt.Fprintf(os.Stderr, "crunshim: temp log: %v\n", err)
		return 127
	}
	defer func() {
		stdio.Close()
		os.Remove(stdio.Name())
	}()
	cmd.Stdout, cmd.Stderr = stdio, stdio
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
	// invisible: after 25s, SIGQUIT the child AND every runsc-sandbox
	// grandchild found via /proc (their Go runtime dumps all goroutine
	// stacks to stderr; the sandbox's stderr is /dev/null, which this
	// shim pointed at /dev/console) - then dump our captured tail.
	// Debug mode only, and never for `run`: a healthy one-shot container
	// outlives 25s and must not be SIGQUIT'd.
	isRun := false
	for _, a := range args[1:] {
		if a == "run" {
			isRun = true
			break
		}
	}
	var timed *time.Timer
	if debug && !isRun {
		timed = time.AfterFunc(25*time.Second, func() {
			if c, err := os.OpenFile("/dev/console", os.O_WRONLY, 0); err == nil {
				for _, pid := range findRunsc() {
					// /proc FIRST: a pre-runtime child dies silently on
					// SIGQUIT, taking the evidence with it
					dumpProcState(c, pid)
				}
				fmt.Fprintf(c, "\ncrunshim: runsc still running after 25s, sent SIGQUIT\n----- runsc output tail -----\n%s\n----- end -----\n", fileTail(stdio, 32<<10))
				c.Close()
			}
			if cmd.Process != nil {
				cmd.Process.Signal(syscall.SIGQUIT)
			}
			for _, pid := range findRunsc() {
				syscall.Kill(pid, syscall.SIGQUIT)
			}
		})
		defer timed.Stop()
	}
	err = cmd.Wait()
	signal.Stop(sigc)
	replayStdio(stdio)
	if err != nil {
		if c, cerr := os.OpenFile("/dev/console", os.O_WRONLY, 0); cerr == nil {
			fmt.Fprintf(c, "\ncrunshim: runsc failed: %v\n----- runsc output tail -----\n%s\n----- end -----\n", err, fileTail(stdio, 32<<10))
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

// fileTail returns the last limit bytes of f, without disturbing the
// file offset of any concurrent writer.
func fileTail(f *os.File, limit int64) string {
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return ""
	}
	start := int64(0)
	if st.Size() > limit {
		start = st.Size() - limit
	}
	buf := make([]byte, st.Size()-start)
	n, _ := f.ReadAt(buf, start)
	return string(buf[:n])
}

// replayStdio forwards the child's captured output to our stderr so
// containerd's task errors keep the runtime's diagnostics (bounded).
func replayStdio(f *os.File) {
	const maxReplay = 256 << 10
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return
	}
	if st.Size() > maxReplay {
		fmt.Fprintf(os.Stderr, "crunshim: [%d bytes of runtime output elided]\n", st.Size()-maxReplay)
	}
	fmt.Fprint(os.Stderr, fileTail(f, maxReplay))
}

func fixDev(debug bool) {
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
	if debug && exists("/dev/console") {
		// runsc wires the sandbox child's stdin/stdout/stderr to /dev/null,
		// so a boot process dying before logger init vanishes without a
		// trace. Debug mode points /dev/null at the VM console.
		os.Remove("/dev/null")
		if err := os.Symlink("/dev/console", "/dev/null"); err != nil {
			fmt.Fprintf(os.Stderr, "crunshim: /dev/null -> /dev/console: %v\n", err)
		}
	}
}

// findRunsc returns PIDs of processes whose cmdline contains
// "runsc-sandbox" or "runsc-gofer" (the re-exec'd grandchildren, which
// are not signal-reachable through our direct child's process group).
func findRunsc() []int {
	var pids []int
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		cl, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		s := string(cl)
		if strings.Contains(s, "runsc-sandbox") || strings.Contains(s, "runsc-gofer") {
			pids = append(pids, pid)
		}
	}
	return pids
}

// dumpProcState writes a hung process's kernel-side state to w: what
// it's called, its State line, its wait channel, its in-kernel syscall
// and its kernel stack (D-state hangs never answer SIGQUIT, and a Go
// runtime that hasn't installed signal handlers yet can't either).
func dumpProcState(w io.Writer, pid int) {
	p := fmt.Sprintf("/proc/%d", pid)
	fmt.Fprintf(w, "\ncrunshim: --- /proc state for pid %d ---\n", pid)
	for _, f := range []string{"cmdline", "status", "wchan", "syscall", "stack"} {
		b, err := os.ReadFile(p + "/" + f)
		if err != nil {
			fmt.Fprintf(w, "%s: %v\n", f, err)
			continue
		}
		if f == "cmdline" {
			b = []byte(strings.ReplaceAll(string(b), "\x00", " "))
		}
		if f == "status" {
			// keep only the interesting lines
			var keep []string
			for _, ln := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(ln, "Name:") || strings.HasPrefix(ln, "State:") ||
					strings.HasPrefix(ln, "PPid:") || strings.HasPrefix(ln, "Threads:") {
					keep = append(keep, ln)
				}
			}
			b = []byte(strings.Join(keep, "\n"))
		}
		fmt.Fprintf(w, "%s:\n%s\n", f, b)
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
