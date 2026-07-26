// crunshim is installed as /sbin/crun in the gVisor rootfs variant
// (mkrootfs-gvisor.sh). It prepares the VM's /dev — nerdbox's vminitd
// mounts none and the EROFS root's /dev is an empty read-only dir — so
// that runsc can allocate the container console pty parent-side (kr/pty
// opens /dev/ptmx, then /dev/pts/N), then execs the real runtime.
//
// crun never needed this because it allocates the pty inside the
// container's mount namespace; runsc does it before starting the sandbox.
package main

import (
	"fmt"
	"os"
	"syscall"
)

const realRuntime = "/sbin/crun.runsc"

func main() {
	fixDev()
	if err := syscall.Exec(realRuntime, os.Args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "crunshim: exec %s: %v\n", realRuntime, err)
		os.Exit(127)
	}
}

func fixDev() {
	// Prefer devtmpfs (full device set incl. ptmx); fall back to tmpfs +
	// a manual ptmx node if the kernel lacks devtmpfs. Messages go to
	// stderr, which vminitd captures into the runtime error chain.
	if err := syscall.Mount("devtmpfs", "/dev", "devtmpfs", 0, ""); err != nil {
		fmt.Fprintf(os.Stderr, "crunshim: devtmpfs mount failed (%v), trying tmpfs\n", err)
		if err := syscall.Mount("tmpfs", "/dev", "tmpfs", 0, "mode=755"); err != nil {
			fmt.Fprintf(os.Stderr, "crunshim: tmpfs mount on /dev failed: %v\n", err)
			return
		}
	}
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		if err := mknod("/dev/ptmx", 5, 2); err != nil {
			fmt.Fprintf(os.Stderr, "crunshim: mknod /dev/ptmx: %v\n", err)
		}
	}
	if _, err := os.Stat("/dev/pts"); err != nil {
		_ = syscall.Mkdir("/dev/pts", 0o755)
	}
	// kr/pty resolves the slave to /dev/pts/N — devpts must be mounted.
	if err := syscall.Mount("devpts", "/dev/pts", "devpts", 0, "mode=620,ptmxmode=666"); err != nil {
		fmt.Fprintf(os.Stderr, "crunshim: devpts mount: %v\n", err)
	}
}

func mknod(path string, major, minor uint32) error {
	dev := int((major << 8) | minor) // valid for majors < 4096, minors < 256
	return syscall.Mknod(path, syscall.S_IFCHR|0o620, dev)
}
