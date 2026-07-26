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
