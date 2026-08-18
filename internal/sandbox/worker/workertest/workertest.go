//go:build linux || darwin

// Package workertest holds the assertions a re-exec'd worker makes about
// itself from inside the child process. Every worker role must satisfy them
// identically, and each role's tests drive its own helper process, so the
// checks live here rather than being copied into each test binary.
package workertest

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// AssertStdinUnreadable checks the confinement property every re-exec'd worker
// must hold: stdin is closed, and the diagnostic fds are pipes rather than
// regular files the worker could truncate or grow. It runs inside the child,
// so a violation exits with a distinct status the parent test reports.
func AssertStdinUnreadable() {
	if os.Getenv("GANTRY_TEST_WORKER_STDIN_UNREADABLE") != "1" {
		return
	}
	var one [1]byte
	if n, err := syscall.Read(0, one[:]); !errors.Is(err, syscall.EBADF) {
		_, _ = fmt.Fprintf(os.Stderr, "worker stdin is readable: read=%d err=%v\n", n, err)
		os.Exit(97)
	}
	for _, fd := range []int{1, 2} {
		var stat syscall.Stat_t
		if err := syscall.Fstat(fd, &stat); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "worker diagnostic fd %d stat: %v\n", fd, err)
			os.Exit(98)
		}
		if stat.Mode&syscall.S_IFMT == syscall.S_IFREG {
			_, _ = fmt.Fprintf(os.Stderr, "worker diagnostic fd %d is a regular file\n", fd)
			os.Exit(99)
		}
		if err := syscall.Ftruncate(fd, 1<<30); err == nil {
			_, _ = fmt.Fprintf(os.Stderr, "worker diagnostic fd %d accepted ftruncate\n", fd)
			os.Exit(100)
		}
	}
}
