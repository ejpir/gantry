package workerconf

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Apply confines the current (worker) process, strongest tier first:
//
//  1. mount tier — private tmpfs root via pivot_root (needs
//     CAP_SYS_ADMIN, provided by the supervisor spawning us with
//     CLONE_NEWUSER|CLONE_NEWNS; absent on AppArmor-restricted hosts or
//     a plain spawn, in which case the seccomp tier still applies);
//  2. close_range — everything above the dense fd table dies;
//  3. no_new_privs + seccomp-bpf whitelist (TSYNC across all threads).
//
// A tier that fails is recorded in the report and the next tier still
// installs; Verify then reports the honest per-property outcome. An
// error is returned only when NO tier could be installed.
func Apply(spec Spec) (*Report, error) {
	rep := &Report{Platform: "linux"}

	// The close tier's keep set is computed FIRST: /proc/self/fd (the
	// only way to discover the runtime's anon fds) vanishes when the
	// mount tier pivots the root.
	keep := fdKeepSet(spec)

	if spec.ConfRoot != "" {
		_, _ = fmt.Fprintf(os.Stderr, "workerconf: mount tier: confineMounts(%s)\n", spec.ConfRoot)
		if err := confineMounts(spec.ConfRoot); err != nil {
			rep.Notes = append(rep.Notes, "mount tier unavailable: "+err.Error())
		} else {
			rep.Applied = true
			rep.Notes = append(rep.Notes, "mount tier: private tmpfs root (no /proc, empty /dev)")
		}
	} else {
		rep.Notes = append(rep.Notes, "mount tier skipped: no ConfRoot")
	}

	// The close tier kills every fd the worker cannot justify. The
	// keep set is the dense table (0..KeepFDs), the live conn dups
	// (KeepFDExtra), and kernel-internal runtime plumbing
	// (epoll/eventfd/timerfd anon inodes).
	if err := closeExcept(keep); err != nil {
		rep.Notes = append(rep.Notes, "close tier: "+err.Error())
	} else {
		rep.Applied = true
		rep.Notes = append(rep.Notes, fmt.Sprintf("close tier: unjustified fds closed (kept %d)", len(keep)))
	}

	_, _ = fmt.Fprintln(os.Stderr, "workerconf: installing seccomp filter")
	if err := installSeccomp(); err != nil {
		rep.Notes = append(rep.Notes, "seccomp tier unavailable: "+err.Error())
	} else {
		_, _ = fmt.Fprintln(os.Stderr, "workerconf: seccomp filter installed")
		rep.Applied = true
		rep.Notes = append(rep.Notes, "seccomp tier: syscall whitelist (TSYNC)")
	}

	if !rep.Applied {
		return rep, fmt.Errorf("workerconf: no confinement tier could be installed")
	}
	return rep, nil
}

// confineMounts pivots the process into a fresh tmpfs root containing
// an empty /dev and no /proc. The KVM hypervisor fd arrives already
// open through the descriptor table, so no device nodes need binding.
func confineMounts(root string) error {
	// Contain all mount propagation before making anything new.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	if err := unix.Mount("tmpfs", root, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return fmt.Errorf("mount tmpfs root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "dev"), 0o755); err != nil {
		return err
	}
	old := filepath.Join(root, "old")
	if err := os.MkdirAll(old, 0o755); err != nil {
		return err
	}
	if err := unix.PivotRoot(root, old); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	if err := unix.Unmount("/old", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %w", err)
	}
	if err := os.Remove("/old"); err != nil {
		return fmt.Errorf("remove old root mountpoint: %w", err)
	}
	return nil
}

// fdKeepSet computes the descriptors the worker may keep: the dense
// inherited table (0..KeepFDs), the live conn dups (KeepFDExtra), and
// kernel-internal runtime plumbing (epoll/eventfd/timerfd anon inodes,
// discovered via /proc/self/fd — closing the Go runtime's poller fd
// would silently break its netpoll-driven channel I/O).
func fdKeepSet(spec Spec) map[int]bool {
	keep := map[int]bool{}
	for fd := 0; fd <= spec.KeepFDs; fd++ {
		keep[fd] = true
	}
	for _, fd := range spec.KeepFDExtra {
		keep[fd] = true
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "workerconf: /proc/self/fd survey unavailable: %v\n", err)
		return keep
	}
	for _, e := range entries {
		link, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil {
			continue
		}
		switch link {
		case "anon_inode:[eventpoll]", "anon_inode:[eventfd]", "anon_inode:[timerfd]":
			var fd int
			if _, err := fmt.Sscanf(e.Name(), "%d", &fd); err == nil {
				keep[fd] = true
			}
		}
	}
	return keep
}

// closeExcept closes every descriptor outside the keep set (bounded
// loop; close_range(2) has no exclusion mechanism). EBADF on gaps is
// expected.
func closeExcept(keep map[int]bool) error {
	for fd := 0; fd < 4096; fd++ {
		if !keep[fd] {
			_ = unix.Close(fd)
		}
	}
	return nil
}
