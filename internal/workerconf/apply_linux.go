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

	if spec.ConfRoot != "" {
		if err := confineMounts(spec.ConfRoot); err != nil {
			rep.Notes = append(rep.Notes, "mount tier unavailable: "+err.Error())
		} else {
			rep.Applied = true
			rep.Notes = append(rep.Notes, "mount tier: private tmpfs root (no /proc, empty /dev)")
		}
	} else {
		rep.Notes = append(rep.Notes, "mount tier skipped: no ConfRoot")
	}

	if err := closeFrom(spec.KeepFDs + 1); err != nil {
		rep.Notes = append(rep.Notes, "close_range: "+err.Error())
	} else {
		rep.Applied = true
	}

	if err := installSeccomp(); err != nil {
		rep.Notes = append(rep.Notes, "seccomp tier unavailable: "+err.Error())
	} else {
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

// closeFrom closes every descriptor >= first. The worker's descriptor
// table is dense (0..KeepFDs), so one close_range covers all strays;
// kernels without close_range(2) (<5.9) get a bounded fallback loop.
func closeFrom(first int) error {
	_, _, errno := unix.RawSyscall(unix.SYS_CLOSE_RANGE, uintptr(first), ^uintptr(0), 0)
	switch errno {
	case 0:
		return nil
	case unix.ENOSYS:
		for fd := first; fd < 4096; fd++ {
			_ = unix.Close(fd) // EBADF on gaps is expected
		}
		return nil
	default:
		return fmt.Errorf("close_range: %w", errno)
	}
}
