package workerconf

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Apply confines the current (worker) process, strongest tier first:
//
//  1. mount tier — private tmpfs root via pivot_root (needs
//     CAP_SYS_ADMIN, provided by the supervisor spawning us with
//     CLONE_NEWUSER|CLONE_NEWNS; absent on AppArmor-restricted hosts or
//     a plain spawn, in which case the seccomp tier still applies);
//  2. descriptor tier — every unjustified live descriptor is closed;
//  3. no_new_privs + seccomp-bpf whitelist (TSYNC across all threads).
//
// A tier that fails is recorded in the report and the next tier still
// installs; Verify then reports the honest per-property outcome. An
// error is returned only when NO tier could be installed.
func Apply(spec Spec) (*Report, error) {
	if !validProfile(spec.Profile) {
		return nil, fmt.Errorf("workerconf: invalid syscall profile %d", spec.Profile)
	}
	rep := &Report{Platform: "linux"}

	// The close tier's keep set is computed FIRST: /proc/self/fd (the
	// only way to discover the runtime's anon fds) vanishes when the
	// mount tier pivots the root.
	keep, openFDs, fdSurveyErr := surveyFDs(spec)

	if spec.ConfRoot != "" {
		_, _ = fmt.Fprintf(os.Stderr, "workerconf: mount tier: confineMounts(%s)\n", spec.ConfRoot)
		if err := confineMounts(spec); err != nil {
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
	if fdSurveyErr != nil {
		rep.Notes = append(rep.Notes, "close tier unavailable: "+fdSurveyErr.Error())
		rep.Results = append(rep.Results, PropertyResult{
			Property: PropFDTable,
			State:    StateIndeterminate,
			Detail:   fdSurveyErr.Error(),
		})
	} else if err := closeExcept(keep, openFDs); err != nil {
		rep.Notes = append(rep.Notes, "close tier: "+err.Error())
		rep.Results = append(rep.Results, PropertyResult{
			Property: PropFDTable,
			State:    StateUnenforced,
			Detail:   err.Error(),
		})
	} else {
		rep.Applied = true
		rep.Notes = append(rep.Notes, fmt.Sprintf("close tier: unjustified fds closed (kept %d)", len(keep)))
		rep.Results = append(rep.Results, PropertyResult{
			Property: PropFDTable,
			State:    StateEnforced,
			Detail:   fmt.Sprintf("unjustified descriptors closed; %d justified descriptors retained", len(keep)),
		})
	}

	// CLONE_NEWPID is installed together with a fresh user namespace by the
	// supervisor, making the worker PID 1. RLIMIT_NPROC is then scoped to that
	// namespace's uid accounting instead of the daemon user's global process
	// count. Namespace-less auto fallback cannot make that claim and degrades
	// honestly rather than applying a noisy per-host-UID limit.
	if spec.MaxTasks > 0 {
		if os.Getpid() != 1 {
			rep.Notes = append(rep.Notes, "task tier unavailable: worker has no dedicated PID/user namespace")
		} else if err := setTaskLimit(spec.MaxTasks); err != nil {
			rep.Notes = append(rep.Notes, "task tier unavailable: "+err.Error())
		} else {
			rep.Applied = true
			rep.Notes = append(rep.Notes, fmt.Sprintf("task tier: RLIMIT_NPROC=%d", spec.MaxTasks))
		}
	}
	// The mount setup needed CAP_SYS_ADMIN inside the private user namespace.
	// Nothing after this point does. Dropping every effective/permitted cap is
	// also what makes RLIMIT_NPROC enforceable for namespace uid 0.
	if err := dropCapabilities(); err != nil {
		rep.Notes = append(rep.Notes, "capability drop unavailable: "+err.Error())
	} else {
		rep.Notes = append(rep.Notes, "capability tier: effective and permitted sets empty")
	}
	if spec.MaxTasks > 0 {
		// capget is intentionally absent from the final filter: it accepts a
		// PID hidden behind a user pointer and cannot be restricted to self by
		// seccomp. Capture the verified result now, after capset and rlimit but
		// before installing the filter; Verify preserves it below.
		rep.Results = append(rep.Results, probeTaskLimit(spec.MaxTasks))
	}

	_, _ = fmt.Fprintln(os.Stderr, "workerconf: installing seccomp filter")
	if err := installSeccompFor(spec); err != nil {
		rep.Notes = append(rep.Notes, "seccomp tier unavailable: "+err.Error())
		rep.Results = append(rep.Results, PropertyResult{
			Property: PropSyscall,
			State:    StateUnenforced,
			Detail:   err.Error(),
		})
	} else {
		_, _ = fmt.Fprintln(os.Stderr, "workerconf: seccomp filter installed")
		rep.Applied = true
		rep.Notes = append(rep.Notes, "seccomp tier: syscall whitelist (TSYNC)")
		rep.Results = append(rep.Results, PropertyResult{
			Property: PropSyscall,
			State:    StateEnforced,
			Detail:   "role filter installed with TSYNC",
		})
	}

	if !rep.Applied {
		return rep, fmt.Errorf("workerconf: no confinement tier could be installed")
	}
	return rep, nil
}

func setTaskLimit(max uint64) error {
	limit := &unix.Rlimit{Cur: max, Max: max}
	if err := unix.Setrlimit(unix.RLIMIT_NPROC, limit); err != nil {
		return fmt.Errorf("set RLIMIT_NPROC: %w", err)
	}
	return nil
}

func dropCapabilities() error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	return nil
}

// confineMounts pivots the process into a fresh tmpfs root containing
// an empty /dev and no /proc. The KVM hypervisor fd arrives already
// open through the descriptor table, so no device nodes need binding.
func confineMounts(spec Spec) (retErr error) {
	root := spec.ConfRoot
	// Contain all mount propagation before making anything new.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	if err := unix.Mount("tmpfs", root, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount tmpfs root: %w", err)
	}
	pivoted := false
	defer func() {
		if retErr != nil && !pivoted {
			_ = unix.Unmount(root, unix.MNT_DETACH)
		}
	}()
	for _, path := range spec.ReadFiles {
		if err := copyPrivateConfig(root, path); err != nil {
			return err
		}
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
	pivoted = true
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

const maxPrivateConfigBytes = 256 << 10

// copyPrivateConfig snapshots one small, immutable host configuration file
// into the private root. Missing optional files are harmless; oversized or
// unreadable files fail the mount tier instead of leaving a partially useful
// resolver setup. The tmpfs mount shadows every pre-existing entry below root,
// so a local attacker cannot redirect the destination with a planted symlink.
func copyPrivateConfig(root, path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) || strings.Contains(clean, "\x00") {
		return fmt.Errorf("private config path %q is not an absolute file", path)
	}
	source, err := os.Open(clean)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open private config %s: %w", clean, err)
	}
	defer func() { _ = source.Close() }()
	info, err := source.Stat()
	if err != nil {
		return fmt.Errorf("stat private config %s: %w", clean, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("private config %s is not a regular file", clean)
	}

	data, err := io.ReadAll(io.LimitReader(source, maxPrivateConfigBytes+1))
	if err != nil {
		return fmt.Errorf("read private config %s: %w", clean, err)
	}
	if len(data) > maxPrivateConfigBytes {
		return fmt.Errorf("private config %s exceeds %d bytes", clean, maxPrivateConfigBytes)
	}
	destination := filepath.Join(root, strings.TrimPrefix(clean, string(filepath.Separator)))
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create private config directory: %w", err)
	}
	if err := os.WriteFile(destination, data, 0o444); err != nil {
		return fmt.Errorf("write private config %s: %w", clean, err)
	}
	return nil
}

// surveyFDs computes the descriptors the worker may keep and snapshots every
// currently open descriptor. Closing only unjustified live entries is both
// complete (including descriptors above 4095) and substantially cheaper than
// walking RLIMIT_NOFILE with one close syscall per possible descriptor.
//
// The keep set is the dense inherited table (0..KeepFDs), the live conn dups
// (KeepFDExtra), and kernel-internal runtime plumbing (epoll/eventfd/timerfd
// anon inodes). Apply performs the survey before pivot_root removes /proc.
func surveyFDs(spec Spec) (keep map[int]bool, open []int, retErr error) {
	keep = map[int]bool{}
	for fd := 0; fd <= spec.KeepFDs; fd++ {
		keep[fd] = true
	}
	for _, fd := range spec.KeepFDExtra {
		keep[fd] = true
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return keep, nil, fmt.Errorf("survey /proc/self/fd: %w", err)
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd < 0 {
			continue
		}
		open = append(open, fd)
		link, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil {
			continue
		}
		switch link {
		case "anon_inode:[eventpoll]", "anon_inode:[eventfd]", "anon_inode:[timerfd]":
			keep[fd] = true
		}
	}
	return keep, open, nil
}

// closeExcept closes each unjustified descriptor observed immediately before
// the mount tier. EBADF is harmless: os.ReadDir's own descriptor appears in
// its listing and is closed when the survey returns.
func closeExcept(keep map[int]bool, open []int) error {
	for _, fd := range open {
		if keep[fd] {
			continue
		}
		if err := unix.Close(fd); err != nil && !errors.Is(err, unix.EBADF) {
			return fmt.Errorf("close fd %d: %w", fd, err)
		}
	}
	return nil
}
