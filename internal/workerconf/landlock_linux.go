package workerconf

import (
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

// applyPathLandlock installs a deny-by-default Landlock ruleset for filesystem
// operations. readFiles names exact regular files that remain readable; no
// directory subtree is delegated. Existing descriptors remain usable, which
// is the worker capability model: the VMM receives its assets by descriptor,
// the MCP worker receives brokered byte streams, and the network worker needs
// only immutable resolver snapshots in its private root.
func applyPathLandlock(readFiles []string) (int, int, error) {
	cleanPaths := make([]string, 0, len(readFiles))
	seen := make(map[string]struct{}, len(readFiles))
	for _, rawPath := range readFiles {
		path := filepath.Clean(rawPath)
		if !filepath.IsAbs(rawPath) || path != rawPath {
			return 0, 0, fmt.Errorf("read allowance must be a clean absolute path: %q", rawPath)
		}
		if _, duplicate := seen[path]; duplicate {
			continue
		}
		seen[path] = struct{}{}
		cleanPaths = append(cleanPaths, path)
	}

	version, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0,
		unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, 0, fmt.Errorf("query ABI: %w", errno)
	}
	if version < 1 {
		return 0, 0, fmt.Errorf("invalid ABI %d", version)
	}
	abi := int(version)
	allowed := 0

	access := landlockHandledAccess(abi)
	attr := unix.LandlockRulesetAttr{Access_fs: access}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return abi, 0, fmt.Errorf("create ruleset: %w", errno)
	}
	rulesetFD := int(fd)
	defer func() { _ = unix.Close(rulesetFD) }()

	for _, path := range cleanPaths {
		added, err := addLandlockReadFile(rulesetFD, path)
		if err != nil {
			return abi, allowed, err
		}
		if added {
			allowed++
		}
	}

	// landlock_restrict_self requires no_new_privs for an unprivileged worker.
	// The later seccomp installer repeats this idempotent operation.
	if _, _, errno := unix.RawSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return abi, allowed, fmt.Errorf("no_new_privs: %w", errno)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return abi, allowed, fmt.Errorf("restrict self: %w", errno)
	}
	return abi, allowed, nil
}

func landlockHandledAccess(abi int) uint64 {
	access := uint64(
		unix.LANDLOCK_ACCESS_FS_EXECUTE |
			unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
			unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
			unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
			unix.LANDLOCK_ACCESS_FS_MAKE_REG |
			unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
			unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		access |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		access |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	// ABI 5 added device-ioctl mediation. Workers receive no ambient device
	// paths; handling it also prevents future accidental descriptor inheritance
	// from becoming ambient authority.
	if abi >= 5 {
		access |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return access
}

// addLandlockReadFile adds one exact-file read allowance. Missing optional
// resolver snapshots are skipped: the private-root copy step uses the same
// semantics, and creating a rule for a broader parent would grant more than
// the role requested.
func addLandlockReadFile(rulesetFD int, path string) (bool, error) {
	pathFD, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("open read allowance %q: %w", path, err)
	}
	defer func() { _ = unix.Close(pathFD) }()

	var stat unix.Stat_t
	if err := unix.Fstat(pathFD, &stat); err != nil {
		return false, fmt.Errorf("stat read allowance %q: %w", path, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return false, fmt.Errorf("read allowance %q is not a regular file", path)
	}

	rule := unix.LandlockPathBeneathAttr{
		Allowed_access: unix.LANDLOCK_ACCESS_FS_READ_FILE,
		Parent_fd:      int32(pathFD),
	}
	_, _, errno := unix.Syscall6(
		unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFD),
		uintptr(unix.LANDLOCK_RULE_PATH_BENEATH),
		uintptr(unsafe.Pointer(&rule)),
		0, 0, 0,
	)
	if errno != 0 {
		return false, fmt.Errorf("allow read file %q: %w", path, errno)
	}
	return true, nil
}
