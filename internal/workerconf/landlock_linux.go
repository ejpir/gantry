package workerconf

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// applyMCPPathLandlock installs a deny-all Landlock ruleset for filesystem
// operations. ProfileMCP needs no paths after the TLS roots and bootstrap have
// been consumed: all useful data arrives on already-open broker channels.
// Existing descriptors remain usable, which is exactly the capability model.
func applyMCPPathLandlock() (int, error) {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0,
		unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, fmt.Errorf("query ABI: %w", errno)
	}
	if abi < 1 {
		return 0, fmt.Errorf("invalid ABI %d", abi)
	}

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
	// ABI 5 added device-ioctl mediation. ProfileMCP does not receive device
	// descriptors, but handling it prevents a future accidental inheritance
	// from becoming ambient authority.
	if abi >= 5 {
		access |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}

	attr := unix.LandlockRulesetAttr{Access_fs: access}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return int(abi), fmt.Errorf("create ruleset: %w", errno)
	}
	defer func() { _ = unix.Close(int(fd)) }()

	// landlock_restrict_self requires no_new_privs for an unprivileged worker.
	// The later seccomp installer repeats this idempotent operation.
	if _, _, errno := unix.RawSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return int(abi), fmt.Errorf("no_new_privs: %w", errno)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return int(abi), fmt.Errorf("restrict self: %w", errno)
	}
	return int(abi), nil
}
