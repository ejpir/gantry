//go:build windows

package selfupdate

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const protectedUpdateSDDL = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"

var (
	processElevation = currentProcessElevation
	moveFile         = windows.MoveFileEx
)

// installStaged replaces the running executable in process, leaving no helper
// behind. Windows lets a running image be renamed, so the live executable is
// moved aside and the verified payload takes the freed path immediately.
//
// This deliberately avoids the obvious alternative of handing the swap to a
// detached child that waits for this process to exit. That design needed an
// interpreter launched with a base64-encoded command and a hidden window, and
// under an elevated caller a SYSTEM scheduled task registered under a random
// name and unregistered right after starting. Endpoint protection cannot tell
// that sequence apart from a dropper installing persistence, and Defender's
// static model scores the strings alone: doing the work here removes both the
// behavior and the strings.
func installStaged(staged, target string) error {
	if err := protectStagedUpdate(staged); err != nil {
		return err
	}
	retired, err := retiredPath(target)
	if err != nil {
		return err
	}
	// Renaming the image this process is executing from is safe: the open
	// section keeps running against the renamed file, and the rename only
	// frees the target path so the replacement can take it.
	if err := moveFilePath(target, retired, windows.MOVEFILE_REPLACE_EXISTING); err != nil {
		return fmt.Errorf("move running Gantry executable aside: %w", err)
	}
	if err := moveFilePath(staged, target,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		// Never leave the installation with no executable at target.
		if restore := moveFilePath(retired, target, windows.MOVEFILE_REPLACE_EXISTING); restore != nil {
			return fmt.Errorf("install Gantry executable %s: %w (restoring %s failed: %v)",
				target, err, retired, restore)
		}
		return fmt.Errorf("install Gantry executable %s: %w", target, err)
	}
	discardRetired(retired)
	return nil
}

// retiredPath names the replaced executable. The random suffix keeps repeated
// updates and a leftover from an earlier one from colliding, and the leading
// dot matches how stageBinary names its own sibling temporaries.
func retiredPath(target string) (string, error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("name replaced Gantry executable: %w", err)
	}
	return filepath.Join(filepath.Dir(target),
		"."+filepath.Base(target)+".old-"+hex.EncodeToString(suffix[:])), nil
}

// discardRetired removes the replaced executable. This process still has the
// image mapped, so the unlink normally fails until exit; scheduling it for the
// next boot is a best effort that needs privileges the caller may not hold. A
// leftover sibling is harmless either way — it never shadows target.
func discardRetired(retired string) {
	if os.Remove(retired) == nil {
		return
	}
	_ = moveFilePath(retired, "", windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}

// moveFilePath wraps MoveFileEx in path handling. An empty destination is the
// documented way to spell "delete" for MOVEFILE_DELAY_UNTIL_REBOOT.
func moveFilePath(from, to string, flags uint32) error {
	source, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return fmt.Errorf("invalid path %q: %w", from, err)
	}
	var destination *uint16
	if to != "" {
		if destination, err = windows.UTF16PtrFromString(to); err != nil {
			return fmt.Errorf("invalid path %q: %w", to, err)
		}
	}
	return moveFile(source, destination, flags)
}

func currentProcessElevation() (bool, error) {
	var elevated uint32
	var outputSize uint32
	err := windows.GetTokenInformation(
		windows.GetCurrentProcessToken(),
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevated)),
		uint32(unsafe.Sizeof(elevated)),
		&outputSize,
	)
	if err != nil {
		return false, fmt.Errorf("query process elevation: %w", err)
	}
	if outputSize != uint32(unsafe.Sizeof(elevated)) {
		return false, fmt.Errorf("query process elevation: unexpected result size %d", outputSize)
	}
	return elevated != 0, nil
}

// protectStagedUpdate closes the window between verifying the payload and
// moving it into place. stageBinary writes the staged file next to target,
// which can be a directory a lesser-privileged user may write to; when this
// process is elevated, the file gets an Administrators owner and a protected
// SYSTEM/Administrators-only DACL so nothing can swap its contents after the
// checksum check. Unelevated installs keep their user-owned ACL so the same
// user can still finish the update.
func protectStagedUpdate(staged string) error {
	elevated, err := processElevation()
	if err != nil {
		return err
	}
	if !elevated {
		return nil
	}
	descriptor, err := windows.SecurityDescriptorFromString(protectedUpdateSDDL)
	if err != nil {
		return fmt.Errorf("build protected update permissions: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read protected update owner: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read protected update permissions: %w", err)
	}
	securityInformation := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION |
		windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(
		staged, windows.SE_FILE_OBJECT, securityInformation, owner, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("protect elevated staged update: %w", err)
	}
	return nil
}
