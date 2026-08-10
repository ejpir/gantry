//go:build windows

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsFileAllAccess windows.ACCESS_MASK = 0x001f01ff

var trustedWindowsServiceSIDs = [...]string{
	"S-1-5-18",     // LocalSystem.
	"S-1-5-32-544", // Builtin Administrators.
}

// createSandboxDirectory protects the root before creating its child. That
// closes the useful race in which an account allowed by an inherited DACL
// could replace the sandbox directory between creation and hardening.
func createSandboxDirectory(path string) error {
	root := filepath.Dir(filepath.Clean(path))
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		return err
	}
	if err := createPrivateWindowsDirectory(root, false); err != nil {
		return fmt.Errorf("secure sandbox root: %w", err)
	}
	return createPrivateWindowsDirectory(path, true)
}

func secureSandboxDirectory(path string) error {
	root := filepath.Dir(filepath.Clean(path))
	if err := secureWindowsPath(root, true, false); err != nil {
		return fmt.Errorf("secure sandbox root: %w", err)
	}
	return secureWindowsPath(path, true, true)
}

func secureLocalEndpoint(path string) error {
	return secureWindowsPath(path, false, false)
}

// createPrivateWindowsDirectory supplies the DACL to CreateDirectory so a new
// path is never briefly visible with token-default or inherited permissions.
func createPrivateWindowsDirectory(path string, inheritChildren bool) error {
	userSID, err := currentWindowsUserSID()
	if err != nil {
		return err
	}
	descriptor, _, err := privateWindowsDescriptor(userSID, inheritChildren)
	if err != nil {
		return err
	}
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	err = windows.CreateDirectory(path16, attributes)
	runtime.KeepAlive(descriptor)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	return secureWindowsPath(path, true, inheritChildren)
}

// secureWindowsPath replaces inherited permissions with a protected DACL.
// Only the process user, LocalSystem, and Builtin Administrators retain
// access. The descriptor is read back because accepting an inherited or NULL
// DACL here exposes unauthenticated root-shell control to other host users.
func secureWindowsPath(path string, directory, inheritChildren bool) error {
	if err := validateWindowsPath(path, directory); err != nil {
		return err
	}
	userSID, err := currentWindowsUserSID()
	if err != nil {
		return err
	}
	if err := verifyPrivateWindowsPath(path, userSID, inheritChildren); err == nil {
		return nil
	}
	// A path owned by another account remains mutable by that owner even after
	// replacing its DACL. Refuse it instead of manufacturing a false boundary.
	if err := verifyWindowsOwner(path, userSID); err != nil {
		return err
	}

	descriptor, dacl, err := privateWindowsDescriptor(userSID, inheritChildren)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("set private DACL: %w", err)
	}
	runtime.KeepAlive(descriptor)

	if err := verifyPrivateWindowsPath(path, userSID, inheritChildren); err != nil {
		return fmt.Errorf("verify private DACL: %w", err)
	}
	return nil
}

func privateWindowsDescriptor(userSID *windows.SID, inheritChildren bool) (*windows.SECURITY_DESCRIPTOR, *windows.ACL, error) {
	inheritance := ""
	if inheritChildren {
		inheritance = "OICI"
	}
	sddl := fmt.Sprintf(
		"D:P(A;%s;FA;;;%s)(A;%s;FA;;;SY)(A;%s;FA;;;BA)",
		inheritance, userSID.String(), inheritance, inheritance,
	)
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, nil, fmt.Errorf("build private DACL: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return nil, nil, fmt.Errorf("read private DACL: %w", err)
	}
	return descriptor, dacl, nil
}

func validateWindowsPath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if directory && !info.IsDir() {
		return fmt.Errorf("%q is not a directory", path)
	}
	if !directory && info.IsDir() {
		return fmt.Errorf("%q is a directory", path)
	}
	if directory {
		path16, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(path16)
		if err != nil {
			return err
		}
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("refusing reparse-point sandbox directory %q", path)
		}
	}
	return nil
}

func currentWindowsUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("current process user: %w", err)
	}
	sid, err := user.User.Sid.Copy()
	if err != nil {
		return nil, fmt.Errorf("copy current process SID: %w", err)
	}
	return sid, nil
}

func verifyWindowsOwner(path string, want *windows.SID) error {
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read owner: %w", err)
	}
	if descriptor == nil {
		return fmt.Errorf("missing security descriptor")
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read owner SID: %w", err)
	}
	if owner == nil || !owner.Equals(want) {
		return fmt.Errorf("path is not owned by the current user")
	}
	return nil
}

func verifyPrivateWindowsPath(path string, userSID *windows.SID, inheritChildren bool) error {
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	if descriptor == nil {
		return fmt.Errorf("missing security descriptor")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PRESENT == 0 || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("DACL is absent or inherits permissions")
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(userSID) {
		return fmt.Errorf("owner is not the current user")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return fmt.Errorf("NULL DACL grants unrestricted access")
	}

	required := map[string]bool{userSID.String(): false}
	for _, sid := range trustedWindowsServiceSIDs {
		required[sid] = false
	}
	if dacl.AceCount < uint16(len(required)) || dacl.AceCount > 3 {
		return fmt.Errorf("unexpected DACL entry count %d", dacl.AceCount)
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return err
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("DACL entry %d is not an allow entry", index)
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return fmt.Errorf("DACL entry %d is inherited", index)
		}
		wantInheritance := uint8(0)
		if inheritChildren {
			wantInheritance = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
		}
		if ace.Header.AceFlags&windows.VALID_INHERIT_FLAGS != wantInheritance {
			return fmt.Errorf("DACL entry %d has unexpected inheritance flags", index)
		}
		const minimumSIDSize = 8
		if uintptr(ace.Header.AceSize) < unsafe.Offsetof(ace.SidStart)+minimumSIDSize {
			return fmt.Errorf("DACL entry %d has a truncated SID", index)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return fmt.Errorf("DACL entry %d has an invalid SID", index)
		}
		sidString := sid.String()
		if _, ok := required[sidString]; !ok {
			return fmt.Errorf("DACL grants access to untrusted SID %s", sidString)
		}
		if ace.Mask&windowsFileAllAccess != windowsFileAllAccess && ace.Mask&windows.GENERIC_ALL == 0 {
			return fmt.Errorf("DACL entry for %s lacks full control", sidString)
		}
		required[sidString] = true
	}
	for sid, present := range required {
		if !present {
			return fmt.Errorf("DACL is missing trusted SID %s", sid)
		}
	}
	return nil
}
