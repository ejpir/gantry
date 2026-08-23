package worker

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsWorkerAppContainerName = "Gantry.Worker.NoNetwork.v1"

const hresultAlreadyExists = 0x800700b7

var (
	createAppContainerProfileProc = windows.NewLazySystemDLL("userenv.dll").NewProc("CreateAppContainerProfile")
	deriveAppContainerSIDProc     = windows.NewLazySystemDLL("userenv.dll").NewProc("DeriveAppContainerSidFromAppContainerName")
)

type windowsAppContainerProfile struct {
	sid *windows.SID
}

func openWindowsWorkerAppContainer() (*windowsAppContainerProfile, error) {
	name, err := windows.UTF16PtrFromString(windowsWorkerAppContainerName)
	if err != nil {
		return nil, fmt.Errorf("encode AppContainer name: %w", err)
	}
	displayName, err := windows.UTF16PtrFromString("Gantry confined worker")
	if err != nil {
		return nil, fmt.Errorf("encode AppContainer display name: %w", err)
	}
	description, err := windows.UTF16PtrFromString("Zero-capability identity for Gantry worker processes")
	if err != nil {
		return nil, fmt.Errorf("encode AppContainer description: %w", err)
	}

	var sid *windows.SID
	hresult, _, _ := createAppContainerProfileProc.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(displayName)),
		uintptr(unsafe.Pointer(description)),
		0,
		0,
		uintptr(unsafe.Pointer(&sid)),
	)
	switch code := uint32(hresult); code {
	case 0:
		if sid == nil {
			return nil, fmt.Errorf("CreateAppContainerProfile returned a nil SID")
		}
		return &windowsAppContainerProfile{sid: sid}, nil
	case hresultAlreadyExists:
		// Profiles are per-user and persistent. Reusing one stable identity avoids
		// accumulating package profiles on every worker launch.
	default:
		return nil, windowsHRESULT("CreateAppContainerProfile", code)
	}

	hresult, _, _ = deriveAppContainerSIDProc.Call(
		uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&sid)))
	if code := uint32(hresult); code != 0 {
		return nil, windowsHRESULT("DeriveAppContainerSidFromAppContainerName", code)
	}
	if sid == nil {
		return nil, fmt.Errorf("DeriveAppContainerSidFromAppContainerName returned a nil SID")
	}
	return &windowsAppContainerProfile{sid: sid}, nil
}

func (profile *windowsAppContainerProfile) Close() error {
	if profile == nil || profile.sid == nil {
		return nil
	}
	err := windows.FreeSid(profile.sid)
	profile.sid = nil
	return err
}

func grantAppContainerExecutableAccess(path string, sid *windows.SID) error {
	if sid == nil {
		return fmt.Errorf("grant AppContainer executable access: nil SID")
	}
	securityDescriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read executable ACL: %w", err)
	}
	dacl, _, err := securityDescriptor.DACL()
	if err != nil {
		return fmt.Errorf("read executable DACL: %w", err)
	}

	// Grant only read/execute on the current binary to this private profile.
	// The worker still cannot replace the executable, and the one-process Job
	// prevents using this grant to spawn a second copy.
	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
	newDACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry}, dacl)
	if err != nil {
		return fmt.Errorf("build executable AppContainer DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, newDACL, nil); err != nil {
		return fmt.Errorf("grant executable AppContainer access: %w", err)
	}
	runtime.KeepAlive(securityDescriptor)
	runtime.KeepAlive(sid)
	return nil
}

func windowsHRESULT(operation string, code uint32) error {
	if code&0xffff0000 == 0x80070000 {
		return fmt.Errorf("%s: %w (HRESULT %#08x)", operation, windows.Errno(code&0xffff), code)
	}
	return fmt.Errorf("%s: HRESULT %#08x", operation, code)
}
