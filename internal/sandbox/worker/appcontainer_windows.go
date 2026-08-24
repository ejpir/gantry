package worker

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsWorkerNoNetworkAppContainerName = "Gantry.Worker.NoNetwork.v1"
	windowsWorkerNetworkAppContainerName   = "Gantry.Worker.Network.v1"
)

// Well-known Windows capability SIDs. The network worker is itself the
// egress-policy enforcement point and therefore needs ordinary stream and
// datagram authority. Filesystem and process authority remain absent.
var windowsNetworkCapabilitySIDs = []string{
	"S-1-15-3-1", // internetClient
	"S-1-15-3-2", // internetClientServer
	"S-1-15-3-3", // privateNetworkClientServer
}

const hresultAlreadyExists = 0x800700b7

var (
	createAppContainerProfileProc = windows.NewLazySystemDLL("userenv.dll").NewProc("CreateAppContainerProfile")
	deriveAppContainerSIDProc     = windows.NewLazySystemDLL("userenv.dll").NewProc("DeriveAppContainerSidFromAppContainerName")
)

type windowsAppContainerProfile struct {
	sid          *windows.SID
	capabilities []windows.SIDAndAttributes
	// capabilitySIDs retains the Go allocations referenced by capabilities.
	capabilitySIDs []*windows.SID
}

func openWindowsWorkerAppContainer(network bool) (*windowsAppContainerProfile, error) {
	profileName := windowsWorkerNoNetworkAppContainerName
	descriptionText := "Zero-capability identity for Gantry worker processes"
	if network {
		profileName = windowsWorkerNetworkAppContainerName
		descriptionText = "Network-capable identity for Gantry's confined network worker"
	}
	name, err := windows.UTF16PtrFromString(profileName)
	if err != nil {
		return nil, fmt.Errorf("encode AppContainer name: %w", err)
	}
	displayName, err := windows.UTF16PtrFromString("Gantry confined worker")
	if err != nil {
		return nil, fmt.Errorf("encode AppContainer display name: %w", err)
	}
	description, err := windows.UTF16PtrFromString(descriptionText)
	if err != nil {
		return nil, fmt.Errorf("encode AppContainer description: %w", err)
	}
	capabilities, capabilitySIDs, err := windowsAppContainerCapabilities(network)
	if err != nil {
		return nil, err
	}
	var capabilityPointer uintptr
	if len(capabilities) != 0 {
		capabilityPointer = uintptr(unsafe.Pointer(&capabilities[0]))
	}

	var sid *windows.SID
	hresult, _, _ := createAppContainerProfileProc.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(displayName)),
		uintptr(unsafe.Pointer(description)),
		capabilityPointer,
		uintptr(len(capabilities)),
		uintptr(unsafe.Pointer(&sid)),
	)
	runtime.KeepAlive(capabilities)
	runtime.KeepAlive(capabilitySIDs)
	switch code := uint32(hresult); code {
	case 0:
		if sid == nil {
			return nil, fmt.Errorf("CreateAppContainerProfile returned a nil SID")
		}
		return &windowsAppContainerProfile{
			sid: sid, capabilities: capabilities, capabilitySIDs: capabilitySIDs,
		}, nil
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
	return &windowsAppContainerProfile{
		sid: sid, capabilities: capabilities, capabilitySIDs: capabilitySIDs,
	}, nil
}

func windowsAppContainerCapabilities(network bool) ([]windows.SIDAndAttributes, []*windows.SID, error) {
	if !network {
		return nil, nil, nil
	}
	attributes := make([]windows.SIDAndAttributes, 0, len(windowsNetworkCapabilitySIDs))
	sids := make([]*windows.SID, 0, len(windowsNetworkCapabilitySIDs))
	for _, text := range windowsNetworkCapabilitySIDs {
		sid, err := windows.StringToSid(text)
		if err != nil {
			return nil, nil, fmt.Errorf("derive AppContainer capability %s: %w", text, err)
		}
		sids = append(sids, sid)
		attributes = append(attributes, windows.SIDAndAttributes{
			Sid: sid, Attributes: windows.SE_GROUP_ENABLED,
		})
	}
	return attributes, sids, nil
}

func (profile *windowsAppContainerProfile) Close() error {
	if profile == nil || profile.sid == nil {
		return nil
	}
	err := windows.FreeSid(profile.sid)
	profile.sid = nil
	return err
}

func grantWindowsWorkerExecutableAccess(path string, sid *windows.SID) error {
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
