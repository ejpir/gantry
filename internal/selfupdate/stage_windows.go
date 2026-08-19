//go:build windows

package selfupdate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const stagedNameAttempts = 100

var processElevation = currentProcessElevation

// createStagedFile applies the elevated file's protected DACL in CREATE_NEW,
// rather than exposing a default-permission name and tightening it later. Its
// open handle denies share-write and share-delete while download, hashing, and
// platform validation run. The DACL continues that protection after close and
// until ReplaceFileW exclusively opens the verified payload.
func createStagedFile(target string) (*os.File, error) {
	elevated, err := processElevation()
	if err != nil {
		return nil, err
	}
	var descriptor *windows.SECURITY_DESCRIPTOR
	if elevated {
		descriptor, err = protectedStagedDescriptor()
		if err != nil {
			return nil, err
		}
	}
	var attributes *windows.SecurityAttributes
	if descriptor != nil {
		attributes = &windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: descriptor,
		}
	}
	for range stagedNameAttempts {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, fmt.Errorf("name staged Gantry executable: %w", err)
		}
		path := filepath.Join(filepath.Dir(target),
			"."+filepath.Base(target)+".update-"+hex.EncodeToString(suffix[:]))
		path16, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, fmt.Errorf("invalid staged path %q: %w", path, err)
		}
		handle, err := windows.CreateFile(
			path16,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ,
			attributes,
			windows.CREATE_NEW,
			windows.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		runtime.KeepAlive(descriptor)
		if err == nil {
			file := os.NewFile(uintptr(handle), path)
			if file == nil {
				_ = windows.CloseHandle(handle)
				return nil, fmt.Errorf("open staged Gantry executable")
			}
			return file, nil
		}
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		return nil, fmt.Errorf("create protected staged update: %w", err)
	}
	return nil, fmt.Errorf("create protected staged update: exhausted unique names")
}

func protectedStagedDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("query staged update owner: %w", err)
	}
	// Keep the creating administrator as owner/access principal so a mocked
	// elevation test and non-UAC administrator accounts remain usable. No
	// inherited or broad host-user ACE is ever present.
	sddl := "O:" + user.User.Sid.String() + "G:" + user.User.Sid.String() +
		"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")"
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build protected update permissions: %w", err)
	}
	return descriptor, nil
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
