//go:build windows

package secret

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func openSecretFile(path string) (*os.File, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_SEQUENTIAL_SCAN,
		0,
	)
	if err != nil {
		return nil, err
	}
	fileType, typeErr := windows.GetFileType(handle)
	if typeErr != nil {
		_ = windows.CloseHandle(handle)
		return nil, typeErr
	}
	if fileType != windows.FILE_TYPE_DISK {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("%s is not a regular disk file", path)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("open %s returned an invalid handle", path)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return file, nil
}
