//go:build windows

package sshconfig

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// OpenSSHCommandPath returns an unquoted absolute executable token for Win32
// OpenSSH. Its KnownHostsCommand rejects quoted executable paths containing
// spaces as non-absolute, so use the file's DOS short path when necessary.
func OpenSSHCommandPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if !strings.ContainsAny(absolute, " \t\"'") {
		return filepath.ToSlash(absolute), nil
	}
	longPath, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return "", err
	}
	size, err := windows.GetShortPathName(longPath, nil, 0)
	if err != nil {
		return "", fmt.Errorf("resolve short executable path for Win32 OpenSSH: %w", err)
	}
	if size == 0 {
		return "", fmt.Errorf("resolve short executable path for Win32 OpenSSH: empty result")
	}
	buffer := make([]uint16, size)
	written, err := windows.GetShortPathName(longPath, &buffer[0], uint32(len(buffer)))
	if err != nil {
		return "", fmt.Errorf("resolve short executable path for Win32 OpenSSH: %w", err)
	}
	if written == 0 || written >= uint32(len(buffer)) {
		return "", fmt.Errorf("resolve short executable path for Win32 OpenSSH: invalid result")
	}
	shortPath := windows.UTF16ToString(buffer[:written])
	if strings.ContainsAny(shortPath, " \t\"'") {
		return "", fmt.Errorf("Win32 OpenSSH requires Gantry at a path without spaces; install it outside %q", filepath.Dir(absolute))
	}
	return filepath.ToSlash(shortPath), nil
}
