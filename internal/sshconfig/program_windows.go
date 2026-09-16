//go:build windows

package sshconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// OpenSSHProgram resolves the native Windows OpenSSH client explicitly. Git's
// MSYS OpenSSH can precede it in PATH but interprets absolute helper paths in a
// different namespace, making one managed KnownHostsCommand invalid for the
// other implementation.
func OpenSSHProgram(name string) (string, error) {
	if name != "ssh" && name != "sftp" {
		return "", fmt.Errorf("unsupported OpenSSH program %q", name)
	}
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return "", fmt.Errorf("locate native Windows OpenSSH: %w", err)
	}
	path := filepath.Join(systemDirectory, "OpenSSH", name+".exe")
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("native Windows OpenSSH %s is required: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("native Windows OpenSSH %s is not a regular file", path)
	}
	return path, nil
}
