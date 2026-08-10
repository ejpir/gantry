//go:build !windows

package sandbox

import "os"

func createSandboxDirectory(path string) error {
	return os.MkdirAll(path, 0o700)
}

func secureSandboxDirectory(path string) error {
	return os.Chmod(path, 0o700)
}

func secureLocalEndpoint(path string) error {
	return os.Chmod(path, 0o600)
}
