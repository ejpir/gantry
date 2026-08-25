package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const guestInstallDir = "/run/gantry/bin"

// runInstallSelf copies the currently executing, host-verified helper from its
// read-only live share into the trusted per-boot runtime directory. The mode is
// invoked only by the daemon in a root session; keeping the destination fixed
// prevents it from becoming a general privileged file-copy primitive.
func runInstallSelf(args []string) int {
	if len(args) != 0 {
		return 2
	}
	self, err := os.Executable()
	if err == nil {
		err = installSelfFrom(self, guestInstallDir)
	}
	if err != nil {
		debugf("install-self: %v", err)
		return 1
	}
	return 0
}

func installSelfFrom(source, destinationDir string) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open self: %w", err)
	}
	defer func() { _ = input.Close() }()

	if err := os.MkdirAll(destinationDir, 0o755); err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	temporary, err := os.CreateTemp(destinationDir, ".gantry-guest-*")
	if err != nil {
		return fmt.Errorf("create temporary helper: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	failed := func(cause error) error {
		_ = temporary.Close()
		return cause
	}
	if err := temporary.Chmod(0o755); err != nil {
		return failed(fmt.Errorf("set helper mode: %w", err))
	}
	if _, err := io.Copy(temporary, input); err != nil {
		return failed(fmt.Errorf("copy helper: %w", err))
	}
	if err := temporary.Sync(); err != nil {
		return failed(fmt.Errorf("sync helper: %w", err))
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close helper: %w", err)
	}

	helperPath := filepath.Join(destinationDir, "gantry-guest")
	if err := os.Rename(temporaryPath, helperPath); err != nil {
		return fmt.Errorf("install helper: %w", err)
	}
	credentialPath := filepath.Join(destinationDir, "credhelper")
	if err := os.Remove(credentialPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("replace credential helper: %w", err)
	}
	if err := os.Link(helperPath, credentialPath); err != nil {
		return fmt.Errorf("link credential helper: %w", err)
	}
	return nil
}
