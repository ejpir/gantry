//go:build !windows

package sshconfig

import "os/exec"

// OpenSSHProgram resolves an OpenSSH client program for the host platform.
func OpenSSHProgram(name string) (string, error) { return exec.LookPath(name) }
