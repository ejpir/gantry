//go:build !windows

package sshconfig

// OpenSSHCommandPath returns an executable path suitable for an OpenSSH
// direct-command directive such as KnownHostsCommand.
func OpenSSHCommandPath(path string) (string, error) { return path, nil }
