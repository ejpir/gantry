//go:build windows

package sshgw

import "github.com/ejpir/gantry/internal/sandbox/localsec"

func secureSSHStateDir(path string) error    { return localsec.CreateManagerDir(path) }
func secureSSHPrivateFile(path string) error { return localsec.SecureRegularFile(path) }
