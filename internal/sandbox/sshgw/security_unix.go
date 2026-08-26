//go:build !windows

package sshgw

import (
	"os"

	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

func secureSSHStateDir(path string) error    { return localsec.CreateManagerDir(path) }
func secureSSHPrivateFile(path string) error { return os.Chmod(path, 0o600) }
