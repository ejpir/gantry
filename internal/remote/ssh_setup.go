package remote

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/sshgw"
	"github.com/ejpir/gantry/internal/sshconfig"
)

// SetupSSH installs one remote block before the broad *.gantry block. It
// performs no network calls; KnownHostsCommand pins the key on first use.
func SetupSSH(target string, remove bool) error {
	if err := layout.ValidateName(target); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	knownHostsHelper, err := sshconfig.OpenSSHCommandPath(self)
	if err != nil {
		return err
	}
	begin, end := "# >>> gantry remote "+target, "# <<< gantry remote "+target
	block := strings.Join([]string{
		begin,
		"Host *." + target + ".gantry",
		"    User " + sshgw.DefaultUserSentinel,
		"    ProxyCommand " + sshconfig.ShellCommand(self, "ssh-proxy", "-remote", target, "%n"),
		"    KnownHostsCommand " + sshconfig.ArgvCommand(knownHostsHelper, "ssh-known-hosts", "-remote", target, "%n"),
		"    UserKnownHostsFile " + sshconfig.QuotePath(remoteKnownHostsPath(target)),
		"    GlobalKnownHostsFile none",
		"    StrictHostKeyChecking yes",
		end,
	}, "\n")
	return sshconfig.Apply(filepath.Join(baseDir(), "ssh"), begin, end, block, remove, true)
}
