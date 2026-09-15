package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ejpir/gantry/internal/remote"
	"github.com/ejpir/gantry/internal/sandbox/sshgw"
	"github.com/ejpir/gantry/internal/sshconfig"
)

const (
	sshConfigBegin = "# >>> gantry sandboxes"
	sshConfigEnd   = "# <<< gantry sandboxes"
)

var openSSHVersionRE = regexp.MustCompile(`OpenSSH(?:_for_Windows)?_([0-9]+)\.([0-9]+)`)

func managedSSHBlock(self string) string {
	return strings.Join([]string{
		sshConfigBegin,
		"Host *.gantry",
		"    User " + sshgw.DefaultUserSentinel,
		// Use the original alias, not a HostName override.
		"    ProxyCommand " + shellCommand(self, "ssh-proxy", "%n"),
		"    KnownHostsCommand " + knownHostsCommand(self, "ssh-known-hosts"),
		"    UserKnownHostsFile " + quoteSSHConfigPath(filepath.Join(sshInstallDir(), "known_hosts")),
		"    StrictHostKeyChecking accept-new",
		sshConfigEnd,
	}, "\n")
}

func updateManagedSSHBlock(content, block string, remove bool) (string, error) {
	return sshconfig.Update(content, sshConfigBegin, sshConfigEnd, block, remove, false)
}

func sshSetup(remove bool) error {
	if !remove {
		supported, version, err := sshSupportsKnownHostsCommand()
		if err != nil {
			return err
		}
		if !supported {
			return fmt.Errorf("OpenSSH %s does not support KnownHostsCommand; version 8.4 or newer is required", version)
		}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := sshconfig.Apply(sshInstallDir(), sshConfigBegin, sshConfigEnd, managedSSHBlock(self), remove, false); err != nil {
		return err
	}
	if err := ensureSSHKnownHostsFile(); err != nil {
		return err
	}
	profiles, err := remote.List()
	if err != nil {
		return err
	}
	for _, profile := range profiles {
		// Offline-safe: first use fetches and pins the key over authenticated
		// TLS. Each remote block is prepended ahead of the broad local one.
		if err := remote.SetupSSH(profile.Name, remove); err != nil {
			return err
		}
	}
	return nil
}

func sshSupportsKnownHostsCommand() (bool, string, error) {
	output, err := exec.Command("ssh", "-V").CombinedOutput()
	if err != nil {
		return false, "", fmt.Errorf("run ssh -V: %w", err)
	}
	match := openSSHVersionRE.FindStringSubmatch(string(output))
	if len(match) != 3 {
		return false, strings.TrimSpace(string(output)), fmt.Errorf("cannot determine OpenSSH version from %q", strings.TrimSpace(string(output)))
	}
	var major, minor int
	_, _ = fmt.Sscanf(match[1]+"."+match[2], "%d.%d", &major, &minor)
	return major > 8 || (major == 8 && minor >= 4), match[1] + "." + match[2], nil
}
