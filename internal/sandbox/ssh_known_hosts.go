package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/sandbox/sshgw"
)

// CmdSSHKnownHosts implements OpenSSH KnownHostsCommand.
func CmdSSHKnownHosts(argv []string) int {
	if len(argv) > 1 {
		fmt.Fprintln(os.Stderr, "usage: gantry ssh-known-hosts [HOST]")
		return 2
	}
	host := "*.gantry"
	if len(argv) == 1 {
		host = argv[0]
		if _, err := normalizeSSHHost(host); err != nil {
			fmt.Fprintln(os.Stderr, "gantry ssh-known-hosts:", err)
			return 2
		}
	}
	line, err := sshgw.KnownHostsLine(sshHostKeyPath(), host)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh-known-hosts:", err)
		return 1
	}
	fmt.Println(line)
	return 0
}

func sshShellQuote(value string) string {
	if runtime.GOOS == "windows" {
		return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func shellCommand(argv ...string) string {
	quoted := make([]string, len(argv))
	for index, value := range argv {
		// OpenSSH expands tokens such as %h before handing ProxyCommand and
		// KnownHostsCommand to the user's shell. Keep the token inside shell
		// quotes so a HostName override cannot become shell syntax first.
		quoted[index] = sshShellQuote(value)
	}
	return strings.Join(quoted, " ")
}

func quoteSSHConfigPath(path string) string {
	return `"` + strings.ReplaceAll(path, `\`, `\\`) + `"`
}

func ensureSSHKnownHostsFile() error {
	if err := localsec.CreateManagerDir(sshInstallDir()); err != nil {
		return err
	}
	path := filepath.Join(sshInstallDir(), "known_hosts")
	for {
		info, err := os.Lstat(path)
		if err == nil {
			// Reject links and special files before OpenFile or Chmod can follow
			// them and mutate an attacker-selected target.
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return fmt.Errorf("%q is not a real regular file", path)
			}
			if err := localsec.SecureRegularFile(path); err != nil {
				return err
			}
			return os.Chmod(path, 0o600)
		}
		if !os.IsNotExist(err) {
			return err
		}
		// O_EXCL turns a symlink planted after Lstat into EEXIST rather than
		// following it. Retry so the new object is validated without side effects.
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
}
