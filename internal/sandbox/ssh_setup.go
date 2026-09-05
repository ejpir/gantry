package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/sandbox/sshgw"
)

const (
	sshConfigBegin = "# >>> gantry sandboxes"
	sshConfigEnd   = "# <<< gantry sandboxes"
	sshSetupWait   = 5 * time.Second
)

var openSSHVersionRE = regexp.MustCompile(`OpenSSH(?:_for_Windows)?_([0-9]+)\.([0-9]+)`)

func managedSSHBlock(self string) string {
	return strings.Join([]string{
		sshConfigBegin,
		"Host *.gantry",
		"    User " + sshgw.DefaultUserSentinel,
		// %n is the original alias that matched *.gantry. Unlike %h/%H, it is
		// not replaced by a HostName override from another SSH config source.
		"    ProxyCommand " + shellCommand(self, "ssh-proxy", "%n"),
		"    KnownHostsCommand " + shellCommand(self, "ssh-known-hosts"),
		"    UserKnownHostsFile " + quoteSSHConfigPath(filepath.Join(sshInstallDir(), "known_hosts")),
		"    StrictHostKeyChecking accept-new",
		sshConfigEnd,
	}, "\n")
}

func updateManagedSSHBlock(content, block string, remove bool) (string, error) {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	begin := strings.Index(content, sshConfigBegin)
	end := strings.Index(content, sshConfigEnd)
	if strings.Count(content, sshConfigBegin) > 1 || strings.Count(content, sshConfigEnd) > 1 ||
		(begin >= 0) != (end >= 0) || (begin >= 0 && end < begin) {
		return "", fmt.Errorf("managed SSH markers are incomplete; repair the file by hand before retrying")
	}
	if begin >= 0 {
		end += len(sshConfigEnd)
		if end < len(content) && content[end] == '\n' {
			end++
		}
		content = content[:begin] + content[end:]
	}
	content = strings.TrimRight(content, "\n")
	if remove {
		if content == "" {
			return "", nil
		}
		return content + "\n", nil
	}
	if content != "" {
		content += "\n\n"
	}
	return content + block + "\n", nil
}

func lockSSHSetup(path string) (*os.File, error) {
	deadline := time.Now().Add(sshSetupWait)
	var lastErr error
	for {
		lock, err := gutil.TryLockFile(path)
		if err == nil {
			return lock, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for SSH setup lock %s: %w", path, lastErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func sshSetup(remove bool) (resultErr error) {
	if !remove {
		supported, version, err := sshSupportsKnownHostsCommand()
		if err != nil {
			return err
		}
		if !supported {
			return fmt.Errorf("OpenSSH %s does not support KnownHostsCommand; version 8.4 or newer is required", version)
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := localsec.CreateManagerDir(sshDir); err != nil {
		return err
	}
	if err := localsec.CreateManagerDir(sshInstallDir()); err != nil {
		return err
	}
	lockPath := filepath.Join(sshInstallDir(), "config.lock")
	lock, err := lockSSHSetup(lockPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()

	self, err := os.Executable()
	if err != nil {
		return err
	}
	managedPath := filepath.Join(sshInstallDir(), "config")
	managed, err := os.ReadFile(managedPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	nextManaged, err := updateManagedSSHBlock(string(managed), managedSSHBlock(self), remove)
	if err != nil {
		return fmt.Errorf("%s: %w", managedPath, err)
	}
	if err := atomicfile.WriteFileDurable(managedPath, []byte(nextManaged), 0o600); err != nil {
		return err
	}
	if err := localsec.SecureRegularFile(managedPath); err != nil {
		return err
	}
	if err := ensureSSHKnownHostsFile(); err != nil {
		return err
	}

	mainPath := filepath.Join(sshDir, "config")
	mainData, err := os.ReadFile(mainPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	mainContent := strings.ReplaceAll(string(mainData), "\r\n", "\n")
	include := "Include " + quoteSSHConfigPath(managedPath)
	lines := strings.Split(mainContent, "\n")
	filtered := lines[:0]
	found := false
	for _, line := range lines {
		if strings.TrimSpace(line) == include {
			found = true
			if remove {
				continue
			}
		}
		filtered = append(filtered, line)
	}
	mainContent = strings.TrimRight(strings.Join(filtered, "\n"), "\n")
	if !remove && !found {
		if mainContent != "" {
			mainContent = include + "\n" + mainContent
		} else {
			mainContent = include
		}
	}
	if mainContent != "" {
		mainContent += "\n"
	}
	if err := atomicfile.WriteFileDurable(mainPath, []byte(mainContent), 0o600); err != nil {
		return err
	}
	return localsec.SecureRegularFile(mainPath)
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
