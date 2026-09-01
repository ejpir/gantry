package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/sandbox/sshgw"
)

const (
	sshConfigBegin = "# >>> gantry sandboxes"
	sshConfigEnd   = "# <<< gantry sandboxes"
	sshSetupWait   = 5 * time.Second
)

var (
	runSSHProcess    = runAttachedCommand
	openSSHVersionRE = regexp.MustCompile(`OpenSSH(?:_for_Windows)?_([0-9]+)\.([0-9]+)`)
)

// CmdSSH implements the stock-client wrapper and its setup/doctor helpers.
func CmdSSH(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gantry ssh NAME [-- CMD ...] | gantry ssh doctor NAME | gantry ssh setup [--remove]")
		return 2
	}
	switch argv[0] {
	case "setup":
		remove := len(argv) == 2 && argv[1] == "--remove"
		if len(argv) > 1 && !remove {
			fmt.Fprintln(os.Stderr, "usage: gantry ssh setup [--remove]")
			return 2
		}
		if err := sshSetup(remove); err != nil {
			fmt.Fprintln(os.Stderr, "gantry ssh setup:", err)
			return 1
		}
		if remove {
			fmt.Println("gantry ssh setup: managed SSH configuration removed")
		} else {
			fmt.Println("gantry ssh setup: configured Host *.gantry")
		}
		return 0
	case "doctor":
		if len(argv) != 2 {
			fmt.Fprintln(os.Stderr, "usage: gantry ssh doctor NAME")
			return 2
		}
		return cmdSSHDoctor(argv[1])
	}

	target := argv[0]
	userName, name := "", target
	if user, host, found := strings.Cut(target, "@"); found {
		userName, name = user, host
		if userName == "" {
			fmt.Fprintln(os.Stderr, "gantry ssh: SSH user must not be empty")
			return 2
		}
	}
	name = strings.TrimSuffix(name, ".gantry")
	if err := layout.ValidateName(name); err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh:", err)
		return 2
	}
	command := argv[1:]
	if len(command) > 0 {
		if command[0] != "--" {
			fmt.Fprintln(os.Stderr, "usage: gantry ssh NAME [-- CMD ...]")
			return 2
		}
		command = command[1:]
	}
	cfg, err := readSSHConfig(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh:", err)
		return 1
	}
	if !cfg.SSH {
		fmt.Fprintf(os.Stderr, "gantry ssh: sandbox %q has SSH disabled; restart with -ssh\n", name)
		return 1
	}
	if _, alive := layout.PID(name); !alive {
		fmt.Fprintf(os.Stderr, "gantry ssh: sandbox %q is stopped\n", name)
		return 1
	}

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh:", err)
		return 1
	}
	if err := ensureSSHKnownHostsFile(); err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh:", err)
		return 1
	}
	args := []string{
		"-o", "ProxyCommand=" + shellCommand(self, "ssh-proxy", name),
		"-o", "KnownHostsCommand=" + shellCommand(self, "ssh-known-hosts"),
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + filepath.Join(sshInstallDir(), "known_hosts"),
	}
	if userName == "" {
		userName = "root"
		if imageConfig := sshImageConfig(cfg); imageConfig != nil {
			userName = defaultSSHUser(imageConfig.User, imageConfig.UID)
		}
	}
	args = append(args, "-l", userName, name+".gantry")
	if len(command) != 0 {
		// OpenSSH concatenates every argv element after the host with spaces; it
		// does not preserve argument boundaries. Pass one POSIX-shell-quoted
		// command so `gantry ssh NAME -- sh -c "..."` reaches the guest intact
		// on Windows and Unix alike.
		args = append(args, remoteSSHCommand(command))
	}
	return runSSHProcess("ssh", args, os.Stdin, os.Stdout, os.Stderr)
}

func runAttachedCommand(name string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	command := exec.Command(name, args...)
	command.Stdin, command.Stdout, command.Stderr = stdin, stdout, stderr
	if err := command.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		_, _ = fmt.Fprintln(stderr, "gantry:", err)
		return 1
	}
	return 0
}

func readSSHConfig(name string) (config.RunConfig, error) {
	var cfg config.RunConfig
	data, err := os.ReadFile(filepath.Join(layout.Dir(name), "sandbox.json"))
	if err != nil {
		return cfg, fmt.Errorf("sandbox %q does not exist", name)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("sandbox %q has a corrupt configuration: %w", name, err)
	}
	return cfg, nil
}

func normalizeSSHHost(host string) (string, error) {
	name := strings.TrimSuffix(host, ".gantry")
	if name == host || layout.ValidateName(name) != nil {
		return "", fmt.Errorf("invalid Gantry SSH hostname %q; valid sandboxes: %s", host, strings.Join(sshSandboxNames(), ", "))
	}
	return name, nil
}

func sshSandboxNames() []string {
	entries, _ := os.ReadDir(layout.Root())
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() || !layout.ValidName(entry.Name()) {
			continue
		}
		if _, err := os.Stat(filepath.Join(layout.Dir(entry.Name()), "sandbox.json")); err == nil {
			names = append(names, entry.Name()+".gantry")
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return []string{"(none)"}
	}
	return names
}

// CmdSSHProxy bridges SSH client stdio to a validated sandbox-local socket.
func CmdSSHProxy(argv []string) int {
	if len(argv) != 1 {
		fmt.Fprintln(os.Stderr, "usage: gantry ssh-proxy NAME")
		return 2
	}
	name := argv[0]
	if strings.HasSuffix(name, ".gantry") {
		var err error
		name, err = normalizeSSHHost(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry ssh-proxy:", err)
			return 2
		}
	} else if err := layout.ValidateName(name); err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh-proxy:", err)
		return 2
	}
	cfg, err := readSSHConfig(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh-proxy:", err)
		return 1
	}
	if !cfg.SSH {
		fmt.Fprintf(os.Stderr, "gantry ssh-proxy: sandbox %q has SSH disabled; restart with -ssh\n", name)
		return 1
	}
	if _, alive := layout.PID(name); !alive {
		fmt.Fprintf(os.Stderr, "gantry ssh-proxy: sandbox %q is stopped\n", name)
		return 1
	}
	conn, err := dialSSH(name, layout.Dir(name), 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry ssh-proxy: sandbox %q SSH endpoint unavailable: %v\n", name, err)
		return 1
	}
	defer func() { _ = conn.Close() }()
	inputDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(conn, os.Stdin)
		if half, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
		close(inputDone)
	}()
	_, outputErr := io.Copy(os.Stdout, conn)
	_ = conn.Close()
	<-inputDone
	if outputErr != nil && !errors.Is(outputErr, net.ErrClosed) {
		fmt.Fprintln(os.Stderr, "gantry ssh-proxy:", outputErr)
		return 1
	}
	return 0
}

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

func remoteSSHCommand(argv []string) string {
	quoted := make([]string, len(argv))
	for index, value := range argv {
		quoted[index] = "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
	}
	return strings.Join(quoted, " ")
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

func managedSSHBlock(self string) string {
	return strings.Join([]string{
		sshConfigBegin,
		"Host *.gantry",
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

func cmdSSHDoctor(name string) int {
	name = strings.TrimSuffix(name, ".gantry")
	if err := layout.ValidateName(name); err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh doctor:", err)
		return 2
	}
	cfg, err := readSSHConfig(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh doctor:", err)
		return 1
	}
	fmt.Printf("%-18s %s\n", "SSH enabled", yesNo(cfg.SSH))
	fmt.Printf("%-18s %s\n", "Dev Containers", yesNo(cfg.DevContainers))
	if _, alive := layout.PID(name); !alive {
		fmt.Printf("%-18s no\nRemote-SSH will fail: sandbox is stopped (run gantry resume %s)\n", "Sandbox running", name)
		return 1
	}
	fmt.Printf("%-18s yes\n", "Sandbox running")
	if !cfg.SSH {
		fmt.Printf("Remote-SSH will fail: SSH is disabled (run gantry configure %s -ssh)\n", name)
		return 1
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Println("Remote-SSH will fail: cannot locate the Gantry executable")
		return 1
	}
	const probe = `
check() { if "$@" >/dev/null 2>&1; then echo yes; else echo no; fi; }
echo GANTRY_SSH_DOCTOR_sh=yes
echo GANTRY_SSH_DOCTOR_tar=$(check command -v tar)
if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then d=yes; else d=no; fi
echo GANTRY_SSH_DOCTOR_downloader=$d
if getconf GNU_LIBC_VERSION >/dev/null 2>&1; then l=yes; elif ls /lib/ld-musl-*.so.1 >/dev/null 2>&1 && ls /usr/lib/libstdc++.so* >/dev/null 2>&1; then l=yes; else l=no; fi
echo GANTRY_SSH_DOCTOR_runtime=$l
if [ -n "$HOME" ] && [ -d "$HOME" ] && [ -w "$HOME" ]; then h=yes; else h=no; fi
echo GANTRY_SSH_DOCTOR_home=$h
echo GANTRY_SSH_DOCTOR_user=$(id -un 2>/dev/null || echo unknown)
echo GANTRY_SSH_DOCTOR_podman=$(check command -v podman)
echo GANTRY_SSH_DOCTOR_fuse=$(check test -c /dev/fuse)
echo GANTRY_SSH_DOCTOR_tun=$(check test -c /dev/net/tun)
`
	// Probe the environment the SSH gateway actually selects. With Dev
	// Containers enabled this is the curated IDE peer container, while ordinary
	// `gantry exec` deliberately remains in the workload image.
	output, probeErr := exec.Command(self, "ssh", name, "--", "sh", "-c", probe).CombinedOutput()
	values := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok && strings.HasPrefix(key, "GANTRY_SSH_DOCTOR_") {
			values[strings.TrimPrefix(key, "GANTRY_SSH_DOCTOR_")] = value
		}
	}
	if probeErr != nil || values["sh"] != "yes" {
		fmt.Printf("%-18s no\n", "Bourne shell")
		fmt.Println("Remote-SSH will fail: no sh in image (install one or choose another image)")
		return 1
	}
	fmt.Printf("%-18s %s\n", "Bourne shell", values["sh"])
	fmt.Printf("%-18s %s\n", "tar", values["tar"])
	fmt.Printf("%-18s %s\n", "curl or wget", values["downloader"])
	fmt.Printf("%-18s %s\n", "libc + libstdc++", values["runtime"])
	fmt.Printf("%-18s %s\n", "Writable HOME", values["home"])
	fmt.Printf("%-18s %s\n", "Default user", values["user"])
	for _, requirement := range []struct{ key, fix string }{
		{"tar", "no tar in image"},
		{"runtime", "editor runtime requirements are missing"},
		{"home", "default user's HOME is not writable"},
	} {
		if values[requirement.key] != "yes" {
			fmt.Printf("Remote-SSH will fail: %s (fix the image)\n", requirement.fix)
			return 1
		}
	}
	if cfg.DevContainers {
		fmt.Printf("%-18s %s\n", "Podman", values["podman"])
		fmt.Printf("%-18s %s\n", "/dev/fuse", values["fuse"])
		fmt.Printf("%-18s %s\n", "/dev/net/tun", values["tun"])
		if values["podman"] != "yes" || values["fuse"] != "yes" || values["tun"] != "yes" {
			fmt.Println("Dev Containers will fail: curated IDE image or nested-runtime devices are incomplete")
			return 1
		}
	}
	if values["downloader"] != "yes" {
		fmt.Println("Remote-SSH ready for client-side server upload; set remote.SSH.localServerDownload=always")
		return 0
	}
	fmt.Println("Remote-SSH ready")
	return 0
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
