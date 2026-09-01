package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

var runSSHProcess = runAttachedCommand

// CmdSSH implements the stock-client wrapper and dispatches its setup and
// diagnostic helpers.
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

func remoteSSHCommand(argv []string) string {
	quoted := make([]string, len(argv))
	for index, value := range argv {
		quoted[index] = "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
	}
	return strings.Join(quoted, " ")
}
