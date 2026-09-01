package sandbox

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/layout"
)

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
