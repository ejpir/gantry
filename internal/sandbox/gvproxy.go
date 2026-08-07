package sandbox

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/gutil"
)

// StartGVProxy launches gvproxy with its API and vfkit unixgram sockets in
// dir and waits for the vfkit socket. The caller kills the process.
func StartGVProxy(binPath, dir string) (*exec.Cmd, string, error) {
	netSock := filepath.Join(dir, "net.sock")
	apiSock := filepath.Join(dir, "gvproxy-api.sock")
	netLog, err := os.Create(filepath.Join(dir, "gvproxy.log"))
	if err != nil {
		return nil, "", err
	}
	gvPath := binPath
	if !strings.ContainsRune(gvPath, os.PathSeparator) && gutil.FileExists(gvPath) {
		// exec.Command only searches $PATH for bare names; prefer the
		// binary next to gantry (what scripts/run-macos.sh does with artifacts/gvproxy).
		if abs, err := filepath.Abs(gvPath); err == nil {
			gvPath = abs
		}
	}
	// gvproxy's SSH-forward listener defaults to tcp/2222, so every second
	// instance (stale process or a concurrent sandbox) dies with "address
	// already in use". gvproxy rejects -ssh-port 0 ("must be between 1024
	// and 65535"), so grab a free port ourselves; we never use the SSH
	// forward anyway.
	sshPort, err := freeTCPPort()
	if err != nil {
		_ = netLog.Close()
		return nil, "", fmt.Errorf("allocate gvproxy ssh port: %w", err)
	}
	cmd := exec.Command(gvPath, "-debug", "-ssh-port", fmt.Sprint(sshPort), "-listen", "unix://"+apiSock, "-listen-vfkit", "unixgram://"+netSock)
	cmd.Stdout, cmd.Stderr = netLog, netLog
	if err := cmd.Start(); err != nil {
		_ = netLog.Close()
		return nil, "", fmt.Errorf("start gvproxy: %w", err)
	}
	// Record the pid so `gantry stop` can clean up even if the daemon was
	// SIGKILLed (defers don't run then, orphaning gvproxy on port 2222...).
	_ = os.WriteFile(filepath.Join(dir, "gvproxy.pid"), []byte(fmt.Sprint(cmd.Process.Pid)), 0o644)
	for i := 0; i < 300 && !gutil.FileExists(netSock); i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if !gutil.FileExists(netSock) {
		_ = netLog.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, "", fmt.Errorf("gvproxy did not create %s", netSock)
	}
	return cmd, netSock, nil
}

func freeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}
