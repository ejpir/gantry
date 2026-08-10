//go:build darwin

package workerconf

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestApplyNetworkConfinedDarwin applies the production Seatbelt profile in a
// disposable child. It proves the inherited packet channel and new IP
// TCP/UDP sockets remain usable while new local IPC, host filesystem access,
// executable launch, and signaling the live supervisor are denied.
func TestApplyNetworkConfinedDarwin(t *testing.T) {
	if os.Getenv("WORKERCONF_NETWORK_DARWIN_HELPER") == "1" {
		networkConfinedDarwinHelper()
		return
	}
	workdir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestApplyNetworkConfinedDarwin$", "-test.v")
	cmd.Env = append(os.Environ(), "WORKERCONF_NETWORK_DARWIN_HELPER=1", "GODEBUG=netdns=go", "WORKERCONF_NETWORK_DIR="+workdir)
	output, err := cmd.CombinedOutput()
	text := string(output)
	if err != nil {
		t.Fatalf("darwin network confinement helper: %v\n%s", err, text)
	}
	for _, marker := range []string{
		"INHERITED-CHANNEL-OK", "TCP-LISTEN-OK", "UDP-LISTEN-OK",
		"UNIX-SOCKET-DENIED", "RESOLVER-CONFIG-READABLE",
		"BROKERED-LOG-PIPE-OK", "LOG-PATH-DENIED", "RUNTIME-SYSCTL-OK",
	} {
		if !strings.Contains(text, marker) {
			t.Errorf("helper output lacks %s:\n%s", marker, text)
		}
	}
	var report Report
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "{\"platform\"") {
			if err := json.Unmarshal([]byte(line), &report); err != nil {
				t.Fatalf("decode confinement report: %v\n%s", err, text)
			}
		}
	}
	for _, property := range []string{PropFSRead, PropFSWrite, PropExec, PropProcEnum, PropProcSignal} {
		if got := report.Property(property); got.State != StateEnforced {
			t.Errorf("%s = %s (%s), want enforced\n%s", property, got.State, got.Detail, text)
		}
	}
	if got := report.Property(PropNetDial).State; got != StateDisabled {
		t.Errorf("net-dial = %s, want disabled for the network role", got)
	}
}

func networkConfinedDarwinHelper() {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		darwinHelperFatal("create inherited channel", err)
	}
	defer func() {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
	}()

	spec := NetworkSpec(2, "")
	report, err := Apply(spec)
	if err != nil {
		darwinHelperFatal("apply Seatbelt", err)
	}
	if _, err := syscall.Write(fds[0], []byte{'x'}); err != nil {
		darwinHelperFatal("write inherited channel", err)
	}
	var packet [1]byte
	if _, err := syscall.Read(fds[1], packet[:]); err != nil || packet[0] != 'x' {
		darwinHelperFatal("read inherited channel", err)
	}
	println("INHERITED-CHANNEL-OK")
	if _, err := os.Stderr.WriteString("BROKERED-LOG-PIPE-OK\n"); err != nil {
		darwinHelperFatal("write inherited diagnostic pipe", err)
	}
	logPath := filepath.Join(os.Getenv("WORKERCONF_NETWORK_DIR"), "worker-net.log")
	if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err == nil {
		_ = f.Close()
		darwinHelperFatal("broker-owned log path unexpectedly writable", nil)
	} else if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		darwinHelperFatal("broker-owned log path", err)
	}
	println("LOG-PATH-DENIED")
	if value, err := unix.Sysctl("hw.ncpu"); err != nil || value == "" {
		darwinHelperFatal("read allowed runtime sysctl", err)
	}
	println("RUNTIME-SYSCTL-OK")

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		darwinHelperFatal("TCP listen", err)
	}
	_ = tcp.Close()
	println("TCP-LISTEN-OK")
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		darwinHelperFatal("UDP listen", err)
	}
	_ = udp.Close()
	println("UDP-LISTEN-OK")

	created, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		_ = syscall.Close(created[0])
		_ = syscall.Close(created[1])
		darwinHelperFatal("new Unix socketpair unexpectedly succeeded", nil)
	}
	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		darwinHelperFatal("new Unix socketpair", err)
	}
	println("UNIX-SOCKET-DENIED")

	if data, err := os.ReadFile("/etc/resolv.conf"); err != nil || len(data) == 0 {
		darwinHelperFatal("read resolver config", err)
	}
	println("RESOLVER-CONFIG-READABLE")

	Verify(spec, report)
	data, _ := json.Marshal(report)
	_, _ = os.Stdout.Write(append(data, '\n'))
}

func darwinHelperFatal(operation string, err error) {
	_, _ = fmt.Fprintln(os.Stderr, operation+":", err)
	os.Exit(2)
}
