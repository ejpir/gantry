package workerconf

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestApplyNetworkConfined is an executable contract test for the role:
// ordinary TCP/UDP host sockets remain usable, while host filesystem access,
// exec, raw packet sockets, process creation, and /proc enumeration are gone.
func TestApplyNetworkConfined(t *testing.T) {
	if os.Getenv("WORKERCONF_NETWORK_HELPER") == "1" {
		networkConfinedHelper()
		return
	}
	root := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestApplyNetworkConfined", "-test.v")
	cmd.Env = append(os.Environ(), "WORKERCONF_NETWORK_HELPER=1", "WORKERCONF_ROOT="+root)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	output, err := cmd.CombinedOutput()
	text := string(output)
	if err != nil {
		if namespaceTestUnavailable(err, text) {
			t.Skipf("unprivileged userns unavailable on this host: %v\n%s", err, text)
		}
		t.Fatalf("network confinement helper failed: %v\n%s", err, text)
	}
	for _, marker := range []string{
		"TCP-LISTEN-OK", "UDP-LISTEN-OK", "RAW-SOCKET-DENIED",
		"PROCESS-CLONE-DENIED", "RESOLVER-CONFIG-READABLE", "UNJUSTIFIED-FD-CLOSED",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("helper output lacks %s:\n%s", marker, text)
		}
	}
	var report Report
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "{\"platform\"") {
			if err := json.Unmarshal([]byte(line), &report); err != nil {
				t.Fatalf("decode report: %v\n%s", err, text)
			}
		}
	}
	mountOK := !strings.Contains(strings.Join(report.Notes, " "), "mount tier unavailable")
	properties := []string{PropFSWrite, PropExec, PropFDTable, PropSyscall, PropTaskLimit}
	if mountOK {
		properties = append(properties, PropFSRead, PropProcEnum)
	}
	for _, property := range properties {
		if got := report.Property(property); got.State != StateEnforced {
			t.Errorf("%s = %s (%s), want enforced\n%s", property, got.State, got.Detail, text)
		}
	}
	if got := report.Property(PropNetDial).State; got != StateDisabled {
		t.Errorf("net-dial = %s, want disabled for the network role", got)
	}
	if !mountOK {
		t.Skipf("mount tier unavailable in this environment; non-mount network-worker tiers verified, notes: %v", report.Notes)
	}
}

func networkConfinedHelper() {
	if os.Getpid() != 1 {
		_, _ = fmt.Fprintln(os.Stderr, "network helper PID is", os.Getpid(), "want 1")
		os.Exit(2)
	}
	spec := NetworkSpec(2, os.Getenv("WORKERCONF_ROOT"))
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "control socketpair:", err)
		os.Exit(2)
	}
	channels := make([]net.Conn, 0, len(fds))
	for _, fd := range fds {
		file := os.NewFile(uintptr(fd), "worker-channel")
		conn, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "control FileConn:", err)
			os.Exit(2)
		}
		channels = append(channels, conn)
		if rawConn, ok := conn.(syscall.Conn); ok {
			raw, _ := rawConn.SyscallConn()
			_ = raw.Control(func(fd uintptr) { spec.KeepFDExtra = append(spec.KeepFDExtra, int(fd)) })
		}
	}
	defer func() {
		for _, conn := range channels {
			_ = conn.Close()
		}
	}()
	// Put an unjustified descriptor well outside the dense inherited table.
	// The production survey must find and close it without walking every gap.
	nullFD, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "open high-fd source:", err)
		os.Exit(2)
	}
	highFD, err := unix.FcntlInt(uintptr(nullFD), unix.F_DUPFD_CLOEXEC, 512)
	_ = unix.Close(nullFD)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "allocate high fd:", err)
		os.Exit(2)
	}
	report, err := Apply(spec)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "apply:", err)
		os.Exit(2)
	}
	if _, err := unix.FcntlInt(uintptr(highFD), unix.F_GETFD, 0); !errors.Is(err, syscall.EBADF) {
		_, _ = fmt.Fprintln(os.Stderr, "unjustified high fd survived:", highFD, err)
		os.Exit(2)
	}
	println("UNJUSTIFIED-FD-CLOSED")
	rawFD, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "raw tcp socket:", err)
		os.Exit(2)
	}
	if err := unix.Bind(rawFD, &unix.SockaddrInet4{}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "raw tcp bind:", err)
		os.Exit(2)
	}
	if err := unix.Listen(rawFD, 1); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "raw tcp listen:", err)
		os.Exit(2)
	}
	_ = unix.Close(rawFD)
	println("RAW-TCP-LISTEN-OK")

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "tcp listen:", err)
		os.Exit(2)
	}
	_ = tcp.Close()
	println("TCP-LISTEN-OK")
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "udp listen:", err)
		os.Exit(2)
	}
	_ = udp.Close()
	println("UDP-LISTEN-OK")

	if fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, 0); !errors.Is(err, syscall.EPERM) {
		if err == nil {
			_ = unix.Close(fd)
		}
		_, _ = fmt.Fprintln(os.Stderr, "raw packet socket result:", err)
		os.Exit(2)
	}
	println("RAW-SOCKET-DENIED")

	pid, _, errno := syscall.RawSyscall(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0)
	if errno == 0 {
		if pid == 0 {
			os.Exit(99)
		}
		var status syscall.WaitStatus
		_, _ = syscall.Wait4(int(pid), &status, 0, nil)
		_, _ = fmt.Fprintln(os.Stderr, "process clone unexpectedly succeeded with PID", pid)
		os.Exit(2)
	}
	if errno != syscall.EPERM {
		_, _ = fmt.Fprintln(os.Stderr, "process clone:", errno)
		os.Exit(2)
	}
	println("PROCESS-CLONE-DENIED")

	if data, err := os.ReadFile("/etc/resolv.conf"); err != nil || len(data) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "private resolver config:", err, "bytes", len(data))
		os.Exit(2)
	}
	println("RESOLVER-CONFIG-READABLE")

	// Verify also performs real filesystem and exec probes. It must run after
	// the positive socket controls so a too-narrow filter cannot masquerade as
	// stronger isolation by merely breaking the worker.
	Verify(spec, report)
	data, _ := json.Marshal(report)
	_, _ = os.Stdout.Write(append(data, '\n'))
}
