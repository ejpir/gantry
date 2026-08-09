package workerconf

// TestApplyPreservesLiveConnDups is the AL2023 regression test: the
// close tier once killed the net.FileConn DUPS of the live channel
// conns (they land above the dense table), severing the worker's
// control channel mid-Apply — the supervisor EOF'd and SIGKILLed the
// healthy worker. The keep set must cover the dups (KeepFDExtra) and
// kernel-internal runtime plumbing (epoll anon inodes).

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestApplyPreservesLiveConnDups(t *testing.T) {
	if os.Getenv("WORKERCONF_HELPER") == "1" {
		connDupHelper()
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cmd := exec.Command(exe, "-test.run", "TestApplyPreservesLiveConnDups")
	cmd.Env = append(os.Environ(), "WORKERCONF_HELPER=1", "WORKERCONF_ROOT="+root)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.CombinedOutput()
	text := string(out)
	if err != nil {
		if namespaceTestUnavailable(err, text) {
			t.Skipf("unprivileged userns unavailable on this host: %v\n%s", err, text)
		}
		t.Fatalf("helper failed: %v\n%s", err, text)
	}
	for _, want := range []string{"DUP-ALIVE", "FILECONN-OK", "POLLER-ALIVE", "SURVIVED"} {
		if !strings.Contains(text, want) {
			t.Fatalf("helper output lacks %s:\n%s", want, text)
		}
	}
}

func connDupHelper() {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		os.Exit(2)
	}
	defer func() { _, _ = syscall.Close(fds[0]), syscall.Close(fds[1]) }()
	conn, err := net.FileConn(os.NewFile(uintptr(fds[0]), "sp"))
	if err != nil {
		os.Exit(2)
	}
	dupFD := -1
	if sc, ok := conn.(syscall.Conn); ok {
		if raw, err := sc.SyscallConn(); err == nil {
			_ = raw.Control(func(f uintptr) { dupFD = int(f) })
		}
	}
	if dupFD < 0 || dupFD == fds[0] {
		_, _ = os.Stderr.WriteString("helper: FileConn did not dup as expected\n")
		os.Exit(2)
	}
	spec := DefaultSpec(2, os.Getenv("WORKERCONF_ROOT"))
	// Both live ends must be in the keep set — exactly what production
	// does for its live conns.
	spec.KeepFDExtra = []int{dupFD, fds[1]}
	rep, err := Apply(spec)
	if err != nil || rep == nil || !rep.Applied {
		_, _ = os.Stderr.WriteString("helper: Apply degraded unexpectedly\n")
		os.Exit(2)
	}
	// The dup must be open post-Apply...
	if _, _, errno := syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(dupFD), syscall.F_GETFD, 0); errno != 0 {
		_, _ = os.Stderr.WriteString("helper: conn dup was closed by the close tier\n")
		os.Exit(1)
	}
	println("DUP-ALIVE")
	// ...net.FileConn must still wrap a fresh socket fd (getsockopt is
	// whitelisted): the vsock.forward path does exactly this for every
	// guest-brokered connection.
	peer, err := net.FileConn(os.NewFile(uintptr(fds[1]), "peer"))
	if err != nil {
		_, _ = os.Stderr.WriteString("helper: FileConn post-Apply: " + err.Error() + "\n")
		os.Exit(1)
	}
	_ = peer.Close()
	println("FILECONN-OK")
	// ...and the runtime poller must still function: a timer through
	// the netpoll path fires.
	done := make(chan struct{})
	go func() {
		_, _ = conn.Write([]byte{1})
		close(done)
	}()
	<-done
	println("POLLER-ALIVE")
	println("SURVIVED")
}
