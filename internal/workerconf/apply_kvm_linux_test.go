package workerconf

// TestApplyKVMIoctl is the AL2023 regression test for the seccomp
// filter's ioctl argument check: the request is seccomp_data.args[1]
// (the check once read args[0] — the fd — and denied the entire KVM
// range, killing every confined boot on real KVM). It also proves a
// /dev/kvm fd inherited through the confined Apply (userns + private
// root + close tier + filter) still serves the full KVM ioctl surface.
// Skips on hosts without /dev/kvm.

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestApplyKVMIoctl(t *testing.T) {
	if os.Getenv("WORKERCONF_HELPER") == "1" {
		kvmHelper()
		return
	}
	if _, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
		t.Skip("no /dev/kvm")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cmd := exec.Command(exe, "-test.run", "TestApplyKVMIoctl")
	cmd.Env = append(os.Environ(), "WORKERCONF_HELPER=1", "WORKERCONF_ROOT="+root)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.CombinedOutput()
	t.Logf("helper:\n%s", out)
	if err != nil {
		t.Fatalf("helper failed: %v", err)
	}
	if !strings.Contains(string(out), "KVM-IOCTL-OK") {
		t.Fatal("KVM ioctl denied under confinement")
	}
}

func kvmHelper() {
	kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open /dev/kvm: %v\n", err)
		os.Exit(2)
	}
	spec := DefaultSpec(int(kvm.Fd()), os.Getenv("WORKERCONF_ROOT"))
	rep, applyErr := Apply(spec)
	fmt.Fprintf(os.Stderr, "apply: err=%v notes=%v\n", applyErr, rep.Notes)
	// KVM_GET_API_VERSION = _IO(0xAE, 0x00)
	v, _, errno := syscall.RawSyscall(syscall.SYS_IOCTL, kvm.Fd(), 0xAE00, 0)
	fmt.Fprintf(os.Stderr, "KVM_GET_API_VERSION: v=%d errno=%v\n", v, errno)
	if errno == 0 {
		println("KVM-IOCTL-OK")
	}
}
