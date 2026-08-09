package sandbox

import (
	"syscall"
	"testing"
)

func TestWorkerConfineProcAttrIncludesPIDNamespace(t *testing.T) {
	attr := workerSysProcAttr()
	workerConfineProcAttr(attr)

	want := uintptr(syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID)
	if attr.Cloneflags&want != want {
		t.Fatalf("confined worker clone flags %#x do not contain %#x", attr.Cloneflags, want)
	}
	if attr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("confined worker parent-death signal = %v, want SIGKILL", attr.Pdeathsig)
	}
}
