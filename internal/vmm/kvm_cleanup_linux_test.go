//go:build linux

package vmm

import (
	"errors"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func cleanupTestPipeFD(t *testing.T) uintptr {
	t.Helper()
	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
	})
	return uintptr(fds[0])
}

func requireBadFD(t *testing.T, label string, fd uintptr) {
	t.Helper()
	if _, err := unix.FcntlInt(fd, unix.F_GETFD, 0); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("%s fd %d remains open: %v", label, fd, err)
	}
}

func TestMachineCloseReleasesKVMBackendResourcesExactlyOnce(t *testing.T) {
	kvmFD := cleanupTestPipeFD(t)
	vmFD := cleanupTestPipeFD(t)
	gicFD := cleanupTestPipeFD(t)
	vcpuFD := cleanupTestPipeFD(t)
	run, err := syscall.Mmap(-1, 0, osPageSize(), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		t.Fatal(err)
	}
	runAddr := uintptr(unsafe.Pointer(&run[0]))

	resources := &kvmMachineResources{
		kvm:     &kvmFile{fd: kvmFD},
		vmFD:    vmFD,
		vmOpen:  true,
		gicFD:   gicFD,
		gicOpen: true,
		vcpus:   []*kvmVCPU{{id: 0, fd: vcpuFD, run: kvmRunStruct{data: run}}},
	}
	m := &Machine{}
	if err := m.beginRun(); err != nil {
		t.Fatal(err)
	}
	if err := m.adoptBackend(resources); err != nil {
		t.Fatal(err)
	}
	m.finishRun()
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	for label, fd := range map[string]uintptr{
		"KVM": kvmFD, "VM": vmFD, "GIC": gicFD, "vCPU": vcpuFD,
	} {
		requireBadFD(t, label, fd)
	}
	var residency byte
	_, _, errno := syscall.Syscall(syscall.SYS_MINCORE, runAddr, uintptr(osPageSize()), uintptr(unsafe.Pointer(&residency)))
	if !errors.Is(errno, syscall.ENOMEM) {
		t.Fatalf("kvm_run mapping still present: mincore errno=%v", errno)
	}

	// A second Machine.Close must not touch descriptors the process may have
	// acquired after the first teardown.
	newFD := cleanupTestPipeFD(t)
	if err := m.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := unix.FcntlInt(newFD, unix.F_GETFD, 0); err != nil {
		t.Fatalf("second Close affected a new descriptor: %v", err)
	}
	_ = syscall.Close(int(newFD))
}

func TestKVMRunReservationsReleaseUnstartedVCPUs(t *testing.T) {
	resources := &kvmMachineResources{vcpus: []*kvmVCPU{{id: 0}, {id: 1}}}
	resources.prepareVCPURuns()

	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_ = resources.runVCPU(resources.vcpus[0], func(*kvmVCPU) error {
			close(started)
			<-release
			return nil
		})
		close(done)
	}()
	<-started

	// The second vCPU never starts. Returning from backend setup must release
	// its reservation without stealing the running vCPU's Done call.
	resources.abandonVCPURuns()
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("claimed vCPU did not finish")
	}
	waited := make(chan struct{})
	go func() {
		resources.runWG.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("unstarted vCPU reservation leaked")
	}

	called := false
	if err := resources.runVCPU(resources.vcpus[1], func(*kvmVCPU) error {
		called = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("abandoned vCPU ran after its reservation was released")
	}
}

func osPageSize() int { return syscall.Getpagesize() }
