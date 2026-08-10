//go:build linux || darwin

package vmm

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ejpir/gantry/internal/virtio"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func openCleanupTestARMKernel(t *testing.T) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Image")
	header := make([]byte, 64)
	copy(header[0x38:], "ARM\x64")
	if err := os.WriteFile(path, header, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func openCleanupTestDisk(t *testing.T, name string) (string, *os.File) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	return path, f
}

func openCleanupTestFile(t *testing.T, name string, data []byte) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func requireClosedFile(t *testing.T, label string, f *os.File) {
	t.Helper()
	if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("%s descriptor remained open: %v", label, err)
	}
}

type closeCountingConn struct {
	net.Conn
	closes atomic.Int32
}

type closeCountingFilesystem struct {
	closes atomic.Int32
}

func (*closeCountingFilesystem) HandleRequest([][]byte, [][]byte) (int, fuse.Status) {
	return 0, fuse.ENOSYS
}

func (f *closeCountingFilesystem) Close() error {
	f.closes.Add(1)
	return nil
}

func (c *closeCountingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func requireClosedAndUnlockedDisk(t *testing.T, path string, original *os.File) {
	t.Helper()
	if _, err := original.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("disk descriptor remained open after failure: %v", err)
	}
	reopened, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := virtio.NewBlkFile(reopened, true)
	if err != nil {
		_ = reopened.Close()
		t.Fatalf("writable disk lock remained held after failure: %v", err)
	}
	if err := blk.Close(); err != nil {
		t.Fatalf("close reattached disk: %v", err)
	}
}

func TestPrepareFailureClosesAttachedDevices(t *testing.T) {
	diskPath, disk := openCleanupTestDisk(t, "attached.img")
	attached := &closeCountingFilesystem{}
	rejected := &closeCountingFilesystem{}

	_, err := Prepare(Opts{
		MemSize: MinMemoryBytes,
		VCPUs:   1,
		Kernel:  openCleanupTestARMKernel(t),
		Disks:   []*os.File{disk},
		Filesystems: []Filesystem{
			{Tag: "attached", Handler: attached, Owner: attached},
			{Handler: rejected, Owner: rejected},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "tag must contain") {
		t.Fatalf("Prepare error = %v, want filesystem validation failure", err)
	}
	requireClosedAndUnlockedDisk(t, diskPath, disk)
	if got := attached.closes.Load(); got != 1 {
		t.Fatalf("attached filesystem closes = %d, want 1", got)
	}
	if got := rejected.closes.Load(); got != 1 {
		t.Fatalf("rejected filesystem closes = %d, want 1", got)
	}
}

func TestPrepareValidationFailureClosesEveryInput(t *testing.T) {
	kernel := openCleanupTestARMKernel(t)
	initrd := openCleanupTestFile(t, "initrd", []byte{1})
	_, rootfs := openCleanupTestDisk(t, "rootfs.img")
	_, roDisk := openCleanupTestDisk(t, "ro.img")
	_, rwDisk := openCleanupTestDisk(t, "rw.img")
	kvm := openCleanupTestFile(t, "kvm", nil)
	netSide, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	netConn := &closeCountingConn{Conn: netSide}
	filesystem := &closeCountingFilesystem{}

	_, err := Prepare(Opts{
		MemSize: MinMemoryBytes - 1,
		VCPUs:   1,
		Kernel:  kernel,
		Initrd:  initrd,
		Rootfs:  rootfs,
		KVM:     kvm,
		DisksRO: []*os.File{roDisk},
		Disks:   []*os.File{rwDisk},
		NetConn: netConn,
		Filesystems: []Filesystem{{
			Tag: "shared", Handler: filesystem, Owner: filesystem,
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "memory must be at least") {
		t.Fatalf("Prepare error = %v, want minimum-memory error", err)
	}
	for label, f := range map[string]*os.File{
		"kernel": kernel, "initrd": initrd, "rootfs": rootfs,
		"read-only disk": roDisk, "writable disk": rwDisk, "KVM": kvm,
	} {
		requireClosedFile(t, label, f)
	}
	if got := netConn.closes.Load(); got != 1 {
		t.Fatalf("network connection closes = %d, want 1", got)
	}
	if got := filesystem.closes.Load(); got != 1 {
		t.Fatalf("filesystem closes = %d, want 1", got)
	}
}

func TestPrepareDiskConstructorFailureClosesRejectedAndRemainingInputs(t *testing.T) {
	firstPath, first := openCleanupTestDisk(t, "first.img")
	lockedPath, lockHolder := openCleanupTestDisk(t, "locked.img")
	locked, err := os.OpenFile(lockedPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := virtio.NewBlkFile(lockHolder, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	remainingPath, remaining := openCleanupTestDisk(t, "remaining.img")
	kvm := openCleanupTestFile(t, "kvm", nil)
	netSide, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	netConn := &closeCountingConn{Conn: netSide}

	_, err = Prepare(Opts{
		MemSize: MinMemoryBytes,
		VCPUs:   1,
		Kernel:  openCleanupTestARMKernel(t),
		KVM:     kvm,
		Disks:   []*os.File{first, locked, remaining},
		NetConn: netConn,
	})
	if err == nil || !strings.Contains(err.Error(), "already attached") {
		t.Fatalf("Prepare error = %v, want writable-lock rejection", err)
	}
	requireClosedAndUnlockedDisk(t, firstPath, first)
	requireClosedFile(t, "rejected disk", locked)
	requireClosedAndUnlockedDisk(t, remainingPath, remaining)
	requireClosedFile(t, "KVM", kvm)
	if got := netConn.closes.Load(); got != 1 {
		t.Fatalf("network connection closes = %d, want 1", got)
	}
}

func TestMachineCloseReleasesSuccessfulPrepareInputsOnce(t *testing.T) {
	kernel := openCleanupTestARMKernel(t)
	initrd := openCleanupTestFile(t, "initrd", []byte{0x7f})
	rootPath, rootfs := openCleanupTestDisk(t, "rootfs.img")
	kvm := openCleanupTestFile(t, "kvm", nil)
	netSide, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	netConn := &closeCountingConn{Conn: netSide}
	filesystem := &closeCountingFilesystem{}

	m, err := Prepare(Opts{
		MemSize: MinMemoryBytes,
		VCPUs:   1,
		Kernel:  kernel,
		Initrd:  initrd,
		Rootfs:  rootfs,
		KVM:     kvm,
		NetConn: netConn,
		Filesystems: []Filesystem{{
			Tag: "shared", Handler: filesystem, Owner: filesystem,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	requireClosedFile(t, "kernel", kernel)
	requireClosedFile(t, "initrd", initrd)
	if _, err := rootfs.Stat(); err != nil {
		t.Fatalf("rootfs closed before Machine.Close: %v", err)
	}
	if _, err := kvm.Stat(); err != nil {
		t.Fatalf("KVM closed before Machine.Close: %v", err)
	}
	if got := filesystem.closes.Load(); got != 0 {
		t.Fatalf("filesystem closed before Machine.Close: %d", got)
	}

	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	requireClosedAndUnlockedDisk(t, rootPath, rootfs)
	requireClosedFile(t, "KVM", kvm)
	if got := netConn.closes.Load(); got != 1 {
		t.Fatalf("network connection closes = %d, want 1", got)
	}
	if got := filesystem.closes.Load(); got != 1 {
		t.Fatalf("filesystem closes = %d, want 1", got)
	}
}

func TestPrepareRejectsReusedFilesystemOwnerAndClosesItOnce(t *testing.T) {
	filesystem := &closeCountingFilesystem{}
	_, err := Prepare(Opts{
		MemSize: MinMemoryBytes,
		VCPUs:   1,
		Kernel:  openCleanupTestARMKernel(t),
		Filesystems: []Filesystem{
			{Tag: "one", Handler: filesystem, Owner: filesystem},
			{Tag: "two", Handler: filesystem, Owner: filesystem},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "reuse the same owner") {
		t.Fatalf("Prepare error = %v, want duplicate-owner rejection", err)
	}
	if got := filesystem.closes.Load(); got != 1 {
		t.Fatalf("filesystem closes = %d, want 1", got)
	}
}

func TestPrepareRejectsReusedDescriptorObject(t *testing.T) {
	kernel := openCleanupTestARMKernel(t)
	_, err := Prepare(Opts{
		MemSize: MinMemoryBytes,
		VCPUs:   1,
		Kernel:  kernel,
		KVM:     kernel,
	})
	if err == nil || !strings.Contains(err.Error(), "reuse the same descriptor") {
		t.Fatalf("Prepare error = %v, want duplicate-descriptor rejection", err)
	}
	requireClosedFile(t, "shared kernel/KVM", kernel)
}

func TestAddVirtioFailureClosesRejectedDevice(t *testing.T) {
	m := &Machine{
		arch: "amd64",
		mem:  virtio.NewRAM(make([]byte, 4096), 0),
	}
	defer func() { _ = m.Close() }()
	for range x86MMIOIRQs {
		if _, err := m.addVirtio(virtio.NewRNG(), "rng"); err != nil {
			t.Fatal(err)
		}
	}

	diskPath, disk := openCleanupTestDisk(t, "rejected.img")
	blk, err := virtio.NewBlkFile(disk, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.addVirtio(blk, "blk"); err == nil || !strings.Contains(err.Error(), "supports at most") {
		t.Fatalf("addVirtio error = %v, want slot-limit rejection", err)
	}
	requireClosedAndUnlockedDisk(t, diskPath, disk)
}

func TestAttachVsockRejectsListenerFailureBeforeBoot(t *testing.T) {
	forwardDir := filepath.Join(t.TempDir(), strings.Repeat("x", 80))
	if err := os.MkdirAll(forwardDir, 0o700); err != nil {
		t.Fatal(err)
	}
	machine := &Machine{
		arch: "arm64",
		mem:  virtio.NewRAM(make([]byte, 1<<20), 0),
	}
	defer func() { _ = machine.Close() }()

	err := machine.attachVsock(Opts{
		GuestCID:    3,
		VsockFwd:    forwardDir,
		VsockListen: []uint32{1026},
	})
	if err == nil || !strings.Contains(err.Error(), "listen port 1026") {
		t.Fatalf("attachVsock() error = %v, want listener failure", err)
	}
}
