//go:build linux || darwin

package vmm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/virtio"
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
	hub, err := virtio.NewShareHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()

	_, err = Prepare(Opts{
		MemSize:  4 << 20,
		Kernel:   openCleanupTestARMKernel(t),
		Disks:    []*os.File{disk},
		ShareHub: hub,
		Shares: []Share{{
			Tag:  "conflict",
			Path: t.TempDir(),
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("Prepare error = %v, want share-mode conflict", err)
	}
	requireClosedAndUnlockedDisk(t, diskPath, disk)
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
