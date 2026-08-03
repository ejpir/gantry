//go:build linux || darwin

// Policy-parity test for one-shot shares (gantry run/exec -share): since
// NewFS builds the same export node as persistent hub shares, the
// default-deny mknod, special-file open rejection and host-enforced RO must
// all hold on this path too. Drives FS.handler at the wire level, exactly
// like a guest kernel would.
package virtio

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOneShotSharePolicyParity(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}

	dev, err := NewFS("oneshot", dir)
	if err != nil {
		t.Fatal(err)
	}
	fuseInitDevice(t, dev)

	const (
		fuseMknod = 8
		eperm     = -1
		erofs     = -30
	)

	fileNode, errno := lookup(t, dev, 2, 1, "file.txt")
	if errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}
	openIn := make([]byte, 8) // flags=0 (O_RDONLY)
	if _, errno, _ := req(t, dev,
		[][]byte{fuseInHeader(fuseOpen, 3, fileNode, len(openIn)), openIn},
		16, 16); errno != 0 {
		t.Errorf("open regular file errno %d, want 0", errno)
	}

	// A pre-existing special file must never be opened through the share:
	// opening a host device node has side effects.
	pipeNode, errno := lookup(t, dev, 4, 1, "pipe")
	if errno != 0 {
		t.Fatalf("fifo lookup errno %d", errno)
	}
	if _, errno, _ := req(t, dev,
		[][]byte{fuseInHeader(fuseOpen, 5, pipeNode, len(openIn)), openIn},
		16, 16); errno != eperm {
		t.Errorf("open FIFO errno %d, want EPERM", errno)
	}

	// MKNOD: a guest must not plant special files through one-shot shares.
	mknodIn := make([]byte, 16)
	binary.LittleEndian.PutUint32(mknodIn[0:4], uint32(syscall.S_IFCHR|0o644))
	if _, errno, _ := req(t, dev,
		[][]byte{fuseInHeader(fuseMknod, 6, 1, len(mknodIn)+5), mknodIn, []byte("dev0\x00")},
		16, 128); errno != eperm {
		t.Errorf("mknod errno %d, want EPERM", errno)
	}

	// RO one-shot shares reject writes at the export layer.
	devRO, err := NewFS("oneshot-ro", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	fuseInitDevice(t, devRO)
	roFile, errno := lookup(t, devRO, 1, 1, "file.txt")
	if errno != 0 {
		t.Fatalf("ro file lookup errno %d", errno)
	}
	binary.LittleEndian.PutUint32(openIn[0:4], 1) // O_WRONLY
	if _, errno, _ := req(t, devRO,
		[][]byte{fuseInHeader(fuseOpen, 2, roFile, len(openIn)), openIn},
		16, 16); errno != erofs {
		t.Errorf("ro open(O_WRONLY) errno %d, want EROFS", errno)
	}
}
