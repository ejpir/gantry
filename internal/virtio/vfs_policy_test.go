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

	dev, err := newTestFS("oneshot", dir)
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
	devRO, err := newTestFS("oneshot-ro", dir, true)
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

// After an inode was resolved as a real directory, a host-side swap of that
// directory for a symlink must fail every subsequent operation through the
// pinned-root walk (O_NOFOLLOW on every component) — and, critically, must
// never act on the symlink's target outside the share.
func TestPinnedRootRejectsSwappedDirectory(t *testing.T) {
	share := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "file.txt"), []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(share, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(share, "sub", "file.txt"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}

	dev, err := newTestFS("pinned", share)
	if err != nil {
		t.Fatal(err)
	}
	fuseInitDevice(t, dev)

	subNode, errno := lookup(t, dev, 2, 1, "sub")
	if errno != 0 {
		t.Fatalf("sub lookup errno %d", errno)
	}
	if _, errno := lookup(t, dev, 3, subNode, "file.txt"); errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}

	// Host-side swap: real directory becomes a symlink out of the share.
	if err := os.RemoveAll(filepath.Join(share, "sub")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(share, "sub")); err != nil {
		t.Fatal(err)
	}

	// UNLINK through the stale inode must fail, and the outside file must
	// survive untouched.
	name := append([]byte("file.txt"), 0)
	_, errno, _ = req(t, dev,
		[][]byte{fuseInHeader(10 /* UNLINK */, 4, subNode, len(name)), name},
		16, 16)
	if errno == 0 {
		t.Fatal("unlink through a swapped directory succeeded")
	}
	if _, err := os.Stat(filepath.Join(outside, "file.txt")); err != nil {
		t.Fatalf("swapped-symlink unlink reached outside the share: %v", err)
	}

	// OPEN through the stale inode must fail too (O_NOFOLLOW walk).
	openIn := make([]byte, 8)
	_, errno, _ = req(t, dev,
		[][]byte{fuseInHeader(fuseOpen, 5, subNode, len(openIn)), openIn},
		16, 16)
	if errno == 0 {
		t.Error("opendir/open through a swapped directory succeeded")
	}
}
