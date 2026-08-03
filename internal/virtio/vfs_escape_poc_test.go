//go:build linux || darwin

// Regression test for the virtio-fs share escape (fixed in the vendored
// go-fuse bridge: validGuestName rejects ".", "..", and names containing
// '/' or NUL before they reach the loopback path joins).
//
// A guest is not obliged to use the Linux FUSE client. It can place arbitrary
// bytes on the virtio-fs request virtqueue. This test drives FS.handler
// directly — exactly the bytes a malicious guest kernel/driver would put on
// the ring — and asserts that a LOOKUP whose name is "../<file>" can no
// longer resolve a path OUTSIDE the exported share, while ordinary in-share
// lookups keep working.
//
//	go test -run TestVirtioFSShareEscape -v .
package virtio

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// FUSE operation helpers shared with the hub tests live in
// test_helpers_test.go.

// fuseInitDevice negotiates the protocol like the Linux client does first.
func fuseInitDevice(t *testing.T, dev *FS) {
	t.Helper()
	initPayload := make([]byte, 64)
	binary.LittleEndian.PutUint32(initPayload[0:4], 7)  // major
	binary.LittleEndian.PutUint32(initPayload[4:8], 38) // minor
	if _, errno, _ := req(t, dev,
		[][]byte{fuseInHeader(fuseInit, 1, 0, len(initPayload)), initPayload},
		16, 64); errno != 0 {
		t.Fatalf("FUSE_INIT errno %d", errno)
	}
}

// lookup sends FUSE_LOOKUP and returns (nodeid, errno).
func lookup(t *testing.T, dev *FS, unique uint64, parent uint64, name string) (uint64, int32) {
	t.Helper()
	n := append([]byte(name), 0)
	_, errno, out := req(t, dev,
		[][]byte{fuseInHeader(fuseLookup, unique, parent, len(n)), n},
		16, 128)
	if errno != 0 {
		return 0, errno
	}
	return binary.LittleEndian.Uint64(out[1][0:8]), 0
}

// req sends one request to the device and returns (bytesWritten, errno). errno
// is the signed value from the fuse_out_header (0 == success).
func req(t *testing.T, dev *FS, in [][]byte, outSizes ...int) (int, int32, [][]byte) {
	t.Helper()
	out := make([][]byte, len(outSizes))
	for i, n := range outSizes {
		out[i] = make([]byte, n)
	}
	n, status := dev.handler.HandleRequest(in, out)
	if status != fuse.OK {
		t.Fatalf("transport status %v", status)
	}
	errno := int32(binary.LittleEndian.Uint32(out[0][4:8]))
	return n, errno, out
}

func TestVirtioFSShareEscape(t *testing.T) {
	// The share the host exports to the guest.
	share := t.TempDir()
	if err := os.WriteFile(filepath.Join(share, "hello.txt"), []byte("in-share\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A host file OUTSIDE the share (a sibling of the share root).
	secretPath := filepath.Join(filepath.Dir(share), "OUTSIDE-SECRET")
	if err := os.WriteFile(secretPath, []byte("TOP SECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(secretPath) })

	dev, err := NewFS("escape", share)
	if err != nil {
		t.Fatal(err)
	}

	// FUSE_INIT — negotiate protocol 7.38, as the Linux client does first.
	initPayload := make([]byte, 64)
	binary.LittleEndian.PutUint32(initPayload[0:4], 7)  // major
	binary.LittleEndian.PutUint32(initPayload[4:8], 38) // minor
	if _, errno, _ := req(t, dev,
		[][]byte{fuseInHeader(fuseInit, 1, 0, len(initPayload)), initPayload},
		16, 64); errno != 0 {
		t.Fatalf("FUSE_INIT errno %d", errno)
	}

	// Every name that could escape the exported root must be rejected.
	for _, escape := range []string{
		"../OUTSIDE-SECRET", "..", ".", "a/../../OUTSIDE-SECRET",
		"sub/..", "", "x", // "x" is fine as a *name* but doesn't exist; checked below
	} {
		if escape == "x" {
			continue
		}
		name := append([]byte(escape), 0)
		_, errno, _ := req(t, dev,
			[][]byte{fuseInHeader(fuseLookup, 2, 1, len(name)), name},
			16, 128)
		if errno == 0 {
			t.Errorf("LOOKUP %q RESOLVED — share escape still present", escape)
		} else {
			t.Logf("LOOKUP %q rejected (errno %d)", escape, errno)
		}
	}

	// An ordinary in-share lookup must still work.
	if _, errno := lookup(t, dev, 3, 1, "hello.txt"); errno != 0 {
		t.Fatalf("in-share LOOKUP failed (errno %d) — bridge over-rejecting", errno)
	}
}

// The name validation alone is not enough: a guest can plant an in-share
// symlink pointing outside the root and then descend through it. The
// vendored loopback must refuse (securePath containment check).
func TestVirtioFSSymlinkEscapeBlocked(t *testing.T) {
	share := t.TempDir()
	if err := os.WriteFile(filepath.Join(share, "hello.txt"), []byte("in-share\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(share)
	secretPath := filepath.Join(parent, "OUTSIDE-SECRET")
	if err := os.WriteFile(secretPath, []byte("TOP SECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(secretPath) })

	dev, err := NewFS("symlink-escape", share)
	if err != nil {
		t.Fatal(err)
	}
	fuseInitDevice(t, dev)

	// plant share/evil -> <parent of share> (creating symlinks is legitimate)
	body := append(append([]byte("evil"), 0), append([]byte(parent), 0)...)
	if _, errno, _ := req(t, dev,
		[][]byte{fuseInHeader(fuseSymlink, 2, 1, len(body)), body},
		16, 128); errno != 0 {
		t.Fatalf("SYMLINK errno %d", errno)
	}

	// resolving the symlink itself is fine...
	evil, errno := lookup(t, dev, 3, 1, "evil")
	if errno != 0 {
		t.Fatalf("LOOKUP evil errno %d", errno)
	}
	// ...but descending THROUGH it must not reach the host's parent dir.
	if _, errno := lookup(t, dev, 4, evil, "OUTSIDE-SECRET"); errno == 0 {
		t.Error("SYMLINK ESCAPE: looked up host file through in-share symlink")
	} else {
		t.Logf("descent through symlink rejected (errno %d)", errno)
	}
	// and neither must creating a file through it
	createIn := make([]byte, 16)
	name := append([]byte("pwned"), 0)
	if _, errno, _ := req(t, dev,
		[][]byte{fuseInHeader(fuseCreate, 5, evil, len(createIn)+len(name)), createIn, name},
		16, 144); errno == 0 {
		t.Error("SYMLINK ESCAPE: created host file through in-share symlink")
	} else {
		t.Logf("create through symlink rejected (errno %d)", errno)
	}
	if _, err := os.Lstat(filepath.Join(parent, "pwned")); err == nil {
		os.Remove(filepath.Join(parent, "pwned"))
		t.Error("host file pwned exists outside the share")
	}

	// legitimate in-share subdirectory traversal still works
	if _, errno := lookup(t, dev, 6, 1, "hello.txt"); errno != 0 {
		t.Fatalf("in-share LOOKUP failed (errno %d)", errno)
	}
}

// `-share ...,ro` must be enforced on the host: mutating opcodes and
// writable OPENs get EROFS from roFuseHandler before the loopback sees them.
func TestVirtioFSReadOnlyShare(t *testing.T) {
	share := t.TempDir()
	if err := os.WriteFile(filepath.Join(share, "hello.txt"), []byte("in-share\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dev, err := NewFS("ro-share", share, true)
	if err != nil {
		t.Fatal(err)
	}
	fuseInitDevice(t, dev)

	const erofs = -30 // Linux EROFS on the wire

	hello, errno := lookup(t, dev, 2, 1, "hello.txt")
	if errno != 0 {
		t.Fatalf("LOOKUP errno %d", errno)
	}
	// read-only OPEN works
	openIn := make([]byte, 8) // flags=0 (O_RDONLY)
	if _, errno, _ := req(t, dev,
		[][]byte{fuseInHeader(fuseOpen, 3, hello, len(openIn)), openIn},
		16, 16); errno != 0 {
		t.Fatalf("O_RDONLY open on ro share errno %d", errno)
	}
	// writable OPEN is rejected
	binary.LittleEndian.PutUint32(openIn[0:4], 1) // O_WRONLY
	if _, errno, _ := req(t, dev,
		[][]byte{fuseInHeader(fuseOpen, 4, hello, len(openIn)), openIn},
		16, 16); errno != erofs {
		t.Fatalf("O_WRONLY open on ro share errno %d, want %d (EROFS)", errno, erofs)
	}
	// WRITE / CREATE / UNLINK are rejected
	writeIn := make([]byte, 40)
	if _, errno, _ := req(t, dev,
		[][]byte{fuseInHeader(fuseWrite, 5, hello, len(writeIn)+4), writeIn, []byte("data")},
		16, 16); errno != erofs {
		t.Fatalf("WRITE on ro share errno %d, want EROFS", errno)
	}
	createIn := make([]byte, 16)
	name := append([]byte("new.txt"), 0)
	if _, errno, _ := req(t, dev,
		[][]byte{fuseInHeader(fuseCreate, 6, 1, len(createIn)+len(name)), createIn, name},
		16, 144); errno != erofs {
		t.Fatalf("CREATE on ro share errno %d, want EROFS", errno)
	}
	if _, errno, _ := req(t, dev,
		[][]byte{fuseInHeader(fuseUnlink, 7, 1, len(name)), name},
		16); errno != erofs {
		t.Fatalf("UNLINK on ro share errno %d, want EROFS", errno)
	}
	// and the file really is untouched
	if b, _ := os.ReadFile(filepath.Join(share, "hello.txt")); string(b) != "in-share\n" {
		t.Fatal("ro share content modified")
	}
}

// The read-only gate is default-deny with the vendored opcode definitions:
// every mutation opcode (xattr writes included — the original bug used
// FSYNC/LISTXATTR's numbers for SETXATTR/REMOVEXATTR) and every
// write-affecting OPEN flag (O_TRUNC passed before) must get EROFS,
// while harmless read-only requests keep working.
func TestVirtioFSReadOnlyGate(t *testing.T) {
	share := t.TempDir()
	if err := os.WriteFile(filepath.Join(share, "hello.txt"), []byte("in-share\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dev, err := NewFS("ro-gate", share, true)
	if err != nil {
		t.Fatal(err)
	}
	fuseInitDevice(t, dev)

	const erofs = -30 // Linux EROFS on the wire

	hello, errno := lookup(t, dev, 2, 1, "hello.txt")
	if errno != 0 {
		t.Fatalf("LOOKUP errno %d", errno)
	}

	// outSizes must match the op's reply iov exactly (the inner server
	// validates the shape); denied ops never reach that validation.
	gate := func(unique uint64, op uint32, nodeid uint64, outSizes []int, payload ...[]byte) int32 {
		payloadLen := 0
		for _, p := range payload {
			payloadLen += len(p)
		}
		in := [][]byte{fuseInHeader(op, unique, nodeid, payloadLen)}
		in = append(in, payload...)
		_, errno, _ := req(t, dev, in, outSizes...)
		return errno
	}

	// Every mutation opcode is rejected — including SETXATTR (21) and
	// REMOVEXATTR (24), which the old blocklist mis-numbered as 20/23.
	mutations := map[string]uint32{
		"SETATTR": 4, "SYMLINK": 6, "MKNOD": 8, "MKDIR": 9,
		"UNLINK": 10, "RMDIR": 11, "RENAME": 12, "LINK": 13,
		"WRITE": 16, "SETXATTR": 21, "REMOVEXATTR": 24,
		"SETLK": 32, "SETLKW": 33, "CREATE": 35, "IOCTL": 39,
		"FALLOCATE": 43, "RENAME2": 45, "COPY_FILE_RANGE": 47,
		"TMPFILE": 51,
	}
	uniq := uint64(100)
	for name, op := range mutations {
		uniq++
		body := make([]byte, 64)
		if errno := gate(uniq, op, hello, []int{16, 256}, body); errno != erofs {
			t.Errorf("%s (%d) on ro share errno %d, want EROFS", name, op, errno)
		}
	}

	// Unknown / future opcodes are denied by default.
	if errno := gate(999, 999, 1, []int{16, 256}, make([]byte, 16)); errno != erofs {
		t.Errorf("unknown opcode 999 errno %d, want EROFS", errno)
	}

	// Read-only opcodes the old table mis-classified as mutations must
	// reach the filesystem again (they may fail for other reasons —
	// unknown file handle here — but never with EROFS). Bodies are sized
	// to the wire structs so the inner server's strict parser accepts
	// them: fuse_fsync_in = 16, fuse_getxattr_in = 8 (+name).
	readOnly := map[string]struct {
		op   uint32
		body []byte
		outs []int
	}{
		"FSYNC":     {20, make([]byte, 16), []int{16}},
		"LISTXATTR": {23, make([]byte, 8), []int{16, 8}},
		"GETXATTR":  {22, append(make([]byte, 8), []byte("user.x\x00")...), []int{16, 8}},
	}
	for name, rc := range readOnly {
		uniq++
		if errno := gate(uniq, rc.op, hello, rc.outs, rc.body); errno == erofs {
			t.Errorf("%s (%d) denied on ro share — gate over-blocking", name, rc.op)
		}
	}

	// OPEN flag gate: every write-affecting flag is rejected even with
	// the O_RDONLY access mode (O_RDONLY|O_TRUNC truncated host files
	// before this existed).
	writeFlags := map[string]uint32{
		"O_WRONLY":         1,
		"O_RDWR":           2,
		"O_RDONLY|O_CREAT": 0x40,
		"O_RDONLY|O_TRUNC": 0x200,
		"O_RDONLY|O_APPEN": 0x400,
		"O_TMPFILE|O_RDWR": 0x410002,
	}
	for name, flags := range writeFlags {
		uniq++
		openIn := make([]byte, 8)
		binary.LittleEndian.PutUint32(openIn[0:4], flags)
		if _, errno, _ := req(t, dev,
			[][]byte{fuseInHeader(fuseOpen, uniq, hello, len(openIn)), openIn},
			16, 16); errno != erofs {
			t.Errorf("OPEN %s on ro share errno %d, want EROFS", name, errno)
		}
	}

	// Plain O_RDONLY OPEN (with harmless flags) still works.
	uniq++
	openIn := make([]byte, 8)
	binary.LittleEndian.PutUint32(openIn[0:4], 0x8000) // O_LARGEFILE
	if _, errno, _ := req(t, dev,
		[][]byte{fuseInHeader(fuseOpen, uniq, hello, len(openIn)), openIn},
		16, 16); errno != 0 {
		t.Fatalf("O_RDONLY OPEN on ro share errno %d", errno)
	}

	// and the file really is untouched
	if b, _ := os.ReadFile(filepath.Join(share, "hello.txt")); string(b) != "in-share\n" {
		t.Fatal("ro share content modified")
	}
}
