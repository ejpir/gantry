package virtio

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

const (
	fuseGetattr = 3
	fuseOpendir = 27
)

func fuseInitHub(t *testing.T, hub *ShareHub) {
	t.Helper()
	payload := make([]byte, 64)
	binary.LittleEndian.PutUint32(payload[0:4], 7)
	binary.LittleEndian.PutUint32(payload[4:8], 38)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseInit, 1, 0, len(payload)), payload}, 16, 64); errno != 0 {
		t.Fatalf("FUSE_INIT errno %d", errno)
	}
}

func hubReq(t *testing.T, hub *ShareHub, in [][]byte, outSizes ...int) (int, int32, [][]byte) {
	t.Helper()
	out := make([][]byte, len(outSizes))
	for i, n := range outSizes {
		out[i] = make([]byte, n)
	}
	n, status := hub.handler.HandleRequest(in, out)
	if status != fuse.OK {
		t.Fatalf("transport status %v", status)
	}
	errno := int32(binary.LittleEndian.Uint32(out[0][4:8]))
	return n, errno, out
}

func hubLookup(t *testing.T, hub *ShareHub, unique uint64, parent uint64, name string) (uint64, int32) {
	t.Helper()
	wireName := append([]byte(name), 0)
	_, errno, out := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseLookup, unique, parent, len(wireName)), wireName}, 16, 128)
	if errno != 0 {
		return 0, errno
	}
	return binary.LittleEndian.Uint64(out[1][0:8]), 0
}

func publishHubShare(t *testing.T, hub *ShareHub, tag, path string, ro bool) *ShareExport {
	t.Helper()
	prepared, _, err := hub.Prepare(tag, path, ro)
	if err != nil {
		t.Fatal(err)
	}
	export, err := hub.Publish(prepared)
	if err != nil {
		t.Fatal(err)
	}
	return export
}

func TestShareHubDynamicNamespace(t *testing.T) {
	hub, err := NewShareHub()
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	fuseInitHub(t, hub)

	const (
		erofs  = -30
		estale = -116
	)
	if node, errno := hubLookup(t, hub, 2, 1, "code"); node != 0 || errno != 0 {
		t.Fatalf("missing dynamic share lookup node=%d errno=%d, want negative node 0", node, errno)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	publishHubShare(t, hub, "code", dir, true)

	tagNode, errno := hubLookup(t, hub, 3, 1, "code")
	if errno != 0 || tagNode <= 1 {
		t.Fatalf("dynamic share lookup node=%d errno=%d", tagNode, errno)
	}
	getattrIn := make([]byte, 16)
	if _, errno, attrOut := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseGetattr, 30, tagNode, len(getattrIn)), getattrIn}, 16, 104); errno != 0 {
		t.Fatalf("export root getattr errno %d", errno)
	} else if mode := binary.LittleEndian.Uint32(attrOut[1][76:80]); mode&uint32(syscall.S_IFMT) != uint32(syscall.S_IFDIR) || mode&0o777 != 0o755 {
		t.Fatalf("export root mode %#o, want directory mode 0755", mode)
	}
	opendirIn := make([]byte, 8)
	_, errno, _ = hubReq(t, hub,
		[][]byte{fuseInHeader(fuseOpendir, 31, tagNode, len(opendirIn)), opendirIn}, 16, 16)
	if errno != 0 {
		t.Fatalf("export root opendir errno %d", errno)
	}
	fileNode, errno := hubLookup(t, hub, 4, tagNode, "hello.txt")
	if errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}
	openIn := make([]byte, 8)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseOpen, 5, fileNode, len(openIn)), openIn}, 16, 16); errno != 0 {
		t.Fatalf("read-only open errno %d", errno)
	}
	binary.LittleEndian.PutUint32(openIn[0:4], 1) // O_WRONLY
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseOpen, 6, fileNode, len(openIn)), openIn}, 16, 16); errno != erofs {
		t.Fatalf("writable open on RO export errno %d, want EROFS", errno)
	}

	if _, err := hub.Remove("code", true); err != nil {
		t.Fatal(err)
	}
	if node, errno := hubLookup(t, hub, 7, 1, "code"); node != 0 || errno != 0 {
		t.Fatalf("removed share lookup node=%d errno=%d, want negative node 0", node, errno)
	}
	revokedIn := make([]byte, 16)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseGetattr, 8, fileNode, len(revokedIn)), revokedIn}, 16, 104); errno != estale {
		t.Fatalf("forced revoked node getattr errno %d, want ESTALE", errno)
	}
}

func TestShareHubPinsRenamedHostRoot(t *testing.T) {
	hub, err := NewShareHub()
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	fuseInitHub(t, hub)

	parent := t.TempDir()
	original := filepath.Join(parent, "original")
	moved := filepath.Join(parent, "moved")
	if err := os.Mkdir(original, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(original, "pinned.txt"), []byte("old root\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	publishHubShare(t, hub, "code", original, true)
	tagNode, errno := hubLookup(t, hub, 2, 1, "code")
	if errno != 0 {
		t.Fatal(errno)
	}
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, errno := hubLookup(t, hub, 3, tagNode, "pinned.txt"); errno != 0 {
		t.Fatalf("pinned root lookup after rename errno %d", errno)
	}

	// The replacement directory at the original path must not retarget
	// opens: reads have to come from the pinned (renamed) root.
	if err := os.WriteFile(filepath.Join(original, "pinned.txt"), []byte("REPLACEMENT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fileNode, errno := hubLookup(t, hub, 4, tagNode, "pinned.txt")
	if errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}
	openIn := make([]byte, 8)
	_, errno, openOut := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseOpen, 5, fileNode, len(openIn)), openIn}, 16, 16)
	if errno != 0 {
		t.Fatalf("open errno %d", errno)
	}
	readIn := make([]byte, 40)
	copy(readIn[0:8], openOut[1][0:8])                 // fh
	binary.LittleEndian.PutUint32(readIn[16:20], 4096) // size
	_, errno, readOut := hubReq(t, hub,
		[][]byte{fuseInHeader(15 /* fuseRead */, 6, fileNode, len(readIn)), readIn}, 16, 4096)
	if errno != 0 {
		t.Fatalf("read errno %d", errno)
	}
	if got := string(readOut[1][:9]); got != "old root\n" {
		t.Fatalf("read %q, want content from the pinned (renamed) root", got)
	}
}

func TestShareHubRenameWithinExport(t *testing.T) {
	hub, err := NewShareHub()
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	fuseInitHub(t, hub)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "before.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	publishHubShare(t, hub, "code", dir, false)
	tagNode, errno := hubLookup(t, hub, 2, 1, "code")
	if errno != 0 {
		t.Fatal(errno)
	}
	oldName := append([]byte("before.txt"), 0)
	newName := append([]byte("after.txt"), 0)
	renameIn := make([]byte, 8)
	binary.LittleEndian.PutUint64(renameIn, tagNode)
	payload := append(renameIn, oldName...)
	payload = append(payload, newName...)
	_, errno, _ = hubReq(t, hub,
		[][]byte{fuseInHeader(12, 3, tagNode, len(payload)), payload}, 16)
	if errno != 0 {
		t.Fatalf("rename errno %d", errno)
	}
	fileNode, errno := hubLookup(t, hub, 4, tagNode, "after.txt")
	if errno != 0 {
		t.Fatalf("renamed lookup errno %d", errno)
	}
	getattrIn := make([]byte, 16)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseGetattr, 5, fileNode, len(getattrIn)), getattrIn}, 16, 104); errno != 0 {
		t.Fatalf("renamed node getattr errno %d", errno)
	}
}

func TestShareHubCrossExportRenameRejected(t *testing.T) {
	hub, err := NewShareHub()
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	fuseInitHub(t, hub)

	left, right := t.TempDir(), t.TempDir()
	for _, dir := range []string{left, right} {
		if err := os.WriteFile(filepath.Join(dir, "file"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	publishHubShare(t, hub, "left", left, false)
	publishHubShare(t, hub, "right", right, false)
	leftNode, errno := hubLookup(t, hub, 2, 1, "left")
	if errno != 0 {
		t.Fatal(errno)
	}
	rightNode, errno := hubLookup(t, hub, 3, 1, "right")
	if errno != 0 {
		t.Fatal(errno)
	}
	// RENAME payload: two NUL-terminated names. The header nodeid is the old
	// parent; the payload begins with the new parent nodeid.
	name := append([]byte("file"), 0)
	renameIn := make([]byte, 8)
	binary.LittleEndian.PutUint64(renameIn, rightNode)
	payload := append(renameIn, name...)
	payload = append(payload, name...)
	_, errno, _ = hubReq(t, hub,
		[][]byte{fuseInHeader(12, 4, leftNode, len(payload)), payload}, 16)
	if errno != -18 { // Linux EXDEV
		t.Fatalf("cross-export rename errno %d, want EXDEV", errno)
	}
	if _, err := os.Stat(filepath.Join(left, "file")); err != nil {
		t.Fatal("rename escaped the left export")
	}
}

// TestShareHubDefaultDenyOps covers the hub's default-deny operation
// policy over the FUSE wire: host-side ioctls, special-file creation and
// non-user xattrs all execute with the VMM's credentials and must never
// cross the guest boundary, even inside a writable export.
func TestShareHubDefaultDenyOps(t *testing.T) {
	hub, err := NewShareHub()
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	fuseInitHub(t, hub)

	const (
		fuseMknod       = 8
		fuseSetxattr    = 21
		fuseRemovexattr = 24
		fuseIoctl       = 39
		eperm           = -1
		enotsup         = -95
	)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	publishHubShare(t, hub, "work", dir, false)

	tagNode, errno := hubLookup(t, hub, 2, 1, "work")
	if errno != 0 {
		t.Fatalf("share lookup errno %d", errno)
	}

	// MKNOD: a guest must not plant special files on the host.
	mknodIn := make([]byte, 16)
	binary.LittleEndian.PutUint32(mknodIn[0:4], uint32(syscall.S_IFCHR|0o644))
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseMknod, 3, tagNode, len(mknodIn)+5), mknodIn, []byte("dev0\x00")}, 16, 128); errno != eperm {
		t.Errorf("mknod errno %d, want EPERM", errno)
	}

	fileNode, errno := hubLookup(t, hub, 4, tagNode, "file.txt")
	if errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}

	// XATTR writes: only user.* may cross the boundary.
	setxattr := func(unique uint64, name, value string) int32 {
		in := make([]byte, 8) // fuse SetXAttrIn: size, flags
		binary.LittleEndian.PutUint32(in[0:4], uint32(len(value)))
		payload := append(in, append([]byte(name+"\x00"), []byte(value)...)...)
		_, errno, _ := hubReq(t, hub,
			[][]byte{fuseInHeader(fuseSetxattr, unique, fileNode, len(payload)), payload}, 16, 16)
		return errno
	}
	for i, attr := range []string{"security.capability", "trusted.overlay.opaque", "system.posix_acl_access"} {
		if errno := setxattr(uint64(10+i), attr, "x"); errno != eperm {
			t.Errorf("setxattr %s errno %d, want EPERM", attr, errno)
		}
		removeIn := []byte(attr + "\x00")
		if _, errno, _ := hubReq(t, hub,
			[][]byte{fuseInHeader(fuseRemovexattr, 20, fileNode, len(removeIn)), removeIn}, 16, 16); errno != eperm {
			t.Errorf("removexattr %s errno %d, want EPERM", attr, errno)
		}
	}
	if errno := setxattr(30, "user.gantry", "x"); errno != 0 {
		t.Errorf("setxattr user.* errno %d, want allowed", errno)
	}

	// IOCTL: default-deny even though the host permits mutating ioctls
	// (FS_IOC_SETFLAGS et al.) through O_RDONLY descriptors.
	openIn := make([]byte, 8)
	_, errno, openOut := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseOpen, 40, fileNode, len(openIn)), openIn}, 16, 16)
	if errno != 0 {
		t.Fatalf("open errno %d", errno)
	}
	ioctlIn := make([]byte, 32)         // fh, flags, cmd, arg, inSize, outSize
	copy(ioctlIn[0:8], openOut[1][0:8]) // fh
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseIoctl, 41, fileNode, len(ioctlIn)), ioctlIn}, 16, 16); errno != enotsup {
		t.Errorf("ioctl errno %d, want ENOTSUP", errno)
	}
}
