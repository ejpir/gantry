//go:build linux || darwin

package sharefs

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
)

func TestShareHubCreateRejectsExistingFIFO(t *testing.T) {
	directory := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(directory, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	fuseInitHub(t, hub)
	publishHubShare(t, hub, "work", directory, false)
	tagNode, errno := hubLookup(t, hub, 2, 1, "work")
	if errno != 0 {
		t.Fatalf("share lookup errno %d", errno)
	}

	create := make([]byte, 16)
	// Linux FUSE flags are used on every host: O_RDWR|O_CREAT|O_NONBLOCK.
	binary.LittleEndian.PutUint32(create[0:4], 0x2|0x40|guestONonblock)
	binary.LittleEndian.PutUint32(create[4:8], 0o600)
	payload := append(create, []byte("pipe\x00")...)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseCreate, 3, tagNode, len(payload)), payload}, 16, 144); errno != -int32(syscall.EPERM) {
		t.Fatalf("CREATE existing FIFO errno %d, want EPERM", errno)
	}
	info, err := os.Lstat(filepath.Join(directory, "pipe"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("CREATE replaced FIFO with mode %v", info.Mode())
	}
}

func TestValidateOpenedFileRejectsActualFIFODescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	handle := fs.NewLoopbackFile(fd)
	if errno := validateOpenedFile(t.Context(), handle, guestONonblock); errno != syscall.EPERM {
		t.Fatalf("FIFO descriptor validation errno = %v, want EPERM", errno)
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("rejected FIFO descriptor remained open: %v", err)
	}
}

func TestShareHubHandlelessSetattrRejectsFIFO(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	fuseInitHub(t, hub)
	publishHubShare(t, hub, "work", directory, false)
	tagNode, errno := hubLookup(t, hub, 2, 1, "work")
	if errno != 0 {
		t.Fatalf("share lookup errno %d", errno)
	}
	fifoNode, errno := hubLookup(t, hub, 3, tagNode, "pipe")
	if errno != 0 {
		t.Fatalf("FIFO lookup errno %d", errno)
	}

	setattr := make([]byte, 88)
	binary.LittleEndian.PutUint32(setattr[0:4], 1<<3) // FATTR_SIZE
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseSetattr, 4, fifoNode, len(setattr)), setattr}, 16, 104); errno != -int32(syscall.EPERM) {
		t.Fatalf("handle-less SETATTR on FIFO errno %d, want EPERM", errno)
	}
}

func TestShareHubRenameRejectsWhiteout(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	destination := filepath.Join(directory, "destination")
	if err := os.WriteFile(source, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	fuseInitHub(t, hub)
	publishHubShare(t, hub, "work", directory, false)
	tagNode, errno := hubLookup(t, hub, 2, 1, "work")
	if errno != 0 {
		t.Fatalf("share lookup errno %d", errno)
	}

	// FUSE_RENAME2 carries newdir, flags and padding before both names.
	rename := make([]byte, 16)
	binary.LittleEndian.PutUint64(rename[0:8], tagNode)
	binary.LittleEndian.PutUint32(rename[8:12], 4) // RENAME_WHITEOUT
	payload := append(rename, []byte("source\x00destination\x00")...)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(45, 3, tagNode, len(payload)), payload}, 16); errno != -int32(syscall.EPERM) {
		t.Fatalf("RENAME_WHITEOUT errno %d, want EPERM", errno)
	}
	if got, err := os.ReadFile(source); err != nil || string(got) != "unchanged" {
		t.Fatalf("source changed after rejected whiteout: data=%q err=%v", got, err)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination exists after rejected whiteout: %v", err)
	}
}

func TestShareHubLinkRejectsSpecialFile(t *testing.T) {
	directory := t.TempDir()
	pipe := filepath.Join(directory, "pipe")
	alias := filepath.Join(directory, "alias")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	fuseInitHub(t, hub)
	publishHubShare(t, hub, "work", directory, false)
	tagNode, errno := hubLookup(t, hub, 2, 1, "work")
	if errno != 0 {
		t.Fatalf("share lookup errno %d", errno)
	}
	pipeNode, errno := hubLookup(t, hub, 3, tagNode, "pipe")
	if errno != 0 {
		t.Fatalf("FIFO lookup errno %d", errno)
	}

	link := make([]byte, 8)
	binary.LittleEndian.PutUint64(link, pipeNode)
	payload := append(link, []byte("alias\x00")...)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(13, 4, tagNode, len(payload)), payload}, 16, 128); errno != -int32(syscall.EPERM) {
		t.Fatalf("LINK special file errno %d, want EPERM", errno)
	}
	if _, err := os.Lstat(alias); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("special-file alias exists after rejected link: %v", err)
	}
}
