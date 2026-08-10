package fs

import (
	"context"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

type setattrProbeNode struct {
	Inode
	called bool
	file   FileHandle
}

func (n *setattrProbeNode) Setattr(_ context.Context, file FileHandle, _ *fuse.SetAttrIn, _ *fuse.AttrOut) syscall.Errno {
	n.called = true
	n.file = file
	return 0
}

func TestSetattrRejectsFileHandleFromAnotherInode(t *testing.T) {
	root := &setattrProbeNode{}
	bridge := NewNodeFS(root, nil).(*rawBridge)
	childOps := &setattrProbeNode{}
	child := bridge.newInode(context.Background(), childOps, StableAttr{Ino: 2, Mode: fuse.S_IFREG}, false)

	bridge.mu.Lock()
	bridge.kernelNodeIds[child.nodeId] = child
	foreign := bridge.registerFile(child, struct{}{}, 0)
	bridge.mu.Unlock()

	in := &fuse.SetAttrIn{}
	in.NodeId = 1
	in.Valid = fuse.FATTR_FH
	in.Fh = uint64(foreign.fh)
	if got := bridge.SetAttr(nil, in, &fuse.AttrOut{}); got != fuse.EBADF {
		t.Fatalf("SetAttr status = %v, want EBADF", got)
	}
	if root.called {
		t.Fatal("SetAttr dispatched a foreign file handle")
	}
}

func TestSetattrIgnoresUnflaggedFileHandle(t *testing.T) {
	root := &setattrProbeNode{}
	bridge := NewNodeFS(root, nil).(*rawBridge)
	child := bridge.newInode(context.Background(), &setattrProbeNode{}, StableAttr{Ino: 2, Mode: fuse.S_IFREG}, false)

	bridge.mu.Lock()
	bridge.kernelNodeIds[child.nodeId] = child
	foreign := bridge.registerFile(child, struct{}{}, 0)
	bridge.mu.Unlock()

	in := &fuse.SetAttrIn{}
	in.NodeId = fuse.FUSE_ROOT_ID
	in.Fh = uint64(foreign.fh) // ignored without FATTR_FH
	if got := bridge.SetAttr(nil, in, &fuse.AttrOut{}); got != fuse.OK {
		t.Fatalf("SetAttr status = %v, want OK", got)
	}
	if !root.called || root.file != nil {
		t.Fatalf("SetAttr called=%v file=%v, want called with nil file", root.called, root.file)
	}
}

func TestUnknownNodeReturnsStale(t *testing.T) {
	bridge := NewNodeFS(&setattrProbeNode{}, nil).(*rawBridge)
	header := &fuse.InHeader{NodeId: 1 << 62}
	if got := bridge.Lookup(nil, header, "child", &fuse.EntryOut{}); got != fuse.ESTALE {
		t.Fatalf("Lookup status = %v, want ESTALE", got)
	}
	// FORGET has no response; an unknown ID must be ignored rather than panic.
	bridge.Forget(header.NodeId, 1)
}

type blockingReadFile struct {
	started      chan struct{}
	continueRead chan struct{}
	released     chan struct{}
	startOne     sync.Once
	releaseOne   sync.Once
}

func (f *blockingReadFile) Read(context.Context, []byte, int64) (fuse.ReadResult, syscall.Errno) {
	f.startOne.Do(func() { close(f.started) })
	<-f.continueRead
	return fuse.ReadResultData(nil), 0
}

func (f *blockingReadFile) Release(context.Context) syscall.Errno {
	f.releaseOne.Do(func() { close(f.released) })
	return 0
}

func TestReleaseWaitsForInFlightFileOperation(t *testing.T) {
	bridge := NewNodeFS(&setattrProbeNode{}, nil).(*rawBridge)
	file := &blockingReadFile{
		started:      make(chan struct{}),
		continueRead: make(chan struct{}),
		released:     make(chan struct{}),
	}
	bridge.mu.Lock()
	entry := bridge.registerFile(bridge.root, file, 0)
	bridge.mu.Unlock()

	readDone := make(chan fuse.Status, 1)
	go func() {
		_, status := bridge.Read(nil, &fuse.ReadIn{
			InHeader: fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID},
			Fh:       uint64(entry.fh),
		}, nil)
		readDone <- status
	}()
	awaitTestSignal(t, file.started, "read start")

	releaseDone := make(chan struct{})
	go func() {
		bridge.Release(nil, &fuse.ReleaseIn{
			InHeader: fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID},
			Fh:       uint64(entry.fh),
		})
		close(releaseDone)
	}()

	deadline := time.Now().Add(time.Second)
	for {
		_, acquired, status := bridge.acquireFile(fuse.FUSE_ROOT_ID, uint64(entry.fh))
		if status == fuse.EBADF {
			break
		}
		if status != fuse.OK {
			t.Fatalf("acquire during release = %v", status)
		}
		acquired.wg.Done()
		if time.Now().After(deadline) {
			t.Fatal("release did not retire handle")
		}
		runtime.Gosched()
	}
	select {
	case <-file.released:
		t.Fatal("Release closed file while Read was in flight")
	default:
	}

	close(file.continueRead)
	if status := awaitTestStatus(t, readDone, "read completion"); status != fuse.OK {
		t.Fatalf("Read status = %v, want OK", status)
	}
	awaitTestSignal(t, file.released, "file release")
	awaitTestSignal(t, releaseDone, "release completion")
	if _, status := bridge.Read(nil, &fuse.ReadIn{
		InHeader: fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID},
		Fh:       uint64(entry.fh),
	}, nil); status != fuse.EBADF {
		t.Fatalf("Read after Release = %v, want EBADF", status)
	}
}

func awaitTestSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func awaitTestStatus(t *testing.T, ch <-chan fuse.Status, what string) fuse.Status {
	t.Helper()
	select {
	case status := <-ch:
		return status
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return fuse.EIO
	}
}
