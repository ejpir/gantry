package fs

import (
	"context"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// bridgeNamespaceProbe records the exact point at which the optional Gantry
// bridge lock is released.  The callback lets tests prove that the matching
// in-memory inode-tree update happened before Unlock, rather than merely that
// the Node operation itself ran under the lock.
type bridgeNamespaceProbe struct {
	gate sync.Mutex

	held        atomic.Bool
	locks       atomic.Int32
	unlocks     atomic.Int32
	callbackGap atomic.Bool
	treeReady   atomic.Bool

	beforeUnlock func() bool
}

func (p *bridgeNamespaceProbe) lock() {
	p.gate.Lock()
	p.held.Store(true)
	p.locks.Add(1)
}

func (p *bridgeNamespaceProbe) unlock() {
	if p.beforeUnlock != nil && p.beforeUnlock() {
		p.treeReady.Store(true)
	}
	p.held.Store(false)
	p.unlocks.Add(1)
	p.gate.Unlock()
}

func (p *bridgeNamespaceProbe) observeCallback() {
	if !p.held.Load() {
		p.callbackGap.Store(true)
	}
}

type bridgeNamespaceNode struct {
	Inode
	probe *bridgeNamespaceProbe

	lookupChild *Inode
}

func (n *bridgeNamespaceNode) GantryLockRawBridge() {
	n.probe.lock()
}

func (n *bridgeNamespaceNode) GantryUnlockRawBridge() {
	n.probe.unlock()
}

func (n *bridgeNamespaceNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	n.probe.observeCallback()
	child := n.NewInode(ctx, &Inode{}, StableAttr{Ino: 2, Mode: fuse.S_IFREG})
	n.lookupChild = child
	out.Attr.Ino = 2
	out.Attr.Mode = fuse.S_IFREG | 0600
	return child, 0
}

func (n *bridgeNamespaceNode) Rename(_ context.Context, _ string, _ InodeEmbedder, _ string, _ uint32) syscall.Errno {
	n.probe.observeCallback()
	return 0
}

func TestGantryBridgeLockSpansLookupTreeInsertion(t *testing.T) {
	probe := &bridgeNamespaceProbe{}
	root := &bridgeNamespaceNode{probe: probe}
	bridge := NewNodeFS(root, nil).(*rawBridge)
	probe.beforeUnlock = func() bool {
		return root.lookupChild != nil && root.GetChild("child") == root.lookupChild
	}

	status := bridge.Lookup(nil, &fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}, "child", &fuse.EntryOut{})
	if status != fuse.OK {
		t.Fatalf("Lookup status = %v, want OK", status)
	}
	assertBridgeNamespaceProbe(t, probe)
}

func TestGantryBridgeLockSpansRenameTreeUpdate(t *testing.T) {
	tests := []struct {
		name  string
		flags uint32
	}{
		{name: "move"},
		{name: "exchange", flags: RENAME_EXCHANGE},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := &bridgeNamespaceProbe{}
			root := &bridgeNamespaceNode{probe: probe}
			bridge := NewNodeFS(root, nil).(*rawBridge)
			oldChild := root.NewPersistentInode(context.Background(), &Inode{}, StableAttr{Ino: 2, Mode: fuse.S_IFREG})
			if !root.AddChild("old", oldChild, false) {
				t.Fatal("failed to install old child")
			}

			var newChild *Inode
			if tt.flags&RENAME_EXCHANGE != 0 {
				newChild = root.NewPersistentInode(context.Background(), &Inode{}, StableAttr{Ino: 3, Mode: fuse.S_IFREG})
				if !root.AddChild("new", newChild, false) {
					t.Fatal("failed to install new child")
				}
			}
			probe.beforeUnlock = func() bool {
				if root.GetChild("new") != oldChild {
					return false
				}
				if tt.flags&RENAME_EXCHANGE != 0 {
					return root.GetChild("old") == newChild
				}
				return root.GetChild("old") == nil
			}

			input := &fuse.RenameIn{
				InHeader: fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID},
				Newdir:   fuse.FUSE_ROOT_ID,
				Flags:    tt.flags,
			}
			if status := bridge.Rename(nil, input, "old", "new"); status != fuse.OK {
				t.Fatalf("Rename status = %v, want OK", status)
			}
			assertBridgeNamespaceProbe(t, probe)
		})
	}
}

type failingOpenDirNode struct {
	Inode
	probe *bridgeNamespaceProbe
}

func (n *failingOpenDirNode) GantryLockRawBridge() {
	n.probe.lock()
}

func (n *failingOpenDirNode) GantryUnlockRawBridge() {
	n.probe.unlock()
}

func (n *failingOpenDirNode) OpendirHandle(context.Context, uint32) (FileHandle, uint32, syscall.Errno) {
	n.probe.observeCallback()
	return nil, 0, syscall.EPERM
}

func TestGantryBridgeUnlocksAfterZeroMessageOpenDirError(t *testing.T) {
	probe := &bridgeNamespaceProbe{}
	root := &failingOpenDirNode{probe: probe}
	bridge := NewNodeFS(root, &Options{ZeroMessageOpenDir: true}).(*rawBridge)
	out := fuse.NewDirEntryList(make([]byte, 4096), 0)
	status := bridge.ReadDirPlus(nil, &fuse.ReadIn{
		InHeader: fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID},
	}, out)
	if status != fuse.EPERM {
		t.Fatalf("ReadDirPlus status = %v, want EPERM", status)
	}
	if probe.callbackGap.Load() {
		t.Fatal("OpendirHandle callback ran outside Gantry bridge lock")
	}
	if probe.held.Load() || probe.locks.Load() != 1 || probe.unlocks.Load() != 1 {
		t.Fatalf("lock state after OpendirHandle error: held=%v locks=%d unlocks=%d", probe.held.Load(), probe.locks.Load(), probe.unlocks.Load())
	}
}

func assertBridgeNamespaceProbe(t *testing.T, probe *bridgeNamespaceProbe) {
	t.Helper()
	if probe.callbackGap.Load() {
		t.Fatal("Node callback ran outside Gantry bridge lock")
	}
	if !probe.treeReady.Load() {
		t.Fatal("Gantry bridge lock was released before inode-tree update")
	}
	if probe.held.Load() || probe.locks.Load() != 1 || probe.unlocks.Load() != 1 {
		t.Fatalf("unexpected lock state: held=%v locks=%d unlocks=%d", probe.held.Load(), probe.locks.Load(), probe.unlocks.Load())
	}
}
