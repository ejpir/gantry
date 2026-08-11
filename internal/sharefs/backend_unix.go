//go:build linux || darwin

package sharefs

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hanwen/go-fuse/v2/fs"
)

// The Unix backend pins each export root by descriptor, then lets go-fuse's
// loopback implementation resolve descendants relative to that capability.

// The Unix loopback wrapper rewrites owner fields via mapGuestOwner, so
// uid=/gid= exports are supported.
const shareOwnerMappingSupported = true

func newExportNode(exp *Export, path string, salt uint64) (fs.InodeEmbedder, Identity, func(), error) {
	rootFD, identity, err := openRoot(path)
	if err != nil {
		return nil, Identity{}, nil, err
	}
	return newExportNodeFD(exp, identity, rootFD, salt)
}

// openRoot pins a share root for the lifetime of its export.
func openRoot(path string) (*os.File, Identity, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, Identity{}, fmt.Errorf("resolve share path: %w", err)
	}
	rootFD, err := os.Open(abs)
	if err != nil {
		return nil, Identity{}, fmt.Errorf("open share root: %w", err)
	}
	info, err := rootFD.Stat()
	if err != nil || !info.IsDir() {
		_ = rootFD.Close()
		if err == nil {
			err = fmt.Errorf("not a directory")
		}
		return nil, Identity{}, fmt.Errorf("share root %s: %w", abs, err)
	}
	identity, err := identityFromRoot(rootFD, info)
	if err != nil {
		_ = rootFD.Close()
		return nil, Identity{}, err
	}
	return rootFD, identity, nil
}

// newExportNodeFD takes ownership of an already-pinned root descriptor.
func newExportNodeFD(exp *Export, identity Identity, rootFD *os.File, salt uint64) (fs.InodeEmbedder, Identity, func(), error) {
	rootNode, err := fs.NewLoopbackRootFD(identity.Path(), int(rootFD.Fd()))
	if err != nil {
		_ = rootFD.Close()
		return nil, Identity{}, nil, fmt.Errorf("create loopback export: %w", err)
	}
	loopback, ok := rootNode.(*fs.LoopbackNode)
	if !ok {
		_ = rootFD.Close()
		return nil, Identity{}, nil, fmt.Errorf("unexpected loopback root %T", rootNode)
	}
	loopback.RootData.InoSalt = salt
	exp.watchRootFD = int(rootFD.Fd())
	rootData := loopback.RootData
	node := &shareNode{LoopbackNode: fs.LoopbackNode{RootData: rootData}, export: exp}
	rootData.RootNode = node
	registerShareDirCache(exp)
	release := func() {
		closeShareDirCache(exp)
		_ = rootFD.Close()
	}
	return node, identity, release, nil
}
