//go:build windows

package sharefs

import "github.com/hanwen/go-fuse/v2/fs"

// Linux open(2) flag values as they appear on the virtio-fs wire.
const (
	linuxOExcl      = 0x80
	linuxODirectory = 0x10000
)

// Windows reports host ACL-derived ownership, so numeric UID/GID mapping is
// rejected explicitly instead of becoming a silent no-op.
const shareOwnerMappingSupported = false

func invalidateShareDirCache(*Export) {}

// newExportNode pins sharePath beneath a root HANDLE and builds the export's
// policy-wrapped FUSE root.
func newExportNode(exp *Export, sharePath string, salt uint64) (fs.InodeEmbedder, Identity, func(), error) {
	backend, err := newWinExportFS(sharePath, salt)
	if err != nil {
		return nil, Identity{}, nil, err
	}
	node := &winShareNode{export: exp, backend: backend}
	exp.watchRootHandle = uintptr(backend.root)
	release := func() { _ = backend.Close() }
	return node, backend.identity, release, nil
}
