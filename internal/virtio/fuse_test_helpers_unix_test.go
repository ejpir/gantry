//go:build linux || darwin

package virtio

import (
	"encoding/binary"

	"github.com/ejpir/gantry/internal/sharefs"
)

const (
	fuseLookup  = 1
	fuseSymlink = 6
	fuseUnlink  = 10
	fuseOpen    = 14
	fuseWrite   = 16
	fuseInit    = 26
	fuseCreate  = 35
)

// fuseInHeader builds the 40-byte struct fuse_in_header that prefixes every
// request: {len, opcode, unique, nodeid, uid, gid, pid, ...}.
func fuseInHeader(op uint32, unique, nodeid uint64, payloadLen int) []byte {
	b := make([]byte, 40)
	binary.LittleEndian.PutUint32(b[0:4], uint32(40+payloadLen))
	binary.LittleEndian.PutUint32(b[4:8], op)
	binary.LittleEndian.PutUint64(b[8:16], unique)
	binary.LittleEndian.PutUint64(b[16:24], nodeid)
	return b
}

func newTestFS(tag, root string, readOnly ...bool) (*FS, error) {
	ro := len(readOnly) != 0 && readOnly[0]
	server, err := sharefs.NewServer(tag, root, ro)
	if err != nil {
		return nil, err
	}
	device, err := NewFS(tag, server, server)
	if err != nil {
		_ = server.Close()
		return nil, err
	}
	return device, nil
}
