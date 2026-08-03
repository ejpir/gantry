package virtio

import "encoding/binary"

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

type testPacketConn struct {
	rx chan []byte
	tx chan []byte
}

func (c *testPacketConn) Read(p []byte) (int, error) {
	frame := <-c.rx
	return copy(p, frame), nil
}

func (c *testPacketConn) Write(p []byte) (int, error) {
	c.tx <- append([]byte(nil), p...)
	return len(p), nil
}

func (c *testPacketConn) Close() error { return nil }
