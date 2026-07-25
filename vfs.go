//go:build linux || darwin

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// virtio-fs, without DAX, backed by go-fuse's loopback filesystem. This is
// the same high-level path used by nerdbox/libkrun for host bind mounts:
// the VMM exports a host directory under a tag, vminitd mounts that tag in
// the guest, and crun bind-mounts the guest path into the container.
//
// TRUST BOUNDARY: the request virtqueue is written by the guest, not by the
// Linux FUSE client, so the vendored go-fuse carries two gantry patches —
// validGuestName (bridge.go: rejects ".", "..", "/", NUL in names) and
// LoopbackNode.securePath (loopback.go: refuses paths that escape the share
// root through an intermediate symlink swap). Re-vendoring upstream go-fuse
// must re-apply both; TestVirtioFSShareEscape/TestVirtioFSSymlinkEscapeBlocked
// fail without them. `,ro` is enforced here too (roFuseHandler).
const (
	virtioFSDeviceID = 26
	virtioFSHiprioQ  = 0
	virtioFSRequestQ = 1
	// virtioFSTagLen lives in share.go (needed on all platforms)
)

type fuseRequestHandler interface {
	HandleRequest(in, out [][]byte) (int, fuse.Status)
}

type virtioFS struct {
	core    *virtioMMIOCore
	tag     string
	root    string
	ro      bool // -share ...,ro: enforced HERE (host side), see roFuseHandler
	handler fuseRequestHandler
	verbose bool
}

func newVirtioFS(tag, root string, ro ...bool) (*virtioFS, error) {
	if tag == "" || len([]byte(tag)) > virtioFSTagLen {
		return nil, fmt.Errorf("tag must be 1..%d bytes", virtioFSTagLen)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve shared directory: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("stat shared directory: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("shared path is not a directory: %s", abs)
	}

	rootNode, err := fs.NewLoopbackRoot(abs)
	if err != nil {
		return nil, fmt.Errorf("create loopback filesystem: %w", err)
	}
	roFlag := len(ro) > 0 && ro[0]
	debug := envOr("GANTRY_DEBUG_FS", "MINIVM_DEBUG_FS") != ""
	logger := log.New(io.Discard, "", 0)
	if debug {
		logger = log.New(os.Stdout, "[fs "+tag+"] ", 0)
	}
	raw := fs.NewNodeFS(rootNode, nil)
	protocol := fuse.NewProtocolServer(raw, &fuse.MountOptions{
		Debug:                debug,
		Logger:               logger,
		FsName:               tag,
		Name:                 "virtiofs",
		MaxWrite:             128 << 10,
		IgnoreSecurityLabels: true,
	})
	var handler fuseRequestHandler = protocol
	if roFlag {
		handler = &roFuseHandler{inner: protocol}
	}
	return &virtioFS{
		tag:     tag,
		root:    abs,
		ro:      roFlag,
		handler: handler,
		verbose: debug,
	}, nil
}

// roFuseHandler enforces `-share ...,ro` on the HOST side: the guest-side
// MS_RDONLY mount is only a convention, and a hostile guest is precisely
// what the flag is meant to defend against. Mutating opcodes and writable
// OPENs get EROFS before they reach the loopback filesystem.
type roFuseHandler struct{ inner fuseRequestHandler }

func (h *roFuseHandler) HandleRequest(in, out [][]byte) (int, fuse.Status) {
	if status := roGate(in); status != fuse.OK {
		if len(out) == 0 || len(out[0]) < 16 {
			return 0, status
		}
		h := out[0][:16]
		binary.LittleEndian.PutUint32(h[0:4], 16)
		binary.LittleEndian.PutUint32(h[4:8], uint32(-int32(status)))
		if len(in) > 0 && len(in[0]) >= 16 {
			copy(h[8:16], in[0][8:16]) // request unique ID
		}
		return 16, fuse.OK
	}
	return h.inner.HandleRequest(in, out)
}

// FUSE opcodes that mutate host state (linux/fuse.h). On a `,ro` share the
// host rejects them — the guest-side MS_RDONLY mount is only a convention,
// and a sandboxed guest is precisely what `,ro` is meant to defend against.
var roMutatingOps = map[uint32]bool{
	4:  true, // SETATTR
	6:  true, // SYMLINK
	8:  true, // MKNOD
	9:  true, // MKDIR
	10: true, // UNLINK
	11: true, // RMDIR
	12: true, // RENAME
	13: true, // LINK
	16: true, // WRITE
	20: true, // SETXATTR
	23: true, // REMOVEXATTR
	35: true, // CREATE
	39: true, // IOCTL
	43: true, // FALLOCATE
	45: true, // RENAME2
	47: true, // COPY_FILE_RANGE
}

const fuseOpOpen = 14

// roGate inspects a raw FUSE request and returns EROFS for operations that
// would mutate the host share. The header is 40 bytes (opcode @4); OPEN's
// flags word is the first 4 payload bytes.
func roGate(in [][]byte) fuse.Status {
	var hdr [44]byte
	n := 0
	for _, b := range in {
		n += copy(hdr[n:], b)
		if n >= len(hdr) {
			break
		}
	}
	if n < 40 {
		return fuse.OK // malformed; let the protocol server complain
	}
	op := binary.LittleEndian.Uint32(hdr[4:8])
	if roMutatingOps[op] {
		return fuse.EROFS
	}
	if op == fuseOpOpen && n >= 44 {
		flags := binary.LittleEndian.Uint32(hdr[40:44])
		if flags&0x3 != 0 { // O_WRONLY / O_RDWR (O_RDONLY == 0)
			return fuse.EROFS
		}
	}
	return fuse.OK
}

func (v *virtioFS) deviceID() uint32 { return virtioFSDeviceID }
func (v *virtioFS) features() uint64 { return 0 }
func (v *virtioFS) numQueues() int   { return 2 }
func (v *virtioFS) reset()           {}

func (v *virtioFS) configRead(off uint64, p []byte) {
	// struct virtio_fs_config { char tag[36]; le32 num_request_queues; }
	var cfg [virtioFSTagLen + 4]byte
	copy(cfg[:virtioFSTagLen], []byte(v.tag))
	binary.LittleEndian.PutUint32(cfg[virtioFSTagLen:], 1)
	if off < uint64(len(cfg)) {
		copy(p, cfg[off:])
	}
}
func (v *virtioFS) configWrite(off uint64, p []byte) {}

func (v *virtioFS) logf(format string, args ...any) {
	if v.verbose {
		fmt.Printf("[fs %s] "+format+"\n", append([]any{v.tag}, args...)...)
	}
}

// Both the hiprio and ordinary request queues carry FUSE requests. The
// hiprio queue is used for operations such as INTERRUPT and FORGET.
func (v *virtioFS) handleQueue(qn int) {
	if qn != virtioFSHiprioQ && qn != virtioFSRequestQ {
		return
	}
	q := &v.core.queues[qn]
	for {
		head, chain, ok := v.core.availChain(q)
		if !ok {
			return
		}
		readable, writable := splitChain(chain)
		in, err := v.readIOV(readable)
		if err != nil {
			v.logf("read request descriptors: %v", err)
			v.core.pushUsed(q, head, 0)
			continue
		}
		out := make([][]byte, len(writable))
		for i, d := range writable {
			out[i] = make([]byte, d.len)
		}

		n, status := v.handler.HandleRequest(in, out)
		if status != fuse.OK {
			v.logf("protocol request failed: %v", status)
			// HandleRequest normally serializes filesystem errors itself.
			// A non-OK return denotes a malformed transport request.
			n = v.writeProtocolError(in, out, status)
		}
		if len(writable) == 0 { // FORGET/BATCH_FORGET suppress replies.
			n = 0
		}
		if n < 0 {
			n = 0
		}
		capacity := 0
		for _, b := range out {
			capacity += len(b)
		}
		if n > capacity {
			n = capacity
		}
		written, err := v.writeIOV(writable, out, n)
		if err != nil {
			v.logf("write response descriptors: %v", err)
			written = 0
		}
		v.core.pushUsed(q, head, written)
	}
}

func (v *virtioFS) readIOV(ds []desc) ([][]byte, error) {
	out := make([][]byte, len(ds))
	for i, d := range ds {
		out[i] = make([]byte, d.len)
		if err := v.core.mem.readAt(d.addr, out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (v *virtioFS) writeIOV(ds []desc, bufs [][]byte, limit int) (uint32, error) {
	var written uint32
	remaining := limit
	for i, d := range ds {
		if remaining <= 0 || i >= len(bufs) {
			break
		}
		b := bufs[i]
		if len(b) > remaining {
			b = b[:remaining]
		}
		if len(b) > int(d.len) {
			b = b[:d.len]
		}
		if err := v.core.mem.writeAt(d.addr, b); err != nil {
			return written, err
		}
		written += uint32(len(b))
		remaining -= len(b)
	}
	return written, nil
}

// writeProtocolError creates a FUSE out_header for parse-level failures.
func (v *virtioFS) writeProtocolError(in, out [][]byte, status fuse.Status) int {
	if len(out) == 0 || len(out[0]) < 16 {
		return 0
	}
	h := out[0][:16]
	binary.LittleEndian.PutUint32(h[0:4], 16)
	binary.LittleEndian.PutUint32(h[4:8], uint32(-int32(status)))
	if len(in) > 0 && len(in[0]) >= 16 {
		copy(h[8:16], in[0][8:16]) // request unique ID
	}
	return 16
}
