//go:build linux || darwin

package virtio

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"syscall"

	"gantry/internal/gutil"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// virtio-fs, without DAX, backed by go-fuse's loopback filesystem. This is
// the same high-level path used by nerdbox/libkrun for host bind mounts:
// the VMM exports a host directory under a tag, vminitd mounts that tag in
// the guest, and crun bind-mounts the guest path into the container.
//
// TRUST BOUNDARY: the request virtqueue is written by the guest, not by the
// Linux FUSE client, so the vendored go-fuse carries gantry patches:
// validGuestName (bridge.go: rejects ".", "..", "/", NUL in names),
// LoopbackNode.securePath (loopback.go: refuses paths that escape the share
// root through an intermediate symlink swap), the exported opcode aliases
// (opcode_gantry.go), Linux-guest errno mapping for Darwin, and the pinned
// NewLoopbackRootFD/RootPrefix/InoSalt support used by ShareHub. Re-vendoring
// upstream go-fuse must re-apply all of them;
// TestVirtioFSShareEscape/TestVirtioFSSymlinkEscapeBlocked fail without the
// first two. `,ro` is enforced here too (roFuseHandler).
const (
	virtioFSDeviceID = 26
	virtioFSHiprioQ  = 0
	virtioFSRequestQ = 1
	// FSTagLen lives in share.go (needed on all platforms)
)

type fuseRequestHandler interface {
	HandleRequest(in, out [][]byte) (int, fuse.Status)
}

type FS struct {
	core    *Core
	tag     string
	root    string
	ro      bool // -share ...,ro: enforced HERE (host side), see roFuseHandler
	handler fuseRequestHandler
	verbose bool
}

func NewFS(tag, root string, ro ...bool) (*FS, error) {
	if tag == "" || len([]byte(tag)) > FSTagLen {
		return nil, fmt.Errorf("tag must be 1..%d bytes", FSTagLen)
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
	// Ownership squash: gVisor's gofer chowns every file/dir it creates
	// to the container process's uid (MkdirAt{UID:0,...}), and non-root
	// hosts (macOS!) cannot chown at all -> every share write failed with
	// EPERM under -runtime runsc. Ownership on a share is cosmetic (the
	// host uid owns everything regardless), so child nodes retry failed
	// chowns with the uid/gid change dropped.
	ln := rootNode.(*fs.LoopbackNode)
	ln.RootData.NewNode = func(rootData *fs.LoopbackRoot, parent *fs.Inode, name string, st *syscall.Stat_t) fs.InodeEmbedder {
		return &squashNode{LoopbackNode: fs.LoopbackNode{RootData: rootData}}
	}
	roFlag := len(ro) > 0 && ro[0]
	debug := gutil.EnvOr("GANTRY_DEBUG_FS", "MINIVM_DEBUG_FS") != ""
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
	return &FS{
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

// roAllowedOps is the DEFAULT-DENY allowlist for a `,ro` share: opcodes
// known to be read-only pass; every other opcode — including mutation
// opcodes added to the protocol after this list was written — gets EROFS.
// (This replaced a mutation blocklist whose hand-copied numbers were
// wrong for SETXATTR/REMOVEXATTR: those mutations reached the loopback
// while harmless FSYNC/LISTXATTR were denied.) Values come from the
// vendored go-fuse opcode aliases (third_party/go-fuse/fuse/
// opcode_gantry.go), so drift against the shared definitions is a
// compile error, not a silent hole.
var roAllowedOps = map[uint32]bool{
	fuse.OpLookup:      true,
	fuse.OpForget:      true,
	fuse.OpGetattr:     true,
	fuse.OpReadlink:    true,
	fuse.OpOpen:        true, // flags gated separately below
	fuse.OpRead:        true,
	fuse.OpStatfs:      true,
	fuse.OpRelease:     true,
	fuse.OpFsync:       true,
	fuse.OpGetxattr:    true,
	fuse.OpListxattr:   true,
	fuse.OpFlush:       true,
	fuse.OpInit:        true,
	fuse.OpOpendir:     true,
	fuse.OpReaddir:     true,
	fuse.OpReleasedir:  true,
	fuse.OpFsyncdir:    true,
	fuse.OpGetlk:       true,
	fuse.OpAccess:      true,
	fuse.OpInterrupt:   true,
	fuse.OpBmap:        true,
	fuse.OpDestroy:     true,
	fuse.OpPoll:        true,
	fuse.OpNotifyReply: true,
	fuse.OpBatchForget: true,
	fuse.OpReaddirplus: true,
	fuse.OpLseek:       true,
	fuse.OpStatx:       true,
}

// Linux open(2) flag values as they appear on the FUSE wire. These are
// the GUEST's Linux constants regardless of the host OS — deliberately
// NOT the syscall package's, which differ on macOS and Windows.
const (
	linuxOAccmode = 0x3      // O_WRONLY|O_RDWR (O_RDONLY == 0)
	linuxOCreat   = 0x40     // 0100
	linuxOTrunc   = 0x200    // 01000
	linuxOAppend  = 0x400    // 02000
	linuxOTmpfile = 0x410000 // __O_TMPFILE | O_DIRECTORY

	// openWriteFlags is every open flag that can mutate host state even
	// with the access mode set to O_RDONLY — O_RDONLY|O_TRUNC truncated
	// host files through a "read-only" share before this mask existed.
	openWriteFlags = linuxOAccmode | linuxOCreat | linuxOTrunc | linuxOAppend | linuxOTmpfile
)

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
	if !roAllowedOps[op] {
		return fuse.EROFS
	}
	if op == fuse.OpOpen && n >= 44 {
		flags := binary.LittleEndian.Uint32(hdr[40:44])
		if flags&openWriteFlags != 0 {
			return fuse.EROFS
		}
	}
	return fuse.OK
}

func (v *FS) deviceID() uint32 { return virtioFSDeviceID }
func (v *FS) features() uint64 { return 0 }
func (v *FS) numQueues() int   { return 2 }
func (v *FS) reset()           {}

func (v *FS) configRead(off uint64, p []byte) {
	// struct virtio_fs_config { char tag[36]; le32 num_request_queues; }
	var cfg [FSTagLen + 4]byte
	copy(cfg[:FSTagLen], []byte(v.tag))
	binary.LittleEndian.PutUint32(cfg[FSTagLen:], 1)
	if off < uint64(len(cfg)) {
		copy(p, cfg[off:])
	}
}
func (v *FS) configWrite(off uint64, p []byte) {}

func (v *FS) logf(format string, args ...any) {
	if v.verbose {
		fmt.Printf("[fs %s] "+format+"\n", append([]any{v.tag}, args...)...)
	}
}

// Both the hiprio and ordinary request queues carry FUSE requests. The
// hiprio queue is used for operations such as INTERRUPT and FORGET.
func (v *FS) handleQueue(qn int) {
	if qn != virtioFSHiprioQ && qn != virtioFSRequestQ {
		return
	}
	q := &v.core.queues[qn]
	for {
		head, chain, ok := v.core.availChain(qn)
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

func (v *FS) readIOV(ds []desc) ([][]byte, error) {
	out := make([][]byte, len(ds))
	for i, d := range ds {
		out[i] = make([]byte, d.len)
		if err := v.core.mem.readAt(d.addr, out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (v *FS) writeIOV(ds []desc, bufs [][]byte, limit int) (uint32, error) {
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
func (v *FS) writeProtocolError(in, out [][]byte, status fuse.Status) int {
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

// fsMaxChainBytes caps one FUSE message: the 40-byte header plus the
// negotiated MaxWrite (128 KiB), with generous headroom for
// READDIRPLUS/read reply buffers from guests with 16K/64K pages. A
// guest declaring more is fishing for a guest-RAM-sized host allocation
// (review finding 2).
const fsMaxChainBytes = 256 << 10

func (v *FS) maxChainBytes(qn int) uint64 { return fsMaxChainBytes }

func (v *FS) setCore(c *Core) { v.core = c }

// Root reports the exported host directory (logs).
func (v *FS) Root() string { return v.root }

// squashNode wraps loopback child nodes with ownership-squash Setattr
// (see NewFS). Only child nodes are wrapped; the root node keeps stock
// behavior.
type squashNode struct {
	fs.LoopbackNode
}

var _ fs.NodeSetattrer = (*squashNode)(nil)

func (n *squashNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	errno := n.LoopbackNode.Setattr(ctx, f, in, out)
	if errno != syscall.EPERM && errno != syscall.EACCES {
		return errno
	}
	if in.Valid&(fuse.FATTR_UID|fuse.FATTR_GID) == 0 {
		return errno
	}
	retry := *in
	retry.Valid &^= fuse.FATTR_UID | fuse.FATTR_GID
	if retry.Valid != 0 {
		// Apply the non-owner changes (mode/size/times); owner stays
		// with the host uid.
		return n.LoopbackNode.Setattr(ctx, f, &retry, out)
	}
	// Pure chown: pretend it worked, reporting fresh attrs.
	return n.LoopbackNode.Getattr(ctx, f, out)
}
