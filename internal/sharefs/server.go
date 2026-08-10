//go:build linux || darwin || windows

package sharefs

import (
	"encoding/binary"
	"io"
	"log"
	"os"
	"sync"

	"github.com/ejpir/gantry/internal/fusewire"
	"github.com/ejpir/gantry/internal/shares"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// Server exposes one host directory through the raw FUSE protocol. It owns
// the pinned root capability and is independent of both virtio and IPC.
type Server struct {
	root    string
	export  *Export
	handler fusewire.Handler
	guard   *requestGuard
	request sync.RWMutex
	closed  bool
}

// NewServer opens and pins root, then builds a host-enforced FUSE server.
// Close must be called even if the consumer fails to attach the server.
func NewServer(tag, root string, readOnly bool) (*Server, error) {
	if err := shares.ValidateShareTag(tag); err != nil {
		return nil, err
	}
	export := &Export{Tag: tag, RO: readOnly}
	export.state.Store(int32(ExportActive))
	node, identity, release, err := newExportNode(export, root, 1<<32)
	if err != nil {
		return nil, err
	}
	canonical := identity.Path()
	export.identity = identity
	export.Path = canonical
	export.node = node
	export.release = release

	debug := os.Getenv("GANTRY_DEBUG_FS") != ""
	logger := log.New(io.Discard, "", 0)
	if debug {
		logger = log.New(os.Stdout, "[fs "+tag+"] ", 0)
	}
	server := &Server{root: canonical, export: export, guard: newRequestGuard()}
	protocol := fuse.NewProtocolServer(fs.NewNodeFS(node, nil), &fuse.MountOptions{
		Debug:                debug,
		Logger:               logger,
		FsName:               tag,
		Name:                 "virtiofs",
		MaxWrite:             128 << 10,
		IgnoreSecurityLabels: true,
		PanicHandler:         server.guard.containPanic,
	})
	var handler fusewire.Handler = protocol
	if readOnly {
		handler = readOnlyHandler{next: protocol}
	}
	server.handler = handler
	server.guard.setReporter(protocol)
	return server, nil
}

func (s *Server) Root() string { return s.root }

func (s *Server) HandleRequest(in, out [][]byte) (int, fuse.Status) {
	s.request.RLock()
	defer s.request.RUnlock()
	if s.closed {
		return 0, fuse.EIO
	}
	return s.guard.handle(s.handler, in, out)
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.request.Lock()
	defer s.request.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.export.finish()
	return nil
}

type readOnlyHandler struct{ next fusewire.Handler }

func (h readOnlyHandler) HandleRequest(in, out [][]byte) (int, fuse.Status) {
	if status := readOnlyGate(in); status != fuse.OK {
		if n := fusewire.WriteError(in, out, status); n != 0 {
			return n, fuse.OK
		}
		return 0, status
	}
	return h.next.HandleRequest(in, out)
}

// Linux flags appear on the FUSE wire on every host OS.
const (
	linuxOAccmode = 0x3
	linuxOCreat   = 0x40
	linuxOTrunc   = 0x200
	linuxOAppend  = 0x400
	linuxOTmpfile = 0x410000

	openWriteFlags = linuxOAccmode | linuxOCreat | linuxOTrunc | linuxOAppend | linuxOTmpfile
)

// readOnlyGate is default-deny: new FUSE opcodes cannot accidentally gain
// write access. A switch is faster and easier to audit than a mutable map.
func readOnlyGate(in [][]byte) fuse.Status {
	var header [44]byte
	n := fusewire.CopyPrefix(header[:], in)
	if n < 40 {
		return fuse.OK // let go-fuse classify malformed protocol input
	}
	op := binary.LittleEndian.Uint32(header[4:8])
	if !readOnlyOperation(op) {
		return fuse.EROFS
	}
	if op == fuse.OpOpen && n >= len(header) {
		flags := binary.LittleEndian.Uint32(header[40:44])
		if flags&openWriteFlags != 0 {
			return fuse.EROFS
		}
	}
	return fuse.OK
}

func readOnlyOperation(op uint32) bool {
	switch op {
	case fuse.OpLookup,
		fuse.OpForget,
		fuse.OpGetattr,
		fuse.OpReadlink,
		fuse.OpOpen,
		fuse.OpRead,
		fuse.OpStatfs,
		fuse.OpRelease,
		fuse.OpFsync,
		fuse.OpGetxattr,
		fuse.OpListxattr,
		fuse.OpFlush,
		fuse.OpInit,
		fuse.OpOpendir,
		fuse.OpReaddir,
		fuse.OpReleasedir,
		fuse.OpFsyncdir,
		fuse.OpGetlk,
		fuse.OpAccess,
		fuse.OpInterrupt,
		fuse.OpBmap,
		fuse.OpDestroy,
		fuse.OpPoll,
		fuse.OpNotifyReply,
		fuse.OpBatchForget,
		fuse.OpReaddirplus,
		fuse.OpLseek,
		fuse.OpStatx:
		return true
	default:
		return false
	}
}

var (
	_ fusewire.Handler = (*Server)(nil)
	_ io.Closer        = (*Server)(nil)
)
