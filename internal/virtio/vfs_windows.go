//go:build windows

package virtio

import (
	"encoding/binary"
	"fmt"
	"time"

	"gantry/internal/gutil"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// FS is the legacy one-shot virtio-fs device backed by the Windows native
// passthrough implementation. Persistent sandboxes use ShareHub instead.
type FS struct {
	core    *Core
	tag     string
	root    string
	export  *ShareExport
	handler fuseRequestHandler
	verbose bool
}

func NewFS(tag, root string, ro ...bool) (*FS, error) {
	if tag == "" || len([]byte(tag)) > FSTagLen {
		return nil, fmt.Errorf("tag must be 1..%d bytes", FSTagLen)
	}
	roFlag := len(ro) > 0 && ro[0]
	backend, err := newWinExportFS(root, 1<<32)
	if err != nil {
		return nil, err
	}
	exp := &ShareExport{Tag: tag, Path: backend.path, RO: roFlag, release: func() { _ = backend.Close() }}
	exp.state.Store(int32(ShareExportActive))
	exp.node = &winShareNode{export: exp, backend: backend}
	debug := gutil.EnvOr("GANTRY_DEBUG_FS", "MINIVM_DEBUG_FS") != ""
	zero := time.Duration(0)
	raw := fs.NewNodeFS(exp.node, &fs.Options{
		MountOptions: fuse.MountOptions{
			Debug:                debug,
			FsName:               tag,
			Name:                 "virtiofs",
			MaxWrite:             128 << 10,
			IgnoreSecurityLabels: true,
		},
		EntryTimeout:    &zero,
		AttrTimeout:     &zero,
		NegativeTimeout: &zero,
	})
	protocol := fuse.NewProtocolServer(raw, &fuse.MountOptions{
		Debug:                debug,
		FsName:               tag,
		Name:                 "virtiofs",
		MaxWrite:             128 << 10,
		IgnoreSecurityLabels: true,
	})
	return &FS{tag: tag, root: backend.path, export: exp, handler: protocol, verbose: debug}, nil
}

func (v *FS) Root() string { return v.root }

func (v *FS) Close() error {
	if v != nil && v.export != nil {
		v.export.finish()
	}
	return nil
}

func (v *FS) deviceID() uint32 { return virtioFSDeviceID }
func (v *FS) features() uint64 { return 0 }
func (v *FS) numQueues() int   { return 2 }
func (v *FS) reset()           {}
func (v *FS) setCore(c *Core)  { v.core = c }

func (v *FS) configRead(off uint64, p []byte) {
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
			n = v.writeProtocolError(in, out, status)
		}
		if len(writable) == 0 {
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

func (v *FS) writeProtocolError(in, out [][]byte, status fuse.Status) int {
	if len(out) == 0 || len(out[0]) < 16 {
		return 0
	}
	buf := out[0][:16]
	binary.LittleEndian.PutUint32(buf[0:4], 16)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(-int32(status)))
	if len(in) > 0 && len(in[0]) >= 16 {
		copy(buf[8:16], in[0][8:16])
	}
	return 16
}

func (v *FS) maxChainBytes(qn int) uint64 { return fsMaxChainBytes }
