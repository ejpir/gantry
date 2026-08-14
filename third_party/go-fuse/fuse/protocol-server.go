// Copyright 2024 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuse

import (
	"encoding/binary"
	"sync"
	"syscall"
)

// protocolServer bridges from the FUSE datatypes to a RawFileSystem
type protocolServer struct {
	fileSystem RawFileSystem

	writev func([][]byte) (int, syscall.Errno)

	// gantryNotificationSink carries unsolicited FUSE invalidations over
	// Gantry's negotiated virtio-fs notification queue. Ordinary /dev/fuse
	// mounts continue to use writev above.
	gantryNotificationMu   sync.RWMutex
	gantryNotificationSink func([]byte) Status

	interruptMu    sync.Mutex
	reqInflight    []*request
	connectionDead bool

	kernelSettingsMu sync.RWMutex
	kernelSettings   InitIn

	opts *MountOptions

	// in-flight notify-retrieve queries
	retrieveMu   sync.Mutex
	retrieveNext uint64
	retrieveTab  map[uint64]*retrieveCacheRequest // notifyUnique -> retrieve request
}

func (ms *protocolServer) handleRequest(h *operationHandler, req *request) {
	ms.addInflight(req)
	defer ms.dropInflight(req)

	if req.status.Ok() && ms.opts.Debug {
		ms.opts.Logger.Println(req.InputDebug())
	}

	if h == nil || h.Func == nil {
		c := req.inHeader().Opcode
		if c != _OP_COPY_FILE_RANGE_64 { // _OP_COPY_FILE_RANGE_64 is intentionally not supported.
			ms.opts.Logger.Printf("Unimplemented opcode %v", operationName(c))
		}
		req.status = ENOSYS
	} else if req.inHeader().NodeId == pollHackInode ||
		req.inHeader().NodeId == FUSE_ROOT_ID && h.FileNames > 0 && req.filename() == pollHackName {
		doPollHackLookup(ms, req)
	} else if req.status.Ok() {
		func() {
			defer func() {
				if r := recover(); r != nil {
					req.status = ms.opts.PanicHandler(r)
					if req.status == 0 {
						req.status = EIO
					}
				}
			}()
			h.Func(ms, req)
		}()
	}

	// Forget/NotifyReply do not wait for reply from filesystem server.
	switch req.inHeader().Opcode {
	case _OP_INTERRUPT:
		// ? what other status can interrupt generate?
		if req.status.Ok() {
			req.suppressReply = true
		}
	default:
		req.suppressReply = h != nil && h.SuppressReply
	}
	if req.status == EINTR {
		ms.interruptMu.Lock()
		dead := ms.connectionDead
		ms.interruptMu.Unlock()
		if dead {
			req.suppressReply = true
		}
	}
	if req.suppressReply {
		return
	}
	if req.readResult != nil && ms.opts.DisableSplice {
		req.outPayload, req.status = req.readResult.Bytes(req.outPayload)
		req.readResult.Done()
		req.readResult = nil
	}

	req.serializeHeader(req.outPayloadSize())

	if ms.opts.Debug {
		ms.opts.Logger.Println(req.OutputDebug())
	}
}

func (ms *protocolServer) addInflight(req *request) {
	ms.interruptMu.Lock()
	defer ms.interruptMu.Unlock()
	req.inflightIndex = len(ms.reqInflight)
	ms.reqInflight = append(ms.reqInflight, req)
}

func (ms *protocolServer) dropInflight(req *request) {
	ms.interruptMu.Lock()
	defer ms.interruptMu.Unlock()
	this := req.inflightIndex
	last := len(ms.reqInflight) - 1
	if last != this {
		ms.reqInflight[this] = ms.reqInflight[last]
		ms.reqInflight[this].inflightIndex = this
	}
	ms.reqInflight = ms.reqInflight[:last]
}

func (ms *protocolServer) interruptRequest(unique uint64) Status {
	ms.interruptMu.Lock()
	defer ms.interruptMu.Unlock()

	// This is slow, but this operation is rare.
	for _, inflight := range ms.reqInflight {
		if unique == inflight.inHeader().Unique && !inflight.interrupted {
			close(inflight.cancel)
			inflight.interrupted = true
			return OK
		}
	}

	return EAGAIN
}

func (ms *protocolServer) cancelAll() {
	ms.interruptMu.Lock()
	defer ms.interruptMu.Unlock()
	ms.connectionDead = true
	for _, req := range ms.reqInflight {
		if !req.interrupted {
			close(req.cancel)
			req.interrupted = true
		}
	}
	// Leave ms.reqInflight alone, or dropInflight will barf.
}

// ProtocolServer bridges from FUSE request/response types to the
// Go-FUSE RawFileSystem API calls.
//
// EXPERIMENTAL: not subject to API stability.
type ProtocolServer struct {
	protocolServer
}

// NewProtocolServer creates a ProtocolServer for the RawFileSystem.
//
// EXPERIMENTAL: not subject to API stability.
func NewProtocolServer(fs RawFileSystem, opts *MountOptions) *ProtocolServer {
	// ProtocolServer has no pipe, so splicing READ results to the
	// caller is not possible; force the in-process READ path.
	optsCopy := *opts
	optsCopy.setDefaults(fs)
	optsCopy.DisableSplice = true

	server := &ProtocolServer{
		protocolServer: protocolServer{
			fileSystem:  fs,
			retrieveTab: make(map[uint64]*retrieveCacheRequest),
			opts:        &optsCopy,
		},
	}
	if initializer, ok := fs.(interface{ InitProtocol(*ProtocolServer) }); ok {
		initializer.InitProtocol(server)
	}
	return server
}

// GantryResourceUsage forwards optional live inode/file-handle accounting
// from the raw filesystem. GANTRY PATCH: this is consumed by gantry's
// process-boundary share broker; other protocol-server users are unaffected.
func (ps *ProtocolServer) GantryResourceUsage() (nodes, handles int) {
	if reporter, ok := ps.fileSystem.(interface {
		GantryResourceUsage() (nodes, handles int)
	}); ok {
		return reporter.GantryResourceUsage()
	}
	return 0, 0
}

// GantryPruneResources asks the guest kernel to release up to limit cached
// inode references. GANTRY PATCH: ordinary kernel FUSE mounts reclaim these
// under memory pressure; Gantry also requests reclamation proactively so a
// legitimate large tree walk does not trip the supervisor's retention bound.
func (ps *ProtocolServer) GantryPruneResources(limit int) Status {
	const maxPruneNodes = (8<<10 - 16 - 16) / 8
	if limit <= 0 {
		return OK
	}
	limit = min(limit, maxPruneNodes)
	provider, ok := ps.fileSystem.(interface {
		GantryPruneCandidates(limit int) []uint64
	})
	if !ok {
		return ENOSYS
	}
	ps.kernelSettingsMu.RLock()
	settings := ps.kernelSettings
	ps.kernelSettingsMu.RUnlock()
	if settings.Major < 7 || (settings.Major == 7 && settings.Minor < 45) {
		return ENOSYS
	}
	ps.gantryNotificationMu.RLock()
	ready := ps.gantryNotificationSink != nil
	ps.gantryNotificationMu.RUnlock()
	if !ready {
		return EAGAIN
	}
	ids := provider.GantryPruneCandidates(limit)
	if len(ids) == 0 {
		return OK
	}
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], uint32(len(ids)))
	payload := make([]byte, 8*len(ids))
	for i, id := range ids {
		binary.LittleEndian.PutUint64(payload[i*8:], id)
	}
	return ps.sendGantryNotification(NOTIFY_PRUNE, data, payload)
}

// GantrySetNotificationSink installs the transport for unsolicited reverse
// invalidations. The callback receives a call-scoped contiguous frame.
func (ps *ProtocolServer) GantrySetNotificationSink(sink func([]byte) Status) {
	ps.gantryNotificationMu.Lock()
	ps.gantryNotificationSink = sink
	ps.gantryNotificationMu.Unlock()
}

func (ps *protocolServer) gantryNotify(iov [][]byte) Status {
	ps.gantryNotificationMu.RLock()
	defer ps.gantryNotificationMu.RUnlock()
	if ps.gantryNotificationSink == nil {
		return ENOSYS
	}
	total := iovLen(iov)
	message := make([]byte, total)
	offset := 0
	for _, part := range iov {
		offset += copy(message[offset:], part)
	}
	return ps.gantryNotificationSink(message)
}

func (ps *ProtocolServer) sendGantryNotification(code int32, data, payload []byte) Status {
	total := 16 + len(data) + len(payload)
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(total))
	binary.LittleEndian.PutUint32(header[4:8], uint32(code))
	return ps.protocolServer.gantryNotify([][]byte{header, data, payload})
}

func (ps *ProtocolServer) InodeNotify(node uint64, off int64, length int64) Status {
	data := make([]byte, 24)
	binary.LittleEndian.PutUint64(data[0:8], node)
	binary.LittleEndian.PutUint64(data[8:16], uint64(off))
	binary.LittleEndian.PutUint64(data[16:24], uint64(length))
	return ps.sendGantryNotification(NOTIFY_INVAL_INODE, data, nil)
}

func (ps *ProtocolServer) EntryNotify(parent uint64, name string) Status {
	if name == "" {
		return EINVAL
	}
	data := make([]byte, 16)
	binary.LittleEndian.PutUint64(data[0:8], parent)
	binary.LittleEndian.PutUint32(data[8:12], uint32(len(name)))
	payload := append([]byte(name), 0)
	return ps.sendGantryNotification(NOTIFY_INVAL_ENTRY, data, payload)
}

func (ps *ProtocolServer) DeleteNotify(parent uint64, child uint64, name string) Status {
	if name == "" {
		return EINVAL
	}
	data := make([]byte, 24)
	binary.LittleEndian.PutUint64(data[0:8], parent)
	binary.LittleEndian.PutUint64(data[8:16], child)
	binary.LittleEndian.PutUint32(data[16:20], uint32(len(name)))
	payload := append([]byte(name), 0)
	return ps.sendGantryNotification(NOTIFY_DELETE, data, payload)
}

func (ps *ProtocolServer) InodeNotifyStoreCache(uint64, int64, []byte) Status {
	return ENOSYS
}

func (ps *ProtocolServer) InodeRetrieveCache(uint64, int64, []byte) (int, Status) {
	return 0, ENOSYS
}

// GantryNotifyEpoch invalidates all dentries from the previous FUSE
// connection epoch. It is used as the bounded fail-safe for watcher loss.
func (ps *ProtocolServer) GantryNotifyEpoch() Status {
	ps.kernelSettingsMu.RLock()
	settings := ps.kernelSettings
	ps.kernelSettingsMu.RUnlock()
	if settings.Major < 7 || (settings.Major == 7 && settings.Minor < 44) {
		return ENOSYS
	}
	return ps.sendGantryNotification(NOTIFY_INC_EPOCH, nil, nil)
}

func iovLen(iov [][]byte) int {
	var r int
	for _, e := range iov {
		r += len(e)
	}
	return r
}

// HandleRequest parses the iov in `in`, calls into the raw
// filesystem, and puts the result in `out`. The shapes of the
// input/output IOVs should follow conventions used by virtiofs.
// The return value is the number of bytes written.
//
// EXPERIMENTAL: not subject to API stability.
func (ps *ProtocolServer) HandleRequest(in [][]byte, out [][]byte) (int, Status) {
	// for virtiofs, we get
	//
	// 2026/04/17 13:34:40 in: 40 32
	// 2026/04/17 13:34:40 out: 16 16 4096
	//
	// ie. the iov looks like {header , variable size, payload},
	// for both input and output.
	//
	// Our input data types have the InHeader embedded in the FooIn
	// types, so we can never fully avoid copying. A virtqueue may split both
	// request data and payload at arbitrary descriptor/page boundaries.
	inTogether := make([]byte, iovLen(in))
	copyIOVToBytes(inTogether, in)
	h, inSize, outSize, outPayloadSize, errno := parseRequest(inTogether, &ps.kernelSettings)
	if errno != 0 {
		return 0, errno
	}
	req := request{
		cancel:        make(chan struct{}),
		inputBuf:      inTogether[:inSize],
		suppressReply: h.SuppressReply,
	}

	req.inPayload = inTogether[inSize:]

	startOut := out
	var payloadOut [][]byte
	if !h.SuppressReply {
		// validate the shape of the output iov. If we fail any of this, it's probably a programming error on our side, but
		// since we can't trust the guest, be paranoid and return EIO instead.
		if len(out) > 0 && len(out[0]) == int(sizeOfOutHeader) {
			req.outHeaderBuf = out[0]
			out = out[1:]
		} else {
			ps.opts.Logger.Printf("op %v: got %v, out iov should start with 16 bytes", h.Name, iovLens(startOut))
			return 0, EIO
		}

		if outSize > 0 {
			if len(out) > 0 && len(out[0]) == outSize {
				req.outDataBuf = out[0]
				out = out[1:]
			} else {
				ps.opts.Logger.Printf("op %v: got %v, outData iov should have %d bytes", h.Name, iovLens(startOut), outSize)
				return 0, EIO
			}
		}

		payloadOut = out
		// READLINK has no request field declaring the maximum response size.
		// The guest communicates that limit solely through the remaining
		// writable descriptors, so use their aggregate capacity. Other
		// variable-size operations carry an explicit size parsed above.
		if h.OpCode == int(_OP_READLINK) {
			outPayloadSize = iovLen(payloadOut)
		}
		if iovLen(payloadOut) < outPayloadSize {
			ps.opts.Logger.Printf("op %s: got %v, payload iov should have %d bytes", h.Name, iovLens(startOut), outPayloadSize)
			return 0, EIO
		}
		if outPayloadSize != 0 {
			req.outPayload = make([]byte, outPayloadSize)
		}
	}

	ps.protocolServer.handleRequest(h, &req)
	if len(req.outPayload) > outPayloadSize {
		ps.opts.Logger.Printf("op %s: produced %d payload bytes, response has room for %d", h.Name, len(req.outPayload), outPayloadSize)
		return 0, EIO
	}
	copyBytesToIOV(payloadOut, req.outPayload)

	// Per the virtio spec, vring_used_elem.len should hold the
	// number of bytes the device wrote to the descriptor
	// chain. Returning more  inflates the live-migration dirty-page
	// log and violates the spec.
	return int(sizeOfOutHeader) + len(req.outDataBuf) + len(req.outPayload), 0
}

func copyIOVToBytes(dst []byte, src [][]byte) int {
	offset := 0
	for _, part := range src {
		offset += copy(dst[offset:], part)
		if offset == len(dst) {
			break
		}
	}
	return offset
}

func copyBytesToIOV(dst [][]byte, src []byte) int {
	offset := 0
	for _, part := range dst {
		offset += copy(part, src[offset:])
		if offset == len(src) {
			break
		}
	}
	return offset
}

func iovLens(in [][]byte) []int {
	var lens []int
	for _, b := range in {
		lens = append(lens, len(b))
	}
	return lens
}
