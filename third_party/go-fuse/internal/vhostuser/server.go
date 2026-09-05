// Copyright 2024 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vhostuser

import (
	"fmt"
	"io"
	"log"
	"net"
	"reflect"
	"syscall"
	"unsafe"
)

/*
   Vhost-user requires host and guest to be the same architecture (the
  guest directly maps host memory and uses host virtual addresses for
  the vring pointers), so they will always have the same endianness.

  The virtio spec defines the ring fields as little-endian, and
  le16toh is there for correctness in the general case, but on a
  little-endian host (x86-64, ARM64 in LE mode -- the only
  architectures where vhost-user is used in practice) it compiles to a
  no-op.
*/

// Following comment from claude

// Ring implements the virtio split-ring (virtqueue) shared memory protocol.
// The ring is the data-plane interface between the guest (driver) and the
// host (device). All three sub-structures ( Desc, Avail, Used ) reside in
// guest-physical memory that is mapped by both sides.
//
// Memory layout (legacy/split ring, num must be a power of 2):
//
//	[ desc[0..num-1]      ]  16 bytes each, guest+host readable
//	[ avail.flags         ]  uint16, written by guest
//	[ avail.idx           ]  uint16, written by guest
//	[ avail.ring[0..num-1]]  uint16 each, written by guest
//	[ avail.used_event    ]  uint16, written by guest (if EVENT_IDX)
//	[ <padding to 4k>     ]
//	[ used.flags          ]  uint16, written by host
//	[ used.idx            ]  uint16, written by host
//	[ used.ring[0..num-1] ]  8 bytes each, written by host
//	[ used.avail_event    ]  uint16, written by host (if EVENT_IDX)
//
// Descriptor table (Desc):
//
//	Each entry describes one guest-physical memory buffer:
//	  addr  uint64  guest-physical address
//	  len   uint32  length in bytes
//	  flags uint16  NEXT (chained), WRITE (host-writable), INDIRECT
//	  next  uint16  index of next descriptor if NEXT flag is set
//
//	A descriptor chain is a linked list starting from a head descriptor.
//	Chains allow scatter-gather: a single logical request can span multiple
//	non-contiguous buffers. By convention, read-only buffers (guest -> host)
//	come before write-only buffers (host -> guest) in a chain.
//
//	If the INDIRECT flag is set, addr/len point to a guest buffer that itself
//	contains an array of descriptors, allowing longer chains than num permits.
//
//	The descriptor table is allocated by the guest and populated before the
//	head index is published in the avail ring. The host must treat all fields
//	as potentially hostile (malicious guest), validating addr, len and next
//	before dereferencing them.
//
// Available ring (Avail), written by guest, read by host:
//
//	avail.ring[] holds descriptor head indices (into Desc) of requests the
//	guest has prepared and is handing to the host.
//	avail.idx is a free-running uint16 counter (wraps at 65536, not at num).
//	The host tracks last_avail_idx; the difference (uint16 arithmetic) is the
//	number of new entries to consume. The ring slot for counter value n is
//	n % num.
//
//	Guest publish sequence:
//	  1. Write descriptor chain into Desc[].
//	  2. Write head index into avail.ring[avail.idx % num].
//	  3. WriteBarrier()                  -- ensure 1+2 visible before 4.
//	  4. avail.idx++                     -- publish to host.
//	  5. FullBarrier()                   -- store-load fence.
//	  6. If !(used.flags & NO_NOTIFY): kick host via eventfd.
//
// Used ring (Used), written by host, read by guest:
//
//	used.ring[] holds completed requests: id (descriptor head index) and
//	len (bytes written into the chain's writable buffers).
//	used.idx is a free-running uint16 counter, same wrapping rules as avail.idx.
//
//	Host completion sequence:
//	  1. Write used.ring[used_idx % num] = {id, len}.
//	  2. WriteBarrier()                  -- ensure 1 visible before 3.
//	  3. used.idx++                      -- publish to guest.
//	  4. FullBarrier()                   -- store-load fence.
//	  5. Read used_event (avail.ring[num]) to decide whether to notify.
//	  6. If notification needed: signal guest via call eventfd.
//
// Notification suppression (VIRTIO_RING_F_EVENT_IDX):
//
//	Instead of a simple NO_NOTIFY flag, each side publishes a threshold:
//	  used_event  (in avail.ring[num]):  guest tells host "notify me when
//	              used.idx reaches this value".
//	  avail_event (in used.ring[num]):   host tells guest "kick me when
//	              avail.idx reaches this value".
//	This allows coalescing: the host skips the call fd write unless
//	used.idx has just crossed the threshold the guest requested. The
//	FullBarrier between writing used.idx and reading used_event is
//	essential: without it the host might read a stale threshold and
//	skip a notification the guest is waiting for.
//
// Ownership:
//
//	The descriptor table and avail ring belong to the guest; the host
//	reads them. The used ring belongs to the host; the guest reads it.
//	Both sides may read each other's fields but must only write their own.
//	The host must never trust the guest's fields for safety. Chain
//	traversal must validate every index and length before use.
type Ring struct {
	// Constant
	Num   int
	Flags uint32

	// Guest physical address of the logging bitmap; resolved lazily when
	// LOG_SHMFD-based logging is actually used.
	LogGuestAddr uint64

	// Num entries
	Desc  []VringDesc
	Avail *VringAvail

	// Num entries
	AvailRing      []uint16
	AvailUsedEvent *uint16
	Used           *VringUsed

	// Num entries
	UsedRing       []VringUsedElement
	UsedAvailEvent *uint16
}

func (r *Ring) Initialized() bool {
	return r.Avail != nil
}

type VirtqInflight struct {
	Features      uint64
	Version       uint16
	DescNum       uint16
	LastBatchHead uint16
	UsedIdx       uint16

	Desc0 DescStateSplit // array.
}

type DescStateSplit struct {
	inflight uint8
	padding  [5]uint8
	next     uint16
	counter  uint64
}

type InflightDesc struct {
	index   uint16
	counter uint64
}

// Server implements the vhost-user protocol, which sets up the virtqs
// through a unix socket connection.
type Server struct {
	conn   *net.UnixConn
	device *Device

	Debug bool
}

func NewServer(c *net.UnixConn, d *Device) *Server {
	return &Server{conn: c, device: d}
}

func (s *Server) Close() error {
	s.conn.Close()
	s.device.Close()
	return nil
}

func (s *Server) Serve() error {
	for {
		if err := s.oneRequest(); err != nil {
			return err
		}
	}
}

func (s *Server) getProtocolFeatures(rep *GetProtocolFeaturesReply) {
	rep.Mask = composeMask(s.device.GetProtocolFeatures())
}
func (s *Server) setProtocolFeatures(rep *SetProtocolFeaturesRequest) {
}

func (s *Server) getFeatures(rep *GetFeaturesReply) {
	rep.Mask = composeMask(s.device.GetFeatures())
}

func (s *Server) setFeatures(rep *SetFeaturesRequest) {
	features := make([]int, 0, 8)
	for bit := 0; bit < 64; bit++ {
		if rep.Mask&(uint64(1)<<bit) != 0 {
			features = append(features, bit)
		}
	}
	s.device.SetFeatures(features)
}

const hdrSize = int(unsafe.Sizeof(Header{}))

const (
	_VERSION_MASK = 0x3
	_VERSION      = 0x1
	_REPLY        = 0x1 << 2
	_NEED_REPLY   = 0x1 << 3

	// Every request currently supported by this backend carries at most one
	// descriptor. Bound ancillary input before the request header is trusted.
	maxRequestFDs = 1
)

type requestSpec struct {
	payloadSize uint32
	fdCount     int
}

var requestSpecs = map[uint32]requestSpec{
	REQ_GET_FEATURES:          {},
	REQ_SET_FEATURES:          {payloadSize: uint32(unsafe.Sizeof(SetFeaturesRequest{}))},
	REQ_SET_OWNER:             {},
	REQ_SET_VRING_NUM:         {payloadSize: uint32(unsafe.Sizeof(VhostVringState{}))},
	REQ_SET_VRING_ADDR:        {payloadSize: uint32(unsafe.Sizeof(VhostVringAddr{}))},
	REQ_SET_VRING_BASE:        {payloadSize: uint32(unsafe.Sizeof(VhostVringState{}))},
	REQ_SET_VRING_KICK:        {payloadSize: uint32(unsafe.Sizeof(U64Payload{})), fdCount: 1},
	REQ_SET_VRING_CALL:        {payloadSize: uint32(unsafe.Sizeof(U64Payload{})), fdCount: 1},
	REQ_SET_VRING_ERR:         {payloadSize: uint32(unsafe.Sizeof(U64Payload{})), fdCount: 1},
	REQ_GET_PROTOCOL_FEATURES: {},
	REQ_SET_PROTOCOL_FEATURES: {payloadSize: uint32(unsafe.Sizeof(SetProtocolFeaturesRequest{}))},
	REQ_GET_QUEUE_NUM:         {},
	REQ_SET_VRING_ENABLE:      {payloadSize: uint32(unsafe.Sizeof(VhostVringState{}))},
	REQ_GET_MAX_MEM_SLOTS:     {},
	REQ_ADD_MEM_REG:           {payloadSize: uint32(unsafe.Sizeof(VhostUserMemRegMsg{})), fdCount: 1},
}

func closeReceivedFDs(fds []int) {
	for _, fd := range fds {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
	}
}

func appendUnixRights(oob []byte, fds *[]int) error {
	if len(oob) == 0 {
		return nil
	}
	scms, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return fmt.Errorf("parse control message: %w", err)
	}
	for _, scm := range scms {
		if scm.Header.Level != syscall.SOL_SOCKET || scm.Header.Type != syscall.SCM_RIGHTS {
			return fmt.Errorf("unsupported control message level=%d type=%d", scm.Header.Level, scm.Header.Type)
		}
		rights, err := syscall.ParseUnixRights(&scm)
		if err != nil {
			return fmt.Errorf("parse unix rights: %w", err)
		}
		for _, fd := range rights {
			syscall.CloseOnExec(fd)
		}
		*fds = append(*fds, rights...)
		if len(*fds) > maxRequestFDs {
			return fmt.Errorf("received %d fds, maximum is %d", len(*fds), maxRequestFDs)
		}
	}
	return nil
}

// readRequestBytes reads exactly len(dst) stream bytes and collects rights
// attached to every recvmsg chunk. A sender may fragment either the header or
// payload, and SCM_RIGHTS can legally arrive with either one.
func (s *Server) readRequestBytes(dst []byte, fds *[]int) error {
	for len(dst) > 0 {
		var oob [4096]byte
		n, oobN, flags, _, err := s.conn.ReadMsgUnix(dst, oob[:])
		if appendErr := appendUnixRights(oob[:oobN], fds); appendErr != nil {
			return appendErr
		}
		if flags&(syscall.MSG_CTRUNC|syscall.MSG_TRUNC) != 0 {
			return fmt.Errorf("truncated recvmsg flags %#x", flags)
		}
		if n > 0 {
			dst = dst[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

// oneRequest reads and handles one vhost-user message from the connection.
func (s *Server) oneRequest() error {
	var inBuf, outBuf [4096]byte
	var inFDs []int
	defer func() { closeReceivedFDs(inFDs) }()
	if err := s.readRequestBytes(inBuf[:hdrSize], &inFDs); err != nil {
		return fmt.Errorf("read vhost-user header: %w", err)
	}

	inHeader := (*Header)(unsafe.Pointer(&inBuf[0]))
	reqName := reqNames[int(inHeader.Request)]
	if reqName == "" {
		reqName = fmt.Sprintf("request %d", inHeader.Request)
	}
	if inHeader.Flags&_VERSION_MASK != _VERSION || inHeader.Flags&^uint32(_VERSION_MASK|_NEED_REPLY) != 0 {
		return fmt.Errorf("invalid flags %#x for %s", inHeader.Flags, reqName)
	}
	spec, ok := requestSpecs[inHeader.Request]
	if !ok {
		return fmt.Errorf("unsupported operation %s", reqName)
	}
	if inHeader.Size != spec.payloadSize {
		return fmt.Errorf("payload size %d for %s, want %d", inHeader.Size, reqName, spec.payloadSize)
	}
	if inHeader.Size > 0 {
		if err := s.readRequestBytes(inBuf[hdrSize:hdrSize+int(inHeader.Size)], &inFDs); err != nil {
			return fmt.Errorf("read %s payload: %w", reqName, err)
		}
	}
	if len(inFDs) != spec.fdCount {
		return fmt.Errorf("got %d fds for %s, want %d", len(inFDs), reqName, spec.fdCount)
	}
	for _, fd := range inFDs {
		if err := syscall.SetNonblock(fd, true); err != nil {
			return fmt.Errorf("set %s fd nonblocking: %w", reqName, err)
		}
	}

	needReply := (inHeader.Flags & _NEED_REPLY) != 0
	inPayload := unsafe.Pointer(&inBuf[hdrSize])
	if s.Debug {
		inDebug := ""
		if f := decodeIn[inHeader.Request]; f != nil {
			inDebug = fmt.Sprintf("%v", f(inPayload))
		} else if inHeader.Size > 0 {
			inDebug = fmt.Sprintf("payload %q (%d bytes)", inBuf[hdrSize:hdrSize+int(inHeader.Size)], inHeader.Size)
		}

		flagStr := ""
		if needReply {
			flagStr = "need_reply "
		}
		log.Printf("rx %-2d %s %s %sFDs %v", inHeader.Request, reqName, inDebug, flagStr, inFDs)
	}

	var outHeader = (*Header)(unsafe.Pointer(&outBuf[0]))
	outPayloadPtr := unsafe.Pointer(&outBuf[hdrSize])
	inPayloadPtr := unsafe.Pointer(&inBuf[hdrSize])
	*outHeader = *inHeader
	outHeader.Flags |= _REPLY
	outHeader.Flags &^= _NEED_REPLY

	// Most control-plane mutations run under the dispatch write lock so they
	// cannot race vring dequeue. SET_VRING_ENABLE manages that lock internally:
	// disabling must release it before joining a reader that may be waiting on
	// the read side.
	var rep any
	var deviceErr error
	dispatch := func() {
		switch inHeader.Request {
		case REQ_GET_FEATURES:
			r := (*GetFeaturesReply)(outPayloadPtr)
			s.getFeatures(r)
			rep = r
		case REQ_SET_FEATURES:
			req := (*SetFeaturesRequest)(inPayloadPtr)
			s.setFeatures(req)
		case REQ_GET_PROTOCOL_FEATURES:
			r := (*GetProtocolFeaturesReply)(outPayloadPtr)
			s.getProtocolFeatures(r)
			rep = r
		case REQ_SET_PROTOCOL_FEATURES:
			req := (*SetProtocolFeaturesRequest)(inPayloadPtr)
			s.setProtocolFeatures(req)

		case REQ_GET_QUEUE_NUM:
			r := (*U64Payload)(outPayloadPtr)
			r.Num = s.device.GetQueueNum()
			rep = r
		case REQ_GET_MAX_MEM_SLOTS:
			r := (*U64Payload)(outPayloadPtr)
			r.Num = s.device.regions.GetMaxMemslots()
			rep = r
		case REQ_SET_OWNER:
			s.device.SetOwner()
		case REQ_SET_VRING_CALL:
			req := (*U64Payload)(inPayloadPtr)
			deviceErr = s.device.SetVringCall(inFDs[0], req.Num)
			if deviceErr == nil {
				inFDs[0] = -1
			}
		case REQ_SET_VRING_ERR:
			req := (*U64Payload)(inPayloadPtr)
			deviceErr = s.device.SetVringErr(inFDs[0], req.Num)
			if deviceErr == nil {
				inFDs[0] = -1
			}
		case REQ_SET_VRING_KICK:
			req := (*U64Payload)(inPayloadPtr)
			deviceErr = s.device.SetVringKick(inFDs[0], req.Num)
			if deviceErr == nil {
				inFDs[0] = -1
			}
		case REQ_ADD_MEM_REG:
			req := (*VhostUserMemRegMsg)(inPayloadPtr)
			fd := inFDs[0]
			inFDs[0] = -1 // AddMemReg consumes the fd on every return path.
			deviceErr = s.device.regions.AddMemReg(fd, &req.Region)
		case REQ_SET_VRING_NUM:
			req := (*VhostVringState)(inPayloadPtr)
			deviceErr = s.device.SetVringNum(req)
		case REQ_SET_VRING_BASE:
			req := (*VhostVringState)(inPayloadPtr)
			deviceErr = s.device.SetVringBase(req)
		case REQ_SET_VRING_ENABLE:
			req := (*VhostVringState)(inPayloadPtr)
			deviceErr = s.device.SetVringEnable(req)
		case REQ_SET_VRING_ADDR:
			req := (*VhostVringAddr)(inPayloadPtr)
			deviceErr = s.device.SetVringAddr(req)
		default:
			panic("validated request lacks dispatch")
		}
	}
	if inHeader.Request == REQ_SET_VRING_ENABLE {
		dispatch()
	} else {
		s.device.dispatchMu.Lock()
		dispatch()
		s.device.dispatchMu.Unlock()
	}

	outPayloadSz := 0
	if needReply && rep == nil {
		r := (*U64Payload)(outPayloadPtr)
		if deviceErr != nil {
			log.Printf("request error: %v", deviceErr)
			r.Num = 1
		} else {
			r.Num = 0
		}
		rep = r
	} else if deviceErr != nil {
		log.Printf("device error: %v", deviceErr)
	}

	var repBytes []byte
	if rep != nil {
		outPayloadSz = int(reflect.ValueOf(rep).Elem().Type().Size())
		outHeader.Size = uint32(outPayloadSz)
		repBytes = outBuf[:hdrSize+outPayloadSz]
	}
	if s.Debug {
		outDebug := "no reply"
		if rep != nil {
			if s, ok := rep.(fmt.Stringer); ok {
				outDebug = s.String()
			} else {
				outDebug = fmt.Sprintf("payload %q (%d bytes)", repBytes[hdrSize:], outPayloadSz)
			}
		}

		log.Printf("tx    %s %s", reqName, outDebug)
	}
	if len(repBytes) > 0 {
		if _, err := s.conn.Write(repBytes); err != nil {
			log.Printf("%v %T", err, err)
			return err
		}
	}
	return nil
}
