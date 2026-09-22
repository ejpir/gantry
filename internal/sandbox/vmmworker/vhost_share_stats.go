//go:build linux || darwin

package vmmworker

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

type vhostShareRecord struct {
	request               uint64
	unique                uint64
	opcode                uint32
	status                fuse.Status
	wireErrno             int32
	written               int
	readCount, writeCount uint8
	readLens, writeLens   [8]uint32
	elapsed               time.Duration
}

type vhostOpcodeStats struct {
	requests uint64
	handler  time.Duration
	maximum  time.Duration
}

type vhostShareStats struct {
	mu                sync.Mutex
	started           time.Time
	lastFinished      time.Time
	maximumRequestGap time.Duration
	requestGapAfter   uint64
	requests          uint64
	errors            uint64
	handler           time.Duration
	maximum           time.Duration
	logEvery          uint64
	trace             int
	byOpcode          map[uint32]*vhostOpcodeStats
	records           [64]vhostShareRecord
}

func newVhostShareStats() *vhostShareStats {
	if os.Getenv("GANTRY_VHOST_STATS") == "" {
		return nil
	}
	started := time.Now()
	trace := 0
	if os.Getenv("GANTRY_VHOST_TRACE") == "1" {
		trace = 600
	}
	return &vhostShareStats{
		started: started, lastFinished: started, logEvery: statsLogEvery(), trace: trace,
		byOpcode: make(map[uint32]*vhostOpcodeStats),
	}
}

// statsLogEvery keeps the default cadence at 25k requests while allowing
// fine-grained request counting for small diagnostic probes.
func statsLogEvery() uint64 {
	value := os.Getenv("GANTRY_VHOST_STATS_EVERY")
	if value == "" {
		return 25000
	}
	every, err := strconv.ParseUint(strings.TrimSpace(value), 10, 20)
	if err != nil || every == 0 || every > 25000 {
		return 25000
	}
	return every
}

func (s *vhostShareStats) observe(in, out [][]byte, written int, status fuse.Status, elapsed time.Duration) {
	if s == nil {
		return
	}
	finished := time.Now()
	started := finished.Add(-elapsed)
	var opcode uint32
	var unique uint64
	if len(in) != 0 && len(in[0]) >= 16 {
		opcode = binary.LittleEndian.Uint32(in[0][4:8])
		unique = binary.LittleEndian.Uint64(in[0][8:16])
	}
	var wireErrno int32
	if len(out) != 0 && len(out[0]) >= 8 {
		wireErrno = int32(binary.LittleEndian.Uint32(out[0][4:8]))
	}
	record := vhostShareRecord{
		unique: unique, opcode: opcode, status: status, wireErrno: wireErrno,
		written: written, elapsed: elapsed,
	}
	for index := 0; index < len(in) && index < len(record.readLens); index++ {
		record.readLens[index] = uint32(len(in[index]))
		record.readCount++
	}
	for index := 0; index < len(out) && index < len(record.writeLens); index++ {
		record.writeLens[index] = uint32(len(out[index]))
		record.writeCount++
	}

	s.mu.Lock()
	if s.trace > 0 {
		s.trace--
		s.traceLocked(in, out, opcode, unique)
	}
	if started.After(s.lastFinished) {
		gap := started.Sub(s.lastFinished)
		if gap > s.maximumRequestGap {
			s.maximumRequestGap = gap
			s.requestGapAfter = s.requests
		}
	}
	if finished.After(s.lastFinished) {
		s.lastFinished = finished
	}
	s.requests++
	record.request = s.requests
	s.records[(s.requests-1)%uint64(len(s.records))] = record
	opcodeStats := s.byOpcode[opcode]
	if opcodeStats == nil {
		opcodeStats = new(vhostOpcodeStats)
		s.byOpcode[opcode] = opcodeStats
	}
	opcodeStats.requests++
	opcodeStats.handler += elapsed
	if elapsed > opcodeStats.maximum {
		opcodeStats.maximum = elapsed
	}
	s.handler += elapsed
	if elapsed > s.maximum {
		s.maximum = elapsed
	}
	if status != fuse.OK || wireErrno != 0 {
		s.errors++
		if s.errors <= 20 {
			fmt.Fprintf(os.Stderr, "vhost-share-error: request=%d unique=%d op=%s transport=%v errno=%d elapsed=%s\n",
				s.requests, unique, fuseOpcodeName(opcode), status, wireErrno, elapsed.Round(time.Microsecond))
		}
		if s.errors == 1 {
			s.dumpFlightLocked()
		}
	}
	if s.requests%s.logEvery == 0 {
		s.logLocked()
	}
	s.mu.Unlock()
}

// traceLocked dumps the fields which decide guest cache behaviour for the
// metadata-heavy opcodes. EntryOut/AttrOut validity windows are the only
// mechanism by which the guest may skip a round trip; printing them on the
// wire settles whether the server or the guest discards caching.
func (s *vhostShareStats) traceLocked(in, out [][]byte, opcode uint32, unique uint64) {
	if opcode != 1 && opcode != 3 && opcode != 52 { // lookup, getattr, statx
		return
	}
	var nodeID uint64
	if len(in) != 0 && len(in[0]) >= 24 {
		nodeID = binary.LittleEndian.Uint64(in[0][16:24])
	}
	line := fmt.Sprintf("vhost-share-trace: request=%d unique=%d op=%s node=%d",
		s.requests+1, unique, fuseOpcodeName(opcode), nodeID)
	if len(out) >= 2 {
		data := out[1]
		switch opcode {
		case 1: // EntryOut: nodeid, generation, entryValid, attrValid, entryValidNSec, attrValidNSec
			if len(data) >= 40 {
				line += fmt.Sprintf(" entry-valid=%ds attr-valid=%ds out-node=%d",
					binary.LittleEndian.Uint64(data[16:24]), binary.LittleEndian.Uint64(data[24:32]),
					binary.LittleEndian.Uint64(data[0:8]))
			}
		case 3, 52: // AttrOut/StatxOut: attrValid, attrValidNSec, ...
			if len(data) >= 8 {
				line += fmt.Sprintf(" attr-valid=%ds", binary.LittleEndian.Uint64(data[0:8]))
			}
		}
	}
	fmt.Fprintln(os.Stderr, line)
}

func (s *vhostShareStats) dumpFlightLocked() {
	first := uint64(1)
	if s.requests > 15 {
		first = s.requests - 15
	}
	fmt.Fprintf(os.Stderr, "vhost-share-flight: last requests %d..%d\n", first, s.requests)
	for request := first; request <= s.requests; request++ {
		record := s.records[(request-1)%uint64(len(s.records))]
		if record.request != request {
			continue
		}
		fmt.Fprintf(os.Stderr,
			"vhost-share-flight: request=%d unique=%d op=%s in=%v out=%v written=%d transport=%v errno=%d elapsed=%s\n",
			record.request, record.unique, fuseOpcodeName(record.opcode),
			record.readLens[:record.readCount], record.writeLens[:record.writeCount], record.written,
			record.status, record.wireErrno, record.elapsed.Round(time.Microsecond))
	}
}

func (s *vhostShareStats) logLocked() {
	keys := make([]int, 0, len(s.byOpcode))
	for opcode := range s.byOpcode {
		keys = append(keys, int(opcode))
	}
	sort.Ints(keys)
	var operations strings.Builder
	for _, key := range keys {
		if operations.Len() != 0 {
			operations.WriteByte(',')
		}
		stats := s.byOpcode[uint32(key)]
		average := time.Duration(0)
		if stats.requests != 0 {
			average = time.Duration(int64(stats.handler) / int64(stats.requests))
		}
		fmt.Fprintf(&operations, "%s=%d/%s/%s", fuseOpcodeName(uint32(key)), stats.requests,
			average.Round(time.Microsecond), stats.maximum.Round(time.Microsecond))
	}
	wall := time.Since(s.started)
	fmt.Fprintf(os.Stderr,
		"vhost-share-stats: requests=%d errors=%d wall=%s handler-total=%s handler-avg=%s handler-max=%s request-gap-max=%s(after=%d) ops(count/avg/max)=[%s]\n",
		s.requests, s.errors, wall.Round(time.Millisecond), s.handler.Round(time.Millisecond),
		time.Duration(int64(s.handler)/int64(s.requests)).Round(time.Microsecond), s.maximum.Round(time.Microsecond),
		s.maximumRequestGap.Round(time.Millisecond), s.requestGapAfter, operations.String())
}

func fuseOpcodeName(opcode uint32) string {
	switch opcode {
	case 1:
		return "lookup"
	case 2:
		return "forget"
	case 3:
		return "getattr"
	case 14:
		return "open"
	case 15:
		return "read"
	case 16:
		return "write"
	case 17:
		return "statfs"
	case 18:
		return "release"
	case 25:
		return "flush"
	case 26:
		return "init"
	case 27:
		return "opendir"
	case 28:
		return "readdir"
	case 29:
		return "releasedir"
	case 34:
		return "interrupt"
	case 40:
		return "poll"
	case 42:
		return "batch-forget"
	case 44:
		return "readdirplus"
	case 52:
		return "statx"
	default:
		return fmt.Sprintf("op%d", opcode)
	}
}
