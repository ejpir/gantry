//go:build linux || darwin

package sandbox

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
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
	mu       sync.Mutex
	started  time.Time
	requests uint64
	errors   uint64
	handler  time.Duration
	maximum  time.Duration
	byOpcode map[uint32]*vhostOpcodeStats
	records  [64]vhostShareRecord
}

func newVhostShareStats() *vhostShareStats {
	if os.Getenv("GANTRY_VHOST_STATS") == "" {
		return nil
	}
	return &vhostShareStats{started: time.Now(), byOpcode: make(map[uint32]*vhostOpcodeStats)}
}

func (s *vhostShareStats) observe(in, out [][]byte, written int, status fuse.Status, elapsed time.Duration) {
	if s == nil {
		return
	}
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
	if s.requests%25000 == 0 {
		s.logLocked()
	}
	s.mu.Unlock()
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
		"vhost-share-stats: requests=%d errors=%d wall=%s handler-total=%s handler-avg=%s handler-max=%s ops(count/avg/max)=[%s]\n",
		s.requests, s.errors, wall.Round(time.Millisecond), s.handler.Round(time.Millisecond),
		time.Duration(int64(s.handler)/int64(s.requests)).Round(time.Microsecond), s.maximum.Round(time.Microsecond), operations.String())
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
