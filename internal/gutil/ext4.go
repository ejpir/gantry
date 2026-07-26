package gutil

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

// ext4.go — read the ext4 superblock host-side, for an honest rwlayer
// diagnosis before boot. The superblock sits at byte offset 1024; field
// offsets verified against dumpe2fs. We read a handful of fields only:
// state, mount count, error counters, and the recorded last-error
// function — exactly what "stale file handle" hints need to stop being
// guesses.

// Ext4Info is the interesting slice of an ext4 superblock.
type Ext4Info struct {
	State        uint16 // 1 = cleanly unmounted, 2 = errors detected
	MountCount   uint16
	ErrorCount   uint32
	LastErrTime  time.Time // zero when no error recorded
	LastErrFunc  string    // e.g. "ext4_validate_block_bitmap"
	FirstErrFunc string
}

// Ext4StateError is the s_state bit for "errors detected".
const Ext4StateError = 2

// ProbeExt4 parses the superblock of an ext2/3/4 image. Returns an error
// for non-ext images (bad magic).
func ProbeExt4(path string) (*Ext4Info, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var sb [2048]byte
	if _, err := f.ReadAt(sb[:], 1024); err != nil {
		return nil, err
	}
	if magic := binary.LittleEndian.Uint16(sb[56:58]); magic != 0xef53 {
		return nil, fmt.Errorf("%s is not ext2/3/4 (magic %#x)", path, magic)
	}
	// field offsets from fs/ext4/ext4.h (struct ext4_super_block)
	info := &Ext4Info{
		State:        binary.LittleEndian.Uint16(sb[58:60]),
		MountCount:   binary.LittleEndian.Uint16(sb[52:54]),
		ErrorCount:   binary.LittleEndian.Uint32(sb[0x170:0x174]),
		FirstErrFunc: cstr(sb[0x184:0x1A4]),
		LastErrFunc:  cstr(sb[0x1BC:0x1DC]),
	}
	if ts := binary.LittleEndian.Uint32(sb[0x1A8:0x1AC]); ts != 0 {
		info.LastErrTime = time.Unix(int64(ts), 0)
	}
	return info, nil
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// Diagnosis is a one-line human summary for warnings.
func (i *Ext4Info) Diagnosis() string {
	if i.ErrorCount == 0 && i.State&Ext4StateError == 0 {
		return "healthy"
	}
	s := fmt.Sprintf("filesystem recorded %d error(s)", i.ErrorCount)
	if i.LastErrFunc != "" {
		s += " — last: " + i.LastErrFunc
		if !i.LastErrTime.IsZero() {
			s += " at " + i.LastErrTime.Format("2006-01-02 15:04:05")
		}
	}
	return s
}
