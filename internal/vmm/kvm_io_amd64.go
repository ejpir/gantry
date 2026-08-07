//go:build linux && amd64

package vmm

import "github.com/ejpir/gantry/internal/gutil"

// Port-I/O exit fields (x86); only the amd64 backend decodes IO exits.
func (r kvmRunStruct) ioDir() uint8    { return r.data[32] } // 0 = IN, 1 = OUT
func (r kvmRunStruct) ioSize() uint8   { return r.data[33] }
func (r kvmRunStruct) ioPort() uint16  { return uint16(gutil.LE32(r.data[34:])) }
func (r kvmRunStruct) ioCount() uint32 { return gutil.LE32(r.data[36:]) }
func (r kvmRunStruct) ioData() []byte  { return r.data[r.ioDataOff():] }
func (r kvmRunStruct) ioDataOff() uint64 {
	return gutil.LE64(r.data[40:])
}
