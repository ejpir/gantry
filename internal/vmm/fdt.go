package vmm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gantry/internal/virtio"
	"sort"
)

// This is a minimal Flattened Device Tree (DTB) writer. The VMM builds the
// exact tree a Linux arm64 kernel needs to boot: memory, CPUs, PSCI, GICv3,
// architected timer, and a PL011 UART for the serial console. It mirrors
// what kvmtool / Firecracker generate, minus virtio devices.

// Guest physical memory map (aligned with QEMU's "virt" machine conventions).
const (
	gicdBase = 0x08000000 // GICv3 distributor, 64 KiB
	gicdSize = 0x10000
	gicrBase = 0x080A0000 // GICv3 redistributors (2x64K frames per vCPU)

	uartBase = 0x09000000 // PL011
	uartSize = 0x1000
	uartIRQ  = 33 // GIC SPI 1 -> INTID 33

	ramBase = 0x40000000
)

const (
	fdtBeginNode = 1
	fdtEndNode   = 2
	fdtProp      = 3
	fdtEnd       = 9
	fdtMagic     = 0xd00dfeed
)

type fdtBuilder struct {
	strct   bytes.Buffer
	strs    []string
	strOff  map[string]uint32
	strSize uint32
}

func newFDT() *fdtBuilder {
	return &fdtBuilder{strOff: map[string]uint32{}}
}

func (f *fdtBuilder) putBE32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	f.strct.Write(b[:])
}

func (f *fdtBuilder) align4() {
	for f.strct.Len()%4 != 0 {
		f.strct.WriteByte(0)
	}
}

func (f *fdtBuilder) beginNode(name string) {
	f.putBE32(fdtBeginNode)
	f.strct.WriteString(name)
	f.strct.WriteByte(0)
	f.align4()
}

func (f *fdtBuilder) endNode() { f.putBE32(fdtEndNode) }

func (f *fdtBuilder) strOffset(name string) uint32 {
	if off, ok := f.strOff[name]; ok {
		return off
	}
	// dedupe property name strings
	f.strs = append(f.strs, name)
	off := f.strSize
	f.strOff[name] = off
	f.strSize += uint32(len(name)) + 1
	return off
}

func (f *fdtBuilder) propRaw(name string, val []byte) {
	f.putBE32(fdtProp)
	f.putBE32(uint32(len(val)))
	f.putBE32(f.strOffset(name))
	f.strct.Write(val)
	f.align4()
}

func (f *fdtBuilder) propU32(name string, vals ...uint32) {
	var b bytes.Buffer
	for _, v := range vals {
		var tmp [4]byte
		binary.BigEndian.PutUint32(tmp[:], v)
		b.Write(tmp[:])
	}
	f.propRaw(name, b.Bytes())
}

func (f *fdtBuilder) propU64(name string, vals ...uint64) {
	var b bytes.Buffer
	for _, v := range vals {
		var tmp [8]byte
		binary.BigEndian.PutUint64(tmp[:], v)
		b.Write(tmp[:])
	}
	f.propRaw(name, b.Bytes())
}

func (f *fdtBuilder) propStr(name string, vals ...string) {
	var b bytes.Buffer
	for _, v := range vals {
		b.WriteString(v)
		b.WriteByte(0)
	}
	f.propRaw(name, b.Bytes())
}

func (f *fdtBuilder) propEmpty(name string) { f.propRaw(name, nil) }

// build produces the final DTB. All multi-byte header fields are big-endian.
func (f *fdtBuilder) build() []byte {
	f.putBE32(fdtEnd)

	strBlock := bytes.Buffer{}
	// keep deterministic order == insertion order (already unique)
	for _, s := range f.strs {
		strBlock.WriteString(s)
		strBlock.WriteByte(0)
	}

	const headerSize = 40
	rsvmap := make([]byte, 16) // single terminating zero entry
	structBytes := f.strct.Bytes()
	strBytes := strBlock.Bytes()

	total := headerSize + len(rsvmap) + len(structBytes) + len(strBytes)
	out := bytes.Buffer{}
	be32 := func(v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		out.Write(b[:])
	}
	be32(fdtMagic)                                   // magic
	be32(uint32(total))                              // totalsize
	be32(headerSize + 16)                            // off_dt_struct
	be32(uint32(headerSize + 16 + len(structBytes))) // off_dt_strings
	be32(headerSize)                                 // off_mem_rsvmap
	be32(17)                                         // version
	be32(16)                                         // last_comp_version
	be32(0)                                          // boot_cpuid_phys
	be32(uint32(len(strBytes)))                      // size_dt_strings
	be32(uint32(len(structBytes)))                   // size_dt_struct
	out.Write(rsvmap)
	out.Write(structBytes)
	out.Write(strBytes)
	return out.Bytes()
}

// buildGuestFDT renders the device tree for our VM.
// memSize in bytes; initrdStart/End are guest-physical (0 = no initrd);
// nVirtio virtio-mmio devices are declared at 0x0a000000+i*0x200, SPI 16+i.
func buildGuestFDT(memSize uint64, initrdStart, initrdEnd uint64, cmdline string, nVirtio int, nCPU ...int) []byte {
	vcpus := 1
	if len(nCPU) > 0 && nCPU[0] > 0 {
		vcpus = nCPU[0]
	}
	f := newFDT()

	f.beginNode("") // root
	f.propU32("#address-cells", 2)
	f.propU32("#size-cells", 2)
	f.propStr("compatible", "linux,dummy-virt")
	f.propStr("model", "gantry")
	f.propU32("interrupt-parent", 1) // &gic

	// /chosen
	f.beginNode("chosen")
	f.propStr("bootargs", cmdline)
	if initrdStart != 0 {
		f.propU64("linux,initrd-start", initrdStart)
		f.propU64("linux,initrd-end", initrdEnd)
	}
	f.propU64("kaslr-seed", 0) // 0 = KASLR off: PC maps 1:1 to the kernel image (debug)
	f.endNode()

	// /memory
	f.beginNode(fmt.Sprintf("memory@%x", ramBase))
	f.propStr("device_type", "memory")
	f.propU32("reg", 0, ramBase, uint32(memSize>>32), uint32(memSize))
	f.endNode()

	// /cpus — one node per vCPU. reg is the MPIDR affinity: Aff1 = index
	// (reg = i<<8), matching the MPIDRs the VMM assigns (and KVM's own
	// vcpu->mpidr scheme). The kernel passes this value as the PSCI
	// CPU_ON target, so the VMM decodes the vCPU id back from Aff1.
	f.beginNode("cpus")
	f.propU32("#address-cells", 1)
	f.propU32("#size-cells", 0)
	for i := 0; i < vcpus; i++ {
		f.beginNode(fmt.Sprintf("cpu@%x", i<<8))
		f.propStr("device_type", "cpu")
		f.propStr("compatible", "arm,armv8")
		f.propU32("reg", uint32(i<<8))
		f.propStr("enable-method", "psci")
		f.endNode()
	}
	f.endNode()

	// /psci — power/reset + CPU on/off handled in-kernel by KVM
	f.beginNode("psci")
	f.propStr("compatible", "arm,psci-0.2")
	f.propStr("method", "hvc")
	f.propU32("cpu_suspend", 0xc4000001) // PSCI_0_2_FN_CPU_SUSPEND
	f.propU32("cpu_off", 0x84000002)
	f.propU32("cpu_on", 0xc4000003)
	f.propU32("migrate", 0xc4000005)
	f.endNode()

	// /gic — GICv3, addresses must match KVM_CREATE_DEVICE setup
	f.beginNode(fmt.Sprintf("intc@%x", gicdBase))
	f.propStr("compatible", "arm,gic-v3")
	f.propU32("#interrupt-cells", 3)
	f.propU32("#address-cells", 2)
	f.propU32("#size-cells", 2)
	f.propEmpty("interrupt-controller")
	f.propU32("reg", 0, gicdBase, 0, gicdSize, 0, gicrBase, 0, uint32(vcpus)*0x20000)
	f.propU32("#redistributor-regions", 1)
	f.propU32("phandle", 1)
	f.endNode()

	// /timer — arch timer (sec-phys, phys, virt, hyp-phys); PPIs, level-low
	f.beginNode("timer")
	f.propStr("compatible", "arm,armv8-timer")
	f.propEmpty("always-on")
	f.propU32("interrupts",
		1, 13, 0xf08,
		1, 14, 0xf08,
		1, 11, 0xf08,
		1, 10, 0xf08)
	f.endNode()

	// /clk24mhz — reference clock for the PL011
	f.beginNode("clk24mhz")
	f.propStr("compatible", "fixed-clock")
	f.propU32("#clock-cells", 0)
	f.propU32("clock-frequency", 24000000)
	f.propStr("clock-output-names", "clk24mhz")
	f.propU32("phandle", 2)
	f.endNode()

	// virtio-mmio devices (transport v2), QEMU-virt-style layout
	for i := 0; i < nVirtio; i++ {
		base := virtio.MMIOBaseArm64 + uint64(i)*virtio.MMIOStrideArm64
		f.beginNode(fmt.Sprintf("virtio_mmio@%x", base))
		f.propStr("compatible", "virtio,mmio")
		f.propU32("reg", 0, uint32(base), 0, virtio.MMIOSize)
		f.propU32("interrupts", 0, uint32(16+i), 0x1) // GIC_SPI, edge-rising
		f.endNode()
	}

	// /pl011@9000000 — serial console, SPI 1 => INTID 33.
	// The Linux amba-pl011 driver requires BOTH clocks (uartclk + apb_pclk),
	// exactly like QEMU's node — with only uartclk the probe fails and no
	// ttyAMA0 console ever registers (no /dev/console for init!).
	f.beginNode(fmt.Sprintf("pl011@%x", uartBase))
	f.propStr("compatible", "arm,pl011", "arm,primecell")
	f.propU32("reg", 0, uartBase, 0, uartSize)
	f.propU32("interrupts", 0, 1, 0x4) // GIC_SPI 1, level-high
	f.propU32("clocks", 2, 2)
	f.propStr("clock-names", "uartclk", "apb_pclk")
	f.endNode()

	f.endNode() // root

	return f.build()
}

// sanity check that names in strings block were emitted uniquely & sorted for
// reproducible builds (debug helper; not used on hot path).
func (f *fdtBuilder) stringsUnique() bool {
	cp := append([]string(nil), f.strs...)
	sort.Strings(cp)
	for i := 1; i < len(cp); i++ {
		if cp[i] == cp[i-1] {
			return false
		}
	}
	return true
}
