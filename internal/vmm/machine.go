package vmm

import (
	"encoding/binary"
	"fmt"
	"gantry/internal/gutil"
	"gantry/internal/netpol"
	"gantry/internal/virtio"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

// Guest physical layout inside RAM:
//
//	0x40000000  FDT (x0 points here at boot)
//	0x40200000  kernel Image (2 MiB aligned; header text_offset is zero)
//	0x46000000  initramfs
const (
	fdtAddr    = ramBase
	initrdOff  = 0x06000000
	kernelOff  = 0x00200000 // fallback for relocatable Images with text_offset=0
	maxFDTSize = 0x20000    // keep FDT well below kernel entry
)

// stdoutWrite emits guest console output, buffered to avoid one write
// syscall per byte (thousands per second during boot). The console writer
// and buffer live on the Machine (not package globals): more than one
// Machine may exist per process, and flush-on-shutdown runs on backend
// threads — the mutex covers both.
func (m *Machine) stdoutWrite(b byte) {
	m.consoleMu.Lock()
	defer m.consoleMu.Unlock()
	m.stdoutBuf = append(m.stdoutBuf, b)
	if b == '\n' || len(m.stdoutBuf) >= 4096 {
		m.consoleW.Write(m.stdoutBuf)
		m.stdoutBuf = m.stdoutBuf[:0]
	}
}

func (m *Machine) stdoutFlush() {
	m.consoleMu.Lock()
	defer m.consoleMu.Unlock()
	if len(m.stdoutBuf) > 0 {
		m.consoleW.Write(m.stdoutBuf)
		m.stdoutBuf = m.stdoutBuf[:0]
	}
}

// kernelArch sniffs the guest architecture from a kernel image file:
// an ELF64 with EM_X86_64 (Docker ships vmlinux as nerdbox-kernel-x86_64)
// or a raw arm64 Image ("ARM\x64" magic @ 0x38).
func KernelArch(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var hdr [0x40]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	if string(hdr[1:4]) == "ELF" {
		if binary.LittleEndian.Uint16(hdr[18:]) == 62 { // EM_X86_64
			return "amd64", nil
		}
		if binary.LittleEndian.Uint16(hdr[18:]) == 183 { // EM_AARCH64
			return "arm64", nil
		}
		return "", fmt.Errorf("%s: unsupported ELF machine %d", path, binary.LittleEndian.Uint16(hdr[18:]))
	}
	if binary.LittleEndian.Uint32(hdr[0x38:]) == 0x644d5241 { // "ARM\x64"
		return "arm64", nil
	}
	return "", fmt.Errorf("%s: unrecognized kernel image (not x86-64 ELF, not arm64 Image)", path)
}

// loadKernel loads the guest kernel into RAM and returns its entry point
// and architecture. A zero text_offset denotes a relocatable Image; place it at the
// next 2 MiB boundary after the FDT rather than QEMU's legacy +0x80000
// address (which Linux reports as a firmware bug).
//
//	0x08 u64 text_offset
//	0x10 u64 image_size
//	0x18 u64 flags (bits 1-2: page size: 1=4K, 2=16K, 3=64K)
//	0x38 u32 magic "ARM\x64"
func loadKernel(path string, ram []byte) (entry uint64, arch string, err error) {
	img, err := os.ReadFile(path)
	if err != nil {
		return 0, "", err
	}
	arch, err = KernelArch(path)
	if err != nil {
		return 0, "", err
	}
	if arch == "amd64" {
		entry, err = loadKernelX86(img, ram)
		return entry, arch, err
	}
	if len(img) < 0x40 || binary.LittleEndian.Uint32(img[0x38:]) != 0x644d5241 {
		return 0, "", fmt.Errorf("%s: not an arm64 kernel Image (bad magic)", path)
	}
	textOffset := binary.LittleEndian.Uint64(img[0x08:])
	imageSize := binary.LittleEndian.Uint64(img[0x10:])
	flags := binary.LittleEndian.Uint64(img[0x18:])
	if ps := (flags >> 1) & 0x3; ps == 0 {
		fmt.Printf("warning: kernel has no page-size flag; assuming 4K/16K-safe layout\n")
	}
	if textOffset == 0 {
		textOffset = kernelOff
	}
	entry = ramBase + textOffset
	dst := textOffset
	if uint64(len(img)) > uint64(len(ram))-dst {
		return 0, "", fmt.Errorf("kernel too big for guest RAM")
	}
	copy(ram[dst:], img)
	fmt.Printf("kernel: %s (%d bytes) @ %#x, image_size=%d, entry %#x\n",
		path, len(img), ramBase+dst, imageSize, entry)
	return entry, arch, nil
}

func loadInitrd(path string, ram []byte) (start, end uint64, err error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	start = ramBase + initrdOff
	if uint64(len(blob)) > uint64(len(ram))-initrdOff {
		return 0, 0, fmt.Errorf("initramfs too big for guest RAM")
	}
	copy(ram[initrdOff:], blob)
	fmt.Printf("initrd: %s (%d bytes) @ %#x\n", path, len(blob), start)
	return start, start + uint64(len(blob)), nil
}

// machine is the OS-independent guest: RAM, boot assets, and the MMIO device
// model. Backends (KVM on Linux, Hypervisor.framework on macOS) only provide
// vCPU execution, MMIO exits, and IRQ injection.
type Machine struct {
	ram       []byte
	mem       *virtio.RAM
	entry     uint64
	arch      string // "arm64" | "amd64"
	fdt       []byte
	uart      *pl011     // arm64 console (MMIO)
	uartIO    *uart16550 // x86 console (port I/O 0x3f8)
	cmos      *cmosRTC   // x86 only
	ioapic    *ioApic    // x86, WHPX only (KVM has it in-kernel)
	pit       *pit8254   // x86, WHPX only
	pic       *pic8259   // x86, WHPX only
	virtios   []*virtio.Core
	irqLine   func(irq int, level bool) // installed by the backend
	stdinDone chan struct{}
	// consoleStdin wires host stdin into the guest UART (interactive `run`;
	// off for `exec`, where the terminal belongs to the container session).
	consoleStdin bool
	vcpus        int
	consoleMu    sync.Mutex
	consoleW     io.Writer
	stdoutBuf    []byte
}

// x86 virtio-mmio window: above RAM (<=3 GiB), below the APIC window at
// 0xfec00000. IRQs use free legacy lines (identity-mapped to IO-APIC pins
// by the MPS table); IRQ 4 belongs to the serial port.
const (
	x86MMIOBase   = 0xc0000000
	x86MMIOStride = 0x1000
)

var x86MMIOIRQs = []int{3, 5, 6, 7, 9, 10, 11, 12}

// addVirtio attaches one virtio-mmio device at the next free slot.
func (m *Machine) addVirtio(dev virtio.Device, name string) (*virtio.Core, error) {
	idx := len(m.virtios)
	var base uint64
	var irq int
	if m.arch == "amd64" {
		if idx >= len(x86MMIOIRQs) {
			return nil, fmt.Errorf("virtio-%s: x86-64 supports at most %d virtio-mmio devices (%d legacy IRQ lines)", name, len(x86MMIOIRQs), len(x86MMIOIRQs))
		}
		base = x86MMIOBase + uint64(idx)*x86MMIOStride
		irq = x86MMIOIRQs[idx]
	} else {
		base = virtio.MMIOBaseArm64 + uint64(idx)*virtio.MMIOStrideArm64
		irq = virtio.MMIOIRQArm64 + idx
	}
	core := virtio.NewCoreAt(dev, m.mem, base, irq, m.raise, name)
	m.virtios = append(m.virtios, core)
	return core, nil
}

// raise routes a device interrupt to the backend's irq line (if installed).
func (m *Machine) raise(irq int, level bool) {
	if m.irqLine != nil {
		m.irqLine(irq, level)
	}
}

var dbgMMIO = gutil.EnvOr("GANTRY_DEBUG_UART", "MINIVM_DEBUG_UART") != ""

// handleMMIO routes one guest MMIO access. Returns the read value (reads).
// A flat sequence of range checks; unassigned space reads-as-zero.
func (m *Machine) handleMMIO(isWrite bool, phys uint64, data []byte, length uint32) uint32 {
	if m.uart != nil && phys >= uartBase && phys < uartBase+uartSize {
		if dbgMMIO {
			op := "R"
			if isWrite {
				op = "W"
			}
			fmt.Printf("[mmio] %s %#x len=%d data=%x\n", op, phys, length, data[:min(int(length), 4)])
		}
		return m.uart.mmio(isWrite, phys-uartBase, data, length)
	}
	for _, vc := range m.virtios {
		if phys >= vc.Base() && phys < vc.Base()+virtio.MMIOSize {
			off := phys - vc.Base()
			if isWrite {
				vc.MMIOWrite(off, gutil.LE32(data))
				return 0
			}
			return vc.MMIORead(off, length)
		}
	}
	if m.ioapic != nil && phys >= ioApicMMIOBase && phys < ioApicMMIOBase+ioApicMMIOSize {
		var v uint32
		if isWrite {
			v = gutil.LE32(data)
		}
		return m.ioapic.mmio(isWrite, phys-ioApicMMIOBase, v)
	}
	return 0 // unassigned: reads-as-zero, writes ignored
}

var dbgIO = gutil.EnvOr("GANTRY_DEBUG", "MINIVM_DEBUG") != ""

// handleIO routes one x86 port-I/O access (16550 console, CMOS RTC; other
// legacy ports read as 1s / drop writes like an empty bus).
func (m *Machine) handleIO(isWrite bool, port uint16, val uint32, size int) uint32 {
	switch {
	case port >= x86SerialPort && port < x86SerialPort+x86SerialSize && m.uartIO != nil:
		if isWrite {
			m.uartIO.ioWrite(port, byte(val))
			return 0
		}
		return uint32(m.uartIO.ioRead(port))
	case port == cmosIndexPort || port == cmosDataPort:
		if isWrite {
			m.cmos.ioWrite(port, byte(val))
			return 0
		}
		return uint32(m.cmos.ioRead(port))
	case m.pit != nil && ((port >= 0x40 && port <= 0x43) || port == 0x61):
		if isWrite {
			m.pit.ioWrite(port, byte(val))
			return 0
		}
		return uint32(m.pit.ioRead(port))
	case m.pic != nil && (port == 0x20 || port == 0x21 || port == 0xa0 || port == 0xa1):
		if isWrite {
			m.pic.ioWrite(port, byte(val))
			return 0
		}
		return uint32(m.pic.ioRead(port))
	}
	if dbgIO && !isWrite {
		fmt.Printf("[io] unhandled read port %#x\n", port)
	}
	return 0xffffffff
}

type Opts struct {
	MemSize     uint64
	KernelPath  string
	InitrdPath  string   // optional when Disks are set
	RootfsPath  string   // virtio-blk image /dev/vda (e.g. nerdbox EROFS), optional
	DisksRO     []string // extra virtio-blk images attached READ-ONLY (container images: vdb...)
	Disks       []string // extra virtio-blk images, writable (rwlayers, scratch disks)
	Shares      []Share
	NetEndpoint string         // Unix datagram raw-Ethernet endpoint; "" disables NIC
	NetConn     net.Conn       // QEMU-framed in-process link (embedded netstack); takes precedence over NetEndpoint
	NetPolicy   *netpol.Policy // egress policy on the NetConn link; nil = unrestricted
	NetMAC      [6]byte
	NetVFKIT    bool
	VsockFwd    string // host dir for vsock forwarding; "" disables vsock
	Interactive bool   // wire host stdin into the guest UART
	VCPUs       int    // guest vCPU count (SMP); 0/1 = single vCPU
	GuestCID    uint64
	VsockListen []uint32 // guest ports accepting host-originated connections
	Cmdline     string
	// Console receives the guest serial console (default os.Stdout); the
	// sandbox daemon points it at console.log, `exec -console` at stderr.
	Console io.Writer
}

func Prepare(o Opts) (*Machine, error) {
	m := &Machine{stdinDone: make(chan struct{}), consoleStdin: o.Interactive,
		consoleW: o.Console, stdoutBuf: make([]byte, 0, 4096)}
	if m.consoleW == nil {
		m.consoleW = os.Stdout
	}

	// guest RAM is allocated by the backend (it must be mapped into the
	// hypervisor); here we only fill it.
	ram, err := allocGuestRAM(o.MemSize)
	if err != nil {
		return nil, err
	}
	m.ram = ram

	entry, arch, err := loadKernel(o.KernelPath, ram)
	if err != nil {
		return nil, err
	}
	m.entry = entry
	m.arch = arch
	if arch == "amd64" {
		m.mem = virtio.NewRAM(ram, 0)
	} else {
		m.mem = virtio.NewRAM(ram, ramBase)
	}

	var is, ie uint64
	if o.InitrdPath != "" {
		is, ie, err = loadInitrd(o.InitrdPath, ram)
		if err != nil {
			return nil, err
		}
	}

	if arch == "amd64" {
		m.uartIO = newUART16550(func(level bool) { m.raise(x86SerialIRQ, level) },
			func(b byte) { m.stdoutWrite(b) })
		m.cmos = &cmosRTC{}
		m.pit = newPIT(func(level bool) { m.raise(0, level) })
		m.pic = &pic8259{}
		fmt.Printf("serial: %s (console=ttyS0)\n", m.uartIO)
	} else {
		m.uart = newPL011(m.raise, func(b byte) { m.stdoutWrite(b) })
	}

	// virtio devices (MMIO slots 0..n). Read-only images (container
	// rootfs) must NOT take the writable-disk flock: cached images are
	// shared across sandboxes by design.
	type disk struct {
		path string
		rw   bool
	}
	var allDisks []disk
	if o.RootfsPath != "" {
		allDisks = append(allDisks, disk{o.RootfsPath, false}) // /dev/vda first
	}
	for _, p := range o.DisksRO {
		allDisks = append(allDisks, disk{p, false})
	}
	for _, p := range o.Disks {
		allDisks = append(allDisks, disk{p, true})
	}
	for i, dsk := range allDisks {
		path, writable := dsk.path, dsk.rw
		blk, err := virtio.NewBlk(path, writable)
		if err != nil {
			return nil, fmt.Errorf("disk %s: %w", path, err)
		}
		core, err := m.addVirtio(blk, "blk")
		if err != nil {
			return nil, err
		}
		mode := "rw"
		if !writable {
			mode = "ro"
		}
		fmt.Printf("virtio-blk: %s @ %#x irq %d (%s, %d MiB) -> /dev/vd%c\n",
			path, core.Base(), core.IRQ(), mode, blk.Size()>>20, 'a'+i)
	}
	for _, share := range o.Shares {
		if err := m.addShare(share); err != nil {
			return nil, err
		}
	}
	if o.NetConn != nil || o.NetEndpoint != "" {
		var nic *virtio.Net
		var err error
		var how string
		if o.NetConn != nil {
			nic = virtio.NewNetConnPolicy(o.NetConn, o.NetMAC, o.NetPolicy)
			how = "embedded netstack"
		} else {
			nic, err = virtio.NewNetUnixgram(o.NetEndpoint, o.NetMAC, o.NetVFKIT)
			if err != nil {
				return nil, fmt.Errorf("virtio-net: %w", err)
			}
			how = "unixgram " + o.NetEndpoint
		}
		core, err := m.addVirtio(nic, "net")
		if err != nil {
			return nil, err
		}
		fmt.Printf("virtio-net: mac %02x:%02x:%02x:%02x:%02x:%02x @ %#x irq %d, %s\n",
			o.NetMAC[0], o.NetMAC[1], o.NetMAC[2], o.NetMAC[3], o.NetMAC[4], o.NetMAC[5],
			core.Base(), core.IRQ(), how)
	}
	if o.VsockFwd != "" {
		vs := virtio.NewVsock(o.GuestCID, o.VsockFwd)
		core, err := m.addVirtio(vs, "vsock")
		if err != nil {
			return nil, err
		}
		for _, p := range o.VsockListen {
			if _, err := vs.AddListen(p); err != nil {
				fmt.Printf("[vsock] listen %d: %v\n", p, err)
			}
		}
		fmt.Printf("virtio-vsock: guest cid %d @ %#x irq %d, host dir %s\n",
			o.GuestCID, core.Base(), core.IRQ(), o.VsockFwd)
	}
	// Always attach virtio-rng + virtio-rtc devices. The nerdbox kernel
	// seeds crng from the rng at probe (CONFIG_HW_RANDOM_VIRTIO): without
	// it, boot entropy is a coin flip and vminitd's DHCP can time out in
	// getrandom(), killing PID 1. The rtc gives hctosys + PTP time sync.
	rng := virtio.NewRNG()
	rngCore, err := m.addVirtio(rng, "rng")
	if err != nil {
		return nil, err
	}
	fmt.Printf("virtio-rng: entropy @ %#x irq %d\n", rngCore.Base(), rngCore.IRQ())
	rtc := virtio.NewRTC()
	rtcCore, err := m.addVirtio(rtc, "rtc")
	if err != nil {
		return nil, err
	}
	fmt.Printf("virtio-rtc: UTC (host time) @ %#x irq %d\n", rtcCore.Base(), rtcCore.IRQ())

	m.vcpus = max(o.VCPUs, 1)
	cmdline := o.Cmdline
	if arch == "amd64" {
		// no FDT on x86: virtio-mmio devices come from the kernel cmdline
		var slots strings.Builder
		for _, vc := range m.virtios {
			fmt.Fprintf(&slots, " virtio_mmio.device=0x%x@0x%x:%d",
				x86MMIOStride, vc.Base(), vc.IRQ())
		}
		cmdline = insertKernelArgs(cmdline, strings.TrimSpace(slots.String()))
		if err := setupX86Boot(ram, cmdline, o.MemSize, m.vcpus); err != nil {
			return nil, err
		}
		fmt.Printf("boot params @ %#x, cmdline @ %#x (%d bytes), MPS @ %#x\n",
			x86ZeroPage, x86CmdlineAddr, len(cmdline), x86MPSFloatingPtr)
		return m, nil
	}
	m.fdt = buildGuestFDT(o.MemSize, is, ie, cmdline, len(m.virtios), m.vcpus)
	if len(m.fdt) > maxFDTSize {
		return nil, fmt.Errorf("FDT too large: %d", len(m.fdt))
	}
	copy(m.ram[fdtAddr-ramBase:], m.fdt)
	fmt.Printf("fdt: %d bytes @ %#x\n", len(m.fdt), fdtAddr)
	return m, nil
}

// insertKernelArgs inserts kernel arguments before the "--" that separates
// vminitd's own flags in the nerdbox cmdline.
func insertKernelArgs(cmdline, args string) string {
	if args == "" {
		return cmdline
	}
	if i := strings.Index(cmdline, " -- "); i >= 0 {
		return cmdline[:i] + " " + args + cmdline[i:]
	}
	return cmdline + " " + args
}

// backend is the hypervisor contract: run a prepared machine until guest
// shutdown/reset or error. One implementation per platform, selected by
// build tags (KVM arm64/x86-64, HVF on macOS, WHPX on Windows) — see
// platformBackend in vm_linux.go, kvm_amd64.go, vm_darwin.go and
// whpx_windows.go. Adding a platform means implementing backend and
// returning it from platformBackend; nothing else in vmm is platform-aware.
type backend interface {
	run(m *Machine) error
}

// Run boots the prepared machine on the platform hypervisor backend.
func Run(m *Machine) error { return platformBackend().run(m) }

// PSTATE at boot: EL1h (0b0101), all exceptions masked (D A I F = 0x3c0).
const pstateEL1hMask = 0x3c5
