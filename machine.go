package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
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
// syscall per byte (thousands per second during boot).
//
// consoleWriter is where the guest serial console goes: os.Stdout for the
// interactive `run` flow, a log file (or os.Stderr) for `exec`.
var (
	consoleWriter io.Writer = os.Stdout
	stdoutBuf               = make([]byte, 0, 4096)
)

func stdoutWrite(b byte) {
	stdoutBuf = append(stdoutBuf, b)
	if b == '\n' || len(stdoutBuf) >= 4096 {
		consoleWriter.Write(stdoutBuf)
		stdoutBuf = stdoutBuf[:0]
	}
}

func stdoutFlush() {
	if len(stdoutBuf) > 0 {
		consoleWriter.Write(stdoutBuf)
		stdoutBuf = stdoutBuf[:0]
	}
}

// kernelArch sniffs the guest architecture from a kernel image file:
// an ELF64 with EM_X86_64 (Docker ships vmlinux as nerdbox-kernel-x86_64)
// or a raw arm64 Image ("ARM\x64" magic @ 0x38).
func kernelArch(path string) (string, error) {
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
	arch, err = kernelArch(path)
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
type machine struct {
	ram       []byte
	mem       guestMem
	entry     uint64
	arch      string // "arm64" | "amd64"
	fdt       []byte
	uart      *pl011     // arm64 console (MMIO)
	uartIO    *uart16550 // x86 console (port I/O 0x3f8)
	cmos      *cmosRTC   // x86 only
	ioapic    *ioApic    // x86, WHPX only (KVM has it in-kernel)
	pit       *pit8254   // x86, WHPX only
	pic       *pic8259   // x86, WHPX only
	devBase   uint64     // virtio-mmio slot 0 base
	devStride uint64
	devIRQ    int // virtio-mmio slot 0 IRQ (arm64: 48+idx, x86: list)
	virtios   []*virtioMMIOCore
	irqLine   func(irq int, level bool) // installed by the backend
	stdinDone chan struct{}
	// consoleStdin wires host stdin into the guest UART (interactive `run`;
	// off for `exec`, where the terminal belongs to the container session).
	consoleStdin bool
	vcpus        int
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
func (m *machine) addVirtio(dev virtioDevice, name string) *virtioMMIOCore {
	idx := len(m.virtios)
	var base uint64
	var irq int
	if m.arch == "amd64" {
		if idx >= len(x86MMIOIRQs) {
			panic("too many virtio devices for x86 IRQ list")
		}
		base = x86MMIOBase + uint64(idx)*x86MMIOStride
		irq = x86MMIOIRQs[idx]
	} else {
		base = virtioMMIOBase + uint64(idx)*virtioMMIOStride
		irq = virtioMMIOIRQ + idx
	}
	core := newVirtioMMIOAt(dev, m.mem, base, irq, m.raise, name)
	m.virtios = append(m.virtios, core)
	return core
}

// raise routes a device interrupt to the backend's irq line (if installed).
func (m *machine) raise(irq int, level bool) {
	if m.irqLine != nil {
		m.irqLine(irq, level)
	}
}

var dbgMMIO = envOr("GANTRY_DEBUG_UART", "MINIVM_DEBUG_UART") != ""

// handleMMIO routes one guest MMIO access. Returns the read value (reads).
func (m *machine) handleMMIO(isWrite bool, phys uint64, data []byte, length uint32) uint32 {
	switch {
	case m.uart != nil && phys >= uartBase && phys < uartBase+uartSize:
		if dbgMMIO {
			op := "R"
			if isWrite {
				op = "W"
			}
			fmt.Printf("[mmio] %s %#x len=%d data=%x\n", op, phys, length, data[:min(int(length), 4)])
		}
		return m.uart.mmio(isWrite, phys-uartBase, data, length)
	default:
		for _, vc := range m.virtios {
			if phys >= vc.base && phys < vc.base+virtioMMIOSize {
				off := phys - vc.base
				if isWrite {
					vc.mmioWrite(off, le32(data))
					return 0
				}
				return vc.mmioRead(off, length)
			}
		}
	}
	if m.ioapic != nil && phys >= ioApicMMIOBase && phys < ioApicMMIOBase+ioApicMMIOSize {
		var v uint32
		if isWrite {
			v = le32(data)
		}
		return m.ioapic.mmio(isWrite, phys-ioApicMMIOBase, v)
	}
	return 0 // unassigned: reads-as-zero, writes ignored
}

var dbgIO = envOr("GANTRY_DEBUG", "MINIVM_DEBUG") != ""

// handleIO routes one x86 port-I/O access (16550 console, CMOS RTC; other
// legacy ports read as 1s / drop writes like an empty bus).
func (m *machine) handleIO(isWrite bool, port uint16, val uint32, size int) uint32 {
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

type machineOpts struct {
	memSize     uint64
	kernelPath  string
	initrdPath  string   // optional when disks are set
	rootfsPath  string   // virtio-blk image /dev/vda (e.g. nerdbox EROFS), optional
	disks       []string // extra virtio-blk images (/dev/vdb, /dev/vdc, ...)
	shares      []hostShare
	netEndpoint string // Unix datagram raw-Ethernet endpoint; "" disables NIC
	netMAC      [6]byte
	netVFKIT    bool
	vsockFwd    string // host dir for vsock forwarding; "" disables vsock
	interactive bool   // wire host stdin into the guest UART
	vcpus       int    // guest vCPU count (SMP); 0/1 = single vCPU
	guestCID    uint64
	vsockListen []uint32 // guest ports accepting host-originated connections
	cmdline     string
}

func prepareMachine(o machineOpts) (*machine, error) {
	m := &machine{stdinDone: make(chan struct{}), consoleStdin: o.interactive}

	// guest RAM is allocated by the backend (it must be mapped into the
	// hypervisor); here we only fill it.
	ram, err := allocGuestRAM(o.memSize)
	if err != nil {
		return nil, err
	}
	m.ram = ram

	entry, arch, err := loadKernel(o.kernelPath, ram)
	if err != nil {
		return nil, err
	}
	m.entry = entry
	m.arch = arch
	if arch == "amd64" {
		m.mem = ramMem{ram: ram, base: 0}
		m.devBase, m.devStride = x86MMIOBase, x86MMIOStride
	} else {
		m.mem = ramMem{ram: ram, base: ramBase}
		m.devBase, m.devStride = virtioMMIOBase, virtioMMIOStride
	}

	var is, ie uint64
	if o.initrdPath != "" {
		is, ie, err = loadInitrd(o.initrdPath, ram)
		if err != nil {
			return nil, err
		}
	}

	if arch == "amd64" {
		m.uartIO = newUART16550(func(level bool) { m.raise(x86SerialIRQ, level) },
			func(b byte) { stdoutWrite(b) })
		m.cmos = &cmosRTC{}
		m.pit = newPIT(func(level bool) { m.raise(0, level) })
		m.pic = &pic8259{}
		fmt.Printf("serial: %s (console=ttyS0)\n", m.uartIO)
	} else {
		m.uart = newPL011(m.raise, func(b byte) { stdoutWrite(b) })
	}

	// virtio devices (MMIO slots 0..n)
	allDisks := append([]string{}, o.disks...)
	if o.rootfsPath != "" {
		allDisks = append([]string{o.rootfsPath}, allDisks...) // /dev/vda first
	}
	for i, path := range allDisks {
		writable := !(o.rootfsPath != "" && i == 0) // boot rootfs stays read-only
		blk, err := newVirtioBlk(path, writable)
		if err != nil {
			return nil, fmt.Errorf("disk %s: %w", path, err)
		}
		core := m.addVirtio(blk, "blk")
		blk.core = core
		mode := "rw"
		if !writable {
			mode = "ro"
		}
		fmt.Printf("virtio-blk: %s @ %#x irq %d (%s, %d MiB) -> /dev/vd%c\n",
			path, core.base, core.irq, mode, blk.size>>20, 'a'+i)
	}
	for _, share := range o.shares {
		if err := m.addShare(share); err != nil {
			return nil, err
		}
	}
	if o.netEndpoint != "" {
		nic, err := newVirtioNetUnixgram(o.netEndpoint, o.netMAC, o.netVFKIT)
		if err != nil {
			return nil, fmt.Errorf("virtio-net: %w", err)
		}
		core := m.addVirtio(nic, "net")
		nic.core = core
		nic.start()
		fmt.Printf("virtio-net: mac %02x:%02x:%02x:%02x:%02x:%02x @ %#x irq %d, unixgram %s\n",
			o.netMAC[0], o.netMAC[1], o.netMAC[2], o.netMAC[3], o.netMAC[4], o.netMAC[5],
			core.base, core.irq, o.netEndpoint)
	}
	if o.vsockFwd != "" {
		vs := newVirtioVsock(o.guestCID, o.vsockFwd)
		core := m.addVirtio(vs, "vsock")
		vs.core = core
		for _, p := range o.vsockListen {
			if _, err := vs.AddListen(p); err != nil {
				fmt.Printf("[vsock] listen %d: %v\n", p, err)
			}
		}
		fmt.Printf("virtio-vsock: guest cid %d @ %#x irq %d, host dir %s\n",
			o.guestCID, core.base, core.irq, o.vsockFwd)
	}
	// Always attach virtio-rng + virtio-rtc devices. The nerdbox kernel
	// seeds crng from the rng at probe (CONFIG_HW_RANDOM_VIRTIO): without
	// it, boot entropy is a coin flip and vminitd's DHCP can time out in
	// getrandom(), killing PID 1. The rtc gives hctosys + PTP time sync.
	rng := newVirtioRNG()
	rngCore := m.addVirtio(rng, "rng")
	rng.core = rngCore
	fmt.Printf("virtio-rng: entropy @ %#x irq %d\n", rngCore.base, rngCore.irq)
	rtc := newVirtioRTC()
	rtcCore := m.addVirtio(rtc, "rtc")
	rtc.core = rtcCore
	fmt.Printf("virtio-rtc: UTC (host time) @ %#x irq %d\n", rtcCore.base, rtcCore.irq)

	m.vcpus = max(o.vcpus, 1)
	cmdline := o.cmdline
	if arch == "amd64" {
		// no FDT on x86: virtio-mmio devices come from the kernel cmdline
		var slots strings.Builder
		for _, vc := range m.virtios {
			fmt.Fprintf(&slots, " virtio_mmio.device=0x%x@0x%x:%d",
				x86MMIOStride, vc.base, vc.irq)
		}
		cmdline = insertKernelArgs(cmdline, strings.TrimSpace(slots.String()))
		if err := setupX86Boot(ram, cmdline, o.memSize, m.vcpus); err != nil {
			return nil, err
		}
		fmt.Printf("boot params @ %#x, cmdline @ %#x (%d bytes), MPS @ %#x\n",
			x86ZeroPage, x86CmdlineAddr, len(cmdline), x86MPSFloatingPtr)
		return m, nil
	}
	m.fdt = buildGuestFDT(o.memSize, is, ie, cmdline, len(m.virtios), m.vcpus)
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
