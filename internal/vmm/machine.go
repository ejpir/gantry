package vmm

import (
	"encoding/binary"
	"fmt"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/virtio"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
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
		_, _ = m.consoleW.Write(m.stdoutBuf)
		m.stdoutBuf = m.stdoutBuf[:0]
	}
}

func (m *Machine) stdoutFlush() {
	m.consoleMu.Lock()
	defer m.consoleMu.Unlock()
	if len(m.stdoutBuf) > 0 {
		_, _ = m.consoleW.Write(m.stdoutBuf)
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
	defer func() { _ = f.Close() }()
	return KernelArchFile(f)
}

// KernelArchFile is KernelArch for an already-open image: pread-only, so
// the shared descriptor offset is untouched.
func KernelArchFile(f *os.File) (string, error) {
	path := f.Name()
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
func loadKernel(f *os.File, ram []byte) (entry uint64, arch string, err error) {
	path := f.Name()
	fi, err := f.Stat()
	if err != nil {
		return 0, "", err
	}
	img := make([]byte, fi.Size())
	if _, err := f.ReadAt(img, 0); err != nil {
		return 0, "", fmt.Errorf("%s: %w", path, err)
	}
	arch, err = KernelArchFile(f)
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

func loadInitrd(f *os.File, ram []byte) (start, end uint64, err error) {
	path := f.Name()
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	blob := make([]byte, fi.Size())
	if _, err := f.ReadAt(blob, 0); err != nil {
		return 0, 0, fmt.Errorf("%s: %w", path, err)
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
	ram   []byte
	mem   *virtio.RAM
	entry uint64
	arch  string // "arm64" | "amd64"
	fdt   []byte
	uart  *pl011 // arm64 console (MMIO)
	// x86 clusters the legacy PC devices (16550 console, CMOS RTC, PIT,
	// PIC, I/O APIC): they exist only on the x86 boot paths (KVM on
	// linux/amd64, WHPX on Windows) and the whole cluster is build-gated
	// so arm64 builds carry no dead emulation code (x86devices.go).
	x86         x86Devices
	virtios     []*virtio.Core
	rootBlkCore *virtio.Core              // boot rootfs (/dev/vda), for first-request timing
	vsockCore   *virtio.Core              // transport slot, for first-packet timing
	vsock       *virtio.Vsock             // nil when no vsock device attached
	irqLine     func(irq int, level bool) // installed by the backend
	kvmFD       *os.File                  // pre-opened /dev/kvm from Opts.KVM (linux; nil = open by path)
	stdinDone   chan struct{}
	// consoleStdin wires host stdin into the guest UART (interactive `run`;
	// off for `exec`, where the terminal belongs to the container session).
	consoleStdin bool
	vcpus        int
	consoleMu    sync.Mutex
	consoleW     io.Writer
	stdoutBuf    []byte
	bootTiming   *bootTimeline
	closeOnce    sync.Once
	closeErr     error
}

// Close flushes and releases every host resource the machine's devices
// hold: writable disk images are synced to host storage and closed
// (releasing their flocks), packet endpoints and forwarded sockets are
// closed, and the console buffer is flushed. It is idempotent and safe
// to call while the backend is still running (the sandbox daemon's
// graceful-stop path does exactly that) — in-flight device operations
// may then fail, which is expected during teardown (review finding 5:
// VM stop used to be a power cut that never flushed or closed anything).
func (m *Machine) Close() error {
	m.closeOnce.Do(func() {
		for _, vc := range m.virtios {
			if err := vc.Close(); err != nil && m.closeErr == nil {
				m.closeErr = err
			}
		}
		m.stdoutFlush()
	})
	return m.closeErr
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
		if m.bootTiming != nil {
			m.bootTiming.mark(bootFirstUART, "first UART access")
		}
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
			if m.bootTiming != nil {
				m.bootTiming.mark(bootFirstVirtioMMIO, "first virtio-mmio access")
			}
			if isWrite {
				val := gutil.LE32(data)
				if m.bootTiming != nil && off == 0x050 {
					switch {
					case vc == m.rootBlkCore && val == 0:
						m.bootTiming.mark(bootFirstRootBlock, "first root-block request")
					case vc == m.vsockCore && val == 1: // virtio-vsock transmit queue
						m.bootTiming.mark(bootFirstVsockTraffic, "first vsock traffic")
					}
				}
				vc.MMIOWrite(off, val)
				return 0
			}
			return vc.MMIORead(off, length)
		}
	}
	if v, ok := m.x86.mmioX86(isWrite, phys, data); ok {
		return v
	}
	return 0 // unassigned: reads-as-zero, writes ignored
}

type Opts struct {
	MemSize uint64
	// Boot assets are OPEN DESCRIPTORS, not paths: the supervisor resolves
	// and opens everything once (killing path-swap races between staging
	// and boot), and a confined VMM worker can boot without any path
	// resolution rights at all. Prepare consumes Kernel/Initrd (loads and
	// closes them); the disks stay open for the VM's lifetime.
	Kernel *os.File
	Initrd *os.File // optional when Disks are set
	Rootfs *os.File // virtio-blk image /dev/vda (e.g. nerdbox EROFS), optional
	// KVM is a pre-opened /dev/kvm descriptor (Linux only): a confined
	// _vmm-worker cannot open device paths — its private /dev is empty —
	// so the supervisor passes the hypervisor handle in the descriptor
	// table. Nil means "open /dev/kvm by path" (monolithic). The backend
	// keeps it open for the VM's lifetime. Ignored on darwin/windows.
	KVM     *os.File
	DisksRO []*os.File // extra virtio-blk images attached READ-ONLY (container images: vdb...)
	Disks   []*os.File // extra virtio-blk images, writable (rwlayers, scratch disks)
	Shares  []Share
	// ShareHub is the persistent-sandbox share transport: one multiplexed
	// virtio-fs device instead of one MMIO device per Share. It is
	// constructed by the sandbox daemon before Prepare so the broker can
	// keep mutating its namespace while the VM runs.
	ShareHub    *virtio.ShareHub
	NetEndpoint string                  // Unix datagram raw-Ethernet endpoint; "" disables NIC
	NetConn     net.Conn                // QEMU-framed in-process link (embedded netstack); takes precedence over NetEndpoint
	NetPolicy   *netpol.Policy          // egress policy on the NetConn link; nil = unrestricted
	NetTraffic  *netpol.TrafficRecorder // persistent per-VM dashboard accounting
	NetMAC      [6]byte
	NetVFKIT    bool
	VsockFwd    string // host dir for vsock forwarding; "" disables vsock (unless VsockDial is set)
	// VsockDial overrides guest->host connect-out (split VMM: the device
	// runs in the confined worker and bridges dial-backs to the
	// supervisor over RPC; it must never open host sockets by path).
	// VsockNoListen suppresses the AddListen unix listeners (host->guest
	// conns then arrive via Machine.InjectVsockConn from transferred
	// descriptors).
	VsockDial     func(port uint32) (net.Conn, error)
	VsockNoListen bool
	Interactive   bool // wire host stdin into the guest UART
	VCPUs         int  // guest vCPU count (SMP); 0/1 = single vCPU
	GuestCID      uint64
	VsockListen   []uint32 // guest ports accepting host-originated connections
	Cmdline       string
	// Console receives the guest serial console (default os.Stdout); the
	// sandbox daemon points it at console.log, `exec -console` at stderr.
	Console io.Writer
	// BootTimingStart enables first-occurrence guest milestones and anchors
	// their total times to the daemon's boot clock. Split workers reconstruct
	// this timestamp from the bootstrap config; vCPU-relative times remain
	// monotonic and are the authoritative fine-grained measurements.
	BootTimingStart time.Time
}

// InjectVsockConn registers a host-originated stream to the guest's
// listening port (split VMM: the conn arrived as a transferred descriptor
// from the supervisor, which owns all host sockets). The vsock device
// must exist (Prepare attached it).
func (m *Machine) InjectVsockConn(guestPort uint32, nc net.Conn) error {
	if m.vsock == nil {
		_ = nc.Close()
		return fmt.Errorf("no vsock device")
	}
	return m.vsock.InjectConn(guestPort, nc)
}

func Prepare(o Opts) (*Machine, error) {
	bootTimingStart := o.BootTimingStart
	if bootTimingStart.IsZero() && gutil.EnvOr("GANTRY_BOOT_TIMING", "MINIVM_BOOT_TIMING") != "" {
		// Direct `gantry run` and one-shot exec have no daemon clock to pass.
		bootTimingStart = time.Now()
	}
	m := &Machine{stdinDone: make(chan struct{}), consoleStdin: o.Interactive,
		consoleW: o.Console, stdoutBuf: make([]byte, 0, 4096), kvmFD: o.KVM,
		bootTiming: newBootTimeline(bootTimingStart, nil)}
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

	if o.Kernel == nil {
		return nil, fmt.Errorf("vmm: a kernel image descriptor is required")
	}
	defer func() { _ = o.Kernel.Close() }()
	entry, arch, err := loadKernel(o.Kernel, ram)
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
	if o.Initrd != nil {
		defer func() { _ = o.Initrd.Close() }()
		is, ie, err = loadInitrd(o.Initrd, ram)
		if err != nil {
			return nil, err
		}
	}

	if arch == "amd64" {
		m.initX86()
	} else {
		m.uart = newPL011(m.raise, func(b byte) { m.stdoutWrite(b) })
	}

	// virtio devices (MMIO slots 0..n). Read-only images (container
	// rootfs) must NOT take the writable-disk flock: cached images are
	// shared across sandboxes by design.
	type disk struct {
		f  *os.File
		rw bool
	}
	var allDisks []disk
	if o.Rootfs != nil {
		allDisks = append(allDisks, disk{o.Rootfs, false}) // /dev/vda first
	}
	for _, f := range o.DisksRO {
		allDisks = append(allDisks, disk{f, false})
	}
	for _, f := range o.Disks {
		allDisks = append(allDisks, disk{f, true})
	}
	for i, dsk := range allDisks {
		f, writable := dsk.f, dsk.rw
		path := f.Name()
		blk, err := virtio.NewBlkFile(f, writable)
		if err != nil {
			return nil, fmt.Errorf("disk %s: %w", path, err)
		}
		core, err := m.addVirtio(blk, "blk")
		if err != nil {
			return nil, err
		}
		if i == 0 && o.Rootfs != nil {
			m.rootBlkCore = core
		}
		mode := "rw"
		if !writable {
			mode = "ro"
		}
		fmt.Printf("virtio-blk: %s @ %#x irq %d (%s, %d MiB) -> /dev/vd%c\n",
			path, core.Base(), core.IRQ(), mode, blk.Size()>>20, 'a'+i)
	}
	if o.ShareHub != nil {
		if len(o.Shares) != 0 {
			return nil, fmt.Errorf("virtio-fs: ShareHub and per-share devices are mutually exclusive")
		}
		if err := m.addShareHub(o.ShareHub); err != nil {
			return nil, err
		}
	} else {
		for _, share := range o.Shares {
			if err := m.addShare(share); err != nil {
				return nil, err
			}
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
		nic.SetTrafficRecorder(o.NetTraffic)
		core, err := m.addVirtio(nic, "net")
		if err != nil {
			return nil, err
		}
		fmt.Printf("virtio-net: mac %02x:%02x:%02x:%02x:%02x:%02x @ %#x irq %d, %s\n",
			o.NetMAC[0], o.NetMAC[1], o.NetMAC[2], o.NetMAC[3], o.NetMAC[4], o.NetMAC[5],
			core.Base(), core.IRQ(), how)
	}
	if o.VsockFwd != "" || o.VsockDial != nil {
		vs := virtio.NewVsock(o.GuestCID, o.VsockFwd)
		if o.VsockDial != nil {
			vs.SetDial(o.VsockDial)
		}
		core, err := m.addVirtio(vs, "vsock")
		if err != nil {
			return nil, err
		}
		if !o.VsockNoListen {
			for _, p := range o.VsockListen {
				if _, err := vs.AddListen(p); err != nil {
					fmt.Printf("[vsock] listen %d: %v\n", p, err)
				}
			}
		}
		m.vsock = vs
		m.vsockCore = core
		fmt.Printf("virtio-vsock: guest cid %d @ %#x irq %d, host dir %s\n",
			o.GuestCID, core.Base(), core.IRQ(), o.VsockFwd)
	}
	// Always attach virtio-rng. The nerdbox kernel
	// seeds crng from the rng at probe (CONFIG_HW_RANDOM_VIRTIO): without
	// it, boot entropy is a coin flip and vminitd's DHCP can time out in
	// getrandom(), killing PID 1. The rtc gives hctosys + PTP time sync.
	rng := virtio.NewRNG()
	rngCore, err := m.addVirtio(rng, "rng")
	if err != nil {
		return nil, err
	}
	fmt.Printf("virtio-rng: entropy @ %#x irq %d\n", rngCore.Base(), rngCore.IRQ())
	// The RTC is attached on arm64 (HVF exposes no kvm-clock; the
	// smeared-UTC advertisement fixed epoch-boot there). On amd64 it is
	// OFF by default: KVM guests take time from kvm-clock/ptp_kvm (the
	// whole July x86 stack ran with the device unregistered), and a
	// registered rtc0 wedges gVisor's sentry — its CalibratedClock never
	// reports ready, the startup watchdog kills the sandbox, and
	// `runsc start` then fails with "state stopped" (field-proven on
	// c5.metal; with the device absent the same sentry boots in ~26s).
	// GANTRY_RTC=1 force-attaches on amd64, GANTRY_NO_RTC=1 suppresses
	// everywhere (bisect knobs).
	attachRTC := arch != "amd64"
	if gutil.EnvOr("GANTRY_RTC") != "" {
		attachRTC = true
	}
	if gutil.EnvOr("GANTRY_NO_RTC") != "" {
		attachRTC = false
	}
	if attachRTC {
		rtc := virtio.NewRTC()
		rtcCore, err := m.addVirtio(rtc, "rtc")
		if err != nil {
			return nil, err
		}
		fmt.Printf("virtio-rtc: UTC (host time) @ %#x irq %d\n", rtcCore.Base(), rtcCore.IRQ())
	}

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
//
// Lifecycle: the backend owns vCPU execution only. Device teardown is
// Machine.Close — Run invokes it when the guest powers off or the
// backend fails, and a caller that stops the VM out of band (the
// sandbox daemon's signal path) must call it before exiting; it is
// idempotent. Forced process termination remains the fallback after a
// bounded graceful window (gantry stop escalates SIGTERM → SIGKILL).
type backend interface {
	run(m *Machine) error
}

// Run boots the prepared machine on the platform hypervisor backend.
// Devices are flushed and closed (Machine.Close) before Run returns.
func Run(m *Machine) error {
	err := platformBackend().run(m)
	if cerr := m.Close(); err == nil {
		err = cerr
	}
	return err
}

// PSTATE at boot lives in pstate.go (arm64 backends only).
