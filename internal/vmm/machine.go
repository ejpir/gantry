package vmm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/virtio"
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
	if len(m.stdoutBuf) == 0 {
		// In boot-profile mode, add a host stamp at the start of each line.
		// The guest's own printk timestamps are all zero until it registers a
		// timer, so without this there is no way to line a console message up
		// against the exit trace. Basic timing returns the buffer unchanged.
		m.stdoutBuf = m.bootTiming.stampLine(m.stdoutBuf)
	}
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

// KernelArchFile sniffs the guest architecture from an already-open kernel
// image: an ELF64 with EM_X86_64 or a raw arm64 Image ("ARM\x64" magic at
// offset 0x38). It uses pread so the shared descriptor offset is untouched.
func KernelArchFile(f *os.File) (string, error) {
	path := f.Name()
	var hdr [0x40]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return kernelArchHeader(path, hdr[:])
}

func kernelArchHeader(path string, hdr []byte) (string, error) {
	if len(hdr) < 0x40 {
		return "", fmt.Errorf("%s: kernel header is only %d bytes", path, len(hdr))
	}
	if hdr[0] == 0x7f && string(hdr[1:4]) == "ELF" {
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
	size := fi.Size()
	if size < 0x40 {
		return 0, "", fmt.Errorf("%s: kernel image is only %d bytes", path, size)
	}
	var hdr [0x40]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		return 0, "", fmt.Errorf("%s: %w", path, err)
	}
	arch, err = kernelArchHeader(path, hdr[:])
	if err != nil {
		return 0, "", err
	}
	if arch == "amd64" {
		entry, err = loadKernelX86(f, uint64(size), ram)
		return entry, arch, err
	}
	if binary.LittleEndian.Uint32(hdr[0x38:]) != 0x644d5241 {
		return 0, "", fmt.Errorf("%s: not an arm64 kernel Image (bad magic)", path)
	}
	textOffset := binary.LittleEndian.Uint64(hdr[0x08:])
	imageSize := binary.LittleEndian.Uint64(hdr[0x10:])
	flags := binary.LittleEndian.Uint64(hdr[0x18:])
	if ps := (flags >> 1) & 0x3; ps == 0 {
		fmt.Printf("warning: kernel has no page-size flag; assuming 4K/16K-safe layout\n")
	}
	if textOffset == 0 {
		textOffset = kernelOff
	}
	entry = ramBase + textOffset
	dst := textOffset
	if dst > uint64(len(ram)) || uint64(size) > uint64(len(ram))-dst {
		return 0, "", fmt.Errorf("kernel too big for guest RAM")
	}
	target := ram[dst : dst+uint64(size)]
	copy(target, hdr[:])
	if len(target) > len(hdr) {
		if _, err := f.ReadAt(target[len(hdr):], int64(len(hdr))); err != nil {
			return 0, "", fmt.Errorf("%s: %w", path, err)
		}
	}
	fmt.Printf("kernel: %s (%d bytes) @ %#x, image_size=%d, entry %#x\n",
		path, size, ramBase+dst, imageSize, entry)
	return entry, arch, nil
}

func loadInitrd(f *os.File, ram []byte) (start, end uint64, err error) {
	path := f.Name()
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	size := fi.Size()
	if size < 0 {
		return 0, 0, fmt.Errorf("%s: negative initramfs size %d", path, size)
	}
	start = ramBase + initrdOff
	if initrdOff > uint64(len(ram)) || uint64(size) > uint64(len(ram))-initrdOff {
		return 0, 0, fmt.Errorf("initramfs too big for guest RAM")
	}
	target := ram[initrdOff : initrdOff+uint64(size)]
	if len(target) != 0 {
		if _, err := f.ReadAt(target, 0); err != nil {
			return 0, 0, fmt.Errorf("%s: %w", path, err)
		}
	}
	fmt.Printf("initrd: %s (%d bytes) @ %#x\n", path, size, start)
	return start, start + uint64(size), nil
}

// Machine is the OS-independent guest: RAM, boot assets, devices, and the
// native backend lifecycle. Platform backends own their hypervisor resources
// and vCPU threads; Machine.Close joins them before releasing devices or RAM.
type Machine struct {
	ram   []byte
	mem   *virtio.RAM
	entry uint64
	arch  string // "arm64" | "amd64"
	// x86BootMemSize is the ordinary e820/low mapping. With the opt-in
	// virtio-mem path, the rest of ram is mapped above 4 GiB and hot-added by
	// Linux instead of delaying early boot page initialization.
	x86BootMemSize uint64
	x86LowRAMSize  uint64
	x86HotMemSize  uint64
	fdt            []byte
	uart           *pl011 // arm64 console (MMIO)
	// x86 clusters the legacy PC devices (16550 console, CMOS RTC, PIT,
	// PIC, I/O APIC): they exist only on the x86 boot paths (KVM on
	// linux/amd64, WHPX on Windows) and the whole cluster is build-gated
	// so arm64 builds carry no dead emulation code (x86devices.go).
	x86            x86Devices
	virtios        []*virtio.Core
	rootBlkCore    *virtio.Core    // boot rootfs (/dev/vda), for first-request timing
	vsockCore      *virtio.Core    // transport slot, for first-packet timing
	vsock          *virtio.Vsock   // nil when no vsock device attached
	hotMem         *virtio.Mem     // nil unless the opt-in x86 virtio-mem path is active
	hotMemDeferred bool            // tail publication is owned by the daemon-ready edge
	interrupts     interruptRouter // published by the backend; disabled before native teardown
	kvmFD          *os.File        // pre-opened /dev/kvm from Opts.KVM (linux; nil = open by path)
	stdinDone      chan struct{}
	// consoleStdin wires host stdin into the guest UART (interactive `run`;
	// off for `exec`, where the terminal belongs to the container session).
	consoleStdin bool
	vcpus        int
	consoleMu    sync.Mutex
	consoleW     io.Writer
	stdoutBuf    []byte
	bootTiming   *bootTimeline
	resourceMu   sync.Mutex
	backend      io.Closer
	lifecycle    machineLifecycle
	runDone      chan struct{}
	closeOnce    sync.Once
	closeErr     error
}

// Close stops and joins backend initialization and vCPU execution before it
// releases devices and guest RAM. Writable disks are synced and unlocked,
// packet workers and forwarded sockets are joined, and native hypervisor
// mappings are torn down in backend-specific order. It is idempotent and safe
// to race with Run, including the interval before a backend is published.
func (m *Machine) Close() error {
	m.closeOnce.Do(func() {
		m.resourceMu.Lock()
		waitForRun := m.lifecycle.beginStop()
		backend := m.backend
		m.backend = nil
		kvmFD := m.kvmFD
		m.kvmFD = nil
		runDone := m.runDone
		m.resourceMu.Unlock()

		var errs []error
		// Stop new callbacks and wait for any in-flight IRQ delivery before the
		// backend closes native handles. Device workers are joined below.
		m.interrupts.disable()
		if backend != nil {
			if err := backend.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close hypervisor backend: %w", err))
			}
		}
		if waitForRun && runDone != nil {
			<-runDone
		}
		for _, vc := range m.virtios {
			if err := vc.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		m.virtios = nil
		if kvmFD != nil {
			if err := kvmFD.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close KVM descriptor: %w", err))
			}
		}
		if err := m.releaseRAM(); err != nil {
			errs = append(errs, err)
		}
		m.fdt = nil
		m.stdoutFlush()
		m.resourceMu.Lock()
		m.rootBlkCore = nil
		m.vsockCore = nil
		m.vsock = nil
		m.hotMem = nil
		m.hotMemDeferred = false
		m.lifecycle = machineClosed
		m.resourceMu.Unlock()
		m.closeErr = errors.Join(errs...)
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

// IRQs 13-15 are the legacy FPU/IDE lines, but this firmwareless machine has
// neither an FPU interrupt nor IDE controllers. The MPS table already routes
// all three through the userspace IO-APIC, so they are valid additional
// virtio-mmio slots for full sandboxes that also attach virtio-mem.
var x86MMIOIRQs = []int{3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15}

// addVirtio attaches one virtio-mmio device at the next free slot.
func (m *Machine) addVirtio(dev virtio.Device, name string) (*virtio.Core, error) {
	idx := len(m.virtios)
	var base uint64
	var irq int
	if m.arch == "amd64" {
		if idx >= len(x86MMIOIRQs) {
			attachErr := fmt.Errorf("virtio-%s: x86-64 supports at most %d virtio-mmio devices (%d legacy IRQ lines)", name, len(x86MMIOIRQs), len(x86MMIOIRQs))
			if closer, ok := dev.(io.Closer); ok {
				if closeErr := closer.Close(); closeErr != nil {
					return nil, fmt.Errorf("%w; close rejected device: %v", attachErr, closeErr)
				}
			}
			return nil, attachErr
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
	m.interrupts.raise(irq, level)
}

var dbgMMIO = os.Getenv("GANTRY_DEBUG_UART") != ""

// handleMMIO routes one guest MMIO access. Returns the read value (reads).
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
	if vc := m.virtioAt(phys); vc != nil {
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
	if v, ok := m.x86.mmioX86(isWrite, phys, data); ok {
		return v
	}
	return 0 // unassigned: reads-as-zero, writes ignored
}

// virtioAt maps the architecture's fixed MMIO slot geometry directly to a
// device index. This is on every VM-exit path, so it must not scan all devices.
func (m *Machine) virtioAt(phys uint64) *virtio.Core {
	base, stride := uint64(virtio.MMIOBaseArm64), uint64(virtio.MMIOStrideArm64)
	if m.arch == "amd64" {
		base, stride = x86MMIOBase, x86MMIOStride
	}
	if phys < base {
		return nil
	}
	index := (phys - base) / stride
	if index >= uint64(len(m.virtios)) {
		return nil
	}
	device := m.virtios[index]
	if phys < device.Base() || phys-device.Base() >= virtio.MMIOSize {
		return nil
	}
	return device
}

type Opts struct {
	MemSize uint64
	// Boot assets are OPEN DESCRIPTORS, not paths: the supervisor resolves
	// and opens everything once (killing path-swap races between staging
	// and boot), and a confined VMM worker can boot without any path
	// resolution rights at all. Prepare consumes every descriptor, NetConn,
	// and non-nil Filesystem Owner on entry, even when preparation fails.
	// Kernel/Initrd are loaded and closed; disks, KVM, NetConn, and owned
	// filesystems remain owned by the Machine until Close.
	Kernel *os.File
	Initrd *os.File // optional when Disks are set
	Rootfs *os.File // virtio-blk image /dev/vda (e.g. nerdbox EROFS), optional
	// KVM is a pre-opened /dev/kvm descriptor (Linux only): a confined
	// _vmm-worker cannot open device paths — its private /dev is empty —
	// so the supervisor passes the hypervisor handle in the descriptor
	// table. Nil means "open /dev/kvm by path" (monolithic). The backend
	// keeps it open for the VM's lifetime. Ignored on darwin/windows.
	KVM *os.File
	// SharedRAM is an optional pre-sized backing descriptor for guest RAM.
	// Split VMM/vhost mode maps it MAP_SHARED and transfers the same object to
	// the filesystem backend; monolithic VMs leave it nil.
	SharedRAM *os.File
	DisksRO   []*os.File // extra virtio-blk images attached READ-ONLY (container images: vdb...)
	Disks     []*os.File // extra virtio-blk images, writable (rwlayers, scratch disks)
	// DisksPrelocked means a trusted supervisor process owns the exclusive
	// locks for Disks. Split workers use this so compromised children cannot
	// unlock an rwlayer through their inherited disk descriptors.
	DisksPrelocked bool
	// Filesystems are already-resolved protocol endpoints. Host path parsing,
	// root pinning, and share topology selection belong to composition layers;
	// the hypervisor package only attaches virtio devices. A non-nil Owner is
	// consumed by Prepare and closed with the Machine; nil means borrowed.
	Filesystems []Filesystem
	NetEndpoint string // Unix datagram raw-Ethernet endpoint; "" disables NIC
	NetConn     net.Conn
	// NetPolicy and NetTraffic are deliberately device-level interfaces.
	// Policy parsing, persistence, and cross-process synchronization belong
	// to the sandbox boundary, not the hypervisor package.
	NetPolicy  virtio.PacketPolicy
	NetTraffic virtio.TrafficObserver
	NetMAC     [6]byte
	NetVFKIT   bool
	VsockFwd   string // host dir for vsock forwarding; "" disables vsock (unless VsockDial is set)
	// VsockDial overrides guest->host connect-out (split VMM: the device
	// runs in the confined worker and bridges dial-backs to the
	// supervisor over RPC; it must never open host sockets by path).
	// VsockNoListen suppresses the AddListen unix listeners (host->guest
	// conns then arrive via Machine.InjectVsockConn from transferred
	// descriptors).
	VsockDial     func(port uint32) (net.Conn, error)
	VsockNoListen bool
	Interactive   bool // wire host stdin into the guest UART
	VCPUs         int  // guest vCPU count (SMP); validated against [MaxSupportedVCPUs]
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
	if nc == nil {
		return fmt.Errorf("nil vsock connection")
	}
	m.resourceMu.Lock()
	vsock := m.vsock
	running := m.lifecycle == machineRunning
	m.resourceMu.Unlock()
	if !running || vsock == nil {
		_ = nc.Close()
		return fmt.Errorf("vsock device is not running")
	}
	if err := vsock.InjectConn(guestPort, nc); err != nil {
		_ = nc.Close()
		return err
	}
	return nil
}

// RequestHotMemory publishes the opt-in virtio-mem capacity after the daemon
// has accepted the guest RPC connection. It is a no-op for ordinary machines.
// Keeping this edge in the host readiness lifecycle prevents Linux hotplug
// work from racing and occasionally starving the final guest boot steps.
func (m *Machine) RequestHotMemory() error {
	m.resourceMu.Lock()
	defer m.resourceMu.Unlock()
	if m.hotMem == nil || !m.hotMemDeferred {
		return nil
	}
	if m.lifecycle != machineRunning || m.backend == nil {
		return fmt.Errorf("request hot memory: machine is not running")
	}
	// Windows deliberately leaves the tail uncommitted and unmapped during
	// boot. Publish it to Linux only after the native backend makes every GPA
	// accessible; other backends use demand-paged mappings established at run.
	if mapper, ok := m.backend.(interface{ mapHotMemory() error }); ok {
		if err := mapper.mapHotMemory(); err != nil {
			return err
		}
	}
	m.mem.EnableHighRegion()
	m.hotMem.RequestAll()
	return nil
}

func Prepare(o Opts) (result *Machine, resultErr error) {
	inputs, inputErr := collectPrepareInputs(o)
	var m *Machine
	defer func() {
		inputCloseErr := inputs.Close()
		failed := result == nil || resultErr != nil || inputCloseErr != nil
		resultErr = errors.Join(resultErr, inputCloseErr)
		if failed && m != nil {
			resultErr = errors.Join(resultErr, m.Close(), m.releaseRAM())
			result = nil
		}
	}()
	if inputErr != nil {
		return nil, inputErr
	}
	if err := ValidateResources(o.MemSize, o.VCPUs); err != nil {
		return nil, err
	}

	bootTimingStart := o.BootTimingStart
	if bootTimingStart.IsZero() && os.Getenv("GANTRY_BOOT_TIMING") != "" {
		// Direct `gantry run` and one-shot exec have no daemon clock to pass.
		bootTimingStart = time.Now()
	}
	m = &Machine{stdinDone: make(chan struct{}), consoleStdin: o.Interactive,
		consoleW: o.Console, stdoutBuf: make([]byte, 0, 4096), kvmFD: inputs.takeFile(o.KVM),
		bootTiming: newBootTimeline(bootTimingStart, nil)}
	if m.consoleW == nil {
		m.consoleW = os.Stdout
	}
	arch, err := KernelArchFile(o.Kernel)
	if err != nil {
		return nil, err
	}
	initialCommit := o.MemSize
	virtioMemBootSize, virtioMemEnabled := uint64(0), false
	virtioMemDeferred := false
	if arch == "amd64" {
		virtioMemBootSize, virtioMemEnabled = x86VirtioMemLayout(o.MemSize, os.Getenv("GANTRY_VIRTIO_MEM"))
		virtioMemDeferred = virtioMemEnabled && (o.VsockFwd != "" || o.VsockDial != nil)
		if virtioMemDeferred {
			initialCommit = virtioMemBootSize
		}
	}
	// Guest RAM is allocated by the platform layer. Windows reserves the full
	// range but commits only the boot region for virtio-mem; mmap hosts remain
	// demand-paged and therefore ignore initialCommit.
	ram, err := allocGuestRAM(o.MemSize, initialCommit, o.SharedRAM)
	if err != nil {
		return nil, err
	}
	m.ram = ram
	// The Windows virtio-mem tail is still reserved/no-access here. Prefault
	// only memory that belongs to the boot phase; the tail is committed by the
	// WHPX backend immediately before it becomes visible to Linux.
	prefaultGuestRAM(m.bootTiming, ram[:initialCommit])

	entry, loadedArch, err := loadKernel(o.Kernel, ram)
	if closeErr := inputs.closeFile(o.Kernel); err != nil || closeErr != nil {
		return nil, errors.Join(err, closeErr)
	}
	if loadedArch != arch {
		return nil, fmt.Errorf("kernel architecture changed while loading: %s to %s", arch, loadedArch)
	}
	m.entry = entry
	m.arch = arch
	if arch == "amd64" {
		m.x86BootMemSize = o.MemSize
		m.x86LowRAMSize = min(o.MemSize, uint64(x86LowRAMEnd))
		if virtioMemEnabled {
			m.x86BootMemSize = virtioMemBootSize
			m.x86LowRAMSize = virtioMemBootSize
			m.x86HotMemSize = o.MemSize - virtioMemBootSize
		}
		m.mem = virtio.NewSplitRAM(ram, m.x86LowRAMSize, x86HighRAMStart)
		if virtioMemDeferred {
			m.mem.DeferHighRegion()
		}
	} else {
		m.mem = virtio.NewRAM(ram, ramBase)
	}

	var is, ie uint64
	if o.Initrd != nil {
		is, ie, err = loadInitrd(o.Initrd, ram)
		if closeErr := inputs.closeFile(o.Initrd); err != nil || closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
	}

	if arch == "amd64" {
		m.initX86()
	} else {
		m.uart = newPL011(m.raise, func(b byte) { m.stdoutWrite(b) })
	}
	if m.x86HotMemSize != 0 {
		memory, err := virtio.NewMem(x86HighRAMStart, m.x86HotMemSize, x86VirtioMemBlockSize)
		if err != nil {
			return nil, err
		}
		if virtioMemDeferred {
			memory.DeferRequested()
			m.hotMemDeferred = true
		}
		m.hotMem = memory
		core, err := m.addVirtio(memory, "mem")
		if err != nil {
			return nil, err
		}
		fmt.Printf("virtio-mem: boot %d MiB, hot-add %d MiB @ %#x irq %d\n",
			m.x86BootMemSize>>20, m.x86HotMemSize>>20, core.Base(), core.IRQ())
	}

	// Read-only container images deliberately skip the writable-disk flock:
	// cached images are shared across sandboxes.
	if err := m.attachDisks(o, inputs); err != nil {
		return nil, err
	}
	if err := m.attachFilesystems(o, inputs); err != nil {
		return nil, err
	}
	if err := m.attachNetwork(o, inputs); err != nil {
		return nil, err
	}
	if err := m.attachVsock(o); err != nil {
		return nil, err
	}
	// Entropy is mandatory: without virtio-rng the guest may block in
	// getrandom during boot. RTC attachment remains architecture-selective.
	if err := m.attachBootDevices(arch); err != nil {
		return nil, err
	}
	if err := m.finishBoot(o, ram, is, ie); err != nil {
		return nil, err
	}
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

func kernelArgPresent(cmdline, name string) bool {
	if i := strings.Index(cmdline, " -- "); i >= 0 {
		cmdline = cmdline[:i]
	}
	for _, field := range strings.Fields(cmdline) {
		if field == name || strings.HasPrefix(field, name+"=") {
			return true
		}
	}
	return false
}

// backend is the hypervisor contract: run a prepared machine until guest
// shutdown/reset or error. One implementation per platform, selected by
// build tags (KVM arm64/x86-64, HVF on macOS, WHPX on Windows) — see
// platformBackend in vm_linux.go, kvm_amd64.go, vm_darwin.go and
// whpx_windows.go. Adding a platform means implementing backend and
// returning it from platformBackend; nothing else in vmm is platform-aware.
//
// Lifecycle: a platform backend owns its vCPU threads and all native
// hypervisor resources. Machine.Close asks it to stop, joins Run (including
// partial backend initialization), then closes devices and guest RAM.
type backend interface {
	run(m *Machine) error
}

// Run boots the prepared machine on the platform hypervisor backend.
// Devices are flushed and closed (Machine.Close) before Run returns.
func Run(m *Machine) (resultErr error) {
	if m == nil {
		return fmt.Errorf("vmm: nil machine")
	}
	if err := m.beginRun(); err != nil {
		return err
	}
	defer func() {
		m.finishRun()
		if closeErr := m.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	return platformBackend().run(m)
}

// PSTATE at boot lives in pstate.go (arm64 backends only).
