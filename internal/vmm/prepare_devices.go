package vmm

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"

	"github.com/ejpir/gantry/internal/virtio"
)

// checkNilInterface reports an interface value that is non-nil but holds a
// nil pointer — "no policy" expressed as a live implementation that dies (or
// lies) on first use. Callers must leave the field nil to mean absent.
func checkNilInterface(field string, value any) error {
	if value == nil {
		return nil
	}
	switch v := reflect.ValueOf(value); v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		if v.IsNil() {
			return fmt.Errorf("opts.%s holds a nil %s: leave the field nil when there is none", field, v.Type())
		}
	}
	return nil
}

type diskInput struct {
	file     *os.File
	writable bool
}

func (m *Machine) attachDisks(o Opts, inputs *prepareInputs) error {
	disks := make([]diskInput, 0, 1+len(o.DisksRO)+len(o.Disks))
	if o.Rootfs != nil {
		disks = append(disks, diskInput{file: o.Rootfs})
	}
	for _, file := range o.DisksRO {
		disks = append(disks, diskInput{file: file})
	}
	for _, file := range o.Disks {
		disks = append(disks, diskInput{file: file, writable: true})
	}

	for index, disk := range disks {
		path := disk.file.Name()
		var block *virtio.Blk
		var err error
		if disk.writable && o.DisksPrelocked {
			block, err = virtio.NewBlkFilePrelocked(disk.file, true)
		} else {
			block, err = virtio.NewBlkFile(disk.file, disk.writable)
		}
		if err != nil {
			return fmt.Errorf("disk %s: %w", path, err)
		}
		inputs.takeFile(disk.file) // block now owns the descriptor.
		core, err := m.addVirtio(block, "blk")
		if err != nil {
			return err
		}
		if index == 0 && o.Rootfs != nil {
			m.rootBlkCore = core
		}
		mode := "ro"
		if disk.writable {
			mode = "rw"
		}
		fmt.Printf("virtio-blk: %s @ %#x irq %d (%s, %d MiB) -> /dev/vd%c\n",
			path, core.Base(), core.IRQ(), mode, block.Size()>>20, 'a'+index)
	}
	return nil
}

func (m *Machine) attachNetwork(o Opts, inputs *prepareInputs) error {
	if o.NetConn == nil && o.NetEndpoint == "" {
		return nil
	}

	var (
		nic *virtio.Net
		err error
		how string
	)
	if o.NetConn != nil {
		nic = virtio.NewNetConn(inputs.takeNetConn(), o.NetMAC)
		how = "embedded netstack"
	} else {
		nic, err = virtio.NewNetUnixgram(o.NetEndpoint, o.NetMAC, o.NetVFKIT)
		if err != nil {
			return fmt.Errorf("virtio-net: %w", err)
		}
		how = "unixgram " + o.NetEndpoint
	}
	// A typed-nil in either interface is a composition bug with two bad
	// endings: the device's nil guard passes and the first frame panics the
	// VMM, or a nil-tolerant implementation makes every configured deny
	// silently vanish. Neither is survivable for an egress boundary — refuse
	// the boot instead, while the caller can still see why.
	if err := checkNilInterface("NetPolicy", o.NetPolicy); err != nil {
		return err
	}
	if err := checkNilInterface("NetTraffic", o.NetTraffic); err != nil {
		return err
	}
	nic.SetPolicy(o.NetPolicy)
	nic.SetTrafficObserver(o.NetTraffic)
	core, err := m.addVirtio(nic, "net")
	if err != nil {
		return err
	}
	fmt.Printf("virtio-net: mac %02x:%02x:%02x:%02x:%02x:%02x @ %#x irq %d, %s\n",
		o.NetMAC[0], o.NetMAC[1], o.NetMAC[2], o.NetMAC[3], o.NetMAC[4], o.NetMAC[5],
		core.Base(), core.IRQ(), how)
	return nil
}

func (m *Machine) attachVsock(o Opts) error {
	if o.VsockFwd == "" && o.VsockDial == nil {
		return nil
	}
	vsock := virtio.NewVsock(o.GuestCID, o.VsockFwd)
	if o.VsockDial != nil {
		vsock.SetDial(o.VsockDial)
	}
	core, err := m.addVirtio(vsock, "vsock")
	if err != nil {
		return err
	}
	if !o.VsockNoListen {
		for _, port := range o.VsockListen {
			if _, err := vsock.AddListen(port); err != nil {
				return fmt.Errorf("virtio-vsock listen port %d: %w", port, err)
			}
		}
	}
	m.vsock = vsock
	m.vsockCore = core
	fmt.Printf("virtio-vsock: guest cid %d @ %#x irq %d, host dir %s\n",
		o.GuestCID, core.Base(), core.IRQ(), o.VsockFwd)
	return nil
}

func (m *Machine) attachBootDevices(arch string) error {
	// The guest seeds its CRNG from virtio-rng during probe; without it PID 1
	// can block in getrandom before networking is ready.
	rngCore, err := m.addVirtio(virtio.NewRNG(), "rng")
	if err != nil {
		return err
	}
	fmt.Printf("virtio-rng: entropy @ %#x irq %d\n", rngCore.Base(), rngCore.IRQ())

	// arm64 needs the emulated RTC because HVF has no kvm-clock equivalent.
	// Linux x86 uses kvm-clock/ptp_kvm and leaves this off because registering
	// rtc0 can stall runsc. WHPX exposes neither kvm clock, so Windows x86
	// needs virtio-rtc to set and continuously synchronize guest wall time.
	attachRTC := arch != "amd64" || runtime.GOOS == "windows"
	if os.Getenv("GANTRY_RTC") != "" {
		attachRTC = true
	}
	if os.Getenv("GANTRY_NO_RTC") != "" {
		attachRTC = false
	}
	if !attachRTC {
		return nil
	}
	rtcCore, err := m.addVirtio(virtio.NewRTC(), "rtc")
	if err != nil {
		return err
	}
	fmt.Printf("virtio-rtc: UTC (host time) @ %#x irq %d\n", rtcCore.Base(), rtcCore.IRQ())
	return nil
}

func (m *Machine) finishBoot(o Opts, ram []byte, initrdStart, initrdEnd uint64) error {
	m.vcpus = o.VCPUs
	cmdline := o.Cmdline
	if m.arch == "amd64" {
		var err error
		if cmdline, err = platformKernelArgs(cmdline, m.arch); err != nil {
			// A missing/older capability is a performance degradation, not a
			// correctness failure: retain Linux's normal calibration fallback.
			fmt.Printf("WHPX: automatic early kernel arguments unavailable: %v\n", err)
		}
		var slots strings.Builder
		for _, core := range m.virtios {
			fmt.Fprintf(&slots, " virtio_mmio.device=0x%x@0x%x:%d",
				x86MMIOStride, core.Base(), core.IRQ())
		}
		cmdline = insertKernelArgs(cmdline, strings.TrimSpace(slots.String()))
		if m.x86HotMemSize != 0 {
			cmdline = insertKernelArgs(cmdline, "memhp_default_state=online_kernel")
		}
		if err := setupX86Boot(ram, cmdline, m.x86BootMemSize, m.vcpus); err != nil {
			return err
		}
		fmt.Printf("boot params @ %#x, cmdline @ %#x (%d bytes), MPS @ %#x\n",
			x86ZeroPage, x86CmdlineAddr, len(cmdline), x86MPSFloatingPtr)
		return nil
	}

	m.fdt = buildGuestFDT(o.MemSize, initrdStart, initrdEnd, cmdline, len(m.virtios), m.vcpus)
	if len(m.fdt) > maxFDTSize {
		return fmt.Errorf("FDT too large: %d", len(m.fdt))
	}
	fdtOffset := uint64(fdtAddr - ramBase)
	if fdtOffset > uint64(len(m.ram)) || uint64(len(m.fdt)) > uint64(len(m.ram))-fdtOffset {
		return fmt.Errorf("guest RAM too small for FDT")
	}
	copy(m.ram[fdtOffset:], m.fdt)
	fmt.Printf("fdt: %d bytes @ %#x\n", len(m.fdt), fdtAddr)
	return nil
}
