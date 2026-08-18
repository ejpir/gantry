//go:build (linux && amd64) || windows

package vmm

import (
	"fmt"

	"github.com/ejpir/gantry/internal/vmm/devices"
)

// x86Devices clusters the legacy PC devices: 16550 console UART, CMOS
// RTC, PIT and PIC. They exist only on the x86 boot paths (KVM on
// linux/amd64, WHPX on Windows), so the whole cluster — device models,
// port-I/O dispatch, and this struct — is build-gated: arm64 builds
// carry no dead emulation code. The struct is defined per platform
// (x86devices_linux_amd64.go / x86devices_windows.go): WHPX additionally
// needs a userspace I/O APIC, which KVM provides in-kernel. On non-x86
// platforms x86devices_stub.go provides the empty type.
//
// initX86 and handleIO are shared by both x86 backends and live here.

// initX86 wires the legacy devices for the x86 boot path (console=ttyS0).
func (m *Machine) initX86() {
	m.x86.uartIO = devices.NewUART16550(func(level bool) { m.raise(devices.SerialIRQ, level) },
		func(b byte) { m.stdoutWrite(b) })
	m.x86.cmos = &devices.CMOSRTC{}
	m.x86.pit = devices.NewPIT(func(level bool) { m.raise(0, level) })
	m.x86.pic = devices.NewPIC(nil)
	fmt.Printf("serial: %s (console=ttyS0)\n", m.x86.uartIO)
}

// handleIO routes one x86 port-I/O access (16550 console, CMOS RTC; other
// legacy ports read as 1s / drop writes like an empty bus).
func (m *Machine) handleIO(isWrite bool, port uint16, val uint32, size int) uint32 {
	switch {
	case port >= devices.SerialPort && port < devices.SerialPort+devices.SerialSize && m.x86.uartIO != nil:
		if isWrite {
			m.x86.uartIO.IOWrite(port, byte(val))
			return 0
		}
		return uint32(m.x86.uartIO.IORead(port))
	case port == devices.CMOSIndexPort || port == devices.CMOSDataPort:
		if isWrite {
			m.x86.cmos.IOWrite(port, byte(val))
			return 0
		}
		return uint32(m.x86.cmos.IORead(port))
	case m.x86.pit != nil && ((port >= 0x40 && port <= 0x43) || port == 0x61):
		if isWrite {
			m.x86.pit.IOWrite(port, byte(val))
			return 0
		}
		return uint32(m.x86.pit.IORead(port))
	case m.x86.pic != nil && (port == 0x20 || port == 0x21 || port == 0xa0 || port == 0xa1):
		if isWrite {
			m.x86.pic.IOWrite(port, byte(val))
			return 0
		}
		return uint32(m.x86.pic.IORead(port))
	}
	if devices.DebugIO && !isWrite {
		fmt.Printf("[io] unhandled read port %#x\n", port)
	}
	return 0xffffffff
}
