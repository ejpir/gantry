//go:build (linux && amd64) || windows

package devices

// Tiny MC146818 CMOS/RTC emulation for x86-64 guests: ports 0x70 (index) /
// 0x71 (data). The kernel reads wall-clock time from here during early boot
// (before virtio-rtc's hctosys takes over), so we answer the BCD clock
// registers from the host's UTC time. Everything else reads as benign
// defaults (register D with the VRT "battery good" bit set).

import (
	"sync"
	"time"
)

const (
	CMOSIndexPort = 0x70
	CMOSDataPort  = 0x71
)

// mu guards the index register: ioRead/ioWrite run on every vCPU thread
// (machine.handleIO), so -cpus 2 would race it otherwise.
type CMOSRTC struct {
	mu    sync.Mutex
	index byte
}

func bcd(v int) byte { return byte((v/10)<<4 | (v % 10)) }

func (c *CMOSRTC) IORead(port uint16) byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if port == CMOSIndexPort {
		return c.index
	}
	now := time.Now().UTC()
	switch c.index & 0x7f {
	case 0x00:
		return bcd(now.Second())
	case 0x02:
		return bcd(now.Minute())
	case 0x04:
		return bcd(now.Hour())
	case 0x06:
		return bcd(int(now.Weekday()) + 1) // 1=Sunday
	case 0x07:
		return bcd(now.Day())
	case 0x08:
		return bcd(int(now.Month()))
	case 0x09:
		return bcd(now.Year() % 100)
	case 0x0a: // status A: 32.768kHz, no update in progress
		return 0x26
	case 0x0b: // status B: 24h mode, BCD, interrupts off
		return 0x02
	case 0x0c: // status C: no IRQ flags
		return 0x00
	case 0x0d: // status D: VRT (RTC content valid)
		return 0x80
	case 0x0e: // diagnostic status: "no errors"
		return 0x00
	case 0x0f: // shutdown status
		return 0x00
	case 0x32: // century (some kernels read it)
		return bcd(now.Year() / 100)
	}
	return 0
}

func (c *CMOSRTC) IOWrite(port uint16, val byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if port == CMOSIndexPort {
		c.index = val
	}
}
