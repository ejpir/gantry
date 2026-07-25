package vmm

import (
	"fmt"
	"gantry/internal/gutil"
	"os"
	"sync"
)

// Minimal PL011 UART emulation. Register map (ARM DDI0183):
//
//	0x00 UARTDR    data register (rw)
//	0x04 UARTRSR/ECR
//	0x18 UARTFR    flags: TXFE(7) RXFF(6) TXFF(5) RXFE(4) BUSY(3)
//	0x24 UARTIBRD  (ignored)
//	0x28 UARTFBRD  (ignored)
//	0x2C UARTLCR_H (ignored)
//	0x30 UARTCR    control (stored)
//	0x38 UARTIMSC  interrupt mask (rw)
//	0x3C UARTRIS   RAW interrupt status (ro)   <-- was wrongly at 0x40!
//	0x40 UARTMIS   masked interrupt status (ro) = RIS & IMSC
//	0x44 UARTICR   interrupt clear (wo)
//	0xFE0-0xFFF    PeriphID/CellID
//
// The storm this fixed: the driver polls RIS at 0x3C; with our RIS at the
// wrong offset it always read 0 -> pl011_int returned IRQ_NONE -> the
// kernel disabled the IRQ ("nobody cared").
var noUartIRQ = gutil.EnvOr("GANTRY_NO_UART_IRQ", "MINIVM_NO_UART_IRQ") != ""
var dbgUartIRQ = gutil.EnvOr("GANTRY_DEBUG", "MINIVM_DEBUG") != "" || gutil.EnvOr("GANTRY_DEBUG_UART", "MINIVM_DEBUG_UART") != ""

type pl011 struct {
	mu       sync.Mutex
	rxBuf    []byte // bytes typed on host stdin, waiting for the guest
	imsc     uint32
	cr       uint32
	irqLevel bool
	raise    func(irq int, level bool)
	output   func(b byte)
}

func newPL011(raise func(int, bool), output func(byte)) *pl011 {
	return &pl011{raise: raise, output: output}
}

func (u *pl011) dbg(format string, a ...any) {
	if dbgUartIRQ {
		fmt.Printf("[uart] "+format+"\n", a...)
	}
}

// feed is called by the host stdin pump with typed bytes.
func (u *pl011) feed(b []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.rxBuf = append(u.rxBuf, b...)
	u.updateIRQLocked()
}

// updateIRQLocked drives the IRQ line like real PL011 hardware:
// level = (RX interrupt pending AND unmasked). Assert while the FIFO has
// data, deassert once the guest drains it.
func (u *pl011) updateIRQLocked() {
	if u.raise == nil {
		return
	}
	level := len(u.rxBuf) > 0 && u.imsc&0x10 != 0
	if level != u.irqLevel {
		u.dbg("IRQ %d -> %v (fifo=%d imsc=%#x)", uartIRQ, level, len(u.rxBuf), u.imsc)
		u.irqLevel = level
		if !noUartIRQ {
			u.raise(uartIRQ, level)
		}
	}
}

func (u *pl011) ris() uint32 {
	if len(u.rxBuf) > 0 {
		return 0x10 // RXRIS
	}
	return 0
}

// mmio handles one guest MMIO access. Returns the value for reads.
func (u *pl011) mmio(isWrite bool, off uint64, data []byte, length uint32) uint32 {
	u.mu.Lock()
	defer u.mu.Unlock()

	switch {
	case isWrite && off == 0x00: // UARTDR
		for i := uint32(0); i < length && i < 8; i++ {
			if data[i] != 0 { // don't spray NULs from wide writes
				u.output(data[i])
			}
		}
		return 0
	case !isWrite && off == 0x00: // UARTDR read
		var v byte
		if len(u.rxBuf) > 0 {
			v = u.rxBuf[0]
			u.rxBuf = u.rxBuf[1:]
		}
		u.updateIRQLocked()
		return uint32(v)
	case !isWrite && off == 0x18: // UARTFR
		fr := uint32(0x80) // TXFE: transmit fifo always empty
		if len(u.rxBuf) == 0 {
			fr |= 0x10 // RXFE
		}
		return fr
	case isWrite && off == 0x30: // UARTCR
		u.cr = uint32(data[0]) | uint32(data[1])<<8
		return 0
	case !isWrite && off == 0x30:
		return u.cr
	case !isWrite && off == 0x38: // UARTIMSC
		return u.imsc
	case isWrite && off == 0x38:
		u.imsc = uint32(data[0]) | uint32(data[1])<<8
		u.updateIRQLocked()
		return 0
	case !isWrite && off == 0x3c: // UARTRIS — the offset the driver polls
		return u.ris()
	case !isWrite && off == 0x40: // UARTMIS = RIS & IMSC
		return u.ris() & uint32(u.imsc)
	case isWrite && off == 0x44: // UARTICR
		return 0
	case !isWrite && off >= 0xfe0: // UARTPeriphID0-3 / UARTCellID0-3
		return uint32(pl011ID[(off-0xfe0)/4])
	default:
		return 0
	}
}

// pl011ID: PeriphID0-3 (0xfe0..0xfec), CellID0-3 (0xff0..0xffc) — same as QEMU.
var pl011ID = [8]byte{0x11, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1}

// stdinPump copies host stdin into the UART RX buffer.
func (u *pl011) stdinPump(done <-chan struct{}) {
	buf := make([]byte, 64)
	for {
		select {
		case <-done:
			return
		default:
		}
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			u.feed(buf[:n])
		}
		if err != nil {
			return
		}
	}
}
