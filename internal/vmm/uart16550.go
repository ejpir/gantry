//go:build (linux && amd64) || windows

package vmm

// Minimal 16550A UART for x86-64 guests: the kernel's 8250 driver probes
// ports 0x3f8..0x3ff (COM1, IRQ 4) and console=ttyS0 talks to it. Only what
// Linux actually needs: TX/RX holding registers, divisor latches (stored),
// IER/IIR/FCR, LCR (DLAB), MCR, LSR (always ready to transmit), MSR, SCR.

import (
	"fmt"
	"os"
	"sync"
)

const (
	x86SerialPort = 0x3f8
	x86SerialSize = 8
	x86SerialIRQ  = 4
)

type uart16550 struct {
	mu     sync.Mutex
	raise  func(level bool)
	output func(b byte)

	rx  []byte // host input waiting for the guest
	ier byte
	fcr byte
	lcr byte
	mcr byte
	scr byte
	dll byte
	dlm byte
}

func newUART16550(raise func(level bool), output func(byte)) *uart16550 {
	return &uart16550{raise: raise, output: output}
}

func (u *uart16550) dlab() bool { return u.lcr&0x80 != 0 }

// irqLevel computes the IRQ4 line state. A real 16550 treats interrupts as
// level conditions: RX-data-available (IER.0) and THR-empty (IER.1). Our
// host drain is instant, so THR is always empty and the THRE condition is
// exactly IER.1 — the 8250 driver's interrupt-driven TX path (used for
// userspace /dev/console writes, unlike polling kernel printk) stalls
// without it.
func (u *uart16550) irqLevel() bool {
	rx := len(u.rx) > 0 && u.ier&0x01 != 0
	thre := u.ier&0x02 != 0
	return rx || thre
}

// syncIRQ drives the line to the current level; callers hold mu.
func (u *uart16550) syncIRQ() { u.raise(u.irqLevel()) }

func (u *uart16550) feed(b []byte) {
	u.mu.Lock()
	u.rx = append(u.rx, b...)
	u.syncIRQ()
	u.mu.Unlock()
}

func (u *uart16550) ioRead(port uint16) byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	r := byte(port - x86SerialPort)
	switch {
	case r == 0 && u.dlab():
		return u.dll
	case r == 1 && u.dlab():
		return u.dlm
	case r == 0: // RBR
		var b byte
		if len(u.rx) > 0 {
			b = u.rx[0]
			u.rx = u.rx[1:]
		}
		u.syncIRQ()
		return b
	case r == 1: // IER
		return u.ier
	case r == 2: // IIR: FIFO bits mirror FCR; report highest pending cause
		iir := byte(0x01) // no interrupt pending
		if len(u.rx) > 0 && u.ier&0x01 != 0 {
			iir = 0x04 // received data available
		} else if u.ier&0x02 != 0 {
			iir = 0x02 // THR empty
		}
		if u.fcr&0x01 != 0 {
			iir |= 0xc0
		}
		return iir
	case r == 3:
		return u.lcr
	case r == 4:
		return u.mcr
	case r == 5: // LSR: THR empty + transmitter idle; DR when input pending
		lsr := byte(0x60)
		if len(u.rx) > 0 {
			lsr |= 0x01
		}
		return lsr
	case r == 6: // MSR: DCD|DSR|CTS
		return 0xb0
	case r == 7:
		return u.scr
	}
	return 0xff
}

func (u *uart16550) ioWrite(port uint16, val byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	r := byte(port - x86SerialPort)
	switch {
	case r == 0 && u.dlab():
		u.dll = val
	case r == 1 && u.dlab():
		u.dlm = val
	case r == 0: // THR
		u.output(val)
	case r == 1:
		u.ier = val & 0x0f
		u.syncIRQ() // THRE (IER.1) is a level condition: (de)assert now
	case r == 2: // FCR
		u.fcr = val & 0xc9
	case r == 3:
		u.lcr = val
	case r == 4:
		u.mcr = val
	case r == 7:
		u.scr = val
	}
}

// stdinPump forwards host stdin bytes into the guest serial port.
func (u *uart16550) stdinPump(done <-chan struct{}) {
	buf := make([]byte, 256)
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

func (u *uart16550) String() string {
	return fmt.Sprintf("16550 @ %#x irq %d", x86SerialPort, x86SerialIRQ)
}
