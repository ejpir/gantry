//go:build (linux && amd64) || windows

package vmm

// Minimal i8254 PIT for hypervisors without an in-kernel one (WHPX).
// Ports 0x40-0x42 (channel counters), 0x43 (mode/command), plus the port
// 0x61 gate bit for channel 2. Channel 0 in a periodic mode raises IRQ 0
// via a host ticker; counter reads derive from elapsed host time (the PIT
// runs at 1193182 Hz).

import (
	"sync"
	"time"
)

const pitClockHz = 1193182

type pitChannel struct {
	access   byte // latch/lsb/msb/lohi
	mode     byte // 0..5
	reload   uint16
	running  bool
	start    time.Time
	writeLSB bool // toggle state for lohi
	readLSB  bool
}

type pit8254 struct {
	mu     sync.Mutex
	ch     [3]pitChannel
	raise  func(level bool) // IRQ 0 line
	cancel func()
	nmi61  byte // port 0x61 shadow
}

func newPIT(raise func(level bool)) *pit8254 {
	return &pit8254{raise: raise}
}

func (p *pit8254) count(ch int) uint16 {
	c := &p.ch[ch]
	if !c.running || c.reload == 0 {
		return 0
	}
	ticks := uint64(time.Since(c.start).Nanoseconds()) * pitClockHz / 1e9
	if c.mode == 0 { // one-shot: count down to 0 and stop
		if ticks >= uint64(c.reload) {
			return 0
		}
		return c.reload - uint16(ticks)
	}
	// periodic: current value counts down from reload
	return c.reload - uint16(ticks%uint64(c.reload))
}

func (p *pit8254) ioRead(port uint16) byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	idx := int(port - 0x40)
	if idx < 0 || idx > 2 {
		if port == 0x61 {
			// Bit 5 (OUT2) is live state, not a shadow: early TSC
			// calibration runs channel 2 in one-shot mode and polls
			// this bit until the count expires. KVM's in-kernel PIT
			// covers this on Linux; on WHPX we must model it.
			v := p.nmi61 &^ 0x20
			c := &p.ch[2]
			if c.running && c.reload != 0 {
				ticks := uint64(time.Since(c.start).Nanoseconds()) * pitClockHz / 1e9
				expired := false
				if c.mode == 0 || c.mode == 4 { // one-shot: OUT high at terminal count
					expired = ticks >= uint64(c.reload)
				} else { // periodic: high for the second half of each cycle
					expired = ticks%uint64(c.reload) >= uint64(c.reload)/2
				}
				if expired {
					v |= 0x20
				}
			}
			return v
		}
		return 0xff
	}
	v := p.count(idx)
	if p.ch[idx].access == 1 { // LSB only
		return byte(v)
	}
	if p.ch[idx].access == 2 { // MSB only
		return byte(v >> 8)
	}
	// lohi: toggle
	if p.ch[idx].readLSB {
		p.ch[idx].readLSB = false
		return byte(v >> 8)
	}
	p.ch[idx].readLSB = true
	return byte(v)
}

func (p *pit8254) ioWrite(port uint16, val byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if port == 0x43 { // mode/command
		idx := (val >> 6) & 3
		if idx == 3 || (val>>4)&3 == 0 {
			return // read-back / latch commands: not needed by Linux early boot
		}
		c := &p.ch[idx]
		c.access = (val >> 4) & 3
		c.mode = (val >> 1) & 7
		c.writeLSB = true
		c.running = false
		if p.cancel != nil && idx == 0 {
			p.cancel()
			p.cancel = nil
		}
		return
	}
	if port == 0x61 {
		p.nmi61 = val
		return
	}
	idx := int(port - 0x40)
	if idx < 0 || idx > 2 {
		return
	}
	c := &p.ch[idx]
	switch c.access {
	case 1:
		c.reload = uint16(val)
	case 2:
		c.reload = uint16(val) << 8
	default: // lohi
		if c.writeLSB {
			c.reload = c.reload&0xff00 | uint16(val)
			c.writeLSB = false
			return // wait for MSB
		}
		c.reload = c.reload&0x00ff | uint16(val)<<8
	}
	if c.reload == 0 {
		c.reload = 0xffff // 0 means 65536; close enough for a tick source
	}
	c.start = time.Now()
	c.running = true
	if idx == 0 && p.raise != nil {
		p.armTimerLocked()
	}
}

// armTimerLocked (re)starts the IRQ 0 generator for channel 0. Periodic
// modes pulse the line at reload ticks; one-shot fires once.
func (p *pit8254) armTimerLocked() {
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	mode := p.ch[0].mode
	period := time.Duration(uint64(p.ch[0].reload)) * time.Second / pitClockHz
	if period < time.Millisecond/2 {
		period = time.Millisecond / 2 // don't melt the host for absurd rates
	}
	oneShot := mode == 0
	stop := make(chan struct{})
	p.cancel = func() { close(stop) }
	raise := p.raise
	go func() {
		if oneShot {
			t := time.NewTimer(period)
			defer t.Stop()
			select {
			case <-t.C:
				raise(true)
				raise(false)
			case <-stop:
			}
			return
		}
		t := time.NewTicker(period)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				raise(true)
				raise(false) // pulse: edge semantics
			case <-stop:
				return
			}
		}
	}()
}
