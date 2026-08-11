package vmm

import (
	"os"
	"time"
)

// Guest RAM is plain anonymous memory: the host commits a physical page only
// when something touches it, so every first guest access takes a host demand
// fault. prefaultGuestRAM moves that cost into Prepare, where the timeline
// can see it.
//
// Measured on an M-series host, 512 MiB guest: committing all of RAM costs
// ~28 ms and moves the guest's first-UART milestone by nothing at all. Host
// demand paging is NOT a meaningful part of guest boot latency here — the
// idle accounting on the milestone lines is where that time actually went.
// The knob stays as an A/B for future RAM-shaped questions; it is off by
// default because it trades startup latency for committing every guest page,
// including the ones the guest would never touch.
func prefaultGuestRAM(timeline *bootTimeline, ram []byte) {
	if os.Getenv("GANTRY_PREFAULT_RAM") == "" {
		return
	}
	start := time.Now()
	// 4 KiB is the smallest page any supported host uses; a stride that
	// divides the real page size touches every page at worst redundantly.
	const stride = 4096
	for offset := 0; offset < len(ram); offset += stride {
		ram[offset] = 0
	}
	timeline.note("guest RAM prefaulted", start, time.Now())
}
