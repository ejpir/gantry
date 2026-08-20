package virtio

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// virtio-rtc (device ID 17), no ALARM feature: a single requestq answering
// READ/CFG/CLOCK_CAP for one UTC clock backed by the host clock. This is
// the OpenSynergy virtio-rtc protocol (virtio-spec device-types/rtc), which
// is also what the reference VMM implements (crates/devices/virtio-rtc) and what
// the nerdbox kernel's CONFIG_VIRTIO_RTC{_CLASS,_PTP} driver expects. The
// kernel sets the system time from it exactly once, at probe (hctosys);
// the device is pull-only, so keeping wall time synced afterwards is the
// guest's job: vminitd runs a clock-sync loop (patched in at rootfs build
// by patches/nerdbox-v0.2.3-clock-sync.patch) that re-reads the driver's
// /dev/ptp clock every 30s and steps CLOCK_REALTIME. Without that loop
// guest wall time is one probe reading plus raw counter elapsed — it drifts
// at the counter crystal's ppm error and, on HVF/WHPX, skips entire
// host-suspend intervals because the host physical counter stops across
// sleep (x86 KVM attaches no RTC at all: kvm-clock is host-referenced).
const (
	RTCDeviceID = 17

	RTCReqRead      = 0x0001
	RTCReqReadCross = 0x0002
	RTCReqCfg       = 0x1000
	RTCReqClockCap  = 0x1001
	RTCReqCrossCap  = 0x1002
	// 0x1003..0x1005 are alarm requests (VIRTIO_RTC_F_ALARM not offered)

	RTCSOK         = 0
	RTCSEOPNOTSUPP = 2
	RTCSENODEV     = 3
	RTCSEINVAL     = 4

	// RTCClockUTCSmeared is what the kernel's RTC class driver accepts:
	// virtio_rtc_driver.c refuses to create the class device (and thus
	// to run hctosys) for any clock that "may step on leap seconds",
	// i.e. for plain VIRTIO_RTC_CLOCK_UTC. Host POSIX time never steps
	// for leap seconds, so smeared UTC with an unspecified variant is
	// the honest capability.
	RTCClockUTCSmeared = 3 // VIRTIO_RTC_CLOCK_UTC_SMEARED

	RTCRespLen = 16 // all responses we emit are header + 8 bytes
)

type RTC struct {
	core *Core
	now  func() time.Time // test hook
	// probes counts requests for the postmortem/heartbeat log: the first
	// few prove the kernel driver reached us (vs. never probing the node),
	// and every 120th afterwards keeps the guest's 30s clock-sync polls
	// visible as an hourly liveness mark (a drought in field logs means the
	// guest stopped asking).
	probes atomic.Int32
}

func NewRTC() *RTC { return &RTC{now: time.Now} }

// rtcDebug gates the first-requests postmortem log.
var rtcDebug = os.Getenv("GANTRY_DEBUG_RTC") != ""

func (v *RTC) deviceID() uint32 { return RTCDeviceID }
func (v *RTC) features() uint64 { return 0 } // no VIRTIO_RTC_F_ALARM
func (v *RTC) numQueues() int   { return 1 } // requestq only
func (v *RTC) reset()           {}

// No device configuration layout is defined for virtio-rtc.
func (v *RTC) configRead(off uint64, p []byte)  {}
func (v *RTC) configWrite(off uint64, p []byte) {}

func (v *RTC) handleQueue(qn int) {
	q := &v.core.queues[qn]
	for {
		head, chain, ok := v.core.availChain(qn)
		if !ok {
			return
		}
		readable, writable := splitChain(chain)
		req, err := v.core.readChains(readable)

		var resp [RTCRespLen]byte
		switch {
		case err != nil || len(req) < 8:
			resp[0] = RTCSEINVAL
		default:
			if n := v.probes.Add(1); rtcDebug && (n <= 4 || n%120 == 0) {
				fmt.Fprintf(os.Stderr, "virtio-rtc: request #%d msg_type=%#x len=%d\n", n, binary.LittleEndian.Uint16(req[0:2]), len(req))
			}
			v.dispatch(binary.LittleEndian.Uint16(req[0:2]), req, &resp)
		}

		var written uint32
		if len(writable) > 0 && writable[0].len >= RTCRespLen {
			if err := v.core.mem.writeAt(writable[0].addr, resp[:]); err == nil {
				written = RTCRespLen
			}
		}
		v.core.pushUsed(q, head, written)
	}
}

func (v *RTC) dispatch(msgType uint16, req []byte, resp *[RTCRespLen]byte) {
	clockID := func() uint16 {
		if len(req) < 16 {
			return 0xffff // malformed: no clock_id field present
		}
		return binary.LittleEndian.Uint16(req[8:10])
	}

	switch msgType {
	case RTCReqCfg:
		resp[0] = RTCSOK
		binary.LittleEndian.PutUint16(resp[8:], 1) // num_clocks: clock 0
	case RTCReqClockCap:
		if id := clockID(); id != 0 {
			resp[0] = RTCSENODEV
			_ = id
		} else {
			resp[0] = RTCSOK
			resp[8] = RTCClockUTCSmeared // type: smeared UTC
			resp[9] = 0                  // leap_second_smearing: UNSPECIFIED
			resp[10] = 0                 // flags: no alarm capability
		}
	case RTCReqRead:
		if clockID() != 0 {
			resp[0] = RTCSENODEV
		} else {
			resp[0] = RTCSOK
			binary.LittleEndian.PutUint64(resp[8:], uint64(v.now().UnixNano()))
		}
	case RTCReqCrossCap:
		// Supported in principle by the ARM counter driver, but we do not
		// correlate CNTVCT with UTC: report "no cross capability" and let
		// the driver use plain REQ_READ.
		if clockID() != 0 {
			resp[0] = RTCSENODEV
		} else {
			resp[0] = RTCSOK
			resp[8] = 0 // flags: CROSS_CAP not set
		}
	default:
		// READ_CROSS (capability says unsupported), alarm requests
		// (feature not negotiated), unknown msg_type.
		resp[0] = RTCSEOPNOTSUPP
	}
}

// rtcMaxChainBytes caps one request chain; every legitimate RTC message
// is 16 bytes (review finding 2: no device may size host allocations
// from unchecked guest lengths).
const rtcMaxChainBytes = 4096

func (v *RTC) maxChainBytes(qn int) uint64 { return rtcMaxChainBytes }

func (v *RTC) setCore(c *Core) { v.core = c }
