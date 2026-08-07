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
// the nerdbox kernel's CONFIG_VIRTIO_RTC{_CLASS,_PTP} driver expects:
// the kernel sets the system time from it at probe (hctosys), and vminitd's
// clock service keeps it in sync through the /dev/ptp clock the driver
// registers ("no virtio-rtc PTP clock present" without it).
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

	RTCClockUTC = 0

	RTCRespLen = 16 // all responses we emit are header + 8 bytes
)

type RTC struct {
	core *Core
	now  func() time.Time // test hook
	// probes records the first queue activity for postmortems: when the
	// guest clock stays at epoch, "rtc: first request" in the daemon log
	// proves the kernel driver reached us (vs. never probing the node).
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
			if rtcDebug && v.probes.Add(1) <= 4 {
				fmt.Fprintf(os.Stderr, "virtio-rtc: request msg_type=%#x len=%d\n", binary.LittleEndian.Uint16(req[0:2]), len(req))
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
			resp[8] = RTCClockUTC // type
			resp[9] = 0           // leap_second_smearing: UNSPECIFIED
			resp[10] = 0          // flags: no alarm capability
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
