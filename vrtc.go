package main

import (
	"encoding/binary"
	"time"
)

// virtio-rtc (device ID 17), no ALARM feature: a single requestq answering
// READ/CFG/CLOCK_CAP for one UTC clock backed by the host clock. This is
// the OpenSynergy virtio-rtc protocol (virtio-spec device-types/rtc), which
// is also what libsailor implements (crates/devices/virtio-rtc) and what
// the nerdbox kernel's CONFIG_VIRTIO_RTC{_CLASS,_PTP} driver expects:
// the kernel sets the system time from it at probe (hctosys), and vminitd's
// clock service keeps it in sync through the /dev/ptp clock the driver
// registers ("no virtio-rtc PTP clock present" without it).
const (
	virtioRTCDeviceID = 17

	virtioRTCReqRead      = 0x0001
	virtioRTCReqReadCross = 0x0002
	virtioRTCReqCfg       = 0x1000
	virtioRTCReqClockCap  = 0x1001
	virtioRTCReqCrossCap  = 0x1002
	// 0x1003..0x1005 are alarm requests (VIRTIO_RTC_F_ALARM not offered)

	virtioRTCSOK         = 0
	virtioRTCSEOPNOTSUPP = 2
	virtioRTCSENODEV     = 3
	virtioRTCSEINVAL     = 4

	virtioRTCClockUTC = 0

	virtioRTCRespLen = 16 // all responses we emit are header + 8 bytes
)

type virtioRTC struct {
	core *virtioMMIOCore
	now  func() time.Time // test hook
}

func newVirtioRTC() *virtioRTC { return &virtioRTC{now: time.Now} }

func (v *virtioRTC) deviceID() uint32 { return virtioRTCDeviceID }
func (v *virtioRTC) features() uint64 { return 0 } // no VIRTIO_RTC_F_ALARM
func (v *virtioRTC) numQueues() int   { return 1 } // requestq only
func (v *virtioRTC) reset()           {}

// No device configuration layout is defined for virtio-rtc.
func (v *virtioRTC) configRead(off uint64, p []byte)  {}
func (v *virtioRTC) configWrite(off uint64, p []byte) {}

func (v *virtioRTC) handleQueue(qn int) {
	q := &v.core.queues[qn]
	for {
		head, chain, ok := v.core.availChain(q)
		if !ok {
			return
		}
		readable, writable := splitChain(chain)
		req, err := v.core.readChains(readable)

		var resp [virtioRTCRespLen]byte
		switch {
		case err != nil || len(req) < 8:
			resp[0] = virtioRTCSEINVAL
		default:
			v.dispatch(binary.LittleEndian.Uint16(req[0:2]), req, &resp)
		}

		var written uint32
		if len(writable) > 0 && writable[0].len >= virtioRTCRespLen {
			if err := v.core.mem.writeAt(writable[0].addr, resp[:]); err == nil {
				written = virtioRTCRespLen
			}
		}
		v.core.pushUsed(q, head, written)
	}
}

func (v *virtioRTC) dispatch(msgType uint16, req []byte, resp *[virtioRTCRespLen]byte) {
	clockID := func() uint16 {
		if len(req) < 16 {
			return 0xffff // malformed: no clock_id field present
		}
		return binary.LittleEndian.Uint16(req[8:10])
	}

	switch msgType {
	case virtioRTCReqCfg:
		resp[0] = virtioRTCSOK
		binary.LittleEndian.PutUint16(resp[8:], 1) // num_clocks: clock 0
	case virtioRTCReqClockCap:
		if id := clockID(); id != 0 {
			resp[0] = virtioRTCSENODEV
			_ = id
		} else {
			resp[0] = virtioRTCSOK
			resp[8] = virtioRTCClockUTC // type
			resp[9] = 0                 // leap_second_smearing: UNSPECIFIED
			resp[10] = 0                // flags: no alarm capability
		}
	case virtioRTCReqRead:
		if clockID() != 0 {
			resp[0] = virtioRTCSENODEV
		} else {
			resp[0] = virtioRTCSOK
			binary.LittleEndian.PutUint64(resp[8:], uint64(v.now().UnixNano()))
		}
	case virtioRTCReqCrossCap:
		// Supported in principle by the ARM counter driver, but we do not
		// correlate CNTVCT with UTC: report "no cross capability" and let
		// the driver use plain REQ_READ.
		if clockID() != 0 {
			resp[0] = virtioRTCSENODEV
		} else {
			resp[0] = virtioRTCSOK
			resp[8] = 0 // flags: CROSS_CAP not set
		}
	default:
		// READ_CROSS (capability says unsupported), alarm requests
		// (feature not negotiated), unknown msg_type.
		resp[0] = virtioRTCSEOPNOTSUPP
	}
}
