package main

import "crypto/rand"

// virtio-rng (device ID 4): one requestq; the driver posts writable
// buffers and the device fills them with entropy. The nerdbox kernel has
// CONFIG_HW_RANDOM_VIRTIO=y and seeds crng from it at probe — without it,
// boot relies on jitter entropy, which is a coin flip: when it loses,
// vminitd's DHCP client blocks in getrandom() for two minutes, exits,
// PID 1 dies and the VM panics ("could not get random number").
// libsailor ships the same device ("created virtio-rng device").
const virtioRngDeviceID = 4

type virtioRNG struct {
	core *virtioMMIOCore
}

func newVirtioRNG() *virtioRNG { return &virtioRNG{} }

func (v *virtioRNG) deviceID() uint32 { return virtioRngDeviceID }
func (v *virtioRNG) features() uint64 { return 0 }
func (v *virtioRNG) numQueues() int   { return 1 }
func (v *virtioRNG) reset()           {}

// virtio-rng has no device-specific configuration.
func (v *virtioRNG) configRead(off uint64, p []byte)  {}
func (v *virtioRNG) configWrite(off uint64, p []byte) {}

func (v *virtioRNG) handleQueue(qn int) {
	q := &v.core.queues[qn]
	for {
		head, chain, ok := v.core.availChain(q)
		if !ok {
			return
		}
		_, writable := splitChain(chain)
		var total uint32
		for _, d := range writable {
			buf := make([]byte, d.len)
			if _, err := rand.Read(buf); err != nil {
				break
			}
			if err := v.core.mem.writeAt(d.addr, buf); err != nil {
				break
			}
			total += d.len
		}
		v.core.pushUsed(q, head, total)
	}
}
