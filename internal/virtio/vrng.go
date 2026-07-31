package virtio

import "crypto/rand"

// virtio-rng (device ID 4): one requestq; the driver posts writable
// buffers and the device fills them with entropy. The nerdbox kernel has
// CONFIG_HW_RANDOM_VIRTIO=y and seeds crng from it at probe — without it,
// boot relies on jitter entropy, which is a coin flip: when it loses,
// vminitd's DHCP client blocks in getrandom() for two minutes, exits,
// PID 1 dies and the VM panics ("could not get random number").
// libsailor ships the same device ("created virtio-rng device").
const virtioRngDeviceID = 4

type RNG struct {
	core *Core
}

func NewRNG() *RNG { return &RNG{} }

func (v *RNG) deviceID() uint32 { return virtioRngDeviceID }
func (v *RNG) features() uint64 { return 0 }
func (v *RNG) numQueues() int   { return 1 }
func (v *RNG) reset()           {}

// virtio-rng has no device-specific configuration.
func (v *RNG) configRead(off uint64, p []byte)  {}
func (v *RNG) configWrite(off uint64, p []byte) {}

func (v *RNG) handleQueue(qn int) {
	q := &v.core.queues[qn]
	for {
		head, chain, ok := v.core.availChain(qn)
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

// rngMaxChainBytes caps one entropy request. Legitimate hwrng reads are
// a few bytes to a page; 1 MiB is generous but keeps a hostile guest
// from declaring guest-RAM-sized buffers (review finding 2).
const rngMaxChainBytes = 1 << 20

func (v *RNG) maxChainBytes(qn int) uint64 { return rngMaxChainBytes }

func (v *RNG) setCore(c *Core) { v.core = c }
