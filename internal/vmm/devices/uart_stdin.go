//go:build (linux && arm64) || darwin

package devices

import "os"

// Host-stdin wiring for the PL011 console. Only the arm64 backends
// (KVM on Linux, Hypervisor.framework on macOS) pump host stdin into the
// guest UART; the x86 paths keep console I/O port-local.

// stdinPump copies host stdin into the UART RX buffer.
func (u *PL011) StdinPump(done <-chan struct{}) {
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

// feed is called by the host stdin pump with typed bytes.
func (u *PL011) feed(b []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.rxBuf = append(u.rxBuf, b...)
	u.updateIRQLocked()
}
