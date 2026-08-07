//go:build !windows && (!linux || !amd64)

package vmm

// x86Devices is empty outside the x86 boot paths (KVM on linux/amd64,
// WHPX on Windows); the real definitions live in x86devices.go and the
// per-platform x86devices_{linux_amd64,windows}.go.
type x86Devices struct{}

// mmioX86 never claims an address: arm64 platforms have no x86 legacy
// MMIO (I/O APIC) window.
func (x x86Devices) mmioX86(isWrite bool, phys uint64, data []byte) (uint32, bool) {
	return 0, false
}

// initX86 is unreachable here: x86 guests only boot on linux/amd64 (KVM)
// and Windows (WHPX), where the real definition is compiled in. The
// call site is a runtime arch branch, so the symbol must exist; panic
// rather than silently skip device wiring if it is ever reached.
func (m *Machine) initX86() { panic("vmm: x86 guest on a build without x86 support") }
