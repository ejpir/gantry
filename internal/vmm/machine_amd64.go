//go:build amd64

package vmm

func (m *Machine) x86RAMRegions() []x86RAMRegion {
	if m.x86LowRAMSize == 0 {
		return x86RAMRegions(uint64(len(m.ram)))
	}
	return x86RAMRegionsWithLow(uint64(len(m.ram)), m.x86LowRAMSize)
}
