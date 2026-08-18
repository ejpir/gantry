//go:build darwin

package boot

// Hypervisor.framework's GIC model identifies vCPUs through MPIDR Aff1.
func VCPUMPIDR(id int) uint32 {
	return uint32(id) << 8
}

func VCPUIndex(mpidr uint64) int {
	return int((mpidr >> 8) & 0xff)
}
