//go:build darwin

package vmm

// Hypervisor.framework's GIC model identifies vCPUs through MPIDR Aff1.
func guestVCPUMPIDR(id int) uint32 {
	return uint32(id) << 8
}

func guestVCPUIndex(mpidr uint64) int {
	return int((mpidr >> 8) & 0xff)
}
