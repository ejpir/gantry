//go:build !darwin

package vmm

// KVM assigns each vCPU ID directly to MPIDR Aff0.
func guestVCPUMPIDR(id int) uint32 {
	return uint32(id)
}
