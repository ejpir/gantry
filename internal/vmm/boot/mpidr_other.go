//go:build !darwin

package boot

// KVM assigns each vCPU ID directly to MPIDR Aff0.
func VCPUMPIDR(id int) uint32 {
	return uint32(id)
}
