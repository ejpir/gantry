//go:build linux && arm64

package vmm

// ---- arm64-specific KVM constants -------------------------------------------

const (
	kvmArmVcpuInit = 0x4020AEAE // _IOW (0xAE, 0xAE, 32)
	kvmSetOneReg   = 0x4010AEAC // _IOW (0xAE, 0xAC, 16)

	kvmDevTypeArmVGICV3           = 7 // KVM_DEV_TYPE_ARM_VGIC_V3 (5 is VGIC_V2)
	kvmDevArmVGICGrpAddr          = 0
	kvmVGICV3AddrTypeDist         = 2
	kvmVGICV3AddrTypeRedistRegion = 5
	kvmDevArmVGICGrpNrIrqs        = 3
	kvmDevArmVGICGrpCtrl          = 4
	kvmDevArmVGICCtrlInit         = 0

	kvmArmTargetGenericV8 = 5
	kvmArmVcpuPowerOff    = 0 // bit: enable PSCI power off
	kvmArmVcpuPSCI02      = 2 // bit: enable PSCI v0.2

	// KVM_IRQ_LINE's irq field is architecture-specific. Gantry's arm64
	// devices all use GIC SPIs, whose type occupies bits 27:24.
	kvmArmIRQTypeShift = 24
	kvmArmIRQTypeSPI   = 1

	kvmRegArm64   = 0x6000000000000000
	kvmRegSizeU64 = 0x0030000000000000
	kvmRegArmCore = 0x0000000000100000 // 0x0010 << KVM_REG_ARM_COPROC_SHIFT(16)
)

type kvmVcpuInit struct {
	target   uint32
	features [7]uint32
}

// kvmRegArmCoreReg builds the register ID for struct kvm_regs fields.
// struct kvm_regs = { u64 regs[31]; u64 sp; u64 pc; u64 pstate; } and
// KVM_REG_ARM_CORE_REG encodes offsetof in 4-byte words, so each 64-bit
// field spans two indices: xN = 2N, sp = 62, pc = 64, pstate = 66.
// KVM_SET/GET_ONE_REG answer ENOENT for a malformed ID, so keep this
// layout exact.
func kvmRegArmCoreReg(u64Index uint64) uint64 {
	return kvmRegArm64 | kvmRegSizeU64 | kvmRegArmCore | (u64Index * 2)
}

func kvmArmVCPUFeatures(id int) uint32 {
	features := uint32(1 << kvmArmVcpuPSCI02)
	if id != 0 {
		features |= 1 << kvmArmVcpuPowerOff
	}
	return features
}

func kvmArmSPIIRQ(intid int) uint32 {
	return kvmArmIRQTypeSPI<<kvmArmIRQTypeShift | uint32(intid)
}

func kvmArmRedistRegion(vcpus int) uint64 {
	return uint64(vcpus)<<52 | gicrBase
}
