//go:build linux && arm64

package vmm

// ---- arm64-specific KVM constants -------------------------------------------

const (
	kvmArmVcpuInit = 0x4020AEAE // _IOW (0xAE, 0xAE, 32)
	kvmSetOneReg   = 0x4010AEAC // _IOW (0xAE, 0xAC, 16)

	kvmDevTypeArmVGICV3     = 5
	kvmDevArmVGICGrpAddr    = 0
	kvmVGICV3AddrTypeDist   = 0
	kvmVGICV3AddrTypeRedist = 1
	kvmDevArmVGICGrpNrIrqs  = 3
	kvmDevArmVGICGrpCtrl    = 4
	kvmDevArmVGICCtrlInit   = 0

	kvmArmTargetGenericV8 = 0
	kvmArmVcpuPowerOff    = 0 // bit: enable PSCI power off
	kvmArmVcpuPSCI02      = 1 // bit: enable PSCI v0.2

	kvmRegArm64   = 0x0030000000000000
	kvmRegSizeU64 = 0x0030000000000000
	kvmRegArmCore = 0x0010000000000000
)

type kvmVcpuInit struct {
	target   uint32
	features [7]uint32
}

// kvmRegArmCoreReg builds the register ID for struct kvm_regs fields.
// struct kvm_regs = { u64 regs[31]; u64 sp; u64 pc; u64 pstate; }
// word index: xN = N, sp = 31, pc = 32, pstate = 33.
func kvmRegArmCoreReg(wordIndex uint64) uint64 {
	return kvmRegArm64 | kvmRegSizeU64 | kvmRegArmCore | wordIndex
}
