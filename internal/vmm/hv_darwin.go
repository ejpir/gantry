//go:build darwin

package vmm

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// Hypervisor.framework bindings — the exact API surface the reference VMM
// dylib imports (verified against its Mach-O import table), called via purego
// (no cgo), the same mechanism its Go bindings use.
//
// Struct layouts and constants cross-checked against libkrun's public
// hvf crate (containers/libkrun, src/hvf), the reference VMM's ancestor.

var (
	hvVmConfigCreate                func() uintptr
	hvVmConfigGetDefaultIpaSize     func(ipaSize *uint32) uint32
	hvVmConfigSetIpaSize            func(config uintptr, ipaSize uint32) uint32
	hvVmCreate                      func(config uintptr) uint32
	hvVmDestroy                     func() uint32
	hvVmMap                         func(addr unsafe.Pointer, ipa uint64, size uint64, flags uint64) uint32
	hvVmUnmap                       func(ipa uint64, size uint64) uint32
	hvVcpuCreate                    func(vcpu *uint64, exit **hvVcpuExit, config uintptr) uint32
	hvVcpuDestroy                   func(vcpu uint64) uint32
	hvVcpuSetReg                    func(vcpu uint64, reg uint32, value uint64) uint32
	hvVcpuGetReg                    func(vcpu uint64, reg uint32, value *uint64) uint32
	hvVcpuSetSysReg                 func(vcpu uint64, reg uint32, value uint64) uint32
	hvVcpuSetVtimerMask             func(vcpu uint64, masked bool) uint32
	hvVcpuSetPendingInterrupt       func(vcpu uint64, intType uint32, pending bool) uint32
	hvVcpuRun                       func(vcpu uint64) uint32
	hvVcpusExit                     func(vcpus *uint64, count uint32) uint32
	hvGicConfigCreate               func() uintptr
	hvGicConfigSetDistributorBase   func(config uintptr, base uint64) uint32
	hvGicConfigSetRedistributorBase func(config uintptr, base uint64) uint32
	hvGicCreate                     func(config uintptr) uint32
	hvGicSetSpi                     func(intid uint32, level bool) uint32
	osRelease                       func(object uintptr)
)

var (
	loadHVFOnce sync.Once
	loadHVFErr  error
)

// Hypervisor.framework returns encoded mach_error_t values, not small ordinal
// integers. These constants come from Hypervisor/hv_error.h.
const (
	hvSuccess           uint32 = 0
	hvError             uint32 = 0xfae94001
	hvBusy              uint32 = 0xfae94002
	hvBadArgument       uint32 = 0xfae94003
	hvIllegalGuestState uint32 = 0xfae94004
	hvNoResources       uint32 = 0xfae94005
	hvNoDevice          uint32 = 0xfae94006
	hvDenied            uint32 = 0xfae94007
	hvUnsupported       uint32 = 0xfae9400f

	hvMemoryRead  = 1
	hvMemoryWrite = 2
	hvMemoryExec  = 4

	hvRegX0   = 0 // X0..X30 = 0..30
	hvRegLR   = 30
	hvRegPC   = 31
	hvRegCPSR = 34

	hvSysRegMpidrEl1 = 49157 // 0xC005

	hvExitReasonCanceled        = 0
	hvExitReasonException       = 1
	hvExitReasonVtimerActivated = 2
	hvExitReasonUnknown         = 3

	hvInterruptTypeIRQ = 0
	hvInterruptTypeFIQ = 1

	// exception classes (syndrome >> 26) & 0x3f
	ecWfi           = 0x01
	ecHvc           = 0x16
	ecDataAbort     = 0x24 // 0x24 = lower EL, 0x25 = same EL; we match both via &0x3e? see below
	ecDataAbortSame = 0x25
	ecBrk           = 0x3c
)

// hv_vcpu_exit_t: reason @0 (u32+pad), exception @{syndrome, virtual, physical} @8
type hvVcpuExit struct {
	reason          uint32
	_               uint32
	syndrome        uint64
	virtualAddress  uint64
	physicalAddress uint64
}

// hvReturnString decodes hv_return_t for readable errors.
func hvReturnString(ret uint32) string {
	switch ret {
	case hvSuccess:
		return "HV_SUCCESS"
	case hvError:
		return "HV_ERROR"
	case hvBusy:
		return "HV_BUSY"
	case hvBadArgument:
		return "HV_BAD_ARGUMENT"
	case hvIllegalGuestState:
		return "HV_ILLEGAL_GUEST_STATE"
	case hvNoResources:
		return "HV_NO_RESOURCES"
	case hvNoDevice:
		return "HV_NO_DEVICE"
	case hvDenied:
		return "HV_DENIED (check hypervisor entitlement)"
	case hvUnsupported:
		return "HV_UNSUPPORTED"
	}
	return fmt.Sprintf("hv_return_t(%#x)", ret)
}

func loadHVF() error {
	loadHVFOnce.Do(func() {
		loadHVFErr = loadHVFSymbols()
	})
	return loadHVFErr
}

func loadHVFSymbols() error {
	handle, err := purego.Dlopen("/System/Library/Frameworks/Hypervisor.framework/Hypervisor",
		purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return fmt.Errorf("dlopen Hypervisor.framework: %w", err)
	}
	loaded := false
	defer func() {
		if !loaded {
			_ = purego.Dlclose(handle)
		}
	}()
	bind := func(fn any, name string) error {
		sym, err := purego.Dlsym(handle, name)
		if err != nil {
			return fmt.Errorf("dlsym %s: %w", name, err)
		}
		purego.RegisterFunc(fn, sym)
		return nil
	}
	for _, b := range []struct {
		fn   any
		name string
	}{
		{&hvVmConfigCreate, "hv_vm_config_create"},
		{&hvVmConfigGetDefaultIpaSize, "hv_vm_config_get_default_ipa_size"},
		{&hvVmConfigSetIpaSize, "hv_vm_config_set_ipa_size"},
		{&hvVmCreate, "hv_vm_create"},
		{&hvVmDestroy, "hv_vm_destroy"},
		{&hvVmMap, "hv_vm_map"},
		{&hvVmUnmap, "hv_vm_unmap"},
		{&hvVcpuCreate, "hv_vcpu_create"},
		{&hvVcpuDestroy, "hv_vcpu_destroy"},
		{&hvVcpuSetReg, "hv_vcpu_set_reg"},
		{&hvVcpuGetReg, "hv_vcpu_get_reg"},
		{&hvVcpuSetSysReg, "hv_vcpu_set_sys_reg"},
		{&hvVcpuSetVtimerMask, "hv_vcpu_set_vtimer_mask"},
		{&hvVcpuSetPendingInterrupt, "hv_vcpu_set_pending_interrupt"},
		{&hvVcpusExit, "hv_vcpus_exit"},
		{&hvVcpuRun, "hv_vcpu_run"},
		{&hvGicConfigCreate, "hv_gic_config_create"},
		{&hvGicConfigSetDistributorBase, "hv_gic_config_set_distributor_base"},
		{&hvGicConfigSetRedistributorBase, "hv_gic_config_set_redistributor_base"},
		{&hvGicCreate, "hv_gic_create"},
		{&hvGicSetSpi, "hv_gic_set_spi"},
	} {
		if err := bind(b.fn, b.name); err != nil {
			return err
		}
	}
	sym, err := purego.Dlsym(purego.RTLD_DEFAULT, "os_release")
	if err != nil {
		return fmt.Errorf("dlsym os_release: %w", err)
	}
	purego.RegisterFunc(&osRelease, sym)
	loaded = true // process-wide framework binding; intentionally kept open
	return nil
}
