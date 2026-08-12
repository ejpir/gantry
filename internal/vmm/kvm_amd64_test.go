//go:build linux && amd64

package vmm

import "testing"

func TestPrepareKVMCPUID(t *testing.T) {
	cpuid := &kvmCPUID2{nent: 5}
	cpuid.entries[0] = kvmCPUIDEntry2{function: 1, ebx: 0x00a00800}
	cpuid.entries[1] = kvmCPUIDEntry2{function: kvmCPUIDSignature}
	cpuid.entries[2] = kvmCPUIDEntry2{function: kvmCPUIDFeatures}
	cpuid.entries[3] = kvmCPUIDEntry2{function: 0xb}
	cpuid.entries[4] = kvmCPUIDEntry2{function: 0x8000001e}

	if err := prepareKVMCPUID(cpuid, 7, true); err != nil {
		t.Fatal(err)
	}
	leaf1 := cpuid.entries[0]
	if leaf1.ecx&kvmCPUIDFeatureHypervisor == 0 {
		t.Fatal("hypervisor-present bit was not enabled")
	}
	if leaf1.ecx&kvmCPUIDFeatureTSCDeadline == 0 {
		t.Fatal("TSC deadline bit was not enabled")
	}
	if got := leaf1.ebx >> 24; got != 7 {
		t.Fatalf("initial APIC ID = %d, want 7", got)
	}
	if got := cpuid.entries[3].edx; got != 7 {
		t.Fatalf("topology APIC ID = %d, want 7", got)
	}
	if got := cpuid.entries[4].eax; got != 7 {
		t.Fatalf("AMD extended APIC ID = %d, want 7", got)
	}
}

func TestPrepareKVMCPUIDCopiesRemainPerVCPU(t *testing.T) {
	template := &kvmCPUID2{nent: 3}
	template.entries[0] = kvmCPUIDEntry2{function: 1, ebx: 0x00100800}
	template.entries[1] = kvmCPUIDEntry2{function: kvmCPUIDSignature}
	template.entries[2] = kvmCPUIDEntry2{function: kvmCPUIDFeatures}

	cpu0, cpu7 := *template, *template
	if err := prepareKVMCPUID(&cpu0, 0, false); err != nil {
		t.Fatal(err)
	}
	if err := prepareKVMCPUID(&cpu7, 7, false); err != nil {
		t.Fatal(err)
	}
	if got := cpu0.entries[0].ebx >> 24; got != 0 {
		t.Fatalf("CPU0 APIC ID = %d, want 0", got)
	}
	if got := cpu7.entries[0].ebx >> 24; got != 7 {
		t.Fatalf("CPU7 APIC ID = %d, want 7", got)
	}
	if got := template.entries[0].ebx >> 24; got != 0 {
		t.Fatalf("template APIC ID mutated to %d", got)
	}
}

func TestPrepareKVMCPUIDRequiresParavirtualLeaves(t *testing.T) {
	cpuid := &kvmCPUID2{nent: 1}
	cpuid.entries[0] = kvmCPUIDEntry2{function: 1}
	if err := prepareKVMCPUID(cpuid, 0, false); err == nil {
		t.Fatal("missing KVM leaves were accepted")
	}
}
