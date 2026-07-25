# WHPX backend — will it boot?

*Assessment of `whpx_windows.go` against the Windows Hypervisor Platform API
contract. **Not tested on real Windows** — this is derived from the API
semantics and struct layouts, not from a run. Cross-compilation for
`windows/amd64` was verified and is clean.*

**Bottom line: it compiles, but it will not boot as-is.** Two hard blockers,
one likely third, and one performance bug.

---

## Blocker 1 — port I/O never advances RIP

`handleIOExit` (`whpx_windows.go:362`) services the port access and returns
without touching RIP. Compare the MMIO path, which gets this right
(`whpx_windows.go:357`):

```go
rip := binary.LittleEndian.Uint64(buf[32:])
return b.writeGPR(vp, whvRegRip, rip+uint64(op.length))
```

WHPX does **not** complete the instruction on an `X64IoPortAccess` exit. That is
exactly why the exit context hands you `InstructionByteCount` and
`InstructionBytes`, and why QEMU routes this through `WHvEmulatorTryIoEmulation`
— the emulator writes RIP back. Handled manually, you must advance it yourself.

**Symptom:** the guest re-executes the same `IN`/`OUT` forever. This fires on the
*first* port access anywhere in boot — the CMOS read, the PIT program in
`setup_arch`, or an `outb` to port 0x80 used as an I/O delay — all of which
happen well before the console comes up. So it hangs silently with no output at
all, which is the worst symptom to debug remotely.

The asymmetry with the MMIO path is strong evidence this is an oversight rather
than a deliberate choice.

---

## Blocker 2 — no local APIC is ever enabled

Only one partition property is set: `whvPropProcessorCount`
(`whpx_windows.go:196`). `WHvPartitionPropertyCodeLocalApicEmulationMode`
(`0x1005`) is never set, and its default is `WHvX64LocalApicEmulationModeNone`.

Two consequences:

1. **`WHvRequestInterrupt` has nothing to deliver into.** It is the delivery path
   for the entire userspace IO-APIC (`whpx_windows.go:173`), and it requires an
   emulated LAPIC. With emulation mode `None` you are expected to use the
   interrupt-window exit plus `WHvRegisterPendingInterruption` instead. Worse,
   the failure is swallowed: `whvCall` errors there are only printed, and only
   when `dbgIO` is set.

2. **LAPIC MMIO reads as zero.** Guest accesses to `0xfee00000` arrive as
   memory-access exits, and `machine.handleMMIO` has no case for that range. The
   MPS table in `bootx86.go` advertises a LAPIC at that address, so Linux will go
   looking and find a version register of 0.

**Fix:** one more `WHvSetPartitionProperty` call, code `0x1005`, value `1`
(`WHvX64LocalApicEmulationModeXApic`), before `WHvSetupPartition`.

---

## Likely blocker 3 — the AP threads

The comment at `whpx_windows.go:221` says "WHPX holds non-boot processors until
the guest's INIT/SIPI." That is probably not how WHPX behaves.

Unlike KVM — where APs sit in `KVM_MP_STATE_UNINITIALIZED` and `KVM_RUN` returns
`EAGAIN`, which the KVM backend correctly retries — WHPX VPs come up in the
architectural reset state and begin executing as soon as
`WHvRunVirtualProcessor` is called. QEMU gates its AP threads in its own
CPU-start machinery, not in WHPX.

Each AP goroutine would therefore start executing at the reset vector in zeroed
guest RAM and triple-fault. That will not kill the BSP — `runVPLoop` returns the
error and the goroutine prints and exits — but it is not SMP.

**Recommendation:** keep `-cpus 1` on Windows until this can be tested.

---

## Performance bug — HLT spins a host core

`whvExitHalt` re-enters immediately (`whpx_windows.go:291`). RIP still points at
the `HLT`, so the VP re-executes it in a tight loop, pegging a host core while
the guest is idle.

It *does* make forward progress once an interrupt arrives, so this is a
performance bug rather than a hang — but on a mostly-idle sandbox VM it will look
like the VMM is stuck.

---

## Dead code

`whvExitMsrAccess` and `whvExitCpuid` are handled (`whpx_windows.go:300`) but
unreachable: those exits require `WHvPartitionPropertyCodeExtendedVmExits`, which
is never set. Harmless, but misleading — it reads as though MSR/CPUID
interception is wired up.

---

## What is actually correct

Worth recording, because it changes where debugging effort should go. The parts
most likely to be wrong in hand-written WHPX bindings are all right here:

- **Exit-context offsets.** Every one lands: `ExitReason`@0, `VpContext`@8
  (giving `Rip`@32), union@48. So for memory access, `InstructionByteCount`@48,
  `InstructionBytes`@52, `Gpa`@72; for port I/O, `AccessInfo`@68,
  `PortNumber`@72, `Rax`@80. All match the code.
- **`WHV_X64_IO_PORT_ACCESS_INFO` bit fields** — `IsWrite` bit 0, `AccessSize`
  bits 1-3, string/rep mask `0x30`. Correct.
- **Register-name enum values**, including `Efer = 0x2001` and
  `ProcessorCount = 0x1fff`. Correct.
- **`WHV_INTERRUPT_CONTROL`** laid out correctly at 16 bytes (Type bits 0-7,
  DestinationMode 8-11, TriggerMode 12-15, Destination@8, Vector@12).
- **HRESULT handling** — `whvCall` truncates to `int32` before testing, which is
  the correct handling for a 32-bit return in RAX.
- **Partition setup order** — property → setup → map → create VPs. Correct.
- **Not setting TR/LDTR is the safer choice.** Untouched registers keep WHPX's
  reset defaults, which is why the zeroed-TR problem the README describes from
  the KVM bring-up will not reappear here.
- **Long-mode entry state** — `CR0 = 0x80010033` (PG|WP|PE|MP|ET|NE),
  `CR4 = 0x20` (PAE), `EFER = 0x500` (LME|LMA), CS attributes `0xa09b` with the
  L bit set. All consistent.

**One constant I cannot verify from the code:** `whvExitContextSize = 224`. My
estimate of `sizeof(WHV_RUN_VP_EXIT_CONTEXT)` lands near that (the hypercall
context makes the union ~152 bytes). The risk is asymmetric — too small returns
an error, too large is accepted — so leaving it is fine.

---

## Getting it testable

The realistic path is a cheap Windows VM with nested virtualization (an Azure
Dv5/Ev5, or an EC2 `*.metal` running Windows Server 2022 — an hour or two of
runtime). WHPX needs the Hypervisor Platform feature and will not run under most
nested setups:

```
dism /online /enable-feature /featurename:HypervisorPlatform
```

Failing that, fixing blockers 1 and 2 blind is still worth doing — both are
small, well-understood and mechanical.

## README

The Windows row currently reads "✅ builds". That is accurate but reads as
"close to working". Suggest naming these blockers explicitly so nobody
misreads it.

*(Note: the existing macOS doc is `MACOS.md`; rename this to `WINDOWS.md` if you
want the convention to match.)*
