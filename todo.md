3. Resume the sbx storage tracing: rwlayer.img/fsmeta.erofs ext4 writable-layer flow, if you still want the writable-overlay mechanism reproduced in gantry.


$ strings -n 8 /home/agent/libexec/lib/libsailor.dylib | rg '^CONFIG_|^# CONFIG_' > /tmp/nerdbox-kconfig.txt; wc -l /tmp/nerdbox-kconfig.txt; rg -i 'ptp|rtc|VIRTIO'
/tmp/nerdbox-kconfig.txt | rg -v 'not set' | head -40

... (36 earlier lines, ctrl+o to expand)
CONFIG_VIRTIO_MEM=y
CONFIG_VIRTIO_MMIO=y
CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y
CONFIG_VIRTIO_RTC=y
CONFIG_VIRTIO_RTC_PTP=y

Took 0.4s


The kernel config confirms:

- CONFIG_VIRTIO_RTC=y — Docker's kernel has the virtio-rtc driver (out-of-tree; Hilber's series).
- CONFIG_VIRTIO_RTC_PTP=y — and its PTP clock registration. This is what creates /dev/ptp0 named "virtio-rtc" (or the PTP clock "Virtio PTP"?). Hmm — "Virtio PTP" string in vminitd...
  actually in Hilber's driver, the PTP clock name is "virtio-rtc" I think. Wait, there's also CONFIG_VIRTIO_ANCHOR=y — interesting, Docker's traces ClockAnchor? That's a Docker-custom
  device ("VIRTIO_ANCHOR")! The vminitd strings had "ClockAnchor", "GetClockAnchor", "MonoOffsetNs", "vmtraces" — that's for tracing clock conversion, separate concern.

Also CONFIG_PTP_1588_CLOCK_KVM=y (that's the kvm ptp), CONFIG_PTP_1588_CLOCK_VMCLOCK=y.

So the plan: implement the virtio-rtc device per the Hilber virtio-rtc spec (the UAPI header we already have). Need:
1. Device ID: Hilber's spec assigned device ID 47? I need to confirm. The CONFIG_VIRTIO_RTC driver (out-of-tree) — its device ID. The virtio spec PR "virtio-rtc" reserved ID 47 (0x2f)?
   Hmm... wait actually! I remember now: the virtio 1.4 spec candidate lists "RTC" as device ID 47? Let me check via Hilber's patches on lore — can I fetch from lore.kernel.org? Try:
   https://lore.kernel.org/virtio-dev/ — searching is awkward. Alternative: check the actual driver source in OpenSynergy's GitHub mirror? OpenSynergy published virtio-rtc reference
   impl: github.com/OpenSynergy/virtio-rtc? There is "opensynergy/virtio-rtc-linux"? Let me try a few fetches.

Actually — better source of truth: libsailor itself. It implements the device; find "47" / device id in its code via strings: e.g. Rust path strings like "devices/src/virtio/rtc". Let
me grep sailor dylib strings for 'rtc' in file paths (Rust panic messages include file paths).

Earlier strings grep -i 'rtc' showed only kernel config lines + generic "clock" line. Rust file paths like "crates/devices/src/virtio_rtc/..." would appear. Let me grep for 'virtio' in
dylib strings to see device module paths.


 Every piece was reverse-engineered from the production artifacts rather than guessed: vminitd strings, the embedded nerdbox kernel config inside libsailor.dylib, Ghidra-decompiled
 sailor device code, and the virtio spec — and each one has unit tests plus an on-device verification you ran.

 Natural next steps whenever you're interested:

 1. Cross-timestamping (REQ_READ_CROSS with CNTVCT correlation) — we advertise it as unsupported; sailor implements it, and it's a fun one: we control the vtimer, so the math is exact.
 2. VIRTIO_ANCHOR — Docker's custom clock-anchor device (kconfig had CONFIG_VIRTIO_ANCHOR=y, vminitd has GetClockAnchor/MonoOffsetNs) for trace timestamp conversion.
 3. Snapshot/restore — sailor's restore path was visible in the decompiled functions; a gantry exec that resumes a snapshot in ~50ms would be a big UX win.
 4. Commit flow — rwlayer.ext4 diff → new EROFS layer (the commit-ext4-* machinery sbx has).


 What's genuinely new work:

 ┌────────────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │ piece              │ why                                                                                                                       │
 ├────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ x86_64 KVM backend │ different kvm_regs/kvm_sregs, 64-bit boot protocol (bootparams/PVH at 0x100000), no KVM_ARM_VCPU_INIT                     │
 ├────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ interrupt chip     │ GIC→KVM_CREATE_IRQCHIP (in-kernel IOAPIC/APIC — actually simpler)                                                         │
 ├────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ serial             │ PL011 → 16550 UART at 0x3f8 emulation                                                                                     │
 ├────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ SMP                │ PSCI → in-kernel INIT/SIPI (KVM handles it)                                                                               │
 ├────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ images             │ x86_64 kernel + nerdbox rootfs (Docker ships amd64 variants) and ./mkimage.sh debian:bookworm-slim --platform linux/amd64 │
 ├────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ time               │ arch timer → TSC clocksource + kvm-clock                                                                                  │
 ├────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ macOS Intel        │ dead end regardless — HVF x86 would be a third backend; not worth it                                                      │
 └────────────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
