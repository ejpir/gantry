#!/bin/sh
# Boot the gantry guest (same kernel + initramfs our VMM uses) under QEMU
# TCG — pure emulation, no /dev/kvm needed. This validates everything the
# guest sees: FDT-provided devices equivalent to ours, PL011 console,
# initramfs boot, PSCI poweroff.
#
# Our VMM's memory map mirrors QEMU's "virt" machine (GICv3 @0x08000000,
# PL011 @0x09000000, RAM @0x40000000), so a guest that boots here boots
# under gantry on a KVM host.
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARTIFACTS=${GANTRY_ARTIFACTS:-$ROOT/artifacts}
KERNEL="${KERNEL:-$ARTIFACTS/gantry-kernel-arm64-4k}"
INITRD="$ARTIFACTS/initramfs.cpio.gz"

if [ ! -f "$INITRD" ]; then "$ROOT/scripts/build.sh"; fi

# Feed the shell a few commands, then exit -> init powers off -> qemu exits.
( printf 'echo HELLO_FROM_GUEST\n'; printf 'uname -a\n'; printf 'cat /proc/device-tree/model; echo\n'; printf 'exit\n'; sleep 90 ) | \
exec qemu-system-aarch64 \
  -machine virt,gic-version=3 -cpu cortex-a72 -smp 1 -m 512 \
  -kernel "$KERNEL" \
  -initrd "$INITRD" \
  -append "console=ttyAMA0 panic=-1" \
  -nographic -no-reboot
