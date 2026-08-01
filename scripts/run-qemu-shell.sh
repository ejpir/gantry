#!/bin/sh
# Boot the guest and give you an INTERACTIVE shell on the serial console.
# No KVM needed (QEMU TCG emulation). Run this in your own terminal.
#
#   guest# uname -a        <- you type here
#   guest# exit            <- powers off the VM and exits qemu
#   Ctrl-A X               <- emergency: kill qemu
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARTIFACTS=${GANTRY_ARTIFACTS:-$ROOT/artifacts}
KERNEL="${KERNEL:-$ARTIFACTS/nerdbox-kernel-arm64_4k}"
INITRD="$ARTIFACTS/initramfs-shell.cpio.gz"
[ -f "$INITRD" ] || "$ROOT/scripts/build.sh"

exec qemu-system-aarch64 \
  -machine virt,gic-version=3 -cpu cortex-a72 -smp 1 -m 512 \
  -kernel "$KERNEL" \
  -initrd "$INITRD" \
  -append "console=ttyAMA0 panic=-1" \
  -nographic -no-reboot
