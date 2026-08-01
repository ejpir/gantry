#!/bin/sh
# Boot the REAL nerdbox rootfs (EROFs, /dev/vda, vminitd as PID 1) under
# QEMU TCG — using virtio-mmio at the same addresses our VMM uses
# (QEMU "virt" places virtio-*-device on the MMIO bus at 0x0a000000+).
#
# Expected: kernel mounts the erofs rootfs, vminitd starts, then fails to
# dial the host over vsock (no vsock device in this QEMU config) — proving
# the guest side of the hybrid stack end-to-end.
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARTIFACTS=${GANTRY_ARTIFACTS:-$ROOT/artifacts}
KERNEL="${KERNEL:-$ARTIFACTS/nerdbox-kernel-arm64_4k}"
ROOTFS="${ROOTFS:-$ARTIFACTS/nerdbox-rootfs-arm64.erofs}"

timeout "${TIMEOUT:-75}" qemu-system-aarch64 \
  -machine virt,gic-version=3 -cpu cortex-a72 -smp 1 -m 512 \
  -kernel "$KERNEL" \
  -drive file="$ROOTFS",format=raw,if=none,id=d0,readonly=on \
  -device virtio-blk-device,drive=d0 \
  -append "console=ttyAMA0 root=/dev/vda rootfstype=erofs ro init=/sbin/vminitd panic=-1 -- -vsock-rpc-port=1025 -vsock-stream-port=1026 -vsock-cid=3" \
  -nographic -no-reboot 2>&1 || true
