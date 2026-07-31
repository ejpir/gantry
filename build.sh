#!/bin/sh
# Build the gantry VMM host binary, plus the guest init/initramfs when a
# static Linux arm64 busybox is available.
#
# The initramfs is only used by `gantry run -initrd` debug shells;
# `gantry start/exec/pi` boot the nerdbox rootfs and don't need it —
# so on hosts without busybox (macOS) it is skipped, not fatal.
# Point BUSYBOX at a static arm64 busybox to force-build it.
set -e
cd "$(dirname "$0")"

OUT=gantry
[ "$(uname)" = "Darwin" ] && OUT=gantry-darwin-arm64

echo "== build gantry VMM (host binary: $OUT)"
go build -o "$OUT" .

if [ "$(uname)" = "Darwin" ]; then
  echo "== codesign (ad-hoc) with com.apple.security.hypervisor"
  codesign --sign - --entitlements entitlements.plist -f "$OUT" 2>&1 | grep -v 'replacing existing signature' || true
fi

BUSYBOX=${BUSYBOX:-/bin/busybox}
if [ ! -x "$BUSYBOX" ] || ! file "$BUSYBOX" 2>/dev/null | grep -q "ELF.*aarch64.*statically"; then
  echo "== skip guest initramfs (no static Linux arm64 busybox at $BUSYBOX;"
  echo "   only needed for 'gantry run -initrd' debug shells; set BUSYBOX=... to build)"
  echo "done: ./$OUT"
  exit 0
fi

echo "== build guest init (static arm64)"
(cd guest/init && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o /tmp/gantry-init .)

echo "== build mkinitramfs"
(cd tools/mkinitramfs && go build -o /tmp/mkinitramfs .)

echo "== build initramfs (scripted + interactive variants)"
/tmp/mkinitramfs -out initramfs.cpio.gz init=/tmp/gantry-init bin/busybox="$BUSYBOX" etc/rc=guest/rc
/tmp/mkinitramfs -out initramfs-shell.cpio.gz init=/tmp/gantry-init bin/busybox="$BUSYBOX"

echo "done: ./$OUT"
echo "Run with KVM:  ./gantry run -kernel ../nerdbox-kernel-arm64_4k -initrd initramfs.cpio.gz"
echo "No KVM? Test guest:  ./run-qemu-test.sh"
