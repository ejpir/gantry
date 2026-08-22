#!/bin/sh
# Build the gantry VMM host binary, plus the guest init/initramfs when a
# static Linux arm64 busybox is available.
#
# The initramfs is only used by `gantry run -initrd` debug shells;
# `gantry start/exec/pi` boot the nerdbox rootfs and don't need it —
# so on hosts without busybox (macOS) it is skipped, not fatal.
# Point BUSYBOX at a static arm64 busybox to force-build it.
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARTIFACTS=${GANTRY_ARTIFACTS:-$ROOT/artifacts}
mkdir -p "$ARTIFACTS"
cd "$ROOT"

OUT="$ARTIFACTS/gantry"
[ "$(uname)" = "Darwin" ] && OUT="$ARTIFACTS/gantry-darwin-arm64"

echo "== build gantry VMM (host binary: $OUT)"
go build -o "$OUT" ./cmd/gantry

if [ "$(uname)" = "Darwin" ]; then
  echo "== codesign (ad-hoc) with com.apple.security.hypervisor"
  codesign --sign - --entitlements "$ROOT/config/entitlements.plist" -f "$OUT" 2>&1 | grep -v 'replacing existing signature' || true
fi

# Guest helper: cross-compiled for the VM's linux userland. Always rebuild
# it — the daemon delivers this exact file into guests at start, so a
# stale copy silently lacks new modes (mcp-serve, credhelper, ...).
GUEST_MACHINE=$(uname -m)
GUEST_GOARCH=$GUEST_MACHINE
GUEST_ASSET_ARCH=$GUEST_MACHINE
[ "$GUEST_MACHINE" = "x86_64" ] && GUEST_GOARCH=amd64
[ "$GUEST_MACHINE" = "aarch64" ] && GUEST_GOARCH=arm64
[ "$GUEST_GOARCH" = "amd64" ] && GUEST_ASSET_ARCH=x86_64
[ "$GUEST_GOARCH" = "arm64" ] && GUEST_ASSET_ARCH=arm64
echo "== build guest helper (linux/$GUEST_GOARCH)"
CGO_ENABLED=0 GOOS=linux GOARCH=$GUEST_GOARCH go build -trimpath -ldflags='-s -w' \
  -o "$ARTIFACTS/gantry-guest-$GUEST_ASSET_ARCH" ./cmd/gantry-guest

BUSYBOX=${BUSYBOX:-/bin/busybox}
if [ ! -x "$BUSYBOX" ] || ! file "$BUSYBOX" 2>/dev/null | grep -q "ELF.*aarch64.*statically"; then
  echo "== skip guest initramfs (no static Linux arm64 busybox at $BUSYBOX;"
  echo "   only needed for 'gantry run -initrd' debug shells; set BUSYBOX=... to build)"
  echo "done: $OUT"
  exit 0
fi

echo "== build guest init (static arm64)"
(cd guest/init && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o /tmp/gantry-init .)

echo "== build mkinitramfs"
(cd tools/mkinitramfs && go build -o /tmp/mkinitramfs .)

echo "== build initramfs (scripted + interactive variants)"
/tmp/mkinitramfs -out "$ARTIFACTS/initramfs.cpio.gz" init=/tmp/gantry-init bin/busybox="$BUSYBOX" etc/rc=guest/rc
/tmp/mkinitramfs -out "$ARTIFACTS/initramfs-shell.cpio.gz" init=/tmp/gantry-init bin/busybox="$BUSYBOX"

echo "done: $OUT"
echo "Run with KVM:  $OUT run -kernel $ARTIFACTS/gantry-kernel-arm64-4k -initrd $ARTIFACTS/initramfs.cpio.gz"
echo "No KVM? Test guest:  $ROOT/scripts/run-qemu-test.sh"
