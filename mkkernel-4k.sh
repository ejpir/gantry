#!/bin/sh
# mkkernel-4k.sh — build a 4K-page twin of the nerdbox arm64 guest kernel.
#
# Why: gVisor's stock arm64 runsc is compiled for 4K pages and hard-fails
# in `runsc boot` on anything else ("host page size (16384) does not match
# compiled page size (4096)"); upstream ships 4K and 64K variants only.
# The nerdbox arm64 kernel is 16K, so the gVisor-in-guest flow needs a
# kernel rebuilt with CONFIG_ARM64_4K_PAGES=y — everything else identical
# (same version, same config, extracted from the stock kernel).
#
#   ./mkkernel-4k.sh                    # → nerdbox-kernel-arm64-4k
#
# Needs: curl, xz, gcc, flex, bison, bc (native arm64 or cross via
# CROSS_COMPILE=aarch64-linux-gnu-). ~10-20 min on a modern machine.
set -e

VERSION=7.0.12   # must match `strings nerdbox-kernel-arm64 | grep "Linux version"`
STOCK=${1:-nerdbox-kernel-arm64}
OUT=${2:-nerdbox-kernel-arm64-4k}
WORK=${WORK:-/tmp/linux-$VERSION-build}

if [ ! -d "$WORK" ]; then
  echo "== downloading linux-$VERSION"
  curl -fsSL -o /tmp/linux-$VERSION.tar.xz \
    https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-$VERSION.tar.xz
  echo "== extracting to $WORK"
  mkdir -p "$WORK"
  tar -xJf /tmp/linux-$VERSION.tar.xz -C "$WORK" --strip-components=1
fi

cd "$WORK"
[ -f .config ] || {
  echo "== extracting config from $STOCK"
  scripts/extract-ikconfig "$OLDPWD/$STOCK" > .config
}
scripts/config --disable ARM64_16K_PAGES --disable ARM64_64K_PAGES --enable ARM64_4K_PAGES
yes "" | make olddefconfig >/dev/null
grep -q "^CONFIG_ARM64_4K_PAGES=y" .config || { echo "config flip failed" >&2; exit 1; }

echo "== building vmlinux (this takes a while)"
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" vmlinux
cp vmlinux "$OLDPWD/$OUT"
ls -lh "$OLDPWD/$OUT"
echo "done: gantry start <name> -runtime runsc   (auto-picks $OUT)"
