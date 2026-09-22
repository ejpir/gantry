#!/bin/sh
# mkrootfs-gvisor.sh — build a nerdbox VM rootfs variant whose containers
# run under gVisor: /sbin/crun is replaced by runsc (which implements the
# runc CLI on purpose — that's how containerd shims drive gVisor), with
# the real crun kept at /sbin/crun.runc. vminitd is unchanged.
#
#   ./scripts/mkrootfs-gvisor.sh artifacts/nerdbox-rootfs-arm64.erofs
#   → artifacts/nerdbox-rootfs-gvisor-arm64.erofs (use with: -runtime runsc)
#
# Needs: mkfs.erofs, fsck.erofs, wget, tar with zstd support, sha512sum,
# and go. Downloads and verifies the matching gVisor release archive, then
# installs runsc and its normal-execution sidecars and builds the crunshim
# /dev fixer (guest/crunshim) for the target arch.
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

IN=${1:?"usage: mkrootfs-gvisor.sh artifacts/nerdbox-rootfs-ARCH.erofs [ARCH]"}
# ARCH (arm64|x86_64) may be given explicitly — the CI bundle file is
# arch-less (nerdbox-rootfs.erofs); otherwise infer it from the file name.
case "${2:-$IN}" in
*arm64*|*aarch64*) RUNSC_ARCH=aarch64; GO_ARCH=arm64 ;;
*x86_64*|*amd64*) RUNSC_ARCH=x86_64;  GO_ARCH=amd64 ;;
*) echo "cannot infer arch from $IN (pass it as: mkrootfs-gvisor.sh $IN ARCH)" >&2; exit 1 ;;
esac
case "$IN" in
*rootfs-*) OUT=$(echo "$IN" | sed 's/rootfs-/rootfs-gvisor-/') ;;
*rootfs*)  OUT=$(echo "$IN" | sed 's/rootfs/rootfs-gvisor/') ;;  # arch-less CI bundle name
*) echo "input name must contain 'rootfs'" >&2; exit 1 ;;
esac

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "== extracting $IN"
fsck.erofs --extract="$WORK/rootfs" --no-preserve "$IN" >/dev/null
[ -x "$WORK/rootfs/sbin/crun" ] || { echo "no /sbin/crun in $IN — is this a nerdbox rootfs?" >&2; exit 1; }

echo "== downloading gVisor release ($RUNSC_ARCH)"
BASE=https://storage.googleapis.com/gvisor/releases/release/latest/$RUNSC_ARCH
(
	cd "$WORK"
	wget "$BASE/gvisor.tar.zstd" "$BASE/gvisor.tar.zstd.sha512"
	sha512sum -c gvisor.tar.zstd.sha512
	mkdir gvisor
	tar --zstd -xf gvisor.tar.zstd -C gvisor
)
[ -f "$WORK/gvisor/runsc" ] || { echo "gVisor release archive does not contain runsc" >&2; exit 1; }
NORMAL_SIDECARS="gvisor_sentry gvisor-sentry-prewarmer runsc-fd-parking"
for sidecar in $NORMAL_SIDECARS; do
	[ -f "$WORK/gvisor/gvisor-bin/$sidecar" ] || {
		echo "gVisor release archive does not contain gvisor-bin/$sidecar" >&2
		exit 1
	}
done
chmod +x "$WORK/gvisor/runsc"

echo "== building crunshim ($GO_ARCH)"
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=$GO_ARCH \
    go build -trimpath -ldflags='-s -w' -o "$WORK/crunshim" ./guest/crunshim)

echo "== installing: /sbin/crun = crunshim -> /sbin/crun.runsc (crun -> crun.runc)"
mv "$WORK/rootfs/sbin/crun" "$WORK/rootfs/sbin/crun.runc"
cp "$WORK/gvisor/runsc" "$WORK/rootfs/sbin/crun.runsc"
mkdir -p "$WORK/rootfs/sbin/gvisor-bin"
for sidecar in $NORMAL_SIDECARS; do
	cp "$WORK/gvisor/gvisor-bin/$sidecar" "$WORK/rootfs/sbin/gvisor-bin/$sidecar"
done
cp "$WORK/crunshim" "$WORK/rootfs/sbin/crun"

LABEL=$(basename "$OUT" .erofs | tr -cd 'a-zA-Z0-9._-' | cut -c1-15)
echo "== packing $OUT"
mkfs.erofs --all-root -b4096 -zlz4 -L "$LABEL" "$OUT.tmp" "$WORK/rootfs" >/dev/null
mv "$OUT.tmp" "$OUT"
ls -lh "$OUT"
echo "done: gantry start <name> -runtime runsc   (or -rootfs $OUT)"
