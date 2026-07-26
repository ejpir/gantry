#!/bin/sh
# mkrootfs-gvisor.sh — build a nerdbox VM rootfs variant whose containers
# run under gVisor: /sbin/crun is replaced by runsc (which implements the
# runc CLI on purpose — that's how containerd shims drive gVisor), with
# the real crun kept at /sbin/crun.runc. vminitd is unchanged.
#
#   ./mkrootfs-gvisor.sh nerdbox-rootfs-arm64.erofs
#   → nerdbox-rootfs-gvisor-arm64.erofs     (use with: -runtime runsc)
#
# Needs: mkfs.erofs, fsck.erofs, curl, go. Downloads the matching runsc
# release binary (static, ~45 MB) from the gVisor release bucket, and
# builds the crunshim /dev fixer (guest/crunshim) for the target arch.
set -e

IN=${1:?"usage: mkrootfs-gvisor.sh nerdbox-rootfs-ARCH.erofs"}
case "$IN" in
*arm64*|*aarch64*) RUNSC_ARCH=aarch64; GO_ARCH=arm64 ;;
*x86_64*|*amd64*) RUNSC_ARCH=x86_64;  GO_ARCH=amd64 ;;
*) echo "cannot infer arch from $IN" >&2; exit 1 ;;
esac
OUT=$(echo "$IN" | sed 's/rootfs-/rootfs-gvisor-/')
[ "$OUT" != "$IN" ] || { echo "input name must contain 'rootfs-'" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "== extracting $IN"
fsck.erofs --extract="$WORK/rootfs" "$IN" >/dev/null
[ -x "$WORK/rootfs/sbin/crun" ] || { echo "no /sbin/crun in $IN — is this a nerdbox rootfs?" >&2; exit 1; }

echo "== downloading runsc ($RUNSC_ARCH)"
BASE=https://storage.googleapis.com/gvisor/releases/release/latest/$RUNSC_ARCH
curl -fsSL "$BASE/runsc" -o "$WORK/runsc"
curl -fsSL "$BASE/runsc.sha512" -o "$WORK/runsc.sha512"
(cd "$WORK" && sed -i 's/  runsc/  runsc/' runsc.sha512 && sha512sum -c runsc.sha512 >/dev/null)
chmod +x "$WORK/runsc"

echo "== building crunshim ($GO_ARCH)"
(cd "$(dirname "$0")" && CGO_ENABLED=0 GOOS=linux GOARCH=$GO_ARCH \
    go build -trimpath -ldflags='-s -w' -o "$WORK/crunshim" ./guest/crunshim)

echo "== installing: /sbin/crun = crunshim -> /sbin/crun.runsc (crun -> crun.runc)"
mv "$WORK/rootfs/sbin/crun" "$WORK/rootfs/sbin/crun.runc"
cp "$WORK/runsc" "$WORK/rootfs/sbin/crun.runsc"
cp "$WORK/crunshim" "$WORK/rootfs/sbin/crun"

LABEL=$(basename "$OUT" .erofs | tr -cd 'a-zA-Z0-9._-' | cut -c1-15)
echo "== packing $OUT"
mkfs.erofs -b4096 -L "$LABEL" "$OUT.tmp" "$WORK/rootfs" >/dev/null
mv "$OUT.tmp" "$OUT"
ls -lh "$OUT"
echo "done: gantry start <name> -runtime runsc   (or -rootfs $OUT)"
