#!/bin/sh
# Build Gantry's pinned nerdbox guest rootfs with quiet production boot logs.
# Warnings and errors still reach the VM console; verbose plugin/DHCP traces
# remain available with the existing vminitd -debug flag.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARCH=${1:-$(uname -m)}
OUT=${2:-}
case "$ARCH" in
arm64|aarch64) DOCKER_ARCH=arm64; KERNEL_ARCH=arm64 ;;
amd64|x86_64) DOCKER_ARCH=amd64; KERNEL_ARCH=x86_64 ;;
*) echo "usage: $0 [arm64|x86_64] [output.erofs]" >&2; exit 1 ;;
esac
[ -n "$OUT" ] || OUT="$ROOT/artifacts/nerdbox-rootfs-$KERNEL_ARCH.erofs"
case "$OUT" in /*) ;; *) OUT="$PWD/$OUT" ;; esac

WORK=$(mktemp -d "${TMPDIR:-/tmp}/gantry-rootfs.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
SRC="$WORK/nerdbox"
NERDBOX_VERSION=v0.2.3
NERDBOX_COMMIT=cd2c23fe413cdea8176760d63375d3271aa7e611

git clone --quiet --filter=blob:none --no-checkout https://github.com/containerd/nerdbox.git "$SRC"
git -C "$SRC" fetch --quiet --depth 1 origin "$NERDBOX_COMMIT"
git -C "$SRC" checkout --quiet --detach "$NERDBOX_COMMIT"
[ "$(git -C "$SRC" rev-parse HEAD)" = "$NERDBOX_COMMIT" ] || {
	echo "nerdbox $NERDBOX_VERSION resolved to an unexpected commit" >&2
	exit 1
}
for p in "$ROOT/patches/nerdbox-$NERDBOX_VERSION"-*.patch; do
	[ -e "$p" ] || continue
	git -C "$SRC" apply --unidiff-zero --check "$p"
	git -C "$SRC" apply --unidiff-zero "$p"
done

mkdir -p "$WORK/out" "$(dirname "$OUT")"
docker buildx build --progress=plain \
	--file "$SRC/Dockerfile" \
	--platform "linux/$DOCKER_ARCH" \
	--target erofs \
	--build-arg KERNEL_ARCH="$KERNEL_ARCH" \
	--output "type=local,dest=$WORK/out" \
	"$SRC"
cp "$WORK/out/nerdbox-rootfs.erofs" "$OUT"
echo "built: $OUT"
