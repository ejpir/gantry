#!/bin/sh
# Build Gantry's pinned nerdbox guest rootfs with Gantry's clock, DHCP-client
# lifetime, trusted system-sync, isolated-session bundle cleanup, and
# quiet-production-log patches. Warnings and errors still reach
# the VM console; verbose plugin/DHCP traces remain available with vminitd
# -debug.
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
BUILDER=
cleanup() {
	if [ -n "$BUILDER" ]; then
		docker buildx rm --force "$BUILDER" >/dev/null 2>&1 || :
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM
SRC="$WORK/nerdbox"
NERDBOX_VERSION=v0.2.4
NERDBOX_COMMIT=a842ff1395290e1ae595f272ae9a698c0b9ca055

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
# Exporting the rootfs needs BuildKit's local exporter (--output). Probe the
# buildx plugin and fall back to the classic BuildKit frontend
# (DOCKER_BUILDKIT=1 docker build) on hosts whose buildx is absent or too
# old to parse modern flags.
HTTPS_PROXY_VALUE=${HTTPS_PROXY:-${https_proxy:-}}
# A single HTTP proxy URL is commonly published as HTTPS_PROXY even though it
# handles both schemes. The Dockerfile also uses plain HTTP package mirrors.
HTTP_PROXY_VALUE=${HTTP_PROXY:-${http_proxy:-$HTTPS_PROXY_VALUE}}
NO_PROXY_VALUE=${NO_PROXY:-${no_proxy:-}}
ALL_PROXY_VALUE=${ALL_PROXY:-${all_proxy:-}}
# buildx parses each --driver-opt value as CSV even when the shell supplies it
# as one argument. Quote the complete key=value field so commas in NO_PROXY (or
# credentials in another proxy URL) remain part of the environment value.
buildx_driver_opt() {
	printf '"'
	printf '%s' "$1" | sed 's/"/""/g'
	printf '"'
}
BUILD="docker buildx build"
BUILDER_ARG=
if ! docker buildx build --help 2>&1 | grep -q -- "--output"; then
	export DOCKER_BUILDKIT=1
	if docker build --help 2>&1 | grep -q -- "--output"; then
		BUILD="docker build"
	else
		echo "error: need Docker with BuildKit (docker buildx) to export the rootfs" >&2
		exit 1
	fi
elif [ -z "${BUILDX_BUILDER:-}" ]; then
	# A docker-container builder does not inherit the client's proxy settings.
	# Its registry requests then bypass HTTPS_PROXY and commonly fail behind a
	# corporate proxy with an unknown-CA error. Use a short-lived builder with
	# normalized proxy variables; leave an explicitly selected builder alone.
	if [ -n "$HTTP_PROXY_VALUE$HTTPS_PROXY_VALUE$ALL_PROXY_VALUE" ]; then
		BUILDER="gantry-rootfs-$$"
		set -- docker buildx create --name "$BUILDER" --driver docker-container
		[ -z "$HTTP_PROXY_VALUE" ] || set -- "$@" --driver-opt "$(buildx_driver_opt "env.HTTP_PROXY=$HTTP_PROXY_VALUE")"
		[ -z "$HTTPS_PROXY_VALUE" ] || set -- "$@" --driver-opt "$(buildx_driver_opt "env.HTTPS_PROXY=$HTTPS_PROXY_VALUE")"
		[ -z "$NO_PROXY_VALUE" ] || set -- "$@" --driver-opt "$(buildx_driver_opt "env.NO_PROXY=$NO_PROXY_VALUE")"
		[ -z "$ALL_PROXY_VALUE" ] || set -- "$@" --driver-opt "$(buildx_driver_opt "env.ALL_PROXY=$ALL_PROXY_VALUE")"
		"$@" --bootstrap >/dev/null
		BUILDER_ARG="--builder $BUILDER"
	fi
fi
$BUILD $BUILDER_ARG --progress=plain \
	--file "$SRC/Dockerfile" \
	--platform "linux/$DOCKER_ARCH" \
	--target erofs \
	--build-arg KERNEL_ARCH="$KERNEL_ARCH" \
	--build-arg "HTTP_PROXY=$HTTP_PROXY_VALUE" \
	--build-arg "HTTPS_PROXY=$HTTPS_PROXY_VALUE" \
	--build-arg "NO_PROXY=$NO_PROXY_VALUE" \
	--build-arg "ALL_PROXY=$ALL_PROXY_VALUE" \
	--output "type=local,dest=$WORK/out" \
	"$SRC"
cp "$WORK/out/nerdbox-rootfs.erofs" "$OUT"
echo "built: $OUT"
