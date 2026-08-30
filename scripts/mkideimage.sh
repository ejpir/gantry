#!/bin/sh
# Build the curated SSH/Dev Containers image and flatten it to EROFS.
#
# With no arguments, build the current host architecture into the conventional
# artifacts/ release-asset path. A platform can be selected explicitly:
#
#   scripts/mkideimage.sh
#   scripts/mkideimage.sh artifacts/gantry-ide-image-arm64.erofs linux/arm64
set -eu

if [ "$#" -gt 2 ]; then
  echo "usage: mkideimage.sh [OUT.erofs [PLATFORM]]" >&2
  exit 2
fi

PLATFORM=${2:-}
if [ -z "$PLATFORM" ]; then
  case $(uname -m) in
    x86_64|amd64) PLATFORM=linux/amd64 ;;
    arm64|aarch64) PLATFORM=linux/arm64 ;;
    *) echo "unsupported host architecture $(uname -m); pass PLATFORM explicitly" >&2; exit 2 ;;
  esac
fi
case "$PLATFORM" in
  linux/amd64) ASSET_ARCH=x86_64 ;;
  linux/arm64) ASSET_ARCH=arm64 ;;
  *) echo "unsupported development image platform $PLATFORM (want linux/amd64 or linux/arm64)" >&2; exit 2 ;;
esac
OUT=${1:-artifacts/gantry-ide-image-${ASSET_ARCH}.erofs}
mkdir -p "$(dirname "$OUT")"
TAG="gantry-ide-image:$(echo "$PLATFORM" | tr '/:' '--')-$$"
WORK=$(mktemp -d)
OUT_TMP="$OUT.tmp.$$"
CID=""
cleanup() {
  [ -z "$CID" ] || docker rm "$CID" >/dev/null 2>&1 || true
  docker image rm "$TAG" >/dev/null 2>&1 || true
  rm -f "$OUT_TMP"
  rm -rf "$WORK"
}
trap cleanup EXIT

# Use a minimal build context containing only the Dockerfile and its Podman
# launcher. Sending the repository is disastrous for remote engines:
# development trees commonly contain multi-gigabyte VM disks and OCI archives.
cp scripts/ide-image.Dockerfile "$WORK/Dockerfile"
cp scripts/gantry-podman "$WORK/gantry-podman"

# BuildKit's predefined proxy arguments are intentionally forwarded by name,
# not embedded in the Dockerfile or image metadata. Supplying --build-arg NAME
# without a value makes Docker read the value from this process's environment.
# Support both conventional casings because developer shells and CI systems
# differ, and preserve NO_PROXY for local mirrors. An HTTP proxy commonly
# arrives only as HTTPS_PROXY even though it handles both schemes; Debian's
# package mirrors use HTTP, so mirror that value when HTTP_PROXY is absent.
# BuildKit runs registry metadata resolution in a separate daemon. With remote
# Podman behind an intercepting HTTPS proxy, that daemon may not have the
# corporate CA even though Podman's native builder and image store do. Select
# Podman's Docker-compatible build endpoint in that case; --pull=false also
# lets it use a base image already mirrored into the remote engine.
if [ -z "${HTTP_PROXY:-${http_proxy:-}}" ] && [ -n "${HTTPS_PROXY:-${https_proxy:-}}" ]; then
  HTTP_PROXY="${HTTPS_PROXY:-${https_proxy:-}}"
  export HTTP_PROXY
  export http_proxy="$HTTP_PROXY"
fi
PODMAN_BUILD=false
if docker version --format '{{range .Server.Components}}{{println .Name}}{{end}}' 2>/dev/null \
    | grep -qx 'Podman Engine'; then
  PODMAN_BUILD=true
  set -- --pull=false --platform "$PLATFORM" -f "$WORK/Dockerfile" -t "$TAG"
else
  set -- --load --platform "$PLATFORM" -f "$WORK/Dockerfile" -t "$TAG"
fi
for proxy_name in HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; do
  proxy_value=$(printenv "$proxy_name" 2>/dev/null || true)
  if [ -n "$proxy_value" ]; then
    # Some sandbox launchers spell an HTTP proxy as http:///HOST:PORT. That
    # has an empty URL authority and Docker rejects it. Accept this common
    # injected form by removing only the surplus slash(es), while leaving
    # paths, credentials, NO_PROXY lists, and valid URLs untouched.
    case "$proxy_value" in
      http:///*|https:///*)
        proxy_scheme=${proxy_value%%:*}
        proxy_address=${proxy_value#*://}
        while [ "${proxy_address#/}" != "$proxy_address" ]; do
          proxy_address=${proxy_address#/}
        done
        proxy_value="$proxy_scheme://$proxy_address"
        echo "normalizing malformed $proxy_name URL to $proxy_scheme://<proxy>" >&2
        ;;
    esac
    # Export the normalized value under its original spelling. The fixed list
    # above prevents an arbitrary environment name from becoming shell input.
    export "$proxy_name=$proxy_value"
    set -- "$@" --build-arg "$proxy_name"
  fi
done
if "$PODMAN_BUILD"; then
  echo "using remote Podman native builder (BuildKit metadata resolver bypassed)" >&2
  DOCKER_BUILDKIT=0 docker build "$@" "$WORK"
else
  docker buildx build "$@" "$WORK"
fi
CID=$(docker create --platform "$PLATFORM" "$TAG")
ROOTFS_TAR="$WORK/rootfs.tar"
docker export "$CID" >"$ROOTFS_TAR"
docker rm "$CID" >/dev/null
CID=""

# EROFS volume_name is a 16-byte field including its terminating NUL. Build
# the filesystem in local scratch space: OUT is commonly on Gantry's macOS
# shared filesystem, where mkfs's metadata/random writes are extremely slow.
# Feed the export tar directly to mkfs rather than extracting it as the calling
# user: tar headers preserve root ownership, setuid tools such as sudo, and the
# image's explicit UID/GID 1000 home. Only the completed image crosses the
# shared filesystem boundary, as one sequential copy.
LABEL=$(basename "$OUT" .erofs | tr -cd 'a-zA-Z0-9._-' | cut -c1-15)
LOCAL_IMAGE="$WORK/image.erofs"
mkfs.erofs -b4096 -zlz4 -L "$LABEL" --tar=f "$LOCAL_IMAGE" "$ROOTFS_TAR" >/dev/null
if command -v fsck.erofs >/dev/null 2>&1; then
  fsck.erofs "$LOCAL_IMAGE" >/dev/null
fi
cp "$LOCAL_IMAGE" "$OUT_TMP"
mv "$OUT_TMP" "$OUT"
ls -lh "$OUT"
