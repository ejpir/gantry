#!/bin/sh
# mkimage.sh — flatten an OCI image into an EROFS container rootfs
# (the "sbx kit" build step).
#
#   ./scripts/mkimage.sh debian:bookworm-slim artifacts/debian-bookworm.erofs
#   ./scripts/mkimage.sh alpine:latest artifacts/alpine.erofs
#
# Requirements: a working docker daemon, mkfs.erofs. Must run on Linux
# (docker export + erofs-utils); on macOS run it inside a Linux
# container/VM — if the repo is shared, the .erofs appears on the Mac.
#
# The result is used as the container image disk (/dev/vdb):
#   gantry start <name> -image <out.erofs>
set -e

IMAGE=${1:?"usage: mkimage.sh OCI-IMAGE OUT.erofs [PLATFORM]"}
OUT=${2:?"usage: mkimage.sh OCI-IMAGE OUT.erofs [PLATFORM]"}
PLATFORM=${3:-linux/arm64}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "== pulling $IMAGE ($PLATFORM)"
docker pull --quiet --platform "$PLATFORM" "$IMAGE" >/dev/null

echo "== exporting rootfs"
cid=$(docker create --platform "$PLATFORM" "$IMAGE")
trap 'docker rm "$cid" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
mkdir "$WORK/rootfs"
docker export "$cid" | tar -x -C "$WORK/rootfs"
docker rm "$cid" >/dev/null
trap 'rm -rf "$WORK"' EXIT

LABEL=$(basename "$OUT" .erofs | tr -cd 'a-zA-Z0-9._-' | cut -c1-16)
echo "== packing $OUT (erofs, 4K blocks, label $LABEL)"
mkfs.erofs -b4096 -L "$LABEL" "$OUT.tmp" "$WORK/rootfs" >/dev/null
mv "$OUT.tmp" "$OUT"

if command -v fsck.erofs >/dev/null 2>&1; then
  fsck.erofs "$OUT" >/dev/null && echo "== verified"
fi
ls -lh "$OUT"
echo "done: gantry start <name> -image $OUT"
