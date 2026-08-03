#!/bin/sh
# mkkernel-4k.sh — back-compat wrapper: build the 4K-page kernel variant.
#
# gVisor's stock arm64 runsc is compiled for 4K pages and hard-fails in
# `runsc boot` on anything else ("host page size (16384) does not match
# compiled page size (4096)"), so runsc sandboxes need the 4K twin of the
# running kernel. This builds it via mkkernel.sh:
#
#   ./scripts/mkkernel-4k.sh   # → artifacts/gantry-kernel-arm64-4k
#
# (x86_64 is always 4K; gantry-kernel-x86_64 already works with runsc.)
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARCH=$(uname -m)
case "$ARCH" in aarch64) ARCH=arm64 ;; x86_64) ARCH=x86_64 ;; esac
PAGES=4k exec "$ROOT/scripts/mkkernel.sh" "$ARCH"
