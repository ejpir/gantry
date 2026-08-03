#!/bin/sh
# mkkernel-slim.sh — back-compat wrapper for scripts/mkkernel.sh.
#
# Gantry now ships its own hardened kernels (gantry-kernel-<arch>) built by
# mkkernel.sh; this wrapper keeps the old entry point working. Historical
# context: this script produced the boot-time-optimized "slim" nerdbox
# kernel (31.5 ms console flush fixed via loglevel, ~13 ms of subsystem
# probes removed). All of that lives in mkkernel.sh's DISABLES list now.
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARCH=$(uname -m)
case "$ARCH" in aarch64) ARCH=arm64 ;; x86_64) ARCH=x86_64 ;; esac
exec "$ROOT/scripts/mkkernel.sh" "$ARCH"
