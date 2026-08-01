#!/bin/sh
# mkrwlayer.sh — create an ext4 writable layer for a sandbox (the
# sbx rwlayer.img equivalent): a sparse ext4 image with the /upper and
# /work directories overlayfs needs.
#
#   ./scripts/mkrwlayer.sh artifacts/rwlayer-dev.ext4 [SIZE_MB]
#
# Requirements: mkfs.ext4 + debugfs (e2fsprogs). Must run on Linux; on
# macOS use a Linux container/VM with the repo shared. One rwlayer per
# running sandbox — never attach the same image to two live VMs.
set -e

OUT=${1:?"usage: mkrwlayer.sh OUT.ext4 [SIZE_MB]"}
SIZE=${2:-512}

dd if=/dev/zero of="$OUT" bs=1M count=0 seek="$SIZE" 2>/dev/null
mkfs.ext4 -q -L rwlayer "$OUT"
# separate debugfs invocations: multiple -R flags do not compose
debugfs -w -R 'mkdir /upper' "$OUT" >/dev/null 2>&1
debugfs -w -R 'mkdir /work' "$OUT" >/dev/null 2>&1
debugfs -R 'ls /' "$OUT" 2>/dev/null
ls -lh "$OUT"
echo "done: gantry start <name> -rwlayer $OUT   (writable root, persists across stop/start)"
