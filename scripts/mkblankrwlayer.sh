#!/bin/sh
# mkblankrwlayer.sh — regenerate internal/sandbox/assets/blank.ext4.gz:
# a 512 MiB sparse ext4 with /upper + /work (the per-sandbox rwlayer
# template embedded in the binary). Run on Linux with e2fsprogs.
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
OUT=internal/sandbox/assets/blank.ext4.gz
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
dd if=/dev/zero of="$T/blank.ext4" bs=1M count=0 seek=512 2>/dev/null
mkfs.ext4 -q -F -L rwlayer "$T/blank.ext4"
debugfs -w -R 'mkdir /upper' "$T/blank.ext4" >/dev/null 2>&1
debugfs -w -R 'mkdir /work' "$T/blank.ext4" >/dev/null 2>&1
gzip -9 -c "$T/blank.ext4" > "$OUT"
ls -l "$OUT"
