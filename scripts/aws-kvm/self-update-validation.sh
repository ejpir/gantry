#!/bin/sh
# Validate a real checksummed GitHub self-update on a disposable Linux binary.
set -eu

TARGET=${GANTRY_TEST_UPDATE_EXE:-/opt/gantry/gantry-self-update-test}
[ -f "$TARGET" ] || { echo "self-update test binary missing: $TARGET" >&2; exit 1; }
chmod 0700 "$TARGET"

before=$($TARGET version 2>&1 | sed -n '1p')
case "$before" in
"gantry v0.0.0") ;;
*) echo "unexpected pre-update version: $before" >&2; exit 1 ;;
esac
before_hash=$(sha256sum "$TARGET" | awk '{print $1}')
output=$($TARGET update 2>&1)
printf '%s\n' "$output"
after=$($TARGET version 2>&1 | sed -n '1p')
after_hash=$(sha256sum "$TARGET" | awk '{print $1}')

[ "$after" != "gantry v0.0.0" ] || { echo "self-update left the old Linux binary installed" >&2; exit 1; }
[ "$after_hash" != "$before_hash" ] || { echo "self-update did not replace the Linux executable" >&2; exit 1; }
printf '%s\n' "$output" | grep -q 'updated Gantry v0.0.0'
[ -x "$TARGET" ] || { echo "updated Linux executable lost execute permission" >&2; exit 1; }

echo "PASS Linux self-update: $before -> $after (verified asset replaced in place)"
rm -f -- "$TARGET"
