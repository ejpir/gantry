#!/usr/bin/env bash
# bench-boot.sh — measure gantry VM boot and exec latency.
#
# Three numbers, each n times (default 5):
#   1. cold boot   `gantry start` → ready file (spawn + guest boot to RPC)
#   2. exec        `gantry exec <name> -- true` into the running VM
#                  (the per-tool-call cost for agent integrations)
#   3. one-shot    `gantry exec -image ... -- true` (resolve + boot +
#                  container + graceful shutdown, the one-shot flow)
#
# Phase attribution: run one boot with GANTRY_BOOT_TIMING=1 and read
# daemon.log. It includes daemon phases plus first HVF/MMIO/block/vsock
# milestones; in-guest time is in console.log (kernel printk stamps).
#
# usage: ./scripts/bench-boot.sh [runs] [image]
# env:   GANTRY=./artifacts/gantry-darwin-arm64  (binary to test)
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runs=${1:-5}
image=${2:-alpine:latest}
gantry=${GANTRY:-$ROOT/artifacts/gantry}
cd "$ROOT"
name="bench-boot-$$"

now() { python3 -c 'import time; print(int(time.time()*1000))' 2>/dev/null || perl -MTime::HiRes=time -e 'printf "%d\n", time*1000'; }

stats() { # min/median/mean/max over ms values on stdin
	sort -n | awk '{a[NR]=$1; s+=$1} END {
		if (NR) printf "  min %d ms   median %d ms   mean %d ms   max %d ms   (n=%d)\n", a[1], a[int((NR+1)/2)], s/NR, a[NR], NR
	}'
}

cleanup() { "$gantry" delete "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== warm-up (image cache, first-boot outliers) =="
"$gantry" start "$name" -image "$image" >/dev/null 2>&1 && cleanup

echo "== 1. cold boot: gantry start → ready (image=$image, n=$runs) =="
for _ in $(seq 1 "$runs"); do
	t0=$(now)
	"$gantry" start "$name" -image "$image" >/dev/null 2>&1
	t1=$(now)
	echo $((t1 - t0))
	cleanup
done | stats

echo "== 2. exec into a running VM: gantry exec -- true (n=$runs) =="
"$gantry" start "$name" -image "$image" >/dev/null 2>&1
for _ in $(seq 1 "$runs"); do
	t0=$(now)
	"$gantry" exec "$name" -- true >/dev/null 2>&1
	t1=$(now)
	echo $((t1 - t0))
done | stats
cleanup

echo "== 3. one-shot: gantry exec -image -- true (n=$runs) =="
for _ in $(seq 1 "$runs"); do
	t0=$(now)
	"$gantry" exec -image "$image" -- true >/dev/null 2>&1
	t1=$(now)
	echo $((t1 - t0))
done | stats

cat <<EOF

Phase breakdown of one cold boot:

  GANTRY_BOOT_TIMING=1 $gantry start $name -image $image
  grep boot-timing ~/.gantry/sandboxes/$name/daemon.log
  $gantry delete $name

  # "total" shares the daemon clock; "vCPU +" isolates guest execution.
  # in-guest: kernel boot to userspace from printk stamps
  grep -E '^\\[' ~/.gantry/sandboxes/$name/console.log | tail -5
EOF
