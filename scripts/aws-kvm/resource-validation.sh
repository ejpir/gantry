#!/bin/sh
# Validate high guest RAM and KVM SMP on either Linux host architecture.
# The caller supplies the current-architecture Gantry binary and boot assets.
set -eu

ARCH=${GANTRY_TEST_ARCH:-$(uname -m)}
BASE=${GANTRY_TEST_ROOT:-/opt/gantry}
case "$ARCH" in
x86_64|amd64)
	DEFAULT_G=$BASE/gantry-resource-current-amd64
	DEFAULT_KERNEL=$BASE/gantry-kernel-x86_64-slim
	DEFAULT_ROOTFS=$BASE/nerdbox-rootfs-x86_64-quiet.erofs
	DEFAULT_IMAGE=$BASE/debian-bookworm-amd64.erofs
	;;
aarch64|arm64)
	DEFAULT_G=$BASE/gantry-resource-current-arm64
	DEFAULT_KERNEL=$BASE/gantry-kernel-arm64-deferred-smp
	DEFAULT_ROOTFS=$BASE/nerdbox-rootfs-arm64.erofs
	DEFAULT_IMAGE=$BASE/ubuntu-arm64.erofs
	;;
*)
	echo "unsupported host architecture: $ARCH" >&2
	exit 1
	;;
esac
G=${GANTRY_TEST_EXE:-$DEFAULT_G}
KERNEL=${GANTRY_TEST_KERNEL:-$DEFAULT_KERNEL}
ROOTFS=${GANTRY_TEST_ROOTFS:-$DEFAULT_ROOTFS}
IMAGE=${GANTRY_TEST_IMAGE:-$DEFAULT_IMAGE}
MEMORY_MIB=${GANTRY_TEST_MEMORY_MIB:-22528}
TOUCH_GIB=${GANTRY_TEST_TOUCH_GIB:-5}
PREFIX=${GANTRY_TEST_SANDBOX_PREFIX:-resource-$ARCH}

for path in "$G" "$KERNEL" "$ROOTFS" "$IMAGE"; do
	[ -f "$path" ] || { echo "required file missing: $path" >&2; exit 1; }
done
[ -c /dev/kvm ] || { echo "/dev/kvm is unavailable" >&2; exit 1; }

cleanup_one() {
	"$G" stop "$1" >/dev/null 2>&1 || true
	"$G" delete "$1" >/dev/null 2>&1 || true
}

HIGHMEM=$PREFIX-highmem
SMP2=$PREFIX-smp2
SMP4=$PREFIX-smp4
cleanup_all() {
	cleanup_one "$HIGHMEM"
	cleanup_one "$SMP2"
	cleanup_one "$SMP4"
}
trap cleanup_all EXIT HUP INT TERM
cleanup_all

start_sandbox() {
	name=$1
	cpus=$2
	memory=$3
	"$G" start "$name" \
		-kernel "$KERNEL" \
		-rootfs "$ROOTFS" \
		-image "$IMAGE" \
		-mem "$memory" \
		-cpus "$cpus" \
		-process-isolation=off
}

guest_capture() {
	name=$1
	shift
	"$G" exec "$name" -- "$@" 2>&1
}

echo "== $ARCH: $MEMORY_MIB MiB high-memory guest =="
start_sandbox "$HIGHMEM" 1 "$MEMORY_MIB"
MEMINFO=$(guest_capture "$HIGHMEM" cat /proc/meminfo)
MEMTOTAL=$(printf '%s\n' "$MEMINFO" |
	awk '$1 == "MemTotal:" { value=$2 } END { if (value != "") print value }')
MINIMUM_KIB=$(((MEMORY_MIB - 512) * 1024))
[ -n "$MEMTOTAL" ] || { echo "could not parse guest MemTotal" >&2; exit 1; }
[ "$MEMTOTAL" -ge "$MINIMUM_KIB" ] || {
	echo "guest MemTotal $MEMTOTAL KiB is below expected minimum $MINIMUM_KIB KiB" >&2
	exit 1
}
echo "PASS $ARCH guest reports $MEMTOTAL KiB from a $MEMORY_MIB MiB configuration"

"$G" exec "$HIGHMEM" -- sh -c 'command -v perl >/dev/null'
WORKERS=""
index=0
while [ "$index" -lt "$TOUCH_GIB" ]; do
	WORKERS="$WORKERS (perl -e '\$n=1073741824; \$x=\"x\"x\$n; for(\$i=0;\$i<\$n;\$i+=4096){substr(\$x,\$i,1)=\"y\"} sleep 3;' && echo $index >> /tmp/gantry-highmem-done) &"
	index=$((index + 1))
done
"$G" exec "$HIGHMEM" -- sh -c "set -e; rm -f /tmp/gantry-highmem-done; $WORKERS wait; test \$(wc -l < /tmp/gantry-highmem-done) -eq $TOUCH_GIB; rm -f /tmp/gantry-highmem-done; echo touched-workers=$TOUCH_GIB"
echo "PASS $ARCH guest concurrently touched $TOUCH_GIB GiB above the low-memory region"
cleanup_one "$HIGHMEM"

validate_smp() {
	cpus=$1
	name=$2
	echo "== $ARCH: $cpus-vCPU guest =="
	start_sandbox "$name" "$cpus" 1024
	CPUINFO=$(guest_capture "$name" cat /proc/cpuinfo)
	ONLINE=$(printf '%s\n' "$CPUINFO" |
		awk '/^processor[[:space:]]*:/ { n++ } END { print n+0 }')
	[ "$ONLINE" = "$cpus" ] || {
		echo "guest reports ${ONLINE:-no} online CPUs from a $cpus-vCPU configuration" >&2
		exit 1
	}
	MAP_OUTPUT=$(guest_capture "$name" cat /sys/devices/system/cpu/online)
	MAP=$(printf '%s\n' "$MAP_OUTPUT" |
		awk '/^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$/ { value=$0 } END { print value }')
	[ -n "$MAP" ] || MAP="not reported; /proc count used"
	echo "PASS $ARCH guest reports $ONLINE CPUs online (map: $MAP)"

	"$G" exec "$name" -- sh -c 'command -v taskset >/dev/null; command -v perl >/dev/null'
	WORKERS=""
	index=0
	while [ "$index" -lt "$cpus" ]; do
		WORKERS="$WORKERS (taskset -c $index perl -e '\$x=0; for(\$i=0;\$i<2000000;\$i++){\$x=(\$x+\$i)&0x7fffffff} exit(\$x==0);' && echo $index >> /tmp/gantry-smp-done) &"
		index=$((index + 1))
	done
	"$G" exec "$name" -- sh -c "set -e; rm -f /tmp/gantry-smp-done; $WORKERS wait; test \$(wc -l < /tmp/gantry-smp-done) -eq $cpus; rm -f /tmp/gantry-smp-done; echo pinned-workers=$cpus"
	echo "PASS $ARCH guest completed one concurrent, affinity-pinned worker per vCPU"
	cleanup_one "$name"
}

validate_smp 2 "$SMP2"
validate_smp 4 "$SMP4"
echo "RESULT: $ARCH high-memory and SMP validation passed"
