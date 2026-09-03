#!/bin/sh
# Measure large single-directory lookup/scan behavior in the guest writable
# layer and through a live host share. Runs on Linux KVM or Apple-silicon HVF
# hosts with Linux amd64 or arm64 guests.
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
NAME=${GANTRY_TEST_SANDBOX:-dirscan-$ARCH}
SMALL=${GANTRY_TEST_SMALL_DIR_FILES:-5000}
LARGE=${GANTRY_TEST_LARGE_DIR_FILES:-25000}
ROUNDS=${GANTRY_TEST_FIND_ROUNDS:-10}
HOST_BASE=${GANTRY_TEST_HOST_DIR:-/tmp/gantry-dirscan-$ARCH}
GUEST_BASE=${GANTRY_TEST_GUEST_DIR:-/root/gantry-dirscan}

for path in "$G" "$KERNEL" "$ROOTFS" "$IMAGE"; do
	[ -f "$path" ] || { echo "required file missing: $path" >&2; exit 1; }
done
case "$HOST_BASE" in
/tmp/gantry-dirscan-*) ;;
*) echo "unsafe temporary directory: $HOST_BASE" >&2; exit 1 ;;
esac

cleanup() {
	"$G" share remove --force "$NAME" dirscan >/dev/null 2>&1 || true
	"$G" stop "$NAME" >/dev/null 2>&1 || true
	"$G" delete "$NAME" >/dev/null 2>&1 || true
	rm -rf -- "$HOST_BASE"
}
trap cleanup EXIT HUP INT TERM
cleanup

"$G" start "$NAME" \
	-kernel "$KERNEL" \
	-rootfs "$ROOTFS" \
	-image "$IMAGE" \
	-mem 1024 \
	-cpus 2 \
	-process-isolation=off

guest_capture() {
	"$G" exec "$NAME" -- "$@" 2>&1
}

guest_capture sh -c 'command -v find >/dev/null; command -v perl >/dev/null; command -v date >/dev/null' >/dev/null

echo "== $ARCH: populate $SMALL-file and $LARGE-file single directories =="
guest_capture sh -c 'rm -rf "$1"; mkdir -p "$1/small" "$1/large"' sh "$GUEST_BASE" >/dev/null
guest_capture perl -e '
    my ($root, $small, $large) = @ARGV;
    for my $spec (["$root/small", $small], ["$root/large", $large]) {
        my ($dir, $count) = @$spec;
        for (my $i = 0; $i < $count; $i++) {
            my $path = sprintf("%s/file-%06d", $dir, $i);
            open(my $fh, ">", $path) or die "$path: $!";
            close($fh) or die "$path: $!";
        }
    }
' "$GUEST_BASE" "$SMALL" "$LARGE" >/dev/null

python3 - "$HOST_BASE" "$SMALL" "$LARGE" <<'PY'
import os
import sys

root, small, large = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
for label, count in (("small", small), ("large", large)):
    directory = os.path.join(root, label)
    os.makedirs(directory, exist_ok=True)
    for index in range(count):
        path = os.path.join(directory, f"file-{index:06d}")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
PY

"$G" share add "$NAME" "dirscan=$HOST_BASE" >/dev/null

metric() {
	key=$1
	shift
	guest_capture "$@" | awk -F= -v key="$key" '$1 == key { value=$2 } END { if (value != "") print value }'
}

count_files() {
	directory=$1
	metric COUNT sh -c 'count=$(find "$1" -maxdepth 1 -type f | wc -l); echo COUNT=$count' sh "$directory"
}

scan_us() {
	directory=$1
	metric SCAN_US sh -c '
        directory=$1; rounds=$2
        find "$directory" -maxdepth 1 -type f -name __gantry_not_present__ -print >/dev/null
        start=$(date +%s%N)
        index=0
        while [ "$index" -lt "$rounds" ]; do
            find "$directory" -maxdepth 1 -type f -name __gantry_not_present__ -print >/dev/null
            index=$((index + 1))
        done
        end=$(date +%s%N)
        echo SCAN_US=$(((end - start) / 1000))
    ' sh "$directory" "$ROUNDS"
}

direct_us() {
	directory=$1
	metric DIRECT_US sh -c '
        target=$1/file-024999
        start=$(date +%s%N)
        index=0
        while [ "$index" -lt 10000 ]; do
            [ -f "$target" ] || exit 1
            index=$((index + 1))
        done
        end=$(date +%s%N)
        echo DIRECT_US=$(((end - start) / 1000))
    ' sh "$directory"
}

validate_pair() {
	label=$1
	root=$2
	small_count=$(count_files "$root/small")
	large_count=$(count_files "$root/large")
	[ "$small_count" = "$SMALL" ] || { echo "$label small count $small_count, want $SMALL" >&2; exit 1; }
	[ "$large_count" = "$LARGE" ] || { echo "$label large count $large_count, want $LARGE" >&2; exit 1; }

	small_us=$(scan_us "$root/small")
	large_us=$(scan_us "$root/large")
	direct_lookup_us=$(direct_us "$root/large")
	allowed_us=$((small_us * 8 + 500000))
	[ "$large_us" -le "$allowed_us" ] || {
		echo "$label large-dir scans took ${large_us}us; scaling limit is ${allowed_us}us" >&2
		exit 1
	}
	[ "$large_us" -le 10000000 ] || { echo "$label large-dir scans exceeded 10 seconds" >&2; exit 1; }
	[ "$direct_lookup_us" -le 5000000 ] || { echo "$label direct lookups exceeded 5 seconds" >&2; exit 1; }

	ratio=$(awk -v small="$small_us" -v large="$large_us" 'BEGIN { if (small == 0) print "n/a"; else printf "%.2f", large/small }')
	small_ms=$(awk -v us="$small_us" 'BEGIN { printf "%.3f", us/1000 }')
	large_ms=$(awk -v us="$large_us" 'BEGIN { printf "%.3f", us/1000 }')
	direct_ms=$(awk -v us="$direct_lookup_us" 'BEGIN { printf "%.3f", us/1000 }')
	echo "PASS $ARCH $label: $ROUNDS missing-name find scans: $SMALL files ${small_ms}ms, $LARGE files ${large_ms}ms (${ratio}x); 10k direct lookups ${direct_ms}ms"
}

validate_pair "guest writable layer" "$GUEST_BASE"
validate_pair "live host share" /host/dirscan
echo "RESULT: $ARCH large-directory validation passed"
