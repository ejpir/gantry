#!/bin/sh
# Exercise virtio-fs node pruning beyond the supervisor's 64K live-node
# watermark. Runs on either Linux host architecture and preserves logs when
# the guest or control plane stops responding.
set -eu

ARCH=${GANTRY_TEST_ARCH:-$(uname -m)}
BASE=${GANTRY_TEST_ROOT:-/opt/gantry}
case "$ARCH" in
x86_64|amd64)
	G=${GANTRY_TEST_EXE:-$BASE/gantry-resource-current-amd64}
	KERNEL=${GANTRY_TEST_KERNEL:-$BASE/gantry-kernel-x86_64-slim}
	ROOTFS=${GANTRY_TEST_ROOTFS:-$BASE/nerdbox-rootfs-x86_64-quiet.erofs}
	IMAGE=${GANTRY_TEST_IMAGE:-$BASE/debian-bookworm-amd64.erofs}
	;;
aarch64|arm64)
	G=${GANTRY_TEST_EXE:-$BASE/gantry-resource-current-arm64}
	KERNEL=${GANTRY_TEST_KERNEL:-$BASE/gantry-kernel-arm64-deferred-smp}
	ROOTFS=${GANTRY_TEST_ROOTFS:-$BASE/nerdbox-rootfs-arm64.erofs}
	IMAGE=${GANTRY_TEST_IMAGE:-$BASE/ubuntu-arm64.erofs}
	;;
*)
	echo "unsupported host architecture: $ARCH" >&2
	exit 1
	;;
esac

NAME=${GANTRY_TEST_SANDBOX:-prune-$ARCH}
COUNT=${GANTRY_TEST_PRUNE_DIRS:-150000}
ROUNDS=${GANTRY_TEST_PRUNE_ROUNDS:-2}
CPUS=${GANTRY_TEST_CPUS:-4}
HOST_ROOT=/tmp/gantry-prune-$ARCH
LOG_ROOT=/tmp/gantry-prune-logs-$ARCH

for path in "$G" "$KERNEL" "$ROOTFS" "$IMAGE"; do
	[ -f "$path" ] || { echo "required file missing: $path" >&2; exit 1; }
done
[ -c /dev/kvm ] || { echo "/dev/kvm is unavailable" >&2; exit 1; }
case "$HOST_ROOT" in
/tmp/gantry-prune-*) ;;
*) echo "unsafe temporary directory: $HOST_ROOT" >&2; exit 1 ;;
esac

cleanup() {
	"$G" share remove --force "$NAME" prune >/dev/null 2>&1 || true
	"$G" stop "$NAME" >/dev/null 2>&1 || true
	"$G" delete "$NAME" >/dev/null 2>&1 || true
	rm -rf -- "$HOST_ROOT"
}

preserve_logs() {
	mkdir -p "$LOG_ROOT"
	if [ -n "${GANTRY_HOME:-}" ]; then
		sandbox_root=$GANTRY_HOME
	elif [ -n "${HOME:-}" ]; then
		sandbox_root=$HOME/.gantry/sandboxes
	else
		# Match sandboxRoot's fallback when the SSM agent supplies no HOME.
		sandbox_root=/tmp/.gantry/sandboxes
	fi
	sandbox_dir=$sandbox_root/$NAME

	# Ask the guest for diagnostics before disturbing the host process. A VM
	# deadlock may make this fail, but the bounded attempt still records why.
	timeout 15 "$G" exec "$NAME" -- sh -c '
		echo "== uptime =="; cat /proc/uptime
		echo "== cpu pressure =="; cat /proc/pressure/cpu
		echo "== dmesg =="; dmesg
	' >"$LOG_ROOT/guest-diagnostics.log" 2>&1 || true

	# vmm.pid names the Go daemon that owns the VM. Snapshot every host thread,
	# then request Go's SIGQUIT dump while daemon.log is still available. This
	# turns an otherwise opaque timeout into a useful lock/goroutine postmortem.
	vmm_pid=
	if [ -r "$sandbox_dir/vmm.pid" ]; then
		vmm_pid=$(sed -n '1{s/[^0-9].*//;p;}' "$sandbox_dir/vmm.pid")
	fi
	case "$vmm_pid" in
	''|*[!0-9]*) ;;
	*)
		if kill -0 "$vmm_pid" 2>/dev/null; then
			{
				date -u
				echo "PID=$vmm_pid"
				ps -L -p "$vmm_pid" -o pid,tid,psr,stat,pcpu,wchan:32,comm
				for task_dir in /proc/"$vmm_pid"/task/*; do
					[ -d "$task_dir" ] || continue
					tid=${task_dir##*/}
					comm=$(cat "$task_dir/comm" 2>/dev/null || echo unknown)
					wchan=$(cat "$task_dir/wchan" 2>/dev/null || echo unknown)
					echo "===== tid $tid $comm wchan=$wchan ====="
					cat "$task_dir/stack" 2>/dev/null || true
				done
			} >"$LOG_ROOT/host-threads.log" 2>&1 || true
			kill -QUIT "$vmm_pid" 2>/dev/null || true
			attempt=0
			while kill -0 "$vmm_pid" 2>/dev/null && [ "$attempt" -lt 5 ]; do
				sleep 1
				attempt=$((attempt + 1))
			done
		fi
		;;
	esac

	for log in console.log daemon.log worker-vmm.log; do
		if [ -f "$sandbox_dir/$log" ]; then
			cp "$sandbox_dir/$log" "$LOG_ROOT/$log"
		fi
	done
	archive=$LOG_ROOT.tar.gz
	log_parent=${LOG_ROOT%/*}
	log_name=${LOG_ROOT##*/}
	if tar -C "$log_parent" -czf "$archive" "$log_name"; then
		echo "failure dump preserved at $archive" >&2
		sha256sum "$archive" >&2
	else
		echo "failure logs preserved under $LOG_ROOT (archive failed)" >&2
	fi
}

fail() {
	echo "FAIL $ARCH: $*" >&2
	preserve_logs
	exit 1
}

trap cleanup EXIT HUP INT TERM
cleanup
rm -rf -- "$LOG_ROOT"
rm -f -- "$LOG_ROOT.tar.gz"
mkdir -p "$HOST_ROOT/tree"

python3 - "$HOST_ROOT/tree" "$COUNT" <<'PY'
import os
import sys

root, count = sys.argv[1], int(sys.argv[2])
for index in range(count):
    os.mkdir(os.path.join(root, f"dir-{index:06d}"), 0o700)
PY

echo "== $ARCH: traverse $COUNT shared directories for $ROUNDS rounds with $CPUS vCPUs =="
"$G" start "$NAME" \
	-kernel "$KERNEL" \
	-rootfs "$ROOTFS" \
	-image "$IMAGE" \
	-mem 1024 \
	-cpus "$CPUS" \
	-process-isolation=off
"$G" share add "$NAME" "prune=$HOST_ROOT" >/dev/null

round=1
while [ "$round" -le "$ROUNDS" ]; do
	output=$(timeout 180 "$G" exec "$NAME" -- sh -c '
		list=/tmp/gantry-prune-list
		rm -f "$list"
		start_ns=$(date +%s%N)
		find /host/prune/tree -mindepth 1 -maxdepth 1 -type d -print >"$list" || exit 90
		end_ns=$(date +%s%N)
		count=$(wc -l <"$list")
		rm -f "$list"
		echo COUNT=$count
		echo ELAPSED_MS=$(((end_ns - start_ns) / 1000000))
	' 2>&1) || fail "directory traversal $round failed: $output"
	count=$(printf '%s\n' "$output" | awk -F= '$1 == "COUNT" { value=$2 } END { print value }')
	[ "$count" = "$COUNT" ] || fail "directory traversal $round counted ${count:-nothing}, want $COUNT: $output"
	elapsed_ms=$(printf '%s\n' "$output" | awk -F= '$1 == "ELAPSED_MS" { value=$2 } END { print value }')
	timeout 30 "$G" exec "$NAME" -- true >/dev/null 2>&1 || fail "VM became unresponsive after traversal $round"
	echo "PASS $ARCH traversal $round retained control-plane liveness (${elapsed_ms:-unknown} ms)"
	round=$((round + 1))
done

echo "RESULT: $ARCH virtio-fs pruning remained live beyond $COUNT nodes"
