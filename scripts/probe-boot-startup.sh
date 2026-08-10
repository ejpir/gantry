#!/bin/sh
# probe-boot-startup.sh — repeat the low-overhead kernel boot experiments.
#
# A disposable named sandbox is booted repeatedly with the same persisted
# device configuration. Only GANTRY_EXTRA_CMDLINE changes between runs, so
# vCPU-relative milestone deltas compare kernel behavior rather than host
# preparation or device topology. Raw daemon/console logs and a TSV summary
# are retained under artifacts/boot-probes/.
#
# Defaults target Apple Silicon. Override paths when testing another build:
#
#   GANTRY=./artifacts/gantry-darwin-arm64 \
#   KERNEL=./artifacts/gantry-kernel-arm64 \
#   ./scripts/probe-boot-startup.sh
#
# Test an alternate kernel without replacing the production artifact:
#
#   KERNEL=./artifacts/gantry-kernel-arm64-noselinux \
#   ./scripts/probe-boot-startup.sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
default_gantry=$ROOT/artifacts/gantry
if [ "$(uname -s)" = Darwin ]; then
	default_gantry=$ROOT/artifacts/gantry-darwin-arm64
fi
GANTRY=${GANTRY:-$default_gantry}
KERNEL=${KERNEL:-$ROOT/artifacts/gantry-kernel-arm64}
IMAGE=${IMAGE:-$ROOT/artifacts/debian-bookworm.erofs}
NAME=${NAME:-boot-probe-$$}
OUT=${OUT:-$ROOT/artifacts/boot-probes/$(date +%Y%m%d-%H%M%S)}

state_root=${GANTRY_HOME:-$HOME/.gantry/sandboxes}
sandbox_dir=$state_root/$NAME
summary=$OUT/summary.tsv

[ -x "$GANTRY" ] || { echo "missing executable Gantry binary: $GANTRY" >&2; exit 1; }
[ -f "$KERNEL" ] || { echo "missing kernel: $KERNEL" >&2; exit 1; }
[ -f "$IMAGE" ] || { echo "missing image: $IMAGE" >&2; exit 1; }
if [ -e "$sandbox_dir" ]; then
	echo "refusing to replace existing sandbox $NAME at $sandbox_dir" >&2
	echo "choose another disposable name with NAME=..." >&2
	exit 1
fi
mkdir -p "$OUT"

cleanup() {
	"$GANTRY" delete "$NAME" >/dev/null 2>&1 || true
}
trap cleanup 0
trap 'exit 130' HUP INT TERM

{
	printf 'date_utc\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	printf 'host\t%s\n' "$(uname -a)"
	printf 'gantry\t%s\n' "$GANTRY"
	printf 'kernel\t%s\n' "$KERNEL"
	printf 'image\t%s\n' "$IMAGE"
	if command -v shasum >/dev/null 2>&1; then
		printf 'kernel_sha256\t%s\n' "$(shasum -a 256 "$KERNEL" | awk '{print $1}')"
	elif command -v sha256sum >/dev/null 2>&1; then
		printf 'kernel_sha256\t%s\n' "$(sha256sum "$KERNEL" | awk '{print $1}')"
	fi
} >"$OUT/metadata.tsv"
printf 'probe\textra_cmdline\tvcpu_to_rpc_ms\n' >"$summary"
started=false

vcpu_to_rpc() {
	awk '
		/boot-timing: guest vCPU entered HVF/ {
			for (i = 1; i <= NF; i++) if ($i == "ms") { start = $(i - 1); break }
		}
		/boot-timing: guest RPC connected/ {
			for (i = 1; i <= NF; i++) if ($i == "ms") { ready = $(i - 1); break }
		}
		END {
			if (start == "" || ready == "") exit 1
			printf "%.3f", ready - start
		}
	' "$1"
}

run_probe() {
	label=$1
	extra=$2

	if [ "$started" = true ]; then
		"$GANTRY" stop "$NAME" >/dev/null
		GANTRY_BOOT_TIMING=1 GANTRY_EXTRA_CMDLINE="$extra" \
			"$GANTRY" resume "$NAME" >/dev/null
	else
		GANTRY_BOOT_TIMING=1 GANTRY_EXTRA_CMDLINE="$extra" \
			"$GANTRY" start "$NAME" -kernel "$KERNEL" -image "$IMAGE" -rw=false >/dev/null
		started=true
	fi

	cp "$sandbox_dir/daemon.log" "$OUT/$label.daemon.log"
	cp "$sandbox_dir/console.log" "$OUT/$label.console.log"
	cp "$sandbox_dir/sandbox.json" "$OUT/$label.sandbox.json"
	delta=$(vcpu_to_rpc "$OUT/$label.daemon.log")
	printf '%s\t%s\t%s\n' "$label" "$extra" "$delta" >>"$summary"
	printf '\n== %s (vCPU -> RPC %s ms) ==\n' "$label" "$delta"
	grep '^boot-timing:' "$OUT/$label.daemon.log"
}

# Bracketing with two baselines makes ordinary run-to-run jitter visible.
run_probe baseline-before ''
run_probe selinux-off 'selinux=0'
run_probe mem-256 'mem=256M'
run_probe mem-128 'mem=128M'
run_probe baseline-after ''

printf '\nSaved raw logs and summary to %s\n\n' "$OUT"
cat "$summary"
