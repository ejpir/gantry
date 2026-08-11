#!/bin/sh
# Measure clean Gantry startup scaling across vCPU and guest-memory sizes.
#
# Each sample creates a new VM and measures `gantry start` through daemon
# readiness. The image and host file cache are warmed once first; guest caches
# are cold on every sample. CPU and memory sweeps are separate so only one
# resource changes at a time.
#
# GANTRY_BOOT_TIMING supplies low-overhead daemon and vCPU milestones. All
# perturbing profile settings are removed: earlycon creates roughly two
# trapped PL011 MMIO accesses per byte, and GANTRY_BOOT_PROFILE interrupts
# every vCPU for PC sampling. The script reports raw daemon→READY and
# vCPU→READY times separately from the complete CLI invocation.
#
# Usage:
#   ./scripts/bench-boot-scaling.sh [runs] [image]
#
# Example matching the macOS arm64 field setup:
#   IMAGE=nn-docker.artifactory.insim.biz/ubuntu:latest \
#   ./scripts/bench-boot-scaling.sh 7
#
# Useful environment variables:
#   GANTRY=...                 binary under test
#   KERNEL=...                kernel under test
#   CPU_LIST="1 2 4 8"        CPU sweep
#   MEM_LIST="512 1024 4096"  memory sweep, in MiB
#   BASE_CPUS=1               fixed CPU count for the memory sweep
#   BASE_MEM=512              fixed memory size for the CPU sweep
#   PROCESS_ISOLATION=auto    auto | required | off
#   VHOST_SHARES=1            1 enables the split shared-memory share backend
#   NET=true                  true | false
#   BENCH_EXTRA_CMDLINE=...   explicit guest cmdline experiment (for example maxcpus=1)
#   POST_READY_SECONDS=0     keep each VM up after timing (use 0.2 to inspect deferred work)
#   PAUSE_SECONDS=0.25        pause after deleting each VM
#   SAVE_LOGS=1               retain daemon/console/config logs for every run
#   OUT=...                   result directory
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
default_gantry=$ROOT/artifacts/gantry
if [ "$(uname -s)" = Darwin ]; then
	default_gantry=$ROOT/artifacts/gantry-darwin-arm64
fi

GANTRY=${GANTRY:-$default_gantry}
KERNEL=${KERNEL:-$ROOT/artifacts/gantry-kernel-arm64-rngcap}
RUNS=${1:-${RUNS:-7}}
IMAGE=${2:-${IMAGE:-alpine:latest}}
CPU_LIST=${CPU_LIST:-"1 2 4 8"}
MEM_LIST=${MEM_LIST:-"512 1024 4096 8192 16384"}
BASE_CPUS=${BASE_CPUS:-1}
BASE_MEM=${BASE_MEM:-512}
PROCESS_ISOLATION=${PROCESS_ISOLATION:-auto}
VHOST_SHARES=${VHOST_SHARES:-1}
NET=${NET:-true}
BENCH_EXTRA_CMDLINE=${BENCH_EXTRA_CMDLINE:-}
POST_READY_SECONDS=${POST_READY_SECONDS:-0}
PAUSE_SECONDS=${PAUSE_SECONDS:-0.25}
SAVE_LOGS=${SAVE_LOGS:-0}
NAME=${NAME:-boot-scale-$$}
OUT=${OUT:-$ROOT/artifacts/boot-scaling/$(date +%Y%m%d-%H%M%S)-$$}
ROOTFS=${ROOTFS:-}
RUNTIME=${RUNTIME:-crun}

usage() {
	sed -n '2,/^set -eu$/s/^# \{0,1\}//p' "$0"
}

case ${1:-} in
	-h|--help)
		usage
		exit 0
		;;
esac

positive_integer() {
	case $2 in
		''|*[!0-9]*|0)
			echo "$1 must be a positive integer, got: $2" >&2
			exit 2
			;;
	esac
}

positive_integer RUNS "$RUNS"
positive_integer BASE_CPUS "$BASE_CPUS"
positive_integer BASE_MEM "$BASE_MEM"
for value in $CPU_LIST; do
	positive_integer CPU_LIST "$value"
	if [ "$value" -gt 8 ]; then
		echo "CPU_LIST value exceeds Gantry's 8-vCPU limit: $value" >&2
		exit 2
	fi
done
for value in $MEM_LIST; do
	positive_integer MEM_LIST "$value"
done
if [ "$BASE_CPUS" -gt 8 ]; then
	echo "BASE_CPUS exceeds Gantry's 8-vCPU limit: $BASE_CPUS" >&2
	exit 2
fi
case $PROCESS_ISOLATION in
	auto|required|off) ;;
	*) echo "PROCESS_ISOLATION must be auto, required, or off" >&2; exit 2 ;;
esac
case $NET in
	true|false) ;;
	*) echo "NET must be true or false" >&2; exit 2 ;;
esac
case $VHOST_SHARES in
	0|1) ;;
	*) echo "VHOST_SHARES must be 0 or 1" >&2; exit 2 ;;
esac
case $SAVE_LOGS in
	0|1) ;;
	*) echo "SAVE_LOGS must be 0 or 1" >&2; exit 2 ;;
esac

command -v python3 >/dev/null 2>&1 || {
	echo "python3 is required for monotonic sub-millisecond timing" >&2
	exit 1
}
[ -x "$GANTRY" ] || { echo "missing executable Gantry binary: $GANTRY" >&2; exit 1; }
[ -f "$KERNEL" ] || { echo "missing kernel: $KERNEL" >&2; exit 1; }

case $OUT in
	/*) ;;
	*) OUT=$ROOT/$OUT ;;
esac
mkdir -p "$OUT"
cd "$ROOT"

state_root=${GANTRY_HOME:-$HOME/.gantry/sandboxes}
sandbox_dir=$state_root/$NAME
raw=$OUT/raw.tsv
summary=$OUT/summary.tsv

if [ -e "$sandbox_dir" ]; then
	echo "refusing to replace existing sandbox $NAME at $sandbox_dir" >&2
	echo "choose another disposable name with NAME=..." >&2
	exit 1
fi

sha256_file() {
	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		sha256sum "$1" | awk '{print $1}'
	fi
}

{
	printf 'date_utc\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	printf 'host\t%s\n' "$(uname -a)"
	printf 'gantry\t%s\n' "$GANTRY"
	printf 'gantry_sha256\t%s\n' "$(sha256_file "$GANTRY")"
	printf 'kernel\t%s\n' "$KERNEL"
	printf 'kernel_sha256\t%s\n' "$(sha256_file "$KERNEL")"
	printf 'image\t%s\n' "$IMAGE"
	printf 'rootfs\t%s\n' "$ROOTFS"
	printf 'runtime\t%s\n' "$RUNTIME"
	printf 'runs\t%s\n' "$RUNS"
	printf 'cpu_list\t%s\n' "$CPU_LIST"
	printf 'mem_list_mib\t%s\n' "$MEM_LIST"
	printf 'base_cpus\t%s\n' "$BASE_CPUS"
	printf 'base_mem_mib\t%s\n' "$BASE_MEM"
	printf 'process_isolation\t%s\n' "$PROCESS_ISOLATION"
	printf 'vhost_shares\t%s\n' "$VHOST_SHARES"
	printf 'net\t%s\n' "$NET"
	printf 'bench_extra_cmdline\t%s\n' "$BENCH_EXTRA_CMDLINE"
	printf 'post_ready_seconds\t%s\n' "$POST_READY_SECONDS"
	printf 'pause_seconds\t%s\n' "$PAUSE_SECONDS"
	printf 'timing\tlow-overhead internal milestones plus external monotonic CLI timing\n'
	printf 'cache_state\tguest-cold; host image/kernel caches warmed once\n'
	printf 'sanitized\tambient extra cmdline, boot profile, debug, vhost stats, and RAM prefault disabled\n'
	if command -v git >/dev/null 2>&1; then
		printf 'git_head\t%s\n' "$(git rev-parse HEAD 2>/dev/null || true)"
		if [ -n "$(git status --porcelain 2>/dev/null || true)" ]; then
			printf 'git_dirty\tyes\n'
		else
			printf 'git_dirty\tno\n'
		fi
	fi
} >"$OUT/metadata.tsv"
printf 'sweep\tcpus\tmem_mib\trun\tdaemon_to_ready_ms\tdaemon_to_vcpu_ms\tvcpu_to_ready_ms\tcli_to_ready_ms\n' >"$raw"

cleanup() {
	"$GANTRY" delete "$NAME" >/dev/null 2>&1 || true
}
trap cleanup 0
trap 'exit 130' HUP INT TERM

save_sandbox_logs() {
	label=$1
	[ -d "$sandbox_dir" ] || return 0
	for file in daemon.log console.log sandbox.json isolation.json worker-vmm.log worker-net.log; do
		if [ -f "$sandbox_dir/$file" ]; then
			cp "$sandbox_dir/$file" "$OUT/$label.$file"
		fi
	done
}

# Python starts its external timer immediately before spawning Gantry, so
# Python's own startup is outside that sample. Internal raw timings come from
# the daemon/worker's shared low-overhead boot clock.
measure_start() {
	cpus=$1
	mem=$2
	log=$3
	python3 - "$GANTRY" "$NAME" "$IMAGE" "$KERNEL" "$cpus" "$mem" \
		"$PROCESS_ISOLATION" "$VHOST_SHARES" "$NET" "$ROOTFS" "$RUNTIME" \
		"$BENCH_EXTRA_CMDLINE" "$log" <<'PY'
import os
from pathlib import Path
import subprocess
import sys
import time

(
    gantry,
    name,
    image,
    kernel,
    cpus,
    mem,
    isolation,
    vhost_shares,
    net,
    rootfs,
    runtime,
    extra_cmdline,
    log_path,
) = sys.argv[1:]

# Remove settings which perturb guest execution or change the boot experiment.
env = os.environ.copy()
for key in (
    "GANTRY_BOOT_TIMING",
    "GANTRY_BOOT_PROFILE",
    "GANTRY_EXTRA_CMDLINE",
    "GANTRY_DEBUG_BOOT",
    "GANTRY_DEBUG",
    "GANTRY_DEBUG_UART",
    "GANTRY_DEBUG_RTC",
    "GANTRY_DEBUG_NET",
    "GANTRY_DEBUG_FS",
    "GANTRY_NET_PCAP",
    "GANTRY_VHOST_STATS",
    "GANTRY_PREFAULT_RAM",
    "GANTRY_NO_VTIMER_INJECT",
    "GANTRY_NO_RTC",
    "GANTRY_RTC",
    "GANTRY_NO_UART_IRQ",
    "GANTRY_NO_CMDLINE_HARDENING",
    "GANTRY_STRICT_MEMORY_INIT",
):
    env.pop(key, None)
# Basic timing records a handful of milestones. GANTRY_BOOT_PROFILE, which
# performs forced vCPU exits and detailed tracing, remains disabled above.
env["GANTRY_BOOT_TIMING"] = "1"
if extra_cmdline:
    env["GANTRY_EXTRA_CMDLINE"] = extra_cmdline
if vhost_shares == "1":
    env["GANTRY_VHOST_SHARES"] = "1"
else:
    env.pop("GANTRY_VHOST_SHARES", None)

command = [
    gantry,
    "start",
    name,
    "-image",
    image,
    "-kernel",
    kernel,
    "-cpus",
    cpus,
    "-mem",
    mem,
    "-rw=false",
    "-net=" + net,
    "-runtime",
    runtime,
    "-process-isolation",
    isolation,
]
if rootfs:
    command.extend(("-rootfs", rootfs))

with open(log_path, "wb") as output:
    started = time.perf_counter_ns()
    result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, env=env)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000

if result.returncode != 0:
    sys.stderr.write(f"benchmark start failed with exit code {result.returncode}: {' '.join(command)}\n")
    try:
        sys.stderr.write(Path(log_path).read_text(errors="replace"))
    except OSError:
        pass
    raise SystemExit(result.returncode)

print(f"{elapsed_ms:.3f}")
PY
}

boot_metrics() {
	python3 - "$sandbox_dir/daemon.log" "$sandbox_dir/worker-vmm.log" <<'PY'
from pathlib import Path
import re
import sys

texts = []
for name in sys.argv[1:]:
    try:
        texts.append(Path(name).read_text(errors="replace"))
    except OSError:
        pass
text = "\n".join(texts)

if "boot-profile:" in text or "boot-timing: exit  #" in text:
    sys.stderr.write(
        "perturbing boot profile output detected; rebuild Gantry with the "
        "GANTRY_BOOT_PROFILE split and leave that variable unset\n"
    )
    raise SystemExit(1)

def milestone(pattern, label):
    match = re.search(pattern, text)
    if match is None:
        sys.stderr.write(f"missing {label} boot milestone\n")
        raise SystemExit(1)
    return float(match.group(1))

ready = milestone(
    r"boot-timing:\s+guest RPC connected \(READY\)\s+([0-9.]+) ms",
    "guest READY",
)
vcpu_match = re.search(
    r"boot-timing:\s+guest\s+vCPU entered (?:HVF|KVM)\s+([0-9.]+) ms total",
    text,
)
if vcpu_match is not None:
    vcpu = float(vcpu_match.group(1))
else:
    # Supervisor fallback for a backend without a vCPU-entry milestone.
    vcpu = milestone(
        r"boot-timing:\s+vCPUs running; guest booting\s+([0-9.]+) ms",
        "vCPU start",
    )
if ready < vcpu:
    sys.stderr.write(f"READY milestone {ready:.3f} ms precedes vCPU milestone {vcpu:.3f} ms\n")
    raise SystemExit(1)
print(f"{ready:.3f} {vcpu:.3f} {ready - vcpu:.3f}")
PY
}

run_one() {
	sweep=$1
	cpus=$2
	mem=$3
	run=$4
	label=$sweep-c$cpus-m$mem-r$run
	cli_log=$OUT/$label.cli.log

	printf '  %-6s cpus=%-2s mem=%-6s MiB run=%s/%s ... ' \
		"$sweep" "$cpus" "$mem" "$run" "$RUNS"
	if ! cli_elapsed=$(measure_start "$cpus" "$mem" "$cli_log"); then
		echo "FAILED"
		save_sandbox_logs "$label-failed"
		exit 1
	fi
	if ! metrics=$(boot_metrics); then
		echo "FAILED (could not read raw boot milestones)"
		save_sandbox_logs "$label-failed"
		exit 1
	fi
	set -- $metrics
	daemon_ready=$1
	daemon_vcpu=$2
	guest_ready=$3
	printf 'daemon %9s ms; guest %9s ms; CLI %9s ms\n' \
		"$daemon_ready" "$guest_ready" "$cli_elapsed"
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$sweep" "$cpus" "$mem" "$run" "$daemon_ready" "$daemon_vcpu" \
		"$guest_ready" "$cli_elapsed" >>"$raw"

	if [ "$POST_READY_SECONDS" != 0 ]; then
		sleep "$POST_READY_SECONDS"
	fi
	if [ "$SAVE_LOGS" = 1 ]; then
		save_sandbox_logs "$label"
	else
		rm -f "$cli_log"
	fi
	cleanup
	sleep "$PAUSE_SECONDS"
}

echo "== Gantry boot-scaling benchmark =="
echo "binary:    $GANTRY"
echo "kernel:    $KERNEL"
echo "image:     $IMAGE"
echo "output:    $OUT"
echo "isolation: $PROCESS_ISOLATION (vhost shares: $VHOST_SHARES)"
if [ -n "$BENCH_EXTRA_CMDLINE" ]; then
	echo "cmdline:    $BENCH_EXTRA_CMDLINE"
fi
echo
echo "== warm-up (image resolution and host file cache; not measured) =="
warmup_log=$OUT/warmup.cli.log
if ! warmup_ms=$(measure_start "$BASE_CPUS" "$BASE_MEM" "$warmup_log"); then
	save_sandbox_logs warmup-failed
	exit 1
fi
if ! warmup_metrics=$(boot_metrics); then
	save_sandbox_logs warmup-failed
	exit 1
fi
set -- $warmup_metrics
printf '  cpus=%s mem=%s MiB: daemon %s ms; guest %s ms; CLI %s ms\n' \
	"$BASE_CPUS" "$BASE_MEM" "$1" "$3" "$warmup_ms"
if [ "$POST_READY_SECONDS" != 0 ]; then
	sleep "$POST_READY_SECONDS"
fi
if [ "$SAVE_LOGS" = 1 ]; then
	save_sandbox_logs warmup
else
	rm -f "$warmup_log"
fi
cleanup
sleep "$PAUSE_SECONDS"

echo
echo "== CPU sweep (memory fixed at $BASE_MEM MiB) =="
run=1
while [ "$run" -le "$RUNS" ]; do
	for cpus in $CPU_LIST; do
		run_one cpu "$cpus" "$BASE_MEM" "$run"
	done
	run=$((run + 1))
done

echo
echo "== memory sweep (CPUs fixed at $BASE_CPUS) =="
run=1
while [ "$run" -le "$RUNS" ]; do
	for mem in $MEM_LIST; do
		run_one memory "$BASE_CPUS" "$mem" "$run"
	done
	run=$((run + 1))
done

python3 - "$raw" "$summary" <<'PY'
import csv
import math
import statistics
import sys
from collections import OrderedDict

raw_path, summary_path = sys.argv[1:]
groups = OrderedDict()
with open(raw_path, newline="") as source:
    for row in csv.DictReader(source, delimiter="\t"):
        key = (row["sweep"], int(row["cpus"]), int(row["mem_mib"]))
        groups.setdefault(key, []).append(row)

metrics = (
    "daemon_to_ready_ms",
    "daemon_to_vcpu_ms",
    "vcpu_to_ready_ms",
    "cli_to_ready_ms",
)

def describe(rows, metric):
    values = sorted(float(row[metric]) for row in rows)
    p95 = values[max(0, math.ceil(0.95 * len(values)) - 1)]
    return (
        values[0],
        statistics.median(values),
        statistics.fmean(values),
        p95,
        values[-1],
        statistics.pstdev(values),
    )

columns = ["sweep", "cpus", "mem_mib", "n"]
for metric in metrics:
    stem = metric.removesuffix("_ms")
    columns.extend(
        f"{stem}_{suffix}_ms"
        for suffix in ("min", "median", "mean", "p95", "max", "stdev")
    )

with open(summary_path, "w", newline="") as destination:
    writer = csv.writer(destination, delimiter="\t", lineterminator="\n")
    writer.writerow(columns)
    for (sweep, cpus, mem), rows in groups.items():
        output = [sweep, cpus, mem, len(rows)]
        for metric in metrics:
            output.extend(f"{value:.3f}" for value in describe(rows, metric))
        writer.writerow(output)
PY

echo
echo "== raw boot summary =="
python3 - "$summary" <<'PY'
import csv
import sys

with open(sys.argv[1], newline="") as source:
    rows = list(csv.DictReader(source, delimiter="\t"))
print("sweep   cpus  memory      daemon -> READY       vCPU -> READY          CLI -> READY")
print("                              median / p95          median / p95          median / p95")
for row in rows:
    print(
        f"{row['sweep']:<7} {int(row['cpus']):>4}  {int(row['mem_mib']):>6} MiB"
        f"  {float(row['daemon_to_ready_median_ms']):>8.3f} / {float(row['daemon_to_ready_p95_ms']):>8.3f}"
        f"  {float(row['vcpu_to_ready_median_ms']):>8.3f} / {float(row['vcpu_to_ready_p95_ms']):>8.3f}"
        f"  {float(row['cli_to_ready_median_ms']):>8.3f} / {float(row['cli_to_ready_p95_ms']):>8.3f}"
    )
PY

printf '\nRaw samples: %s\nSummary:     %s\nMetadata:    %s\n' \
	"$raw" "$summary" "$OUT/metadata.tsv"
