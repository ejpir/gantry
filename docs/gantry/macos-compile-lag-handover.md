# Handover: macOS sandbox compile-load lag

Status: active investigation, not resolved  
Branch: `feat/ssh`  
Host/backend: Apple silicon macOS, Hypervisor.framework (HVF)  
Affected sandbox: `codex-dev`  
Sandbox state on host: `/Users/eh04xk/.gantry/sandboxes/codex-dev`

## Problem statement

Compiling inside the sandbox causes the guest load average to rise to roughly
30 and makes the sandbox noticeably laggy. The VM is configured with 12 vCPUs.
The initial suspicion was the macOS HVF interrupt/liveness kicker.

Twelve configured vCPUs do not by themselves rule out CPU saturation: they are
host-scheduled vCPU threads rather than dedicated physical cores, and Linux
load average includes both runnable tasks and tasks blocked in uninterruptible
I/O. A load of 30 on 12 vCPUs means demand or blocked work substantially exceeds
the guest's instantaneous capacity.

## Current conclusions

1. **The workload produces very high storage/share interrupt traffic.**
   Representative one-second windows contained approximately 20,000-27,000
   `hv_gic_set_spi` calls.
2. **The production liveness kicker is active under long in-guest runs, but its
   completed native calls are short.** Completed `hv_vcpus_exit` calls averaged
   roughly 33-44 microseconds, initially maxing around 171 microseconds and later
   around 704 microseconds.
3. **Disabling the liveness kicker did not subjectively fix the lag.** The latest
   A/B was started with `GANTRY_HVF_NO_LIVENESS_KICK=1` and remained slow. This
   makes the kicker an unlikely primary cause, although the exact workload and
   timings should be recorded for a rigorous comparison.
4. **The latest coalescing A/B was not measured.** The startup marker proved
   `GANTRY_HVF_IRQ_COALESCE=1` was active, but that invocation omitted
   `GANTRY_HVF_STATS=1` and `GANTRY_VHOST_STATS=1`; therefore only diagnostic
   startup markers, and no runtime statistics, were expected.
5. **An AWS EC2 Mac M4 reproduction identifies workload-level nested
   parallelism as the reason for the extreme load, but not by itself as the
   reason the sandbox feels worse than the host.** `task build` launches six
   GoReleaser targets concurrently, while each Go build can use every visible
   CPU. On a 10-vCPU guest this reached load 116 and 211 runnable tasks. A
   native build on the same 10-core Mac also reached load 90, 79 runnable
   tasks, and 977% aggregate process CPU, so a high load is intrinsic to this
   command. The remaining sandbox-specific difference is two-level scheduling
   plus VM and share overhead.
6. **virtio-fs remains a meaningful secondary cost.** An otherwise equivalent
   uncapped warm build took 141 seconds from the host share and 113 seconds
   from guest-private storage (about 20% faster), but both had load over 100.
7. **Limiting both levels of build concurrency restores headroom without a
   throughput penalty in this workload.** `GOMAXPROCS=4` with GoReleaser
   `--parallelism 2` took 138 seconds versus 141 seconds uncapped, while maximum
   load fell from 116 to 38 and maximum runnable tasks from 211 to 31.
8. **HVF IRQ line coalescing is harmful for this build.** The same uncapped,
   warm, shared-source build took 166 seconds with coalescing versus 141 seconds
   without it, and guest I/O wait rose from 0.4% to 21.3%. Keep the option
   diagnostic-only.

## AWS EC2 Mac M4 reproduction

The reproduction host is an AWS `mac-m4.metal` in `eu-west-1a` with 10 cores
and 24 GiB RAM. The guest used 10 vCPUs and 12 GiB RAM. The tracked
`andromeda-cli` tree was shared into the guest, and the actual GoReleaser build
from `task build` was exercised.

A cold baseline (including initial GoReleaser and module downloads) completed
in 202 seconds and reached:

```text
max load1:       118.58
max runnable:    218
host VMM CPU:    repeatedly 950-986% on a 10-core host
```

For a fair warm-cache comparison, both variants deleted `GOCACHE` and rebuilt
all six release targets:

| Location / concurrency | Elapsed | Max load1 | Max runnable | CPU | I/O wait |
|---|---:|---:|---:|---:|---:|
| native macOS, default concurrency | 94 s | 90.26 | 79 | 977% peak | n/a |
| guest share, default concurrency | 141 s | 116.49 | 211 | 95.0% | 0.4% |
| guest share, `GOMAXPROCS=4`, `--parallelism 2` | 138 s | 38.18 | 31 | 80.1% | 0.9% |
| guest-private, default concurrency | 113 s | 123.43 | 221 | 93.2% | 1.1% |
| guest share, default concurrency, IRQ coalescing | 166 s | 94.13 | 207 | 73.9% | 21.3% |

The native control confirms that GoReleaser's fan-out also saturates the host
outside a sandbox. Native macOS can nevertheless schedule interactive and
compiler processes directly. With 10 guest vCPUs on a 10-core host, macOS sees
10 opaque hot vCPU threads and cannot see which guest work is interactive; VMM,
virtio-fs, network, and supervisor threads also need host time. This
host/guest scheduler layering can make the sandbox less responsive even when
the source workload is equally over-parallelized.

The uncapped shared build generated about 663,000 GIC assertions, including
about 381,000 for the writable disk and 280,000 for virtio-fs. The equivalent
private build eliminated nearly all virtio-fs traffic but still generated
about 387,000 writable-disk assertions and still had load over 120. This is why
virtio-fs explains part of elapsed time but not the extreme run queue.

With IRQ coalescing, about 473,000 repeated line changes were suppressed and
delivered assertions/deassertions became balanced, but the build slowed by 25
seconds and spent much more time in I/O wait. Repeated block/share wakeups
cannot be treated as free redundant work by the current implementation.

A separate EC2 Mac issue was found and fixed during this investigation.
`process-isolation=required` initially made `hv_gic_create` return
`HV_BAD_ARGUMENT`. The macOS unified log showed the confined VMM worker being
denied `sysctl-read hw.pagesize_compat`; Hypervisor.framework queries that
value while creating the GIC on Apple M4/macOS 15. Adding that one VMM-only
Seatbelt allowance fixed the boot. Both 1-vCPU and 10-vCPU required-mode boots
now report `split-net+split-vmm` with network, filesystem, and process
boundaries enforced. No broad Mach or IOKit permission was needed.

## Important log/topology detail

`worker-vmm.log` is append-only/bounded across many starts and contains many old
device maps. Do not use the first matching map. The HVF statistics discussed
here include IRQs through 79, so they correspond to the most recent topology:

| IRQ | Device in current topology |
|---:|---|
| 48 | rootfs `/dev/vda` |
| 49-72 | read-only OCI image layers (`/dev/vdb` through `/dev/vdy`) |
| 62 | active 953 MiB read-only layer `/dev/vdo` |
| 73 | main 60 GiB writable layer `/dev/vdz` |
| 74 | secondary 32 GiB writable layer |
| 75 | `gantry-shares` virtio-fs device |
| 76 | virtio-net |
| 77 | virtio-vsock |
| 78 | virtio-rng |
| 79 | virtio-rtc |

Older starts had fewer layers and therefore assigned virtio-fs/vsock to lower
IRQ numbers. Always correlate statistics with the final device map for that
specific boot.

## Evidence collected

### Vhost/share statistics

With `GANTRY_VHOST_STATS=1`, the daemon reported:

```text
vhost-share-stats: requests=25000 errors=8 wall=22.764s
  handler-total=6.659s handler-avg=266us handler-max=95.458ms
  request-gap-max=5.862s(after=223)

vhost-share-stats: requests=50000 errors=8 wall=23.875s
  handler-total=11.389s handler-avg=228us handler-max=95.458ms
```

The second 25,000 requests arrived in about 1.11 seconds, approximately 22,500
FUSE requests/second. The workload was metadata-heavy:

- `getattr`: 23,885 cumulative at 50k requests
- `lookup`: 5,254
- `open`: 4,840
- `read`: 6,129
- `write`: 2
- `release`: 4,844
- `flush`: 4,843

The early 95 ms `open` outlier happened around request 24 and was not a
sustained handler stall. The logged FUSE errors were mostly normal probes or
fallbacks with `transport=OK`:

- opcode 22 / `GETXATTR`, errno `-61` (`ENODATA`)
- `POLL`, errno `-38` (`ENOSYS`)
- `OPENDIR`, errno `-38` (`ENOSYS` fallback)
- opcode 11 / `RMDIR`, errno `-39` (`ENOTEMPTY`)

### HVF statistics before the coalescing A/B

A representative cumulative snapshot was:

```text
gic(assert=156722 deassert=59530 avg=1us max=2.065ms)
per-irq=[
  62:5491/3539,
  73:109502/17089,
  75:37469/37464,
  77:943/854
]
liveness(batches=602 targets=1475 avg=36us max=704us)
other-kicks(batches=0 targets=0)
```

Interpretation using the current topology:

- IRQ 73 (writable ext4/overlay disk) had a very large assertion/deassertion
  imbalance.
- IRQ 75 (virtio-fs) was nearly one assertion and acknowledgement per
  completion notification and reached tens of thousands of interrupts.
- IRQ 62 showed reads from one active OCI image layer.
- IRQ 77 (vsock) was comparatively quiet, so terminal/SSH output was not the
  principal interrupt source in this capture.

During the largest storage IRQ bursts, liveness counters barely advanced or
stopped advancing. During stretches with almost no GIC activity, all vCPUs
could remain inside HVF long enough for the 250 ms backstop to fire repeatedly.
The completed native calls were still short.

## Code changes currently in the working tree

These changes are uncommitted.

### `GANTRY_HVF_STATS=1`

Implemented in `internal/vmm/vm_darwin.go` and forwarded to split Unix VMM
workers by `internal/sandbox/vmmworker/env_unix.go`.

It emits a cumulative line every second containing:

- GIC assertion/deassertion count and native call latency;
- per-IRQ counts;
- production liveness-kicker batches and target count;
- per-vCPU liveness and canceled-exit count;
- generic/other kick count;
- age of each vCPU currently inside `hv_vcpu_run`.

### `GANTRY_HVF_IRQ_COALESCE=1`

Experimental, off by default. Implemented in the Darwin HVF backend rather
than changing every platform's virtio behavior. Repeated identical GIC line
levels are suppressed until the opposite level arrives. With HVF statistics,
per-IRQ values render as:

```text
IRQ:assertions/deassertions/suppressed
```

The startup marker is:

```text
[diag] GANTRY_HVF_IRQ_COALESCE=1: repeated GIC line levels suppressed
```

The most recent run showed this marker, but omitted `GANTRY_HVF_STATS=1`, so
there is no measurement of how many calls it suppressed or whether it reduced
the relevant interrupt rates.

### `GANTRY_HVF_NO_LIVENESS_KICK=1`

Experimental diagnostic only, off by default. It skips the 50 ms liveness
worker that calls `hv_vcpus_exit` for vCPUs which have remained in
`hv_vcpu_run` for at least 250 ms.

The startup marker is:

```text
[diag] GANTRY_HVF_NO_LIVENESS_KICK=1: lost-vtimer backstop disabled
```

Do not make this the default. It can expose the missed virtual-timer condition
the backstop was added to prevent, potentially causing Linux scheduler/RCU
starvation.

### Nonblocking stalled-call diagnostics

The runtime reporter now uses `vcpuMu.TryLock` instead of blocking behind the
liveness kicker. New output includes:

```text
liveness(... in-flight=yes:3.2s ...)
vcpu-lock=busy
```

This is intended to distinguish a reporter blocked behind a stalled
`hv_vcpus_exit` from general Go scheduler/process starvation.

### Files changed

- `internal/vmm/vm_darwin.go`
- `internal/vmm/vm_idle_darwin_test.go`
- `internal/sandbox/vmmworker/env_unix.go`
- `internal/sandbox/vmmworker/env_unix_test.go`
- `scripts/bench-boot-scaling.sh`
- `docs/gantry/troubleshooting.md`
- this handover document

Unrelated untracked files already exist in the repository; do not delete or
commit them as part of this investigation.

## Exact next run

The previous command omitted both statistics variables. Stop and resume with
all diagnostics enabled:

```sh
cd /Users/eh04xk/repos/minivm

./artifacts/gantry-darwin-arm64 stop codex-dev

GANTRY_VHOST_STATS=1 \
GANTRY_HVF_STATS=1 \
GANTRY_HVF_IRQ_COALESCE=1 \
GANTRY_HVF_NO_LIVENESS_KICK=1 \
  ./scripts/run-macos.sh resume codex-dev
```

Using `scripts/run-macos.sh` is important after source changes: it rebuilds the
Darwin arm64 binary and ad-hoc signs it with the Hypervisor.framework
entitlement.

Confirm all modes:

```sh
DIR="$HOME/.gantry/sandboxes/codex-dev"

grep -E 'GANTRY_HVF_STATS|HVF_IRQ_COALESCE|NO_LIVENESS_KICK' \
  "$DIR/worker-vmm.log" | tail -10
```

Expected markers:

```text
[stats] GANTRY_HVF_STATS=1: cumulative HVF/GIC summary every 1s
[diag] GANTRY_HVF_NO_LIVENESS_KICK=1: lost-vtimer backstop disabled
[diag] GANTRY_HVF_IRQ_COALESCE=1: repeated GIC line levels suppressed
```

Capture two or more consecutive lines during the lag:

```sh
awk '
  /GANTRY_HVF_IRQ_COALESCE=1/ { current=1; next }
  current && /hvf-stats:/ { print }
' "$DIR/worker-vmm.log" | tail -10

grep -E 'vhost-share-stats|vhost-fs-call-stats' \
  "$DIR/daemon.log" "$DIR/worker-vmm.log" | tail -20
```

For IRQ 73, a successful coalescing test should turn the previous approximate
shape:

```text
73:109502/17089/0
```

into something closer to:

```text
73:~17000/~17000/~92000
```

If the suppressed count remains zero after the current-run marker, investigate
why `shouldDeliverIRQ` is not retaining the line state. If suppression is high
but the workload remains slow, coalescing is not the main bottleneck and should
remain diagnostic-only.

## Essential A/B experiments

Use the same build command and input state for each run.

### 1. CPU parallelism without changing VM configuration

Keep 12 configured vCPUs but cap compiler parallelism:

```sh
make -j6
# or
CARGO_BUILD_JOBS=6 cargo build
# or
GOMAXPROCS=6 go build ./...
```

For `andromeda-cli`, GoReleaser adds a second concurrency level. The measured
low-pressure equivalent of `task build` was:

```sh
GOMAXPROCS=4 ./bin/goreleaser build \
  --config .goreleaser.yaml --snapshot --clean --parallelism 2
```

Consider adding the `--parallelism` setting to the Taskfile (and choosing an
appropriate `GOMAXPROCS`) rather than relying on the default of one concurrent
GoReleaser task per reported CPU. On the 10-vCPU reproduction this preserved
elapsed time while greatly reducing load.

If this restores responsiveness, host CPU oversubscription is a major factor.
The macOS host still has to schedule VMM, share, network, supervisor, and UI
threads in addition to the guest vCPU threads.

### 2. Shared source versus guest-private source

```sh
cp -a /workspace/PROJECT /tmp/project-private
cd /tmp/project-private
time BUILD_COMMAND >/tmp/build-private.log 2>&1
```

- Private source smooth, shared source slow: virtio-fs path.
- Both slow at the same parallelism: CPU scheduling or block/overlay path.
- Private source still accesses OCI toolchain layers, so compare IRQ 62 and 73
  deltas as well as IRQ 75.

### 3. Runnable pressure versus I/O wait inside the guest

Run while compiling:

```sh
vmstat 1
```

Interpretation:

- high `r`, low `b`, near-zero idle: CPU oversubscription;
- high `b`, elevated `wa`, or many `D` tasks: I/O wait;
- high load average alone does not distinguish the two.

List runnable and uninterruptible tasks:

```sh
ps -eLo state,pid,tid,psr,pcpu,wchan:32,comm |
  awk '$1 ~ /^[RD]/' |
  head -80
```

Inspect guest IRQ distribution and affinity:

```sh
cat /proc/interrupts
for irq in $(awk '/virtio[0-9]+$/ { gsub(":", "", $1); print $1 }' /proc/interrupts); do
  grep -E "^ *${irq}:" /proc/interrupts
  printf '  configured: '; cat "/proc/irq/$irq/smp_affinity_list"
  printf '  effective:  '; cat "/proc/irq/$irq/effective_affinity_list"
done
```

The intended target is virtio slot modulo 12. In the current layout the hot
IRQs should be spread: IRQ 62 -> CPU 2, IRQ 73 -> CPU 1, IRQ 75 -> CPU 3.

### 4. Host-side samples

Find the daemon and VMM worker:

```sh
DIR="$HOME/.gantry/sandboxes/codex-dev"
DAEMON_PID=$(cat "$DIR/vmm.pid")
ps -o pid,ppid,%cpu,state,time,command -p "$DAEMON_PID"
pgrep -P "$DAEMON_PID" | while read -r pid; do
  ps -o pid,ppid,%cpu,state,time,command -p "$pid"
done
```

During the lag, sample both the `_vmm-worker` and daemon/share process:

```sh
sudo sample VMM_WORKER_PID 10 -file /tmp/codex-dev-vmm.sample.txt
sudo sample "$DAEMON_PID" 10 -file /tmp/codex-dev-daemon.sample.txt
```

Search for likely hot paths:

```sh
grep -Ei \
  'hv_vcpus_exit|hv_gic_set_spi|Hypervisor|RaiseExternal|readCalls|HandleRequest|virtio|fuse|mutex|semacquire' \
  /tmp/codex-dev-*.sample.txt
```

## Source locations relevant to the investigation

- `internal/vmm/vm_darwin.go`
  - `deliverIRQ`
  - `shouldDeliverIRQ`
  - `livenessKicker`
  - `runtimeStatsLine`
  - `runtimeStatsReporter`
  - `hvfVCPU.runLoop`
- `internal/virtio/virtio.go`
  - `Core.raiseIRQ`
  - `Core.RaiseExternalUsedInterrupt`
  - interrupt ACK handling at MMIO offset `0x064`
- `internal/virtio/vhostfs_unix.go`
  - `readCalls`
  - `observeCall`
- `internal/virtio/vblk.go`
  - synchronous block queue draining and `pushUsed`
- `internal/vmm/devices/irq_queue.go`
  - serialized GIC line delivery
- `patches/nerdbox-v0.2.4-virtio-irq-affinity.patch`
  - guest IRQ affinity policy

## Update: virtio-fs namespace caching fix (shipped in this tree)

Root cause of most of the measured ~20-25% virtio-fs penalty: the synthetic
share hub root and every export root served TTL 0 (`shareHubRoot.Lookup`,
`shareHubRoot.Getattr`, and the `isExportRoot` exclusions in
`node_unix.go`/`node_windows.go`). Every guest path walk into `/host/<tag>/...`
therefore revalidated the mount root and the export root with fresh
LOOKUP/GETATTR round trips, even though descendant entries already carried a
one-hour TTL. Wire traces (`GANTRY_VHOST_TRACE=1`) showed `entry-valid=0s
attr-valid=0s` on nodes 1/3/4 and `3600s` on descendants.

The zero TTL predates the reverse notification virtqueue: hot-add/remove used
to rely on instant revalidation, but `Hub.Publish`/`Swap`/`Remove` already
push `NotifyEntry(tag)` invalidations on the hub root once the notification
channel is live. The fix caches the hub root, export entries, and export-root
attributes with the watched TTL exactly when `hub.notificationsReady` is set,
and keeps TTL 0 otherwise. Negative entries are never cached.

Measured on AWS M4 (`mac-m4.metal`, 10 vCPU/12 GiB guest, Andromeda CLI
GoReleaser build, `GOMAXPROCS=4 --parallelism 2`, strict split workers):

- FUSE requests per build: ~275k -> ~110k (LOOKUP 51k -> 4k, GETATTR 128k ->
  6k; the remainder is real data I/O: OPEN/READ/WRITE/RELEASE/FLUSH plus
  benign GETXATTR ENODATA probes).
- Warm capped build: ~184s best-case baseline -> 157-158s reproducibly
  (~15%); typical baseline runs landed anywhere in 184-299s.
- Guest-visible per-stat cost at 500ms spacing dropped from ~52ms to zero
  requests (kernel attr cache hit).

Negative results from the same campaign, all reverted or left diagnostic-only:

- `GANTRY_VHOST_CALL_BATCH` doorbell draining coalesced ~14 of ~150k
  notifications; EVENT_IDX already suppresses nearly all redundant
  interrupts. Not worth it; removed.
- Backend `runtime.Gosched()` completion batching: no measurable gain; removed.
- `GANTRY_FUSE_MAX_BACKGROUND=64`: warm build unchanged (~160s vs ~157s); the
  knob remains available for profiling but the default stays 12.
- Framed (non-vhost) share transport: 258s vs ~230s vhost on the same capped
  build; vhost remains the macOS default.

### Known measurement pitfalls

- `request-gap-max` in `vhost-share-stats` includes idle time between
  separately invoked guest commands; a multi-minute gap after the final
  request of a build is normal, not a stall.
- `vhost-share-stats` `errors` counts wire errnos; thousands of GETXATTR
  ENODATA probes are expected and benign.
- Shell loops with `sleep` as timing harnesses are polluted by timer-slack
  overshoot (observed ~70ms per `sleep 0.5`); count requests, not wall time.
- `strings` on the compressed guest kernel image cannot find patch symbols;
  use `/proc/kallsyms` in the guest (static helpers may be inlined; check
  `virtio_fs_notification_dispatch_work`).

## Potential implementation follow-ups

Do not apply all of these at once; preserve A/B isolation.

1. Add interval deltas to `hvf-stats` so high-rate changes are readable without
   manually subtracting cumulative counters.
2. Add sustained runtime vCPU exit-class accounting (MMIO, WFI, sysreg,
   canceled) rather than only boot-profile accounting. This would quantify
   guest MMIO acknowledgement exits during an interrupt storm.
3. ~~Investigate vhost completion batching/EVENT_IDX behavior.~~ Done: EVENT_IDX
   already suppresses nearly all redundant interrupts; both call-side draining
   and backend completion yielding measured no improvement and were reverted.
   The request-count lever (namespace TTLs above) was the real win.
4. Evaluate core-level ISR coalescing only with the existing virtio/vhost stress
   tests and real-HVF A/B runs. The guest interrupt-ack/rearm race must not lose
   completions.
5. If `in-flight=yes:<large duration>` appears with `vcpu-lock=busy`, separate
   the vCPU registry lock from native handle lifetime protection so a stalled
   `hv_vcpus_exit` cannot block device wake routing or diagnostics.
6. Consider reducing/flattening the 24 read-only OCI layers for a separate A/B;
   do not infer that layer count alone is causal without measurements.

## Validation already performed

After the latest diagnostic changes:

```text
go test ./internal/vmm ./internal/sandbox/vmmworker ./internal/virtio
```

passed. A Darwin arm64 `cmd/gantry` cross-build succeeded, and the Darwin arm64
`internal/vmm` test binary compiled successfully. `go test ./...` passed before
the final no-liveness/nonblocking-reporter additions; rerunning the full suite
is recommended before commit.

## Working-tree caution

The repository already contained unrelated untracked files before this work,
including local OCI archives, keys, examples, and `.pi/`. Do not stage them.
Review with:

```sh
git status --short
git diff -- \
  internal/vmm/vm_darwin.go \
  internal/vmm/vm_idle_darwin_test.go \
  internal/sandbox/vmmworker/env_unix.go \
  internal/sandbox/vmmworker/env_unix_test.go \
  scripts/bench-boot-scaling.sh \
  docs/gantry/troubleshooting.md \
  docs/gantry/macos-compile-lag-handover.md
```
